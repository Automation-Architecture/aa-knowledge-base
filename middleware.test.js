import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import middleware, {
  ALLOWED_EMAILS,
  emailsFromClaims,
  emailsFromUser,
  isAcmePath,
  isAllowedEmail,
  isPublicPath,
} from "./middleware.js";

describe("AAA-769 Phase 1 allowlist", () => {
  it("admits only the hard-coded founder email", () => {
    assert.deepEqual(ALLOWED_EMAILS, ["brad@automationarchitecture.ai"]);
    assert.equal(isAllowedEmail(["brad@automationarchitecture.ai"]), true);
    assert.equal(isAllowedEmail(["Brad@AutomationArchitecture.ai"]), true);
  });

  it("does not admit any other email", () => {
    assert.equal(isAllowedEmail(["engineer@automationarchitecture.ai"]), false);
    assert.equal(isAllowedEmail(["billing@automationarchitecture.ai"]), false);
    assert.equal(isAllowedEmail(["someone@gmail.com"]), false);
    assert.equal(isAllowedEmail([]), false);
    assert.equal(isAllowedEmail(undefined), false);
  });
});

describe("path exemptions", () => {
  it("keeps ACME first and distinct from the login gate", () => {
    assert.equal(isAcmePath("/.well-known/acme-challenge/token"), true);
    assert.equal(isAcmePath("/.well-known/"), true);
    assert.equal(isAcmePath("/login"), false);
    assert.equal(isAcmePath("/"), false);
  });

  it("exposes only the login/callback surfaces unauthenticated", () => {
    assert.equal(isPublicPath("/login"), true);
    assert.equal(isPublicPath("/login.html"), true);
    assert.equal(isPublicPath("/auth/callback"), true);
    assert.equal(isPublicPath("/auth/callback.html"), true);
    assert.equal(isPublicPath("/auth/clerk.js"), true);
    assert.equal(isPublicPath("/api/clerk-config"), true);
    assert.equal(isPublicPath("/favicon.ico"), true);
    assert.equal(isPublicPath("/"), false);
    assert.equal(isPublicPath("/index.html"), false);
  });
});

describe("email extraction", () => {
  it("reads common Clerk session-claim keys", () => {
    assert.deepEqual(emailsFromClaims({ email: "Brad@Example.com" }), [
      "brad@example.com",
    ]);
    assert.deepEqual(
      emailsFromClaims({ primary_email_address: "a@b.com" }),
      ["a@b.com"],
    );
    assert.deepEqual(emailsFromClaims({ sub: "user_123" }), []);
  });

  it("uses the primary and verified Clerk user emails only", () => {
    const user = {
      primaryEmailAddress: { emailAddress: "Brad@automationarchitecture.ai" },
      emailAddresses: [
        {
          emailAddress: "alias@automationarchitecture.ai",
          verification: { status: "verified" },
        },
        {
          emailAddress: "unverified@example.com",
          verification: { status: "unverified" },
        },
      ],
    };
    assert.deepEqual(emailsFromUser(user), [
      "brad@automationarchitecture.ai",
      "alias@automationarchitecture.ai",
    ]);
  });
});

describe("middleware gate", () => {
  it("never gates ACME, even without Clerk keys", async () => {
    delete process.env.CLERK_SECRET_KEY;
    delete process.env.CLERK_PUBLISHABLE_KEY;
    const res = await middleware(
      new Request("https://kb.example/.well-known/acme-challenge/token"),
    );
    assert.equal(res, undefined);
  });

  it("redirects dashboard HTML when Clerk is unset; login stays public", async () => {
    delete process.env.CLERK_SECRET_KEY;
    delete process.env.CLERK_PUBLISHABLE_KEY;
    const dash = await middleware(new Request("https://kb.example/"));
    assert.equal(dash.status, 302);
    assert.equal(new URL(dash.headers.get("location")).pathname, "/login");

    const login = await middleware(new Request("https://kb.example/login"));
    assert.equal(login, undefined);
  });

  it("serves the publishable key to login JS", async () => {
    process.env.CLERK_PUBLISHABLE_KEY = "pk_test_example";
    const res = await middleware(
      new Request("https://kb.example/api/clerk-config"),
    );
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { publishableKey: "pk_test_example" });
    delete process.env.CLERK_PUBLISHABLE_KEY;
  });
});

describe("no runtime Supabase Auth", () => {
  it("drops Supabase from the gate, login, and callback", () => {
    const files = [
      "middleware.js",
      "public/login.html",
      "public/auth/callback.html",
      "public/auth/clerk.js",
    ];
    for (const file of files) {
      const src = readFileSync(file, "utf8");
      assert.equal(src.includes("supabase.co"), false, file);
      assert.equal(src.includes("@supabase/"), false, file);
      assert.equal(src.includes("SUPABASE_ANON_KEY"), file === "middleware.js", file);
      assert.equal(src.includes("qmdblnaqpylbnufvarcu"), file === "middleware.js", file);
    }
  });

  it("documents Clerk env vars and drops SUPABASE_ANON_KEY as required", () => {
    const readme = readFileSync("README.md", "utf8");
    assert.match(readme, /CLERK_SECRET_KEY/);
    assert.match(readme, /CLERK_PUBLISHABLE_KEY/);
    assert.match(readme, /no longer required/);
    assert.match(readme, /SUPABASE_ANON_KEY/);
  });
});
