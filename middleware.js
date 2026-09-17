// Clerk session gate for an internal AAA dashboard (static single-page app).
//
// AAA-769 Phase 1: replaces shared Supabase Auth (aaa-internal-auth /
// qmdblnaqpylbnufvarcu). Access requires (1) a valid Clerk session, AND
// (2) the session email being exactly brad@automationarchitecture.ai.
// Dashboard HTML is never returned to an unauthenticated/unauthorized
// browser — gating happens here at the edge, before public/index.html.
//
// Env vars (Vercel production; values never in repo):
//   CLERK_SECRET_KEY        — required; verifies the session
//   CLERK_PUBLISHABLE_KEY   — required; authenticateRequest + login JS
//   CLERK_JWT_KEY           — optional; networkless JWT verify (PEM)
//
// SUPABASE_ANON_KEY and ALLOWED_EMAILS are unused. Phase 1 allowlist is
// hard-coded (sole default) and does not admit other emails.

import { createClerkClient } from "@clerk/backend";

export const config = { matcher: "/:path*" };

export const ALLOWED_EMAILS = Object.freeze([
  "brad@automationarchitecture.ai",
]);

export function isAcmePath(pathname) {
  return pathname.startsWith("/.well-known/");
}

export function isPublicPath(pathname) {
  return (
    pathname === "/login" ||
    pathname === "/login.html" ||
    pathname === "/favicon.ico" ||
    pathname === "/api/clerk-config" ||
    pathname.startsWith("/auth/")
  );
}

export function emailsFromClaims(claims) {
  if (!claims || typeof claims !== "object") return [];
  const keys = [
    "email",
    "email_address",
    "primary_email",
    "primary_email_address",
  ];
  const out = [];
  for (const key of keys) {
    const value = claims[key];
    if (typeof value === "string" && value.includes("@")) {
      out.push(value.toLowerCase());
    }
  }
  return [...new Set(out)];
}

export function emailsFromUser(user) {
  const out = [];
  const primary = user?.primaryEmailAddress?.emailAddress;
  if (typeof primary === "string" && primary.includes("@")) {
    out.push(primary.toLowerCase());
  }
  for (const entry of user?.emailAddresses || []) {
    if (entry?.verification?.status !== "verified") continue;
    const value = entry.emailAddress;
    if (typeof value === "string" && value.includes("@")) {
      out.push(value.toLowerCase());
    }
  }
  return [...new Set(out)];
}

export function isAllowedEmail(emails) {
  const allowed = new Set(ALLOWED_EMAILS);
  return (emails || []).some((email) => allowed.has(String(email).toLowerCase()));
}

function clerkClient() {
  return createClerkClient({
    secretKey: process.env.CLERK_SECRET_KEY || "",
    publishableKey: process.env.CLERK_PUBLISHABLE_KEY || "",
    jwtKey: process.env.CLERK_JWT_KEY || undefined,
  });
}

function passthrough(extraHeaders) {
  const headers = new Headers(extraHeaders);
  headers.set("x-middleware-next", "1");
  return new Response(null, { headers });
}

function handshakeResponse(state, req) {
  const headers = new Headers(state.headers);
  const location = headers.get("location");
  if (location) {
    headers.set("cache-control", "no-store");
    return new Response(null, { status: 307, headers });
  }
  return Response.redirect(new URL("/login", req.url), 302);
}

export default async function middleware(req) {
  const url = new URL(req.url);
  const { pathname } = url;

  // ACME challenges must never be gated — blocking these stops TLS cert
  // issuance for any custom domain. Keep this first.
  if (isAcmePath(pathname)) return;

  if (pathname === "/api/clerk-config") {
    return Response.json({
      publishableKey: process.env.CLERK_PUBLISHABLE_KEY || "",
    });
  }

  if (!process.env.CLERK_SECRET_KEY || !process.env.CLERK_PUBLISHABLE_KEY) {
    if (isPublicPath(pathname)) return;
    return Response.redirect(new URL("/login", req.url), 302);
  }

  const clerk = clerkClient();
  let state;
  try {
    state = await clerk.authenticateRequest(req, {
      publishableKey: process.env.CLERK_PUBLISHABLE_KEY,
      secretKey: process.env.CLERK_SECRET_KEY,
      jwtKey: process.env.CLERK_JWT_KEY || undefined,
      authorizedParties: [url.origin],
    });
  } catch {
    if (isPublicPath(pathname)) return;
    return Response.redirect(new URL("/login", req.url), 302);
  }

  if (state.status === "handshake") {
    return handshakeResponse(state, req);
  }

  const location = state.headers?.get?.("location");
  if (location) {
    const headers = new Headers(state.headers);
    headers.set("cache-control", "no-store");
    return new Response(null, { status: 307, headers });
  }

  if (isPublicPath(pathname)) {
    return state.headers ? passthrough(state.headers) : undefined;
  }

  if (!state.isAuthenticated) {
    return Response.redirect(new URL("/login", req.url), 302);
  }

  const auth = state.toAuth();
  let emails = emailsFromClaims(auth?.sessionClaims);
  if (!isAllowedEmail(emails) && auth?.userId) {
    try {
      const user = await clerk.users.getUser(auth.userId);
      emails = [...new Set([...emails, ...emailsFromUser(user)])];
    } catch {
      return Response.redirect(new URL("/login", req.url), 302);
    }
  }

  if (!isAllowedEmail(emails)) {
    return Response.redirect(new URL("/login?error=forbidden", req.url), 302);
  }

  return state.headers ? passthrough(state.headers) : undefined;
}
