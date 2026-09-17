// Shared Clerk JS bootstrap for the static login + callback pages.
// Publishable key is served by the edge (CLERK_PUBLISHABLE_KEY) — never a secret.

export function frontendApiFromPk(publishableKey) {
  const encoded = String(publishableKey || "")
    .replace(/^pk_(test|live)_/, "");
  let decoded = "";
  try {
    decoded = atob(encoded);
  } catch {
    return "";
  }
  return decoded.endsWith("$") ? decoded.slice(0, -1) : decoded;
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.crossOrigin = "anonymous";
    script.onload = resolve;
    script.onerror = () => reject(new Error("Failed to load " + src));
    document.head.appendChild(script);
  });
}

export async function loadClerk() {
  const res = await fetch("/api/clerk-config", { cache: "no-store" });
  if (!res.ok) throw new Error("Clerk config unavailable");
  const { publishableKey } = await res.json();
  if (!publishableKey) throw new Error("CLERK_PUBLISHABLE_KEY is not set");

  const fapi = frontendApiFromPk(publishableKey);
  if (!fapi) throw new Error("Invalid CLERK_PUBLISHABLE_KEY");

  await loadScript(`https://${fapi}/npm/@clerk/clerk-js@5/dist/clerk.browser.js`);
  const clerk = new window.Clerk(publishableKey);
  await clerk.load();
  return clerk;
}
