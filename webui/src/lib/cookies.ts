const ONE_YEAR_SECONDS = 60 * 60 * 24 * 365;

function parseCookies(): Record<string, string> {
  if (typeof document === "undefined" || !document.cookie) return {};

  return document.cookie
    .split(";")
    .reduce<Record<string, string>>((acc, entry) => {
      const [rawName, ...rest] = entry.trim().split("=");
      if (!rawName) return acc;
      acc[decodeURIComponent(rawName)] = decodeURIComponent(rest.join("="));
      return acc;
    }, {});
}

export function getCookie(name: string): string | null {
  const cookies = parseCookies();
  return cookies[name] ?? null;
}

export function setCookie(name: string, value: string): void {
  if (typeof document === "undefined") return;

  document.cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}; Max-Age=${ONE_YEAR_SECONDS}; Path=/; SameSite=Lax`;
}
