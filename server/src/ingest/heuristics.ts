// Signals that need no advisory: risky install-script commands and typosquat names.

const STRONG: [RegExp, string][] = [
  [/\b(curl|wget)\b[^|;&]*\|\s*(ba|z)?sh\b/i, "pipes a download straight into a shell"],
  [/base64|atob\(/i, "decodes base64"],
  [/\beval\s*\(|new\s+Function\s*\(/i, "evaluates generated code"],
  [/\bbun\b|bun\.sh|setup_bun/i, "installs or runs the Bun runtime (Shai-Hulud 2.0 did this)"],
  [/\.npmrc|\.ssh|id_rsa|NPM_TOKEN|GITHUB_TOKEN|AWS_(ACCESS|SECRET)|GOOGLE_APPLICATION_CREDENTIALS/i, "touches credentials"],
  [/trufflehog|gh\s+auth|git\s+config\s+--global/i, "uses secret-scanning or git credential tools"],
  [/\brm\s+-rf\s+(~|\$HOME)/i, "deletes files in your home directory"],
];
const NETWORK: [RegExp, string] = [/\b(curl|wget|Invoke-WebRequest)\b|https?:\/\//i, "reaches out to the network"];

/**
 * Risky patterns in install hooks. Running a local file with `node -e` (core-js, msw) or downloading a prebuilt
 * binary is normal, so network access alone never raises a flag; it is only listed next to a strong pattern.
 */
export function scriptFlags(hooks: Record<string, string>): string[] {
  const text = Object.values(hooks).join(" ; ");
  const strong = STRONG.filter(([re]) => re.test(text)).map(([, why]) => why);
  return strong.length ? (NETWORK[0].test(text) ? [...strong, NETWORK[1]] : strong) : [];
}

export const scriptText = (hooks: Record<string, string>) => {
  const s = Object.entries(hooks).map(([h, c]) => `${h}: ${c}`).join("\n");
  return s ? s.slice(0, 500) : undefined;
};

/** Damerau-Levenshtein distance, giving up above `max`. */
export function editDistance(a: string, b: string, max = 1): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array<number>(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    let best = Infinity;
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      best = Math.min(best, d[i][j]);
    }
    if (best > max) return max + 1;
  }
  return d[a.length][b.length];
}

const bare = (s: string) => s.toLowerCase().replace(/[-_.]/g, "");

/**
 * A typosquat is one keystroke (or only separators) away from a top package, and genuinely obscure: under 1/1000th
 * of that package's downloads and under 50k a month. Without download data we don't guess.
 */
export function typosquatOf(name: string, downloads: number | undefined, top: Map<string, number>): string | null {
  if (downloads === undefined || name.startsWith("@") || name.length < 5 || top.has(name)) return null;
  if (downloads > 50_000) return null;
  let best: [string, number] | null = null;
  for (const [t, dl] of top) {
    if (Math.abs(t.length - name.length) > 1 && bare(t) !== bare(name)) continue;
    if (bare(t) !== bare(name) && editDistance(name, t, 1) > 1) continue;
    if (downloads * 1000 > dl) continue;
    if (!best || dl > best[1]) best = [t, dl];
  }
  return best?.[0] ?? null;
}
