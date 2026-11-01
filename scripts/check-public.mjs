// Fail if a file of Verfy Cloud, the hosted service, is tracked in this public repository. The service lives in a
// private repository; this one is the MIT CLI and what users need to install it. Until the split on 2026-10-25 the
// service was here too, which is why this check exists.
//
//   node scripts/check-public.mjs
import { execFileSync } from "node:child_process";

const CLOUD = [
  /^src\//, // the Next.js app
  /^supabase\//,
  /^public\//,
  /^deploy\//,
  /^tests\//, // the service's tests; the CLI's are in verfy-cli/tests
  /^vendor\//,
  /^(?:package|package-lock)\.json$/,
  /^next\.config\.[cm]?[jt]s$/,
  /^(?:tsconfig|vercel)\.json$/,
  /^\.vercel(?:ignore)?(?:\/|$)/,
  /^(?:vitest|eslint)\.config\.[cm]?[jt]s$/,
  /^\.env/,
  /^AGENTS\.md$/,
  /^docs\/(?:API|ARCHITECTURE|DATA_MODEL|DEPLOYMENT|LOCAL_DEVELOPMENT|POSITIONING|THREAT_MODEL|requirements-traceability)\.md$/,
];

const files = execFileSync("git", ["ls-files"], { encoding: "utf8" }).split("\n").filter(Boolean);
const found = files.filter((f) => CLOUD.some((re) => re.test(f)));
if (found.length) {
  console.error(`Verfy Cloud files in the public repository (they belong in the private one):\n  ${found.join("\n  ")}`);
  process.exit(1);
}
console.log(`OK  no Verfy Cloud files among ${files.length} tracked files`);
