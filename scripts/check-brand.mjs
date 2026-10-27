// The product was renamed from its working titles to Verfy. Fail if any old
// product name, namespace or file name is left in the repository.
//
//   node scripts/check-brand.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "coverage", ".venv", "venv", "__pycache__", "dist", "build"]);
// Built from parts so this file does not match itself.
const OLD = ["at" + "las", "at" + "ls", "k" + "afil", "agent" + "cve", "kaf" + "-id", "kf" + "-scan", "kf" + "-sh-", "kf" + "_"];
const RE = new RegExp(OLD.map((s) => s.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")).join("|"), "i");

// real words that contain an old name (the Atlassian MCP server in research/servers.json), the
// advisory ids from before the rename, which stay valid as aliases (for example an old 2025-0001 id),
// and the name of a hosted-service environment variable that check-secrets.mjs looks for
const ALLOWED = new RegExp("atl" + "assian|" + "at" + "ls-(?=[0-9`])|" + "at" + "ls_ip_hash_salt", "gi");

const hits = [];
function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = path.join(dir, name);
    const rel = path.relative(ROOT, full);
    if (RE.test(name)) hits.push(`${rel}: old name in file name`);
    const st = statSync(full);
    if (st.isDirectory()) walk(full);
    else if (st.size < 3_000_000 && !/\.(png|jpe?g|gif|ico|mp4|woff2?|zip|whl|exe|dll)$/i.test(name)) {
      const lines = readFileSync(full, "utf8").split("\n");
      lines.forEach((line, i) => {
        if (RE.test(line.replace(ALLOWED, ""))) hits.push(`${rel}:${i + 1}: ${line.trim().slice(0, 120)}`);
      });
    }
  }
}
walk(ROOT);
if (hits.length) {
  console.error("Old product names found:\n  " + hits.slice(0, 50).join("\n  "));
  process.exit(1);
}
console.log("OK  no old product names");
