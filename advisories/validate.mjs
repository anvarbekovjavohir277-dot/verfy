// Validate advisories/**/*.json: OSV format with a Verfy severity label and at least one public source.
// CI runs this on every pull request; the hosted site imports load() when it publishes them.
//
//   node advisories/validate.mjs
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ID = /^VERFY-\d{4}-\d{4,}$/;
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);

function files(dir) {
  return readdirSync(dir, { recursive: true })
    .map(String)
    .filter((f) => f.endsWith(".json"))
    .sort();
}

export function load(dir = HERE) {
  const out = [];
  const problems = [];
  for (const rel of files(dir)) {
    let a;
    try {
      a = JSON.parse(readFileSync(path.join(dir, rel), "utf8"));
    } catch (e) {
      problems.push(`${rel}: not valid JSON (${e.message})`);
      continue;
    }
    if (!ID.test(a.id ?? "")) problems.push(`${rel}: id must look like VERFY-2025-0001`);
    if (path.basename(rel, ".json") !== a.id) problems.push(`${rel}: file name must equal the id`);
    if (typeof a.summary !== "string" || a.summary.length < 5 || a.summary.length > 300) problems.push(`${rel}: summary must be 5-300 characters`);
    if (typeof a.details !== "string" || !a.details.trim()) problems.push(`${rel}: details are required`);
    if (!SEVERITIES.has(a.severity_label)) problems.push(`${rel}: severity_label must be critical, high, medium or low`);
    if (!Array.isArray(a.affected) || !a.affected.length || !a.affected.every((x) => x?.package?.ecosystem && x?.package?.name)) problems.push(`${rel}: affected[].package {ecosystem, name} is required`);
    if (!Array.isArray(a.references) || !a.references.length || !a.references.every((r) => typeof r.url === "string" && r.url.startsWith("https://"))) problems.push(`${rel}: at least one https reference is required`);
    for (const k of ["published", "modified"]) if (Number.isNaN(Date.parse(a[k]))) problems.push(`${rel}: ${k} must be an RFC 3339 timestamp`);
    if (!["unreviewed", "reviewed"].includes(a.database_specific?.verfy_review)) problems.push(`${rel}: database_specific.verfy_review must be unreviewed or reviewed`);
    out.push(a);
  }
  const ids = out.map((a) => a.id);
  if (new Set(ids).size !== ids.length) problems.push("duplicate advisory ids");
  return { advisories: out, problems };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const { advisories, problems } = load();
  if (problems.length) {
    console.error("Advisory problems:\n  " + problems.join("\n  "));
    process.exit(1);
  }
  console.log(`OK  ${advisories.length} advisories valid`);
}
