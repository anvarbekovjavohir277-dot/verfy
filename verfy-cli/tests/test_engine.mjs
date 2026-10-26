// Runs the shared fixtures through the JavaScript twin of the engine (verfy-cli/js/verfy-engine.mjs).
// Usage: node verfy-cli/tests/test_engine.mjs [--sign-out FILE] [--verify FILE PUBKEY]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createEngine } from "../js/verfy-engine.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA = path.join(__dirname, "..", "src", "verfy", "data");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const K = createEngine(readJson(path.join(DATA, "patterns.json")), readJson(path.join(DATA, "default_policy.json")));

const FX = path.join(__dirname, "fixtures");
let failures = 0, passed = 0;
function eq(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function expect(name, got, want) {
  if (eq(got, want)) { passed++; return; }
  failures++;
  console.error("FAIL " + name + "\n  got:  " + JSON.stringify(got) + "\n  want: " + JSON.stringify(want));
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "--verify") {
    const lines = K.parseLedger(fs.readFileSync(argv[1], "utf8"));
    const res = await K.verifyLedger(lines, K.unb64u(argv[2]));
    process.stdout.write(JSON.stringify(res) + "\n");
    process.exit(res.ok ? 0 : 1);
  }
  if (argv[0] === "--sign-out") {
    const key = await K.keyFromSecret(new Uint8Array(32).map((_, i) => i + 1));
    const pol = K.loadPolicy({ home: "/home/you", workspace: "/home/you/project" });
    const polSha = await K.digest(pol);
    let prev = null; const out = [];
    const acts = [{ server: "s", tool: "Bash", arguments: { command: "ls" } }, { server: "s", tool: "Bash", arguments: { command: "rm -rf ~" } }, { server: "s", tool: "pay", arguments: { amount: 1.5, currency: "USD", note: "ünïcode ✓" } }];
    for (let i = 0; i < acts.length; i++) {
      const d = K.check(acts[i], pol);
      const body = await K.buildReceipt({ seq: i, prev, agent: "node", session: "ses_x", action: acts[i], decision: d, outcome: { status: d.verdict === "deny" ? "blocked" : "ok", result_sha256: null }, policy_sha256: polSha, include_args: true });
      const r = await K.signReceipt(body, key);
      out.push(JSON.stringify(r)); prev = await K.digest(r);
    }
    fs.writeFileSync(argv[1], out.join("\n") + "\n");
    process.stdout.write(key.public + "\n");
    return;
  }

  // canonical JSON
  for (const c of JSON.parse(fs.readFileSync(path.join(FX, "canonical.json"), "utf8"))) expect("canonical", K.canonical(c.value), c.canonical);

  // Secrets are assembled only at test time, so fixtures do not contain complete token-shaped strings.
  for (const c of readJson(path.join(FX, "secrets.json"))) {
    const text = c.parts.join("");
    expect("secrets: " + c.name, K.scanSecrets(text), c.expect);
    expect("redaction: " + c.name, K.redactValue(text), c.expect.length ? "[REDACTED:" + c.expect[0].id + "]" : text);
  }

  // pre-check
  const pre = JSON.parse(fs.readFileSync(path.join(FX, "precheck.json"), "utf8"));
  for (const c of pre.cases) {
    const pol = Object.assign({}, pre.policy, c.policy);
    const r = K.check(c.action, pol, c.context);
    const rules = Array.from(new Set(r.findings.map((f) => f.rule))).sort();
    expect("precheck: " + c.name, { verdict: r.verdict, kind: r.kind, rules }, c.expect);
  }

  // scanner
  for (const c of JSON.parse(fs.readFileSync(path.join(FX, "scan.json"), "utf8"))) {
    const data = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "examples", "tools", c.file), "utf8"));
    const rep = await K.scan(data, c.file.replace(/\.json$/, ""), c.pins || null);
    if (c.pins) {
      const ps = {}; rep.tools.forEach((t) => { ps[t.name] = t.pin; });
      expect("scan pins: " + c.file, { score: rep.score, grade: rep.grade, removed: rep.removed_tools, pinstatus: ps }, c.expect);
    } else {
      expect("scan: " + c.file, { score: rep.score, grade: rep.grade, tools: rep.tools.map((t) => ({ name: t.name, sha256: t.sha256, score: t.score, grade: t.grade, capabilities: t.capabilities, rules: Array.from(new Set(t.findings.map((f) => f.rule))).sort() })) }, c.expect);
    }
  }

  // Ed25519 RFC 8032 vectors
  const vec = [
    ["9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"],
    ["c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82", "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"]
  ];
  const hx = (s) => Uint8Array.from(Buffer.from(s, "hex"));
  for (const [sk, pk, m, sig] of vec) {
    expect("ed25519 public", Buffer.from(await K.ed25519.publicKey(hx(sk))).toString("hex"), pk);
    expect("ed25519 sign", Buffer.from(await K.ed25519.sign(hx(sk), hx(m))).toString("hex"), sig);
    expect("ed25519 verify", await K.ed25519.verify(hx(pk), hx(m), hx(sig)), true);
    expect("ed25519 reject", await K.ed25519.verify(hx(pk), hx(m + "00"), hx(sig)), false);
  }

  // receipts: sign, verify, tamper
  const key = await K.generateKey();
  const pol = K.loadPolicy({});
  let prev = null; const led = [];
  for (let i = 0; i < 4; i++) {
    const act = { server: "x", tool: "Bash", arguments: { command: "echo " + i } };
    const d = K.check(act, pol);
    const r = await K.signReceipt(await K.buildReceipt({ seq: i, prev, agent: "a", session: "s", action: act, decision: d, outcome: { status: "ok", result_sha256: null }, policy_sha256: "sha256:0", include_args: true }), key);
    led.push(r); prev = await K.digest(r);
  }
  expect("ledger ok", (await K.verifyLedger(led, key._pub)).ok, true);
  const tampered = JSON.parse(JSON.stringify(led)); tampered[1].action.args.command = "echo hacked";
  expect("ledger tamper", (await K.verifyLedger(tampered, key._pub)).errors.map((e) => e.index), [1, 2]);
  const dropped = led.slice(0, 1).concat(led.slice(2));
  expect("ledger drop", (await K.verifyLedger(dropped, key._pub)).ok, false);
  const other = await K.generateKey();
  expect("ledger wrong key", (await K.verifyLedger(led, other._pub)).ok, false);
  const secretAct = { tool: "send_email", arguments: { to: "a@b.c", body: "ghp_" + "a".repeat(36) } };
  const sr = await K.buildReceipt({ seq: 0, prev: null, agent: "a", session: "s", action: secretAct, decision: K.check(secretAct, pol), outcome: { status: "blocked", result_sha256: null }, policy_sha256: "x", include_args: true });
  const hashOnly = await K.buildReceipt({ seq: 0, prev: null, agent: "a", session: "s", action: secretAct, decision: K.check(secretAct, pol), outcome: { status: "blocked", result_sha256: null }, policy_sha256: "x" });
  expect("hash-only by default", [hashOnly.action.args, hashOnly.action.args_sha256.slice(0, 7)], [undefined, "sha256:"]);
  expect("redacted args", sr.action.args.body, "[REDACTED:github-token]");

  console.log((failures ? "FAILED" : "OK") + "  " + passed + " passed, " + failures + " failed");
  process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(2); });
