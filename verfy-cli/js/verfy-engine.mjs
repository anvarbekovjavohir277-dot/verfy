/*
 * Verfy engine for the browser and Node.
 *
 * This is a line-for-line port of the Python package (verfy-cli/src/verfy): the
 * scanner, the pre-check, canonical JSON, Ed25519 and receipts. Both engines
 * are tested against the same fixtures in verfy-cli/tests/fixtures, so a verdict you see
 * in the browser is the verdict the gateway gives.
 *
 * Needs globalThis.crypto.subtle (any modern browser over https, Node 18+).
 *
 * ES module: call createEngine(patterns, defaultPolicy) with the JSON files in
 * verfy-cli/src/verfy/data. The hosted Verfy web app (Verfy Cloud) does this with a copy of this directory.
 */
export function createEngine(PATTERNS, DEFAULT_POLICY) {
  "use strict";

  var SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  var VERDICT_RANK = { deny: 2, ask: 1, allow: 0 };
  var subtle = globalThis.crypto && globalThis.crypto.subtle;

  /* ============================================================ helpers */
  var rxCache = {};
  function rx(pattern, flags, g) {
    var k = pattern + "\u0000" + (flags || "") + (g ? "g" : "");
    if (!rxCache[k]) rxCache[k] = new RegExp(pattern, (flags || "") + (g ? "g" : ""));
    var r = rxCache[k];
    r.lastIndex = 0;
    return r;
  }
  function has(list, x) { return list.indexOf(x) >= 0; }
  function setOf(list) { var s = {}; list.forEach(function (x) { s[x] = true; }); return s; }
  function intersects(a, b) { for (var k in a) if (b[k]) return true; return false; }

  function words(name) {
    var s = String(name || "").replace(/([a-z0-9])([A-Z])/g, "$1 $2");
    return s.toLowerCase().split(/[^A-Za-z0-9]+/).filter(Boolean);
  }
  function isInvisible(cp) {
    return PATTERNS.invisible_ranges.some(function (r) { return r[0] <= cp && cp <= r[1]; });
  }
  function entropy(v) {
    if (!v) return 0;
    var c = {}, n = 0, e = 0, k;
    for (var ch of v) { c[ch] = (c[ch] || 0) + 1; n++; }
    for (k in c) { var p = c[k] / n; e -= p * Math.log2(p); }
    return e;
  }
  function scanSecrets(text, every) {
    var out = [];
    if (!text || typeof text !== "string") return out;
    var seen = {};
    PATTERNS.secrets.forEach(function (p) {
      var r = rx(p[2], p[3], true), m;
      while ((m = r.exec(text)) !== null) {
        if (m[0] === "") { r.lastIndex++; continue; }
        var value = m.length > 1 && m[1] !== undefined ? m[1] : m[0];
        var low = value.toLowerCase();
        if (PATTERNS.placeholders.some(function (h) { return low.indexOf(h) >= 0; })) continue;
        if (p[4] === "medium" && entropy(value) < 3.0) continue;
        if (seen[p[0]] && !every) continue;
        seen[p[0]] = true;
        out.push({ id: p[0], label: p[1], severity: p[4], start: m.index, end: m.index + m[0].length });
      }
    });
    return out;
  }
  function secretSpans(text) {
    var out = [];
    scanSecrets(text, true).sort(function (a, b) { return a.start - b.start || b.end - a.end; }).forEach(function (h) {
      var last = out[out.length - 1];
      if (last && h.start < last.end) last.end = Math.max(last.end, h.end);
      else out.push({ id: h.id, start: h.start, end: h.end });
    });
    return out;
  }
  function redact(text) {
    secretSpans(text).reverse().forEach(function (h) { text = text.slice(0, h.start) + "[REDACTED:" + h.id + "]" + text.slice(h.end); });
    return text;
  }
  function redactValue(v) {
    if (typeof v === "string") return scanSecrets(v).length ? redact(v) : v;
    if (Array.isArray(v)) return v.map(redactValue);
    if (v && typeof v === "object") { var o = {}; Object.keys(v).forEach(function (k) { o[k] = redactValue(v[k]); }); return o; }
    return v;
  }
  function flattenStrings(v, path) {
    path = path || "";
    var out = [];
    if (typeof v === "string") out.push([path, v]);
    else if (Array.isArray(v)) v.forEach(function (x, i) { out = out.concat(flattenStrings(x, path + "[" + i + "]")); });
    else if (v && typeof v === "object") Object.keys(v).forEach(function (k) { out = out.concat(flattenStrings(v[k], path ? path + "." + k : k)); });
    return out;
  }
  function isObj(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

  /* ---------------------------------------------------------------- paths */
  function normpath(p) {
    var absolute = p.charAt(0) === "/", parts = [];
    p.split("/").forEach(function (part) {
      if (part === "" || part === ".") return;
      if (part === "..") {
        if (parts.length && parts[parts.length - 1] !== "..") parts.pop();
        else if (!absolute) parts.push("..");
        return;
      }
      parts.push(part);
    });
    var s = parts.join("/");
    return absolute ? "/" + s : (s || ".");
  }
  function toPosix(p) {
    p = p.replace(/\\/g, "/");
    var m = /^([A-Za-z]):(?=\/|$)/.exec(p);
    return m ? "/" + m[1].toLowerCase() + p.slice(2) : p;
  }
  function resolve(p, home, cwd) {
    p = toPosix(String(p || "").trim());
    if (p === "~" || p.indexOf("~/") === 0) p = home + p.slice(1);
    else if (p.indexOf("$HOME") === 0) p = home + p.slice(5);
    else if (p.indexOf("${HOME}") === 0) p = home + p.slice(7);
    if (p.charAt(0) !== "/") p = cwd.replace(/\/+$/, "") + "/" + p;
    return normpath(p);
  }
  function isWithin(path, root) {
    root = root.replace(/\/+$/, "") || "/";
    return path === root || path.indexOf(root + "/") === 0 || root === "/";
  }
  function reEscape(s) { return s.replace(/[.*+?^${}()|[\]\\\/-]/g, "\\$&"); }
  var globCache = {};
  function globRx(pattern) {
    if (globCache[pattern]) return globCache[pattern];
    var i = 0, out = "";
    if (pattern.indexOf("**/") === 0) { out = "(?:.*/)?"; i = 3; }
    while (i < pattern.length) {
      var c = pattern.charAt(i);
      if (pattern.substr(i, 4) === "/**/") { out += "/(?:.*/)?"; i += 4; continue; }
      if (pattern.substr(i, 3) === "/**" && i + 3 === pattern.length) { out += "(?:/.*)?"; i += 3; continue; }
      if (pattern.substr(i, 2) === "**") { out += ".*"; i += 2; continue; }
      if (c === "*") out += "[^/]*";
      else if (c === "?") out += "[^/]";
      else out += reEscape(c);
      i++;
    }
    return (globCache[pattern] = new RegExp("^" + out + "$"));
  }
  function globMatch(pattern, path, home) {
    if (pattern === "~" || pattern.indexOf("~/") === 0) pattern = home + pattern.slice(1);
    if (pattern.indexOf("**/") === 0) return globRx(pattern).test(path.replace(/^\/+/, "")) || globRx(pattern).test(path);
    return globRx(pattern).test(path);
  }
  function firstMatch(patterns, path, home) {
    patterns = patterns || [];
    for (var i = 0; i < patterns.length; i++) if (globMatch(patterns[i], path, home)) return patterns[i];
    return null;
  }
  function nameMatch(pattern, name) {
    return new RegExp("^" + reEscape(pattern).replace(/\\\*/g, ".*") + "$").test(name || "");
  }
  function hostMatch(pattern, host) {
    pattern = pattern.toLowerCase(); host = host.toLowerCase();
    if (pattern.indexOf("*.") === 0) return host === pattern.slice(2) || host.slice(-(pattern.length - 1)) === pattern.slice(1);
    return host === pattern;
  }

  /* ============================================================ canonical JSON */
  function canonical(v) {
    if (v === null || v === undefined) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "number") {
      if (!isFinite(v)) throw new Error("NaN and Infinity cannot be signed");
      return Object.is(v, -0) ? "0" : JSON.stringify(v);
    }
    if (typeof v === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    if (typeof v === "object") {
      return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canonical(v[k]); }).join(",") + "}";
    }
    throw new Error("cannot canonicalize " + typeof v);
  }
  var enc = new TextEncoder();
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return (b < 16 ? "0" : "") + b.toString(16); }).join(""); }
  async function sha256Hex(bytes) { return hex(await subtle.digest("SHA-256", bytes)); }
  async function digest(obj) { return "sha256:" + (await sha256Hex(enc.encode(canonical(obj)))); }

  /* ============================================================ policy */
  function clone(v) { return v === undefined ? undefined : JSON.parse(JSON.stringify(v)); }
  function merge(base, over) {
    if (isObj(base) && isObj(over)) {
      var out = Object.assign({}, base);
      Object.keys(over).forEach(function (k) { out[k] = k in base ? merge(base[k], over[k]) : clone(over[k]); });
      return out;
    }
    return clone(over);
  }
  function loadPolicy(user, opts) {
    opts = opts || {};
    user = user || {};
    if (!isObj(user)) throw new Error("a policy must be a JSON object");
    var pol = merge(DEFAULT_POLICY, user);
    if (!pol.home) pol.home = opts.home || "/home/you";
    if (!pol.workspace) pol.workspace = opts.workspace || pol.home + "/project";
    if (["deny", "allow", "elicit", "team"].indexOf(pol.on_ask) < 0) throw new Error("on_ask must be deny, allow, elicit or team");
    var wait = pol.approval_timeout === undefined ? 120 : pol.approval_timeout;
    if (typeof wait !== "number" || !Number.isInteger(wait) || wait < 10 || wait > 900) throw new Error("approval_timeout must be a whole number of seconds from 10 to 900");
    if (["ask", "deny"].indexOf(pol.fail_mode) < 0) throw new Error("fail_mode must be ask or deny (Verfy never fails open)");
    if (["ask", "deny", "allow"].indexOf((pol.lock || {}).on_new) < 0) throw new Error("lock.on_new must be ask, deny or allow");
    return pol;
  }

  /* ============================================================ scanner */
  var WEIGHTS = { critical: 45, high: 20, medium: 8, low: 3, info: 0 };
  function grade(score) { return score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F"; }

  function extractTools(data) {
    if (isObj(data)) {
      if (isObj(data.result)) data = data.result;
      if ("tools" in data) data = data.tools;
      else if ("name" in data) data = [data];
    }
    if (!Array.isArray(data)) throw new Error('expected a tools/list result, {"tools": [...]} or a list of tools');
    var tools = data.filter(isObj);
    if (tools.length !== data.length) throw new Error("every tool must be a JSON object");
    return tools;
  }
  // pinned when a server sends them: clients act on annotations, and a title or output schema can reach the model
  var PINNED_EXTRAS = ["title", "annotations", "outputSchema"];
  function toolPin(tool) {
    var d = { name: tool.name !== undefined ? tool.name : "", description: tool.description || "", inputSchema: tool.inputSchema !== undefined ? tool.inputSchema : null };
    PINNED_EXTRAS.forEach(function (k) { if (tool[k] !== undefined && tool[k] !== null) d[k] = tool[k]; });
    return digest(d);
  }
  function capabilities(tool) {
    var nameWords = setOf(words(tool.name || "")), joined = words(tool.name || "").join("_");
    var props = (isObj(tool.inputSchema) && tool.inputSchema.properties) || {};
    var params = isObj(props) ? setOf(Object.keys(props).map(function (k) { return k.toLowerCase(); })) : {};
    var caps = [];
    Object.keys(PATTERNS.capabilities).forEach(function (cap) {
      var spec = PATTERNS.capabilities[cap];
      var hit = spec.name.some(function (w) { return nameWords[w] || w === joined; }) || spec.params.some(function (p) { return params[p]; });
      if ((cap === "fs_write" || cap === "fs_read") && hit && !spec.params.length) {
        var pathLike = PATTERNS.path_keys.some(function (k) { return params[k]; });
        hit = pathLike || nameWords.file || nameWords.files || nameWords.directory;
      }
      if (hit) caps.push(cap);
    });
    return caps;
  }
  function texts(tool) {
    var out = [];
    ["title", "description"].forEach(function (k) { if (typeof tool[k] === "string") out.push([k, tool[k]]); });
    if (tool.inputSchema !== undefined && tool.inputSchema !== null) {
      flattenStrings(tool.inputSchema).forEach(function (pv) {
        if (!/\.type$/.test(pv[0]) && pv[0] !== "type") out.push(["inputSchema." + pv[0], pv[1]]);
      });
    }
    ["annotations", "outputSchema"].forEach(function (key) {
      if (tool[key] !== undefined && tool[key] !== null) {
        flattenStrings(tool[key]).forEach(function (pv) {
          if (!/\.type$/.test(pv[0]) && pv[0] !== "type") out.push([key + "." + pv[0], pv[1]]);
        });
      }
    });
    return out;
  }

  var LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };
  function isTag(cp) { return cp >= 0xE0020 && cp <= 0xE007E; }
  // the same text with common disguises taken off: invisible characters, Unicode tags, leet, spaced letters, base64
  function variants(text) {
    var out = [], plain = "";
    for (var ch of text) {
      var cp = ch.codePointAt(0);
      if (isTag(cp)) plain += String.fromCodePoint(cp - 0xE0000);
      else if (!isInvisible(cp)) plain += ch;
    }
    if (plain !== text) out.push(plain);
    out.push(plain.replace(/[013457@$]/g, function (c) { return LEET[c]; }));
    var spaced = plain.replace(/(?<![A-Za-z])[A-Za-z](?: {1,2}[A-Za-z]){4,}(?![A-Za-z])/g, function (m) { return m.replace(/ {2}/g, "\u0000").replace(/ /g, "").replace(/\u0000/g, " "); });
    if (spaced !== plain) out.push(spaced);
    (plain.match(/[A-Za-z0-9+/]{24,}={0,2}/g) || []).forEach(function (blob) {
      var bare = blob.replace(/=+$/, "");
      if (bare.length % 4 === 1) return;
      try {
        var raw = atob(bare + "===".slice(0, (4 - bare.length % 4) % 4));
        if (/^[\t\r\n\x20-\x7e]+$/.test(raw)) out.push(raw);
      } catch (e) { /* not base64 */ }
    });
    return out.filter(function (v, i) { return v !== text && out.indexOf(v) === i; });
  }

  // "Do not include API keys" is the opposite of asking for them: a match right after a negation is skipped
  var NEGATION = /\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|shouldn'?t|avoid|no)\s+(?:[A-Za-z']+\s+){0,2}$/i;
  function affirmed(pattern, flags, text) {
    var re = rx(pattern, flags, true), m;
    while ((m = re.exec(text)) !== null) {
      if (m[0] === "") { re.lastIndex++; continue; }
      var before = text.slice(Math.max(0, m.index - 40), m.index).split(/[.!?\n]/).pop();
      if (!NEGATION.test(before)) return true;
    }
    return false;
  }

  async function scanTool(tool, allNames, pins) {
    var findings = [];
    function add(rule, severity, message, where) {
      where = where || "";
      for (var i = 0; i < findings.length; i++) {
        var f = findings[i];
        if (f.rule === rule && f.where === where && f.message === message) return;
      }
      findings.push({ rule: rule, severity: severity, message: message, where: where });
    }
    var name = tool.name !== undefined ? tool.name : "";
    if (typeof name === "string" && /[A-Za-z]/.test(name) && Array.from(name).some(function (c) { return c.codePointAt(0) > 127; })) {
      add("VFY-SCAN-016", "high", "The tool name mixes Latin with look-alike letters from another script.", "name");
    }
    texts(tool).forEach(function (wt) {
      var where = wt[0], text = wt[1];
      PATTERNS.scan_text.forEach(function (r) { if (affirmed(r[2], r[3], text)) add(r[0], r[1], r[4], where); });
      variants(text).forEach(function (variant) {
        PATTERNS.scan_text.forEach(function (r) {
          if ((r[1] === "critical" || r[1] === "high") && affirmed(r[2], r[3], variant) && !affirmed(r[2], r[3], text)) add(r[0], r[1], r[4] + " It was disguised.", where);
        });
      });
      var bad = {};
      for (var ch of text) { var cp = ch.codePointAt(0); if (isInvisible(cp)) bad["U+" + cp.toString(16).toUpperCase().padStart(4, "0")] = 1; }
      var badList = Object.keys(bad).sort();
      if (badList.length) add("VFY-SCAN-003", "high", "Contains invisible characters (" + badList.slice(0, 4).join(", ") + ") that can hide text from people.", where);
      if (rx("[A-Za-z0-9+/]{60,}={0,2}").test(text) || rx("(?:[0-9a-fA-F]{2}){40,}").test(text)) add("VFY-SCAN-005", "medium", "Contains a long encoded blob that people cannot read.", where);
      scanSecrets(text).forEach(function (s) { add("VFY-SCAN-013", "high", "Contains a " + s.label + ".", where); });
      if (rx("https?://", "i").test(text)) add("VFY-SCAN-008", "low", "Links to an outside URL, which can change after review.", where);
    });
    var desc = tool.description || "";
    if (typeof desc === "string") {
      var dlen = Array.from(desc).length;
      if (dlen > 1500) add("VFY-SCAN-010", "low", "Description is " + dlen + " characters long, a common place to hide instructions.", "description");
      if (!desc.trim()) add("VFY-SCAN-009", "low", "Has no description, so people cannot tell what it does.", "description");
    }
    var schema = tool.inputSchema;
    if (!isObj(schema)) add("VFY-SCAN-007", "low", "Has no input schema, so any arguments are accepted.", "inputSchema");
    else {
      if (schema.type !== "object") add("VFY-SCAN-007", "low", "Input schema is not an object.", "inputSchema");
      var props = isObj(schema.properties) ? schema.properties : {};
      var required = Array.isArray(schema.required) ? schema.required : [];
      Object.keys(props).forEach(function (p) {
        if (/ssh|private[_-]?key|seed[_-]?phrase|mnemonic|contents?[_-]of/i.test(p)) add("VFY-SCAN-017", "high", "The parameter name `" + p + "` asks for a key or the contents of a file.", "inputSchema.properties." + p);
        if (has(PATTERNS.exfil_params, p.toLowerCase()) && has(required, p)) add("VFY-SCAN-006", "medium", "Requires a free-form `" + p + "` parameter, a known side channel for leaking data.", "inputSchema.properties." + p);
      });
      if (has(capabilities(tool), "exec")) {
        Object.keys(props).forEach(function (p) {
          var spec = props[p];
          if (has(PATTERNS.command_keys, p.toLowerCase()) && isObj(spec) && spec.type === "string" && !spec.enum && !spec.pattern) add("VFY-SCAN-011", "low", "Runs any command passed in `" + p + "`. Pair it with a pre-check policy.", "inputSchema.properties." + p);
        });
      }
    }
    var caps = capabilities(tool);
    var ann = isObj(tool.annotations) ? tool.annotations : {};
    if (ann.readOnlyHint === true && caps.some(function (c) { return has(["exec", "fs_write", "payment", "messaging"], c); })) add("VFY-SCAN-012", "medium", "Says it is read-only, but its name and parameters say it changes things.", "annotations.readOnlyHint");
    if (ann.destructiveHint === false && words(name).some(function (w) { return has(PATTERNS.verbs["delete"], w); })) add("VFY-SCAN-012", "medium", "Says it is not destructive, but its name says it deletes.", "annotations.destructiveHint");

    var pin = await toolPin(tool), pinStatus = null;
    if (pins) {
      var known = pins[name];
      if (known === undefined || known === null) pinStatus = "new";
      else if (known === pin) pinStatus = "ok";
      else { pinStatus = "changed"; add("VFY-SCAN-014", "critical", "Its definition changed since you approved it (possible rug pull).", ""); }
    }
    var score = 100;
    findings.forEach(function (f) { score -= WEIGHTS[f.severity]; });
    score = Math.max(0, score);
    if (findings.some(function (f) { return f.severity === "critical"; })) score = Math.min(score, 39);
    findings.sort(function (a, b) { return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]; });
    return { name: name, sha256: pin, pin: pinStatus, capabilities: caps, score: score, grade: grade(score), findings: findings };
  }

  async function scan(data, server, pins) {
    var tools = extractTools(data);
    var names = tools.map(function (t) { return String(t.name !== undefined ? t.name : ""); });
    var results = [];
    for (var i = 0; i < tools.length; i++) results.push(await scanTool(tools[i], names, pins || null));
    var seen = {};
    results.forEach(function (r) {
      if (seen[r.name]) {
        r.findings.push({ rule: "VFY-SCAN-015", severity: "medium", message: "Another tool on this server has the same name.", where: "name" });
        r.score = Math.max(0, r.score - WEIGHTS.medium);
        r.grade = grade(r.score);
      }
      seen[r.name] = true;
    });
    var summary = { critical: 0, high: 0, medium: 0, low: 0 };
    results.forEach(function (r) { r.findings.forEach(function (f) { if (f.severity in summary) summary[f.severity]++; }); });
    var score = results.length ? Math.min.apply(null, results.map(function (r) { return r.score; })) : 100;
    var removed = pins ? Object.keys(pins).filter(function (n) { return !has(names, n); }).sort() : [];
    return { v: "verfy.scan/1", server: server || "server", score: score, grade: grade(score), tool_count: results.length, summary: summary, tools: results, removed_tools: removed };
  }
  function unsafeTools(report) {
    return report.tools.filter(function (t) { return t.pin === "changed" || t.findings.some(function (f) { return f.severity === "critical"; }); }).map(function (t) { return t.name; });
  }

  /* ============================================================ pre-check */
  var SHELLS = ["sh", "bash", "zsh", "dash", "ksh", "fish"];
  var WRAPPERS = ["nohup", "time", "command", "builtin", "exec", "nice", "ionice", "stdbuf", "timeout", "watch", "caffeinate", "busybox", "toybox", "strace", "ltrace", "unshare", "setsid", "flock", "chroot", "parallel"];
  var SHELL_WORDS = ["if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac", "{", "}", "!", "coproc"];
  var FIND_FILTERS = ["-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-newer", "-mtime", "-mmin", "-size"];
  var BAD_SCHEMES = ["gopher", "dict", "ldap", "ldaps", "tftp", "netdoc", "jar"];
  var PRIVATE_HOST = /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|169\.254\.|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/;
  var NETWORK_CMDS = ["curl", "wget", "nc", "ncat", "netcat", "scp", "rsync", "ftp", "sftp", "http", "https", "httpie", "telnet", "socat", "aria2c", "Invoke-WebRequest", "iwr", "irm"];
  var READERS = ["cat", "less", "more", "head", "tail", "base64", "xxd", "od", "strings", "grep", "egrep", "rg", "awk", "sed", "cut", "sort", "uniq", "tac", "nl", "bat", "jq", "gpg", "openssl", "cp", "scp", "rsync", "tar", "zip", "7z", "source", "."];
  var SYSTEM_DIRS = ["/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var", "/System", "/Library", "/Applications", "/Users", "/private"];
  var WINDOWS_DIRS = ["/c/windows", "/c/program files", "/c/program files (x86)", "/c/programdata", "/c/users"];
  var SECRET_ENV = "\\$\\{?[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE|CREDENTIAL|ACCESS_KEY|AUTH)[A-Za-z0-9_]*\\}?";
  var CONTENT_KEYS = ["content", "contents", "text", "data", "body", "new_string", "old_string", "patch", "diff", "new_str", "file_text", "edits"];
  var EXAMPLE_SUFFIXES = [".example", ".sample", ".template", ".dist"];
  var PUBLISH = {
    npm: ["publish", "unpublish", "deprecate"], pnpm: ["publish"], yarn: ["publish", "npm"],
    twine: ["upload"], cargo: ["publish", "yank"], gem: ["push", "yank"], poetry: ["publish"],
    flit: ["publish"], docker: ["push"], podman: ["push"],
    kubectl: ["delete", "apply", "replace", "scale", "rollout", "drain", "edit", "patch", "create", "cordon", "taint"],
    helm: ["install", "upgrade", "uninstall", "delete", "rollback"],
    terraform: ["apply", "destroy", "import", "taint"], tofu: ["apply", "destroy", "import"],
    pulumi: ["up", "destroy", "update"], fly: ["deploy", "destroy"], flyctl: ["deploy", "destroy"],
    firebase: ["deploy"], wrangler: ["deploy", "publish"], serverless: ["deploy", "remove"],
    sls: ["deploy", "remove"], heroku: ["destroy", "releases:rollback", "ps:scale", "config:set", "apps:destroy"]
  };
  function F(rule, verdict, message) { return { rule: rule, verdict: verdict, message: message }; }
  var ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
  function basename(a) { var i = a.lastIndexOf("/"); return i >= 0 ? a.slice(i + 1) : a; }

  function tokenize(cmd) {
    var segs = [], pipe = 0, cur = { argv: [], out: [], inp: [], pipe: 0 };
    var tok = [], hasTok = false, redirect = null, i = 0, n = cmd.length, q = null, depth = 0;
    function endToken() {
      if (hasTok) {
        var t = tok.join("");
        if (redirect) {
          if (redirect !== "skip" && t.charAt(0) !== "&") cur[redirect].push(t);
          redirect = null;
        } else cur.argv.push(t);
      }
      tok = []; hasTok = false;
    }
    function endSeg(newPipe) {
      endToken();
      if (cur.argv.length || cur.out.length || cur.inp.length) segs.push(cur);
      if (newPipe) pipe++;
      cur = { argv: [], out: [], inp: [], pipe: pipe };
    }
    while (i < n) {
      var c = cmd.charAt(i);
      if (q === "'") { if (c === "'") q = null; else tok.push(c); i++; continue; }
      if (q === '"') {
        if (c === "\\" && i + 1 < n && '$`"\\\n'.indexOf(cmd.charAt(i + 1)) >= 0) { tok.push(cmd.charAt(i + 1)); i += 2; continue; }
        if (c === '"') q = null; else tok.push(c);
        i++; continue;
      }
      if (depth > 0) {
        tok.push(c);
        if (c === "(") depth++; else if (c === ")") depth--;
        i++; continue;
      }
      if (c === "\\" && i + 1 < n) { tok.push(cmd.charAt(i + 1)); hasTok = true; i += 2; continue; }
      if (c === "'" || c === '"') { q = c; hasTok = true; i++; continue; }
      if (c === "$" && i + 1 < n && cmd.charAt(i + 1) === "(") { tok.push("$("); hasTok = true; depth = 1; i += 2; continue; }
      if (c === "`") {
        var j = cmd.indexOf("`", i + 1);
        if (j < 0) j = n;
        tok.push(cmd.slice(i, j + 1)); hasTok = true; i = j + 1; continue;
      }
      if (c === " " || c === "\t") { endToken(); i++; continue; }
      if (c === "\n" || c === ";") { endSeg(true); i++; continue; }
      if (c === "&") {
        if (i + 1 < n && cmd.charAt(i + 1) === "&") { endSeg(true); i += 2; continue; }
        if (i + 1 < n && cmd.charAt(i + 1) === ">") {
          endToken(); redirect = "out";
          i += 2 + (i + 2 < n && cmd.charAt(i + 2) === ">" ? 1 : 0);
          continue;
        }
        if (tok.length && "<>".indexOf(tok[tok.length - 1]) >= 0 && tok[tok.length - 1] !== "") { tok.push(c); i++; continue; }
        endSeg(true); i++; continue;
      }
      if (c === "|") {
        if (i + 1 < n && cmd.charAt(i + 1) === "|") { endSeg(true); i += 2; continue; }
        endSeg(false); i++; continue;
      }
      if (c === "(" || c === ")") { endSeg(true); i++; continue; }
      if (c === "<" || c === ">") {
        var digits = tok.join("");
        if (hasTok && !/^[0-9]+$/.test(digits)) endToken();
        else { tok = []; hasTok = false; }
        var kind = c === ">" ? "out" : "inp";
        i++;
        if (i < n && ">|".indexOf(cmd.charAt(i)) >= 0) i++;
        if (i < n && cmd.charAt(i) === "&") { kind = "skip"; i++; }
        else if (c === "<" && i < n && cmd.charAt(i) === "<") { kind = "skip"; i++; }
        redirect = kind;
        continue;
      }
      tok.push(c); hasTok = true; i++;
    }
    endSeg(false);
    return segs;
  }

  function normalizeSeg(seg) {
    var argv = seg.argv.slice();
    var s = { name: "", args: [], out: seg.out, inp: seg.inp, pipe: seg.pipe, sudo: false, xargs: false };
    var opt;
    while (argv.length) {
      var a = argv[0];
      if (ASSIGN.test(a) || has(SHELL_WORDS, a)) { argv.shift(); continue; }
      if (a === "function") { argv.splice(0, 2); continue; }
      var base = basename(a);
      if (base === "sudo" || base === "doas") {
        s.sudo = true; argv.shift();
        while (argv.length && argv[0].charAt(0) === "-") {
          opt = argv.shift();
          if (has(["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"], opt) && argv.length) argv.shift();
        }
        continue;
      }
      if (base === "env") {
        argv.shift();
        while (argv.length && (argv[0].charAt(0) === "-" || ASSIGN.test(argv[0]))) argv.shift();
        if (!argv.length) { s.name = "env"; return s; }
        continue;
      }
      if (base === "xargs") {
        s.xargs = true; argv.shift();
        while (argv.length && argv[0].charAt(0) === "-") {
          opt = argv.shift();
          if (has(["-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a"], opt) && argv.length) argv.shift();
        }
        continue;
      }
      if (has(WRAPPERS, base)) {
        argv.shift();
        while (argv.length && argv[0].charAt(0) === "-") {
          opt = argv.shift();
          if (has(["-n", "-s", "-k", "-c"], opt) && argv.length) argv.shift();
        }
        if (base === "timeout" && argv.length && /^\d/.test(argv[0])) argv.shift();
        if ((base === "flock" || base === "chroot") && argv.length) argv.shift();
        if (base === "parallel") argv = argv.filter(function (x) { return x !== ":::"; });
        continue;
      }
      break;
    }
    if (argv.length) { s.name = basename(argv[0]).replace(/\.exe$/, ""); s.args = argv.slice(1).map(homeArg); }
    s.out = s.out.map(function (x) { return typeof x === "string" ? homeArg(x) : x; });
    s.inp = s.inp.map(function (x) { return typeof x === "string" ? homeArg(x) : x; });
    return s;
  }

  var SSH_OPTS = ["-i", "-p", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-W", "-b", "-c", "-E", "-e", "-m", "-O", "-Q", "-S", "-w"];
  function parseShell(cmd, depth) {
    depth = depth || 0;
    var out = [];
    tokenize(cmd).forEach(function (raw) {
      var s = normalizeSeg(raw);
      s.depth = depth;
      out.push(s);
      if (depth >= 3) return;
      var inner = null;
      if (has(SHELLS, s.name) && has(s.args, "-c")) {
        var k = s.args.indexOf("-c");
        if (k + 1 < s.args.length) inner = s.args[k + 1];
      } else if (s.name === "eval" && s.args.length) inner = s.args.join(" ");
      else if (s.name === "alias") inner = s.args.filter(function (x) { return x.indexOf("=") >= 0; }).map(function (x) { return x.slice(x.indexOf("=") + 1); }).join(" ");
      else if ((s.name === "script" || s.name === "su") && has(s.args, "-c")) {
        var kc = s.args.indexOf("-c");
        if (kc + 1 < s.args.length) inner = s.args[kc + 1];
      } else if (s.name === "find") inner = findExec(s.args);
      else if (has(["powershell", "pwsh", "cmd"], s.name.toLowerCase().replace(/\.exe$/, ""))) {
        var low = s.args.map(function (x) { return x.toLowerCase(); });
        var kp = -1;
        ["-c", "-command", "/c", "/k"].forEach(function (f) { if (kp < 0 && has(low, f)) kp = low.indexOf(f); });
        if (kp >= 0 && kp + 1 < s.args.length) inner = s.args.slice(kp + 1).join(" ");
      } else if (s.name === "ssh") {
        var ops = [], skip = false;
        s.args.forEach(function (a) {
          if (skip) { skip = false; return; }
          if (a.charAt(0) === "-") { skip = has(SSH_OPTS, a); return; }
          ops.push(a);
        });
        if (ops.length >= 2) inner = ops.slice(1).join(" ");
      }
      if (inner) parseShell(inner, depth + 1).forEach(function (x) { x.sudo = x.sudo || (s.name !== "ssh" && s.sudo); out.push(x); });
      s.args.concat([s.name]).forEach(function (t) {
        var r = /\$\(([^()]*)\)|`([^`]*)`/g, m;
        while ((m = r.exec(t)) !== null) {
          var body = m[1] !== undefined ? m[1] : m[2];
          if (body && body.trim()) out = out.concat(parseShell(body, depth + 1));
        }
      });
    });
    return out;
  }

  // what `find -exec` runs, with {} as the folder it starts from, unless that would make a narrow delete look wide
  function findExec(args) {
    var root = args.filter(function (x) { return x.charAt(0) !== "-"; })[0];
    if (root === undefined) root = ".";
    var flags = ["-exec", "-execdir", "-ok", "-okdir"];
    for (var i = 0; i < flags.length; i++) {
      if (!has(args, flags[i])) continue;
      var body = [], rest = args.slice(args.indexOf(flags[i]) + 1);
      for (var j = 0; j < rest.length; j++) {
        if (rest[j] === ";" || rest[j] === "+") break;
        body.push(rest[j] === "{}" && body[0] !== "rm" ? root : rest[j]);
      }
      return body.length ? commandString(body) : null;
    }
    return null;
  }

  function findNarrow(args) {
    return args.some(function (x, i) { return has(FIND_FILTERS, x) && i + 1 < args.length && args[i + 1] !== "*" && args[i + 1] !== "*.*"; });
  }

  function braces(word) {
    var m = /\{([^{}]*,[^{}]*)\}/.exec(word);
    if (!m) return [word];
    return m[1].split(",").map(function (x) { return word.slice(0, m.index) + x + word.slice(m.index + m[0].length); });
  }

  // everything in a command that looks like a path, however it got there: a variable, $(...), a loop, a Windows path
  function named(cmd, segs) {
    var found = cmd.match(/[^\s'"`;|&()<>=,]+/g) || [];
    segs.forEach(function (s) {
      s.args.concat(s.inp, s.out).forEach(function (t) {
        if (typeof t === "string") found = found.concat(t.split("="));
      });
      if (s.name === "find") { // `find ~ -name id_rsa` names that file
        var root = s.args.filter(function (x) { return x.charAt(0) !== "-"; })[0];
        if (root === undefined) root = ".";
        s.args.slice(0, -1).forEach(function (x, i) { if (x === "-name" || x === "-iname") found.push(root + "/" + s.args[i + 1]); });
      }
    });
    var out = [];
    found.forEach(function (w) {
      braces(w).forEach(function (x) {
        var h = homeVars(x.replace(/\\/g, "/")).split("$")[0].split("`")[0];
        if (h.indexOf("://") < 0 && h && (h.charAt(0) === "~" || h.charAt(0) === "/" || h.indexOf("/") >= 0) && out.indexOf(h) < 0) out.push(h);
      });
    });
    return out;
  }

  // the command with a=x put in where $a is used, so that a value in a variable is still seen
  function substituted(cmd) {
    var out = cmd, re = /(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=([^\s;&|)]+)/g, m;
    while ((m = re.exec(cmd)) !== null) {
      var value = m[2].replace(/^['"]+|['"]+$/g, "");
      out = out.replace(new RegExp("\\$(?:" + m[1] + "\\b|\\{" + m[1] + "\\})", "g"), function () { return value; });
    }
    return out;
  }

  function operands(args) {
    var out = [], end = false;
    args.forEach(function (a) {
      if (!end && a === "--") { end = true; return; }
      if (!end && a.charAt(0) === "-" && a !== "-") return;
      out.push(a);
    });
    return out;
  }
  function written(s) {
    var p = s.out.slice(), n = s.name, a = s.args, ops = operands(a);
    if (has(["cp", "mv", "install", "ln"], n) && ops.length >= 2) { p.push(ops[ops.length - 1]); if (n === "mv") p = p.concat(ops.slice(0, -1)); }
    else if (n === "rsync" && ops.length >= 2) p.push(ops[ops.length - 1]);
    else if (n === "tee") p = p.concat(ops);
    else if (has(["rm", "unlink", "rmdir", "shred", "truncate", "touch"], n)) p = p.concat(ops);
    else if (has(["chmod", "chown", "chgrp"], n)) p = p.concat(ops.slice(1));
    else if (n === "sed" && a.some(function (x) { return x === "-i" || (x.indexOf("-i") === 0 && x.indexOf("--") !== 0) || x.indexOf("--in-place") === 0; })) p = p.concat(ops.slice(1));
    else if (n === "dd") a.forEach(function (x) { if (x.indexOf("of=") === 0) p.push(x.slice(3)); });
    return p.filter(function (x) { return x && x.indexOf("://") < 0 && (/^[A-Za-z]:[\\/]/.test(x) || !/^[^/]*@?[^/]+:/.test(x)); });
  }
  function readPaths(s) {
    var p = s.inp.slice();
    if (has(READERS, s.name)) {
      var ops = operands(s.args);
      if (has(["grep", "egrep", "rg", "sed", "awk", "jq"], s.name) && ops.length) ops = ops.slice(1);
      if (has(["cp", "scp", "rsync"], s.name) && ops.length >= 2) ops = ops.slice(0, -1);
      p = p.concat(ops);
    }
    if (s.name === "dd") s.args.forEach(function (x) { if (x.indexOf("if=") === 0) p.push(x.slice(3)); });
    return p.filter(function (x) { return x && x.indexOf("://") < 0; });
  }
  function uploads(s) {
    var n = s.name, a = s.args, out = [], m;
    if (has(["curl", "http", "httpie"], n)) {
      a.forEach(function (x, i) {
        if (has(["-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form"], x) && i + 1 < a.length) {
          var v = a[i + 1];
          if (v.charAt(0) === "@") out.push(v.slice(1));
          m = /=@([^;]+)/.exec(v) || /=<([^;]+)/.exec(v);
          if (m) out.push(m[1]);
        }
        if ((x === "-T" || x === "--upload-file") && i + 1 < a.length) out.push(a[i + 1]);
        if (n !== "curl" && (m = /^[^=@]+@(.+)$/.exec(x))) out.push(m[1]);
      });
    } else if (n === "wget") {
      a.forEach(function (x) { if (x.indexOf("--post-file=") === 0 || x.indexOf("--body-file=") === 0) out.push(x.split("=").slice(1).join("=")); });
    } else if (has(["scp", "rsync", "sftp"], n)) {
      var ops = operands(a);
      if (ops.length >= 2 && ops[ops.length - 1].indexOf(":") >= 0) ops.slice(0, -1).forEach(function (o) { if (o.indexOf(":") < 0) out.push(o); });
    }
    return out.filter(function (x) { return x && x !== "-"; });
  }
  function envDump(s) {
    var n = s.name, a = s.args;
    if (n === "env") return !operands(a).length;
    if (n === "printenv") return true;
    if (n === "export" && (!a.length || (a.length === 1 && a[0] === "-p"))) return true;
    if (n === "declare" && (has(a, "-x") || has(a, "-p"))) return true;
    if (n === "set" && !a.length) return true;
    return false;
  }
  function urls(text) { return (text || "").match(/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s'"<>`]+/g) || []; }

  function Ctx(policy) {
    this.p = policy;
    this.home = normpath(toPosix(policy.home));
    // a home folder on a drive letter means Windows, where file names ignore case
    this.win = /^\/[a-z](?:\/|$)/.test(this.home);
    if (this.win) this.home = this.home.toLowerCase();
    this.ws = this.path(policy.workspace, "/");
    this.vdir = this.path("~/.verfy");
  }
  Ctx.prototype.path = function (p, cwd) {
    var out = resolve(p, this.home, cwd || this.ws);
    return this.win ? out.toLowerCase() : out;
  };
  Ctx.prototype.match = function (patterns, path) {
    patterns = patterns || [];
    for (var i = 0; i < patterns.length; i++) {
      if (firstMatch([this.win ? toPosix(patterns[i]).toLowerCase() : patterns[i]], path, this.home) !== null) return patterns[i];
    }
    return null;
  };
  Ctx.prototype.sensitive = function (path) {
    var base = basename(path);
    if (EXAMPLE_SUFFIXES.some(function (s) { return base.slice(-s.length) === s; })) return null;
    // never by case: macOS and Windows ignore it, so ~/.AWS is ~/.aws there
    var low = path.toLowerCase(), home = this.home.toLowerCase(), list = this.p.files.sensitive;
    for (var i = 0; i < list.length; i++) {
      if (firstMatch([toPosix(list[i]).toLowerCase()], low, home) !== null) return list[i];
    }
    return null;
  };
  Ctx.prototype.protected_ = function (path) { return this.match(this.p.files.deny_write, path); };
  Ctx.prototype.guardsVerfy = function (path) {
    var verdicts = ["deny", "ask"];
    for (var i = 0; i < verdicts.length; i++) {
      var hit = this.match(PATTERNS.self_protect[verdicts[i]], path);
      if (hit !== null) return [verdicts[i], hit];
    }
    return null;
  };
  // Verfy's folder in the home folder, or the signing key or device token in it
  Ctx.prototype.verfySecret = function (path) {
    var vdir = this.vdir;
    return path === vdir || PATTERNS.self_protect.secret.files.some(function (f) { return path === vdir + "/" + f; });
  };
  // a folder Verfy's folder is inside (the home folder, "/", ...)
  Ctx.prototype.holdsVerfy = function (path) { return path !== this.vdir && isWithin(this.vdir, path); };
  Ctx.prototype.allowedOutside = function (path) { return this.match(this.p.files.allow_write, path) !== null; };
  Ctx.prototype.catastrophic = function (path) {
    if (this.win && (/^\/[a-z]$/.test(path) || has(WINDOWS_DIRS, path))) return true;
    return path === "/" || path === this.home || path === this.ws || has(SYSTEM_DIRS, path) || isWithin(this.ws, path);
  };

  var SECRET_MSG = " With them an agent can sign its own receipts or upload as this device. Run it yourself if you meant it.";
  // $HOME/x, %USERPROFILE%\x and the like as ~/x, so they resolve like ~
  function homeVars(p) { return p.replace(/^(?:\$HOME|\$\{HOME\}|\$USERPROFILE|\$\{USERPROFILE\}|%USERPROFILE%|%HOMEPATH%|%HOME%|\$env:USERPROFILE|\$env:HOME|\$env:HOMEPATH|\$\{env:USERPROFILE\})(?=$|[\\/])/i, "~"); }
  // `$HOME/x` in a command, also after `if=`, so that a path check cannot be walked around by spelling home differently
  function homeArg(p) {
    var m = /^((?:if|of)=)(.*)$/.exec(p);
    return m ? m[1] + homeVars(m[2]) : homeVars(p);
  }
  function resolvable(p, here) { return p.indexOf("$") < 0 && p.indexOf("`") < 0 && (here !== null || p.charAt(0) === "/" || p.charAt(0) === "~"); }
  // a finding when one command reads, copies or looks for Verfy's signing key or device token
  function verfySecret(s, ctx, here) {
    var sec = PATTERNS.self_protect.secret, parts = [], i, p, h;
    [s.name].concat(s.args, s.inp, s.out).forEach(function (t) {
      [t].concat(t.split("=").slice(1)).forEach(function (x) { if (x) parts.push(x); });
    });
    for (i = 0; i < parts.length; i++) {
      p = parts[i]; h = homeVars(p);
      if (rx(sec.token, "i").test(p) || (resolvable(h, here) && ctx.verfySecret(ctx.path(h, here)))) {
        return F("VFY-SELF-006", "deny", "Reads Verfy's signing key or device token (" + p + ")." + SECRET_MSG);
      }
    }
    var n = s.name.toLowerCase().replace(/\.exe$/, "");
    if (has(sec.finders, n) && parts.slice(1).some(function (x) { return rx(sec.name, "i").test(x); })) {
      return F("VFY-SELF-007", "ask", "Looks for a file named like Verfy's signing key or device token.");
    }
    if (has(sec.readers, n)) {
      var ops = operands(s.args);
      if (has(["cp", "rsync", "scp", "robocopy", "xcopy", "copy-item", "cpi"], n) && ops.length >= 2) ops = ops.slice(0, -1); // the last one is where the copy goes
      for (i = 0; i < ops.length; i++) {
        h = homeVars(ops[i]);
        if (resolvable(h, here) && ctx.holdsVerfy(ctx.path(h, here))) return F("VFY-SELF-007", "ask", "Reads or copies " + ops[i] + ", which holds Verfy's signing key and device token.");
      }
    }
    return null;
  }

  function selfFinding(hit, p) {
    if (hit[0] === "deny") return F("VFY-SELF-001", "deny", "Changes " + p + ", which Verfy relies on to guard this agent (`" + hit[1] + "`). Make this change yourself if you meant it.");
    return F("VFY-SELF-002", "ask", "Changes the MCP config " + p + ", which could take a server out from behind the Verfy gateway.");
  }
  function verfyCommand(s) {
    var n = s.name.toLowerCase().replace(/\.exe$/, ""), a = s.args, py = /^python[0-9.]*$|^py$/.test(n);
    if (py && a[0] === "-m" && a[1] === "verfy") { n = "verfy"; a = a.slice(2); }
    if ((n === "uvx" && a[0] === "verfy") || (n === "pipx" && a[0] === "run" && a[1] === "verfy") || (n === "uv" && a[0] === "tool" && a[1] === "run" && a[2] === "verfy")) {
      a = a.slice(a.indexOf("verfy") + 1);
      n = "verfy";
    }
    if (n === "verfy") {
      var w = a.filter(function (x) { return x.charAt(0) !== "-"; });
      if (w[0] === "lock" && (w[1] === "approve" || w[1] === "add")) return F("VFY-SELF-003", "deny", "`verfy " + w.slice(0, 2).join(" ") + "` approves a tool change for the agent. A person has to review and run it.");
      if (w[0] === "lock" && w[1] === "check" && has(a, "--update")) return F("VFY-SELF-003", "deny", "`verfy lock check --update` writes verfy.lock for the agent. A person has to review and run it.");
      if (w[0] === "sandbox" && w[1] === "sync" && has(a, "--write")) return F("VFY-SELF-003", "deny", "`verfy sandbox sync --write` changes Claude Code's settings. A person has to review and run it.");
      if (w[0] === "lock" && w[1] === "rollback" && has(a, "--write")) return F("VFY-SELF-003", "deny", "`verfy lock rollback --write` rewrites an MCP config. A person has to review and run it.");
      if (w[0] === "lock" && w[1] === "files" && has(a, "--update")) return F("VFY-SELF-003", "deny", "`verfy lock files --update` approves changed instruction files for the agent. A person has to review and run it.");
      if (w[0] === "import" && has(a, "--save")) return F("VFY-SELF-003", "deny", "`verfy import --save` changes which tools the Verfy gateway blocks. A person has to review and run it.");
      if (w[0] === "policy" && w[1] === "use") return F("VFY-SELF-003", "deny", "`verfy policy use` replaces the policy Verfy enforces. A person has to choose and run it.");
      if (w[0] === "policy" && w[1] === "trust") return F("VFY-SELF-003", "deny", "`verfy policy trust` lets this folder's policy weaken Verfy. A person has to read it and run this.");
      if (w[0] === "init" && has(a, "--force")) return F("VFY-SELF-003", "deny", "`verfy init --force` replaces the signing key, which starts a new receipt chain.");
      // --url as well as --code: with only --url, the code can come from VERFY_ENROLL_CODE
      if ((w[0] === "team" && w[1] === "enroll") || (w[0] === "init" && a.some(function (x) { var f = x.split("=")[0]; return f === "--url" || f === "--code"; })))
        return F("VFY-SELF-003", "deny", "Connects this device to a Verfy Cloud, which decides where its receipts go. A person has to run it.");
      if (w[0] === "team" && w[1] === "auto-sync" && w[2] === "off") return F("VFY-SELF-003", "deny", "`verfy team auto-sync off` stops this device's receipts from reaching your team. A person has to run it.");
      return null;
    }
    var pip = has(["pip", "pip3", "pipx"], n) || (n === "uv" && (a[0] === "pip" || a[0] === "tool")) || (py && a[0] === "-m" && a[1] === "pip");
    if (pip && has(a, "uninstall") && a.some(function (x) { return x.toLowerCase() === "verfy"; })) return F("VFY-SELF-004", "deny", "Uninstalls Verfy.");
    return null;
  }

  // a host written as a number, or as IPv4 inside IPv6, as the address it reaches, so a deny list sees through it
  function dotted(v) { return [3, 2, 1, 0].map(function (k) { return String(Math.floor(v / Math.pow(256, k)) % 256); }).join("."); }
  function canonHost(host) {
    var m = /^(?:0{0,4}:){0,5}:?ffff:(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/.exec(host);
    if (m) return m[1] ? m[1] : dotted(parseInt(m[2], 16) * 65536 + parseInt(m[3], 16));
    var parts = host.split(".");
    if (parts.length < 1 || parts.length > 4 || !parts.every(function (x) { return /^(?:0x[0-9a-f]+|[0-7]+|[1-9][0-9]*)$/.test(x); })) return host;
    var nums = parts.map(function (x) { return x.indexOf("0x") === 0 ? parseInt(x, 16) : (x.length > 1 && x.charAt(0) === "0" ? parseInt(x, 8) : parseInt(x, 10)); });
    var last = nums.pop();
    if (nums.some(function (n) { return n > 255; }) || last >= Math.pow(256, 4 - nums.length)) return host;
    var v = last;
    nums.forEach(function (n, i) { v += n * Math.pow(256, 3 - i); });
    return dotted(v);
  }
  function urlParts(url) {
    var m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^\/?#]*)([^#]*)/.exec(url);
    if (!m) return null;
    var authority = m[1], rest = m[2], userinfo = "";
    var at = authority.lastIndexOf("@");
    if (at >= 0) { userinfo = authority.slice(0, at); authority = authority.slice(at + 1); }
    var host = authority;
    if (host.charAt(0) === "[") host = host.slice(1).split("]")[0];
    else host = host.split(":")[0];
    return { host: canonHost(host.toLowerCase().replace(/\.+$/, "")), userinfo: userinfo, rest: rest };
  }

  function onAllowList(url, ctx) {
    var parts = urlParts(url);
    return !!parts && ctx.p.network.allow.some(function (p) { return hostMatch(p, parts.host); });
  }

  function checkUrl(url, ctx) {
    var out = [];
    var parts = urlParts(url);
    if (!parts) return out;
    var host = parts.host, userinfo = parts.userinfo, rest = parts.rest;
    var net = ctx.p.network, denied = false;
    var scheme = url.split(":")[0].toLowerCase();
    if (has(BAD_SCHEMES, scheme)) out.push(F("VFY-NET-001", "deny", "`" + scheme + ":` URLs are a way to reach internal services."));
    if (/(?:^|[.-])169[.-]254[.-]169[.-]254(?:[.-]|$)/.test(host) && host !== "169.254.169.254") out.push(F("VFY-NET-001", "deny", "`" + host + "` points at the cloud metadata address."));
    if (PRIVATE_HOST.test(host) && !net.allow.some(function (p) { return hostMatch(p, host); })) out.push(F("VFY-NET-004", "ask", "`" + host + "` is an address on a private network."));
    for (var i = 0; i < net.deny.length; i++) {
      if (hostMatch(net.deny[i], host)) { out.push(F("VFY-NET-001", "deny", "`" + host + "` is on the network deny list (`" + net.deny[i] + "`).")); denied = true; break; }
    }
    if (!denied && net.allow.length && !net.allow.some(function (p) { return hostMatch(p, host); })) {
      var v = net.unknown || "ask";
      if (v === "ask" || v === "deny") out.push(F("VFY-NET-002", v, "`" + host + "` is not on the network allow list."));
    }
    if (userinfo.indexOf(":") >= 0) out.push(F("VFY-NET-003", "deny", "The URL carries a username and password."));
    var qr = /[?&]([^=&#]+)=([^&#]*)/g, qm;
    while ((qm = qr.exec(rest)) !== null) {
      if (/(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|auth|sig(?:nature)?|session)/i.test(qm[1]) && qm[2].length >= 8) {
        out.push(F("VFY-NET-003", "deny", "The URL carries a credential in `" + qm[1] + "`."));
        break;
      }
    }
    return out;
  }

  var ROOTISH = ["/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/", "$HOME/*", "${HOME}/*", "/.", "~/."];
  function deleteTargets(t, ctx, cwd) {
    if (has(ROOTISH, t)) return [F("VFY-SH-001", "deny", "Recursive delete of `" + t + "` would wipe far more than intended.")];
    if (t.indexOf("$") >= 0 || t.indexOf("`") >= 0) return [F("VFY-SH-002", "ask", "Recursive delete of `" + t + "`, a path built from a variable.")];
    if (cwd === null && t.charAt(0) !== "/" && t.charAt(0) !== "~") return [F("VFY-SH-002", "ask", "Recursive delete of `" + t + "` after changing to an unknown folder.")];
    var stripped = has(["*", ".*", "./*"], t) ? "." : t.replace(/(?:\/\*|\/\.\*|\/)+$/, "");
    stripped = stripped || "/";
    var abs = ctx.path(stripped, cwd);
    var wildcardRoot = has(["*", ".*", "./*", "./", ".", "..", "../", "../*"], t) || /\/\*$/.test(t);
    if (ctx.catastrophic(abs)) return [F("VFY-SH-001", "deny", "Recursive delete of `" + t + "` would wipe the system, the home folder or the whole project.")];
    if (!isWithin(abs, ctx.ws) && !ctx.allowedOutside(abs)) return [F("VFY-SH-002", "ask", "Recursive delete of `" + t + "`, which is outside the project.")];
    if (wildcardRoot && abs === ctx.ws) return [F("VFY-SH-001", "deny", "Recursive delete of `" + t + "` would wipe the whole project.")];
    return [];
  }

  function shortFlag(x, ch) { return x.charAt(0) === "-" && x.indexOf("--") !== 0 && x.slice(1).indexOf(ch) >= 0; }
  function gitCommand(args) {
    var a = args.slice();
    while (a.length && a[0].charAt(0) === "-") {
      var opt = a.shift();
      if (has(["-C", "-c", "--git-dir", "--work-tree"], opt) && a.length) a.shift();
    }
    return a;
  }

  function pushes(cmd) {
    return parseShell(cmd).some(function (s) { return s.name === "git" && gitCommand(s.args)[0] === "push"; });
  }

  function gitWhy(args) {
    var a = gitCommand(args);
    if (!a.length) return null;
    var sub = a[0], rest = a.slice(1), ops = operands(rest);
    if (sub === "push") {
      if (rest.some(function (x) { return has(["--force", "-f", "--mirror"], x) || shortFlag(x, "f"); }) || ops.some(function (x) { return x.charAt(0) === "+"; })) return "Force-push rewrites shared history.";
      if (has(rest, "--delete") || has(rest, "-d") || ops.some(function (x) { return x.charAt(0) === ":"; })) return "Deletes a branch on the remote.";
    }
    if (sub === "reset" && has(rest, "--hard")) return "`git reset --hard` throws away uncommitted work.";
    if (sub === "clean" && rest.some(function (x) { return x.charAt(0) === "-" && x.indexOf("--") !== 0 && x.indexOf("f") >= 0; })) return "`git clean -f` deletes untracked files for good.";
    if (sub === "clean" && has(rest, "--force")) return "`git clean --force` deletes untracked files for good.";
    if (sub === "checkout" && (has(ops, ".") || (has(rest, "--") && rest[rest.length - 1] !== "--"))) return "`git checkout --` discards uncommitted changes.";
    if (sub === "restore" && !has(rest, "--staged") && ops.length) return "`git restore` discards uncommitted changes.";
    if (sub === "branch" && (has(rest, "-D") || (has(rest, "--delete") && has(rest, "--force")))) return "Force-deletes a branch, including unmerged work.";
    if (sub === "stash" && rest.length && has(["drop", "clear"], rest[0])) return "Deletes stashed work.";
    if (sub === "filter-branch" || sub === "filter-repo") return "Rewrites the whole repository history.";
    if (sub === "reflog" && rest[0] === "expire") return "Expires the reflog, which removes the way back.";
    if (sub === "update-ref" && has(rest, "-d")) return "Deletes a ref directly.";
    return null;
  }
  var GH_PAIRS = ["release create", "release delete", "repo delete", "repo archive", "pr merge", "secret set", "secret delete"];
  function publishWhy(s) {
    var n = s.name, a = s.args, ops = operands(a), first = ops.length ? ops[0] : "";
    if (PUBLISH.hasOwnProperty(n) && has(PUBLISH[n], first)) return "`" + n + " " + first + "` changes something outside this computer.";
    if ((n === "vercel" || n === "netlify") && (has(a, "--prod") || has(a, "--production"))) return "`" + n + "` deploys to production.";
    if (n === "gh" && ops.length >= 2 && has(GH_PAIRS, ops[0] + " " + ops[1])) return "`gh " + ops[0] + " " + ops[1] + "` changes the shared repository.";
    if (has(["aws", "gcloud", "az", "doctl", "oci"], n) && a.some(function (x) { return /(?:^|-)(?:delete|remove|rm|terminate|destroy|purge|deregister)(?:$|-)/.test(x); })) return "`" + n + "` command deletes cloud resources.";
    if (n === "stripe" && a.some(function (x) { return has(["create", "delete", "update", "post", "refunds", "payouts", "transfers", "charges"], x); })) return "`stripe` command can move money or change billing.";
    return null;
  }

  function checkShell(cmd, ctx, again) {
    if (again === undefined) again = true;
    var out = [], segs = parseShell(cmd), cwd = ctx.ws;
    var network = segs.some(function (s) { return has(NETWORK_CMDS, s.name); });
    var sensitiveReads = [], envDumped = false;
    segs.forEach(function (s) {
      var n = s.name, a = s.args, ops, p, abs, hit;
      var secret = verfySecret(s, ctx, s.depth === 0 ? cwd : ctx.ws);
      if (secret) out.push(secret);
      if (s.depth === 0 && n === "cd") {
        ops = operands(a);
        if (!ops.length) cwd = ctx.home;
        else if (ops[0] === "-" || ops[0].indexOf("$") >= 0 || ops[0].indexOf("`") >= 0) cwd = null;
        else if (cwd !== null || ops[0].charAt(0) === "/" || ops[0].charAt(0) === "~") cwd = ctx.path(ops[0], cwd);
        return;
      }
      var here = s.depth === 0 ? cwd : ctx.ws;
      if (n === "rm") {
        var recursive = a.some(function (x) { return has(["-r", "-R", "--recursive"], x) || (x.charAt(0) === "-" && x.indexOf("--") !== 0 && (x.indexOf("r") >= 0 || x.indexOf("R") >= 0)); });
        if (recursive) {
          var tg = operands(a);
          if (s.xargs && !tg.length) out.push(F("VFY-SH-002", "ask", "Recursive delete of paths that come from a pipeline."));
          tg.forEach(function (t) { out = out.concat(deleteTargets(t, ctx, here)); });
        }
      }
      if (n === "find" && (has(a, "-delete") || (has(a, "-exec") && has(a, "rm")))) {
        var fo = a.filter(function (x) { return x.charAt(0) !== "-"; }).slice(0, 1);
        if (!fo.length) fo = ["."];
        p = here !== null ? ctx.path(fo[0], here) : null;
        if (p === null) out.push(F("VFY-SH-002", "ask", "`find -delete` after changing to an unknown folder."));
        else if (p === ctx.ws && !findNarrow(a)) out.push(F("VFY-SH-002", "ask", "`find " + fo[0] + "` deletes everything in the project."));
        else if (ctx.catastrophic(p) && p !== ctx.ws) out.push(F("VFY-SH-001", "deny", "`find " + fo[0] + " -delete` can wipe the system or home folder."));
        else if (!isWithin(p, ctx.ws) && !ctx.allowedOutside(p)) out.push(F("VFY-SH-002", "ask", "`find " + fo[0] + " -delete` deletes files outside the project."));
      }
      var why;
      if (n === "git" && (why = gitWhy(a))) out.push(F("VFY-SH-004", "ask", why));
      if ((why = publishWhy(s))) out.push(F("VFY-SH-009", "ask", why));
      if (s.sudo) out.push(F("VFY-SH-006", "ask", "`" + (n || "command") + "` runs with administrator rights."));
      if (n === "su") out.push(F("VFY-SH-006", "ask", "Switches user with `su`."));
      if (n === "chmod") {
        ops = operands(a);
        var mode = ops.length ? ops[0] : "";
        if (/^0?[0-7]?[0-7][0-7][2367]$/.test(mode) || /(?:^|,)[ao]*[+=][rwxXst]*w/.test(mode) || /^\+?w$/.test(mode)) out.push(F("VFY-SH-012", "ask", "`chmod " + mode + "` lets every user change these files."));
      }
      var own = verfyCommand(s);
      if (own) out.push(own);
      written(s).forEach(function (wp) {
        if (wp.indexOf("$") >= 0 || wp.indexOf("`") >= 0) return;
        abs = ctx.path(wp, here);
        var mine = ctx.guardsVerfy(abs);
        if (mine) { out.push(selfFinding(mine, wp)); return; }
        hit = ctx.protected_(abs);
        if (hit) out.push(F("VFY-SH-011", "deny", "Changes " + wp + ", which is protected (`" + hit + "`)."));
      });
      readPaths(s).forEach(function (rp) {
        if (rp.indexOf("$") >= 0 || rp.indexOf("`") >= 0) return;
        if (ctx.sensitive(ctx.path(rp, here))) sensitiveReads.push(rp);
      });
      if (envDump(s)) envDumped = true;
      if (has(NETWORK_CMDS, n)) {
        uploads(s).forEach(function (up) {
          if (ctx.sensitive(ctx.path(up, here))) out.push(F("VFY-SH-008", "deny", "Uploads the sensitive file " + up + "."));
          else out.push(F("VFY-SH-015", "ask", "Uploads the local file " + up + "."));
        });
        for (var i = 0; i < a.length; i++) {
          if (rx(SECRET_ENV).test(a[i])) { out.push(F("VFY-SH-008", "deny", "Sends a secret environment variable over the network.")); break; }
        }
      }
    });
    if (!out.some(function (f) { return f.rule === "VFY-SELF-006"; })) {
      var flat = segs.map(function (s) { return [s.name].concat(s.args, s.inp, s.out).join(" "); }).join(" ");
      if (rx(PATTERNS.self_protect.secret.text, "i").test(cmd) || rx(PATTERNS.self_protect.secret.text, "i").test(flat)) {
        out.push(F("VFY-SELF-006", "deny", "Names Verfy's folder and its signing key or device token in one command." + SECRET_MSG));
      }
    }
    sensitiveReads.filter(function (x, i) { return sensitiveReads.indexOf(x) === i; }).forEach(function (p) {
      if (network) out.push(F("VFY-SH-008", "deny", "Reads the sensitive file " + p + " in a command that also uses the network."));
      else out.push(F("VFY-SH-007", "ask", "Reads the sensitive file " + p + "."));
    });
    if (!sensitiveReads.length) {
      var names = named(cmd, segs);
      for (var ni = 0; ni < names.length; ni++) {
        var nabs = ctx.path(names[ni]);
        if (ctx.sensitive(nabs) || ctx.sensitive(nabs + "/x")) { out.push(F("VFY-SH-007", "ask", "Names the sensitive path " + names[ni] + ".")); break; }
      }
    }
    if (envDumped) {
      if (network) out.push(F("VFY-SH-008", "deny", "Prints environment variables in a command that also uses the network."));
      else out.push(F("VFY-SH-007", "ask", "Prints environment variables, which often hold secrets."));
    }
    PATTERNS.shell_patterns.forEach(function (r) {
      if (out.some(function (f) { return f.rule === r[0]; })) return;
      if (rx(r[2], r[3]).test(cmd)) out.push(F(r[0], r[1], r[4]));
    });
    if (network) urls(cmd).forEach(function (u) { out = out.concat(checkUrl(u, ctx)); });
    var plain = substituted(cmd);
    if (again && plain !== cmd) {
      var more = checkShell(plain, ctx, false);
      out = out.concat(more[0]);
      network = network || more[1];
    }
    return [out, network];
  }

  function num(v) {
    if (typeof v === "boolean") return null;
    if (typeof v === "number") return v;
    if (typeof v === "string" && /^\s*-?\d+(?:\.\d+)?\s*$/.test(v)) return parseFloat(v);
    return null;
  }
  function commandString(v) {
    if (typeof v === "string") return v;
    if (Array.isArray(v) && v.every(function (x) { return typeof x === "string"; })) {
      return v.map(function (x) { return /^[A-Za-z0-9_.\/=:@%+,-]+$/.test(x) ? x : "'" + x.replace(/'/g, "'\\''") + "'"; }).join(" ");
    }
    return null;
  }
  function lowerKeys(args) { var o = {}; Object.keys(args).forEach(function (k) { o[String(k).toLowerCase()] = args[k]; }); return o; }

  function classify(tool, args) {
    var w = setOf(words(String(tool).split("/").pop()));
    var keys = lowerKeys(args), keyList = Object.keys(keys);
    var verbs = PATTERNS.verbs, execWords = setOf(PATTERNS.capabilities.exec.name);
    var execName = intersects(w, execWords);
    var pathKeyPresent = keyList.some(function (k) { return has(PATTERNS.path_keys, k); });
    for (var i = 0; i < PATTERNS.command_keys.length; i++) {
      var k = PATTERNS.command_keys[i];
      if (k in keys && commandString(keys[k]) !== null) {
        var cmd = commandString(keys[k]);
        if (execName || k !== "command" || /[\s|;&<>$]/.test(cmd)) {
          if (!(k === "command" && pathKeyPresent && !execName)) return "shell";
        }
      }
    }
    // run_shell {"args": ["rm", "-rf", "~"]}
    if (execName && Array.isArray(keys.args) && commandString(keys.args) !== null) return "shell";
    for (i = 0; i < PATTERNS.sql_keys.length; i++) {
      var sk = PATTERNS.sql_keys[i];
      if (typeof keys[sk] === "string" && /^\s*(?:select|insert|update|delete|drop|create|alter|truncate|with|grant|revoke|replace|merge|upsert|copy|call|exec|execute)\b/i.test(sqlText(keys[sk]))) return "sql";
    }
    var hasAmount = PATTERNS.amount_keys.some(function (ak) { return num(keys[ak]) !== null && keys[ak] !== undefined; });
    if (hasAmount && (intersects(w, setOf(verbs.payment)) || "currency" in keys || intersects(w, setOf(PATTERNS.capabilities.payment.name)))) return "payment";
    if (pathKeyPresent || PATTERNS.url_keys.some(function (uk) { return fileUrl(keys[uk]) !== null; })) {
      var sub = typeof keys.command === "string" ? setOf(words(keys.command)) : {};
      var groups = [sub, w];
      for (i = 0; i < groups.length; i++) {
        if (intersects(groups[i], setOf(verbs["delete"]))) return "file_delete";
        if (intersects(groups[i], setOf(verbs.write))) return "file_write";
        if (intersects(groups[i], setOf(verbs.read))) return "file_read";
      }
      return keyList.some(function (x) { return has(CONTENT_KEYS, x); }) ? "file_write" : "file_read";
    }
    if (PATTERNS.url_keys.some(function (uk) { return typeof keys[uk] === "string"; })) return "network";
    if (intersects(w, setOf(verbs.message)) && keyList.some(function (x) { return has(["to", "recipient", "recipients", "channel", "body", "text", "message", "subject", "chat_id", "content"], x); })) return "message";
    return "other";
  }
  // the path in a file: URL: a tool that takes `uri` reads the same file as one that takes `path`
  // SQL without comments, which can sit in the middle of a keyword's spacing
  function sqlText(sql) { return sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " "); }

  function fileUrl(v) {
    if (typeof v !== "string" || v.slice(0, 5).toLowerCase() !== "file:") return null;
    var p = v.replace(/^file:(?:\/\/[^\/]*)?/i, "");
    try { return decodeURIComponent(p); } catch (e) { return p; }
  }
  function pathsOf(args) {
    var out = [];
    Object.keys(args).forEach(function (k) {
      var lk = String(k).toLowerCase(), v = args[k], vals = Array.isArray(v) ? v : [v];
      if (has(PATTERNS.path_keys, lk)) vals.forEach(function (x) { if (typeof x === "string" && x) out.push([lk, fileUrl(x) || x]); });
      else if (has(PATTERNS.url_keys, lk)) vals.forEach(function (x) { if (fileUrl(x)) out.push([lk, fileUrl(x)]); });
    });
    return out;
  }
  function shellText(args) {
    var keys = Object.keys(args);
    var ck = keys.filter(function (k) { return has(PATTERNS.command_keys, k.toLowerCase()) && commandString(args[k]) !== null; })[0];
    if (ck !== undefined) return commandString(args[ck]);
    return commandString(args[keys.filter(function (k) { return k.toLowerCase() === "args"; })[0]]);
  }
  function fmt(x) { return String(Math.round(x * 1e6) / 1e6); }

  function paymentAmount(args) {
    var keys = lowerKeys(args);
    for (var i = 0; i < PATTERNS.amount_keys.length; i++) {
      var k = PATTERNS.amount_keys[i], v = keys[k] === undefined ? null : num(keys[k]);
      if (v !== null) return k === "amount_cents" ? v / 100 : v;
    }
    return null;
  }
  function checkPayment(args, pol, context) {
    var out = [], pay = pol.payments, keys = lowerKeys(args), amount = paymentAmount(args);
    if (amount === null) return out;
    if (amount < 0) return [F("VFY-PAY-006", "deny", "The amount is negative.")];
    var spent = Number(context.spent_today || 0);
    if (pay.max_per_call !== null && pay.max_per_call !== undefined && amount > pay.max_per_call) out.push(F("VFY-PAY-001", "deny", fmt(amount) + " is over the per-payment limit of " + fmt(pay.max_per_call) + "."));
    else if (pay.daily_budget !== null && pay.daily_budget !== undefined && spent + amount > pay.daily_budget) out.push(F("VFY-PAY-002", "deny", "This payment would take today's spending to " + fmt(spent + amount) + ", over the daily budget of " + fmt(pay.daily_budget) + "."));
    else if (pay.ask_above !== null && pay.ask_above !== undefined && amount > pay.ask_above) out.push(F("VFY-PAY-003", "ask", fmt(amount) + " is above the approval threshold of " + fmt(pay.ask_above) + "."));
    var cur = keys.currency || keys.ccy;
    if (typeof cur === "string" && pay.currencies && pay.currencies.length && pay.currencies.map(function (c) { return c.toUpperCase(); }).indexOf(cur.toUpperCase()) < 0) out.push(F("VFY-PAY-004", "ask", "Currency " + cur.toUpperCase() + " is not on the allowed list."));
    if (pay.recipients && pay.recipients.length) {
      for (var i = 0; i < PATTERNS.recipient_keys.length; i++) {
        var rk = PATTERNS.recipient_keys[i];
        if (typeof keys[rk] === "string") {
          if (!pay.recipients.some(function (p) { return nameMatch(p, keys[rk]); })) out.push(F("VFY-PAY-005", "ask", "`" + keys[rk] + "` is not on the list of known recipients."));
          break;
        }
      }
    }
    return out;
  }

  function check(action, policy, context) {
    var complete = policy && Object.keys(DEFAULT_POLICY).every(function (k) { return k in policy; }) && policy.home && policy.workspace;
    var pol = complete ? policy : loadPolicy(policy);
    var ctx = new Ctx(pol);
    context = context || {};
    var tool = String(action.tool || action.name || ""), server = String(action.server || "");
    var args = action.arguments !== undefined ? action.arguments : (action.args !== undefined ? action.args : {});
    if (!isObj(args)) args = { input: args };
    var full = server ? server + "/" + tool : tool, out = [];
    function listed(key) {
      var l = pol.tools[key] || [];
      for (var i = 0; i < l.length; i++) if (nameMatch(l[i], full) || nameMatch(l[i], tool)) return l[i];
      return null;
    }
    var hit = listed("deny");
    if (hit) out.push(F("VFY-TOOL-001", "deny", "`" + full + "` is on the tool deny list (`" + hit + "`)."));
    hit = listed("ask");
    if (hit) out.push(F("VFY-TOOL-002", "ask", "`" + full + "` always needs approval (`" + hit + "`)."));
    var meta = context.tool || {};
    if (meta.critical) out.push(F("VFY-TOOL-003", "deny", "`" + tool + "` failed the Verfy scan with a critical finding."));
    var known = context.known_tools;
    if (known !== undefined && known !== null && !has(known, tool)) out.push(F("VFY-TOOL-005", "deny", "`" + tool + "` is not in the tool list Verfy scanned for this server."));
    if (meta.pin === "changed") out.push(F("VFY-TOOL-004", "deny", "`" + tool + "` changed since it was approved (possible rug pull)."));
    if (meta.pin === "new") {
      var onNew = (pol.lock || {}).on_new || "ask";
      if (onNew === "ask" || onNew === "deny") out.push(F("VFY-TOOL-006", onNew, "`" + tool + "` is not in verfy.lock yet. Review it with `verfy lock approve`."));
    }
    if (meta.pin === "unverified") out.push(F("VFY-TOOL-007", "ask", "verfy.lock could not be read, so `" + tool + "` was not checked against it."));

    var kind = classify(tool, args), trusted = listed("trust") !== null;
    var network = kind === "network" || kind === "message";
    if (trusted) { // trust skips the rules, not what guards Verfy itself
      var plain = check(action, Object.assign({}, pol, { tools: Object.assign({}, pol.tools, { trust: [] }) }), context);
      plain.findings.forEach(function (f) { if (f.rule.indexOf("VFY-SELF-") === 0) out.push(f); });
    }
    if (!trusted) {
      var argKeys = Object.keys(args);
      var touchy = false; // a key file read, or a write outside the project
      if (has(words(tool), "glob") && typeof args.pattern === "string" && rx(PATTERNS.self_protect.secret.token, "i").test(args.pattern)) {
        out.push(F("VFY-SELF-006", "deny", "Lists Verfy's signing key or device token (" + args.pattern + ")." + SECRET_MSG));
      }
      if (kind === "shell") {
        var cmdText = shellText(args);
        var res = checkShell(cmdText, ctx);
        out = out.concat(res[0]); network = res[1];
        touchy = pushes(cmdText) || res[0].some(function (f) { return f.rule === "VFY-SH-007" || f.rule === "VFY-SH-008"; });
      } else if (kind === "sql") {
        var qk = argKeys.filter(function (k) { return has(PATTERNS.sql_keys, k.toLowerCase()) && typeof args[k] === "string"; })[0];
        PATTERNS.sql_patterns.forEach(function (r) { if (rx(r[2], r[3]).test(sqlText(args[qk]))) out.push(F(r[0], r[1], r[4])); });
      } else if (kind.indexOf("file_") === 0) {
        pathsOf(args).forEach(function (kp) {
          var key = kp[0], p = kp[1], abs = ctx.path(p), h;
          var reading = kind === "file_read" || (kind === "file_write" && has(["source", "src", "source_path", "from"], key) && !has(words(tool), "move"));
          if (rx(PATTERNS.self_protect.secret.token, "i").test(p) || ctx.verfySecret(ctx.path(homeVars(p)))) {
            out.push(F("VFY-SELF-006", "deny", "Reads or changes Verfy's signing key or device token (" + p + ")." + SECRET_MSG));
            return;
          }
          if (reading && (has(words(tool), "grep") || has(words(tool), "search")) && ctx.holdsVerfy(ctx.path(homeVars(p)))) {
            out.push(F("VFY-SELF-007", "ask", "Searches " + p + ", which holds Verfy's signing key and device token."));
          }
          if (reading) {
            h = ctx.sensitive(abs);
            if (h) { out.push(F("VFY-FS-003", "ask", "Reads the sensitive file " + p + " (`" + h + "`).")); touchy = true; }
            return;
          }
          var mine = ctx.guardsVerfy(abs);
          if (mine) { out.push(selfFinding(mine, p)); return; }
          h = ctx.protected_(abs);
          if (h) { out.push(F("VFY-FS-001", "deny", "Changes " + p + ", which is protected (`" + h + "`).")); return; }
          if (kind === "file_delete" && ctx.catastrophic(abs)) { out.push(F("VFY-FS-004", "deny", "Deletes " + p + ", which would wipe the system, the home folder or the whole project.")); return; }
          h = ctx.sensitive(abs);
          if (h) out.push(F("VFY-FS-003", "ask", "Changes the sensitive file " + p + " (`" + h + "`)."));
          if (!isWithin(abs, ctx.ws) && !ctx.allowedOutside(abs)) {
            touchy = true;
            var v = pol.files.outside_workspace || "ask";
            if (v === "ask" || v === "deny") out.push(F("VFY-FS-002", v, "Changes " + p + ", which is outside the project."));
          }
        });
      } else if (kind === "payment") out = out.concat(checkPayment(args, pol, context));
      if (kind !== "shell") {
        // a path under any key, also nested: a tool may call it `location` or `options.path`
        var covered = kind.indexOf("file_") === 0 ? pathsOf(args).map(function (kp) { return kp[1]; }) : [];
        flattenStrings(args).forEach(function (pt) {
          var text = pt[1];
          if (has(covered, text) || Array.from(text).length > 1024 || text.indexOf("\n") >= 0 || has(CONTENT_KEYS, pt[0].split(/[.\[]/)[0].toLowerCase())) return;
          var h = fileUrl(text) || homeVars(text.replace(/\\/g, "/"));
          if (/^(?:~|\/|\.\.?\/|[A-Za-z]:\/)/.test(h)) {
            var nh = ctx.sensitive(ctx.path(h));
            if (nh) { out.push(F("VFY-FS-003", "ask", "Names the sensitive file " + text + " (`" + nh + "`).")); touchy = true; }
          }
        });
      }
      var urls = argKeys.filter(function (k) { return has(PATTERNS.url_keys, k.toLowerCase()) && typeof args[k] === "string"; }).map(function (k) { return args[k]; });
      if (kind === "network" || kind === "message") {
        urls.forEach(function (u) { out = out.concat(checkUrl(u, ctx)); });
      }
      flattenStrings(args).forEach(function (pt) {
        scanSecrets(pt[1]).forEach(function (s) {
          if (s.severity === "high" && (network || has(["network", "message", "payment"], kind))) out.push(F("VFY-SEC-001", "deny", "Would send a " + s.label + " out of this computer (in `" + (pt[0] || "arguments") + "`)."));
          else out.push(F("VFY-SEC-001", "ask", "Contains a " + s.label + " (in `" + (pt[0] || "arguments") + "`)."));
        });
      });
      var after = (pol.session || {}).after_outside_text || "off";
      var listedSite = kind === "network" && urls.length > 0 && urls.every(function (u) { return onAllowList(u, ctx); });
      if (context.untrusted && (after === "ask" || after === "deny") && (touchy || (network && !listedSite) || has(["message", "payment", "file_delete"], kind))) {
        out.push(F("VFY-SESSION-001", after, "This session read outside text (" + context.untrusted + "), which can carry instructions, so a person has to approve this."));
      }
    }
    (pol.rules || []).forEach(function (r) {
      var tp = r.tool || "*";
      if (!nameMatch(tp, full) && !nameMatch(tp, tool)) return;
      var pat = rx(r.pattern, r.flags || ""), strs = flattenStrings(args);
      for (var i = 0; i < strs.length; i++) {
        if (r.arg && strs[i][0] !== r.arg) continue;
        if (pat.test(strs[i][1])) { out.push(F(r.id || "custom", r.verdict || "ask", r.message || "Matches a custom rule.")); break; }
      }
    });
    var disabled = setOf(pol.disabled_rules || []), seen = {}, findings = [];
    out.forEach(function (f) {
      var key = f.rule + "\u0000" + f.message;
      // what guards Verfy itself cannot be listed away
      if ((disabled[f.rule] && f.rule.indexOf("VFY-SELF-") !== 0) || seen[key]) return;
      seen[key] = true;
      findings.push(f);
    });
    findings.sort(function (a, b) { return VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict]; });
    return { v: "verfy.check/1", verdict: findings.length ? findings[0].verdict : "allow", kind: kind, tool: full, findings: findings };
  }

  /* ============================================================ Ed25519 (RFC 8032) */
  var P = (1n << 255n) - 19n;
  var L = (1n << 252n) + 27742317777372353535851937790883648493n;
  function mod(a, m) { m = m || P; var r = a % m; return r >= 0n ? r : r + m; }
  function powmod(b, e, m) { var r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
  function inv(x) { return powmod(x, P - 2n, P); }
  var D = mod(-121665n * inv(121666n));
  var I = powmod(2n, (P - 1n) / 4n, P);
  function pAdd(p, q) {
    var A = mod((p[1] - p[0]) * (q[1] - q[0])), B = mod((p[1] + p[0]) * (q[1] + q[0]));
    var C = mod(2n * p[3] * q[3] * D), Dd = mod(2n * p[2] * q[2]);
    var E = B - A, Fv = Dd - C, G = Dd + C, H = B + A;
    return [mod(E * Fv), mod(G * H), mod(Fv * G), mod(E * H)];
  }
  function pMul(s, p) { var q = [0n, 1n, 1n, 0n]; while (s > 0n) { if (s & 1n) q = pAdd(q, p); p = pAdd(p, p); s >>= 1n; } return q; }
  function pEq(p, q) { return mod(p[0] * q[2] - q[0] * p[2]) === 0n && mod(p[1] * q[2] - q[1] * p[2]) === 0n; }
  function recoverX(y, sign) {
    if (y >= P) return null;
    var x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
    if (x2 === 0n) return sign ? null : 0n;
    var x = powmod(x2, (P + 3n) / 8n, P);
    if (mod(x * x - x2) !== 0n) x = mod(x * I);
    if (mod(x * x - x2) !== 0n) return null;
    if (Number(x & 1n) !== sign) x = P - x;
    return x;
  }
  var GY = mod(4n * inv(5n)), GX = recoverX(GY, 0), G = [GX, GY, 1n, mod(GX * GY)];
  function leToInt(b) { var r = 0n; for (var i = b.length - 1; i >= 0; i--) r = (r << 8n) + BigInt(b[i]); return r; }
  function intToLe(n, len) { var b = new Uint8Array(len); for (var i = 0; i < len; i++) { b[i] = Number(n & 255n); n >>= 8n; } return b; }
  function compress(p) { var zi = inv(p[2]), x = mod(p[0] * zi), y = mod(p[1] * zi); return intToLe(y | ((x & 1n) << 255n), 32); }
  function decompress(s) {
    if (s.length !== 32) return null;
    var y = leToInt(s), sign = Number(y >> 255n);
    y &= (1n << 255n) - 1n;
    var x = recoverX(y, sign);
    return x === null ? null : [x, y, 1n, mod(x * y)];
  }
  function concat() { var n = 0, i; for (i = 0; i < arguments.length; i++) n += arguments[i].length; var o = new Uint8Array(n), off = 0; for (i = 0; i < arguments.length; i++) { o.set(arguments[i], off); off += arguments[i].length; } return o; }
  async function sha512(b) { return new Uint8Array(await subtle.digest("SHA-512", b)); }
  async function expand(secret) {
    var h = await sha512(secret), a = leToInt(h.slice(0, 32));
    a &= (1n << 254n) - 8n; a |= 1n << 254n;
    return [a, h.slice(32)];
  }
  var ed25519 = {
    randomSecret: function () { var b = new Uint8Array(32); globalThis.crypto.getRandomValues(b); return b; },
    publicKey: async function (secret) { var e = await expand(secret); return compress(pMul(e[0], G)); },
    sign: async function (secret, msg) {
      var e = await expand(secret), a = e[0], A = compress(pMul(a, G));
      var r = mod(leToInt(await sha512(concat(e[1], msg))), L);
      var Rs = compress(pMul(r, G));
      var h = mod(leToInt(await sha512(concat(Rs, A, msg))), L);
      return concat(Rs, intToLe(mod(r + h * a, L), 32));
    },
    verify: async function (pub, msg, sig) {
      if (pub.length !== 32 || sig.length !== 64) return false;
      var A = decompress(pub); if (!A) return false;
      var R = decompress(sig.slice(0, 32)); if (!R) return false;
      var s = leToInt(sig.slice(32)); if (s >= L) return false;
      var h = mod(leToInt(await sha512(concat(sig.slice(0, 32), pub, msg))), L);
      return pEq(pMul(s, G), pAdd(R, pMul(h, A)));
    }
  };

  /* ============================================================ receipts */
  function b64u(bytes) {
    var s = ""; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function unb64u(s) {
    s = String(s).trim().replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  async function keyId(pub) { return "atl_" + (await sha256Hex(pub)).slice(0, 16); }
  async function generateKey() { return keyFromSecret(ed25519.randomSecret()); }
  async function keyFromSecret(secret) {
    var pub = await ed25519.publicKey(secret);
    return { kty: "Ed25519", kid: await keyId(pub), public: b64u(pub), secret: b64u(secret), _sec: secret, _pub: pub };
  }
  async function signReceipt(body, key) {
    var b = Object.assign({}, body);
    delete b.sig;
    b.v = "verfy.receipt/1";
    b.kid = key.kid;
    var sig = await ed25519.sign(key._sec, enc.encode(canonical(b)));
    return Object.assign(b, { sig: b64u(sig) });
  }
  async function verifyReceipt(r, pub) {
    if (!isObj(r) || r.v !== "verfy.receipt/1" || typeof r.sig !== "string") return false;
    var body = Object.assign({}, r);
    delete body.sig;
    if (body.kid !== (await keyId(pub))) return false;
    var sig;
    try { sig = unb64u(r.sig); } catch (e) { return false; }
    return ed25519.verify(pub, enc.encode(canonical(body)), sig);
  }
  function randomId() { var b = new Uint8Array(8); globalThis.crypto.getRandomValues(b); return "rcpt_" + hex(b); }
  async function buildReceipt(o) {
    var args = (o.action && o.action.arguments) || {};
    var act = { server: o.action.server || "", tool: o.action.tool || "", kind: o.decision.kind || "other", args_sha256: await digest(args) };
    if (o.include_args === true) act.args = redactValue(args);
    var dec = { verdict: o.decision.verdict, rules: (o.decision.findings || []).map(function (f) { return f.rule; }), policy_sha256: o.policy_sha256 };
    if (o.decision.approved_by) dec.approved_by = o.decision.approved_by;
    return {
      v: "verfy.receipt/1", id: o.id || randomId(), seq: o.seq, prev: o.prev === undefined ? null : o.prev,
      issued_at: o.issued_at || new Date().toISOString(), agent: o.agent, session: o.session,
      action: act, decision: dec, outcome: o.outcome, tool_sha256: o.tool_sha256 === undefined ? null : o.tool_sha256
    };
  }
  async function verifyLedger(receipts, pub) {
    var errors = [], prev = null;
    for (var i = 0; i < receipts.length; i++) {
      var r = receipts[i];
      if (!(await verifyReceipt(r, pub))) errors.push({ index: i, seq: isObj(r) ? r.seq : null, error: "bad signature" });
      if (isObj(r)) {
        if (r.seq !== i) errors.push({ index: i, seq: r.seq, error: "expected seq " + i });
        if ((r.prev === undefined ? null : r.prev) !== prev) errors.push({ index: i, seq: r.seq, error: "broken chain: prev does not match the receipt before it" });
        prev = await digest(r);
      }
    }
    return { ok: !errors.length, count: receipts.length, head: prev, errors: errors };
  }
  function parseLedger(text) {
    return String(text).split(/\r?\n/).filter(function (l) { return l.trim(); }).map(function (l, i) {
      try { return JSON.parse(l); } catch (e) { throw new Error("line " + (i + 1) + " is not valid JSON"); }
    });
  }

  return {
    version: "0.2.0",
    PATTERNS: PATTERNS, DEFAULT_POLICY: DEFAULT_POLICY,
    canonical: canonical, digest: digest, sha256Hex: sha256Hex,
    loadPolicy: loadPolicy, check: check, classify: classify, parseShell: parseShell,
    scan: scan, toolPin: toolPin, unsafeTools: unsafeTools, grade: grade,
    scanSecrets: scanSecrets, redactValue: redactValue, paymentAmount: paymentAmount,
    ed25519: ed25519, b64u: b64u, unb64u: unb64u, keyId: keyId, generateKey: generateKey, keyFromSecret: keyFromSecret,
    signReceipt: signReceipt, verifyReceipt: verifyReceipt, buildReceipt: buildReceipt, verifyLedger: verifyLedger, parseLedger: parseLedger
  };
}
