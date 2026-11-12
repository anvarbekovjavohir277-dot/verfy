// Verfy for VS Code, Cursor and Windsurf.
//
// The extension does not check anything itself: the Verfy CLI does, through each agent's hook and the MCP gateway.
// The extension finds the CLI (or offers to install it), shows what `verfy setup` would change, runs it when you
// agree, and can make the editor's terminal open inside the sandbox. It changes no file on its own and makes no
// network call; every change goes through the CLI, which keeps a backup of each file it changes.
"use strict";

const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const WIN = process.platform === "win32";
let out;
let status;
let cli; // [command, ...args before the verfy arguments], once found

function candidates() {
  // the user's own setting only: a folder's .vscode/settings.json must not choose the program this runs
  const own = vscode.workspace.getConfiguration("verfy").inspect("path")?.globalValue;
  const home = os.homedir();
  const list = [];
  if (own) list.push([own]);
  list.push(["verfy"]);
  if (WIN) {
    list.push([path.join(home, "AppData", "Local", "Programs", "verfy", "verfy.exe")]);
    list.push(["py", "-m", "verfy"], ["python", "-m", "verfy"]);
  } else {
    list.push([path.join(home, ".local", "bin", "verfy")], ["python3", "-m", "verfy"]);
  }
  return list;
}

function run(cmd, args, timeout = 60000) {
  return new Promise((resolve) => {
    // no shell: the arguments go to the program as they are
    cp.execFile(cmd[0], [...cmd.slice(1), ...args], { timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof err.code === "number" ? err.code : -1) : 0, stdout: String(stdout || ""), stderr: String(stderr || ""), missing: !!(err && err.code === "ENOENT") });
    });
  });
}

async function findCli() {
  for (const c of candidates()) {
    if (c.length === 1 && path.isAbsolute(c[0]) && !fs.existsSync(c[0])) continue;
    const r = await run(c, ["--version"], 20000);
    if (r.code === 0 && /verfy/i.test(r.stdout + r.stderr)) {
      cli = c;
      return r.stdout.trim();
    }
  }
  cli = undefined;
  return undefined;
}

async function verfy(args, timeout) {
  if (!cli && !(await findCli())) {
    offerInstall();
    return undefined;
  }
  const r = await run(cli, args, timeout);
  out.appendLine(`$ verfy ${args.join(" ")}`);
  out.appendLine((r.stdout + r.stderr).trimEnd());
  out.appendLine("");
  return r;
}

async function offerInstall() {
  const pick = await vscode.window.showWarningMessage(
    "Verfy: the Verfy CLI is not installed, so nothing is checked yet.",
    "Install it",
    "Open the install page"
  );
  if (pick === "Install it") install();
  if (pick === "Open the install page") vscode.env.openExternal(vscode.Uri.parse("https://verfy.dev/install"));
}

function install() {
  // in a terminal you can see, with the command written out; nothing is installed in the background
  const term = vscode.window.createTerminal({ name: "Install Verfy", shellPath: WIN ? "powershell.exe" : undefined });
  term.show();
  term.sendText(WIN ? "python -m pip install --user --upgrade verfy; python -m verfy init" : "(pipx install verfy || python3 -m pip install --user --upgrade verfy) && verfy init");
  vscode.window.showInformationMessage("Verfy: when the install has finished, run \"Verfy: Set up every agent on this computer\".");
}

// show what the CLI would change, and change it only after you agree
async function previewThenWrite(args, what) {
  const preview = await verfy(args);
  if (!preview) return;
  out.show(true);
  if (!/Nothing changed yet/.test(preview.stdout)) {
    if (preview.code !== 0) vscode.window.showWarningMessage("Verfy: a file could not be read or written; the Verfy output says which.");
    else vscode.window.showInformationMessage(/already/.test(preview.stdout) ? `Verfy: ${what} is already done.` : "Verfy: see the Verfy output for what was found.");
    return;
  }
  const ok = await vscode.window.showInformationMessage(
    `Verfy: ${what}? The list of changes is in the Verfy output. A backup of every changed file is kept.`,
    { modal: true },
    "Do it"
  );
  if (ok !== "Do it") return;
  const done = await verfy([...args, "--write"]);
  if (!done) return;
  if (done.code === 0) vscode.window.showInformationMessage("Verfy: done. Restart the agents that are open, and open a new terminal.");
  else vscode.window.showWarningMessage("Verfy: some files were not changed; the Verfy output says why.");
  refresh();
}

async function refresh() {
  const version = cli ? true : await findCli();
  if (!version) {
    status.text = "$(shield) Verfy: not installed";
    status.tooltip = "Click to install the Verfy CLI";
    status.command = "verfy.install";
    return;
  }
  const r = await run(cli, ["setup"], 30000);
  if (r.code !== 0) {
    status.text = "$(warning) Verfy: check";
    status.tooltip = "verfy setup could not read or write a file. Click to see why.";
    status.command = "verfy.setup";
    return true;
  }
  const todo = /Nothing changed yet/.test(r.stdout);
  status.text = todo ? "$(shield) Verfy: set up" : "$(shield) Verfy";
  status.tooltip = todo ? "Some agents here are not guarded yet. Click to set them up." : "Verfy guards the agents found here. Click for more.";
  status.command = todo ? "verfy.setup" : "verfy.menu";
  return todo;
}

async function menu() {
  const items = [
    { label: "Set up every agent on this computer", id: "verfy.setup" },
    { label: "Open the terminal inside the sandbox", id: "verfy.sandboxOn" },
    { label: "Stop opening the terminal inside the sandbox", id: "verfy.sandboxOff" },
    { label: "Check this computer (doctor)", id: "verfy.doctor" },
    { label: "Show risky agent settings (posture)", id: "verfy.posture" },
    { label: "Fix risky agent settings", id: "verfy.postureFix" },
    { label: "Show the latest receipts", id: "verfy.receipts" },
    { label: "Take Verfy out of every agent (undo)", id: "verfy.undo" },
  ];
  const pick = await vscode.window.showQuickPick(items, { placeHolder: "Verfy" });
  if (pick) vscode.commands.executeCommand(pick.id);
}

async function activate(context) {
  out = vscode.window.createOutputChannel("Verfy");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.show();
  const show = (args) => async () => {
    const r = await verfy(args);
    if (r) out.show(true);
  };
  context.subscriptions.push(
    out,
    status,
    vscode.commands.registerCommand("verfy.setup", () => previewThenWrite(["setup"], "Set up every agent found on this computer (hooks and MCP gateway)")),
    vscode.commands.registerCommand("verfy.sandboxOn", () => previewThenWrite(["setup", "--sandbox-terminal", "on"], "Open the terminal of VS Code, Cursor and Windsurf inside the sandbox")),
    vscode.commands.registerCommand("verfy.sandboxOff", () => previewThenWrite(["setup", "--sandbox-terminal", "off"], "Stop opening the terminal inside the sandbox")),
    vscode.commands.registerCommand("verfy.doctor", show(["doctor"])),
    vscode.commands.registerCommand("verfy.posture", show(["posture"])),
    vscode.commands.registerCommand("verfy.postureFix", () => previewThenWrite(["posture", "--fix"], "Fix the risky agent settings found here (the old file is kept next to each)")),
    vscode.commands.registerCommand("verfy.undo", () => previewThenWrite(["setup", "--undo"], "Take Verfy out of every agent's files: its hooks, the MCP gateway and the sandboxed terminal (your key and receipts stay)")),
    vscode.commands.registerCommand("verfy.receipts", show(["ledger", "show"])),
    vscode.commands.registerCommand("verfy.install", install),
    vscode.commands.registerCommand("verfy.menu", menu),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("verfy.path")) {
        cli = undefined;
        refresh();
      }
    })
  );
  const todo = await refresh();
  if (!cli) return offerInstall();
  if (todo && vscode.workspace.getConfiguration("verfy").get("offerSetup") && !context.globalState.get("verfy.setupDeclined")) {
    const pick = await vscode.window.showInformationMessage("Verfy: some AI agents on this computer are not guarded yet.", "Set them up", "Not now", "Don't ask again");
    if (pick === "Set them up") vscode.commands.executeCommand("verfy.setup");
    if (pick === "Don't ask again") context.globalState.update("verfy.setupDeclined", true);
  }
}

function deactivate() {}

module.exports = { activate, deactivate };
