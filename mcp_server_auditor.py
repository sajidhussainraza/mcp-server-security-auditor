#!/usr/bin/env python3
"""MCP Server Security Auditor.

Audits a Model Context Protocol (MCP) server definition for security
risks before an AI agent is allowed to connect to it. MCP servers hand
an agent new capabilities -- file access, shell commands, network
calls, secrets -- and a single over-privileged server can undo every
guardrail the agent itself carries. This tool scores those risks so a
server can be approved, reviewed, or blocked with evidence.

Input is a JSON description of one MCP server:

    {
      "name": "files-plus-shell",
      "version": "1.2.0",
      "transport": "stdio",            // stdio | sse | streamable-http
      "auth": {"type": "none"},        // none | api-key | oauth | token
      "tools": [
        {"name": "run_command",
         "description": "Run a shell command",
         "annotations": {"readOnlyHint": false,
                         "destructiveHint": true,
                         "idempotentHint": false,
                         "openWorldHint": false},
         "parameters": {"command": "string", "confirm": "boolean"}}
      ],
      "resources": [{"uri": "file:///etc/passwd", "name": "passwd"}],
      "prompts": [{"name": "summarise", "description": "..."}]
    }

Tool ``parameters`` may be a flat ``{name: type}`` map or a JSON
Schema object with a ``properties`` map; only the parameter names
are inspected. ``auth`` may be omitted for stdio servers (local
transport), but a remote transport (``sse`` / ``streamable-http``)
with no auth is a finding. ``annotations`` follow the MCP spec:
``readOnlyHint``, ``destructiveHint``, ``idempotentHint`` and
``openWorldHint``.

Rules (see ``--list-rules`` for the full list with severities):

* R01 shell / command execution tools
* R02 destructive tools with no confirmation parameter
* R03 file-write tools with no declared allowed paths
* R04 network egress / open-world tools
* R05 secret and credential access (env vars, tokens, passwords)
* R06 remote transport with no authentication
* R07 tools with no safety annotations at all
* R08 sensitive resources exposed (config files, credentials, env)
* R09 unscoped file reads (arbitrary path, no allowed paths)
* R10 missing server metadata (name, version or description)

Usage:
    python mcp_server_auditor.py examples/risky-server.json
    python mcp_server_auditor.py examples/safe-server.json --json report.json
    python mcp_server_auditor.py server.json --fail-above 25
    python mcp_server_auditor.py server.json --min-severity high
    python mcp_server_auditor.py --list-rules

Exit codes: 0 = risk score at or below --fail-above (default 60),
1 = score above it, 2 = usage/input error.

Standard library only. This tool only reads a server description
and reports on it; it never connects to a server or executes a tool.
"""

import argparse
import json
import re
import sys

# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RULES = {
    "R01": ("critical",
            "Shell / command execution tool",
            "Remove the tool, or run it in a sandbox with an allow-list "
            "of commands and no shell metacharacters."),
    "R02": ("high",
            "Destructive tool with no confirmation parameter",
            "Add a required confirmation parameter (for example "
            "'confirm': true) and log every destructive call."),
    "R03": ("high",
            "File-write tool with no declared allowed paths",
            "Declare 'allowed_paths' on the server and reject writes "
            "outside them."),
    "R04": ("high",
            "Network egress / open-world tool",
            "Restrict destinations to an allow-list of hosts and log "
            "every outbound request."),
    "R05": ("high",
            "Secret / credential access",
            "Never expose environment variables, tokens or passwords "
            "through tools or resources; use a secrets manager."),
    "R06": ("high",
            "Remote transport with no authentication",
            "Add authentication (API key or OAuth) before exposing the "
            "server over SSE or streamable HTTP."),
    "R07": ("medium",
            "Tool with no safety annotations",
            "Set the MCP annotations (readOnlyHint, destructiveHint, "
            "idempotentHint, openWorldHint) on every tool."),
    "R08": ("medium",
            "Sensitive resource exposed",
            "Remove credentials, config files and environment data from "
            "the resource list."),
    "R09": ("medium",
            "Unscoped file read (arbitrary path, no allowed paths)",
            "Declare 'allowed_paths' and reject reads outside them."),
    "R10": ("low",
            "Missing server metadata",
            "Give the server a name, version and description so it can "
            "be identified and reviewed."),
}

SHELL_PATTERNS = (
    r"\b(run|exec|execute|spawn|shell|bash|sh|zsh|powershell|cmd|"
    r"system|popen|subprocess|eval)\b",
)
SHELL_NAMES = (
    "run_command", "exec", "execute", "run_shell", "shell",
    "bash", "powershell", "run_script", "system_command",
)
DESTRUCTIVE_PATTERNS = (
    r"\b(delete|remove|drop|destroy|truncate|wipe|format|kill|"
    r"terminate|purge|uninstall|rm)\b",
)
WRITE_NAMES = (
    "write_file", "save_file", "create_file", "upload_file",
    "move_file", "rename_file", "append_file", "edit_file",
    "write", "save", "upload",
)
WRITE_PATTERNS = (r"\b(write|save|create|upload|append|overwrite)\b",)
READ_NAMES = (
    "read_file", "read", "get_file", "load_file", "cat", "open_file",
)
NETWORK_PATTERNS = (
    r"\b(fetch|http|request|download|webhook|post|get url|curl|"
    r"send email|smtp|socket)\b",
)
SECRET_PATTERNS = (
    r"\b(env|environment|token|password|passwd|secret|api key|"
    r"credential|private key|auth|bearer|aws|access key)\b",
)
SENSITIVE_URI_PATTERNS = (
    r"(\.env|credentials|secrets?|passwd|shadow|\.pem|\.key|"
    r"config\.ya?ml|config\.json|env://|id_rsa)",
)
PATH_PARAM_NAMES = ("path", "filepath", "file_path", "filename",
                    "directory", "dir", "target", "location")
CONFIRM_PARAM_NAMES = ("confirm", "confirmation", "confirmed",
                       "approve", "approved", "dry_run")


def norm(text):
    """Lowercase text with every separator folded to a single space.

    This turns snake_case and kebab-case names such as ``run_command``
    and ``api_key`` into plain words (``run command``, ``api key``)
    so the word-boundary patterns above match them.
    """
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def matches_words(patterns, text):
    """True when any pattern matches the normalised form of ``text``."""
    normalised = norm(text)
    return any(re.search(p, normalised) for p in patterns)


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def param_names(tool):
    """Return the parameter names of a tool definition."""
    params = tool.get("parameters") or {}
    if isinstance(params, dict) and isinstance(params.get("properties"),
                                                dict):
        return list(params["properties"])
    if isinstance(params, dict):
        return list(params)
    if isinstance(params, list):
        return [str(p) for p in params]
    return []


def tool_text(tool):
    """Lowercased searchable text for a tool (name + description)."""
    return f"{tool.get('name', '')} {tool.get('description', '')}".lower()


def matches_any(patterns, text):
    return any(re.search(p, text) for p in patterns)


def load_server(path):
    """Load and validate a server description file."""
    try:
        with open(path, encoding="utf-8") as handle:
            server = json.load(handle)
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}")
    if not isinstance(server, dict):
        raise ValueError(f"{path}: server description must be a JSON object")
    for key in ("tools", "resources", "prompts"):
        value = server.get(key, [])
        if not isinstance(value, list):
            raise ValueError(f"{path}: {key!r} must be a list")
    return server


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def audit(server):
    """Audit a server dict. Returns a list of findings.

    Each finding: {"rule", "severity", "target", "message"}.
    """
    findings = []
    tools = server.get("tools", [])
    resources = server.get("resources", [])
    allowed_paths = server.get("allowed_paths")

    def add(rule, target, message):
        severity, _, _ = RULES[rule]
        findings.append({"rule": rule, "severity": severity,
                         "target": target, "message": message})

    # R10 -- missing metadata.
    missing = [k for k in ("name", "version", "description")
               if not str(server.get(k, "")).strip()]
    if missing:
        add("R10", server.get("name") or "server",
            f"missing metadata: {', '.join(missing)}")

    # R06 -- remote transport without auth.
    transport = str(server.get("transport", "stdio")).lower()
    auth = server.get("auth") or {}
    auth_type = str(auth.get("type", "none")).lower()
    if transport in ("sse", "streamable-http", "http") \
            and auth_type in ("none", "", "missing"):
        add("R06", server.get("name") or "server",
            f"remote transport ({transport}) with no authentication")

    for tool in tools:
        name = str(tool.get("name", "")).strip()
        text = tool_text(tool)
        params = [p.lower() for p in param_names(tool)]
        annotations = tool.get("annotations") or {}
        display = name or "unnamed tool"

        is_shell = name.lower() in SHELL_NAMES \
            or matches_words(SHELL_PATTERNS, text)
        is_destructive = bool(annotations.get("destructiveHint")) \
            or matches_words(DESTRUCTIVE_PATTERNS, text)
        is_write = name.lower() in WRITE_NAMES \
            or matches_words(WRITE_PATTERNS, text)
        is_read = name.lower() in READ_NAMES
        is_network = bool(annotations.get("openWorldHint")) \
            or matches_words(NETWORK_PATTERNS, text)
        touches_secrets = matches_words(SECRET_PATTERNS, text) \
            or any(matches_words(SECRET_PATTERNS, p) for p in params)
        has_path_param = any(p in PATH_PARAM_NAMES for p in params)
        has_confirm = any(p in CONFIRM_PARAM_NAMES for p in params)

        # R01 -- shell / command execution.
        if is_shell:
            add("R01", display,
                "tool can execute shell commands")
        # R02 -- destructive without confirmation.
        if is_destructive and not has_confirm:
            add("R02", display,
                "destructive tool has no confirmation parameter")
        # R03 -- file write without allowed paths.
        if is_write and not allowed_paths:
            add("R03", display,
                "file-write tool with no server-level allowed_paths")
        # R04 -- network egress / open world.
        if is_network:
            add("R04", display,
                "tool reaches the network or the open world")
        # R05 -- secret / credential access.
        if touches_secrets:
            add("R05", display,
                "tool name, description or parameters mention secrets "
                "or credentials")
        # R07 -- no safety annotations.
        if not annotations:
            add("R07", display,
                "no MCP safety annotations (readOnlyHint, "
                "destructiveHint, idempotentHint, openWorldHint)")
        # R09 -- unscoped file read.
        if is_read and has_path_param and not allowed_paths:
            add("R09", display,
                "file-read tool accepts an arbitrary path with no "
                "server-level allowed_paths")

    for resource in resources:
        uri = str(resource.get("uri", ""))
        name = str(resource.get("name", "")) or uri
        if matches_any(SENSITIVE_URI_PATTERNS, uri.lower()) \
                or matches_words(SECRET_PATTERNS, f"{name} {uri}"):
            add("R08", name,
                f"resource exposes sensitive data: {uri}")

    return findings


# ---------------------------------------------------------------------------
# Scoring and reporting
# ---------------------------------------------------------------------------

def summarize(findings):
    """Score findings and produce a summary dict."""
    counts = {level: 0 for level in SEVERITY_WEIGHTS}
    for f in findings:
        counts[f["severity"]] += 1
    score = min(100, sum(SEVERITY_WEIGHTS[level] * n
                         for level, n in counts.items()))
    if score >= 60 or counts["critical"] > 0:
        verdict = "BLOCK"
    elif score >= 25:
        verdict = "REVIEW"
    else:
        verdict = "OK"
    by_rule = {}
    for f in findings:
        entry = by_rule.setdefault(f["rule"], {"count": 0, "severity": None})
        entry["count"] += 1
        entry["severity"] = f["severity"]
    return {
        "score": score,
        "verdict": verdict,
        "total_findings": len(findings),
        "by_severity": counts,
        "by_rule": dict(sorted(by_rule.items())),
    }


def print_report(server, findings, summary):
    name = server.get("name") or "unnamed server"
    print(f"Server: {name} "
          f"(transport: {server.get('transport', 'stdio')}, "
          f"{len(server.get('tools', []))} tool(s), "
          f"{len(server.get('resources', []))} resource(s))")
    print(f"Risk score: {summary['score']}/100 "
          f"({summary['total_findings']} finding(s)) "
          f"-> {summary['verdict']}")
    by_sev = summary["by_severity"]
    print(f"  critical: {by_sev['critical']}, high: {by_sev['high']}, "
          f"medium: {by_sev['medium']}, low: {by_sev['low']}")
    for f in sorted(findings,
                    key=lambda x: (SEVERITY_ORDER[x["severity"]],
                                   x["rule"], x["target"])):
        print(f"  [{f['severity'].upper()}] {f['rule']} "
              f"{f['target']}: {f['message']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit an MCP server definition for security risks "
                    "before an AI agent connects to it.")
    parser.add_argument("file", nargs="?", metavar="FILE",
                        help="JSON file describing the MCP server")
    parser.add_argument("--json", metavar="FILE",
                        help="write a JSON report to FILE")
    parser.add_argument("--fail-above", type=float, default=60,
                        help="exit 1 when the risk score is above this "
                             "(default: 60)")
    parser.add_argument("--min-severity", default=None,
                        choices=list(SEVERITY_ORDER),
                        help="only show findings at or above this severity")
    parser.add_argument("--list-rules", action="store_true",
                        help="list the audit rules and exit")
    args = parser.parse_args(argv)

    if args.list_rules:
        for rule in sorted(RULES):
            severity, title, advice = RULES[rule]
            print(f"{rule} [{severity}] {title}\n    {advice}")
        return 0

    if not args.file:
        parser.error("FILE is required (or use --list-rules)")

    if not 0.0 <= args.fail_above <= 100.0:
        print("error: --fail-above must be between 0 and 100",
              file=sys.stderr)
        return 2

    try:
        server = load_server(args.file)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = audit(server)
    if args.min_severity:
        floor = SEVERITY_ORDER[args.min_severity]
        findings = [f for f in findings
                    if SEVERITY_ORDER[f["severity"]] <= floor]

    summary = summarize(findings)
    if args.json:
        payload = {"server": server.get("name"),
                   "summary": summary,
                   "findings": findings,
                   "rules": {r: {"severity": s, "title": t, "advice": a}
                             for r, (s, t, a) in RULES.items()}}
        try:
            with open(args.json, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            print(f"error: cannot write {args.json}: {exc}", file=sys.stderr)
            return 2
        print(f"JSON report written to {args.json}")

    print_report(server, findings, summary)
    return 1 if summary["score"] > args.fail_above else 0


if __name__ == "__main__":
    sys.exit(main())
