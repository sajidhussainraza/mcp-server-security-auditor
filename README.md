# MCP Server Security Auditor

A dependency-free Python CLI that audits a Model Context Protocol
(MCP) server definition for security risks before an AI agent is
allowed to connect to it. It reads a JSON description of one server
— its transport, authentication, tools, resources and prompts —
checks it against 10 rules, and reports a risk score from 0 to 100
with a verdict of OK, REVIEW or BLOCK.

MCP servers hand an agent new capabilities: file access, shell
commands, network calls, secrets. A single over-privileged server
can undo every guardrail the agent itself carries, so the audit
belongs at the connection step, before the agent ever calls a tool.

## Why this exists

The rest of this series guards the agent: prompt-injection
detection on input, tool-permission auditing before it runs,
output-leak scanning after it responds, context-poison scanning on
everything retrieved in between, corpus-poison scanning before
content is indexed, and a jailbreak test that scores the model
itself. None of that helps if the agent connects to an MCP server
that offers `run_command` with no authentication over HTTP. This
tool closes that gap: it scores the server, not the agent.

## The rules

| Rule | Severity | Check |
|---|---|---|
| R01 | critical | Shell / command execution tool |
| R02 | high | Destructive tool with no confirmation parameter |
| R03 | high | File-write tool with no declared allowed paths |
| R04 | high | Network egress / open-world tool |
| R05 | high | Secret / credential access (env vars, tokens, passwords) |
| R06 | high | Remote transport (SSE / streamable HTTP) with no authentication |
| R07 | medium | Tool with no safety annotations |
| R08 | medium | Sensitive resource exposed (config files, credentials, env) |
| R09 | medium | Unscoped file read (arbitrary path, no allowed paths) |
| R10 | low | Missing server metadata (name, version or description) |

Weights: critical 25, high 15, medium 8, low 3, capped at 100.
Verdict: BLOCK at 60 or above (or any critical finding), REVIEW
at 25 or above, otherwise OK. Every finding carries a remediation
note; run `--list-rules` to see all ten with their advice.

## Input format

A JSON object describing one MCP server. Tool `parameters` may be
a flat `{name: type}` map or a JSON Schema object with a
`properties` map; only the parameter names are inspected. `auth`
may be omitted for stdio servers (local transport), but a remote
transport with no auth is a finding. `annotations` follow the MCP
spec: `readOnlyHint`, `destructiveHint`, `idempotentHint` and
`openWorldHint`. Declare `allowed_paths` on the server to clear
the file-scope rules (R03, R09).

```json
{
  "name": "dev-ops-helper",
  "version": "0.3.1",
  "transport": "streamable-http",
  "auth": {"type": "none"},
  "tools": [
    {"name": "run_command",
     "description": "Run any shell command on the host.",
     "annotations": {"readOnlyHint": false, "destructiveHint": true,
                     "idempotentHint": false, "openWorldHint": false},
     "parameters": {"command": "string"}}
  ],
  "resources": [{"uri": "file:///home/user/.env", "name": "env-file"}],
  "prompts": []
}
```

## Usage

```bash
python mcp_server_auditor.py examples/risky-server.json
python mcp_server_auditor.py examples/safe-server.json --json report.json
python mcp_server_auditor.py server.json --fail-above 25
python mcp_server_auditor.py server.json --min-severity high
python mcp_server_auditor.py --list-rules
```

Exit code: `0` = risk score at or below `--fail-above`
(default 60), `1` = score above it, `2` = usage/input error.

## Example

```text
$ python mcp_server_auditor.py examples/risky-server.json
Server: dev-ops-helper (transport: streamable-http, 6 tool(s), 2 resource(s))
Risk score: 100/100 (12 finding(s)) -> BLOCK
  critical: 1, high: 7, medium: 4, low: 0
  [CRITICAL] R01 run_command: tool can execute shell commands
  [HIGH] R02 delete_file: destructive tool has no confirmation parameter
  [HIGH] R03 write_file: file-write tool with no server-level allowed_paths
  [HIGH] R06 dev-ops-helper: remote transport (streamable-http) with no authentication
  [MEDIUM] R08 env-file: resource exposes sensitive data: file:///home/user/.env
  ...

$ python mcp_server_auditor.py examples/safe-server.json
Server: weather-readonly (transport: stdio, 2 tool(s), 1 resource(s))
Risk score: 15/100 (1 finding(s)) -> OK
  critical: 0, high: 1, medium: 0, low: 0
  [HIGH] R04 get_weather: tool reaches the network or the open world
```

The safe server still carries one high finding: a weather lookup
genuinely reaches the open world, and the score says so honestly
while still passing — 15 out of 100 is a read-only network call,
not a shell.

## Tests

```bash
python -m unittest discover tests -v   # 26 tests, all passing
```

## Files

- `mcp_server_auditor.py` — the auditor (standard library only)
- `tests/test_mcp_server_auditor.py` — 26 unit tests
- `examples/safe-server.json` — read-only weather server, 15/100, OK
- `examples/risky-server.json` — unauthenticated remote dev-ops
  server with a shell, file writes and secrets, 100/100, BLOCK
- `examples/sample-report.json` — JSON report from the risky run

## Limitations

The audit is static: it reads a server description, it never
connects to a server or executes a tool, so a server that lies
about its tools or hides a capability in a vague description will
be under-scored. Name-based detection is heuristic — a tool called
`helper` that runs shell commands under the hood will be missed
unless its description says so. Treat the score as a repeatable
triage gate for the servers you approve, not a proof of safety,
and always review BLOCK findings by hand before connecting.

## How it fits the series

This continues the AI-agent guardrail series: prompt-injection
detection on user input, tool-permission auditing before an agent
runs, output-leak scanning after it responds, context-poison
scanning on everything retrieved in between, corpus-poison
scanning before content is indexed, a jailbreak test that scores
the model itself, and now a server audit that scores the MCP
servers the agent connects to — the last unguarded surface in the
chain.

## LinkedIn fit

One line: it is the supply-chain gate for the AI red teaming of
LLM agents that the author's profile leads with — the tool that
stops an agent inheriting a stranger's shell before the first
prompt is ever sent.

## Author

Sajid Hussain Raza — University Cybersecurity Lecturer, AI Security
Engineer and AI Red Teamer, Director and Co-founder of Cyber Legends,
Lahore. https://cyberlegends.org

## License

MIT.
