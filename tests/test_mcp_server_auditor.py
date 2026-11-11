"""Unit tests for mcp_server_auditor.py."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcp_server_auditor as auditor

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(HERE, "..", "examples")


def load_example(name):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as handle:
        return json.load(handle)


def server_with(**overrides):
    base = {"name": "test-server", "version": "1.0.0",
            "description": "A test server.", "transport": "stdio",
            "tools": [], "resources": [], "prompts": []}
    base.update(overrides)
    return base


def tool(name, description="", annotations=None, parameters=None):
    return {"name": name, "description": description,
            "annotations": annotations or {},
            "parameters": parameters or {}}


ANNOTATED_SAFE = {"readOnlyHint": True, "destructiveHint": False,
                  "idempotentHint": True, "openWorldHint": False}


class TestExamples(unittest.TestCase):
    def test_safe_server_scores_low_and_passes(self):
        server = load_example("safe-server.json")
        findings = auditor.audit(server)
        summary = auditor.summarize(findings)
        # One open-world read-only tool: a single high finding, still OK.
        self.assertEqual(summary["score"], 15)
        self.assertEqual(summary["verdict"], "OK")
        self.assertEqual([f["rule"] for f in findings], ["R04"])

    def test_risky_server_is_blocked(self):
        server = load_example("risky-server.json")
        findings = auditor.audit(server)
        summary = auditor.summarize(findings)
        self.assertEqual(summary["score"], 100)
        self.assertEqual(summary["verdict"], "BLOCK")
        self.assertEqual(summary["total_findings"], 12)
        self.assertEqual(summary["by_severity"]["critical"], 1)
        rules = sorted(f["rule"] for f in findings)
        self.assertEqual(rules, ["R01", "R02", "R02", "R02", "R03",
                                 "R04", "R05", "R06", "R07", "R08",
                                 "R08", "R09"])


class TestRules(unittest.TestCase):
    def test_shell_tool_is_critical(self):
        server = server_with(tools=[
            tool("run_command", "Run a shell command",
                 ANNOTATED_SAFE, {"command": "string"})])
        findings = auditor.audit(server)
        self.assertIn("R01", [f["rule"] for f in findings])
        self.assertEqual(findings[0]["severity"], "critical")

    def test_destructive_tool_with_confirm_is_fine(self):
        server = server_with(tools=[
            tool("delete_file", "Delete a file",
                 {"readOnlyHint": False, "destructiveHint": True,
                  "idempotentHint": True, "openWorldHint": False},
                 {"path": "string", "confirm": "boolean"})])
        rules = [f["rule"] for f in auditor.audit(server)]
        self.assertNotIn("R02", rules)

    def test_destructive_tool_without_confirm_is_flagged(self):
        server = server_with(tools=[
            tool("delete_file", "Delete a file",
                 {"readOnlyHint": False, "destructiveHint": True,
                  "idempotentHint": True, "openWorldHint": False},
                 {"path": "string"})])
        self.assertIn("R02", [f["rule"] for f in auditor.audit(server)])

    def test_allowed_paths_clears_write_and_read_rules(self):
        server = server_with(
            allowed_paths=["/srv/data"],
            tools=[tool("write_file", "Write a file", ANNOTATED_SAFE,
                        {"path": "string"}),
                   tool("read_file", "Read a file", ANNOTATED_SAFE,
                        {"path": "string"})])
        rules = [f["rule"] for f in auditor.audit(server)]
        self.assertNotIn("R03", rules)
        self.assertNotIn("R09", rules)

    def test_write_without_allowed_paths_is_flagged(self):
        server = server_with(tools=[
            tool("write_file", "Write a file", ANNOTATED_SAFE,
                 {"path": "string"})])
        self.assertIn("R03", [f["rule"] for f in auditor.audit(server)])

    def test_stdio_without_auth_is_fine(self):
        server = server_with(transport="stdio", auth={"type": "none"})
        self.assertNotIn("R06", [f["rule"] for f in auditor.audit(server)])

    def test_remote_with_auth_is_fine(self):
        server = server_with(transport="sse", auth={"type": "api-key"})
        self.assertNotIn("R06", [f["rule"] for f in auditor.audit(server)])

    def test_remote_without_auth_is_flagged(self):
        server = server_with(transport="streamable-http",
                             auth={"type": "none"})
        self.assertIn("R06", [f["rule"] for f in auditor.audit(server)])

    def test_tool_without_annotations_is_flagged(self):
        server = server_with(tools=[tool("ping", "Check the server")])
        self.assertIn("R07", [f["rule"] for f in auditor.audit(server)])

    def test_sensitive_resource_is_flagged(self):
        server = server_with(resources=[
            {"uri": "file:///home/user/.env", "name": "env-file"}])
        self.assertIn("R08", [f["rule"] for f in auditor.audit(server)])

    def test_secret_tool_is_flagged(self):
        server = server_with(tools=[
            tool("get_api_key", "Return the stored API key",
                 ANNOTATED_SAFE)])
        self.assertIn("R05", [f["rule"] for f in auditor.audit(server)])

    def test_open_world_hint_is_flagged(self):
        server = server_with(tools=[
            tool("fetch_url", "Fetch a URL",
                 {"readOnlyHint": True, "destructiveHint": False,
                  "idempotentHint": True, "openWorldHint": True},
                 {"url": "string"})])
        self.assertIn("R04", [f["rule"] for f in auditor.audit(server)])

    def test_missing_version_is_flagged(self):
        server = server_with()
        del server["version"]
        self.assertIn("R10", [f["rule"] for f in auditor.audit(server)])

    def test_json_schema_parameters_are_read(self):
        server = server_with(tools=[
            tool("read_file", "Read a file", ANNOTATED_SAFE,
                 {"type": "object",
                  "properties": {"path": {"type": "string"}}})])
        self.assertIn("R09", [f["rule"] for f in auditor.audit(server)])


class TestScoring(unittest.TestCase):
    def test_two_high_findings_is_review(self):
        server = server_with(tools=[
            tool("fetch_url", "Fetch a URL",
                 {"readOnlyHint": True, "destructiveHint": False,
                  "idempotentHint": True, "openWorldHint": True},
                 {"url": "string"}),
            tool("send_email", "Send an email",
                 {"readOnlyHint": False, "destructiveHint": False,
                  "idempotentHint": False, "openWorldHint": True},
                 {"to": "string"})])
        summary = auditor.summarize(auditor.audit(server))
        self.assertEqual(summary["score"], 30)
        self.assertEqual(summary["verdict"], "REVIEW")

    def test_score_is_capped_at_100(self):
        server = load_example("risky-server.json")
        summary = auditor.summarize(auditor.audit(server))
        self.assertEqual(summary["score"], 100)


class TestLoadingAndCli(unittest.TestCase):
    def test_invalid_json_is_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as handle:
            handle.write("{not json")
            path = handle.name
        try:
            with self.assertRaises(ValueError):
                auditor.load_server(path)
        finally:
            os.unlink(path)

    def test_non_object_is_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as handle:
            handle.write("[1, 2, 3]")
            path = handle.name
        try:
            with self.assertRaises(ValueError):
                auditor.load_server(path)
        finally:
            os.unlink(path)

    def test_cli_safe_exits_zero(self):
        code = auditor.main([os.path.join(EXAMPLES, "safe-server.json")])
        self.assertEqual(code, 0)

    def test_cli_risky_exits_one(self):
        code = auditor.main([os.path.join(EXAMPLES, "risky-server.json")])
        self.assertEqual(code, 1)

    def test_cli_risky_passes_with_fail_above_100(self):
        code = auditor.main([os.path.join(EXAMPLES, "risky-server.json"),
                             "--fail-above", "100"])
        self.assertEqual(code, 0)

    def test_cli_min_severity_filters(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as handle:
            json.dump({"summary": None}, handle)
            out_path = handle.name
        try:
            code = auditor.main(
                [os.path.join(EXAMPLES, "risky-server.json"),
                 "--min-severity", "critical", "--json", out_path])
            self.assertEqual(code, 0)  # only the critical finding remains
            with open(out_path, encoding="utf-8") as handle:
                report = json.load(handle)
            self.assertEqual(report["summary"]["total_findings"], 1)
            self.assertEqual(report["findings"][0]["rule"], "R01")
        finally:
            os.unlink(out_path)

    def test_cli_list_rules_exits_zero(self):
        self.assertEqual(auditor.main(["--list-rules"]), 0)

    def test_cli_missing_file_exits_two(self):
        self.assertEqual(auditor.main(["/no/such/server.json"]), 2)


if __name__ == "__main__":
    unittest.main()
