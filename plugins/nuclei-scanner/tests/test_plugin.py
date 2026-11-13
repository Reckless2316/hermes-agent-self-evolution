"""Offline tests: a fake `nuclei` on PATH, no Hermes install and no network."""

import importlib.util
import json
import os
import stat
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def plugin():
    # Load the way Hermes does: a package from a directory with a hyphenated name.
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.nuclei_scanner", PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    sys.modules.setdefault("hermes_plugins", types.ModuleType("hermes_plugins")).__path__ = []
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


FAKE_NUCLEI = """#!/bin/sh
printf '%s\\n' "$@" > "$ARGS_OUT"
[ -n "$FAKE_SLEEP" ] && { echo '{"template-id":"early","info":{"severity":"low"}}'; sleep "$FAKE_SLEEP"; }
echo '{"template-id":"wp-detect","info":{"name":"WP","severity":"info"},"host":"h","matched-at":"https://example.com/","request":"GET / HTTP/1.1","response":"BIG"}'
echo '{"template-id":"wp-xmlrpc","info":{"name":"X","severity":"high"},"matched-at":"https://example.com/xmlrpc.php"}'
echo 'not json'
"""


@pytest.fixture
def env(plugin, tmp_path, monkeypatch):
    wf = tmp_path / "workflows"
    (wf / "sub").mkdir(parents=True)
    for name in ("wordpress-workflow.yaml", "cisco-asa-workflow.yaml", "sub/jira-workflow.yml", "notes.txt"):
        (wf / name).write_text("id: x\n")
    (tmp_path / "secret.yaml").write_text("id: outside\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "nuclei"
    fake.write_text(FAKE_NUCLEI)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("ARGS_OUT", str(tmp_path / "args"))
    settings = {"workflows_dir": str(wf), "allowed_targets": ["example.com", "*.lab.test", "10.0.0.0/8"]}
    monkeypatch.setattr(plugin.tools, "_raw_settings", lambda: settings)
    return type("Env", (), {"tools": plugin.tools, "settings": settings, "tmp": tmp_path, "bindir": bindir})


def run(env, **args):
    return json.loads(env.tools.run_nuclei_workflow(args))


def argv(env):
    return (env.tmp / "args").read_text().splitlines()


def test_register_wires_tools_and_command(plugin):
    calls = {"tools": [], "commands": []}

    class Ctx:
        def register_tool(self, **kw):
            calls["tools"].append(kw)

        def register_command(self, name, handler, description="", args_hint=""):
            calls["commands"].append(name)

    plugin.register(Ctx())
    assert [t["name"] for t in calls["tools"]] == ["list_nuclei_workflows", "run_nuclei_workflow"]
    assert all(t["schema"]["name"] == t["name"] and callable(t["handler"]) for t in calls["tools"])
    assert calls["commands"] == ["nuclei"]


def test_manifest_matches_registered_tools():
    text = (PLUGIN_DIR / "plugin.yaml").read_text()
    assert "manifest_version: 1" in text
    assert "- list_nuclei_workflows" in text and "- run_nuclei_workflow" in text


def test_list_and_filter(env):
    data = json.loads(env.tools.list_nuclei_workflows({}))
    assert data["workflows"] == ["cisco-asa-workflow.yaml", "sub/jira-workflow.yml", "wordpress-workflow.yaml"]
    assert json.loads(env.tools.list_nuclei_workflows({"query": "WORDPRESS"}))["count"] == 1


def test_list_missing_dir(env):
    env.settings["workflows_dir"] = str(env.tmp / "nope")
    assert "not found" in json.loads(env.tools.list_nuclei_workflows({}))["error"]


def test_run_success_summarizes_findings(env):
    data = run(env, target="https://example.com", workflow_name="wordpress-workflow.yaml", severity="High, critical")
    assert data["exit_code"] == 0 and data["findings_count"] == 3 and not data["truncated"]
    assert data["findings"][0] == {
        "template_id": "wp-detect", "name": "WP", "severity": "info", "host": "h",
        "matched_at": "https://example.com/",
    }
    assert data["findings"][2] == {"raw": "not json"}
    args = argv(env)
    assert args[:2] == ["-u", "https://example.com"]
    assert args[args.index("-severity") + 1] == "high,critical"
    assert "-rl" not in args and "-c" not in args


def test_rate_limit_and_concurrency_flags(env):
    env.settings.update(rate_limit=20, concurrency="5")
    run(env, target="example.com", workflow_name="sub/jira-workflow.yml")
    args = argv(env)
    assert args[args.index("-rl") + 1] == "20" and args[args.index("-c") + 1] == "5"


def test_max_findings_truncates(env):
    env.settings["max_findings"] = 1
    data = run(env, target="example.com", workflow_name="wordpress-workflow.yaml")
    assert len(data["findings"]) == 1 and data["findings_count"] == 3 and data["truncated"]


@pytest.mark.parametrize("target", [
    "https://evil.org", "example.com.evil.org", "notexample.com", "lab.test",
    "https://example.com@evil.org/", "11.0.0.1",
])
def test_out_of_scope_refused(env, target):
    data = run(env, target=target, workflow_name="wordpress-workflow.yaml")
    assert "error" in data and not (env.tmp / "args").exists()


@pytest.mark.parametrize("target", [
    "example.com", "EXAMPLE.com:8443", "https://example.com/path?q=1", "http://a.lab.test",
    "10.1.2.3", "https://10.1.2.3:8443/",
])
def test_in_scope_allowed(env, target):
    assert "error" not in run(env, target=target, workflow_name="wordpress-workflow.yaml")


def test_empty_scope_refuses_everything(env):
    env.settings["allowed_targets"] = []
    assert "No scan scope" in run(env, target="example.com", workflow_name="wordpress-workflow.yaml")["error"]


def test_scope_from_env_and_star(env, monkeypatch):
    env.settings["allowed_targets"] = []
    monkeypatch.setenv("NUCLEI_ALLOWED_TARGETS", "*")
    assert "error" not in run(env, target="anything.org", workflow_name="wordpress-workflow.yaml")


@pytest.mark.parametrize("target", ["-l/etc/passwd", "-u evil", "example.com -o /tmp/x", "exa mple.com", "http://example.com:notaport"])
def test_malformed_or_flag_like_target_refused(env, target):
    data = run(env, target=target, workflow_name="wordpress-workflow.yaml")
    assert "Invalid target" in data["error"] and not (env.tmp / "args").exists()


@pytest.mark.parametrize("name", ["../secret.yaml", "/etc/passwd", "notes.txt", "missing.yaml", "sub"])
def test_bad_workflow_refused(env, name):
    data = run(env, target="example.com", workflow_name=name)
    assert "error" in data and not (env.tmp / "args").exists()


def test_symlink_escape_refused(env):
    os.symlink(env.tmp / "secret.yaml", Path(env.settings["workflows_dir"]) / "link.yaml")
    assert "error" in run(env, target="example.com", workflow_name="link.yaml")


def test_invalid_severity_refused(env):
    data = run(env, target="example.com", workflow_name="wordpress-workflow.yaml", severity="high,-o")
    assert "Invalid severity" in data["error"]


def test_missing_args_and_none(env):
    assert "required" in run(env, target="example.com")["error"]
    assert "required" in json.loads(env.tools.run_nuclei_workflow(None))["error"]


def test_nuclei_missing(env):
    (env.bindir / "nuclei").unlink()
    assert "not found in PATH" in run(env, target="example.com", workflow_name="wordpress-workflow.yaml")["error"]


def test_timeout_keeps_partial_findings(env, monkeypatch):
    env.settings["timeout_seconds"] = 1
    monkeypatch.setenv("FAKE_SLEEP", "5")
    data = run(env, target="example.com", workflow_name="wordpress-workflow.yaml")
    assert "timed out after 1 seconds" in data["error"]
    assert data["findings"] == [{"template_id": "early", "severity": "low"}]


def test_slash_command(env):
    cmd = env.tools.nuclei_command
    assert cmd("").startswith("Usage") and cmd("one two three four").startswith("Usage")
    assert "wordpress-workflow.yaml" in cmd("list word")
    out = cmd("https://example.com wordpress-workflow.yaml")
    assert "3 finding(s)" in out and "[high] wp-xmlrpc https://example.com/xmlrpc.php" in out
    assert cmd("https://evil.org wordpress-workflow.yaml").startswith("Error:")
