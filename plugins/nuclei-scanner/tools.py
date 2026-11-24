"""Tool handlers for listing and running Nuclei workflows.

Every handler returns a JSON string and never raises, as Hermes requires.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

PLUGIN_ID = "nuclei-scanner"
SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")
YAML_SUFFIXES = {".yaml", ".yml"}
SCHEMES = ("http", "https")
DEFAULT_MAX_FINDINGS = 25
MAX_TARGET_LENGTH = 2048
_TEXT_LIMIT = 500

# Characters allowed in a target: URL and host characters only. Whitespace, quotes,
# backslashes and "@" (userinfo) are refused, and a leading "-" would be read by nuclei
# as a flag. "*" is refused too, so a wildcard can never be scanned as if it were a host.
_TARGET_RE = re.compile(r"^[A-Za-z0-9\[][A-Za-z0-9._~:/?#\[\]!$&()+,;=%-]*$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


@dataclass
class Settings:
    workflows_dir: Path
    timeout_seconds: int = 300
    rate_limit: int = 0          # requests/second; 0 = nuclei default
    concurrency: int = 0         # parallel templates; 0 = nuclei default
    max_findings: int = DEFAULT_MAX_FINDINGS
    allowed_targets: list[str] = field(default_factory=list)
    invalid_scope: list[str] = field(default_factory=list)


def _raw_settings() -> dict:
    """Return plugins.entries.nuclei-scanner.settings from Hermes config.yaml."""
    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly() or {}
    except Exception:
        return {}
    entry = ((cfg.get("plugins") or {}).get("entries") or {}).get(PLUGIN_ID) or {}
    settings = entry.get("settings") or {}
    return settings if isinstance(settings, dict) else {}


def _int(value, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


# -- scope ------------------------------------------------------------------

def _valid_hostname(name: str) -> bool:
    return 0 < len(name) <= 253 and bool(_HOSTNAME_RE.match(name))


def _ip_or_hostname(text: str) -> str | None:
    """Return the normalized IP address or hostname for text, or None if it is neither."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text if _valid_hostname(text) else None


def _split_port(text: str) -> str:
    """Drop one ':port' suffix. IPv6 literals contain several colons and are left alone."""
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        if port.isdigit() and 0 < int(port) <= 65535:
            return host
    return text


def normalize_scope_entry(entry: str) -> str | None:
    """Canonical form of one allowed_targets entry, or None if it is not a valid scope.

    Accepts '*', '*.domain', a hostname (a ':port' is ignored), an IP address, or a CIDR.
    """
    text = entry.strip().lower()
    if text == "*":
        return text
    text = text.rstrip(".")
    if not text:
        return None
    if "/" in text:
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            return None
        return text
    if text.startswith("*."):
        return text if _valid_hostname(text[2:]) else None
    return _ip_or_hostname(_split_port(text))


def target_host(target: str) -> str | None:
    """Normalized host of an http(s) URL or bare host[:port] target, or None if malformed."""
    if len(target) > MAX_TARGET_LENGTH or not _TARGET_RE.match(target):
        return None
    try:
        if "://" in target:
            if target.split("://", 1)[0].lower() not in SCHEMES:
                return None
            parts = urlsplit(target)
        else:
            parts = urlsplit(f"//{target}")
        _ = parts.port  # raises ValueError on a malformed port
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    return _ip_or_hostname(host.rstrip("."))


def host_in_scope(host: str, allowed: list[str]) -> bool:
    """Match a normalized host against exact names, '*.domain' wildcards, IPs/CIDRs, or '*'."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for entry in allowed:
        if entry == "*" or entry == host:
            return True
        if entry.startswith("*.") and ip is None and host.endswith(entry[1:]):
            return True
        if ip is not None:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
    return False


def get_settings() -> Settings:
    raw = _raw_settings()

    def pick(key: str, env: str, default):
        value = raw.get(key)
        if value in (None, "", []):
            value = os.environ.get(env)
        return default if value in (None, "") else value

    scope = pick("allowed_targets", "NUCLEI_ALLOWED_TARGETS", [])
    if isinstance(scope, str):
        entries = scope.split(",")
    elif isinstance(scope, (list, tuple)):
        entries = list(scope)
    else:
        entries = [scope]

    allowed: list[str] = []
    invalid: list[str] = []
    for entry in entries:
        text = str(entry).strip()
        if not text:
            continue
        normalized = normalize_scope_entry(text)
        if normalized is None:
            invalid.append(text)
        elif normalized not in allowed:
            allowed.append(normalized)

    return Settings(
        workflows_dir=Path(
            str(pick("workflows_dir", "NUCLEI_WORKFLOWS_DIR", "~/nuclei-templates/workflows"))
        ).expanduser().resolve(),
        timeout_seconds=_int(pick("timeout_seconds", "NUCLEI_TIMEOUT_SECONDS", 300), 300, 1),
        rate_limit=_int(pick("rate_limit", "NUCLEI_RATE_LIMIT", 0), 0, 0),
        concurrency=_int(pick("concurrency", "NUCLEI_CONCURRENCY", 0), 0, 0),
        max_findings=_int(
            pick("max_findings", "NUCLEI_MAX_FINDINGS", DEFAULT_MAX_FINDINGS),
            DEFAULT_MAX_FINDINGS, 1,
        ),
        allowed_targets=allowed,
        invalid_scope=invalid,
    )


# -- findings ---------------------------------------------------------------

def _workflow_files(workflows_dir: Path) -> list[str]:
    return sorted(
        p.relative_to(workflows_dir).as_posix()
        for p in workflows_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in YAML_SUFFIXES
    )


def _clip(value):
    return value[:_TEXT_LIMIT] if isinstance(value, str) else value


def _summarize(finding: dict) -> dict:
    """Keep the fields that matter; drop raw requests and responses that flood context.

    Every field is type-checked: one unexpected shape must not discard the whole scan.
    """
    info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
    extracted = finding.get("extracted-results")
    reference = info.get("reference")
    out = {
        "template_id": finding.get("template-id"),
        "name": _clip(info.get("name")),
        "severity": info.get("severity"),
        "type": finding.get("type"),
        "host": finding.get("host"),
        "matched_at": _clip(finding.get("matched-at")),
        "matcher_name": finding.get("matcher-name"),
        "extracted_results": (
            [_clip(str(r)) for r in extracted[:5]] if isinstance(extracted, list) else None
        ),
        "description": _clip(info.get("description")),
        "reference": (
            [_clip(str(r)) for r in reference[:3]] if isinstance(reference, list) else None
        ),
        "timestamp": finding.get("timestamp"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def _parse_findings(stdout: str, max_findings: int) -> tuple[list[dict], int]:
    findings, total = [], 0
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        total += 1
        if len(findings) >= max_findings:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            findings.append({"raw": _clip(line)})
            continue
        if isinstance(obj, dict):
            findings.append(_summarize(obj))
        else:
            findings.append({"raw": _clip(str(obj))})
    return findings, total


def _err(message: str, **extra) -> str:
    return json.dumps({"error": message, **extra})


# -- handlers ---------------------------------------------------------------

def list_nuclei_workflows(args: dict, **kwargs) -> str:
    """List workflow YAML files in the configured directory."""
    try:
        settings = get_settings()
        if not settings.workflows_dir.is_dir():
            return _err(
                f"Workflows directory not found: {settings.workflows_dir}. Set "
                f"plugins.entries.{PLUGIN_ID}.settings.workflows_dir in config.yaml."
            )
        query = str((args or {}).get("query") or "").strip().lower()
        files = _workflow_files(settings.workflows_dir)
        if query:
            files = [f for f in files if query in f.lower()]
        return json.dumps({
            "workflows_dir": str(settings.workflows_dir),
            "count": len(files),
            "workflows": files,
        })
    except Exception as exc:
        return _err(f"Failed to list workflows: {exc}")


def run_nuclei_workflow(args: dict, **kwargs) -> str:
    """Validate inputs, enforce scope, and run one Nuclei workflow."""
    try:
        args = args or {}
        target = str(args.get("target") or "").strip()
        workflow_name = str(args.get("workflow_name") or "").strip()
        severity_raw = str(args.get("severity") or "").strip().lower()
        if not target or not workflow_name:
            return _err("Both 'target' and 'workflow_name' are required.")

        settings = get_settings()
        if settings.invalid_scope:
            return _err(
                f"plugins.entries.{PLUGIN_ID}.settings.allowed_targets has invalid entries "
                f"{settings.invalid_scope}. Use a host, *.domain, IP or CIDR."
            )
        host = target_host(target)
        if host is None:
            return _err("Invalid target: expected a URL or host such as 'https://example.com'.")
        if not settings.allowed_targets:
            return _err(
                "No scan scope configured. List the hosts you are authorized to test in "
                f"plugins.entries.{PLUGIN_ID}.settings.allowed_targets in config.yaml."
            )
        if not host_in_scope(host, settings.allowed_targets):
            return _err(
                f"Target host '{host}' is outside the configured allowed_targets scope.",
                allowed_targets=settings.allowed_targets,
            )

        severities = [s.strip() for s in severity_raw.split(",") if s.strip()]
        bad = [s for s in severities if s not in SEVERITIES]
        if bad:
            return _err(f"Invalid severity {bad}. Allowed: {', '.join(SEVERITIES)}.")

        if not settings.workflows_dir.is_dir():
            return _err(f"Workflows directory does not exist: {settings.workflows_dir}")
        workflow_path = (settings.workflows_dir / workflow_name).resolve()
        if not workflow_path.is_relative_to(settings.workflows_dir):
            return _err("Invalid workflow_name: it must be inside the workflows directory.")
        if workflow_path.suffix.lower() not in YAML_SUFFIXES or not workflow_path.is_file():
            return _err(
                f"Workflow '{workflow_name}' not found in {settings.workflows_dir}. "
                "Use list_nuclei_workflows to see available files."
            )

        nuclei = shutil.which("nuclei")
        if not nuclei:
            return _err("The 'nuclei' binary was not found in PATH. Install Nuclei first.")

        cmd = [nuclei, "-u", target, "-w", str(workflow_path), "-jsonl", "-silent", "-nc", "-duc"]
        if severities:
            cmd += ["-severity", ",".join(severities)]
        if settings.rate_limit:
            cmd += ["-rl", str(settings.rate_limit)]
        if settings.concurrency:
            cmd += ["-c", str(settings.concurrency)]

        timed_out = False
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=settings.timeout_seconds,
                check=False, stdin=subprocess.DEVNULL,
            )
            stdout, stderr, exit_code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out, exit_code = True, None
            stdout, stderr = (
                s.decode(errors="replace") if isinstance(s, bytes) else (s or "")
                for s in (exc.stdout, exc.stderr)
            )

        findings, total = _parse_findings(stdout, settings.max_findings)
        result = {
            "target": target,
            "workflow": workflow_path.relative_to(settings.workflows_dir).as_posix(),
            "exit_code": exit_code,
            "findings_count": total,
            "findings": findings,
            "truncated": total > len(findings),
            "stderr": (stderr or "").strip()[-1000:],
        }
        if timed_out:
            result["error"] = (
                f"Nuclei scan timed out after {settings.timeout_seconds} seconds; "
                "findings collected before the timeout are included."
            )
        return json.dumps(result)
    except Exception as exc:
        return _err(f"Nuclei execution failed: {exc}")


# -- /nuclei slash command --------------------------------------------------

USAGE = "Usage: /nuclei list [query]  |  /nuclei <target> <workflow.yaml> [severity,...]"


def nuclei_command(raw_args: str) -> str:
    """Run the tools directly from a session, without spending LLM tokens."""
    parts = (raw_args or "").split()
    if not parts or parts[0] in {"help", "-h", "--help"}:
        return USAGE
    if parts[0] == "list":
        data = json.loads(list_nuclei_workflows({"query": " ".join(parts[1:])}))
        if "error" in data:
            return f"Error: {data['error']}"
        return f"{data['count']} workflow(s) in {data['workflows_dir']}\n" + "\n".join(data["workflows"])
    if len(parts) not in (2, 3):
        return USAGE
    data = json.loads(run_nuclei_workflow({
        "target": parts[0], "workflow_name": parts[1],
        "severity": parts[2] if len(parts) == 3 else "",
    }))
    if "error" in data and "findings" not in data:
        return f"Error: {data['error']}"
    lines = [f"{data['workflow']} -> {data['target']}: {data['findings_count']} finding(s)"]
    if data.get("error"):
        lines.append(f"Warning: {data['error']}")
    for f in data["findings"]:
        lines.append(
            f"[{f.get('severity', '?')}] {f.get('template_id') or f.get('raw', '?')} "
            f"{f.get('matched_at', '')}".rstrip()
        )
    if data["truncated"]:
        lines.append(f"... showing first {len(data['findings'])}")
    if not data["findings"] and data.get("stderr"):
        lines.append(f"stderr: {data['stderr']}")
    return "\n".join(lines)
