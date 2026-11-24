# nuclei-scanner (Hermes plugin)

Lets Hermes list your Nuclei workflow files and run one against a target you have
authorized. Built and tested against Hermes Agent 0.19.0 and nuclei v3.

- `list_nuclei_workflows(query?)`: workflow YAML files in your workflows directory,
  including subfolders.
- `run_nuclei_workflow(target, workflow_name, severity?)`: runs
  `nuclei -u <target> -w <file> -jsonl` and returns trimmed findings as JSON.
- `/nuclei list [query]` and `/nuclei <target> <workflow.yaml> [severity,...]`: the same
  two actions from inside a session, without spending model tokens.

## Install

```bash
mkdir -p ~/.hermes/plugins
unzip nuclei-scanner.zip -d ~/.hermes/plugins/     # creates ~/.hermes/plugins/nuclei-scanner/
hermes plugins enable nuclei-scanner
```

`hermes plugins enable` then asks whether to let the plugin replace built-in tools. It
doesn't need to, and the same question appears for every non-bundled plugin. Answer **N**.

Add the settings to `~/.hermes/config.yaml`, then restart Hermes:

```yaml
plugins:
  entries:
    nuclei-scanner:
      settings:
        workflows_dir: "~/nuclei-templates/workflows"
        allowed_targets:              # required: scans are refused until this is set
          - example.com               # exact host (a :port suffix is ignored)
          - "*.staging.example.com"   # any subdomain, not the apex
          - 10.0.0.0/8                # IPv4/IPv6 address or CIDR (IPv6 bare, no brackets)
        timeout_seconds: 300
        rate_limit: 0                 # nuclei -rl (requests/second); 0 = nuclei default
        concurrency: 0                # nuclei -c; 0 = nuclei default
        max_findings: 25              # findings returned to the model per run
```

`hermes plugins list` should show `nuclei-scanner` as enabled.

Each setting also has an environment fallback: `NUCLEI_WORKFLOWS_DIR`,
`NUCLEI_ALLOWED_TARGETS` (comma-separated), `NUCLEI_TIMEOUT_SECONDS`, `NUCLEI_RATE_LIMIT`,
`NUCLEI_CONCURRENCY`, `NUCLEI_MAX_FINDINGS`.

## Safety behaviour

- **Scope allowlist.** A target whose host is not in `allowed_targets` is refused before nuclei
  starts. The model chooses the target, and a web page or file it reads could try to steer a
  scan elsewhere, so the check is deliberately outside the model's control. `"*"` allows any
  host; use it only if you accept that.
- **Invalid scope entries are an error, not ignored.** An entry that is not a host, `*.domain`,
  IP or CIDR refuses every scan and names the bad entry.
- **Targets** must be an `http://` or `https://` URL, or a bare host with optional port.
  Anything starting with `-`, containing spaces or quotes, carrying `user@`, or using a
  wildcard is rejected, so a target cannot be read as a nuclei flag.
- **Workflows** must resolve to a `.yaml`/`.yml` file inside `workflows_dir`; symlinks that
  point outside it are refused. **Severities** must come from nuclei's own list.
- No shell is used. Raw requests and responses are dropped from findings, and results are
  capped at `max_findings`. A timeout returns the findings collected so far.

## Limits to know about

- The scope check applies to the target you pass. A template that follows redirects can reach
  a different host, so keep `allowed_targets` as tight as your engagement.
- `/nuclei` runs without the model, but anyone who can message the bot can still use it. Limit
  who can talk to the gateway.

## Tests

```bash
pip install pytest && python -m pytest tests     # offline; uses a fake nuclei binary
```
