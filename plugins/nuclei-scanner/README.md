# nuclei-scanner (Hermes plugin)

Lets Hermes list your Nuclei workflow files and run one against a target you have
authorized. Built and tested against Hermes Agent 0.19.0.

- `list_nuclei_workflows(query?)`: workflow YAML files in your workflows directory.
- `run_nuclei_workflow(target, workflow_name, severity?)`: runs `nuclei -u <target> -w <file>`
  and returns trimmed findings as JSON.
- `/nuclei list [query]` and `/nuclei <target> <workflow.yaml> [severity,...]`: the same
  two actions from inside a session, without spending model tokens.

## Install

```bash
mkdir -p ~/.hermes/plugins
unzip nuclei-scanner.zip -d ~/.hermes/plugins/     # creates ~/.hermes/plugins/nuclei-scanner/
hermes plugins enable nuclei-scanner               # answer N to the "override built-in tools" question
```

Then add settings to `~/.hermes/config.yaml` and restart Hermes:

```yaml
plugins:
  entries:
    nuclei-scanner:
      settings:
        workflows_dir: "~/nuclei-templates/workflows"
        allowed_targets:            # required: scans are refused until this is set
          - example.com             # exact host
          - "*.staging.example.com" # any subdomain (not the apex)
          - 10.0.0.0/8              # IP or CIDR
        timeout_seconds: 300
        rate_limit: 0               # nuclei -rl (requests/second); 0 = nuclei default
        concurrency: 0              # nuclei -c; 0 = nuclei default
        max_findings: 100           # findings returned to the model per run
```

`hermes plugins list` should show `nuclei-scanner` as enabled.

Each setting also has an environment fallback: `NUCLEI_WORKFLOWS_DIR`,
`NUCLEI_ALLOWED_TARGETS` (comma-separated), `NUCLEI_TIMEOUT_SECONDS`, `NUCLEI_RATE_LIMIT`,
`NUCLEI_CONCURRENCY`, `NUCLEI_MAX_FINDINGS`.

## Safety behaviour

- **Scope allowlist.** A target whose host is not in `allowed_targets` is refused before nuclei
  starts. This matters because the model picks the target, and a web page or file it reads can
  try to steer it. `"*"` allows any host; use it only if you accept that.
- Targets must look like a URL or host. Anything starting with `-`, containing spaces, or
  carrying `user@` is rejected, so a target cannot be read as a nuclei flag.
- `workflow_name` must resolve to a `.yaml`/`.yml` file inside `workflows_dir` (symlinks out of
  it are refused). `severity` must be from nuclei's own list.
- No shell is used. Raw requests and responses are dropped from findings.
- On timeout, findings collected so far are returned with an `error` field.

## Tests

```bash
pip install pytest && python -m pytest tests     # offline; uses a fake nuclei binary
```
