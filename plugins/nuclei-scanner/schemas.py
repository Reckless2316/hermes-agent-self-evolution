"""Tool schemas for the Nuclei Scanner plugin."""

LIST_WORKFLOWS = {
    "name": "list_nuclei_workflows",
    "description": (
        "List the Nuclei workflow YAML files in the configured workflows directory. "
        "Optionally filter by a keyword (e.g. 'wordpress', 'cisco', 'jira') to find "
        "the exact workflow filename before running a scan."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Optional case-insensitive substring to match against workflow filenames.",
            },
        },
        "required": [],
    },
}

RUN_WORKFLOW = {
    "name": "run_nuclei_workflow",
    "description": (
        "Run one Nuclei workflow YAML file against a target URL or host. The target must be "
        "inside the operator's allowed_targets scope; out-of-scope targets are refused. "
        "Call list_nuclei_workflows first if you are unsure of the exact workflow filename."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or host to scan (e.g. 'https://example.com').",
            },
            "workflow_name": {
                "type": "string",
                "description": "Workflow filename as returned by list_nuclei_workflows (e.g. 'wordpress-workflow.yaml').",
            },
            "severity": {
                "type": "string",
                "description": "Optional comma-separated severity filter: info, low, medium, high, critical, unknown.",
            },
        },
        "required": ["target", "workflow_name"],
    },
}
