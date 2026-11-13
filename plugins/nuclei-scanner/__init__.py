"""Nuclei Scanner plugin registration."""

import shutil

from . import schemas, tools


def _nuclei_installed() -> bool:
    """Hide the scan tool from the model when the nuclei CLI is not installed."""
    return shutil.which("nuclei") is not None


def register(ctx):
    """Register the Nuclei tools and the /nuclei slash command with Hermes."""
    ctx.register_tool(
        name="list_nuclei_workflows",
        toolset="nuclei-scanner",
        schema=schemas.LIST_WORKFLOWS,
        handler=tools.list_nuclei_workflows,
        emoji="📋",
    )
    ctx.register_tool(
        name="run_nuclei_workflow",
        toolset="nuclei-scanner",
        schema=schemas.RUN_WORKFLOW,
        handler=tools.run_nuclei_workflow,
        check_fn=_nuclei_installed,
        emoji="🛡️",
    )
    ctx.register_command(
        "nuclei",
        tools.nuclei_command,
        description="List Nuclei workflows or run one against an in-scope target",
        args_hint="list [query] | <target> <workflow.yaml> [severity]",
    )
