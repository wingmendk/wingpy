"""Generate the standalone wingpy skill package."""

import argparse
from pathlib import Path

SKILL_FOLDER_NAME = "wingpy-coding-skill"
SKILL_FILE_NAME = "SKILL.md"

DOCUMENT = r"""
---
name: wingpy-coding-skill
description: 'Use when writing, testing, documenting, reviewing, or generating code that imports wingpy, selects a wingpy client, or automates APIC, Catalyst Center, vManage, FMC, Hyperfabric, ISE, Meraki Dashboard, Modeling Labs, Nautobot, NetBox, Nexus Dashboard, or Splunk Enterprise.'
---
## Purpose

This skill guides agents writing or reviewing code that uses wingpy.
It is a routing and decision layer, not a replacement for the wingpy documentation. Use it to pick the right docs, stay close to documented examples, and avoid avoidable design mistakes.

## When to use

Activate this skill when any of the following are true:

- the codebase imports `wingpy` or any of its clients
- the task mentions a wingpy client or supported platform
- the task involves REST API automation with wingpy
- the task asks for examples, tests, wrappers, integrations, or docs related to wingpy
- the task requires choosing the correct wingpy client for a specific platform

## Procedure

1. Identify the target platform and match it to a documented wingpy client.
2. Read the platform-specific User Guide first for task patterns and examples.
3. Read the matching API Reference page to verify constructor parameters, supported methods, and return behavior.
4. Use the client reference below to check for authentication mode, supported environment variables, and the best official API documentation source.
5. Use the FAQ only for shared behavior such as context managers, exceptions, environment variables, and concurrency patterns.
6. Read the general User Guide for configuration details such as logging, error handling, or concurrency.
7. Verify toolchain dependencies, like package manager, virtual environment, and environment variables, before running tests and run required commands in the detected project environment.
8. Write Pythonic solutions using documented wingpy patterns. Use the guardrails and coding patterns below to avoid common mistakes and anti-patterns.

## Client Reference

### Cisco APIC

- Client: `wingpy.CiscoAPIC`
- Auth: session
- Environment variables: `WINGPY_APIC_USERNAME`, `WINGPY_APIC_PASSWORD`, `WINGPY_APIC_BASE_URL`
- User Guide: [Cisco APIC User Guide](https://wingpy.automation.wingmen.dk/user-guide/apic/)
- API Reference: [Cisco APIC API Reference](https://wingpy.automation.wingmen.dk/api/apic/)
- Official REST docs: [Cisco Developer APIC Search](https://developer.cisco.com/docs/search/?q=APIC)

### Cisco Catalyst Center

- Client: `wingpy.CiscoCatalystCenter`
- Auth: session
- Environment variables: `WINGPY_CATALYST_CENTER_USERNAME`, `WINGPY_CATALYST_CENTER_PASSWORD`, `WINGPY_CATALYST_CENTER_BASE_URL`
- User Guide: [Cisco Catalyst Center User Guide](https://wingpy.automation.wingmen.dk/user-guide/catalyst-center/)
- API Reference: [Cisco Catalyst Center API Reference](https://wingpy.automation.wingmen.dk/api/catalyst-center/)
- Official REST docs: [Cisco Developer Catalyst Center Search](https://developer.cisco.com/docs/search/?q=Catalyst%20Center)

### Cisco Catalyst SD-WAN vManage

- Client: `wingpy.CiscoVmanage`
- Auth: session
- Environment variables: `WINGPY_VMANAGE_USERNAME`, `WINGPY_VMANAGE_PASSWORD`, `WINGPY_VMANAGE_BASE_URL`
- User Guide: [Cisco Catalyst SD-WAN vManage User Guide](https://wingpy.automation.wingmen.dk/user-guide/vmanage/)
- API Reference: [Cisco Catalyst SD-WAN vManage API Reference](https://wingpy.automation.wingmen.dk/api/vmanage/)
- Official REST docs: [Cisco Developer vManage Search](https://developer.cisco.com/docs/search/?q=vManage)

### Cisco FMC

- Client: `wingpy.CiscoFMC`
- Auth: session
- Environment variables: `WINGPY_FMC_USERNAME`, `WINGPY_FMC_PASSWORD`, `WINGPY_FMC_BASE_URL`
- User Guide: [Cisco FMC User Guide](https://wingpy.automation.wingmen.dk/user-guide/fmc/)
- API Reference: [Cisco FMC API Reference](https://wingpy.automation.wingmen.dk/api/fmc/)
- Official REST docs: [Cisco FMC Programming References](https://www.cisco.com/c/en/us/support/security/defense-center/products-programming-reference-guides-list.html)

### Cisco Hyperfabric

- Client: `wingpy.CiscoHyperfabric`
- Auth: external token
- Environment variables: `WINGPY_HYPERFABRIC_TOKEN`
- User Guide: [Cisco Hyperfabric User Guide](https://wingpy.automation.wingmen.dk/user-guide/hyperfabric/)
- API Reference: [Cisco Hyperfabric API Reference](https://wingpy.automation.wingmen.dk/api/hyperfabric/)
- Official REST docs: [Cisco Hyperfabric API Docs](https://developer.cisco.com/docs/hyperfabric/)

### Cisco ISE

- Client: `wingpy.CiscoISE`
- Auth: session
- Environment variables: `WINGPY_ISE_USERNAME`, `WINGPY_ISE_PASSWORD`, `WINGPY_ISE_BASE_URL`
- User Guide: [Cisco ISE User Guide](https://wingpy.automation.wingmen.dk/user-guide/ise/)
- API Reference: [Cisco ISE API Reference](https://wingpy.automation.wingmen.dk/api/ise/)
- Official REST docs: [Cisco Developer ISE Search](https://developer.cisco.com/docs/search/?q=Identity+Services+Engine)

### Cisco Meraki Dashboard

- Client: `wingpy.CiscoMerakiDashboard`
- Auth: external token
- Environment variables: `WINGPY_MERAKI_DASHBOARD_TOKEN`, `WINGPY_MERAKI_DASHBOARD_ORG_NAME`
- User Guide: [Cisco Meraki Dashboard User Guide](https://wingpy.automation.wingmen.dk/user-guide/meraki-dashboard/)
- API Reference: [Cisco Meraki Dashboard API Reference](https://wingpy.automation.wingmen.dk/api/meraki-dashboard/)
- Official REST docs: [Cisco Developer Meraki Search](https://developer.cisco.com/docs/search/?q=Meraki+Dashboard)

### Cisco Modeling Labs

- Client: `wingpy.CiscoModelingLabs`
- Auth: session
- Environment variables: `WINGPY_CML_USERNAME`, `WINGPY_CML_PASSWORD`, `WINGPY_CML_BASE_URL`
- User Guide: [Cisco Modeling Labs User Guide](https://wingpy.automation.wingmen.dk/user-guide/cml/)
- API Reference: [Cisco Modeling Labs API Reference](https://wingpy.automation.wingmen.dk/api/cml/)
- Official REST docs: [Cisco Developer CML Search](https://developer.cisco.com/docs/search/?q=Cisco+Modeling+Labs)

### Nautobot

- Client: `wingpy.Nautobot`
- Auth: external token
- Environment variables: `WINGPY_NAUTOBOT_TOKEN`, `WINGPY_NAUTOBOT_BASE_URL`
- User Guide: [Nautobot User Guide](https://wingpy.automation.wingmen.dk/user-guide/nautobot/)
- API Reference: [Nautobot API Reference](https://wingpy.automation.wingmen.dk/api/nautobot/)
- Official REST docs: [Nautobot REST API Overview](https://docs.nautobot.com/projects/core/en/stable/user-guide/platform-functionality/rest-api/overview/)
- Note: ask for the target instance's API specification when behavior may vary by version, plugin, or local extensions.

### NetBox

- Client: `wingpy.NetBox`
- Auth: external token
- Environment variables: `WINGPY_NETBOX_TOKEN`, `WINGPY_NETBOX_BASE_URL`
- User Guide: [NetBox User Guide](https://wingpy.automation.wingmen.dk/user-guide/netbox/)
- API Reference: [NetBox API Reference](https://wingpy.automation.wingmen.dk/api/netbox/)
- Official REST docs: [NetBox REST API Overview](https://netboxlabs.com/docs/netbox/integrations/rest-api/)
- Note: ask for the target instance's API specification when behavior may vary by version, plugin, or local extensions.

### Cisco Nexus Dashboard

- Client: `wingpy.CiscoNexusDashboard`
- Auth: session
- Environment variables: `WINGPY_NEXUS_DASHBOARD_USERNAME`, `WINGPY_NEXUS_DASHBOARD_PASSWORD`, `WINGPY_NEXUS_DASHBOARD_BASE_URL`
- User Guide: [Cisco Nexus Dashboard User Guide](https://wingpy.automation.wingmen.dk/user-guide/nexus-dashboard/)
- API Reference: [Cisco Nexus Dashboard API Reference](https://wingpy.automation.wingmen.dk/api/nexus-dashboard/)
- Official REST docs: [Cisco Developer Nexus Dashboard Search](https://developer.cisco.com/docs/search/?q=Nexus+Dashboard)

### Splunk Enterprise

- Client: `wingpy.SplunkEnterprise`
- Auth: session
- Environment variables: `WINGPY_SPLUNK_ENTERPRISE_USERNAME`, `WINGPY_SPLUNK_ENTERPRISE_PASSWORD`, `WINGPY_SPLUNK_ENTERPRISE_BASE_URL`
- User Guide: [Splunk Enterprise User Guide](https://wingpy.automation.wingmen.dk/user-guide/splunk/)
- API Reference: [Splunk Enterprise API Reference](https://wingpy.automation.wingmen.dk/api/splunk/)
- Official REST docs: [Splunk REST API Reference](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog)

## Core Rules

- Use the documented wingpy client directly unless an added layer owns clear domain behavior.
- Prefer documented endpoint paths, request shapes, and workflow patterns.
- Prefer environment variables over hardcoded credentials when the client supports them.
- Import `wingpy` at module scope in normal application code.
- Build write payloads from documented writable fields. Do not round-trip GET responses into POST or PUT bodies unless the docs explicitly require the same shape.
- Reuse one client context per platform per phase for batch workflows unless the docs show a different requirement.
- If the task is a sync or reconciliation tool, default to the least destructive action when source data is missing or ambiguous.
- Use only the client section that matches the target platform.
- For vendor-specific path or payload semantics, use the platform's official REST documentation in addition to the wingpy docs.

## Abstraction Test

Before adding a helper, wrapper, adapter, or service layer around wingpy, name the behavior it owns.

Good reasons:

- request or response normalization required by the domain
- orchestration across multiple API calls
- conflict detection, safety policy, or plan/apply separation
- batching, polling, or workflow coordination not already provided by wingpy

Bad reasons:

- hiding `import wingpy`
- forwarding one or two client methods unchanged
- storing constructor arguments like `verify`
- renaming a wingpy client without adding behavior

If you cannot name the behavior the abstraction owns, do not create it.

## Tool Shapes

- One-off script: stay very close to the documented example.
- CLI or admin tool: keep platform-specific code thin and explicit.
- Batch mutation tool: prefer one client context per phase and explicit reporting of actions.
- Sync or reconciliation tool: separate planning from applying, use stable identity keys, and prefer `skip` or `noop` over destructive inference.
- Reusable library code: extract only logic that normalizes domain data or enforces policy.

## Escalate When

- the writable payload shape is unclear from the docs
- the unique identifier or matching key is ambiguous
- version-specific behavior could change correctness
- the task implies destructive reconciliation but the source of truth is incomplete
- the vendor docs and wingpy docs appear to disagree

## Documentation Routing

- General getting started and shared patterns: [User Guide](https://wingpy.automation.wingmen.dk/user-guide/)
- Documentation maps: [llms.txt](https://wingpy.automation.wingmen.dk/llms.txt), [llms-full.txt](https://wingpy.automation.wingmen.dk/llms-full.txt)
- FAQ overview: [FAQ](https://wingpy.automation.wingmen.dk/faq/)
- Environment variables: [FAQ: Environment Variables](https://wingpy.automation.wingmen.dk/faq/#environment-variables)
- Session behavior: [FAQ: Session Maintenance](https://wingpy.automation.wingmen.dk/faq/#session-maintenance)
- Path building: [FAQ: Path Building](https://wingpy.automation.wingmen.dk/faq/#path-building)
- Exceptions: [Exceptions API Reference](https://wingpy.automation.wingmen.dk/api/exceptions/)
- Responses: [Responses API Reference](https://wingpy.automation.wingmen.dk/api/responses/)
- Scheduling and concurrency: [Scheduling API Reference](https://wingpy.automation.wingmen.dk/api/scheduling/)
- Changelog: [Changelog](https://wingpy.automation.wingmen.dk/changelog/)

## Guardrails

- Do not invent unsupported wingpy clients.
- Do not invent methods that are not present in the docs or reference.
- Do not bypass wingpy with raw HTTP code unless the task explicitly requires it.
- Do not add custom token refresh logic without evidence that it is needed for that client.
- Do not present guessed behavior as documented fact.
- Never hardcode passwords, secrets or tokens. Use the client environment variables or getpass() when possible.
- Do not expose internal defaults such as timeout, retry counts or page sizes unless the task explicitly requires them.

## Practical Defaults

- Prefer the documented authentication approach for the chosen client.
- Prefer `path_params` when the endpoint contains documented placeholders.
- Use `get_all()` only when the docs show it as the right collection pattern.
- For exception handling, prefer wingpy's documented exception model over broad exception swallowing.
- For parallel API calls, prefer documented `.tasks.schedule()` and `.tasks.run()` patterns when they fit the use case.
- Avoid embedding secrets in reusable examples; use placeholders instead.
"""


def write_skill_package(destination_dir: Path, overwrite: bool = False) -> None:
    """
    Write the skill markdown to a destination directory.

    Parameters
    ----------
    destination_dir
       Directory that will contain the generated skill files.
    overwrite
       Whether to overwrite an existing skill document.

    Raises
    ------
    FileExistsError
        If the skill document already exists and overwrite is False.
    """
    destination_dir.mkdir(parents=True, exist_ok=True)

    skill_doc_path: Path = destination_dir / SKILL_FILE_NAME
    if skill_doc_path.exists() and not overwrite:
        raise FileExistsError(
            f"Refusing to overwrite existing skill document: {skill_doc_path}"
        )

    skill_doc_path.write_text(DOCUMENT.lstrip(), encoding="utf-8")


def generate_skill_folder(
    output_dir: Path = Path.cwd(), overwrite: bool = False
) -> None:
    """
    Generate the Wingpy skill package in the standalone location.

    Parameters
    ----------
    output_dir
       Base directory where the standalone skill folder will be created.
    overwrite
       Whether to overwrite an existing skill document.
    """
    output_dir = output_dir.resolve()
    skill_folder: Path = output_dir / SKILL_FOLDER_NAME

    write_skill_package(skill_folder, overwrite=overwrite)


def run() -> None:
    """
    Run the skill generator CLI.

    Returns
    -------
    None
    """
    parser = argparse.ArgumentParser(
        description="Generate the wingpy-coding-skill package with SKILL.md."
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        help=(
            "The directory where the skill package will be created "
            "(default: ./.agents/skills )."
        ),
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help=("Overwrite an existing SKILL.md without confirmation. Use with caution."),
    )

    args = parser.parse_args()
    if args.output_dir is None:
        args.output_dir = Path.cwd() / ".agents" / "skills"

    print(
        "this will generate a wingpy-coding-skill package at "
        f"{args.output_dir / SKILL_FOLDER_NAME}"
    )

    skill_doc_path: Path = args.output_dir / SKILL_FOLDER_NAME / SKILL_FILE_NAME
    if args.force:
        confirm = "y"
    elif skill_doc_path.exists():
        confirm = input(f"{skill_doc_path} already exists. Overwrite? (y/N): ")
    else:
        confirm = input("Do you want to proceed? (y/N): ")

    if confirm.lower() in ("y", "ye", "yes"):
        generate_skill_folder(
            args.output_dir, overwrite=args.force or skill_doc_path.exists()
        )
        print("wingpy-coding-skill package generated successfully.")
    else:
        print("Operation cancelled.")


if __name__ == "__main__":
    run()
