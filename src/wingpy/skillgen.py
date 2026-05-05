"""
This module contains the skill generator for Wingpy.

The generated skill package is intended for coding agents and documentation
pipelines that need both human-readable instructions and machine-readable
capability metadata.
"""

import argparse
import json
from pathlib import Path
from typing import Any

SKILL_FOLDER_NAME = "wingpy-coding-skill"
SKILL_FILE_NAME = "SKILL.md"
MANIFEST_FILE_NAME = "manifest.json"

DOCUMENT = r"""
---
name: wingpy-coding-skill
description: 'Use when writing, testing, documenting, reviewing, or generating code that imports wingpy, selects a wingpy client, or automates APIC, Catalyst Center, vManage, FMC, Hyperfabric, ISE, Meraki Dashboard, Modeling Labs, Nautobot, NetBox, Nexus Dashboard, or Splunk Enterprise.'
---
> Use this file when working on code that imports, extends, tests, documents, or generates examples for the wingpy Python library.

## Purpose

This skill guides AI agents that are writing or modifying code for projects that use wingpy. It is operational guidance for producing correct, minimal, idiomatic wingpy-based code.

## When to use

Activate this skill when any of the following are true:

- the codebase imports `wingpy`
- the task mentions a wingpy client or supported platform
- the task involves REST API automation with wingpy
- the task asks for examples, tests, wrappers, integrations, or docs related to wingpy
- the task requires choosing the correct wingpy client for a specific platform

## Procedure

1. Identify the target platform and match it to a documented wingpy client.
2. Read the manifest.json file - look for the client's documented capabilities, environment variable support, and shared capabilities.
3. Read the general User Guide to understand overall usage patterns and best practices, like logging, error handling, and concurrency.
4. Read the relevant User Guide to understand usage patterns and examples.
5. Read the client API Reference page to verify constructor parameters, supported methods, and return behavior.
6. Use the FAQ only for cross-cutting behavior such as context managers, exceptions, environment variables, and concurrency patterns.
7. Look for the platform API Reference on https://developer.cisco.com/docs/ to make sure REST API Endpoint paths, parameters, method and response shapes are correct. Do not rely on guesswork or assumptions about API behavior.
8. Write the smallest correct solution using documented wingpy patterns.


## Client Matrix - API Reference Pages

Prefer the most specific documented client.

- Cisco APIC: `wingpy.CiscoAPIC`
   Guide: [Cisco APIC User Guide](https://wingpy.automation.wingmen.dk/user-guide/apic/)
   API: [Cisco APIC API Reference](https://wingpy.automation.wingmen.dk/api/apic/)
- Cisco Catalyst Center: `wingpy.CiscoCatalystCenter`
   Guide: [Cisco Catalyst Center User Guide](https://wingpy.automation.wingmen.dk/user-guide/catalyst-center/)
   API: [Cisco Catalyst Center API Reference](https://wingpy.automation.wingmen.dk/api/catalyst-center/)
- Cisco Catalyst SD-WAN vManage: `wingpy.CiscoVmanage`
   Guide: [Cisco Catalyst SD-WAN vManage User Guide](https://wingpy.automation.wingmen.dk/user-guide/vmanage/)
   API: [Cisco Catalyst SD-WAN vManage API Reference](https://wingpy.automation.wingmen.dk/api/vmanage/)
- Cisco FMC: `wingpy.CiscoFMC`
   Guide: [Cisco FMC User Guide](https://wingpy.automation.wingmen.dk/user-guide/fmc/)
   API: [Cisco FMC API Reference](https://wingpy.automation.wingmen.dk/api/fmc/)
- Cisco Hyperfabric: `wingpy.CiscoHyperfabric`
   Guide: [Cisco Hyperfabric User Guide](https://wingpy.automation.wingmen.dk/user-guide/hyperfabric/)
   API: [Cisco Hyperfabric API Reference](https://wingpy.automation.wingmen.dk/api/hyperfabric/)
- Cisco ISE: `wingpy.CiscoISE`
   Guide: [Cisco ISE User Guide](https://wingpy.automation.wingmen.dk/user-guide/ise/)
   API: [Cisco ISE API Reference](https://wingpy.automation.wingmen.dk/api/ise/)
- Cisco Meraki Dashboard: `wingpy.CiscoMerakiDashboard`
   Guide: [Cisco Meraki Dashboard User Guide](https://wingpy.automation.wingmen.dk/user-guide/meraki-dashboard/)
   API: [Cisco Meraki Dashboard API Reference](https://wingpy.automation.wingmen.dk/api/meraki-dashboard/)
- Cisco Modeling Labs: `wingpy.CiscoModelingLabs`
   Guide: [Cisco Modeling Labs User Guide](https://wingpy.automation.wingmen.dk/user-guide/cml/)
   API: [Cisco Modeling Labs API Reference](https://wingpy.automation.wingmen.dk/api/cml/)
- Nautobot: `wingpy.Nautobot`
   Guide: [Nautobot User Guide](https://wingpy.automation.wingmen.dk/user-guide/nautobot/)
   API: [Nautobot API Reference](https://wingpy.automation.wingmen.dk/api/nautobot/)
- NetBox: `wingpy.NetBox`
   Guide: [NetBox User Guide](https://wingpy.automation.wingmen.dk/user-guide/netbox/)
   API: [NetBox API Reference](https://wingpy.automation.wingmen.dk/api/netbox/)
- Cisco Nexus Dashboard: `wingpy.CiscoNexusDashboard`
   Guide: [Cisco Nexus Dashboard User Guide](https://wingpy.automation.wingmen.dk/user-guide/nexus-dashboard/)
   API: [Cisco Nexus Dashboard API Reference](https://wingpy.automation.wingmen.dk/api/nexus-dashboard/)
- Splunk Enterprise: `wingpy.SplunkEnterprise`
   Guide: [Splunk Enterprise User Guide](https://wingpy.automation.wingmen.dk/user-guide/splunk/)
   API: [Splunk Enterprise API Reference](https://wingpy.automation.wingmen.dk/api/splunk/)

If the requested platform is unsupported or unclear, say so explicitly and avoid inventing a client.

## Core Rules

### Choose the right client

Use the dedicated Wingpy client that matches the target platform.

### Preserve vendor paths

Prefer endpoint paths that match vendor documentation. Do not rewrite documented API paths unless the task explicitly asks for an abstraction.
https://developer.cisco.com/docs/ is the source of truth for Cisco API paths. https://developer.cisco.com/docs/ is a search engine for official Cisco API documentation.
There may be multiple versions of an API documented on https://developer.cisco.com/docs/. If the task does not specify a version, prefer the latest generally available version.

`manifest.json` contains `rest_api_docs_url` for each client as a hint for where to find official API documentation.
Exceptions:
- Nautobot: https://docs.nautobot.com/projects/core/en/stable/user-guide/platform-functionality/rest-api/overview/ provides some information. Ask the user to provide a link to their own instance's specification.
- NetBox: https://netboxlabs.com/docs/netbox/integrations/rest-api/ provides some information. Ask the user to provide a link to their own instance's specification.

### Let Wingpy handle shared concerns

Do not reimplement behavior that Wingpy already provides, such as:

- request setup and common lifecycle behavior
- path parameter substitution via `path_params`
- documented retry and rate-limit handling
- proactive authentication for clients that manage renewable sessions
- context manager cleanup
- environment variable loading

Do not assume every client can refresh an expired external bearer token. Token-only clients such as Hyperfabric and Meraki Dashboard rely on the token you provide.

### Prefer documented patterns

Before inventing a pattern, look for an example in the platform guide or API reference.

### Keep code minimal

Use the smallest amount of code needed to solve the task correctly. Do not add helper layers, wrappers, or framework structure unless requested.

### Be explicit about logging level

The default logging level is WARNING.

### Always import at library level

`import wingpy` is the preferred pattern for imports. Do not import specific clients or submodules unless the task explicitly requires it.

## Coding Patterns

### Authentication input

Prefer the documented authentication approach for the chosen client. When reusable code is requested, prefer environment variables over hardcoded secrets if the client supports them.

### Response shape and pagination

Use `get_all()` to retrieve paginated or combined collections.

### Path parameters

If the endpoint contains placeholders or dynamic identifiers, prefer documented `path_params` usage instead of brittle manual string assembly.

### Context managers

When multiple consecutive API operations are performed, prefer context manager usage when it improves cleanup and clarity.

### Error handling

If the task requires exception handling, prefer Wingpy's documented exception model over broad exception swallowing.

### Concurrency

If the task requires parallel API calls, check the FAQ and scheduling docs before inventing a threading model. Prefer documented `.tasks.schedule()` and `.tasks.run()` patterns where they fit the use case.

## Documentation Routing

Load these concrete resources instead of relying on broad categories alone:

- General getting started: [User Guide](https://wingpy.automation.wingmen.dk/user-guide/)
The User Guide contains sections on authentication, logging, error handling, concurrency, and other cross-cutting concerns that apply to all clients. 
It also contains client-specific sections with usage patterns and examples. It constitutes the idiomatic way to use Wingpy and should be consulted before the API reference.

- FAQ overview: [FAQ](https://wingpy.automation.wingmen.dk/faq/)
Can be consulted for specific questions.

- Environment variables: [FAQ: Environment Variables](https://wingpy.automation.wingmen.dk/faq/#environment-variables)
- Path building: [FAQ: Path Building](https://wingpy.automation.wingmen.dk/faq/#path-building)
- Base client behavior: [Base API Reference](https://wingpy.automation.wingmen.dk/api/base/)
- Exceptions: [Exceptions API Reference](https://wingpy.automation.wingmen.dk/api/exceptions/)
- Responses: [Responses API Reference](https://wingpy.automation.wingmen.dk/api/responses/)

- Scheduling and concurrency: [Scheduling API Reference](https://wingpy.automation.wingmen.dk/api/scheduling/)
Refer to the general guidance found in the User Guide.

## Guardrails

Do not:

- invent unsupported Wingpy clients
- invent methods not present in the docs or reference
- bypass Wingpy with raw HTTP code
- add custom token refresh logic
- manually implement pagination when the client supports `get_all()`
- present guessed behavior as documented fact
- expose internal defaults, such as page size or retry count, unless the task explicitly requires it and the user asks for it - the default behavior is tuned and tested


## Output Expectations

When generating Wingpy-based code:

- use the correct client class
- use `import wingpy` at the library level
- use realistic documented endpoint paths from documentation
- preserve Wingpy-native patterns
- avoid unnecessary abstraction
- make assumptions explicit when required details are missing
- say when a value is a placeholder
- avoid embedding secrets in reusable examples


## User Interaction

- Be inquisitive if the task is ambiguous or missing details. 
- It is better to ask for clarification than to make assumptions that lead to incorrect code. 
- If you must make assumptions, state them explicitly in the output and ask for confirmation before proceeding.
- Consider the human a collaborator who can provide missing details, clarify ambiguities, and review assumptions.
- Think about the most popular libraries - and consider if the task could be simplified with a common library import, like:
    -- Flask
    -- Typer
    -- FastAPI
    -- other small libraries that are widely used and could simplify the task.
- Wingpy uses httpx for HTTP requests, so imports from httpx are acceptable if the task requires functionality not provided by Wingpy's documented client methods.
- Always ask the user to add dependencies and dependency imports before using them.
"""

CLIENT_MATRIX: list[dict[str, Any]] = [
    {
        "platform": "Cisco APIC",
        "client_class": "wingpy.CiscoAPIC",
        "auth_mode": "session",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": True,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_APIC_USERNAME",
                "description": "Username for Cisco APIC authentication",
            },
            {
                "name": "WINGPY_APIC_PASSWORD",
                "description": "Password for Cisco APIC authentication",
            },
            {
                "name": "WINGPY_APIC_BASE_URL",
                "description": "Hostname or IP address of the Cisco APIC controller",
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/apic/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/apic/",
        "rest_api_docs_url": "https://developer.cisco.com/docs/search/?q=APIC",
    },
    {
        "platform": "Cisco Catalyst Center",
        "client_class": "wingpy.CiscoCatalystCenter",
        "auth_mode": "session",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": True,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_CATALYST_CENTER_USERNAME",
                "description": "Username for Cisco Catalyst Center authentication",
            },
            {
                "name": "WINGPY_CATALYST_CENTER_PASSWORD",
                "description": "Password for Cisco Catalyst Center authentication",
            },
            {
                "name": "WINGPY_CATALYST_CENTER_BASE_URL",
                "description": (
                    "Hostname or IP address of the Cisco Catalyst Center controller"
                ),
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/catalyst-center/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/catalyst-center/",
        "rest_api_docs_url": "https://developer.cisco.com/docs/search/?q=Catalyst%20Center",
    },
    {
        "platform": "Cisco Catalyst SD-WAN vManage",
        "client_class": "wingpy.CiscoVmanage",
        "auth_mode": "session",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": True,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_VMANAGE_USERNAME",
                "description": "Username for Cisco vManage authentication",
            },
            {
                "name": "WINGPY_VMANAGE_PASSWORD",
                "description": "Password for Cisco vManage authentication",
            },
            {
                "name": "WINGPY_VMANAGE_BASE_URL",
                "description": "Hostname or IP address of the Cisco vManage controller",
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/vmanage/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/vmanage/",
        "rest_api_docs_url": "https://developer.cisco.com/docs/search/?q=vManage",
    },
    {
        "platform": "Cisco FMC",
        "client_class": "wingpy.CiscoFMC",
        "auth_mode": "session",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": True,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_FMC_USERNAME",
                "description": "Username for Cisco FMC authentication",
            },
            {
                "name": "WINGPY_FMC_PASSWORD",
                "description": "Password for Cisco FMC authentication",
            },
            {
                "name": "WINGPY_FMC_BASE_URL",
                "description": "Hostname or IP address of the Cisco FMC controller",
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/fmc/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/fmc/",
        "rest_api_docs_url": "https://www.cisco.com/c/en/us/support/security/defense-center/products-programming-reference-guides-list.html",
    },
    {
        "platform": "Cisco Hyperfabric",
        "client_class": "wingpy.CiscoHyperfabric",
        "auth_mode": "external-token",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": False,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_HYPERFABRIC_TOKEN",
                "description": "API key for Cisco Hyperfabric authentication",
            }
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/hyperfabric/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/hyperfabric/",
        "rest_api_docs_url": "https://developer.cisco.com/docs/hyperfabric/",
    },
    {
        "platform": "Cisco ISE",
        "client_class": "wingpy.CiscoISE",
        "auth_mode": "session",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": True,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_ISE_USERNAME",
                "description": "Username for Cisco ISE authentication",
            },
            {
                "name": "WINGPY_ISE_PASSWORD",
                "description": "Password for Cisco ISE authentication",
            },
            {
                "name": "WINGPY_ISE_BASE_URL",
                "description": "Hostname or IP address of the Cisco ISE controller",
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/ise/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/ise/",
        "rest_api_docs_url": "https://developer.cisco.com/docs/search/?q=Identity+Services+Engine",
    },
    {
        "platform": "Cisco Meraki Dashboard",
        "client_class": "wingpy.CiscoMerakiDashboard",
        "auth_mode": "external-token",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": False,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_MERAKI_DASHBOARD_TOKEN",
                "description": "API key for Cisco Meraki Dashboard authentication",
            },
            {
                "name": "WINGPY_MERAKI_DASHBOARD_ORG_NAME",
                "description": (
                    "Name of the organization to manage in Cisco Meraki Dashboard"
                ),
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/meraki-dashboard/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/meraki-dashboard/",
        "rest_api_docs_url": "https://developer.cisco.com/docs/search/?q=Meraki+Dashboard",
    },
    {
        "platform": "Cisco Modeling Labs",
        "client_class": "wingpy.CiscoModelingLabs",
        "auth_mode": "session",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": True,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_CML_USERNAME",
                "description": "Username for Cisco Modeling Labs authentication",
            },
            {
                "name": "WINGPY_CML_PASSWORD",
                "description": "Password for Cisco Modeling Labs authentication",
            },
            {
                "name": "WINGPY_CML_BASE_URL",
                "description": (
                    "Hostname or IP address of the Cisco Modeling Labs controller"
                ),
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/cml/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/cml/",
        "rest_api_docs_url": "https://developer.cisco.com/docs/search/?q=Cisco+Modeling+Labs",
    },
    {
        "platform": "Nautobot",
        "client_class": "wingpy.Nautobot",
        "auth_mode": "external-token",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": False,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_NAUTOBOT_TOKEN",
                "description": "API key for Nautobot authentication",
            },
            {
                "name": "WINGPY_NAUTOBOT_BASE_URL",
                "description": "Hostname or IP address of the Nautobot controller",
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/nautobot/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/nautobot/",
    },
    {
        "platform": "NetBox",
        "client_class": "wingpy.NetBox",
        "auth_mode": "external-token",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": False,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_NETBOX_TOKEN",
                "description": "API key for NetBox authentication",
            },
            {
                "name": "WINGPY_NETBOX_BASE_URL",
                "description": "Hostname or IP address of the NetBox controller",
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/netbox/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/netbox/",
    },
    {
        "platform": "Cisco Nexus Dashboard",
        "client_class": "wingpy.CiscoNexusDashboard",
        "auth_mode": "session",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": True,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_NEXUS_DASHBOARD_USERNAME",
                "description": "Username for Cisco Nexus Dashboard authentication",
            },
            {
                "name": "WINGPY_NEXUS_DASHBOARD_PASSWORD",
                "description": "Password for Cisco Nexus Dashboard authentication",
            },
            {
                "name": "WINGPY_NEXUS_DASHBOARD_BASE_URL",
                "description": (
                    "Hostname or IP address of the Cisco Nexus Dashboard controller"
                ),
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/nexus-dashboard/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/nexus-dashboard/",
        "rest_api_docs_url": "https://developer.cisco.com/docs/search/?q=Nexus+Dashboard",
    },
    {
        "platform": "Splunk Enterprise",
        "client_class": "wingpy.SplunkEnterprise",
        "auth_mode": "session",
        "supports_get_all": True,
        "supports_path_params": True,
        "supports_token_refresh": True,
        "automatically_uses_environment_variables": True,
        "environment_variables": [
            {
                "name": "WINGPY_SPLUNK_ENTERPRISE_USERNAME",
                "description": "Username for Splunk Enterprise authentication",
            },
            {
                "name": "WINGPY_SPLUNK_ENTERPRISE_PASSWORD",
                "description": "Password for Splunk Enterprise authentication",
            },
            {
                "name": "WINGPY_SPLUNK_ENTERPRISE_BASE_URL",
                "description": "Hostname or IP address of the Splunk Enterprise controller",
            },
        ],
        "guide_url": "https://wingpy.automation.wingmen.dk/user-guide/splunk/",
        "api_url": "https://wingpy.automation.wingmen.dk/api/splunk/",
        "rest_api_docs_url": "https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog",
    },
]


def build_manifest() -> dict[str, Any]:
    """
    Build the machine-readable Wingpy skill manifest.

    Returns
    -------
    dict[str, Any]
       Structured metadata for coding agents and documentation pipelines.
    """
    return {
        "schema_version": "1.0",
        "skill": {
            "name": SKILL_FOLDER_NAME,
            "description": (
                "Operational guidance and capability metadata for coding agents "
                "that write or review code using the wingpy Python library."
            ),
            "human_document": SKILL_FILE_NAME,
            "machine_manifest": MANIFEST_FILE_NAME,
        },
        "documentation": {
            "home_url": "https://wingpy.automation.wingmen.dk/",
            "user_guide_url": "https://wingpy.automation.wingmen.dk/user-guide/",
            "api_reference_url": "https://wingpy.automation.wingmen.dk/api/",
            "faq_url": "https://wingpy.automation.wingmen.dk/faq/",
            "changelog_url": "https://wingpy.automation.wingmen.dk/changelog/",
            "llms_url": "https://wingpy.automation.wingmen.dk/llms.txt",
            "llms_full_url": "https://wingpy.automation.wingmen.dk/llms-full.txt",
        },
        "rules": {
            "prefer_platform_specific_clients": True,
            "prefer_documented_vendor_paths": True,
            "prefer_environment_variables_for_reusable_examples": True,
            "avoid_raw_http_when_wingpy_supports_task": True,
            "avoid_guessing_undocumented_methods": True,
            "avoid_assuming_token_refresh_for_external_tokens": True,
            "avoid_manual_pagination_when_get_all_is_available": True,
            "avoid_unnecessary_abstraction": True,
        },
        "shared_capabilities": {
            "path_params": True,
            "request_retries": True,
            "rate_limit_handling": True,
            "context_manager_cleanup": True,
            "response_wrappers": [
                "wingpy.ResponseMapping",
                "wingpy.ResponseSequence",
                "wingpy.XMLResponseMapping",
            ],
            "concurrency_entrypoints": [
                "client.tasks.schedule",
                "client.tasks.run",
            ],
        },
        "clients": CLIENT_MATRIX,
    }


def write_skill_package(destination_dir: Path) -> None:
    """
    Write the skill markdown and manifest to a destination directory.

    Parameters
    ----------
    destination_dir
       Directory that will contain the generated skill files.
    """
    destination_dir.mkdir(parents=True, exist_ok=True)

    skill_doc_path: Path = destination_dir / SKILL_FILE_NAME
    skill_doc_path.write_text(DOCUMENT.lstrip(), encoding="utf-8")

    manifest_path: Path = destination_dir / MANIFEST_FILE_NAME
    manifest_path.write_text(
        json.dumps(build_manifest(), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def generate_skill_folder(output_dir: Path = Path.cwd()) -> None:
    """
    Generate the Wingpy skill package in the standalone location.

    Parameters
    ----------
    output_dir
       Base directory where the standalone skill folder will be created.
       will be created.
    """
    output_dir = output_dir.resolve()
    skill_folder: Path = output_dir / SKILL_FOLDER_NAME

    write_skill_package(skill_folder)


def run() -> None:
    """
    Run the skill generator CLI.

    Returns
    -------
    None
    """
    parser = argparse.ArgumentParser(
        description=(
            "Generate the wingpy-coding-skill package with SKILL.md and manifest.json."
        )
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        help=(
            "The directory where the skill package will be created "
            "(default: current working directory)."
        ),
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help=(
            "Force overwrite of existing skill folder without confirmation. "
            "Use with caution."
        ),
    )

    args = parser.parse_args()
    if args.output_dir is None:
        args.output_dir = Path.cwd()

    print(
        "this will generate a wingpy-coding-skill package at "
        f"{args.output_dir / SKILL_FOLDER_NAME}"
    )

    confirm = input("Do you want to proceed? (y/N): ") if not args.force else "y"
    if confirm.lower() in ("y", "ye", "yes"):
        generate_skill_folder(args.output_dir)
        print("wingpy-coding-skill package generated successfully.")
    else:
        print("Operation cancelled.")


if __name__ == "__main__":
    run()
