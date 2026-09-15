# MIDAS

[English](README.md) | [简体中文](README_zh-CN.md)

**Multi-source Intelligent Diagnostic Agent System**

MIDAS is an LLM-based operations and maintenance assistant for multi-source
fault diagnosis at the Dalian Advanced Light Source (DALS). It connects EPICS
process-variable data, Loki logs, Prometheus metrics, and PostgreSQL
configuration records through the Model Context Protocol (MCP), allowing an
agent to assemble evidence from otherwise separate operational systems.

This repository accompanies the manuscript:

> *MIDAS: An LLM-Based Agent for Fault Diagnosis Using Multi-Source
> Operational Data at the Dalian Advanced Light Source*

## Scope

MIDAS is designed as a diagnostic assistant. In the reported evaluation, it
collects operational evidence, identifies a likely fault cause, and provides a
remediation recommendation for operator review. The evaluated workflow does
not autonomously execute remediation actions.

The reported experiments used GPT-5.2 through Azure OpenAI with
`temperature=1`. Other language models were not evaluated, so the repository
does not claim model-independent performance or superiority over other LLMs.

## System overview

```text
Operator request
       |
       v
MIDAS diagnostic agent
       |
       +-- middleware: limits, retries, context management and auditing
       |
       +-- EPICS MCP -------- process variables and IOC status
       +-- Loki MCP --------- machine and service logs
       +-- Prometheus MCP --- monitoring metrics and targets
       +-- PostgreSQL MCP --- PV, device, IOC and host configuration
       |
       v
Evidence-linked diagnosis and operator-reviewed recommendation
```

MCP standardizes tool access but does not merge the four data sources. MIDAS
correlates them at query time using facility identifiers such as PV names, IOC
names, device names, service labels, host names, and IP addresses.

## Repository structure

```text
MIDAS/
├── MCP Servers/                      # MCP adapters for operational data sources
├── MIDAS_Fault_Diagnosis_Raw_Data/   # Retained fault-case records and artifacts
├── evaluated-version/                # Implementation associated with the study
├── hardened-version/                 # Post-study security and audit hardening
├── LICENSE
└── README.md
```

### Evaluated version

`evaluated-version/` preserves the implementation associated with the
diagnostic case study. It is provided for traceability and should not be
treated as a production-ready control-system agent. In particular, its broad
SSH interface and regex-based command filtering are limited safeguards.

### Hardened version

`hardened-version/` contains post-study engineering improvements, including:

- default-deny authorization based on a trusted application identity;
- per-tool, per-host, per-service, and per-operation allow lists;
- fixed, read-oriented SSH diagnostic operations instead of model-supplied
  shell commands;
- host-key verification, bounded output, and execution timeouts;
- PostgreSQL tool-call auditing with argument redaction;
- records for proposed, executed, rejected, failed, and cancelled calls; and
- failure-closed behavior after audit-storage failure.

These improvements were added after the reported diagnostic sessions. They
must not be interpreted as security mechanisms evaluated by the original ten
case records.

## Installation

Create a virtual environment and install the Python dependencies used by the
selected version. A typical installation requires the following packages:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install \
  deepagents \
  langchain \
  langgraph \
  langchain-openai \
  langchain-mcp-adapters \
  langgraph-checkpoint-postgres \
  'psycopg[binary]' \
  paramiko \
  python-dotenv
```

For reproducible use, pin these packages to the versions recorded for the
target deployment rather than relying on the latest releases.

## Configuration

Do not commit credentials to the repository. Configure them through
environment variables or a secret-management service.

The hardened version uses variables similar to the following:

```dotenv
# Azure OpenAI
AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com/
AZURE_OPENAI_API_KEY=<secret>
AZURE_OPENAI_DEPLOYMENT=gpt-5.2
AZURE_OPENAI_API_VERSION=2024-12-01-preview

# Agent memory and audit storage
MIDAS_MEMORY_DATABASE_URL=postgresql://<user>:<password>@<host>:5432/<database>
MIDAS_AUDIT_DATABASE_URL=postgresql://<audit_user>:<password>@<host>:5432/<database>
MIDAS_SETUP_MEMORY_STORE=0

# Authorization policy
MIDAS_AUTHORIZATION_POLICY=/absolute/path/to/policy.json

# MCP endpoints
MIDAS_MCP_EPICS_URL=http://<host>:<port>/sse
MIDAS_MCP_LOKI_URL=http://<host>:<port>/sse
MIDAS_MCP_PROMETHEUS_URL=http://<host>:<port>/sse
MIDAS_MCP_POSTGRES_URL=http://<host>:<port>/sse

# Local code-tool working directory
MIDAS_PROJECT_ROOT=/app
```

Copy the example authorization policy before editing it:

```bash
cp hardened-version/policy_example.json policy.local.json
```

Use non-root SSH accounts and grant only the hosts, services, operations, and
tools required for diagnosis. The application must provide the authenticated
principal identity; it must never be accepted from model-generated input.

## PostgreSQL audit log

Apply the audit schema before starting the hardened agent:

```bash
psql "$MIDAS_AUDIT_DATABASE_URL" -f hardened-version/audit_schema.sql
```

Audit events can be inspected with:

```sql
SELECT occurred_at,
       run_id,
       thread_id,
       tool_name,
       phase,
       duration_ms,
       arguments,
       result,
       error
FROM midas_audit.tool_events
ORDER BY occurred_at DESC;
```

The records support operational inspection, but the current database schema
does not by itself establish tamper evidence. A production deployment should
add restricted database privileges, retention policies, integrity protection,
and off-host backup or replication where required.

## Running MIDAS

1. Start the required EPICS, Loki, Prometheus, and PostgreSQL MCP servers.
2. Configure the model, memory database, audit database, MCP endpoints, and
   authorization policy.
3. Initialize the PostgreSQL memory and audit schemas as required.
4. Start the selected MIDAS agent implementation.

For the hardened implementation:

```bash
cd hardened-version
python midas_agent.py
```

The agent graph must be invoked by an authenticated application that supplies
a principal identifier matching the authorization policy. The example policy
is illustrative and must be adapted to the local facility.

## Evaluation artifacts

`MIDAS_Fault_Diagnosis_Raw_Data/` contains the retained materials associated
with the diagnostic cases. When interpreting these files, note that:

- each case contains one retained diagnostic session;
- multiple `run` entries may represent conversational turns within the same
  session rather than independent repetitions;
- case-level agreement is descriptive and is not an estimate of population
  accuracy or generalizability;
- the repository does not provide a controlled human-performance baseline;
  and
- persistent-memory initialization should be checked before treating cases as
  independent cold-start trials.

Operational identifiers and sensitive facility information should be redacted
before any additional records are published.

## Security considerations

MIDAS interacts with operational infrastructure and must be deployed with
care. At minimum:

- use read-only MCP and database credentials wherever possible;
- do not expose raw shell access to the model;
- use least-privilege, non-root SSH accounts;
- keep credentials out of prompts, source files, logs, and Git history;
- validate authorization again at the execution boundary;
- require explicit operator approval for state-changing operations;
- isolate generated code from the control network and sensitive files; and
- test prompt-injection and cross-tool bypass paths before production use.

The hardened version reduces several risks but is not a complete security
boundary. In particular, arbitrary code execution and generic database-query
tools require additional sandboxing and backend-enforced read-only privileges.

## Data sovereignty

The commercial model in the reported study was used for proof-of-concept
validation. For production deployment, locally hosted open-weight models can
be used so that prompts, operational data, and tool outputs remain within
facility-controlled infrastructure. Model hosting should be combined with
access control, data minimization, retention rules, and audit policies.

## Citation

The formal article citation will be added after publication. Until then,
please cite this repository by its release tag and commit hash. A permanent
archive DOI can be created by linking a GitHub release to Zenodo.

## License

This project is released under the [MIT License](LICENSE).

## Contact

Questions, reproducibility reports, and bug reports are welcome through
GitHub Issues.
