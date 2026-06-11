# Corpus preregistration

This document defines how the real-world MCP server corpus will be selected and
labeled before candidate servers are chosen. The goal is to avoid quietly
choosing servers first and writing criteria afterward.

No server list is selected in this document.

## Goal

Build a reproducible validation corpus that tests whether `mcpscan` can
enumerate real MCP servers, produce useful findings, avoid obvious false
positives, and record failures honestly.

The corpus is for scanner validation and benchmark development. It is not
registry monitoring, ecosystem coverage, or a claim that these servers are the
most important MCP servers.

## Safety Rule

Corpus runs execute third-party code. Real corpus runs must happen inside a
disposable container or VM, not directly on a daily-use workstation.

The harness must still require an explicit acknowledgement flag, but the flag is
not a substitute for isolation.

Recommended isolation:

- disposable Linux container or VM
- no mounted home directory
- no real cloud/API credentials
- temporary workspace only
- network access limited to dependency installation and the server behavior
  needed for the run
- raw reports reviewed before anything is committed

## Target Size And Strata

Target full corpus size: 25 MCP servers.

Initial Slice 9 harness entries may include only two example servers so the
tooling can be tested without pretending the corpus is complete.

Full corpus quota:

| Stratum | Target count | Purpose |
| --- | ---: | --- |
| reference | 6 | Official or reference-style servers that establish baseline behavior |
| popular | 8 | Community servers with visible adoption or repeated recommendations |
| risky | 6 | Servers whose purpose naturally exposes sensitive or powerful capabilities |
| dual_nature | 5 | Servers where a capability can be legitimate or surprising depending on declared purpose |

If a quota cannot be filled with runnable servers, record the gap instead of
silently replacing it with easier targets.

## Inclusion Criteria

A server can enter the candidate pool only if all of these are true:

- Public source repository is available.
- The server implements MCP or is documented as an MCP server.
- A specific commit SHA can be pinned.
- Install and launch steps can be written as deterministic commands.
- The server can be run in a disposable container or VM.
- It can be scanned over stdio or a supported remote transport.
- It can complete MCP initialize and tool/resource/prompt enumeration without
  real production credentials.
- Any required credentials for enumeration can be dummy values, or the manifest
  records that no credentials were needed.

## Exclusion Criteria

Exclude a candidate if any of these are true:

- It requires real credentials before MCP enumeration succeeds.
- It requires interactive login or browser authentication to enumerate.
- Install steps are not reproducible from a pinned commit.
- It intentionally performs destructive actions during startup or enumeration.
- It cannot be isolated in a container or VM with reasonable effort.
- It is primarily malware, exploit code, or a toy fixture rather than a real MCP
  server.

Failures discovered after selection are not retroactive exclusions. They should
be recorded as corpus run failures.

## Selection Procedure

1. Build a candidate sheet from public MCP server sources.
2. Record metadata before running scans:
   - repository URL
   - package name, if any
   - observed popularity signal
   - apparent purpose
   - transport
   - required environment variable names
   - whether dummy credentials appear sufficient for enumeration
   - candidate stratum
3. Apply inclusion/exclusion criteria.
4. Assign strata.
5. Fill quotas using deterministic tie-breakers:
   - runnable with documented install steps
   - no real credentials needed for enumeration
   - transport supported by `mcpscan`
   - distinct capability profile from already-selected servers
   - clearer public provenance
   - higher adoption signal
6. Pin commit SHAs.
7. Add manifest entries.

Do not tune criteria after seeing scanner findings. If criteria must change,
record the change and why.

## Dummy Credentials

Many real MCP servers require environment variables for upstream API calls, but
still enumerate tools successfully with dummy values.

The manifest must record:

- environment variable names provided
- whether values were dummy
- whether enumeration succeeded without valid credentials
- whether any tool invocation was attempted

`mcpscan` validation should not invoke tools that call upstream services during
corpus enumeration.

## Failure Policy

Per-server failures are data, not blockers.

The harness should write:

- `corpus/results/<server_id>/error.txt` for install, launch, timeout, or
  enumeration failures
- `corpus/results/<server_id>/run.log` for sanitized operational logs
- no raw secrets
- no raw source code excerpts
- no raw prompt payloads beyond normal scanner output

Do not delete failed servers from the corpus merely because they failed. Mark
their status and keep the pinned manifest entry unless the original selection
criteria were wrong.

## Label Schema Draft

Ground truth labels attach to server properties, not to any scanner's finding
format.

One label file per server:

```yaml
server_id: filesystem_reference
corpus_sha: "<pinned git sha>"
labeler: "<name or handle>"
label_date: "YYYY-MM-DD"
declared_purpose:
  category: filesystem
  text: "Filesystem MCP server for reading and writing files."
credentials:
  required_for_enumeration: false
  dummy_credentials_used: false
  env_names: []
transport: stdio
enumeration:
  expected_to_succeed: true
  notes: ""
properties:
  - id: file_read_capability
    capability: file_read
    expected_by_purpose: true
    exposed_by:
      - tool: read_file
    severity_if_unexpected: high
    rationale: "Reading files is inherent to the declared filesystem purpose."
  - id: file_write_capability
    capability: file_write
    expected_by_purpose: true
    exposed_by:
      - tool: write_file
    severity_if_unexpected: high
    rationale: "Writing files is inherent to the declared filesystem purpose."
false_positive_notes: []
false_negative_notes: []
```

Required label fields:

- `server_id`
- `corpus_sha`
- `labeler`
- `label_date`
- `declared_purpose`
- `credentials`
- `transport`
- `enumeration`
- `properties`

## Review Questions

Before adding a server to the final corpus, answer:

- Which stratum quota does this server fill?
- Can it enumerate without real credentials?
- Are dummy credentials needed?
- What capability profile does it add that existing selected servers do not?
- Can it run in the isolation environment?
- What would count as an expected finding for its declared purpose?
- What would count as a surprising or undeclared capability?

## Non-Goals

The corpus does not:

- prove complete MCP ecosystem coverage
- monitor registries
- require valid production credentials
- invoke dangerous tools
- rank MCP servers by security
- produce vulnerability disclosures by default
