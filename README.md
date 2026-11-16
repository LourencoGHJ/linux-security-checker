# Golfinho

**Golfinho** is a cross-platform research prototype exploring how system
information can be collected, structured and investigated to support
problem-solving in cybersecurity.

The project is experimental. It is not a production endpoint protection
product, vulnerability scanner or compliance certification tool.

## Research direction

How can technical system observations be converted into clear, evidence-based
investigations and practical recommendations across different operating systems?

The project explores this through independently testable components:

- **Platform adapters** — collect operating-system-specific information.
- **Normalized profile** — expose a common data structure across platforms.
- **Checks** — investigate selected system and security configurations.
- **Evidence and rules** — keep observations separate from conclusions.
- **Investigation references** — connect findings to trustworthy technical sources.
- **Reports** — communicate results and limitations.

## Current implementation

The first working slice collects basic host metadata on Linux and Windows.
It is read-only and does not change system configuration, install packages,
inspect file contents or claim that a host is secure.

The profile includes operating-system family and name, distribution identifier
where applicable, OS version, kernel/release, CPU architecture, hostname,
administrative privileges, collection timestamp and collection mode.

Other operating systems are identified as unknown/unsupported rather than
being incorrectly classified as Linux or Windows.

## Requirements

- Python 3.10 or newer
- No third-party runtime dependencies for the current profile command

## Install from a source checkout

    python -m pip install -e .

Run the profile command:

    python -m golfinho profile
    python -m golfinho profile --format json

Run tests:

    python -m unittest discover -s tests -v

## Research and safety principles

1. Read-only by default.
2. No automatic remediation.
3. An observation is not automatically a vulnerability.
4. Missing permissions or unavailable tools are reported as unknown or
   incomplete, not as a secure/insecure result.
5. Findings should include reproducible evidence, confidence and references.
6. Platform-specific checks stay isolated behind platform adapters.
7. Host identifiers and collected data should be minimized in published reports.

## Project status

Early research prototype — cross-platform profile collection is the first
implemented milestone. Security checks and investigation workflows are
experimental and must be validated before being relied upon.

## Author

Guilherme Faria
