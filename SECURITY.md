# Security scope and reporting

Agent Firewall is a research and portfolio project for a deterministic local financial sandbox. It does not connect to an exchange, manage real funds, or claim production certification.

Please report suspected vulnerabilities privately to the repository owner through an appropriate private GitHub contact or security-reporting channel. Do not include live credentials, personal data, or real financial information in a report.

The supported security boundary is the tool proposal path through `ExecutionGateway`. Trusted-host compromise, compromised identity or approval authorities, multi-host state coordination, crash-consistent financial transactions, real exchange infrastructure, and external audit-log anchoring are outside the current scope. See [`docs/threat-model.md`](docs/threat-model.md) for the complete assumptions and limits.
