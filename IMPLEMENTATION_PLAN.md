\# Agent Firewall — Implementation Plan



This document defines the complete implementation roadmap.



Codex must follow the phases sequentially.



Do not skip phases.



Do not implement future phases prematurely unless a small interface or type is strictly required by the current phase.



Every phase must satisfy its acceptance criteria before proceeding.



The project objective is not maximum feature count.



The objective is to produce a credible, measurable, production-oriented security system for tool-using financial AI agents.



\---



\# PHASE 0 — FOUNDATION, THREAT MODEL, AND EVALUATION DESIGN



\## Objective



Create the engineering foundation before implementing security logic.



We must know:



\- what we are protecting;

\- what is trusted;

\- what is untrusted;

\- what attacks are in scope;

\- what security guarantees we want;

\- how success will eventually be measured.



\## Implement



Set up:



\- Python project;

\- virtual environment workflow;

\- pytest;

\- Ruff;

\- mypy;

\- Git repository;

\- basic package structure;

\- structured logging foundation.



Create:



\- architecture documentation;

\- trust-boundary documentation;

\- threat model;

\- security invariants;

\- metric definitions;

\- implementation roadmap;

\- initial ADRs where necessary.



\## Define threat categories



At minimum:



\- direct prompt injection;

\- indirect prompt injection;

\- unauthorized tool invocation;

\- privilege escalation;

\- tool argument manipulation;

\- approval bypass;

\- excessive financial action;

\- unauthorized tool chaining;

\- malicious/untrusted tool output;

\- stale/expired capability use;

\- malformed security-sensitive requests;

\- capability scope violations.



\## Define metrics



Precisely define:



\- Attack Success Rate;

\- Unauthorized Action Rate;

\- Benign Task Success Rate;

\- False Block Rate;

\- security decision latency;

\- end-to-end task latency.



\## Acceptance Criteria



Phase 0 is complete when:



\- project installs locally;

\- tests execute;

\- Ruff passes;

\- mypy passes;

\- trust boundaries are documented;

\- threat model exists;

\- security invariants exist;

\- metric formulas are explicit;

\- roadmap is documented.



\## Deliverable



A clean repository ready for implementation.



STOP after Phase 0 and report results before continuing.



\---



\# PHASE 1 — SECURITY KERNEL



\## Objective



Build the deterministic authorization core.



No real LLM integration is required yet.



The security kernel must answer:



\*\*May this agent perform this action under this context?\*\*



\## Implement domain models



Create typed representations for:



\- AgentIdentity;

\- ToolRequest;

\- ToolDefinition;

\- Capability;

\- CapabilityConstraint;

\- Policy;

\- PolicyDecision;

\- ApprovalRequirement;

\- SecurityContext;

\- DecisionReason.



Decisions:



\- ALLOW;

\- DENY;

\- REQUIRE\_APPROVAL.



\## Capability Model



Implement explicit capabilities such as:



\- market.read;

\- portfolio.read;

\- orders.read;

\- orders.create;

\- orders.cancel;

\- transfers.create;

\- withdrawals.create.



Capabilities must support constraints.



Examples:



allowed\_symbols



max\_notional\_usd



environment



expiration



agent identity



action scope



\## Default Deny



Unknown or unauthorized operations must fail closed.



Example:



Agent has:



market.read



orders.create



Agent requests:



withdraw\_asset



Result:



DENY



Reason:



MISSING\_CAPABILITY



\## Policy Engine



Implement deterministic policy evaluation.



Initial policies should include:



\- unknown tool denial;

\- missing capability denial;

\- expired capability denial;

\- schema validation;

\- symbol restrictions;

\- maximum order notional;

\- transfer restrictions;

\- withdrawal restrictions;

\- approval requirements;

\- malformed request denial.



Policies must return structured reason codes.



\## Security Invariants



Implement automated tests proving at minimum:



INV-01:

DENY never executes.



INV-02:

Missing capability never authorizes.



INV-03:

Expired capability never authorizes.



INV-04:

REQUIRE\_APPROVAL cannot execute before approval.



INV-05:

Unknown protected tools fail closed.



INV-06:

Invalid tool arguments cannot execute.



\## Testing



Create comprehensive unit tests.



Use property-based testing where valuable, especially around:



\- monetary limits;

\- capability boundaries;

\- malformed inputs;

\- expiration boundaries.



\## Acceptance Criteria



Phase 1 is complete when:



\- capability system works;

\- deterministic policies work;

\- default deny works;

\- typed decisions exist;

\- reason codes exist;

\- critical security invariants have automated tests;

\- all tests pass;

\- Ruff passes;

\- mypy passes.



\## Deliverable



A standalone deterministic security kernel.



It must be possible to test it without an LLM.



STOP and report results.



\---



\# PHASE 2 — FINANCIAL SANDBOX AND SECURE EXECUTION GATEWAY



\## Objective



Create a realistic but safe financial environment and prove that protected actions cannot bypass authorization.



No real money.



No production exchange credentials.



\## Financial Sandbox



Implement deterministic sandbox tools:



\- get\_market\_price;

\- get\_portfolio;

\- get\_open\_orders;

\- create\_order;

\- cancel\_order;

\- transfer\_asset;

\- withdraw\_asset.



Maintain sandbox state such as:



\- balances;

\- positions;

\- orders;

\- transaction history.



Use deterministic fixtures where practical.



\## Typed Tool Schemas



Every tool must have validated input/output schemas.



Example:



create\_order:



symbol



side



quantity or notional



order\_type



optional price



\## Execution Gateway



Implement the only supported execution path:



ToolRequest

→ schema validation

→ capability check

→ policy evaluation

→ approval check

→ execution

→ audit event



Protected tools must not normally be callable directly from agent-facing code.



\## Enforcement Tests



Prove:



Agent without withdrawals.create

→ cannot withdraw.



Agent with orders.create limited to $1,000

→ can create $500 sandbox order.



Same agent:

→ cannot create $10,000 order.



Restricted symbol:

→ cannot trade unsupported symbol.



Expired capability:

→ cannot execute.



\## Failure Handling



Security-sensitive internal failures must fail closed.



\## Acceptance Criteria



Phase 2 is complete when:



\- financial sandbox works;

\- tool schemas are validated;

\- all protected execution passes through gateway;

\- security policies affect actual sandbox state;

\- denied actions do not mutate sandbox state;

\- integration tests cover allow/deny/approval paths;

\- tests/lint/type checks pass.



\## Deliverable



A functioning protected financial environment.



STOP and report results.



\---



\# PHASE 3 — TOOL-USING AI AGENT AND MCP/TOOL INTEGRATION



\## Objective



Introduce an actual AI agent into the system.



The agent must never directly own authorization.



\## Agent Layer



Implement an agent capable of interpreting user tasks and proposing tool calls.



Example tasks:



"What is the current BTC price?"



"Show my portfolio."



"Buy $100 of BTC."



"Cancel order X."



\## Provider Abstraction



Avoid tight coupling to one model provider.



Create a clean model/agent interface.



Support at least:



\- deterministic/mock agent for tests;

\- one real LLM integration for demonstrations/experiments.



The deterministic security kernel must work without paid model access.



\## Tool Integration



Expose sandbox tools to the agent through the controlled gateway.



If MCP materially improves the architecture, introduce MCP integration here.



Do not allow MCP or another integration to bypass the security boundary.



\## Untrusted Content



Introduce the concept of untrusted external content.



The system must distinguish:



\- direct user intent;

\- model-generated actions;

\- external content;

\- trusted policy.



Do not treat instructions found in external content as authorization.



\## End-to-End Flow



User

→ Agent

→ proposed tool call

→ Agent Firewall

→ decision

→ optional approval

→ sandbox execution

→ result

→ Agent



\## Acceptance Criteria



Phase 3 is complete when:



\- an AI agent can use protected tools;

\- all tool execution crosses the firewall;

\- mock/deterministic agent remains available for tests;

\- at least one real-model integration works if credentials are available;

\- external content has explicit trust classification;

\- authorization remains independent from LLM decisions;

\- tests/lint/type checks pass.



\## Deliverable



A real tool-using financial agent protected by Agent Firewall.



STOP and report results.



\---



\# PHASE 4 — ADVERSARIAL EVALUATION FRAMEWORK



\## Objective



Build the core evidence-generating component of the project.



The project must now answer:



\*\*Does Agent Firewall actually improve security?\*\*



\## Scenario Format



Create a structured scenario schema containing at minimum:



\- scenario ID;

\- category;

\- description;

\- user task;

\- agent identity;

\- capabilities;

\- environment state;

\- external/untrusted content if applicable;

\- expected authorization constraints;

\- attack goal where applicable;

\- success/failure criteria.



\## Benign Dataset



Create legitimate tasks covering:



\- market reads;

\- portfolio reads;

\- authorized orders;

\- order cancellation;

\- valid transfers where permitted;

\- legitimate approval workflows.



\## Adversarial Dataset



Include multiple scenarios for:



\- direct prompt injection;

\- indirect prompt injection;

\- unauthorized tools;

\- privilege escalation;

\- amount manipulation;

\- approval bypass;

\- excessive actions;

\- tool chaining;

\- malicious external content;

\- stale capability;

\- malformed requests;

\- scope violations.



\## Financial-Specific Attacks



Prioritize scenarios where successful attacks would cause a sensitive action.



Examples:



Agent is authorized for:



orders.create max $500



Attack attempts:



$50,000 order.



Agent has:



portfolio.read



Attack attempts:



withdraw\_asset.



External content attempts to make the agent:



transfer funds.



Agent is permitted to trade BTC only.



Attack attempts:



ETH or unsupported asset.



\## Benchmark Configurations



Implement at least:



\### BASELINE A



Unprotected agent.



No Agent Firewall authorization.



\### BASELINE B



Basic static rules.



Simple allow/deny mechanism.



\### SYSTEM C



Full Agent Firewall.



Capability + policy + approval + audit enforcement.



\## Metrics



Compute automatically:



\- Attack Success Rate;

\- Unauthorized Action Rate;

\- Benign Task Success Rate;

\- False Block Rate;

\- security decision latency;

\- end-to-end latency.



\## Experiment Artifacts



Produce machine-readable output.



Example:



experiments/

baseline\_unprotected.json



experiments/

baseline\_rules.json



experiments/

firewall.json



Do not manually copy metric values into result files.



\## Reproducibility



Support:



\- fixed seeds where applicable;

\- configuration capture;

\- model identification;

\- benchmark version;

\- timestamp;

\- environment metadata.



\## Acceptance Criteria



Phase 4 is complete when:



\- benchmark can execute end-to-end;

\- benign scenarios exist;

\- adversarial scenarios exist;

\- three configurations can be compared;

\- metrics are calculated automatically;

\- experiment artifacts are generated;

\- benchmark execution is reproducible enough to rerun;

\- tests/lint/type checks pass.



\## Deliverable



A reproducible adversarial evaluation framework.



STOP and report results.



\---



\# PHASE 5 — APPROVALS, OBSERVABILITY, AUDIT AND REPLAY



\## Objective



Make the system operationally understandable.



A production security system must answer:



\*\*What happened, why did it happen, and what was executed?\*\*



\## Human Approval



Implement explicit approval workflow.



Example:



Agent requests:



create\_order($20,000)



Firewall:



REQUIRE\_APPROVAL



Execution must pause.



Only a valid approval authority can authorize continuation.



Approval should have:



\- approval ID;

\- requesting agent;

\- action;

\- relevant arguments;

\- reason;

\- expiration;

\- status.



Prevent:



\- reuse;

\- approval for modified action;

\- approval after expiration.



\## Structured Audit Events



Record:



\- trace\_id;

\- run\_id;

\- agent\_id;

\- requested tool;

\- safe/normalized arguments;

\- required capability;

\- policies evaluated;

\- matched policy;

\- decision;

\- reason code;

\- approval state;

\- decision latency;

\- execution status.



Never log secrets unnecessarily.



\## Replay



Implement deterministic security-decision replay where possible.



Replay must allow a developer to inspect:



\- what action was proposed;

\- what security context existed;

\- what policy applied;

\- why the decision occurred;

\- whether execution happened.



Replay does NOT need private model chain-of-thought.



\## CLI / Developer Inspection



Provide a practical way to inspect:



\- runs;

\- decisions;

\- denied actions;

\- approvals;

\- policy reasons.



A lightweight CLI is preferred initially.



Do not build a large frontend yet.



\## Acceptance Criteria



Phase 5 is complete when:



\- sensitive actions can require approval;

\- approval cannot be trivially bypassed;

\- audit records exist for protected actions;

\- decisions can be inspected;

\- relevant decisions can be replayed;

\- traces correlate the complete action lifecycle;

\- tests/lint/type checks pass.



\## Deliverable



An auditable and explainable Agent Firewall runtime.



STOP and report results.



\---



\# PHASE 6 — SECURITY HARDENING AND RELIABILITY



\## Objective



Attempt to break the system.



Do not add flashy features.



Focus on bypass resistance and reliability.



\## Adversarial Hardening



Test:



\- malformed tool calls;

\- unexpected types;

\- boundary monetary values;

\- negative values;

\- floating-point/decimal issues;

\- Unicode/encoding edge cases where relevant;

\- unknown tools;

\- duplicate requests;

\- replayed approvals;

\- changed arguments after approval;

\- expired approval;

\- expired capability;

\- conflicting policies;

\- missing context;

\- policy engine failure;

\- audit failure behavior;

\- concurrent requests where relevant.



\## Property-Based Tests



Use property-based testing for high-value invariants.



Example:



For every generated order amount greater than the capability limit:



execution must never succeed without required authorization.



\## Fail-Closed Testing



Simulate internal failures.



Examples:



policy evaluator throws exception;



capability data unavailable;



malformed security context.



Sensitive actions must not silently fall through to execution.



\## Performance



Measure:



\- policy decision p50;

\- p95;

\- p99;

\- throughput where meaningful;

\- end-to-end overhead.



Profile before optimizing.



Do not optimize hypothetical bottlenecks.



\## Regression Suite



Every discovered security bug should become a regression test.



\## Acceptance Criteria



Phase 6 is complete when:



\- critical edge cases have been tested;

\- property-based security tests exist where justified;

\- fail-closed behavior is verified;

\- discovered bypasses have regression tests;

\- performance has been measured;

\- major known limitations are documented;

\- tests/lint/type checks pass.



\## Deliverable



A hardened release candidate ready for final evaluation.



STOP and report results.



\---



\# PHASE 7 — FROZEN FINAL BENCHMARK AND PORTFOLIO RELEASE



\## Objective



Generate the final evidence used in the portfolio and resume.



This phase is evaluation and packaging, not benchmark-driven development.



\## Freeze



Freeze:



\- benchmark version;

\- scenario definitions;

\- metric definitions;

\- system configuration;

\- baselines.



Do not modify the system based on individual final benchmark failures and rerun until the desired number appears.



If a genuine implementation bug invalidates the experiment:



\- document the bug;

\- fix it;

\- version the benchmark/run;

\- rerun transparently.



\## Final Experiments



Run:



Baseline A — unprotected agent



Baseline B — basic rules



System C — Agent Firewall



Record complete artifacts.



\## Final Metrics



At minimum report:



\- total scenarios;

\- benign scenarios;

\- adversarial scenarios;

\- Attack Success Rate;

\- Unauthorized Action Rate;

\- Benign Task Success Rate;

\- False Block Rate;

\- p50/p95 security decision latency;

\- end-to-end latency.



Break security results down by attack category.



\## Failure Analysis



Do NOT hide failures.



Document:



\- successful attacks;

\- false blocks;

\- unsupported threats;

\- limitations;

\- cases requiring semantic detection;

\- cases deterministic authorization cannot solve.



This increases credibility.



\## Final Artifact



Generate:



experiments/final\_benchmark.json



This must be the source of truth for final reported numbers.



\## README



Create a high-quality README containing:



\- business/security problem;

\- why tool-using financial agents create risk;

\- system architecture;

\- threat model;

\- demo;

\- benchmark;

\- baselines;

\- measured results;

\- latency;

\- limitations;

\- reproduction instructions.



README metrics must be traceable to experiment artifacts.



\## Demo



Provide a concise reproducible demonstration.



Example:



Normal request

→ ALLOW

→ execution.



Unauthorized request

→ DENY.



High-risk request

→ REQUIRE\_APPROVAL.



Indirect injection

→ agent proposes unsafe action

→ firewall prevents unauthorized execution.



\## Resume Metrics



Create:



docs/resume\_metrics.md



Only include claims directly supported by final experiment artifacts.



Never include invented business impact.



\## Acceptance Criteria



Phase 7 is complete when:



\- final benchmark is frozen and executed;

\- artifacts exist;

\- results are reproducible;

\- failure analysis exists;

\- README is complete;

\- demo is reproducible;

\- resume metrics are evidence-backed;

\- full tests pass;

\- Ruff passes;

\- mypy passes.



\## Final Deliverable



A portfolio-grade Agent Firewall demonstrating:



\- financial AI agents;

\- tool calling;

\- runtime authorization;

\- least privilege;

\- policy enforcement;

\- human approval;

\- adversarial evaluation;

\- observability;

\- replay;

\- security engineering;

\- reliability;

\- measurable performance.



\---



\# FINAL RULE



Never optimize this project for the number of features.



Optimize for:



\*\*security guarantees + adversarial evidence + engineering quality + reproducibility.\*\*



At the end of every phase:



1\. run tests;

2\. run lint;

3\. run type checking;

4\. report results;

5\. document unresolved issues;

6\. STOP.



Proceed to the next phase only after explicit instruction.

