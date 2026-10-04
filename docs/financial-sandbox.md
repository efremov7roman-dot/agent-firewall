# Deterministic financial sandbox

The Phase 2 sandbox exists only to make authorization consequences measurable. It has no
network client, credential loading, exchange integration, or path to real funds.

## Fixed initial state

- prices: BTCUSDT = 50,000 USD, ETHUSDT = 2,500 USD, USDTUSD = 1 USD;
- marked balances: USD = 100,000, USDT = 10,000, BTC = 50,000, ETH = 25,000 USD;
- positions: 1 BTC and 10 ETH;
- no orders or transactions.

Balances are marked USD values rather than exchange-grade asset ledgers. This is an
explicit Phase 2 simplification that keeps transfer/withdrawal limit tests exact. Orders
are deterministic OPEN records and do not simulate matching, fees, slippage, or fills.

Every new gateway instance owns isolated state. IDs are monotonic (`order-000001`,
`transaction-000001`). Read calls return copies. Mutations validate all failure
conditions before changing state, avoiding partial updates for expected failures.

## Execution boundary

The mutable `_FinancialSandbox` is internal. Agent-facing code receives
`ExecutionGateway`, which performs schema validation, capability/policy evaluation,
approval verification, execution, and lifecycle-event correlation. It executes the
normalized arguments captured by the decision rather than rereading mutable raw input.

The default approval verifier denies all approvals. Phase 5 adds a trusted
`ApprovalManager` with allowlisted authorities, local persistence, expiration,
single-use consumption, and a SHA-256 digest over agent, principal, environment, tool,
and normalized arguments. Phase 9 coordinates file-backed consumption across local
manager instances and partitions sandbox state by principal/environment. It is not a
distributed multi-host transaction service. Sandbox reads, authorization-state checks,
and mutations are serialized per gateway to prevent duplicate IDs, lost balance updates,
aggregate-limit races, and concurrent overspending.
