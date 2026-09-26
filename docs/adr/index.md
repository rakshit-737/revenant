# Architecture Decision Records

Short records of the load-bearing design decisions and their trade-offs.

| ADR | Decision |
| --- | --- |
| [0001](0001-rules-not-ml-for-causal-claims.md) | Deterministic rules, not ML, produce causal claims |
| [0002](0002-indexed-rule-engine.md) | Indexed, nearest-cause rule engine with a PID-reuse guard |
| [0003](0003-entity-keys.md) | Lossy entity keys instead of raw-string identity |
| [0004](0004-stories-not-paths.md) | Incident stories (causal subtrees), not enumerated paths |
| [0005](0005-custody-ledger.md) | Hash-chained custody ledger, persisted append-only in SQLite |
| [0006](0006-benchmark-methodology.md) | Benchmark methodology (ground truth without hand labels) |
| [0007](0007-timestamp-normalisation.md) | Timestamp normalisation across collectors |
