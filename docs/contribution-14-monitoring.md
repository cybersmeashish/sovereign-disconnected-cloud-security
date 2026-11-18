# 14 — Local security monitoring

[SQLite monitor](../assurance/observability.py) ingests bounded synthetic records, detects five authentication denials in sixty seconds and flags rejected imports/recovery requests. It enforces event-count and time retention and records eviction/expiration counts.

The run observes a repeated-denial alert, then expiration and backlog loss. An unknown event type intentionally has no detection rule; that miss is reported. Rules are limited to this fixture vocabulary. There is no endpoint agent, production SIEM, attack-coverage estimate or claimed completeness. Ingestion currently trusts supplied event timestamps; operational time validation, backlog prioritization and protected retention need further work.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
