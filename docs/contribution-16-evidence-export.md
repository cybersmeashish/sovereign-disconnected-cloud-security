# 16 — Controlled evidence export

[Exporter](../assurance/observability.py) requires an allowed recipient, site and classification, rejects mixed-site data and batch replay, and emits only ID/site/kind/time fields. It records a payload digest, recipient, batch identifier, sender key and time, then signs the body and custody record.

Tests deny unknown recipients, unauthorized classifications and mixed-site exports and confirm private detail fields disappear. The custody signature authenticates a local assertion; it does not prove recipient receipt, transport confidentiality or a physically one-way transfer. Recipient approvals, replay state and policy distribution are ephemeral reference inputs. No message is sent to a real recipient.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
