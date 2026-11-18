# 11 — Offline software inventory and vulnerability review

[CycloneDX 1.6 example](../examples/sbom.cdx.json) inventories the three pinned Python packages. [Advisory snapshot](../examples/advisory-snapshot.json) records successful exact-version queries against GitHub's reviewed advisory catalog, with collection time and query URLs. [Review function](../assurance/inventory.py) reports snapshot age, missing coverage and known matches. A separate [synthetic finding](../examples/advisory-synthetic-negative.json) exercises the negative case.

The expanded report calculates age at execution. After seven days the reference marks the snapshot stale; a future timestamp is unverified. No matching advisory in this small query snapshot is **not an absence-of-vulnerability conclusion**. OS layers, transitive native libraries, exploitability and new advisories need separate review. Connected preparation hash-locks wheels; the isolated build installs them without network access.

[Completion and measured evidence](contributions-08-28.md) · [Expanded verification](expanded-verification.md) · [Primary references](expanded-references.md)
