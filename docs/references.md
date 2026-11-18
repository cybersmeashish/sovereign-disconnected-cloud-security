# Primary sources and attribution

Sources are technical baselines for the stated design and assumptions. The boundary records, flow rules, dependency model and local authority are original reference artifacts; no source endorses this implementation.

| Source | Relevance and scope |
| --- | --- |
| [NIST SP 800-207, Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final) | Resource/action authorization and the distinction between network location and trust |
| [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | Published control material to examine for identity, boundaries, inventories and recovery; no compliance conclusion |
| [Docker: none network driver](https://docs.docker.com/engine/network/drivers/none/) | Container network-none behavior and loopback observation |
| [AWS: Outposts regional-disconnection considerations](https://docs.aws.amazon.com/wellarchitected/latest/data-residency-hybrid-cloud-services-lens/drhcrel05-bp04.html) | A vendor-specific example of dependencies that need review; no AWS deployment tested |
| [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | Password-storage design context; the lab's algorithm/parameters are explicit, without production assurance |

The existing arithmetic capacity reference derives from Ashish Srivastava's earlier generic capacity-model work. Its previous nine tests are retained.

The official Python image is pinned by its retrieved image digest in the Dockerfile. Preparation, image identity, code hashes, runtime restrictions and observed outcomes are distinct evidence.
