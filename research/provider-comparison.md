# Provider comparison — documentation findings versus own tests

Retrieved 18 November 2026. No provider environment was tested.

| Dimension | AWS Outposts racks — documented | Google Distributed Cloud air-gapped — documented | Own reference lab |
| --- | --- | --- | --- |
| Connectivity model | Parent Region/service-link dependency for management and monitoring | Designed for disconnected operation without public Google Cloud/internet connectivity | One network-disabled Linux container |
| Local operation | Running instances remain locally accessible; workloads can fail on regional dependencies | Local platform security/IAM and disconnected workload controls described | Synthetic local login/read/review |
| Administration | Regional mutating/control-plane operations fail during the described disconnection | Air-gapped security and operations model documented | Ephemeral local authority; no provider control plane |
| Update/security inputs | Establish the selected services' regional dependencies and update arrangements | Security operations describes air-gapped patch delivery and offline security inputs | Signed synthetic data bundles, pinned connected preparation |
| Recovery | Verify service/instance/site failure behavior for the selected deployment | Disaster recovery and operational roles are documented | Five clean config/data/software-key restores |
| Procurement gap | Test actual regional/local dependencies, administration and recovery | Verify contracted local roles, update custody and recovery implementation | Cannot substitute for a provider pilot or residency evidence |

Sources: [AWS regional disconnection](https://docs.aws.amazon.com/wellarchitected/latest/data-residency-hybrid-cloud-services-lens/drhcrel05-bp04.html), [GDC security](https://docs.cloud.google.com/distributed-cloud/hosted/docs/latest/gdcag/security), [GDC security operations](https://docs.cloud.google.com/distributed-cloud/hosted/docs/latest/gdcag/security-operations).

Product scope and documented configuration matter. Neither column establishes legal sovereignty, customer deployment or accreditation. Source hashes are recorded separately; living documentation may change.
