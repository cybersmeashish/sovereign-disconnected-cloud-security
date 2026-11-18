# Sovereign AI integration contract

The local case uses `assurance.policy.LocalAI`, a deterministic router with no learned weights.

| Boundary | Reference contract | Remaining integration work |
| --- | --- | --- |
| Model/runtime inventory | Pinned Python packages plus a synthetic model-data bundle | Real model weights/tokenizer/runtime, licenses, accelerators and completeness |
| Model updates | Separate signed admission gate; site/builder/digest/approval checks | Durable release freshness and a reviewed real model-loader format |
| Retrieval | Trusted resource site/tenant checked by local authority | Index/chunk ACL propagation and verified model outputs |
| Tools | Explicit `read_record`/`acknowledge_alert` action map | Real tool adapters and independently authorized side effects |
| Evidence export | Recipient/site/classification gate and field filtering | Approved physical/transport disclosure boundary |

Prompt text grants no additional authority. Cross-scope retrieval and shell execution are denied in the fixture. No claim is made about real-model prompt-injection robustness or accuracy.

[Sovereign AI workspace](https://github.com/cybersmeashish/sovereign-AI) · [Measured case](contribution-26-sovereign-ai.md)
