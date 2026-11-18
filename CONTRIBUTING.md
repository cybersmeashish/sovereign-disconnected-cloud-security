# Contribute a bounded, reproducible security result

Publish one question, its scoped threat or failure, an artifact, legitimate-use and negative cases, actual observations, limitations and next question. Use synthetic fixtures or material you are authorized to make public.

Run `python3 -m unittest discover -s tests -v`. For isolation-related changes, rebuild the pinned image and run `python3 -m tools.run_isolated_lab`. A source-manifest mismatch means the image is stale; rebuild rather than accepting earlier evidence.

Add tests for a meaningful trust-boundary or failure change. Keep design, modeled behavior, measured reference behavior, and actual deployment assurance clearly labeled.

Never commit real credentials, private customer details, classified material or production datasets.
