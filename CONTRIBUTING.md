# Contributing

Changes should preserve the positional compatibility invocation unless a
breaking release is planned. New feature flags must be documented, validated,
and gated so unrelated tools do not execute.

Before opening a pull request, run:

```bash
make test
make lint
make format-check
```

Add tests for new CLI contracts, output schemas, artifact behavior, and failure
paths. Never commit real assessment data or credentials. Keep sourceable
cross-cutting behavior under `lib/fathomtrace`; service-specific extraction from
the main script should be incremental and compatibility-tested.
