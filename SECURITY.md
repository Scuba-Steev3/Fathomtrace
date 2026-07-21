# Security policy

Fathomtrace is intended only for systems that you own or are explicitly authorized
to assess. Some optional modules attempt credentials, generate substantial
traffic, or alter a remote configuration when an explicitly intrusive flag is
selected.

Do not include live credentials, hashes, tickets, private keys, customer data,
or unredacted scan artifacts in a public issue. Report a suspected vulnerability
privately to the repository maintainer and include the affected version, impact,
and a minimal reproduction that uses synthetic data.

Generated session directories may contain sensitive material. Keep them outside
source control, review permissions before sharing, and delete them according to
the assessment's retention policy.

Credential values are redacted by default. `--show-secrets` deliberately
disables that protection for console output and stored metadata; do not use it
with shared terminals, CI logs, shell recording, or broadly accessible loot
directories.
