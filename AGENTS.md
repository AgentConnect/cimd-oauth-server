# Repository instructions

This repository is private. Do not publish source, packages or images publicly.

Follow [AWiki coding rules](../awiki-harness/rules/ai-coding-rules.md), [verification policy](../awiki-harness/rules/verification-policy.md) and [dependency source rules](../awiki-harness/rules/dependency-sources.md).

## Scope

CIMD/private_key_jwt/client_credentials authorization server, resource verifier and MCP example. Current TypeScript implementation belongs under ts/; rust/ is reserved for future work.

The owning implementation plan is in `../awiki-plan/20261104-dsh-shared-agent-identity/modules/`. Follow the current local-signing-only scope. Preserve user changes and other agents' file ownership. Commit messages, code comments, logs and errors use English; planning prose uses Chinese.

Use task-isolated databases, keys, state roots and ports. Record real tests and distinguish unit/fixture evidence from remote or product validation. Never log tokens, full assertions, private keys or credentials. No shared-service restart, remote deployment or public release is implied by module work.
