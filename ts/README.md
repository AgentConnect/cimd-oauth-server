# Private CIMD OAuth runtime package

This package contains the built reference authorization server, independent resource verifier, PostgreSQL migrations and two-tool MCP application. It is private/closed-source and must not be published publicly. Third-party dependencies retain their own licenses.

The source repository includes the complete tests and implementation evidence. The runtime tarball deliberately includes only built service modules, migration/config/admin launchers, the public configuration template and required license documentation; local test logs, execution artifacts, test-only AS products and native/source integration fixtures are excluded.

Use `npm run start:as:built`, `npm run start:mcp:built`, `npm run migrate:built`, `npm run configure:built` and `npm run admin:built -- <operation>` after privately injecting the appropriate configuration. See [runtime package instructions](docs/runtime-package.md). Missing configuration fails closed. Nothing starts automatically when the package is installed.
