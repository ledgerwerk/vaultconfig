---
schema_version: 4
id: content-0007
kind: content
type: section
section: deployment_view
title: Deployment View
order: 70
status: accepted
version: 2
body_format: markdown
source_refs:
  - pyproject.toml
  - vaultconfig/cli.py
  - vaultconfig/secrets/fileio.py
  - vaultconfig/secrets/keyring_store.py
---

Install `vaultconfig` into the application environment. The same package exposes the `vaultconfig` console script. No database or server deployment is required.

- **Configuration files:** The CLI chooses an explicit directory first, then `VAULTCONFIG_DIR`, then the platform default. Defaults use `APPDATA` on Windows or `XDG_CONFIG_HOME` on other platforms when set, with home-directory fallbacks. Python callers pass the directory directly to `ConfigManager`.
- **File vault:** The application chooses a writable, protected directory. The backend checks ownership and permissions on POSIX. On Windows, the deployment must supply appropriate access controls.
- **OS keyring:** Install the `keyring` extra and provide a supported native backend in the current user session. An unavailable or unsupported backend fails rather than falling back to plaintext.
