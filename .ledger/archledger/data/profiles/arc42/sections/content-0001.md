---
schema_version: 4
id: content-0001
kind: content
type: section
section: introduction_and_goals
title: Introduction and Goals
order: 10
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/__init__.py
  - vaultconfig/config.py
  - vaultconfig/secrets/api.py
---

VaultConfig is a Python library and local CLI for managing named application configurations, validating their contents, and optionally encrypting configuration files at rest. It also provides a separate Python API for storing individual named secrets without embedding them in application configuration.

Application developers use the Python API to load validated settings and retrieve secrets. Operators use the CLI to inspect, modify, encrypt, and export configuration or supply it to a child process. Maintainers need changes to preserve compatibility with existing configuration files and keep optional integrations isolated.
