---
schema_version: 2
object_type: release_entry
versioning:
  schema_version: 1
  revision: 1
entry_id: entry-0005
release_version: v0.3.0
kind: changed
summary:
  Changed CLI format detection to require `--format` in directories with mixed
  configuration formats
status: accepted
audience: null
scopes: []
source_refs: []
paths:
  - vaultconfig/cli.py
  - vaultconfig/formats/yaml_format.py
issues: []
prs: []
sources:
  - git:0938a81017fe3cce141e326f7a89d4c553de80b4
contributors: []
breaking: true
internal: false
order: 5
---

YAML discovery recognizes both `.yaml` and `.yml` and rejects duplicate names across
those extensions.
