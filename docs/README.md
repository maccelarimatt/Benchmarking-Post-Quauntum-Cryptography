# Documentation Overview

This directory collects extended guides that complement the package-level
READMEs. The layout is ready to be consumed by MkDocs, Sphinx, or another
static-site generator once you are ready to publish a docs site.

## Suggested Workflow
- Start with MkDocs for a quick static site (`mkdocs serve`).
- Link to package READMEs for CLI/GUI usage details.
- Promote shared terminology (categories, adapters, passes) so the CLI, GUI,
  and docs all speak the same language.

## Reference Map
- `algorithm-implementations.md` – backend overview and benchmarking notes.
- `image-encryption-pipeline.md` – walkthrough of the GUI demo pipeline.
- `llm-integration-guide.md` – configuring the AI-assisted analysis panel.
- `security/` – estimator models, side-channel methodology, and native backend
  checklists.
- `testing/validation-coverage.md` – vector/KAT coverage for the runners.
- `issues/` – known-problem notes (e.g., Dilithium validation prerequisites).
