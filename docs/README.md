# Documentation Overview

The `docs/` tree hosts extended guides that complement the package-level
READMEs and provide background for benchmarks, security estimators, and GUI
workflows. Each topic sits in its own subdirectory so the material can be wired
directly into MkDocs, Sphinx, or another static-site generator.

## How to use this directory
- Start with MkDocs for a quick preview (`mkdocs serve`) or plug the folders
  into your existing documentation pipeline.
- Link back to package READMEs (CLI, GUI, adapters) to keep step-by-step setup
  instructions close to the code.
- Reuse the shared terminology defined here (categories, adapters, passes) so
  tooling, docs, and presentations stay aligned.

## Contents
- `algorithm-implementations/` - backend overviews, benchmarking notes, and
  references for each cryptographic family.
- `image-encryption-pipeline/` - GUI demo walkthrough with entropy analysis
  callouts.
- `llm-integration-guide/` - configuration guide for wiring the optional
  benchmarking assistant.
- `security/` - estimator models, side-channel methodology, and native backend
  checklists (contains several deep-dive articles).
- `testing/` - validation coverage notes for runners and adapters.
- `issues/` - known issue reports and troubleshooting guidance.

