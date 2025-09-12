# pqcbench-core

Core interfaces and utilities used by the CLI/GUI and adapters.

Contains
- `pqcbench.interfaces`: `KEM` and `Signature` Protocols
- `pqcbench.registry`: lightweight adapter registry with `register/get/list`
- `pqcbench.metrics`: dataclasses for batch benchmark outputs

Usage
- Adapters implement the Protocols and call `@registry.register("name")`
- Consumers look up implementations by name: `cls = registry.get("kyber")`
