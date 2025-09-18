# pqcbench-native

Native adapters that call the C implementations bundled in `native/` to drive
PQC and classical algorithms without Python overhead.

Build the shared library first (see `native/README.md`), then install this
package editable to expose the adapters:

```bash
pip install -e libs/core
pip install -e libs/adapters/native
```
