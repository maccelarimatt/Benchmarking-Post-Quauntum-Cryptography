# pqcbench_native C library

Shared library exposing thin wrappers around liboqs (and optionally OpenSSL)
so that PQC/classical algorithms can be executed without Python overhead.

## Build

```bash
cmake -S native -B native/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/build --config Release
```

The project builds liboqs as a subdirectory. If OpenSSL development headers
are available, RSA KEM/signature helpers are enabled automatically; otherwise
the native library still builds with PQC support and the Python RSA adapter is
used as a fallback.

Set `PQCBENCH_NATIVE_LIB` to the resulting shared library path if it is not
located under `native/build` when running the Python adapters.
