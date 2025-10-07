# Cold-Run Memory Isolation

`pqcbench` measures each benchmark in a fresh Python process so allocator
caches, liboqs buffers, and interpreter state never leak between runs. This
note summarises the pipeline and points to the relevant code for deeper dives.

## Execution Flow

1. `measure(...)` dispatches work to `_run_isolated` (`apps/cli/src/pqcbench_cli/runners/common.py:48`).
2. `_run_isolated` spawns a child via the `multiprocessing` `spawn` context and
   hands it `_isolated_worker` (`common.py:12,94`).
3. `_isolated_worker` invokes `_single_run_metrics`, records timing/memory, sends
   the result back through a pipe, and exits (`common.py:118-195`).
4. Process termination releases every byte touched during the trial; the next
   iteration starts from a cold cache.

## Memory Sampling Inside the Child

- A `gc.collect()` precedes sampling to stabilise the heap.
- Baseline RSS (USS when available) comes from `psutil` (`common.py:145`).
- `tracemalloc` starts before the operation and stops after completion to capture
  the peak Python heap (`common.py:164`).
- The reported memory figure is `max(RSS delta, tracemalloc peak)` measured in KB
  (`common.py:176-195`).

## State Reset Between Trials

- `_MP_CONTEXT = multiprocessing.get_context('spawn')` guarantees a brand-new
  interpreter per run (`common.py:12`).
- Stateless helpers such as `_kem_keygen_factory` and `_sig_sign_factory`
  construct inputs within the child (`common.py:680-770`).
- When the child exits, OS-level cleanup ensures caches and pools do not persist.

## Key Takeaways

- Trials are fully isolated; no warm caches bleed across iterations.
- Memory usage reflects the maximum footprint observed for the measured
  operation only.
- Automatic cleanup via process exit provides fair, repeatable measurements.
