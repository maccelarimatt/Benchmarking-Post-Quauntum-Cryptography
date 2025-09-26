Overview
Each micro-benchmark run executes in its own freshly spawned Python process so allocator caches, liboqs buffers, and interpreter state never leak across trials.

Execution Flow

measure dispatches runs to _run_isolated (apps/cli/src/pqcbench_cli/runners/common.py:48).
_run_isolated spins up a child using the multiprocessing spawn context and hands it _isolated_worker (apps/cli/src/pqcbench_cli/runners/common.py:12, :94).
_isolated_worker calls _single_run_metrics, records timing/memory, sends the results through a pipe, then the child exits (apps/cli/src/pqcbench_cli/runners/common.py:118, :134).
Process termination automatically releases every byte the run touched; the next iteration starts from a cold cache.
Memory Sampling in the Child

After gc.collect(), the child samples its unique RSS (USS when available) as a baseline via psutil (apps/cli/src/pqcbench_cli/runners/common.py:145).
tracemalloc starts before the operation and stops afterward to capture the peak Python heap (apps/cli/src/pqcbench_cli/runners/common.py:164).
Once the operation finishes, another RSS sample plus GC yields the delta; the reported memory is max(RSS delta, tracemalloc peak) in KB (apps/cli/src/pqcbench_cli/runners/common.py:176–:195).
State Reset Between Trials

_MP_CONTEXT = multiprocessing.get_context('spawn') forces a brand-new interpreter for every run (apps/cli/src/pqcbench_cli/runners/common.py:12).
Stateless helpers such as _kem_keygen_factory or _sig_sign_factory prepare the operation inside the child (apps/cli/src/pqcbench_cli/runners/common.py:680–:770).
When the child exits, the OS reclaims its entire address space, so no caches or pools survive into the next measurement.
Key Takeaways

Trials are fully isolated; no warm caches.
Memory usage reflects the maximum observed footprint during that run.
Automatic cleanup via process exit guarantees fair, repeatable measurements.
