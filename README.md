# Unbounded allocation and blocking read loop in VectorSetRdbLoad via RESTORE

## Affected product

Redis 8.4.x, 8.6.x, 8.8.x and 8.10.1, including the built-in Vector Sets
module data type (`vectorset`, compiled into redis-server when Vector Sets
are enabled, which is the default). Verified on Redis 8.10.1 (tag 3399357);
the same code is present on the current `unstable` branch
(`modules/vector-sets/vset.c`, function `VectorSetRdbLoad()`).

## Summary

`VectorSetRdbLoad()` reads a per-node parameter count directly from the RDB
stream and uses it for both the allocation and the read loop without any
upper bound or error check:

```c
uint32_t params_count = RedisModule_LoadUnsigned(rdb);
if (RedisModule_IsIOError(rdb)) { ... goto ioerr; }

uint64_t *params = RedisModule_Alloc(params_count*sizeof(uint64_t));
for (uint32_t j = 0; j < params_count; j++) {
    /* Ignore loading errors here: handled at the end of the loop. */
    params[j] = RedisModule_LoadUnsigned(rdb);
}
```

An attacker who can execute `RESTORE` supplies a dump payload whose node
parameter count is 0xFFFFFFFF. On 64-bit builds this requests a ~34 GB
allocation; with `RedisModule_Alloc()` (zmalloc) a failed allocation is
fatal, so a single unauthenticated command aborts the whole process. If the
allocator instead satisfies the request (permissive overcommit), the main
thread spins through up to 2^32 module reads, stalling the event loop for
all clients. On 32-bit builds `params_count * sizeof(uint64_t)` truncates
to a small allocation and the loop writes far past it, producing heap
corruption.

## Severity

High. CVSS v3.1 base score 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) for
the default 64-bit build: remote, unauthenticated, reliable single-command
process abort (or multi-second event-loop stall when the allocation
succeeds). On 32-bit builds the same input causes a controlled-size heap
out-of-bounds write, raising the practical severity for those deployments.

## Trigger entry

`RESTORE key 0 <payload>`:

`restoreCommand()` (src/cluster.c) -> `verifyDumpPayload()` (version and
CRC64 only; the CRC is recomputed by the attacker) -> `rdbLoadObject()` ->
`moduleTypeLookupModuleByID()` matches the built-in `vectorset` type ->
`VectorSetRdbLoad()`.

`RESTORE` belongs to the default command set, so on a default deployment
(no ACL restrictions) no authentication is required. This attack surface was
previously confirmed by the fix for the RESTORE-related memory access issue
in the same function; the field involved here, its root cause and its fix
location are different.

## Proof of concept

`poc/craft_vectorset_params_payload.py` derives the payload from a
legitimate `DUMP` reply of the same Redis version: it replays the module
serialization to locate the first node's parameter-count field, replaces
the value with 0xFFFFFFFF (`rdbSaveLen` 32-bit form), and recomputes the
CRC64 footer so `verifyDumpPayload()` accepts the payload.

```
redis-cli VADD vset VALUES 2 1.0 2.0 element1
redis-cli --raw DUMP vset | head -c -1 > base_payload.bin
redis-cli DEL vset
python3 poc/craft_vectorset_params_payload.py base_payload.bin payload.bin
redis-server --port 6399 --save '' --appendonly no --daemonize yes
redis-cli -p 6399 -x RESTORE vset 0 < payload.bin
```

(`head -c -1` removes the newline that redis-cli appends in raw mode.)

Result on Redis 8.10.1 production build (-O2, libc allocator, 7.5 GB host,
default overcommit heuristic): the allocation of 34,359,738,360 bytes fails
immediately and the process aborts; the client sees the connection close
about 0.15 s after sending the command.

```
# Out Of Memory allocating 34359738360 bytes!
# Guru Meditation: Redis aborting for OUT OF MEMORY. Allocating 34359738360
# bytes! #server.c:7824
# Redis 8.10.1 crashed by signal: 11, si_code: 1
```

The full crash report is included as `poc/crash-vset-oom.log`. Under a
permissive overcommit policy the same payload instead completes the failed
read loop with the event loop blocked for the duration, after which the
payload is rejected cleanly; both outcomes are a denial of service for all
connected clients.

## Suggested fix

1. Reject implausible counts before allocating, e.g. bound `params_count`
   by the remaining stream length or a fixed constant (a node of dimension
   d needs at most a handful of parameters).
2. Break out of the parameter read loop on IO error instead of spinning to
   the declared count (the surrounding code already documents that loading
   errors are tolerated, but the loop should still terminate).

## Relation to previously published issues

A prior RESTORE-related memory access fix addressed the projection-matrix
field of the same function (size computation, bounds and blob-length
validation). This report concerns the `params_count` field: no bound check
exists, the allocation size is unbounded, and the read loop ignores stream
errors. A separate open issue about RESTORE and duplicate HNSW element IDs
describes a use-after-free on re-insertion, which is likewise a different
defect. Both references are listed only to document that the areas were
checked for overlap; the behavior described here is not covered by either.
