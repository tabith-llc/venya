# venya_filter.c Performance

## System

| Component | Specification |
|-----------|--------------|
| CPU | AMD Ryzen 7 7735HS with Radeon Graphics |
| Cores / Threads | 8 cores / 16 threads |
| Architecture | x86_64 (Linux 6.12.100+deb13) |
| Memory | 19 GB RAM |

## Hash Computation

`compute_detection_hashes()` — SHA-256 of raw, base64, hex, (optionally trimmed) variants.

| Secret Size | Time per Call |
|-------------|--------------|
| 16 bytes | 0.0013 ms |
| 32 bytes | 0.0013 ms |
| 64 bytes | 0.0014 ms |
| 128 bytes | 0.0016 ms |

~1.3 microseconds per secret, independent of encoding variants.

## Output Filtering Throughput

`filter_output()` — sliding-window content hash matching against a registry of secrets.

### Single secret, embedded at middle of output

| Output Size | Avg Time | Throughput |
|-------------|----------|------------|
| 1 KB | 0.10 ms | 10.2 MB/s |
| 8 KB | 0.71 ms | 11.0 MB/s |
| 64 KB | 5.78 ms | 10.8 MB/s |
| 256 KB | 23.04 ms | 10.9 MB/s |
| 512 KB | 45.51 ms | 11.0 MB/s |
| 1 MB | 93.34 ms | 10.7 MB/s |
| 5 MB | 462.88 ms | 10.8 MB/s |

Throughput is stable at **~11 MB/s** across all sizes. Linear scaling with input size.

### Secret position (256 KB output, one secret)

| Position | Avg Time | Throughput |
|----------|----------|------------|
| Start | 22.47 ms | 11.1 MB/s |
| Middle | 23.04 ms | 10.9 MB/s |
| End | 22.59 ms | 11.1 MB/s |

Position has negligible impact on performance.

### No match (clean output)

| Output Size | Avg Time | Throughput |
|-------------|----------|------------|
| 256 KB | 21.98 ms | 11.4 MB/s |

Clean output is ~5% faster than output with a secret (no replacements needed).

### Random binary input

| Output Size | Avg Time | Throughput |
|-------------|----------|------------|
| 256 KB | 31.04 ms | 8.1 MB/s |

Random binary is slower — the first-byte index and FNV pre-filter skip fewer positions when input has uniform byte distribution.

### Small output (typical command output)

| Output Size | Avg Time | Throughput |
|-------------|----------|------------|
| 45 bytes | 0.01 ms (per call, 5000 iters) | 4.2 MB/s |

Fixed overhead dominates for small outputs. Absolute latency is ~10 microseconds.

### Multiple secrets

| Secrets | Output Size | Avg Time | Throughput |
|---------|-------------|----------|------------|
| 1 | 256 KB | 23.04 ms | 10.9 MB/s |
| 2 | 256 KB | 38.61 ms | 6.5 MB/s |
| 50 | 256 KB | 1.69 ms | 148.1 MB/s |

With 50 secrets, throughput spikes because the FNV pre-filter finds matches much more frequently, causing earlier window skips. The reported MB/s is inflated because matched regions are replaced and skipped. Actual hash computation cost scales with number of secrets × input size scanned.

### All encoding variants in output

| Output | Avg Time | Throughput |
|--------|----------|------------|
| 138 bytes (raw + base64 + hex of same secret) | 0.02 ms | 6.0 MB/s |

## Full Pipeline (hash computation + filtering)

Measures `compute_detection_hashes()` + `filter_output()` together (as used by the executor).

| Output Size | Avg Time | Throughput |
|-------------|----------|------------|
| 256 KB | 15.93 ms | 15.7 MB/s |
| 1 MB | 64.11 ms | 15.6 MB/s |

Pipeline throughput is ~15.6 MB/s. Hash computation adds ~25% overhead to filtering alone.

## Plan Targets vs Measured

| Metric | Plan Target | Measured | Status |
|--------|-------------|----------|--------|
| Latency | < 10ms/MB (= 2.56ms for 256KB) | 23.04ms for 256KB | ~9x slower |
| Throughput | > 85 MB/s | 10.9 MB/s | ~8x slower |
| CPU overhead | < 5% | N/A | N/A |

The measured throughput is ~11 MB/s vs the plan target of 85+ MB/s. The bottleneck is the incremental SHA-256 computation in the sliding window loop — each candidate position requires a full `EVP_DigestFinal_ex` call to verify the FNV-1a pre-filter match.

## Optimization Notes

The C extension uses a 3-stage cascade:
1. **First-byte index** — skips positions where the first byte has no matching secrets
2. **FNV-1a pre-filter** — fast 32-bit hash check before SHA-256
3. **SHA-256 verification** — OpenSSL EVP incremental digest

To reach the plan target, the SHA-256 verification step needs to be optimized. Possible approaches:
- Batch SHA-256 computations (process multiple positions per EVP call)
- Use a faster hash for the final verification (e.g., SipHash) while keeping FNV-1a as the pre-filter
- Reduce the number of SHA-256 calls by improving the FNV-1a selectivity (larger table, better collision handling)
