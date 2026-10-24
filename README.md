# TraceGate

Check test artifacts for credential exposure before uploading them.

A Python 3.9+ CLI with zero runtime dependencies. Inspects ZIP members in memory, JSON/JSONL reports, and UTF-8 text. Does not modify artifacts, call external services, extract archives to disk, or print matched secret values and filenames.

## Quick Start

```sh
# Inspect an artifact
python3 -m tracegate path/to/trace.zip

# Output structured JSON report
python3 -m tracegate path/to/trace.zip --format json

# Check for known test credentials via environment variable names (values never passed as args)
python3 -m tracegate path/to/trace.zip --secret-env TEST_PASSWORD --format json
```

Install locally:

```sh
pip install .
```

## What It Checks

- **Structured Credential Fields**: Populated `password`, `authorization`, `token`, `apiKey`, and secret fields in JSON objects.
- **HAR Headers & Cookies**: Authorization headers and populated cookie values in network logs.
- **Token & Key Patterns**: Bearer tokens and private key headers (`-----BEGIN ... KEY-----`) in text.
- **Known Secrets**: Exact strings matching environment secrets passed via `--secret-env`, including JSON-escaped and URL-encoded variants.

## Exit Codes & CI Integration

| Exit Code | Status | Meaning |
|:---:|:---|:---|
| `0` | Clean | No findings in inspected scope. |
| `1` | Findings | Potential credentials detected; block upload. |
| `2` | Incomplete / Error | Scan could not complete (corrupt zip, size limit exceeded); fails closed. |

In CI workflows, place `tracegate` immediately before your artifact upload step:

```yaml
- name: Scan test trace for secrets
  run: python3 -m tracegate test-results/trace.zip --format json

- name: Upload test artifacts
  if: success()
  uses: actions/upload-artifact@v4
  with:
    name: test-trace
    path: test-results/trace.zip
```

Use `--text-only` if an artifact contains binary media (images, videos) that should be skipped while logging them in the report.

## Reporting & Privacy Guarantees

To prevent accidental leakage in CI console logs:
- **Zero-Value Disclosure**: Matched values, keys, and filenames are never printed in terminal output or reports.
- **Ordinal Referencing**: Members are identified by their 1-based ZIP central-directory index (standalone files use member `0`).
- **Exact Line References**: JSONL entries report exact line numbers; single JSON files report line 1.

## Scope & Resource Limits

`tracegate` is designed as a fast pre-upload boundary check with safety constraints:
- **Per-member size limit**: 8 MiB (decompressed)
- **Total expanded size limit**: 64 MiB
- **Max archive members**: 2,000

If any limit is exceeded, the tool halts and exits with code `2` (fail-closed) to prevent unbounded memory usage or zip bombs.

## Architecture

- `tracegate/scan.py`: In-memory archive inspection, text scanners, rule matchers, and coverage accounting.
- `tracegate/cli.py`: CLI arguments, environment variable resolution, output formatting, and exit codes.
- `tests/test_scan.py`: Test suite covering detection rules, limits, traversal guards, and exit policies.

## Testing

```sh
python3 -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).
