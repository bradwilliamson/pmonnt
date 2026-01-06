# pmonnt-core tests

## Fixture-driven tests

Golden JSON fixtures live under `tests/data/` and are loaded with `include_str!()` to keep tests deterministic and offline.

## Privileged Windows smoke tests

Some Windows-only checks require elevated access (e.g., reading certain security/token information).

- Default: privileged checks are skipped.
- Opt-in: set `PMONNT_RUN_PRIV_TESTS=1` when running tests.

Example:

- `PMONNT_RUN_PRIV_TESTS=1 cargo test -p pmonnt-core --test windows_smoke`

## Integration / network tests

Default test runs are intended to be deterministic and offline.

- Opt-in: set `PMONNT_RUN_INTEGRATION_TESTS=1` to allow tests that may talk to live services.

Examples:

- `PMONNT_RUN_INTEGRATION_TESTS=1 cargo test -p pmonnt-core --test malwarebazaar_integration`

Some OS-specific or long-running checks are also marked `#[ignore]` and must be run explicitly:

- `cargo test -p pmonnt-core --test yara_scan_smoke -- --ignored`
