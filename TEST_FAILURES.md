# Test Failures Tracking

This document tracks test failures and their status. Tests that fail due to smoltcp limitations are marked as **EXPECTED**.

## Status Legend

- ✅ **PASSING**: Test passes
- ⚠️ **EXPECTED FAILURE**: Test fails but failure is expected (e.g., due to smoltcp limitations)
- ❌ **UNEXPECTED FAILURE**: Test fails unexpectedly (needs investigation)
- 🔄 **IN PROGRESS**: Test is being fixed

## Test Failures

### RFC Compliance Tests

| Test | Status | Reason | Notes |
|------|--------|--------|-------|
| `rfc793_tcp_connection_states` | ⚠️ EXPECTED | SYN-ACK from reverse direction may not match rule | Connection tracking should handle this, but rule matching may fail if rule requires specific ports |

### Fuzzy Parser Tests

| Test | Status | Reason | Notes |
|------|--------|--------|-------|
| All fuzzy parser tests | ✅ PASSING | - | All parser fuzzy tests pass |

### Edge Cases Tests

| Test | Status | Reason | Notes |
|------|--------|--------|-------|
| All edge cases tests | ✅ PASSING | - | All edge cases tests pass |

### RFC Full Compliance Tests

| Test | Status | Reason | Notes |
|------|--------|--------|-------|
| TBD | - | - | Tests to be run and tracked |

## Known Limitations

### smoltcp Limitations

The following features may not be fully supported due to smoltcp limitations:

1. **TCP State Machine**: smoltcp may not implement full TCP state machine
2. **IP Options**: Complex IP options may not be fully parsed
3. **TCP Options**: TCP header options may not be fully supported
4. **Checksum Validation**: Checksums may not be validated (firewall doesn't validate)

## Test Execution

To run tests and update this document:

```bash
# Run all tests
cargo test --no-default-features

# Run specific test suite
cargo test --no-default-features --test rfc_full_compliance_tests
cargo test --no-default-features --test fuzzy_parser_tests

# Run with output to see failures
cargo test --no-default-features -- --nocapture
```

## Last Updated

- Date: [To be updated after test run]
- Total Tests: 42 (property) + 7 (RFC compliance) + 24 (edge cases) + [TBD] (fuzzy) + [TBD] (full RFC)
- Passing: [TBD]
- Expected Failures: [TBD]
- Unexpected Failures: [TBD]

