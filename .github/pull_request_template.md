## Summary of Changes

A concise description of the problem solved and the implementation approach.

## Security & Invariant Impact

- [ ] Does this PR modify any security-critical paths (policy evaluation, credential leasing, egress proxy, or receipt signing)?
- [ ] If yes, which Security Invariants (SI-001 through SI-024) are affected, and how are they maintained?
- [ ] Are all errors handled via fail-closed pipelines?

## Verification & Testing

- [ ] Unit tests added / updated
- [ ] Integration tests added / updated
- [ ] `cargo test --workspace --all-targets` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] `cargo deny check` passes

## Related Issues

Closes #
