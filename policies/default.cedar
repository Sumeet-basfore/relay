// Default Cedar Policies for Relay MVP
// Enforces:
// 1. Permitted safe filesystem reads
// 2. Explicit forbid on sensitive secrets/credentials (.env, private keys, AWS creds)
// 3. Destructive actions require step-up operator approval
// 4. Governed GitHub and PostgreSQL queries
// 5. Strict default-deny for all unmentioned actions

// 1. Filesystem: Permit read operations on general files
@id("permit_fs_reads")
permit (
    principal,
    action in [Relay::Action::"fs.read", Relay::Action::"fs.read_file"],
    resource
);

// 2. Filesystem: Explicitly FORBID reading sensitive configuration and credential files
@id("forbid_sensitive_files")
forbid (
    principal,
    action in [
        Relay::Action::"fs.read",
        Relay::Action::"fs.read_file",
        Relay::Action::"fs.write",
        Relay::Action::"fs.write_file"
    ],
    resource
)
when {
    context has path && (
        context.path like "*/.env*" ||
        context.path like "*/id_rsa*" ||
        context.path like "*/id_ed25519*" ||
        context.path like "*/.aws/*" ||
        context.path like "*/.ssh/*" ||
        context.path like "*/node.key"
    )
};

// 3. Filesystem: File deletions require interactive operator approval
@id("require_approval_fs_delete")
@advice("REQUIRE_HUMAN_APPROVAL")
@approval_required("Interactive operator approval required for file deletion")
permit (
    principal,
    action in [Relay::Action::"fs.delete", Relay::Action::"fs.delete_file"],
    resource
);

// 4. Filesystem: File writes in workspace
@id("permit_fs_writes")
permit (
    principal,
    action in [Relay::Action::"fs.write", Relay::Action::"fs.write_file"],
    resource
);

// 5. GitHub: Permit read-only repository access
@id("permit_github_reads")
permit (
    principal,
    action in [
        Relay::Action::"github.read",
        Relay::Action::"github.get_repository",
        Relay::Action::"github.get_pull_request",
        Relay::Action::"github.get_issue",
        Relay::Action::"github.get_branch"
    ],
    resource
);

// 6. GitHub: Permit governed write operations
@id("permit_github_writes")
permit (
    principal,
    action in [
        Relay::Action::"github.write",
        Relay::Action::"github.create_issue",
        Relay::Action::"github.create_pull_request",
        Relay::Action::"github.create_branch"
    ],
    resource
);

// 6. PostgreSQL: Permit read queries
@id("permit_postgres_reads")
permit (
    principal,
    action in [Relay::Action::"postgres.read", Relay::Action::"postgres.query"],
    resource
);

// 7. PostgreSQL: Absolute forbid on destructive DDL statements
@id("forbid_postgres_ddl")
forbid (
    principal,
    action in [
        Relay::Action::"postgres.ddl",
        Relay::Action::"db.drop_table",
        Relay::Action::"db.truncate_table"
    ],
    resource
)
when {
    context has is_destructive && context.is_destructive == true
};
