// =============================================================================
// Relay Golden Reference Cedar Policies (Demo Environment)
// =============================================================================

// 1. Permitted Filesystem Read (Public files)
@id("permit_public_fs_read")
permit (
    principal,
    action in [Relay::Action::"fs.read", Relay::Action::"fs.read_file"],
    resource
)
when {
    context has path && (
        context.path like "*/public.txt" ||
        context.path like "*/output/*"
    )
};

// 2. Permitted Filesystem Write (Scoped output directory only)
@id("permit_scoped_fs_write")
permit (
    principal,
    action in [Relay::Action::"fs.write", Relay::Action::"fs.write_file"],
    resource
)
when {
    context has path && context.path like "*/output/*"
};

// 3. Human Approval Step-Up for Filesystem Delete
@id("require_approval_fs_delete")
@advice("REQUIRE_HUMAN_APPROVAL")
@approval_required("Interactive operator approval required to delete files in demo environment")
permit (
    principal,
    action in [Relay::Action::"fs.delete", Relay::Action::"fs.delete_file"],
    resource
)
when {
    context has path && context.path like "*/output/*"
};

// 4. Strict Forbid on Protected Assets & Credentials
@id("forbid_protected_assets")
forbid (
    principal,
    action in [
        Relay::Action::"fs.read",
        Relay::Action::"fs.read_file",
        Relay::Action::"fs.write",
        Relay::Action::"fs.write_file",
        Relay::Action::"fs.delete",
        Relay::Action::"fs.delete_file"
    ],
    resource
)
when {
    context has path && (
        context.path like "*/protected.txt" ||
        context.path like "*/.env*" ||
        context.path like "*/id_rsa*" ||
        context.path like "*/id_ed25519*" ||
        context.path like "*/.ssh/*"
    )
};

// 5. Permitted PostgreSQL Read (Scoped demo tables)
@id("permit_postgres_demo_read")
permit (
    principal,
    action in [Relay::Action::"postgres.read", Relay::Action::"postgres.query"],
    resource
);

// 6. Strict Forbid on Destructive DDL Queries
@id("forbid_postgres_ddl")
forbid (
    principal,
    action in [
        Relay::Action::"postgres.ddl",
        Relay::Action::"db.drop_table",
        Relay::Action::"db.truncate_table"
    ],
    resource
);

// 7. External MCP Egress Destination Authorization (Approved external API)
@id("permit_approved_external_egress")
permit (
    principal,
    action in [Relay::Action::"mcp.http_request", Relay::Action::"mcp.external_egress"],
    resource
)
when {
    context has host && (
        context.host == "api.example.com" ||
        context.host == "httpbin.org"
    )
};

// 8. Strict Forbid on Private Network and Cloud Metadata Destinations (SI-022)
@id("forbid_private_and_metadata_egress")
forbid (
    principal,
    action in [Relay::Action::"mcp.http_request", Relay::Action::"mcp.external_egress"],
    resource
)
when {
    context has host && (
        context.host == "169.254.169.254" ||
        context.host == "fd00:ec2::254" ||
        context.host == "127.0.0.1" ||
        context.host == "localhost" ||
        context.host like "10.*" ||
        context.host like "192.168.*" ||
        context.host like "172.16.*" ||
        context.host like "*.internal"
    )
};
