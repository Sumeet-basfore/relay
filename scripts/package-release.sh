#!/usr/bin/env bash
# Relay Release Packaging Automation Script
# Generates release tarballs and SHA256SUMS manifests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="${VERSION:-$(grep '^version = ' "${ROOT_DIR}/Cargo.toml" | head -n1 | cut -d '"' -f2)}"
TARGET="${TARGET:-$(rustc -vV | grep 'host:' | cut -d ' ' -f2)}"
DIST_DIR="${ROOT_DIR}/dist"
RELEASE_DIR="${ROOT_DIR}/target/${TARGET}/release"
if [ ! -d "${RELEASE_DIR}" ]; then
    RELEASE_DIR="${ROOT_DIR}/target/release"
fi

echo "=== Packaging Relay Release ==="
echo "Version: ${VERSION}"
echo "Target:  ${TARGET}"
echo "Source:  ${RELEASE_DIR}"
echo "Output:  ${DIST_DIR}"

# Build release binary if not present
if [ ! -f "${RELEASE_DIR}/relay" ]; then
    echo "Building release binary for ${TARGET}..."
    cargo build --release --bin relay
fi

mkdir -p "${DIST_DIR}"

ARCHIVE_NAME="relay-v${VERSION}-${TARGET}"
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGING_DIR}"' EXIT

PKG_DIR="${STAGING_DIR}/${ARCHIVE_NAME}"
mkdir -p "${PKG_DIR}"

# Copy binary and assets
cp "${RELEASE_DIR}/relay" "${PKG_DIR}/"
chmod 0755 "${PKG_DIR}/relay"

if [ -f "${ROOT_DIR}/README.md" ]; then
    cp "${ROOT_DIR}/README.md" "${PKG_DIR}/"
fi

if [ -f "${ROOT_DIR}/deny.toml" ]; then
    cp "${ROOT_DIR}/deny.toml" "${PKG_DIR}/"
fi

# Copy default policies if present
if [ -d "${ROOT_DIR}/policies" ]; then
    cp -r "${ROOT_DIR}/policies" "${PKG_DIR}/"
fi

# Create tarball (.tar.gz)
TARBALL="${DIST_DIR}/${ARCHIVE_NAME}.tar.gz"
tar -czf "${TARBALL}" -C "${STAGING_DIR}" "${ARCHIVE_NAME}"
echo "Created archive: ${TARBALL}"

# Generate SHA256SUMS
cd "${DIST_DIR}"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${ARCHIVE_NAME}.tar.gz" > "${ARCHIVE_NAME}.tar.gz.sha256"
    sha256sum *.tar.gz > SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${ARCHIVE_NAME}.tar.gz" > "${ARCHIVE_NAME}.tar.gz.sha256"
    shasum -a 256 *.tar.gz > SHA256SUMS
fi

echo "=== Release Packaging Complete ==="
echo "Artifacts generated in ${DIST_DIR}:"
ls -la "${DIST_DIR}"
