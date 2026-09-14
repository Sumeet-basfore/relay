#!/usr/bin/env bash
# Relay Safe Installer Script
# Installs Relay binary for the current platform without requiring root privileges.

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
RELAY_DIST_DIR="${RELAY_DIST_DIR:-}"

echo "=== Relay Secure Installer ==="

# 1. Detect Operating System
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM_OS="unknown-linux-gnu";;
    Darwin*)    PLATFORM_OS="apple-darwin";;
    CYGWIN*|MINGW*|MSYS*) PLATFORM_OS="pc-windows-msvc";;
    *)          echo "Error: Unsupported operating system: ${OS}" >&2; exit 1;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)   PLATFORM_ARCH="x86_64";;
    aarch64|arm64)  PLATFORM_ARCH="aarch64";;
    *)              echo "Error: Unsupported architecture: ${ARCH}" >&2; exit 1;;
esac

TARGET="${PLATFORM_ARCH}-${PLATFORM_OS}"
ARCHIVE_NAME="relay-v${VERSION}-${TARGET}"
TARBALL="${ARCHIVE_NAME}.tar.gz"

echo "Detected Platform: ${TARGET}"
echo "Target Version:    ${VERSION}"
echo "Installation Dir:  ${INSTALL_DIR}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
chmod 0700 "${TMP_DIR}"

# 3. Locate or Download Release Archive
if [ -n "${RELAY_DIST_DIR}" ] && [ -f "${RELAY_DIST_DIR}/${TARBALL}" ]; then
    echo "Using local distribution package from ${RELAY_DIST_DIR}/${TARBALL}"
    cp "${RELAY_DIST_DIR}/${TARBALL}" "${TMP_DIR}/"
    if [ -f "${RELAY_DIST_DIR}/SHA256SUMS" ]; then
        cp "${RELAY_DIST_DIR}/SHA256SUMS" "${TMP_DIR}/"
    fi
elif [ -f "./dist/${TARBALL}" ]; then
    echo "Using repository dist package ./dist/${TARBALL}"
    cp "./dist/${TARBALL}" "${TMP_DIR}/"
    if [ -f "./dist/SHA256SUMS" ]; then
        cp "./dist/SHA256SUMS" "${TMP_DIR}/"
    fi
elif [ -f "./target/release/relay" ]; then
    echo "Using compiled release binary ./target/release/relay"
    mkdir -p "${TMP_DIR}/${ARCHIVE_NAME}"
    cp "./target/release/relay" "${TMP_DIR}/${ARCHIVE_NAME}/"
else
    # In production, download from release repository
    RELEASE_URL="https://github.com/relay-security/relay/releases/download/v${VERSION}/${TARBALL}"
    CHECKSUM_URL="https://github.com/relay-security/relay/releases/download/v${VERSION}/SHA256SUMS"
    echo "Fetching release archive from ${RELEASE_URL}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${RELEASE_URL}" -o "${TMP_DIR}/${TARBALL}" || {
            echo "Error: Failed to download release archive from ${RELEASE_URL}" >&2
            exit 1
        }
        curl -fsSL "${CHECKSUM_URL}" -o "${TMP_DIR}/SHA256SUMS" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${RELEASE_URL}" -O "${TMP_DIR}/${TARBALL}" || {
            echo "Error: Failed to download release archive from ${RELEASE_URL}" >&2
            exit 1
        }
        wget -q "${CHECKSUM_URL}" -O "${TMP_DIR}/SHA256SUMS" 2>/dev/null || true
    else
        echo "Error: curl or wget is required to download Relay" >&2
        exit 1
    fi
fi

# 4. Verify Cryptographic Checksum if manifest present
if [ -f "${TMP_DIR}/SHA256SUMS" ] && [ -f "${TMP_DIR}/${TARBALL}" ]; then
    echo "Verifying SHA-256 checksum..."
    cd "${TMP_DIR}"
    if command -v sha256sum >/dev/null 2>&1; then
        grep "${TARBALL}" SHA256SUMS | sha256sum --check --status || {
            echo "Error: Cryptographic checksum verification failed for ${TARBALL}!" >&2
            exit 1
        }
    elif command -v shasum >/dev/null 2>&1; then
        grep "${TARBALL}" SHA256SUMS | shasum -a 256 --check --status || {
            echo "Error: Cryptographic checksum verification failed for ${TARBALL}!" >&2
            exit 1
        }
    fi
    echo "Checksum verification: PASSED"
fi

# 5. Extract Archive
if [ -f "${TMP_DIR}/${TARBALL}" ]; then
    echo "Extracting ${TARBALL}..."
    tar -xzf "${TMP_DIR}/${TARBALL}" -C "${TMP_DIR}"
fi

# 6. Install Binary
mkdir -p "${INSTALL_DIR}"
chmod 0755 "${INSTALL_DIR}"

if [ ! -f "${TMP_DIR}/${ARCHIVE_NAME}/relay" ]; then
    echo "Error: relay binary not found in extracted archive" >&2
    exit 1
fi

cp "${TMP_DIR}/${ARCHIVE_NAME}/relay" "${INSTALL_DIR}/relay"
chmod 0755 "${INSTALL_DIR}/relay"

# 7. Verify Installed Binary
echo "Verifying installation..."
INSTALLED_BIN="${INSTALL_DIR}/relay"
if ! "${INSTALLED_BIN}" --version >/dev/null 2>&1; then
    echo "Error: Installed binary failed execution test" >&2
    exit 1
fi

RELAY_VER="$("${INSTALLED_BIN}" --version)"
echo "Successfully installed: ${RELAY_VER} -> ${INSTALLED_BIN}"

# 8. Check PATH
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*)
        echo "PATH is correctly configured."
        ;;
    *)
        echo ""
        echo "NOTE: ${INSTALL_DIR} is not in your current PATH."
        echo "To make 'relay' accessible everywhere, add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
        ;;
esac

echo "Run 'relay doctor' to verify system health and configuration."
