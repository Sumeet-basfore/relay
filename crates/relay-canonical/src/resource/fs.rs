//! Filesystem path normalization and secure boundary validation.
//!
//! Handles:
//! - Absolute and relative paths
//! - Lexical normalization (resolving `.` and `..` without filesystem calls)
//! - Symlink resolution and escape detection
//! - Dangling symlink detection
//! - Symlink cycle detection
//! - Non-existent path handling via existing ancestor resolution
//! - Platform separator normalization ('\' -> '/')
//! - Sandbox / base directory containment enforcement

use relay_domain::{CanonicalizationError, ResourceUri};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Output of filesystem path normalization
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedPath {
    pub lexical_path: String,
    pub physical_path: Option<String>,
    pub is_existing: bool,
}

impl NormalizedPath {
    /// Returns the authoritative canonical path (physical if resolved, else lexical)
    pub fn canonical_path(&self) -> &str {
        self.physical_path.as_deref().unwrap_or(&self.lexical_path)
    }

    /// Converts normalized path into canonical file:// ResourceUri
    pub fn to_resource_uri(&self) -> Result<ResourceUri, CanonicalizationError> {
        let p = self.canonical_path();
        let formatted = if p.starts_with('/') {
            format!("file://{p}")
        } else {
            format!("file:///{p}")
        };
        ResourceUri::parse(&formatted)
            .map_err(|e| CanonicalizationError::InvalidResource(formatted, e.to_string()))
    }
}

/// Filesystem normalizer with optional base directory containment check
#[derive(Debug, Clone)]
pub struct FilesystemNormalizer {
    base_dir: PathBuf,
    enforce_boundary: bool,
}

impl Default for FilesystemNormalizer {
    fn default() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        Self::new(cwd, false)
    }
}

impl FilesystemNormalizer {
    /// Creates a normalizer with the given base directory
    pub fn new(base_dir: impl AsRef<Path>, enforce_boundary: bool) -> Self {
        let base_dir = base_dir.as_ref().to_path_buf();
        Self {
            base_dir,
            enforce_boundary,
        }
    }

    /// Pure lexical normalization without filesystem I/O
    pub fn normalize_lexical(&self, raw_path: &str) -> Result<PathBuf, CanonicalizationError> {
        if raw_path.contains('\0') {
            return Err(CanonicalizationError::PathError {
                path: raw_path.to_string(),
                reason: "Null bytes not permitted in path".to_string(),
            });
        }

        let trimmed = raw_path.trim();
        if trimmed.is_empty() {
            return Err(CanonicalizationError::PathError {
                path: raw_path.to_string(),
                reason: "Path cannot be empty".to_string(),
            });
        }

        // Standardize separators
        let unified = trimmed.replace('\\', "/");
        let path = Path::new(&unified);

        let combined = if path.is_absolute() {
            PathBuf::from("/")
        } else {
            self.base_dir.clone()
        };

        let mut components = Vec::new();
        for c in combined.components() {
            if let std::path::Component::Normal(p) = c {
                components.push(p.to_string_lossy().to_string());
            }
        }

        for comp in Path::new(&unified).components() {
            match comp {
                std::path::Component::RootDir => {
                    if path.is_absolute() {
                        components.clear();
                    }
                }
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if components.is_empty() {
                        if self.enforce_boundary {
                            return Err(CanonicalizationError::PathTraversal {
                                path: raw_path.to_string(),
                                reason: format!(
                                    "escaped above base directory '{}'",
                                    self.base_dir.display()
                                ),
                            });
                        }
                    } else {
                        components.pop();
                    }
                }
                std::path::Component::Normal(part) => {
                    components.push(part.to_string_lossy().to_string());
                }
                std::path::Component::Prefix(_) => {}
            }
        }

        let mut result = PathBuf::from("/");
        for c in components {
            result.push(c);
        }

        if self.enforce_boundary {
            let base_lexical = self.lexical_clean(&self.base_dir);
            if !result.starts_with(&base_lexical) {
                return Err(CanonicalizationError::PathTraversal {
                    path: raw_path.to_string(),
                    reason: format!(
                        "path does not reside within base directory '{}'",
                        self.base_dir.display()
                    ),
                });
            }
        }

        Ok(result)
    }

    fn lexical_clean(&self, path: &Path) -> PathBuf {
        let mut comps = Vec::new();
        for c in path.components() {
            match c {
                std::path::Component::Normal(p) => comps.push(p.to_string_lossy().to_string()),
                std::path::Component::ParentDir => {
                    comps.pop();
                }
                _ => {}
            }
        }
        let mut res = PathBuf::from("/");
        for c in comps {
            res.push(c);
        }
        res
    }

    /// Full normalization with filesystem resolution, symlink inspection,
    /// dangling symlink detection, and non-existent ancestor resolution.
    pub fn resolve_path(&self, raw_path: &str) -> Result<NormalizedPath, CanonicalizationError> {
        let lexical = self.normalize_lexical(raw_path)?;
        let lexical_str = lexical.to_string_lossy().to_string();

        let base_canonical =
            std::fs::canonicalize(&self.base_dir).unwrap_or_else(|_| self.base_dir.clone());

        // Check if file or symlink exists on disk
        match std::fs::symlink_metadata(&lexical) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    // Path is a symlink: resolve real target
                    match std::fs::canonicalize(&lexical) {
                        Ok(target) => {
                            if self.enforce_boundary && !target.starts_with(&base_canonical) {
                                return Err(CanonicalizationError::PathTraversal {
                                    path: raw_path.to_string(),
                                    reason: format!(
                                        "symlink points to target outside base directory: '{}'",
                                        target.display()
                                    ),
                                });
                            }
                            Ok(NormalizedPath {
                                lexical_path: lexical_str,
                                physical_path: Some(target.to_string_lossy().to_string()),
                                is_existing: true,
                            })
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::NotFound {
                                Err(CanonicalizationError::DanglingSymlink { path: lexical_str })
                            } else if e.raw_os_error() == Some(libc::ELOOP)
                                || format!("{e:?}").contains("loop")
                                || format!("{e:?}").contains("FilesystemLoop")
                            {
                                Err(CanonicalizationError::SymlinkCycle { path: lexical_str })
                            } else {
                                Err(CanonicalizationError::PathError {
                                    path: lexical_str,
                                    reason: e.to_string(),
                                })
                            }
                        }
                    }
                } else {
                    // Regular file or directory exists
                    let canonical = std::fs::canonicalize(&lexical).map_err(|e| {
                        CanonicalizationError::PathError {
                            path: lexical_str.clone(),
                            reason: e.to_string(),
                        }
                    })?;

                    if self.enforce_boundary && !canonical.starts_with(&base_canonical) {
                        return Err(CanonicalizationError::PathTraversal {
                            path: raw_path.to_string(),
                            reason: format!(
                                "canonical path escapes base directory: '{}'",
                                canonical.display()
                            ),
                        });
                    }

                    Ok(NormalizedPath {
                        lexical_path: lexical_str,
                        physical_path: Some(canonical.to_string_lossy().to_string()),
                        is_existing: true,
                    })
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File does not exist yet: find deepest existing ancestor
                let mut current = lexical.as_path();
                let mut suffixes = Vec::new();
                let mut existing_ancestor = None;

                while let Some(parent) = current.parent() {
                    if let Some(file_name) = current.file_name() {
                        suffixes.push(file_name.to_os_string());
                    }
                    if parent.exists() {
                        existing_ancestor = Some(parent.to_path_buf());
                        break;
                    }
                    current = parent;
                }

                if let Some(ancestor) = existing_ancestor {
                    match std::fs::canonicalize(&ancestor) {
                        Ok(canonical_ancestor) => {
                            if self.enforce_boundary
                                && !canonical_ancestor.starts_with(&base_canonical)
                            {
                                return Err(CanonicalizationError::PathTraversal {
                                    path: raw_path.to_string(),
                                    reason: format!(
                                        "ancestor directory escapes base directory: '{}'",
                                        canonical_ancestor.display()
                                    ),
                                });
                            }

                            let mut resolved = canonical_ancestor;
                            for s in suffixes.into_iter().rev() {
                                resolved.push(s);
                            }

                            Ok(NormalizedPath {
                                lexical_path: lexical_str,
                                physical_path: Some(resolved.to_string_lossy().to_string()),
                                is_existing: false,
                            })
                        }
                        Err(e) => {
                            if e.raw_os_error() == Some(libc::ELOOP) {
                                Err(CanonicalizationError::SymlinkCycle {
                                    path: ancestor.to_string_lossy().to_string(),
                                })
                            } else {
                                Err(CanonicalizationError::PathError {
                                    path: ancestor.to_string_lossy().to_string(),
                                    reason: e.to_string(),
                                })
                            }
                        }
                    }
                } else {
                    Ok(NormalizedPath {
                        lexical_path: lexical_str,
                        physical_path: None,
                        is_existing: false,
                    })
                }
            }
            Err(e) => Err(CanonicalizationError::PathError {
                path: lexical_str,
                reason: e.to_string(),
            }),
        }
    }
}
