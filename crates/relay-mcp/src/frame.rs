//! Newline-delimited JSON frame parsing with bounded buffering.

use relay_domain::ProtocolError;

/// Maximum allowed MCP stdio frame size (4 MiB).
pub const MAX_FRAME_SIZE_BYTES: usize = 4 * 1024 * 1024;

/// A single complete protocol frame (one JSON-RPC message line, without the trailing newline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame(Vec<u8>);

impl RawFrame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Incremental parser for newline-delimited JSON-RPC frames.
#[derive(Debug, Clone)]
pub struct FrameBuffer {
    pending: Vec<u8>,
    max_frame_bytes: usize,
}

impl FrameBuffer {
    pub fn new(max_frame_bytes: usize) -> Self {
        Self {
            pending: Vec::new(),
            max_frame_bytes,
        }
    }

    pub fn with_default_limit() -> Self {
        Self::new(MAX_FRAME_SIZE_BYTES)
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    /// Append bytes read from the transport and extract any complete frames.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<RawFrame>, ProtocolError> {
        if self.pending.len() + chunk.len() > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                size_bytes: self.pending.len() + chunk.len(),
                max_bytes: self.max_frame_bytes,
            });
        }

        self.pending.extend_from_slice(chunk);
        self.drain_complete_frames()
    }

    fn drain_complete_frames(&mut self) -> Result<Vec<RawFrame>, ProtocolError> {
        let mut frames = Vec::new();

        while let Some(newline_idx) = self.pending.iter().position(|&b| b == b'\n') {
            let mut line = self.pending.drain(..=newline_idx).collect::<Vec<_>>();
            line.pop();
            while line.last() == Some(&b'\r') {
                line.pop();
            }

            if line.is_empty() {
                continue;
            }

            if line.len() > self.max_frame_bytes {
                return Err(ProtocolError::FrameTooLarge {
                    size_bytes: line.len(),
                    max_bytes: self.max_frame_bytes,
                });
            }

            frames.push(RawFrame(line));
        }

        if self.pending.len() > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                size_bytes: self.pending.len(),
                max_bytes: self.max_frame_bytes,
            });
        }

        Ok(frames)
    }
}

/// Encode a frame for wire transmission (appends a single trailing newline).
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if payload.len() > MAX_FRAME_SIZE_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            size_bytes: payload.len(),
            max_bytes: MAX_FRAME_SIZE_BYTES,
        });
    }

    let mut out = Vec::with_capacity(payload.len() + 1);
    out.extend_from_slice(payload);
    out.push(b'\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_frame() {
        let mut buf = FrameBuffer::with_default_limit();
        let frames = buf.push(b"{\"jsonrpc\":\"2.0\"}\n").unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].as_bytes(), b"{\"jsonrpc\":\"2.0\"}");
    }

    #[test]
    fn parses_partial_reads() {
        let mut buf = FrameBuffer::with_default_limit();
        assert!(buf.push(b"{\"a\":").unwrap().is_empty());
        assert_eq!(buf.push(b"1}\n").unwrap().len(), 1);
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = FrameBuffer::new(8);
        let err = buf.push(b"012345678\n").unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn rejects_unbounded_pending_buffer() {
        let mut buf = FrameBuffer::new(16);
        let err = buf.push(&[b'x'; 17]).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn strips_trailing_cr() {
        let mut buf = FrameBuffer::with_default_limit();
        let frames = buf.push(b"{\"ok\":true}\r\n").unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].as_bytes(), b"{\"ok\":true}");
    }

    #[test]
    fn skips_empty_lines() {
        let mut buf = FrameBuffer::with_default_limit();
        let frames = buf.push(b"\n\n{\"ok\":true}\n\n").unwrap();
        assert_eq!(frames.len(), 1);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn frame_buffer_never_exceeds_limit(chunk in proptest::collection::vec(any::<u8>(), 0..512)) {
            let max = 64usize;
            let mut buf = FrameBuffer::new(max);
            match buf.push(&chunk) {
                Ok(_) => prop_assert!(buf.pending_len() <= max),
                Err(ProtocolError::FrameTooLarge { .. }) => {},
                Err(other) => prop_assert!(false, "unexpected error: {other}"),
            }
        }

        #[test]
        fn roundtrip_line_splitting(payload in r#"[a-zA-Z0-9_{}\":, -]{0,200}"#) {
            let line = format!("{}\n", payload);
            let mut buf = FrameBuffer::with_default_limit();
            let mut all_frames = Vec::new();

            for byte in line.bytes() {
                all_frames.extend(buf.push(&[byte]).unwrap());
            }

            if !payload.is_empty() {
                prop_assert_eq!(all_frames.len(), 1);
                prop_assert_eq!(all_frames[0].as_bytes(), payload.as_bytes());
            }
        }
    }
}
