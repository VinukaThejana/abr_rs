use thiserror::Error;

#[derive(Error, Debug)]
pub enum SrtError {
    #[error("packet too small to contain a valid SRT header or payload: {0} bytes")]
    PacketTooSmall(usize),

    #[error("invalid or unknown control packet type: {0:#06x}")]
    InvalidControlType(u16),

    #[error("invalid or unknown handshake type: {0:#010x}")]
    InvalidHandshakeType(u32),

    #[error("sequence number {0} falls outside the valid receive window")]
    SequenceOutOfWindow(u32),

    #[error("malformed payload: {0}")]
    MalformedPayload(String),

    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),
}
