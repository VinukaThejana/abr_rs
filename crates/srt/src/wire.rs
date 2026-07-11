use crate::SrtError;
use std::marker::PhantomData;

pub(crate) type BeReader<'a> = BufferReader<'a, BigEndian>;
pub(crate) type BeWriter<'a> = BufferWriter<'a, BigEndian>;
pub(crate) type LeReader<'a> = BufferReader<'a, LittleEndian>;
pub(crate) type LeWriter<'a> = BufferWriter<'a, LittleEndian>;

/// Byte order. Implemented by `BigEndian` and `LittleEndian`
pub(crate) trait Endianness {
    fn read_u16(bytes: [u8; 2]) -> u16;
    fn read_u32(bytes: [u8; 4]) -> u32;
    fn write_u16(value: u16) -> [u8; 2];
    fn write_u32(value: u32) -> [u8; 4];
}

/// Network byte order (big-endian), used by majority of SRT fields
pub(crate) struct BigEndian;

/// Little-endian (little-endian), used by some SRT fields (e.g. `SRT_MSGCTRL`)
pub(crate) struct LittleEndian;

impl Endianness for BigEndian {
    fn read_u16(bytes: [u8; 2]) -> u16 {
        u16::from_be_bytes(bytes)
    }

    fn read_u32(bytes: [u8; 4]) -> u32 {
        u32::from_be_bytes(bytes)
    }

    fn write_u16(value: u16) -> [u8; 2] {
        value.to_be_bytes()
    }

    fn write_u32(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }
}

impl Endianness for LittleEndian {
    fn read_u16(bytes: [u8; 2]) -> u16 {
        u16::from_le_bytes(bytes)
    }

    fn read_u32(bytes: [u8; 4]) -> u32 {
        u32::from_le_bytes(bytes)
    }

    fn write_u16(value: u16) -> [u8; 2] {
        value.to_le_bytes()
    }

    fn write_u32(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }
}

pub(crate) struct BufferReader<'a, E: Endianness> {
    buffer: &'a [u8],
    position: usize,
    _endian: PhantomData<E>,
}

impl<'a, E: Endianness> BufferReader<'a, E> {
    pub(crate) fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            position: 0,
            _endian: PhantomData,
        }
    }

    /// Reads a u16 from the buffer using the endianness specified by the type parameter `E`.
    pub(crate) fn read_u16(&mut self) -> Result<u16, SrtError> {
        self.read_u16_as::<E>()
    }

    /// Reads a u32 from the buffer using the endianness specified by the type parameter `E`.
    pub(crate) fn read_u32(&mut self) -> Result<u32, SrtError> {
        self.read_u32_as::<E>()
    }

    /// Reads a u16 from the buffer using the explicitly specified endianness.
    /// Advances the position by 2 bytes.
    pub(crate) fn read_u16_as<Other: Endianness>(&mut self) -> Result<u16, SrtError> {
        let end = self.position + 2;
        let slice = self
            .buffer
            .get(self.position..end)
            .ok_or(SrtError::PacketTooSmall(self.buffer.len()))?;
        let bytes: [u8; 2] = slice.try_into().unwrap();
        self.position = end;
        Ok(Other::read_u16(bytes))
    }

    /// Reads a u32 from the buffer using the explicitly specified endianness.
    /// Advances the position by 4 bytes.
    pub(crate) fn read_u32_as<Other: Endianness>(&mut self) -> Result<u32, SrtError> {
        let end = self.position + 4;
        let slice = self
            .buffer
            .get(self.position..end)
            .ok_or(SrtError::PacketTooSmall(self.buffer.len()))?;
        let bytes: [u8; 4] = slice.try_into().unwrap();
        self.position = end;
        Ok(Other::read_u32(bytes))
    }

    /// Raw aw bytes are copied as-is, no reinterpretation
    pub(crate) fn read_slice<const N: usize>(&mut self) -> Result<[u8; N], SrtError> {
        let end = self.position + N;
        let slice = self
            .buffer
            .get(self.position..end)
            .ok_or(SrtError::PacketTooSmall(self.buffer.len()))?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        self.position = end;
        Ok(out)
    }

    /// Current cursor position, in bytes from the start of the buffer
    pub(crate) fn current_position(&self) -> usize {
        self.position
    }

    /// Remaining bytes in thge buffer that have not yet been read, in bytes
    pub(crate) fn remaining_bytes(&self) -> usize {
        self.buffer.len() - self.position
    }
}

pub(crate) struct BufferWriter<'a, E: Endianness> {
    buffer: &'a mut [u8],
    position: usize,
    _endian: PhantomData<E>,
}

impl<'a, E: Endianness> BufferWriter<'a, E> {
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            position: 0,
            _endian: PhantomData,
        }
    }

    /// Writes a u16 to the buffer using the endianness specified by the type parameter `E`.
    pub(crate) fn write_u16(&mut self, value: u16) {
        self.write_u16_as::<E>(value);
    }

    /// Writes a u32 to the buffer using the endianness specified by the type parameter `E`.
    pub(crate) fn write_u32(&mut self, value: u32) {
        self.write_u32_as::<E>(value);
    }

    /// Wrties a u16 to the buffer using the explicitly specified endianness.
    /// Advances the position by 2 bytes.
    pub(crate) fn write_u16_as<Other: Endianness>(&mut self, value: u16) {
        self.buffer[self.position..self.position + 2].copy_from_slice(&Other::write_u16(value));
        self.position += 2;
    }

    /// Wrties a u32 to the buffer using the explicitly specified endianness.
    /// Advances the position by 4 bytes.
    pub(crate) fn write_u32_as<Other: Endianness>(&mut self, value: u32) {
        self.buffer[self.position..self.position + 4].copy_from_slice(&Other::write_u32(value));
        self.position += 4;
    }

    /// Writes a slice of bytes to the buffer as-is, no reinterpretation
    pub(crate) fn write_slice(&mut self, value: &[u8]) {
        let len = value.len();
        self.buffer[self.position..self.position + len].copy_from_slice(value);
        self.position += len;
    }

    /// Current cursor position, in bytes from the start of the buffer
    pub(crate) fn current_position(&self) -> usize {
        self.position
    }
}
