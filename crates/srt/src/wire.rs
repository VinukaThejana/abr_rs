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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn be_reader_read_u16() {
        let buf = [0x01, 0x02];
        let mut r = BeReader::new(&buf);
        assert_eq!(r.read_u16().unwrap(), 0x0102);
        assert_eq!(r.current_position(), 2);
    }

    #[test]
    fn be_reader_read_u32() {
        let buf = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut r = BeReader::new(&buf);
        assert_eq!(r.read_u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.current_position(), 4);
    }

    #[test]
    fn be_writer_write_u16() {
        let mut buf = [0u8; 2];
        {
            let mut w = BeWriter::new(&mut buf);
            w.write_u16(0x0102);
            assert_eq!(w.current_position(), 2);
        }
        assert_eq!(buf, [0x01, 0x02]);
    }

    #[test]
    fn be_writer_write_u32() {
        let mut buf = [0u8; 4];
        {
            let mut w = BeWriter::new(&mut buf);
            w.write_u32(0xDEAD_BEEF);
            assert_eq!(w.current_position(), 4);
        }
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn le_reader_read_u16() {
        let buf = [0x02, 0x01];
        let mut r = LeReader::new(&buf);
        assert_eq!(r.read_u16().unwrap(), 0x0102);
    }

    #[test]
    fn le_reader_read_u32() {
        let buf = [0xEF, 0xBE, 0xAD, 0xDE];
        let mut r = LeReader::new(&buf);
        assert_eq!(r.read_u32().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn le_writer_write_u16() {
        let mut buf = [0u8; 2];
        let mut w = LeWriter::new(&mut buf);
        w.write_u16(0x0102);
        assert_eq!(buf, [0x02, 0x01]);
    }

    #[test]
    fn le_writer_write_u32() {
        let mut buf = [0u8; 4];
        let mut w = LeWriter::new(&mut buf);
        w.write_u32(0xDEAD_BEEF);
        assert_eq!(buf, [0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn be_reader_read_u16_as_le() {
        let buf = [0x02, 0x01];
        let mut r = BeReader::new(&buf);
        assert_eq!(r.read_u16_as::<LittleEndian>().unwrap(), 0x0102);
    }

    #[test]
    fn be_reader_read_u32_as_le() {
        let buf = [0xEF, 0xBE, 0xAD, 0xDE];
        let mut r = BeReader::new(&buf);
        assert_eq!(r.read_u32_as::<LittleEndian>().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn be_writer_write_u16_as_le() {
        let mut buf = [0u8; 2];
        let mut w = BeWriter::new(&mut buf);
        w.write_u16_as::<LittleEndian>(0x0102);
        assert_eq!(buf, [0x02, 0x01]);
    }

    #[test]
    fn be_writer_write_u32_as_le() {
        let mut buf = [0u8; 4];
        let mut w = BeWriter::new(&mut buf);
        w.write_u32_as::<LittleEndian>(0xDEAD_BEEF);
        assert_eq!(buf, [0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn reader_read_slice() {
        let buf = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut r = BeReader::new(&buf);
        let out = r.read_slice::<4>().unwrap();
        assert_eq!(out, [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(r.current_position(), 4);
    }

    #[test]
    fn writer_write_slice() {
        let mut buf = [0u8; 6];
        {
            let mut w = BeWriter::new(&mut buf);
            w.write_slice(&[0x01, 0x02, 0x03]);
            w.write_slice(&[0x04, 0x05, 0x06]);
            assert_eq!(w.current_position(), 6);
        }
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn sequential_reads() {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        buf[2..6].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        buf[6..8].copy_from_slice(&0x5678u16.to_be_bytes());

        let mut r = BeReader::new(&buf);
        assert_eq!(r.read_u16().unwrap(), 0x1234);
        assert_eq!(r.current_position(), 2);
        assert_eq!(r.read_u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.current_position(), 6);
        assert_eq!(r.read_u16().unwrap(), 0x5678);
        assert_eq!(r.current_position(), 8);
    }

    #[test]
    fn remaining_bytes_tracks_correctly() {
        let buf = [0u8; 10];
        let mut r = BeReader::new(&buf);
        assert_eq!(r.remaining_bytes(), 10);
        r.read_u32().unwrap();
        assert_eq!(r.remaining_bytes(), 6);
        r.read_u16().unwrap();
        assert_eq!(r.remaining_bytes(), 4);
        r.read_slice::<4>().unwrap();
        assert_eq!(r.remaining_bytes(), 0);
    }

    #[test]
    fn read_u16_on_empty_buffer_errors() {
        let buf: [u8; 0] = [];
        let mut r = BeReader::new(&buf);
        assert!(r.read_u16().is_err());
    }

    #[test]
    fn read_u32_on_short_buffer_errors() {
        let buf = [0u8; 3]; // need 4
        let mut r = BeReader::new(&buf);
        assert!(r.read_u32().is_err());
    }

    #[test]
    fn read_slice_on_short_buffer_errors() {
        let buf = [0u8; 2];
        let mut r = BeReader::new(&buf);
        assert!(r.read_slice::<4>().is_err());
    }

    #[test]
    fn read_u16_after_partial_consume_errors() {
        let buf = [0u8; 3]; // enough for one u16, not two
        let mut r = BeReader::new(&buf);
        assert!(r.read_u16().is_ok());
        assert!(r.read_u16().is_err());
    }

    #[test]
    fn be_round_trip_u16() {
        let mut buf = [0u8; 2];
        BeWriter::new(&mut buf).write_u16(0xCAFE);
        assert_eq!(BeReader::new(&buf).read_u16().unwrap(), 0xCAFE);
    }

    #[test]
    fn be_round_trip_u32() {
        let mut buf = [0u8; 4];
        BeWriter::new(&mut buf).write_u32(0xBADC0FFE);
        assert_eq!(BeReader::new(&buf).read_u32().unwrap(), 0xBADC0FFE);
    }

    #[test]
    fn le_round_trip_u16() {
        let mut buf = [0u8; 2];
        LeWriter::new(&mut buf).write_u16(0xCAFE);
        assert_eq!(LeReader::new(&buf).read_u16().unwrap(), 0xCAFE);
    }

    #[test]
    fn le_round_trip_u32() {
        let mut buf = [0u8; 4];
        LeWriter::new(&mut buf).write_u32(0xBADC0FFE);
        assert_eq!(LeReader::new(&buf).read_u32().unwrap(), 0xBADC0FFE);
    }

    #[test]
    fn round_trip_zero() {
        let mut buf = [0xFFu8; 4];
        BeWriter::new(&mut buf).write_u32(0);
        assert_eq!(BeReader::new(&buf).read_u32().unwrap(), 0);
    }

    #[test]
    fn round_trip_max_u16() {
        let mut buf = [0u8; 2];
        BeWriter::new(&mut buf).write_u16(u16::MAX);
        assert_eq!(BeReader::new(&buf).read_u16().unwrap(), u16::MAX);
    }

    #[test]
    fn round_trip_max_u32() {
        let mut buf = [0u8; 4];
        BeWriter::new(&mut buf).write_u32(u32::MAX);
        assert_eq!(BeReader::new(&buf).read_u32().unwrap(), u32::MAX);
    }
}
