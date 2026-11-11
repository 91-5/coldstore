//! `.coldstore` container header and frame-region IO primitives.
//!
//! Layout (docs/format.md):
//!
//! ```text
//! 64 B header | frame 0 | frame 1 | … | frame N | skippable index frame
//! ```
//!
//! The header is written LAST (seek back to 0 after frames + index are on
//! disk) and the container is published by renaming the temp file, so a
//! crash can never leave a half-written container with a valid header.
//! All offsets/sizes are u64 (AV-8: >2 GiB members are first-class).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use anyhow::{bail, Result};

use super::index::{CONTAINER_VERSION, HEADER_SIZE};

/// Magic at offset 0.
pub const MAGIC: &[u8; 8] = b"COLDSTR\0";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContainerHeader {
    pub version: u16,
    /// true → embedded skippable-frame index is authoritative (AV-3).
    pub index_embedded: bool,
    pub frame_count: u64,
    /// Total container file size in bytes (header included).
    pub total_size: u64,
    /// Absolute offset of the skippable index frame (0 when sidecar mode).
    pub index_offset: u64,
    /// Total skippable frame bytes incl. 8-byte skippable header (0 = none).
    pub index_len: u64,
}

impl ContainerHeader {
    pub fn pack(&self) -> [u8; HEADER_SIZE as usize] {
        let mut h = [0u8; HEADER_SIZE as usize];
        h[0..8].copy_from_slice(MAGIC);
        h[8..10].copy_from_slice(&self.version.to_le_bytes());
        let flags: u16 = if self.index_embedded { 1 } else { 0 };
        h[10..12].copy_from_slice(&flags.to_le_bytes());
        h[16..24].copy_from_slice(&self.frame_count.to_le_bytes());
        h[24..32].copy_from_slice(&self.total_size.to_le_bytes());
        h[32..40].copy_from_slice(&self.index_offset.to_le_bytes());
        h[40..48].copy_from_slice(&self.index_len.to_le_bytes());
        h
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE as usize {
            bail!("头部截断: {} 字节 < {HEADER_SIZE}", buf.len());
        }
        if &buf[0..8] != MAGIC {
            bail!(
                "魔数不符: {:?}（期望 {:?}）—— 不是 .coldstore 容器或文件损坏",
                &buf[0..8],
                MAGIC
            );
        }
        let version = u16::from_le_bytes([buf[8], buf[9]]);
        if version > CONTAINER_VERSION {
            bail!("容器版本过新: {version} > 本程序支持 {CONTAINER_VERSION}");
        }
        let flags = u16::from_le_bytes([buf[10], buf[11]]);
        if flags & !0x1 != 0 {
            bail!("头部保留位非零（容器损坏或版本不符）: flags={flags:#x}");
        }
        let frame_count = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let total_size = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let index_offset = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let index_len = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        let header = ContainerHeader {
            version,
            index_embedded: flags & 1 == 1,
            frame_count,
            total_size,
            index_offset,
            index_len,
        };
        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<()> {
        if self.total_size < HEADER_SIZE {
            bail!("total_size {} 小于头部大小，容器损坏", self.total_size);
        }
        if self.index_len > 0 {
            let end = self
                .index_offset
                .checked_add(self.index_len)
                .ok_or_else(|| anyhow::anyhow!("index_offset 溢出"))?;
            if end > self.total_size {
                bail!(
                    "索引区越界: offset {} + len {} > total {}（容器损坏）",
                    self.index_offset,
                    self.index_len,
                    self.total_size
                );
            }
            if self.index_offset < HEADER_SIZE {
                bail!("索引区起点 {} 侵入头部（容器损坏）", self.index_offset);
            }
        }
        Ok(())
    }
}

/// Write the final header at offset 0 of a fully-written container.
pub fn write_header(file: &mut File, header: &ContainerHeader) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header.pack())?;
    Ok(())
}

/// Read + validate the header of an existing container.
pub fn read_header(file: &mut File) -> Result<ContainerHeader> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; HEADER_SIZE as usize];
    file.read_exact(&mut buf)?;
    ContainerHeader::parse(&buf)
}

/// Read the embedded index region described by the header (empty when the
/// header declares index_len == 0).
pub fn read_embedded_region(file: &mut File, header: &ContainerHeader) -> Result<Vec<u8>> {
    if header.index_len == 0 {
        return Ok(Vec::new());
    }
    file.seek(SeekFrom::Start(header.index_offset))?;
    let mut buf = vec![0u8; header.index_len as usize];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// zstd frame window descriptor parser (AV-2): proves from the *frame
/// header bytes* that a frame was compressed with `--long=27`.
///
/// zstd format §3.1.1: after the 4-byte magic and the frame-header
/// descriptor byte, a window-descriptor byte is present unless the
/// `Single_Segment_flag` is set. `windowLog = 10 + Exponent` where
/// Exponent is the high 5 bits of the descriptor; Mantissa adds a fraction.
pub fn frame_window_log(frame: &[u8]) -> Result<u32> {
    if frame.len() < 6 {
        bail!("帧头过短: {} 字节", frame.len());
    }
    let magic = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    const FRAME_MAGIC: u32 = 0xFD2FB528;
    if magic != FRAME_MAGIC {
        bail!("zstd 帧魔数不符: {magic:#010x}");
    }
    let fhd = frame[4];
    let single_segment = (fhd >> 5) & 1;
    if single_segment == 1 {
        // No window descriptor: window defaults to srcSize (≤ 2^26 here).
        bail!("帧为 Single_Segment 模式（无窗口描述符）—— 不适用本断言");
    }
    let wd = frame[5];
    let exponent = (wd >> 3) & 0x1F;
    Ok(10 + u32::from(exponent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_pack_parse_roundtrip() {
        let h = ContainerHeader {
            version: CONTAINER_VERSION,
            index_embedded: true,
            frame_count: 3,
            total_size: 64 + 1000 + 77,
            index_offset: 64 + 1000,
            index_len: 77,
        };
        let bytes = h.pack();
        assert_eq!(&bytes[0..8], MAGIC);
        assert_eq!(ContainerHeader::parse(&bytes).unwrap(), h);

        // >2 GiB sizes survive the u64 roundtrip (AV-8)
        let big = ContainerHeader {
            version: CONTAINER_VERSION,
            index_embedded: false,
            frame_count: 2,
            total_size: 64 + 3_000_000_000u64,
            index_offset: 0,
            index_len: 0,
        };
        assert_eq!(ContainerHeader::parse(&big.pack()).unwrap(), big);
    }

    #[test]
    fn bad_magic_and_out_of_bounds_index_rejected() {
        let mut bytes = [0u8; 64];
        bytes[0..8].copy_from_slice(b"NOTMAGIC");
        assert!(ContainerHeader::parse(&bytes).is_err());

        let h = ContainerHeader {
            version: CONTAINER_VERSION,
            index_embedded: true,
            frame_count: 1,
            total_size: 100,
            index_offset: 64,
            index_len: 500, // 64+500 > 100 → out of bounds
        };
        assert!(ContainerHeader::parse(&h.pack()).is_err());
    }

    #[test]
    fn window_descriptor_math_matches_spec() {
        // Synthetic headers: exponent = 17 → windowLog 27 (--long=27).
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0x00); // FHD: single_segment=0
        frame.push(17u8 << 3); // window descriptor, mantissa 0
        assert_eq!(frame_window_log(&frame).unwrap(), 27);

        // mantissa set → same exponent, still 27
        let mut frame2 = frame.clone();
        frame2[5] = (17u8 << 3) | 0b101;
        assert_eq!(frame_window_log(&frame2).unwrap(), 27);

        // single-segment frame has no descriptor → not applicable
        let mut frame3 = Vec::new();
        frame3.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame3.push(0x20); // single_segment = 1
        assert!(frame_window_log(&frame3).is_err());
    }
}
