use std::{
    fmt::{Debug, Formatter},
    net::Ipv4Addr,
};

use anyhow::{anyhow, bail};

pub struct Capture<'a> {
    data: &'a [u8],
}

impl<'a> Capture<'a> {
    const HEADER_LENGTH: usize = 24;

    pub fn new(data: &'a [u8]) -> anyhow::Result<Self> {
        let mut position = 0;
        let magic = u32::read_le(data, &mut position);
        assert_eq!(magic, 0xA1B2C3D4);
        let ver = (u16::read_le(data, &mut position), u16::read_le(data, &mut position));
        assert_eq!(ver, (2, 4));
        position += u32::BYTES; // Reserved 1
        position += u32::BYTES; // Reserved 2
        let snap_len = u32::read_le(data, &mut position);
        assert_eq!(snap_len, u16::MAX as u32);
        let link_type = u32::read_le(data, &mut position);
        assert_eq!(link_type, 1); // Ethernet

        assert_eq!(position, Self::HEADER_LENGTH);
        Ok(Self { data })
    }

    pub fn records(&self) -> Records<'_> {
        Records::new(self)
    }
}

pub struct Records<'a> {
    pcap: &'a Capture<'a>,
    position: usize,
}

impl<'a> Records<'a> {
    fn new(pcap: &'a Capture<'a>) -> Self {
        Self {
            pcap,
            position: Capture::HEADER_LENGTH,
        }
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = PhysicalFrame<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.pcap.data.len() {
            return None;
        }
        let frame = PhysicalFrame::read(self.pcap.data, &mut self.position).unwrap();
        Some(frame)
    }
}

pub struct PhysicalFrame<'a> {
    data: &'a [u8],
}

impl<'a> PhysicalFrame<'a> {
    fn read(data: &'a [u8], position: &mut usize) -> anyhow::Result<Self> {
        *position += u32::BYTES; // TS - seconds
        *position += u32::BYTES; // TS - micro/nanos
        let captured = u32::read_le(data, position);
        let original = u32::read_le(data, position);
        if captured != original {
            bail!("packet was truncated")
        }
        let enclosed_data = &data[*position..*position + captured as usize];
        *position += captured as usize;
        Ok(Self { data: enclosed_data })
    }

    pub fn ip(self) -> anyhow::Result<IpPacket<'a>> {
        IpPacket::new(self)
    }
}

impl Debug for PhysicalFrame<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let alt = f.alternate();
        let mut s = f.debug_struct("PhysicalFrame");
        let s = s.field("length", &self.data.len());
        if alt {
            s.field("data", &self.data).finish()
        } else {
            s.finish_non_exhaustive()
        }
    }
}

pub struct IpPacket<'a> {
    pub data: &'a [u8],
    pub protocol: Protocol,
    pub source: Ipv4Addr,
    pub dest: Ipv4Addr,
}

impl<'a> IpPacket<'a> {
    fn new(phys: PhysicalFrame<'a>) -> anyhow::Result<Self> {
        // Ethernet Frame
        let data = phys.data;
        let mut position = 0;
        position += 6; // Destination MAC
        position += 6; // Source MAC
        let type_length = u16::read_be(data, &mut position) as usize;
        if type_length != 0x800 {
            bail!("expected an IP(v4) record, found 0x{type_length:04X}");
        }

        // IPv4 Frame
        let ip_start = position;
        let magic = u8::read_be(data, &mut position);
        let version = (magic & 0xF0) >> 4;
        let ihl = magic & 0x0F;
        if version != 4 {
            bail!("expected an IPv4 record")
        }
        if ihl != 5 {
            bail!("IPv4 header had options specified")
        }
        position += 1; // DSCP + ECN
        let total_length = u16::read_be(data, &mut position);
        position += 2; // Identification
        position += 2; // Flags + Fragment offset
        position += 1; // TTL
        let protocol = u8::read_be(data, &mut position);
        position += 2; // Header checksum - we just assume this is valid

        let source = Ipv4Addr::from(u32::read_be(data, &mut position));
        let dest = Ipv4Addr::from(u32::read_be(data, &mut position));

        let protocol = Protocol::from_byte(protocol)?;
        let data_length = (total_length as usize) - (position - ip_start);
        debug_assert_eq!(position - ip_start, 20); // As ihl is 5
        let ip_data = &data[position..];
        debug_assert_eq!(data_length, ip_data.len());
        Ok(Self {
            data: ip_data,
            protocol,
            source,
            dest,
        })
    }
}

impl Debug for IpPacket<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let alt = f.alternate();
        let mut s = f.debug_struct("IpPacket");
        let s = s
            .field("protocol", &self.protocol)
            .field("source", &self.source)
            .field("dest", &self.dest)
            .field("length", &self.data.len());
        if alt {
            s.field("data", &self.data).finish()
        } else {
            s.finish_non_exhaustive()
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub enum Protocol {
    TCP,
    UDP,
}

impl Protocol {
    fn from_byte(b: u8) -> anyhow::Result<Self> {
        match b {
            0x06 => Ok(Self::TCP),
            0x11 => Ok(Self::UDP),
            _ => Err(anyhow!("unknown protocol 0x{b:02X}")),
        }
    }
}

trait Readable: Sized {
    const BYTES: usize;

    fn read_le(data: &[u8], position: &mut usize) -> Self;
    fn read_be(data: &[u8], position: &mut usize) -> Self;
}

macro_rules! impl_readable {
    ($($t:ty: $size:literal),+ $(,)?) => {
        $(
        impl Readable for $t {
            const BYTES: usize = $size;

            fn read_le(data: &[u8], position: &mut usize) -> Self {
                let part = &data[*position..*position + $size];
                *position += $size;
                let part = part.try_into().unwrap();
                Self::from_le_bytes(part)
            }

            fn read_be(data: &[u8], position: &mut usize) -> Self {
                let part = &data[*position..*position + $size];
                *position += $size;
                let part = part.try_into().unwrap();
                Self::from_be_bytes(part)
            }
        }
        )+
    };
}

impl_readable! {
    u8: 1,
    u16: 2,
    u32: 4,
    u64: 8,
}
