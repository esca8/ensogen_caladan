use crate::Buffer;
use crate::Connection;
use crate::LoadgenProtocol;
use crate::Packet;
use crate::Transport;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::Read;

pub struct Payload {
    pub work_iterations: u64,
    pub timestamp: u64,
    pub randomness: u16,
    pub padding: u32,
}

pub const PAYLOAD_SIZE: usize = 22; /* serialized payload size: 8 + 8 + 2 + 4 bytes */

#[derive(Clone, Copy)]
pub struct SyntheticProtocol {}

impl LoadgenProtocol for SyntheticProtocol {
    fn uses_ordered_requests(&self) -> bool {
        false
    }

    fn gen_req(&self, i: usize, p: &Packet, buf: &mut Vec<u8>) {
        Payload {
            work_iterations: p.work_iterations,
            timestamp: i as u64,
            randomness: p.randomness,
            padding: 0,
        }
        .serialize_into(buf)
        .unwrap();
    }

    fn read_response(&self, mut sock: &Connection, buf: &mut Buffer) -> io::Result<(usize, u64)> {
        let scratch = buf.get_empty_buf();
        sock.read_exact(&mut scratch[..PAYLOAD_SIZE])?;
        let payload = Payload::deserialize(&mut &scratch[..])?;
        Ok((payload.timestamp as usize, payload.randomness.into()))
    }
}

impl SyntheticProtocol {
    pub fn with_args(_matches: &clap::ArgMatches, _tport: Transport) -> Self {
        SyntheticProtocol {}
    }

    pub fn args<'a, 'b>() -> Vec<clap::Arg<'a, 'b>> {
        vec![]
    }
}

impl Payload {
    pub fn serialize_into<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u64::<BigEndian>(self.work_iterations)?;
        writer.write_u64::<BigEndian>(self.timestamp)?;
        writer.write_u16::<BigEndian>(self.randomness)?;
        writer.write_u32::<BigEndian>(self.padding)?;
        Ok(())
    }

    pub fn deserialize<R: io::Read>(reader: &mut R) -> io::Result<Payload> {
        let p = Payload {
            work_iterations: reader.read_u64::<BigEndian>()?,
            timestamp: reader.read_u64::<BigEndian>()?,
            randomness: reader.read_u16::<BigEndian>()?,
            padding: reader.read_u32::<BigEndian>()?,
        };
        return Ok(p);
    }
}
