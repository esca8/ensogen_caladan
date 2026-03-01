use crate::Buffer;
use crate::Connection;
use crate::LoadgenProtocol;
use crate::Packet;
use crate::Transport;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::io;
use std::io::Read;

pub struct Payload {
    pub work_iterations: u64,
    pub timestamp: u16,
    pub randomness: u64,
}

pub const PAYLOAD_SIZE: usize = 18;

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct SyntheticProtocol {}

impl LoadgenProtocol for SyntheticProtocol {
    fn uses_ordered_requests(&self) -> bool {
        false
    }

    fn gen_req(&self, i: usize, p: &Packet, buf: &mut Vec<u8>) {
        // Note: gen_req is not on server path (client only)
        Payload {
            work_iterations: p.work_iterations,
            timestamp: 0,
            randomness: 0,
        }
        .serialize_into(buf)
        .unwrap();
    }

    fn read_response(&self, mut sock: &Connection, buf: &mut Buffer) -> io::Result<(usize, u64)> {
        let scratch = buf.get_empty_buf();
        sock.read_exact(&mut scratch[..PAYLOAD_SIZE])?;
        let payload = Payload::deserialize(&mut &scratch[..])?;
        Ok((0, 0))
    }
}

impl SyntheticProtocol {
    pub fn with_args(_matches: &clap::ArgMatches, _tport: Transport) -> Self {
        SyntheticProtocol {}
    }

    pub fn args() -> Vec<clap::Arg> {
        vec![]
    }
}

impl Payload {
    pub fn serialize_into<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u64::<BigEndian>(self.work_iterations)?;
        writer.write_u16::<BigEndian>(self.timestamp)?;
        writer.write_u64::<BigEndian>(self.randomness)?;
        Ok(())
    }

    pub fn deserialize<R: io::Read>(reader: &mut R) -> io::Result<Payload> {
        let p = Payload {
            work_iterations: reader.read_u64::<BigEndian>()?,
            timestamp: reader.read_u16::<BigEndian>()?,
            randomness: reader.read_u64::<BigEndian>()?,
        };
        return Ok(p);
    }
}
