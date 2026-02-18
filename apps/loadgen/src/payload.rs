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
    pub timestamp: u64,
    pub _padding: u16
}

pub const PAYLOAD_SIZE: usize = 18;

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct SyntheticProtocol {}

impl LoadgenProtocol for SyntheticProtocol {
    fn uses_ordered_requests(&self) -> bool {
        false
    }

    fn gen_req(&self, i: usize, p: &Packet, buf: &mut Vec<u8>) {
        Payload {
            work_iterations: 0 as u64,
            timestamp: 0 as u64,
            _padding: 0 as u16, 
        }
        .serialize_into(buf)
        .unwrap();
    }

    fn read_response(&self, mut sock: &Connection, buf: &mut Buffer) -> io::Result<(usize, u64)> {
        Ok((0,0))
        // NOTE: client not used
        // let scratch = buf.get_empty_buf();
        // sock.read_exact(&mut scratch[..PAYLOAD_SIZE])?;
        // let payload = Payload::deserialize(&mut &scratch[..])?;
        // Ok((payload.index as usize, payload.randomness))
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
        writer.write_u64::<BigEndian>(self.timestamp)?;
        writer.write_u16::<BigEndian>(self._padding)?;
        Ok(())
    }

    pub fn deserialize<R: io::Read>(reader: &mut R) -> io::Result<Payload> {
        let p = Payload {
            work_iterations: reader.read_u64::<BigEndian>()?,
            timestamp: reader.read_u64::<BigEndian>()?,
            _padding: reader.read_u16::<BigEndian>()?,
        };
        return Ok(p);
    }
}
