//! T6 (Black Ops 2) PC fast-file reader probe.
//!
//! File layout:
//!   0x000  magic "TAff0100", u32 version (0x93)
//!   0x00c  auth header: magic "PHEEBs71", u32 flags, name[32], signature[256]
//!   0x138  chunk data: repeated `[u32 size][size bytes]`, size == 0 ends the file
//!
//! Chunks are dealt round-robin to 4 streams. Each chunk is Salsa20-decrypted and then
//! raw-deflate decompressed (max 0x8000 bytes out). Each stream has its own ring of 200
//! 20-byte hash blocks seeded from the zone name; the IV of a chunk is the first 8 bytes of
//! the stream's current hash block, and the SHA-1 of the decrypted chunk is XORed into the
//! next hash block. The file is read through a 0x80000 byte buffer, which matters because
//! a size field that would straddle a buffer boundary is skipped past.

use flate2::read::DeflateDecoder;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use salsa20::Salsa20;
use sha1::{Digest, Sha1};
use std::io::Read;

const KEY: [u8; 32] = [
    0x64, 0x1D, 0x8A, 0x2F, 0xE3, 0x1D, 0x3A, 0xA6, 0x36, 0x22, 0xBB, 0xC9, 0xCE, 0x85, 0x87, 0x22,
    0x9D, 0x42, 0xB0, 0xF8, 0xED, 0x9B, 0x92, 0x41, 0x30, 0xBF, 0x88, 0xB6, 0x5E, 0xDC, 0x50, 0xBE,
];

const NAME_OFFSET: usize = 0x18;
const DATA_START: usize = 0x138;
const STREAM_COUNT: usize = 4;
const XCHUNK_SIZE: usize = 0x8000;
const VANILLA_BUFFER_SIZE: usize = 0x80000;
const BLOCK_HASHES_COUNT: usize = 200;
const SHA1_SIZE: usize = 20;

/// Per-stream hash-block ring used to derive Salsa20 IVs.
struct IvRing {
    hashes: Vec<u8>, // [BLOCK_HASHES_COUNT][STREAM_COUNT][SHA1_SIZE]
    index: [usize; STREAM_COUNT],
}

impl IvRing {
    fn new(zone_name: &[u8]) -> Self {
        let len = zone_name.len().min(31);
        let total = BLOCK_HASHES_COUNT * STREAM_COUNT * SHA1_SIZE;
        let mut hashes = vec![0u8; total];
        let mut off = 0;
        for i in (0..total).step_by(4) {
            hashes[i..i + 4].fill(zone_name[off]);
            off = (off + 1) % len;
        }
        IvRing { hashes, index: [0; STREAM_COUNT] }
    }

    fn block_offset(&self, stream: usize) -> usize {
        self.index[stream] * STREAM_COUNT * SHA1_SIZE + stream * SHA1_SIZE
    }

    fn decrypt_chunk(&mut self, stream: usize, data: &mut [u8]) {
        let off = self.block_offset(stream);
        let iv: [u8; 8] = self.hashes[off..off + 8].try_into().unwrap();
        let mut cipher = Salsa20::new((&KEY).into(), (&iv).into());
        cipher.apply_keystream(data);

        let hash = Sha1::digest(&*data);
        self.index[stream] = (self.index[stream] + 1) % BLOCK_HASHES_COUNT;
        let next = self.block_offset(stream);
        for i in 0..SHA1_SIZE {
            self.hashes[next + i] ^= hash[i];
        }
    }
}

struct Zone {
    name: String,
    data: Vec<u8>,
    chunks: usize,
}

fn decode(file: &[u8]) -> Result<Zone, String> {
    if file.len() < DATA_START || &file[..8] != b"TAff0100" {
        return Err("not a T6 fast file".into());
    }
    let name_bytes = &file[NAME_OFFSET..NAME_OFFSET + 32];
    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
    let name = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();
    let mut ring = IvRing::new(&name_bytes[..name_len]);

    let mut pos = DATA_START;
    let mut vbuf = DATA_START % VANILLA_BUFFER_SIZE; // OAT seeds this from the file position
    let mut chunk_no = 0usize;
    let mut data = Vec::new();

    loop {
        // Size field handling, mirroring the game's buffered reader.
        if vbuf + 4 > VANILLA_BUFFER_SIZE {
            pos += VANILLA_BUFFER_SIZE - vbuf;
            vbuf = 0;
        }
        vbuf = (vbuf + 4) % VANILLA_BUFFER_SIZE;
        if pos + 4 > file.len() {
            break;
        }
        let size = u32::from_le_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if size == 0 {
            break;
        }
        if size > XCHUNK_SIZE || pos + size > file.len() {
            return Err(format!("chunk {chunk_no}: bad size {size:#x} at {pos:#x}"));
        }
        let mut chunk = file[pos..pos + size].to_vec();
        pos += size;
        vbuf = (vbuf + size) % VANILLA_BUFFER_SIZE;

        ring.decrypt_chunk(chunk_no % STREAM_COUNT, &mut chunk);

        let mut out = Vec::with_capacity(XCHUNK_SIZE);
        DeflateDecoder::new(&chunk[..])
            .read_to_end(&mut out)
            .map_err(|e| format!("chunk {chunk_no}: inflate failed: {e}"))?;
        data.extend_from_slice(&out);
        chunk_no += 1;
    }
    Ok(Zone { name, data, chunks: chunk_no })
}

fn main() {
    let mut ok = 0;
    let mut bad = 0;
    for path in std::env::args().skip(1) {
        let file = match std::fs::read(&path) {
            Ok(f) => f,
            Err(e) => {
                println!("{path}: {e}");
                bad += 1;
                continue;
            }
        };
        match decode(&file) {
            Ok(z) => {
                ok += 1;
                let size = u32::from_le_bytes(z.data[0..4].try_into().unwrap());
                println!(
                    "OK  {:<28} {:>5} chunks  {:>10} bytes  XFile.size={size}  head={:02x?}",
                    z.name,
                    z.chunks,
                    z.data.len(),
                    &z.data[..16.min(z.data.len())]
                );
            }
            Err(e) => {
                bad += 1;
                println!("ERR {path}: {e}");
            }
        }
    }
    println!("{ok} ok, {bad} failed");
}
