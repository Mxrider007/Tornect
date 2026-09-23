//! SHA-256 (FIPS 180-4) for `pt-fetch` and `dist`: the pinned downloads, the
//! bundled files and `SHA256SUMS`.
//!
//! Written out here because `xtask` depends on nothing but `anyhow`, and a hash
//! crate would be one more `Cargo.lock` entry for the release tooling to trust.
//! The tests pin it to the FIPS 180-2 known answers and to digests at every
//! padding boundary (55, 56, 63, 64 bytes and one block on); the real tarballs,
//! 22–32 MB each, must also hash to the pins that `sha256sum` and the Tor
//! Project's signed list established (`packaging/pt/SOURCES.md`).

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::Path;

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// A running SHA-256.
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    /// Message length in bytes so far.
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: H0,
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.filled > 0 {
            let take = (64 - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < 64 {
                return;
            }
            let block = self.block;
            compress(&mut self.state, &block);
            self.filled = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            let block: &[u8; 64] = block.try_into().expect("chunks_exact(64) yields 64 bytes");
            compress(&mut self.state, block);
        }
        let rest = blocks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.filled = rest.len();
    }

    pub fn finish(mut self) -> [u8; 32] {
        // 0x80, then zeros up to 56 bytes into a block, then the length in bits.
        let bits = self.length.wrapping_mul(8);
        let zeros = if self.filled < 56 {
            55 - self.filled
        } else {
            119 - self.filled
        };
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        pad[1 + zeros..9 + zeros].copy_from_slice(&bits.to_be_bytes());
        self.update(&pad[..9 + zeros]);
        debug_assert_eq!(self.filled, 0, "the padding ends on a block boundary");
        let mut out = [0u8; 32];
        for (bytes, word) in out.chunks_exact_mut(4).zip(self.state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().expect("chunks_exact(4) yields 4 bytes"));
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, wi) in K.iter().zip(w) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (word, add) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(add);
    }
}

/// Lower-case hex, the form `sha256sum` prints and the pins use.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The SHA-256 of `data`, as lower-case hex.
#[cfg(test)]
pub fn hex_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex(&hasher.finish())
}

/// The SHA-256 of a file's contents, as lower-case hex.
pub fn file_hex(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-2 appendix B (and the empty message).
    #[test]
    fn known_answers() {
        assert_eq!(
            hex_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex_digest(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
        assert_eq!(
            hex_digest(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 7 + 3) % 256) as u8).collect()
    }

    /// Digests from Python's `hashlib` for the lengths where the padding
    /// changes shape: one byte short of, at and past the 56-byte length field,
    /// the block edge, and the same one block later.
    #[test]
    fn padding_boundaries() {
        for (len, want) in [
            (
                55,
                "e7313d333c272e639f790978283f9eb392e843d0f29b7016828bb1daa4aac70b",
            ),
            (
                56,
                "4324d65f3c103567f5589c710bc08f8523f929a9272e3af36fc968e52abc6c27",
            ),
            (
                57,
                "35df609437dcfea3279283ab79fd554e2bf78f8f7ae2de532d8ee300b09e8f73",
            ),
            (
                63,
                "81c80242132f230c3bd41b3e63bbcff16107339549214a99614ff26664625055",
            ),
            (
                64,
                "39e3d7b6b5d075d37d053ad89b24b41bef4f3c29760c84447cab3f3be1882241",
            ),
            (
                65,
                "aacca6ff74fdbb296d165a45cecfa04e5127bc008770fbbdd48006f2d2fae95e",
            ),
            (
                119,
                "9ce7368e4daf32341631b492e80359dc9f594b48453cd0dd5bf0b19279cc177e",
            ),
            (
                120,
                "7836b787757e95e58b3ca5aec90b1b004e8deba1e50e9675af9cabf1a13a04b5",
            ),
            (
                127,
                "a8d23e75d936f303d248888d9b165ee543f4cbafcad3c9dd2a79bd84faa11d07",
            ),
            (
                128,
                "d2742f1f4ac6bb7ca2b239ee18402ba8b3f9f8e652d2a72973c2b9ba11c08cf6",
            ),
            (
                129,
                "307f8fc2c1622b92762e818d39a185d4d667ad49a4b07ceae1f4afa008a93ec4",
            ),
            (
                1000,
                "1e9bc38cbf860b9ec31918b065f9b52476c549a782e0e7990bed8ce3868d2371",
            ),
        ] {
            assert_eq!(hex_digest(&pattern(len)), want, "length {len}");
        }
    }

    /// Feeding the same bytes in two pieces, split anywhere, changes nothing.
    #[test]
    fn split_updates_hash_like_one() {
        for len in [0, 1, 55, 56, 63, 64, 65, 130] {
            let data = pattern(len);
            let whole = hex_digest(&data);
            for cut in 0..=len {
                let mut hasher = Sha256::new();
                hasher.update(&data[..cut]);
                hasher.update(&data[cut..]);
                assert_eq!(hex(&hasher.finish()), whole, "length {len}, cut {cut}");
            }
        }
    }

    #[test]
    fn a_file_hashes_like_its_bytes() {
        let dir = std::env::temp_dir().join(format!("xtask-sha256-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data");
        let data = pattern(200_000);
        std::fs::write(&path, &data).unwrap();
        let got = file_hex(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(got, hex_digest(&data));
    }
}
