//! The job's random generator: the ChaCha20 keystream under a key from the operating system.

use chacha20_poly1305::chacha20::ChaCha20;
use chacha20_poly1305::{Key, Nonce};

pub struct Rng {
    key: [u8; 32],
    block: u32,
    buf: [u8; 64],
    pos: usize,
}

impl Default for Rng {
    fn default() -> Rng {
        Rng::new()
    }
}

impl Rng {
    /// Keyed from the operating system's generator.
    pub fn new() -> Rng {
        let mut key = [0u8; 32];
        os_fill(&mut key);
        Rng::from_key(key)
    }

    /// A generator whose output is a function of key alone.
    pub fn from_key(key: [u8; 32]) -> Rng {
        Rng { key, block: 0, buf: [0; 64], pos: 64 }
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            if self.pos == self.buf.len() {
                self.buf = ChaCha20::new(Key::new(self.key), Nonce::new([0; 12]), 0).get_keystream(self.block);
                self.block = self.block.checked_add(1).expect("fewer than 2^32 blocks drawn");
                self.pos = 0;
            }
            *byte = self.buf[self.pos];
            self.pos += 1;
        }
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }

    pub fn rand64(&mut self) -> u64 {
        u64::from_le_bytes(self.bytes())
    }

    /// Uniform in [0, n). n must not be 0.
    pub fn randrange(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        let max = n - 1;
        if max == 0 {
            return 0;
        }
        let shift = max.leading_zeros();
        loop {
            let draw = self.rand64() >> shift;
            if draw <= max {
                return draw;
            }
        }
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.randrange(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }
}

/// Fill out from the operating system's generator. There is no fallback: a job cannot run without
/// fresh randomness (A4).
pub fn os_fill(out: &mut [u8]) {
    getrandom::fill(out).expect("the operating system's random number generator failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randrange_bounds() {
        let mut rng = Rng::from_key([7; 32]);
        for n in [1u64, 2, 3, 7, 1000, u64::MAX] {
            for _ in 0..200 {
                assert!(rng.randrange(n) < n);
            }
        }
        let mut seen = [false; 5];
        for _ in 0..200 {
            seen[rng.randrange(5) as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn keyed_output_repeats() {
        let a: [u8; 100] = Rng::from_key([1; 32]).bytes();
        let b: [u8; 100] = Rng::from_key([1; 32]).bytes();
        let c: [u8; 100] = Rng::from_key([2; 32]).bytes();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
