//! Guest: "this melody is in key" — proven without revealing the melody.
//!
//! Private input : the melody, as MIDI note numbers (0..=127), at least one note.
//! Public input  : key root (0..=11, 0 = C) and mode (0 = major, 1 = natural minor).
//! Rule          : every note belongs to the scale, and the last note is the tonic.
//! Journal (36 B): [root u8][mode u8][n u16 LE][sha256(melody bytes) 32 B]
//!
//! Anyone holding the receipt learns exactly the journal and nothing else. The
//! Kaspa covenant pins this program's image id; a receipt from any other program,
//! or any other journal, fails the on-chain check.
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

const MAJOR: [u8; 7] = [0, 2, 4, 5, 7, 9, 11];
const MINOR: [u8; 7] = [0, 2, 3, 5, 7, 8, 10];

fn main() {
    // Inputs are written by the host in this order (see host/src/main.rs).
    let root: u8 = env::read();
    let mode: u8 = env::read();
    let melody: Vec<u8> = env::read();

    assert!(root < 12, "root must be 0..=11");
    assert!(mode < 2, "mode must be 0 (major) or 1 (minor)");
    assert!(!melody.is_empty(), "melody must have at least one note");
    assert!(melody.len() <= u16::MAX as usize, "melody too long");

    let scale = if mode == 0 { MAJOR } else { MINOR };

    // Every note, reduced to a pitch class relative to the root, must be a scale degree.
    for &note in &melody {
        assert!(note < 128, "not a MIDI note");
        let degree = (note % 12 + 12 - root) % 12;
        assert!(scale.contains(&degree), "note outside the key");
    }

    // The melody must resolve: last note is the tonic.
    assert!(melody[melody.len() - 1] % 12 == root, "melody does not end on the tonic");

    // Publish only what we want the world to know.
    let digest = Impl::hash_bytes(&melody);
    let n = melody.len() as u16;
    let mut journal = Vec::with_capacity(36);
    journal.push(root);
    journal.push(mode);
    journal.extend_from_slice(&n.to_le_bytes());
    journal.extend_from_slice(digest.as_bytes());
    env::commit_slice(&journal);
}
