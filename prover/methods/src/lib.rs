//! Exposes MELODY_ELF (the guest binary) and MELODY_ID (its image id, [u32; 8]).
include!(concat!(env!("OUT_DIR"), "/methods.rs"));
