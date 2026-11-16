//! KCC-20 Last Call reference cells (argent-lang/kcc20-reference c8a0871, template 9703112e…; bridge-v4/KCC20.sil):
//! which outputs of a token transfer are burn cells, and how much each holds.
//!
//! A cell's amount is inside its P2SH hash, so the outputs alone do not say it. The spender's signature script
//! does: a `transfer` carries the next states as six grouped-field pushes (KCC-1 3.4.6: amounts as LE64s, owners,
//! owner schemes, borrow schemes, guards, extension commitments), then the witness, the entry tag `79c71c23` and
//! the input cell's redeem. The redeem gives the prefix and suffix (its template hash is checked), so every next
//! state can be rebuilt into a redeem and hashed; an output is a burn cell when its script equals the P2SH of a
//! rebuilt burn state (owner BURN_OWNER, scheme 03, borrow 00, zero guard, zero commitment) and it carries the
//! token's covenant id. A mistake in parsing can only miss a cell, never invent one: the hash decides. The relay
//! guest (outbound/kaspa-prover/primitives/src/relay.rs) runs the same rebuild from its embedded suffix.

/// Template hash of the reference cell: BLAKE3(LE64(1) || 6b || LE64(3885) || suffix).
pub const TEMPLATE: [u8; 32] = [
    0x97, 0x03, 0x11, 0x2e, 0xe6, 0xe3, 0x55, 0x51, 0x07, 0xcd, 0x16, 0x88, 0x58, 0x99, 0x2b, 0x77, 0xd3, 0xb7, 0x4f, 0x65, 0x52, 0x05,
    0xb2, 0xb4, 0x63, 0xb1, 0xf9, 0xec, 0x2e, 0xc7, 0x3c, 0xf7,
];
/// BLAKE2b-256(6a): the p2sh owner nobody can satisfy (its script is OP_RETURN).
pub const BURN_OWNER: [u8; 32] = [
    0xd3, 0x79, 0xe5, 0x0f, 0x3e, 0x22, 0x03, 0xf9, 0xa9, 0x25, 0x84, 0x91, 0x63, 0x35, 0xbb, 0x7c, 0xd0, 0x14, 0xb2, 0x37, 0xce, 0xaa,
    0x8b, 0x36, 0xf1, 0xd3, 0xd8, 0x0d, 0x0c, 0xc8, 0x8b, 0x32,
];
pub const TAG_TRANSFER: [u8; 4] = [0x79, 0xc7, 0x1c, 0x23];
pub const OWNER_P2SH: u8 = 0x03;
pub const WINDOW_LEN: usize = 145;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub amount: u64,
    pub owner: [u8; 32],
    pub owner_scheme: u8,
    pub borrow_scheme: u8,
    pub guard: [u8; 32],
    pub commitment: [u8; 32],
}

impl Cell {
    pub fn is_burn(&self) -> bool {
        self.owner == BURN_OWNER && self.owner_scheme == OWNER_P2SH && self.borrow_scheme == 0 && self.guard == [0; 32] && self.commitment == [0; 32]
    }
}

pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&(prefix.len() as u64).to_le_bytes());
    h.update(prefix);
    h.update(&(suffix.len() as u64).to_le_bytes());
    h.update(suffix);
    *h.finalize().as_bytes()
}

pub fn window(template: &[u8; 32], c: &Cell) -> Vec<u8> {
    let mut v = Vec::with_capacity(WINDOW_LEN);
    v.push(0x20);
    v.extend_from_slice(template);
    v.push(0x08);
    v.extend_from_slice(&c.amount.to_le_bytes());
    v.push(0x20);
    v.extend_from_slice(&c.owner);
    v.extend_from_slice(&[0x01, c.owner_scheme, 0x01, c.borrow_scheme, 0x20]);
    v.extend_from_slice(&c.guard);
    v.push(0x20);
    v.extend_from_slice(&c.commitment);
    v
}

/// `aa 20 BLAKE2b-256(redeem) 87`
pub fn p2sh_script(redeem: &[u8]) -> Vec<u8> {
    let d = blake2b_simd::Params::new().hash_length(32).hash(redeem);
    let mut s = Vec::with_capacity(35);
    s.extend_from_slice(&[0xaa, 0x20]);
    s.extend_from_slice(d.as_bytes());
    s.push(0x87);
    s
}

/// The data pushes of a push-only script, in order; None if any opcode is not a push. OP_0 pushes the empty
/// vector, OP_1NEGATE [0x81], OP_1..OP_16 the one byte 1..16 (how a minimal encoder writes small values).
pub fn pushes(s: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < s.len() {
        let op = s[i];
        i += 1;
        let n = match op {
            0x00 => 0,
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = *s.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let n = u16::from_le_bytes(s.get(i..i + 2)?.try_into().ok()?) as usize;
                i += 2;
                n
            }
            0x4e => {
                let n = u32::from_le_bytes(s.get(i..i + 4)?.try_into().ok()?) as usize;
                i += 4;
                n
            }
            0x4f => {
                out.push(vec![0x81]);
                continue;
            }
            0x51..=0x60 => {
                out.push(vec![op - 0x50]);
                continue;
            }
            _ => return None,
        };
        out.push(s.get(i..i + n)?.to_vec());
        i += n;
    }
    Some(out)
}

/// A one-byte-per-cell field: the push, or what a minimal encoder made of it for a single cell.
fn byte_field(p: &[u8], n: usize) -> Option<Vec<u8>> {
    if p.len() == n {
        Some(p.to_vec())
    } else if n == 1 && p.is_empty() {
        Some(vec![0])
    } else {
        None
    }
}

/// A reference-cell `transfer` signature script -> (prefix, suffix, next states). None when the script is not a
/// transfer of a cell of this template (another entry, another program, or not push-only).
pub fn transfer_next_states(sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<Cell>)> {
    let p = pushes(sig)?;
    if p.len() != 9 || p[7] != TAG_TRANSFER {
        return None;
    }
    let redeem = &p[8];
    if redeem.len() <= 1 + WINDOW_LEN {
        return None;
    }
    let (prefix, suffix) = (&redeem[..1], &redeem[1 + WINDOW_LEN..]);
    if template_hash(prefix, suffix) != TEMPLATE || redeem[1] != 0x20 || redeem[2..34] != TEMPLATE {
        return None;
    }
    let (am, ow) = (&p[0], &p[1]);
    if am.is_empty() || am.len() % 8 != 0 {
        return None;
    }
    let n = am.len() / 8;
    if ow.len() != 32 * n || p[4].len() != 32 * n || p[5].len() != 32 * n {
        return None;
    }
    let schemes = byte_field(&p[2], n)?;
    let borrows = byte_field(&p[3], n)?;
    let cells = (0..n)
        .map(|k| Cell {
            amount: u64::from_le_bytes(am[8 * k..8 * k + 8].try_into().unwrap()),
            owner: ow[32 * k..32 * k + 32].try_into().unwrap(),
            owner_scheme: schemes[k],
            borrow_scheme: borrows[k],
            guard: p[4][32 * k..32 * k + 32].try_into().unwrap(),
            commitment: p[5][32 * k..32 * k + 32].try_into().unwrap(),
        })
        .collect();
    Some((prefix.to_vec(), suffix.to_vec(), cells))
}

/// One output of the burn transaction, as the scan needs it.
pub struct Out<'a> {
    pub spk_version: u16,
    pub script: &'a [u8],
    pub covenant_id: Option<[u8; 32]>,
}

/// The burn cells of a transaction: (output index, amount) for every output under `token` whose script is the
/// P2SH of a burn state named by some input's transfer. Sorted by output index.
pub fn burn_cells(outputs: &[Out], sigscripts: &[&[u8]], token: &[u8; 32]) -> Vec<(u32, u64)> {
    let mut candidates: Vec<(Vec<u8>, u64)> = Vec::new();
    for sig in sigscripts {
        if let Some((prefix, suffix, cells)) = transfer_next_states(sig) {
            for c in cells.iter().filter(|c| c.is_burn()) {
                let mut r = prefix.clone();
                r.extend(window(&TEMPLATE, c));
                r.extend_from_slice(&suffix);
                candidates.push((p2sh_script(&r), c.amount));
            }
        }
    }
    let mut found = Vec::new();
    for (i, o) in outputs.iter().enumerate() {
        if o.spk_version != 0 || o.covenant_id.as_ref() != Some(token) {
            continue;
        }
        if let Some((_, a)) = candidates.iter().find(|(s, _)| s.as_slice() == o.script) {
            found.push((i as u32, *a));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> serde_json_lite::J {
        let p = std::env::var("KCC20_FIXTURES")
            .unwrap_or_else(|_| format!("{}/../../bridge-v4/tests/fixtures/bridgemint-fixtures.json", env!("CARGO_MANIFEST_DIR")));
        serde_json_lite::parse(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}")))
    }

    /// The fixture's executed transfer (1,000,000 units -> 600,000 + 400,000, both p2pk): the parser reads both
    /// next states and the input redeem's template, and finds no burn cell.
    #[test]
    fn parses_the_fixture_transfer() {
        let f = fixture();
        let t = f.get("transfer_example");
        let sig = hex::decode(t.get("sig_script").s()).unwrap();
        let (prefix, suffix, cells) = transfer_next_states(&sig).expect("the fixture transfer parses");
        assert_eq!(prefix, vec![0x6b]);
        assert_eq!(suffix.len(), 3885);
        assert_eq!(hex::encode(&suffix), f.get("kcc20").get("suffix").s());
        let mut redeem = vec![0x6b];
        redeem.extend(window(&TEMPLATE, &Cell { amount: 1_000_000, owner: hex::decode("1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f").unwrap().try_into().unwrap(), owner_scheme: 0, borrow_scheme: 0, guard: [0; 32], commitment: [0; 32] }));
        redeem.extend(&suffix);
        assert_eq!(hex::encode(&redeem), t.get("input_cell_redeem").s(), "the input redeem rebuilt from its window");
        assert_eq!(cells.iter().map(|c| c.amount).collect::<Vec<_>>(), vec![600_000, 400_000]);
        assert!(cells.iter().all(|c| !c.is_burn() && c.owner_scheme == 0));
        // outputs as the transfer created them: no burn cell among them
        let token = [0x71u8; 32];
        let scripts: Vec<Vec<u8>> = cells.iter().map(|c| { let mut r = prefix.clone(); r.extend(window(&TEMPLATE, c)); r.extend(&suffix); p2sh_script(&r) }).collect();
        let outs: Vec<Out> = scripts.iter().map(|s| Out { spk_version: 0, script: s, covenant_id: Some(token) }).collect();
        assert!(burn_cells(&outs, &[&sig], &token).is_empty());
    }

    /// The same transfer with its first next state turned into a burn (owner BURN_OWNER, scheme 3): the burn cell
    /// is found with its amount, the change cell is not, and an output under another covenant id is ignored.
    /// The fixture's minted burn cell (amount 7) gives the expected spk independently.
    #[test]
    fn finds_a_burn_cell() {
        let f = fixture();
        let sig = hex::decode(f.get("transfer_example").get("sig_script").s()).unwrap();
        let p = pushes(&sig).unwrap();
        let mut rebuilt = Vec::new();
        let push = |v: &mut Vec<u8>, d: &[u8]| {
            match d.len() {
                n @ 0..=0x4b => v.push(n as u8),
                n @ 0x4c..=0xff => { v.push(0x4c); v.push(n as u8); }
                n => { v.push(0x4d); v.extend_from_slice(&(n as u16).to_le_bytes()); }
            }
            v.extend_from_slice(d);
        };
        let mut owners = p[1].clone();
        owners[..32].copy_from_slice(&BURN_OWNER);
        let mut amounts = p[0].clone();
        amounts[..8].copy_from_slice(&7u64.to_le_bytes());
        let fields = [amounts, owners, vec![3, 0], p[3].clone(), p[4].clone(), p[5].clone(), p[6].clone(), p[7].clone(), p[8].clone()];
        for d in &fields {
            push(&mut rebuilt, d);
        }
        let (prefix, suffix, cells) = transfer_next_states(&rebuilt).unwrap();
        assert!(cells[0].is_burn() && !cells[1].is_burn());
        let token = [0x71u8; 32];
        let scripts: Vec<Vec<u8>> = cells.iter().map(|c| { let mut r = prefix.clone(); r.extend(window(&TEMPLATE, c)); r.extend(&suffix); p2sh_script(&r) }).collect();
        let fixture_burn_spk = f.get("mint_example").get("recipients").a().iter().find(|r| r.get("amount").n() == 7).unwrap().get("spk").s().to_string();
        assert_eq!(hex::encode(&scripts[0]), fixture_burn_spk, "the burn cell of amount 7 is the fixture's");
        let outs = vec![
            Out { spk_version: 0, script: &scripts[1], covenant_id: Some(token) },
            Out { spk_version: 0, script: &scripts[0], covenant_id: Some(token) },
            Out { spk_version: 0, script: &scripts[0], covenant_id: Some([0x72; 32]) },
            Out { spk_version: 1, script: &scripts[0], covenant_id: Some(token) },
        ];
        assert_eq!(burn_cells(&outs, &[&rebuilt], &token), vec![(1, 7)]);
        // the unmodified transfer's sigscript names no burn, so the same outputs give nothing
        assert!(burn_cells(&outs, &[&sig], &token).is_empty());
        // a single burn state written by a minimal encoder: scheme 3 as OP_3, borrow 0 as OP_0
        let mut one = Vec::new();
        push(&mut one, &7u64.to_le_bytes());
        push(&mut one, &BURN_OWNER);
        one.push(0x53);
        one.push(0x00);
        push(&mut one, &[0; 32]);
        push(&mut one, &[0; 32]);
        for d in &fields[6..] {
            push(&mut one, d);
        }
        assert_eq!(burn_cells(&outs, &[&one], &token), vec![(1, 7)]);
        // another program's redeem (template check) and another entry tag are not read
        let mut bad = fields.clone();
        bad[8][200] ^= 1;
        let mut s = Vec::new();
        for d in &bad { push(&mut s, d); }
        assert!(transfer_next_states(&s).is_none());
        let mut bad = fields.clone();
        bad[7] = vec![0xfd, 0x3e, 0xf1, 0x4a];
        let mut s = Vec::new();
        for d in &bad { push(&mut s, d); }
        assert!(transfer_next_states(&s).is_none());
        assert!(pushes(&[0x6a]).is_none(), "OP_RETURN is not a push");
    }

    /// Minimal JSON for the fixture file (strings without escapes, unsigned numbers, objects, arrays).
    mod serde_json_lite {
        pub enum J {
            S(String),
            N(u64),
            A(Vec<J>),
            O(Vec<(String, J)>),
        }
        impl J {
            pub fn get(&self, k: &str) -> &J {
                match self {
                    J::O(v) => &v.iter().find(|(kk, _)| kk == k).unwrap_or_else(|| panic!("fixture: no key {k}")).1,
                    _ => panic!("fixture: not an object"),
                }
            }
            pub fn s(&self) -> &str {
                match self { J::S(s) => s, _ => panic!("fixture: not a string") }
            }
            pub fn n(&self) -> u64 {
                match self { J::N(n) => *n, _ => panic!("fixture: not a number") }
            }
            pub fn a(&self) -> &[J] {
                match self { J::A(v) => v, _ => panic!("fixture: not an array") }
            }
        }
        pub fn parse(s: &str) -> J {
            fn ws(b: &[u8], i: &mut usize) { while *i < b.len() && (b[*i] as char).is_ascii_whitespace() { *i += 1; } }
            fn val(b: &[u8], i: &mut usize) -> J {
                ws(b, i);
                match b[*i] {
                    b'"' => { *i += 1; let st = *i; while b[*i] != b'"' { assert!(b[*i] != b'\\'); *i += 1; } let s = String::from_utf8(b[st..*i].to_vec()).unwrap(); *i += 1; J::S(s) }
                    b'{' => { *i += 1; let mut v = vec![]; loop { ws(b, i); if b[*i] == b'}' { *i += 1; break; } let k = match val(b, i) { J::S(s) => s, _ => panic!() }; ws(b, i); *i += 1; v.push((k, val(b, i))); ws(b, i); if b[*i] == b',' { *i += 1; } } J::O(v) }
                    b'[' => { *i += 1; let mut v = vec![]; loop { ws(b, i); if b[*i] == b']' { *i += 1; break; } v.push(val(b, i)); ws(b, i); if b[*i] == b',' { *i += 1; } } J::A(v) }
                    _ => { let st = *i; while (b[*i] as char).is_ascii_digit() { *i += 1; } J::N(std::str::from_utf8(&b[st..*i]).unwrap().parse().unwrap()) }
                }
            }
            val(s.as_bytes(), &mut 0)
        }
    }
}
