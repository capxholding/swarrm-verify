// Apache-2.0 (public verifier repo)
//! Shared deterministic-CBOR wire primitives for both verifier profiles.
//!
//! This module owns only item-head encoding and the bounded iterative scan.
//! Profile-specific value and map rules remain in their respective modules.

/// Emit a minimal CBOR item head. COSE, certificates, and B28 reuse this exact
/// primitive so their deterministic encodings cannot drift on width selection.
pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    match arg {
        0..=23 => out.push((major << 5) | arg as u8),
        24..=0xff => out.extend_from_slice(&[(major << 5) | 24, arg as u8]),
        0x100..=0xffff => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push((major << 5) | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

/// Parse one item head at `i` -> (major, argument, next offset). Rejects tags,
/// floats, simple values other than false/true/null, indefinite/reserved info.
pub(crate) fn read_head(data: &[u8], i: usize) -> Option<(u8, u64, usize)> {
    let byte = *data.get(i)?;
    let (major, info) = (byte >> 5, byte & 0x1f);
    let i = i + 1;
    if major == 6 {
        return None; // tag
    }
    if major == 7 {
        return matches!(info, 20..=22).then_some((major, 0, i)); // false/true/null only
    }
    if info < 24 {
        return Some((major, u64::from(info), i));
    }
    if info > 27 {
        return None; // 28-30 reserved, 31 indefinite
    }
    let width = 1usize << (info - 24);
    let raw = data.get(i..i + width)?;
    let mut arg = 0u64;
    for byte in raw {
        arg = (arg << 8) | u64::from(*byte);
    }
    Some((major, arg, i + width))
}

/// Iterative structural scan of one item. An explicit stack bounds hostile
/// nesting; every claimed length must fit in the buffer before materialization.
fn scan_string(data: &[u8], i: &mut usize, arg: u64) -> Option<()> {
    let remaining = data.len().checked_sub(*i)?;
    (arg <= remaining as u64).then_some(())?;
    *i += arg as usize;
    Some(())
}

fn scan_container(data: &[u8], i: usize, major: u8, arg: u64, stack: &mut Vec<u64>, max_depth: usize) -> Option<bool> {
    let count = if major == 4 { arg } else { arg.checked_mul(2)? };
    if count > (data.len() - i) as u64 {
        return None; // every member needs >= 1 byte
    }
    if count == 0 {
        return Some(false);
    }
    if stack.len() >= max_depth {
        return None;
    }
    stack.push(count);
    Some(true)
}

fn scan_item(data: &[u8], i: &mut usize, major: u8, arg: u64, stack: &mut Vec<u64>, max_depth: usize) -> Option<bool> {
    match major {
        2 | 3 => scan_string(data, i, arg).map(|()| false),
        4 | 5 => scan_container(data, *i, major, arg, stack, max_depth),
        _ => Some(false),
    }
}

fn complete_item(stack: &mut Vec<u64>) -> bool {
    while let Some(top) = stack.last_mut() {
        *top -= 1;
        if *top > 0 {
            return false;
        }
        stack.pop();
    }
    true
}

pub(crate) fn structural_scan(data: &[u8], max_depth: usize, max_items: usize) -> Option<usize> {
    let mut stack: Vec<u64> = Vec::new();
    let mut i = 0usize;
    let mut items = 0usize;
    loop {
        items = items.checked_add(1)?;
        if items > max_items {
            return None;
        }
        let (major, arg, next) = read_head(data, i)?;
        i = next;
        if scan_item(data, &mut i, major, arg, &mut stack, max_depth)? {
            continue;
        }
        if complete_item(&mut stack) {
            return Some(i);
        }
    }
}
