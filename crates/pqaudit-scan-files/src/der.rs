//! A small DER reader and writer.
//!
//! The reader borrows from the input. It copies nothing and allocates nothing.
//! It supports tags of one byte and lengths of up to 4 bytes.

/// The tag of an INTEGER.
pub(crate) const INTEGER: u8 = 0x02;
/// The tag of a BIT STRING.
pub(crate) const BIT_STRING: u8 = 0x03;
/// The tag of an OCTET STRING.
pub(crate) const OCTET_STRING: u8 = 0x04;
/// The tag of a NULL.
pub(crate) const NULL: u8 = 0x05;
/// The tag of an OBJECT IDENTIFIER.
pub(crate) const OID: u8 = 0x06;
/// The tag of a SEQUENCE.
pub(crate) const SEQUENCE: u8 = 0x30;

/// One DER element.
#[derive(Clone, Copy)]
pub(crate) struct Tlv<'a> {
    /// The tag byte.
    pub tag: u8,
    /// The content bytes.
    pub content: &'a [u8],
    /// The whole element: tag, length, and content.
    pub whole: &'a [u8],
}

/// Read one element from the start of the data. Return it and the bytes after it.
pub(crate) fn read(data: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *data.first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *data.get(1)?;
    let (header, length) = if first < 0x80 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(2..2 + count)?;
        let length = bytes
            .iter()
            .fold(0usize, |total, byte| (total << 8) | usize::from(*byte));
        (2 + count, length)
    };
    let end = header.checked_add(length)?;
    let whole = data.get(..end)?;
    Some((
        Tlv {
            tag,
            content: &whole[header..],
            whole,
        },
        &data[end..],
    ))
}

/// Read one element and check its tag.
pub(crate) fn read_tag(data: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    read(data).filter(|(tlv, _)| tlv.tag == tag)
}

/// Write one element.
pub(crate) fn write(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// Return the number of bits of a big-endian number without leading zero bits.
pub(crate) fn bit_length(bytes: &[u8]) -> Option<u32> {
    let skip = bytes.iter().take_while(|byte| **byte == 0).count();
    let rest = &bytes[skip..];
    let first = *rest.first()?;
    let bits = rest.len() * 8 - first.leading_zeros() as usize;
    u32::try_from(bits).ok()
}

/// Write the content bytes of an OBJECT IDENTIFIER as dotted text.
pub(crate) fn oid_text(content: &[u8]) -> Option<String> {
    let (first, rest) = content.split_first()?;
    let mut text = format!("{}.{}", first / 40, first % 40);
    let mut value: u64 = 0;
    for byte in rest {
        value = value
            .checked_mul(128)?
            .checked_add(u64::from(byte & 0x7f))?;
        if byte & 0x80 == 0 {
            text.push('.');
            text.push_str(&value.to_string());
            value = 0;
        }
    }
    (rest.last()? & 0x80 == 0).then_some(text)
}
