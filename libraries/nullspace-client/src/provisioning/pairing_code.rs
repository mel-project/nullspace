use crate::internal::InternalRpcError;

pub(crate) fn format_pairing_code(code: u64) -> String {
    let digits = code.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 4);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(4) {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

pub(crate) fn parse_pairing_code_input(code: &str) -> Result<u64, InternalRpcError> {
    let normalized: String = code
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '-')
        .collect();
    if normalized.is_empty() || !normalized.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(InternalRpcError::Other(
            "invalid pairing code format".into(),
        ));
    }
    normalized
        .parse::<u64>()
        .map_err(|_| InternalRpcError::Other("pairing code is out of range".into()))
}

pub(crate) fn encode_pairing_code(channel: u32, token: u32) -> Result<u64, InternalRpcError> {
    let mut bits = Vec::new();
    bits.push(true);
    encode_elias_delta_bits(u64::from(channel) + 1, &mut bits);
    for index in (0..32).rev() {
        bits.push(((token >> index) & 1) == 1);
    }
    if bits.len() > 64 {
        return Err(InternalRpcError::Other(
            "pairing channel is too large to encode".into(),
        ));
    }
    let mut value = 0u64;
    for bit in bits {
        value = (value << 1) | u64::from(bit);
    }
    Ok(value)
}

pub(crate) fn decode_pairing_code(code: u64) -> Result<(u32, u32), InternalRpcError> {
    if code == 0 {
        return Err(InternalRpcError::Other("invalid pairing code".into()));
    }
    let bit_len = 64 - code.leading_zeros() as usize;
    let mut bits = Vec::with_capacity(bit_len);
    for shift in (0..bit_len).rev() {
        bits.push(((code >> shift) & 1) == 1);
    }
    if bits.first().copied() != Some(true) {
        return Err(InternalRpcError::Other(
            "invalid pairing code prefix".into(),
        ));
    }
    let mut cursor = 1;
    let delta = decode_elias_delta_bits(&bits, &mut cursor)?;
    if delta == 0 {
        return Err(InternalRpcError::Other(
            "invalid pairing code channel".into(),
        ));
    }
    let channel_u64 = delta - 1;
    let channel = u32::try_from(channel_u64)
        .map_err(|_| InternalRpcError::Other("pairing code channel out of range".into()))?;
    if bits.len() != cursor + 32 {
        return Err(InternalRpcError::Other(
            "invalid pairing code length".into(),
        ));
    }
    let mut token = 0u32;
    for bit in bits.iter().skip(cursor) {
        token = (token << 1) | u32::from(*bit);
    }
    Ok((channel, token))
}

fn encode_elias_delta_bits(value: u64, out: &mut Vec<bool>) {
    let value_bits = usize::BITS as usize - value.leading_zeros() as usize;
    let len_bits = usize::BITS as usize - value_bits.leading_zeros() as usize;
    out.extend(std::iter::repeat_n(false, len_bits.saturating_sub(1)));
    for shift in (0..len_bits).rev() {
        out.push(((value_bits >> shift) & 1) == 1);
    }
    for shift in (0..value_bits.saturating_sub(1)).rev() {
        out.push(((value >> shift) & 1) == 1);
    }
}

fn decode_elias_delta_bits(bits: &[bool], cursor: &mut usize) -> Result<u64, InternalRpcError> {
    let mut zeros = 0usize;
    while *cursor + zeros < bits.len() && !bits[*cursor + zeros] {
        zeros += 1;
    }
    if *cursor + zeros >= bits.len() {
        return Err(InternalRpcError::Other("invalid pairing code delta".into()));
    }
    *cursor += zeros;
    let len_bits = zeros + 1;
    if *cursor + len_bits > bits.len() {
        return Err(InternalRpcError::Other("invalid pairing code delta".into()));
    }
    let mut value_bits = 0usize;
    for bit in &bits[*cursor..*cursor + len_bits] {
        value_bits = (value_bits << 1) | usize::from(*bit);
    }
    *cursor += len_bits;
    if value_bits == 0 {
        return Err(InternalRpcError::Other("invalid pairing code delta".into()));
    }
    if *cursor + value_bits.saturating_sub(1) > bits.len() {
        return Err(InternalRpcError::Other("invalid pairing code delta".into()));
    }
    let mut value = 1u64;
    for bit in &bits[*cursor..*cursor + value_bits.saturating_sub(1)] {
        value = (value << 1) | u64::from(*bit);
    }
    *cursor += value_bits.saturating_sub(1);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{decode_pairing_code, encode_pairing_code, format_pairing_code, parse_pairing_code_input};

    #[test]
    fn pairing_code_roundtrip() {
        let channels = [0u32, 1, 2, 9, 63, 255, 1_024, 65_535, 1_000_000];
        let tokens = [0u32, 1, 0x1234_5678, u32::MAX];
        for channel in channels {
            for token in tokens {
                let code = encode_pairing_code(channel, token).expect("encode code");
                let (decoded_channel, decoded_token) =
                    decode_pairing_code(code).expect("decode code");
                assert_eq!(decoded_channel, channel);
                assert_eq!(decoded_token, token);
            }
        }
    }

    #[test]
    fn pairing_code_parse_normalizes_spaces_and_dashes() {
        let code = 1234_5678_9012u64;
        let display = format_pairing_code(code);
        assert_eq!(
            parse_pairing_code_input(&display).expect("parse display"),
            code
        );
        assert_eq!(
            parse_pairing_code_input("1234-5678-9012").expect("parse dashed"),
            code
        );
    }

    #[test]
    fn pairing_code_rejects_bad_input() {
        assert!(parse_pairing_code_input("").is_err());
        assert!(parse_pairing_code_input("abc").is_err());
        assert!(parse_pairing_code_input("12 34 x").is_err());
    }
}
