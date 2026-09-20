use des::TdesEde2;
use des::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use md5::{Digest, Md5};

use crate::error::{NewcamdError, Result};

const MD5_CRYPT_B64: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub fn derive_login_key(key1: &[u8], key2: &[u8]) -> Result<[u8; 16]> {
    if key1.len() != 14 {
        return Err(NewcamdError::InvalidData(
            "newcamd key must be exactly 14 bytes".to_string(),
        ));
    }

    let mut des14 = [0_u8; 14];
    des14.copy_from_slice(key1);
    for (idx, byte) in key2.iter().enumerate() {
        des14[idx % 14] ^= *byte;
    }

    Ok(key_spread(&des14))
}

pub fn encrypt_message(buffer: &mut Vec<u8>, des_key: &[u8; 16]) -> Result<()> {
    let no_pad_bytes = (8 - ((buffer.len() - 1) % 8)) % 8;
    if buffer.len() + no_pad_bytes + 1 + 8 >= crate::protocol::CWS_NETMSGSIZE {
        return Err(NewcamdError::Protocol("packet too large"));
    }

    for _ in 0..no_pad_bytes {
        buffer.push(rand::random());
    }

    let mut checksum = 0_u8;
    for byte in &buffer[2..] {
        checksum ^= *byte;
    }
    buffer.push(checksum);

    let ivec: [u8; 8] = rand::random();
    let cipher = TdesEde2::new(des_key.into());

    let mut work_ivec = ivec;
    for block in buffer[2..].chunks_exact_mut(8) {
        let block: &mut Block<TdesEde2> = block.try_into().expect("8-byte chunk");
        for i in 0..8 {
            block[i] ^= work_ivec[i];
        }
        cipher.encrypt_block(block);
        work_ivec.copy_from_slice(block);
    }

    buffer.extend_from_slice(&ivec);
    Ok(())
}

pub fn decrypt_message(buffer: &mut [u8], des_key: &[u8; 16]) -> Result<usize> {
    if (buffer.len() - 2) % 8 != 0 || (buffer.len() - 2) < 16 {
        return Err(NewcamdError::Protocol("invalid encrypted payload length"));
    }

    let data_len = buffer.len() - 8;
    let cipher = TdesEde2::new(des_key.into());
    let mut next_ivec = [0_u8; 8];
    next_ivec.copy_from_slice(&buffer[data_len..]);

    let mut pos = 2;
    while pos < data_len {
        let mut ivec = [0_u8; 8];
        ivec.copy_from_slice(&next_ivec);
        next_ivec.copy_from_slice(&buffer[pos..pos + 8]);

        let block: &mut Block<TdesEde2> = (&mut buffer[pos..pos + 8])
            .try_into()
            .expect("8-byte chunk");
        cipher.decrypt_block(block);
        for i in 0..8 {
            block[i] ^= ivec[i];
        }
        pos += 8;
    }

    let mut checksum = 0_u8;
    for byte in &buffer[2..data_len] {
        checksum ^= *byte;
    }
    if checksum != 0 {
        return Err(NewcamdError::Crypto("checksum mismatch"));
    }

    Ok(data_len)
}

pub fn md5_crypt(password: &str, salt: &str) -> String {
    let salt = extract_salt(salt);
    let password_bytes = password.as_bytes();
    let salt_bytes = salt.as_bytes();

    let mut ctx = Md5::new();
    ctx.update(password_bytes);
    ctx.update(b"$1$");
    ctx.update(salt_bytes);

    let mut alt = Md5::new();
    alt.update(password_bytes);
    alt.update(salt_bytes);
    alt.update(password_bytes);
    let alt_sum = alt.finalize();

    let mut pw_len = password_bytes.len();
    while pw_len > 0 {
        let take = pw_len.min(16);
        ctx.update(&alt_sum[..take]);
        pw_len -= take;
    }

    let mut bit_len = password_bytes.len();
    while bit_len > 0 {
        if (bit_len & 1) == 1 {
            ctx.update([0_u8]);
        } else {
            ctx.update([password_bytes[0]]);
        }
        bit_len >>= 1;
    }

    let mut final_sum = ctx.finalize().to_vec();

    for i in 0..1000 {
        let mut loop_ctx = Md5::new();
        if (i & 1) == 1 {
            loop_ctx.update(password_bytes);
        } else {
            loop_ctx.update(&final_sum);
        }

        if i % 3 != 0 {
            loop_ctx.update(salt_bytes);
        }

        if i % 7 != 0 {
            loop_ctx.update(password_bytes);
        }

        if (i & 1) == 1 {
            loop_ctx.update(&final_sum);
        } else {
            loop_ctx.update(password_bytes);
        }

        final_sum = loop_ctx.finalize().to_vec();
    }

    let mut out = String::with_capacity(34);
    out.push_str("$1$");
    out.push_str(&salt);
    out.push('$');
    out.push_str(&to_b64(final_sum[0], final_sum[6], final_sum[12], 4));
    out.push_str(&to_b64(final_sum[1], final_sum[7], final_sum[13], 4));
    out.push_str(&to_b64(final_sum[2], final_sum[8], final_sum[14], 4));
    out.push_str(&to_b64(final_sum[3], final_sum[9], final_sum[15], 4));
    out.push_str(&to_b64(final_sum[4], final_sum[10], final_sum[5], 4));
    out.push_str(&to_b64(0, 0, final_sum[11], 2));
    out
}

fn extract_salt(raw: &str) -> String {
    let mut value = raw;
    if let Some(stripped) = value.strip_prefix("$1$") {
        value = stripped;
    }
    if let Some(pos) = value.find('$') {
        value = &value[..pos];
    }
    value.chars().take(8).collect()
}

fn to_b64(b2: u8, b1: u8, b0: u8, count: usize) -> String {
    let mut value = ((b2 as u32) << 16) | ((b1 as u32) << 8) | (b0 as u32);
    let mut out = String::with_capacity(count);
    for _ in 0..count {
        out.push(MD5_CRYPT_B64[(value & 0x3F) as usize] as char);
        value >>= 6;
    }
    out
}

fn key_spread(normal: &[u8; 14]) -> [u8; 16] {
    let mut spread = [0_u8; 16];
    spread[0] = normal[0] & 0xFE;
    spread[1] = ((normal[0] << 7) | (normal[1] >> 1)) & 0xFE;
    spread[2] = ((normal[1] << 6) | (normal[2] >> 2)) & 0xFE;
    spread[3] = ((normal[2] << 5) | (normal[3] >> 3)) & 0xFE;
    spread[4] = ((normal[3] << 4) | (normal[4] >> 4)) & 0xFE;
    spread[5] = ((normal[4] << 3) | (normal[5] >> 5)) & 0xFE;
    spread[6] = ((normal[5] << 2) | (normal[6] >> 6)) & 0xFE;
    spread[7] = normal[6] << 1;
    spread[8] = normal[7] & 0xFE;
    spread[9] = ((normal[7] << 7) | (normal[8] >> 1)) & 0xFE;
    spread[10] = ((normal[8] << 6) | (normal[9] >> 2)) & 0xFE;
    spread[11] = ((normal[9] << 5) | (normal[10] >> 3)) & 0xFE;
    spread[12] = ((normal[10] << 4) | (normal[11] >> 4)) & 0xFE;
    spread[13] = ((normal[11] << 3) | (normal[12] >> 5)) & 0xFE;
    spread[14] = ((normal[12] << 2) | (normal[13] >> 6)) & 0xFE;
    spread[15] = normal[13] << 1;

    adjust_odd_parity(&mut spread);
    spread
}

fn adjust_odd_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        let mut parity = 1_u8;
        for bit in 1..8 {
            if ((*byte >> bit) & 0x1) == 1 {
                parity ^= 1;
            }
        }
        *byte = (*byte & 0xFE) | parity;
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt_message, encrypt_message, md5_crypt};

    const KEY: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    #[test]
    fn md5_crypt_known_vector() {
        let hash = md5_crypt("password", "abcdefgh");
        assert_eq!(hash, "$1$abcdefgh$G//4keteveJp0qb8z2DxG/");
    }

    /// Ciphertext from `openssl enc -des-ede-cbc -K <KEY> -iv 0011223344556677 -nopad`
    /// over the bytes 0x00..=0x0F, whose XOR checksum is zero.
    #[test]
    fn decrypt_message_openssl_vector() {
        let mut wire = vec![
            0x00, 0x00, // length prefix, not encrypted
            0x81, 0x8c, 0x0b, 0xf6, 0x65, 0xca, 0x88, 0xed, 0x55, 0x29, 0x6f, 0x9d, 0xbc, 0xe2,
            0xaf, 0x50, // ciphertext
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // iv
        ];
        let plain_len = decrypt_message(&mut wire, &KEY).unwrap();
        assert_eq!(plain_len, 18);
        assert_eq!(&wire[2..18], &(0_u8..16).collect::<Vec<_>>()[..]);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut buffer = vec![0, 0, 0xE3, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let plain = buffer.clone();
        encrypt_message(&mut buffer, &KEY).unwrap();
        assert_eq!((buffer.len() - 2) % 8, 0);
        let plain_len = decrypt_message(&mut buffer, &KEY).unwrap();
        assert_eq!(&buffer[..plain.len()], &plain[..]);
        assert!(plain_len >= plain.len());
    }
}
