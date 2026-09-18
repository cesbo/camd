use des::Des;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use md5::{Digest, Md5};
use rand::RngCore;

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

    let mut rng = rand::thread_rng();
    for _ in 0..no_pad_bytes {
        buffer.push((rng.next_u32() & 0xFF) as u8);
    }

    let mut checksum = 0_u8;
    for byte in &buffer[2..] {
        checksum ^= *byte;
    }
    buffer.push(checksum);

    let mut ivec = [0_u8; 8];
    rng.fill_bytes(&mut ivec);

    let mut work_ivec = ivec;
    for block in buffer[2..].chunks_exact_mut(8) {
        for i in 0..8 {
            block[i] ^= work_ivec[i];
        }
        triple_des_hash_encrypt_block(block, des_key)?;
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
    let mut next_ivec = [0_u8; 8];
    next_ivec.copy_from_slice(&buffer[data_len..]);

    let mut pos = 2;
    while pos < data_len {
        let mut ivec = [0_u8; 8];
        ivec.copy_from_slice(&next_ivec);
        next_ivec.copy_from_slice(&buffer[pos..pos + 8]);

        let block = &mut buffer[pos..pos + 8];
        triple_des_crypt_decrypt_block(block, des_key)?;
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

fn triple_des_hash_encrypt_block(block: &mut [u8], key: &[u8; 16]) -> Result<()> {
    let k1 =
        Des::new_from_slice(&key[0..8]).map_err(|_| NewcamdError::Crypto("invalid DES key K1"))?;
    let k2 =
        Des::new_from_slice(&key[8..16]).map_err(|_| NewcamdError::Crypto("invalid DES key K2"))?;

    let mut b = GenericArray::clone_from_slice(block);
    k1.encrypt_block(&mut b);
    k2.decrypt_block(&mut b);
    k1.encrypt_block(&mut b);
    block.copy_from_slice(&b);
    Ok(())
}

fn triple_des_crypt_decrypt_block(block: &mut [u8], key: &[u8; 16]) -> Result<()> {
    let k1 =
        Des::new_from_slice(&key[0..8]).map_err(|_| NewcamdError::Crypto("invalid DES key K1"))?;
    let k2 =
        Des::new_from_slice(&key[8..16]).map_err(|_| NewcamdError::Crypto("invalid DES key K2"))?;

    let mut b = GenericArray::clone_from_slice(block);
    k1.decrypt_block(&mut b);
    k2.encrypt_block(&mut b);
    k1.decrypt_block(&mut b);
    block.copy_from_slice(&b);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::md5_crypt;

    #[test]
    fn md5_crypt_known_vector() {
        let hash = md5_crypt("password", "abcdefgh");
        assert_eq!(hash, "$1$abcdefgh$G//4keteveJp0qb8z2DxG/");
    }
}
