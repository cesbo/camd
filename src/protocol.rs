pub const CWS_NETMSGSIZE: usize = 500;
pub const LOGIN_INIT_SEQ_LEN: usize = 14;
pub const HEADER_SIZE_525: usize = 12;

pub mod msg {
    pub const MSG_CLIENT_2_SERVER_LOGIN: u8 = 0xE0;
    pub const MSG_CLIENT_2_SERVER_LOGIN_ACK: u8 = 0xE1;
    pub const MSG_CLIENT_2_SERVER_LOGIN_NAK: u8 = 0xE2;
    pub const MSG_CARD_DATA_REQ: u8 = 0xE3;
    pub const MSG_CARD_DATA: u8 = 0xE4;
    pub const MSG_KEEPALIVE: u8 = 0xFD;
    /// DVB CA section table_id range used for EMM (ECM uses 0x80/0x81).
    pub const EMM_TABLE_ID_RANGE: std::ops::RangeInclusive<u8> = 0x82..=0x8F;
}

#[derive(Debug, Clone, Copy)]
pub struct Header525 {
    pub msg_id: u16,
    pub sid: u16,
    pub caid: u16,
    pub provider: u32,
    pub flags: u8,
}

#[derive(Debug, Clone)]
pub struct NewcamdPacket {
    pub header: Header525,
    pub command: u8,
    pub data: Vec<u8>,
}

pub fn encode_payload(command: u8, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(3 + data.len());
    payload.push(command);
    payload.push(0);
    payload.push(0);
    payload.extend_from_slice(data);
    patch_payload_len(&mut payload);
    payload
}

pub fn patch_payload_len(payload: &mut [u8]) {
    if payload.len() < 3 {
        return;
    }

    let body_len = payload.len() - 3;
    payload[1] = (payload[1] & 0xF0) | (((body_len >> 8) & 0x0F) as u8);
    payload[2] = (body_len & 0xFF) as u8;
}

pub fn parse_decrypted_525(buffer: &[u8]) -> Option<NewcamdPacket> {
    if buffer.len() < 15 {
        return None;
    }

    let payload_len = ((((buffer[13] & 0x0F) as usize) << 8) | (buffer[14] as usize)) + 3;
    if HEADER_SIZE_525 + payload_len > buffer.len() {
        return None;
    }

    let payload = &buffer[HEADER_SIZE_525..HEADER_SIZE_525 + payload_len];
    if payload.len() < 3 {
        return None;
    }

    let msg_id = u16::from_be_bytes([buffer[2], buffer[3]]);
    let sid = u16::from_be_bytes([buffer[4], buffer[5]]);
    let caid = u16::from_be_bytes([buffer[6], buffer[7]]);
    let provider = ((buffer[8] as u32) << 16) | ((buffer[9] as u32) << 8) | (buffer[10] as u32);
    let flags = buffer[11];

    Some(NewcamdPacket {
        header: Header525 {
            msg_id,
            sid,
            caid,
            provider,
            flags,
        },
        command: payload[0],
        data: payload[3..].to_vec(),
    })
}
