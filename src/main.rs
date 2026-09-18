use std::env;

use newcamd_lib::{Client, EcmRequest, NewcamdConfig};

#[tokio::main(flavor = "current_thread")]
async fn main() -> newcamd_lib::Result<()> {
    let arguments = Arguments::parse()?;

    let config = NewcamdConfig {
        host: arguments.host,
        port: arguments.port,
        username: arguments.username,
        password: arguments.password,
        des_key_14: arguments.des_key_14,
        provider: arguments.provider,
        ..NewcamdConfig::default()
    };

    let (client, connection) = Client::connect(config).await?;
    println!("connected: CAID {:04X}", client.caid());

    let connection_task = tokio::spawn(connection.run());
    let section = arguments.ecm;
    let response = client
        .send_ecm(&EcmRequest {
            sid: arguments.sid,
            caid: 0,
            provider: arguments.provider,
            section,
        })
        .await?;

    if response.found {
        println!("control word: {}", hex(&response.cw));
    } else {
        println!("ECM was not found");
    }

    connection_task.abort();
    Ok(())
}

struct Arguments {
    host: String,
    port: u16,
    username: String,
    password: String,
    des_key_14: [u8; 14],
    sid: u16,
    provider: u32,
    ecm: Vec<u8>,
}

impl Arguments {
    fn parse() -> newcamd_lib::Result<Self> {
        let mut arguments = env::args().skip(1);
        let mut values = std::collections::HashMap::new();

        while let Some(name) = arguments.next() {
            if name == "--help" || name == "-h" {
                println!(
                    "Usage: newcamd_lib --host HOST --port PORT --user USER --pass PASSWORD --des-key HEX --ecm HEX [--sid SID] [--provider PROVIDER]"
                );
                std::process::exit(0);
            }

            let value = arguments.next().ok_or_else(|| {
                newcamd_lib::NewcamdError::InvalidData(format!("missing value for {name}"))
            })?;
            if !name.starts_with("--") {
                return Err(newcamd_lib::NewcamdError::InvalidData(format!(
                    "unexpected argument {name}"
                )));
            }
            values.insert(name, value);
        }

        let des_key = parse_hex(required(&values, "--des-key")?)?;
        let des_key_14 = des_key.try_into().map_err(|key: Vec<u8>| {
            newcamd_lib::NewcamdError::InvalidData(format!(
                "--des-key must contain exactly 14 bytes, got {}",
                key.len()
            ))
        })?;

        Ok(Self {
            host: required(&values, "--host")?.to_string(),
            port: parse_number(required(&values, "--port")?, "--port")?,
            username: required(&values, "--user")?.to_string(),
            password: required(&values, "--pass")?.to_string(),
            des_key_14,
            sid: optional_number(&values, "--sid", 0)?,
            provider: optional_number(&values, "--provider", 0)?,
            ecm: parse_hex(required(&values, "--ecm")?)?,
        })
    }
}

fn required<'a>(
    values: &'a std::collections::HashMap<String, String>,
    name: &str,
) -> newcamd_lib::Result<&'a str> {
    values.get(name).map(String::as_str).ok_or_else(|| {
        newcamd_lib::NewcamdError::InvalidData(format!("missing required argument {name}"))
    })
}

fn parse_number<T>(value: &str, name: &str) -> newcamd_lib::Result<T>
where
    T: TryFrom<u64> + std::str::FromStr,
{
    let number = if let Some(value_without_prefix) = value.strip_prefix("0x") {
        u64::from_str_radix(value_without_prefix, 16)
    } else {
        value.parse()
    }
    .map_err(|_| {
        newcamd_lib::NewcamdError::InvalidData(format!("invalid {name} value: {value}"))
    })?;

    T::try_from(number).map_err(|_| {
        newcamd_lib::NewcamdError::InvalidData(format!("invalid {name} value: {value}"))
    })
}

fn optional_number<T>(
    values: &std::collections::HashMap<String, String>,
    name: &str,
    default: T,
) -> newcamd_lib::Result<T>
where
    T: TryFrom<u64> + std::str::FromStr,
{
    values
        .get(name)
        .map(|value| parse_number(value, name))
        .unwrap_or(Ok(default))
}

fn parse_hex(value: &str) -> newcamd_lib::Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(newcamd_lib::NewcamdError::InvalidData(
            "NEWCAMD_ECM_HEX must have an even number of characters".to_string(),
        ));
    }

    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| {
                newcamd_lib::NewcamdError::InvalidData(
                    "NEWCAMD_ECM_HEX must contain only hexadecimal characters".to_string(),
                )
            })
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}
