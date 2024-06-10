use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Key;
use aes_gcm::Nonce;
use android_logger::Config;
use anyhow::anyhow;
use anyhow::Result;
use data_encoding::BASE32;
use jni::objects::GlobalRef;
use jni::objects::JByteArray;
use jni::objects::JClass;
use jni::objects::JObject;
use jni::JNIEnv;
use log::debug;
use log::error;
use log::LevelFilter;
use pbkdf2::pbkdf2_hmac;
use serde::Deserialize;
use serde::Serialize;
use sha1::Digest;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Sha512;
use std::fmt;
use std::fmt::Write;
use std::str;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct Entity {
    algorithm: String,
    digits: usize,
    issuer: Option<String>,
    label: Option<String>,
    period: u64,
    secret: String,
}

impl Entity {
    fn generate_totp(&self) -> Result<String> {
        let mut secret_decoded = BASE32.decode(self.secret.as_bytes())?;
        let hex_secret = secret_decoded.iter().fold(String::new(), |mut output, &x| {
            let _ = write!(&mut output, "{x:02X}");
            output
        });
        secret_decoded.zeroize();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let steps = time_steps(now.as_secs(), self.period, 0);
        Ok(generate_totp(
            hex_secret,
            &steps,
            self.digits,
            &self.algorithm,
        ))
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entity")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("issuer", &self.issuer)
            .field("label", &self.label)
            .field("period", &self.label)
            .finish()
    }
}

fn native_activity_create() {
    #[cfg(debug_assertions)]
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Debug)
            .with_tag("rustandroidtotp"),
    );
    #[cfg(not(debug_assertions))]
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Off)
            .with_tag("rustandroidtotp"),
    );
}

fn use_callback(env: &mut JNIEnv, callback: &GlobalRef, message: &str) {
    let message = &env.new_string(message).unwrap();
    env.call_method(
        callback,
        "callback",
        "(Ljava/lang/String;)V",
        &[message.into()],
    )
    .unwrap();
}

#[no_mangle]
pub extern "system" fn Java_com_victorprokhorov_rustandroidtotp_Bindings_main<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    encrypted_database: JByteArray<'local>,
    password: JByteArray<'local>,
    callback: JObject<'local>,
) {
    native_activity_create();
    let jvm = env.get_java_vm().unwrap();
    let encrypted_database = env.convert_byte_array(encrypted_database).unwrap();
    let mut password = env.convert_byte_array(password).unwrap();
    let callback = env.new_global_ref(callback).unwrap();
    debug!("Arguments parsed");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        tx.send(()).unwrap();
        let mut env = jvm.attach_current_thread().unwrap();
        let mut json_string = match decrypt_database(&encrypted_database, &password) {
            Ok(json_string) => json_string,
            Err(err) => {
                password.zeroize();
                error!("Failed to decrypt database {err}");
                use_callback(&mut env, &callback, "Failed to decrypt database");
                return;
            }
        };
        debug!("Database decrypted");
        let entities: Vec<Entity> = match serde_json::from_str(&json_string) {
            Ok(entities) => entities,
            Err(err) => {
                json_string.zeroize();
                password.zeroize();
                error!("Failed to deserialize JSON string. {err}");
                use_callback(&mut env, &callback, "Failed to decrypt database");
                return;
            }
        };
        json_string.zeroize();
        drop(json_string);
        debug!("{entities:?}");
        loop {
            let entries: String = entities
                .iter()
                .map(|entity| match entity.generate_totp() {
                    Ok(mut totp) => {
                        let mut entry = String::new();
                        if let Some(issuer) = &entity.issuer {
                            entry.push_str(issuer);
                        }
                        if let Some(label) = &entity.label {
                            entry.push(' ');
                            entry.push_str(label);
                        }
                        if !entry.is_empty() {
                            entry.push(' ');
                        }
                        entry.push_str(&totp);
                        totp.zeroize();
                        entry
                    }
                    Err(err) => {
                        error!("Failed to generate TOTP. {err}");
                        let mut entry = String::new();
                        if let Some(issuer) = &entity.issuer {
                            entry.push_str(issuer);
                        }
                        if let Some(label) = &entity.label {
                            entry.push(' ');
                            entry.push_str(label);
                        }
                        entry
                    }
                })
                .collect();
            use_callback(&mut env, &callback, &entries);
            thread::sleep(Duration::from_secs(1));
        }
    });
    rx.recv().unwrap();
}

fn decrypt_database(database: &[u8], password: &[u8]) -> Result<String> {
    let rounds = u32::from_be_bytes(database[..4].try_into()?);
    let salt = &database[4..16];
    let cipher_text = &database[16..];
    let mut derived_key = [0; 32];
    pbkdf2_hmac::<Sha1>(password, salt, rounds, &mut derived_key);
    let mut plain_text_buffer = decrypt_aes256gcm(derived_key, cipher_text)?;
    let plain_text_string = str::from_utf8(&plain_text_buffer)?.to_string();
    plain_text_buffer.zeroize();
    Ok(plain_text_string)
}

fn decrypt_aes256gcm(
    key: [u8; 32],
    cipher_text: &[u8],
) -> Result<aes_gcm::aead::heapless::Vec<u8, 4096>> {
    let iv = &cipher_text[..12];
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    let mut buffer = aes_gcm::aead::heapless::Vec::<u8, 4096>::new();
    buffer
        .extend_from_slice(&cipher_text[12..])
        .map_err(|()| anyhow!("Extend from slice failed"))?;
    cipher
        .decrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|err| anyhow!("Decrypt in place failed. {:?}", err))?;
    Ok(buffer)
}

fn time_steps(value: u64, period: u64, start: u64) -> String {
    format!("{:016X}", (value - start) / period)
}

#[must_use]
pub fn generate_totp(
    mut key: String,
    steps: &str,
    return_digits: usize,
    algorithm: &str,
) -> String {
    let mut key_bytes = hex_str_to_bytes(&key);
    key.zeroize();
    let steps = hex_str_to_bytes(steps);
    let mut hash = match algorithm {
        "SHA256" => hmac_sha256(&key_bytes, &steps),
        "SHA512" => hmac_sha512(&key_bytes, &steps),
        _ => hmac_sha1(&key_bytes, &steps),
    };
    key_bytes.zeroize();
    let offset = (hash[hash.len() - 1] & 0xf) as usize;
    let binary = u32::from(hash[offset] & 0x7f) << 24
        | u32::from(hash[offset + 1]) << 16
        | u32::from(hash[offset + 2]) << 8
        | u32::from(hash[offset + 3]);
    hash.zeroize();
    let totp = binary % DIGITS_POWER[return_digits];
    format!("{totp:0return_digits$}")
}

const DIGITS_POWER: [u32; 9] = [
    1,
    10,
    100,
    1000,
    10000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
];

fn hmac_sha1(key: &[u8], text: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    let mut block = [0x36; 64];
    let mut o_key_pad = [0x5c; 64];
    for (i, byte) in key.iter().enumerate() {
        block[i] ^= byte;
        o_key_pad[i] ^= byte;
    }
    hasher.update(block);
    hasher.update(text);
    let inner_hash = hasher.finalize_reset();
    hasher.update(o_key_pad);
    hasher.update(inner_hash);
    hasher.finalize().to_vec()
}

fn hmac_sha256(key: &[u8], text: &[u8]) -> Vec<u8> {
    let mut key = key.to_vec();
    if key.len() > 64 {
        key = Sha256::digest(&key).to_vec();
    }
    let mut block = [0x36; 64];
    let mut o_key_pad = [0x5c; 64];
    for (i, byte) in key.iter().enumerate() {
        block[i] ^= byte;
        o_key_pad[i] ^= byte;
    }
    let mut hasher = Sha256::new();
    hasher.update(block);
    hasher.update(text);
    let inner_hash = hasher.finalize_reset();
    hasher.update(o_key_pad);
    hasher.update(inner_hash);
    hasher.finalize().to_vec()
}

fn hmac_sha512(key: &[u8], text: &[u8]) -> Vec<u8> {
    let mut key = key.to_vec();
    if key.len() > 128 {
        key = Sha512::digest(&key).to_vec();
    }
    if key.len() < 128 {
        key.resize(128, 0);
    }
    let mut block = [0x36; 128];
    let mut o_key_pad = [0x5c; 128];
    for (i, byte) in key.iter().enumerate() {
        block[i] ^= byte;
        o_key_pad[i] ^= byte;
    }
    let mut hasher = Sha512::new();
    hasher.update(block);
    hasher.update(text);
    let inner_hash = hasher.finalize_reset();
    hasher.update(o_key_pad);
    hasher.update(inner_hash);
    hasher.finalize().to_vec()
}

fn hex_str_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_sha1_rfc6238() {
        let seed_hex = "3132333435363738393031323334353637383930";
        let t0 = 0;
        let x = 30;
        let test_times = vec![
            (59, "0000000000000001", "94287082"),
            (1_111_111_109, "00000000023523EC", "07081804"),
            (1_111_111_111, "00000000023523ED", "14050471"),
            (1_234_567_890, "000000000273EF07", "89005924"),
            (2_000_000_000, "0000000003F940AA", "69279037"),
            (20_000_000_000, "0000000027BC86AA", "65353130"),
        ];

        for &(time, expected_time_step, expected_totp) in &test_times {
            let time_step = time_steps(time, x, t0);
            let totp = generate_totp(seed_hex.to_string(), &time_step, 8, "SHA1");
            assert_eq!(time_step, expected_time_step);
            assert_eq!(totp, expected_totp);
        }
    }

    #[test]
    fn test_totp_sha256_rfc6238() {
        let seed_hex = "3132333435363738393031323334353637383930313233343536373839303132";
        let t0 = 0;
        let x = 30;
        let test_times = vec![
            (59, "0000000000000001", "46119246"),
            (1_111_111_109, "00000000023523EC", "68084774"),
            (1_111_111_111, "00000000023523ED", "67062674"),
            (1_234_567_890, "000000000273EF07", "91819424"),
            (2_000_000_000, "0000000003F940AA", "90698825"),
            (20_000_000_000, "0000000027BC86AA", "77737706"),
        ];

        for &(time, expected_time_step, expected_totp) in &test_times {
            let time_step = time_steps(time, x, t0);
            let totp = generate_totp(seed_hex.to_string(), &time_step, 8, "SHA256");
            assert_eq!(time_step, expected_time_step);
            assert_eq!(totp, expected_totp);
        }
    }

    #[test]
    fn test_totp_sha512_rfc6238() {
        let seed_hex = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";
        let t0 = 0;
        let x = 30;
        let test_times = vec![
            (59, "0000000000000001", "90693936"),
            (1_111_111_109, "00000000023523EC", "25091201"),
            (1_111_111_111, "00000000023523ED", "99943326"),
            (1_234_567_890, "000000000273EF07", "93441116"),
            (2_000_000_000, "0000000003F940AA", "38618901"),
            (20_000_000_000, "0000000027BC86AA", "47863826"),
        ];

        for &(time, expected_time_step, expected_totp) in &test_times {
            let time_step = time_steps(time, x, t0);
            let totp = generate_totp(seed_hex.to_string(), &time_step, 8, "SHA512");
            assert_eq!(time_step, expected_time_step);
            assert_eq!(totp, expected_totp);
        }
    }

    #[test]
    fn entity_secret_zeroized_on_drop() {
        use std::slice;

        let mut tolerance = 3;
        let ptr: *const u8;
        {
            let entity = Entity {
                algorithm: "SHA1".to_string(),
                digits: 6,
                issuer: None,
                label: None,
                period: 30,
                secret: "3132333435363738393031323334353637383930".to_string(),
            };
            ptr = entity.secret.as_ptr();
            unsafe {
                assert_eq!(
                    "3132333435363738393031323334353637383930".as_bytes(),
                    slice::from_raw_parts(ptr, 40)
                );
            }
        }

        unsafe {
            let zeroized_slice = slice::from_raw_parts(ptr, 40);
            for (a, b) in zeroized_slice
                .iter()
                .zip("3132333435363738393031323334353637383930".as_bytes())
            {
                if a == b {
                    tolerance -= 1;
                }
            }
        }
        assert!(tolerance > 0, "Too many bytes have the same values as the original secret, indicating that it wasn't properly zeroized.");
    }
}
