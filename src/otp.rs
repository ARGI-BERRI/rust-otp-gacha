use base32::{Alphabet, decode};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

pub fn get_secret_key(secret: Option<&str>, key_length: usize) -> Vec<u8> {
    return match secret {
        Some(s) => decode(Alphabet::RFC4648 { padding: true }, s).expect("Invalid base32 secret"),
        None => rand::thread_rng()
            .sample_iter(rand::distributions::Standard)
            .take(key_length)
            .collect(),
    };
}

pub fn get_hmac_based_otp(secret_key: &[u8], counter: u64, digit: usize) -> String {
    let digest = HmacSha1::new_from_slice(secret_key)
        .expect("HMAC can take key of any size")
        .chain_update(&counter.to_be_bytes())
        .finalize()
        .into_bytes();

    let offset = (digest[19] & 0xf) as usize;
    let otp_full = ((u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ])) & 0x7fffffff) as u64;

    return format!(
        "{:0digit$}",
        otp_full % 10u64.pow(digit as u32),
        digit = digit
    );
}

pub fn get_time_based_otp(
    secret_key: &[u8],
    unix_time: Option<u64>,
    time_step: u64,
    digit: usize,
) -> String {
    let now = unix_time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let step = now / time_step;

    return get_hmac_based_otp(secret_key, step, digit);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_hmac_based_otp() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for (counter, &exp) in expected.iter().enumerate() {
            let otp = get_hmac_based_otp(secret, counter as u64, 6);
            assert_eq!(otp, exp);
        }
    }

    #[test]
    fn test_get_time_based_otp() {
        // RFC 6238 Appendix B SHA1 test vectors
        let secret = b"12345678901234567890";
        let testcases = [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];

        for &(timestamp, expected) in &testcases {
            let otp = get_time_based_otp(secret, Some(timestamp), 30, 8);
            assert_eq!(otp, expected, "failed at timestamp {}", timestamp);
        }
    }
}
