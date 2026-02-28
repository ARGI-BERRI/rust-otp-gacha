use base32::{Alphabet, decode};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

pub fn get_secret_key(secret: Option<&str>, key_length: usize) -> Vec<u8> {
    match secret {
        Some(s) => decode(Alphabet::RFC4648 { padding: true }, s).expect("Invalid base32 secret"),
        None => rand::thread_rng()
            .sample_iter::<u8, _>(rand::distributions::Standard)
            .take(key_length)
            .collect(),
    }
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

    format!(
        "{:0digit$}",
        otp_full % 10u64.pow(digit as u32),
        digit = digit
    )
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

    get_hmac_based_otp(secret_key, step, digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test get_hmac_based_otp's outputs against test vectors from RFC 4226 Appendix D
    #[test]
    fn test_get_hmac_based_otp() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for (counter, &exp) in expected.iter().enumerate() {
            let otp = get_hmac_based_otp(secret, counter as u64, 6);
            assert_eq!(otp, exp, "HOTP counter={}", counter);
        }
    }

    /// Test that get_hmac_based_otp correctly zero-pads OTPs to the specified digit length
    #[test]
    fn test_get_hmac_based_otp_leading_zero() {
        let secret = b"12345678901234567890";
        let otp = get_hmac_based_otp(secret, 0, 8);

        assert_eq!(otp.len(), 8, "OTP must be exactly 8 digits");
        assert!(
            otp.chars().all(|c| c.is_ascii_digit()),
            "OTP must contain only digits"
        );
    }

    /// Test that get_hmac_based_otp produces OTPs of correct length and format
    /// for various (6, 7, 8) digit lengths
    #[test]
    fn test_get_hmac_based_otp_digit_lengths() {
        let secret = b"12345678901234567890";
        for &digit in &[6usize, 7, 8] {
            let otp = get_hmac_based_otp(secret, 0, digit);
            assert_eq!(otp.len(), digit, "OTP must be exactly {} digits", digit);
            assert!(
                otp.chars().all(|c| c.is_ascii_digit()),
                "OTP must contain only digits"
            );
        }
    }

    /// Test get_time_based_otp's outputs against SHA-1 Test vectors in RFC 6238 Appendix B
    #[test]
    fn test_get_time_based_otp() {
        let secret = b"12345678901234567890";
        let testcases = [
            (59u64, "94287082"),
            (1111111109u64, "07081804"),
            (1111111111u64, "14050471"),
            (1234567890u64, "89005924"),
            (2000000000u64, "69279037"),
            (20000000000u64, "65353130"),
        ];

        for &(timestamp, expected) in &testcases {
            let otp = get_time_based_otp(secret, Some(timestamp), 30, 8);
            assert_eq!(otp, expected, "TOTP failed at timestamp {}", timestamp);
        }
    }

    /// Test get_time_based_otp's behavior at time step boundaries
    /// to ensure it changes OTP at correct intervals
    #[test]
    fn test_get_time_based_otp_time_step_boundary() {
        let secret = b"12345678901234567890";

        let otp_at_0 = get_time_based_otp(secret, Some(0), 30, 6);
        let otp_at_29 = get_time_based_otp(secret, Some(29), 30, 6);
        let otp_at_30 = get_time_based_otp(secret, Some(30), 30, 6);
        let otp_at_59 = get_time_based_otp(secret, Some(59), 30, 6);

        assert_eq!(
            otp_at_0, otp_at_29,
            "unix_time 0 and 29 must yield the same OTP (step=0)"
        );
        assert_eq!(
            otp_at_30, otp_at_59,
            "unix_time 30 and 59 must yield the same OTP (step=1)"
        );
        assert_ne!(
            otp_at_0, otp_at_30,
            "Different time steps must yield different OTPs"
        );
    }

    /// Test get_time_based_otp with None for unix_time to ensure it generates a valid OTP
    /// based on current time
    #[test]
    fn test_get_time_based_otp_current_time() {
        let secret = b"12345678901234567890";
        let otp = get_time_based_otp(secret, None, 30, 6);
        assert_eq!(otp.len(), 6, "Current-time TOTP must be 6 digits");
        assert!(
            otp.chars().all(|c| c.is_ascii_digit()),
            "TOTP must contain only digits"
        );
    }

    /// Test get_secret_key generates random keys of specified length when None is given
    #[test]
    fn test_get_secret_key_random_length() {
        for &len in &[10usize, 20, 32] {
            let key = get_secret_key(None, len);
            assert_eq!(key.len(), len, "Random key must have {} bytes", len);
        }
    }

    /// Test get_secret_key generates different random keys on multiple calls with None
    #[test]
    fn test_get_secret_key_random_unique() {
        let key1 = get_secret_key(None, 20);
        let key2 = get_secret_key(None, 20);
        assert_ne!(key1, key2, "Two random keys should not be identical");
    }

    /// Test get_secret_key decodes Base32 string, if it's valid
    #[test]
    fn test_get_secret_key_from_base32() {
        // "JBSWY3DPEE======" is a Base 32-encoded string of "Hello!"
        let key = get_secret_key(Some("JBSWY3DPEE======"), 0);
        assert_eq!(key, b"Hello!", "Base32 decoding must produce correct bytes");
    }

    /// Test get_secret_key panics on invalid Base32 string
    #[test]
    #[should_panic(expected = "Invalid base32 secret")]
    fn test_get_secret_key_invalid_base32() {
        get_secret_key(Some("!!!INVALID!!!"), 0);
    }
}
