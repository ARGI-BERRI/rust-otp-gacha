mod otp;

fn main() {
    let generated_secret_key = otp::get_secret_key(None, 20);
    println!("Generated Secret: {:?}", generated_secret_key);

    let secret_key: &[u8] = b"12345678901234567890";
    println!("Secret for test vectors: {:?}", secret_key);

    let hotp = otp::get_hmac_based_otp(&secret_key, 0, 6);
    let totp = otp::get_time_based_otp(&secret_key, Some(59), 30, 8);

    println!("Test Vector - HOTP: {}", hotp);
    println!("Test Vector - TOTP: {}", totp);

    let mut current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(
        indicatif::ProgressStyle::default_spinner()
            .template("{spinner} {pos} items [{elapsed_precise}] ({per_sec})")
            .unwrap(),
    );

    loop {
        let totp = otp::get_time_based_otp(&secret_key, Some(current_time), 30, 6);

        if totp == "777777" {
            let date = chrono::DateTime::from_timestamp(current_time as i64, 0).unwrap();
            println!("Found TOTP 777777 at time {}", date);
        }

        pb.inc(1);

        current_time += 30;
    }
}
