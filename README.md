# rust-otp-gacha

This app will find the date that the OTP number becomes 777777.

You can see the X-Days that 777777 will appear in your OTP Generator by running `cargo run --release`. Example outputs are:

```log
Generated Secret: [191, 211, 112, 225, 229, 113, 55, 70, 68, 117, 163, 169, 46, 246, 177, 173, 57, 163, 52, 6]
Secret for test vectors: [49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48]
Test Vector - HOTP: 755224
Test Vector - TOTP: 94287082
⠈ 794197 items [00:00:00] (3,161,876.8943/s)
Found TOTP 777777 at time 2026-07-04 16:13:20 UTC
⠋ 1430748 items [00:00:00] (3,169,408.5784/s)
Found TOTP 777777 at time 2027-02-11 14:50:20 UTC
⠤ 2914783 items [00:00:00] (3,176,098.7929/s)
Found TOTP 777777 at time 2028-08-02 18:03:20 UTC
```

## Run and test

```bash
# Please note that it runs endlessly.
cargo run --release

# All unit test should be passed
cargo test
```

## License

Apache License 2.0
