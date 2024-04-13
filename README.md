# lazyxchacha-rs

Lazy XChaCha20-Poly1305 in golang base on RustCrypto: ChaCha20Poly1305.

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/prongbang)

### Algorithm details

- Key exchange: X25519
- Encryption: XChaCha20
- Authentication: Poly1305

### Install

```shell

```

### Benchmark

```shell
Gnuplot not found, using plotters backend
encrypt                 time:   [1.4821 µs 1.4897 µs 1.5010 µs]
                        change: [-33.403% -32.895% -32.441%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  1 (1.00%) high mild
  3 (3.00%) high severe

Benchmarking decrypt: Warming up for 3.0000 s
decrypt                 time:   [1.3529 µs 1.3560 µs 1.3594 µs]
                        change: [-27.218% -27.057% -26.897%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 8 outliers among 100 measurements (8.00%)
  8 (8.00%) high mild
```

### How to use

- Generate KeyPair

```rust
let keypair = KeyPair::new();
```

- Key Exchange & Shared Key

```rust
let client_kp = KeyPair::new();
let server_kp = KeyPair::new();
let server_pk = server_kp.pk_string();

let shared_key = SharedKey::new(server_pk, client_kp.sk);
```

- Encrypt

```rust
let lazyxchacha = LazyXChaCha::new();
let shared_key = SharedKey::new(server_pk, client_kp.sk);
let plaintext = r#"{"message": "hi"}"#;

let ciphertext = lazyxchacha.encrypt(plaintext, shared_key);
```

- Decrypt

```rust
let lazyxchacha = LazyXChaCha::new();
let shared_key = SharedKey::new(server_pk, client_kp.sk);
let ciphertext = "58b99ca4a7";

let plaintext = lazyxchacha.decrypt(ciphertext, shared_key);
```
