use criterion::{Criterion, criterion_group, criterion_main};
use lazyxchacha::lazyxchacha::LazyXChaCha;

fn criterion_benchmark(c: &mut Criterion) {
    // Given
    let lazyxchacha = LazyXChaCha::new();
    let shared_key = "edf9d004edae8335f095bb8e01975c42cf693ea60322b75cb7c6667dc836fd7e";
    let plaintext = r#"{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}"#;
    let ciphertext = "58b99ca42eaed1949d3d707208b39fc9bd8d8b35d44066c072c4ce44cd004971a66389adbfcb3b59903bc22dd825cf7267c63efda6c86bdb0f62571858ac914af67d7cf92e84738996441afcb141a9f621e795e2d2446e1b75d26ee61187c1680af84b5625c3bc9199f69abfb940dbf90970fd1b53bf51d86524249e3af9132b8fdb09f0cd3303f2e9eeeae8e3333104ebb4463aa7";

    c.bench_function("encrypt", |b| b.iter(|| {
        let actual = lazyxchacha.encrypt(plaintext, shared_key);
        if actual.is_empty() {
            eprintln!("error: is empty")
        }
    }));

    c.bench_function("decrypt", |b| b.iter(|| {
        let actual = lazyxchacha.decrypt(ciphertext, shared_key);
        if actual.is_empty() {
            eprintln!("error: is empty")
        }
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);