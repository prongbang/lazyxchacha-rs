login:
	cargo login

config_token:
	vim ~/.cargo/credentials.toml

publish:
	cargo publish --dry-run

# make bench
bench:
	cargo bench

# make bench_report
bench_report:
	open target/criterion/report/index.html