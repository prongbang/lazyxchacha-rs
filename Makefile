login:
	cargo login

config_token:
	vim ~/.cargo/credentials.toml
	vim ~/.zshrc
	# export CARGO_REGISTRY_TOKEN=token

publish:
	cargo publish --dry-run

# make bench
bench:
	cargo bench

# make bench_report
bench_report:
	open target/criterion/report/index.html