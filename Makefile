BIN_ELFVIEW=elfview

test1:
	@ cd draft && gcc -c arr.c -o arr
	@ cargo test it_works -- --nocapture

.PHONY: elfview
elfview:
	@ cargo build --features elfview --bin ${BIN_ELFVIEW}  --release
	@ cp ./target/release/${BIN_ELFVIEW} .

install:
	@ cargo install --path . --features elfview --bin ${BIN_ELFVIEW}
