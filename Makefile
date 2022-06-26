

test1:
	@ cd draft && gcc arr.c -o arr
	@ cargo test it_works -- --nocapture
