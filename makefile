asm-kernel:
	clang++ asm-kernel.cpp -o asm-kernel -std=c++-17 -fsanitize=address,undefined
