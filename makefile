.PHONY: run

run: 
	jupyter console --KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']"

asm-kernel:
	clang++ asm-kernel.cpp -o asm-kernel -std=c++-17 -fsanitize=address,undefined
