.PHONY: run

run-console: 
	jupyter console --KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']"

run-notebook:
	jupyter console --KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']" --ip=''

asm-kernel:
	clang++ asm-kernel.cpp -o asm-kernel -std=c++-17 -fsanitize=address,undefined
