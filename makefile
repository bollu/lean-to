.PHONY: run build-cpp-kernel

run-cpp-console: build-cpp-kernel
	jupyter console --kernel asmcpp

build-cpp-kernel:
	mkdir -p build/
	clang++ asm-kernel.cpp -o build/asm-kernel-cpp -std=c++17 -fsanitize=address -fsanitize=undefined -lzmq -lssl -lcrypto ${leanc --print-ldflags}

# v WORKS
run-console:
	jupyter console --kernel asm
	

run-console-old: 
	jupyter console --KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']"

run-notebook: install-kernel
	jupyter notebook --ip='0.0.0.0' --kernel as
		

# v BORKED [reasons unknown]
run-notebook-old: install-kernel
	jupyter notebook --ip='0.0.0.0' \
		--KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']" 

# v WORKS 
install-kernel:
	cp  -r kernelspec/* ${HOME}/.local/share/jupyter/kernels/

