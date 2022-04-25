.PHONY: run build-cpp-kernel
LEANLDFLAGS=$(shell leanc --print-ldflags)

run-cpp-notebook: build-cpp-kernel
	jupyter notebook --ip='0.0.0.0' --kernel asmcpp
run-cpp-console: build-cpp-kernel
	jupyter console --kernel asmcpp


build-cpp-kernel:
	mkdir -p build
	# bear to generate compile_commands.json
	# from lean/lake: |supportInterpreter:| Whether to
	# expose symbols within the executable to the Lean interpreter. This allows
	# the executable to interpret Lean files (e.g., via Lean.Elab.runFrontend).
	# Implementation-wise, this passes -rdynamic to the linker when building on
	# a non-Windows systems. Defaults to false.
	bear -- clang++ -g -O0 asm-kernel.cpp build/ir/REPLLib.c -DLEAN_EXPORTING -o build/asm-kernel-cpp  -std=c++17 \
		-fsanitize=address -fsanitize=undefined -lzmq -lssl -lcrypto \
		-rdynamic \
		-Wl,--export-dynamic \
		$(LEANLDFLAGS)

# v WORKS
run-console:
	jupyter console --kernel asm
	

run-console-old: 
	jupyter console --KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']"

run-notebook: install-kernel
	jupyter notebook --ip='0.0.0.0' --kernel asm
		

# v BORKED [reasons unknown]
run-notebook-old: install-kernel
	jupyter notebook --ip='0.0.0.0' \
		--KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']" 

# v WORKS 
install-kernel:
	cp  -r kernelspec/* ${HOME}/.local/share/jupyter/kernels/

