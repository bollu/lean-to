.PHONY: run build-cpp-kernel

run-cpp-console: build-cpp-kernel
	jupyter console --kernel asmcpp

build-cpp-kernel:
	make -C build/

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

