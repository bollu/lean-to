.PHONY: run

# v WORKS
run-console: 
	jupyter console --KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']"

# v BORKED [reasons unknown]
run-notebook: install-kernel
	jupyter notebook --ip='0.0.0.0' \
		--KernelManager.kernel_cmd="['python3', './simple_kernel.py','{connection_file}']" 

# v WORKS 
install-kernel:
	mkdir -p ${HOME}/.local/share/jupyter/kernels/asm
	cp -r kernelspec/* ${HOME}/.local/share/jupyter/kernels/asm/
