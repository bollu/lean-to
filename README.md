-- https://jupyter-client.readthedocs.io/en/stable/kernels.html
We are here trying to learn how to write a Jupyter kernel.

To start, 

```bash=
jupyter console --KernelManager.kernel_cmd="['./simple_kernel.py','{connection_file}']"
```
##### Python packaging hell
- https://github.com/jupyter/jupyter_console/issues/241

##### References
- https://github.com/dsblank/simple_kernel
