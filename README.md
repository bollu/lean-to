-- https://jupyter-client.readthedocs.io/en/stable/kernels.html
We are here trying to learn how to write a Jupyter kernel.

To start, 

```bash=
  jupyter kernel install --KernelManager.kernel_cmd="['./kernel_exe.py','{connection_file}']" &
  jupyter console --existing <whatever the previous command spits out as the runtime>
```
##### Python packaging hell
- https://github.com/jupyter/jupyter_console/issues/241

##### References
- https://github.com/dsblank/simple_kernel
