We are here trying to learn how to write a Jupyter kernel.

To start, 

```bash=
  jupyter kernel install --KernelManager.kernel_cmd="['./kernel_exe.py','{connection_file}']" &
  jupyter console --existing <whatever the previous command spits out as the runtime>
```
