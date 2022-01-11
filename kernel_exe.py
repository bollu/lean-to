#!/usr/bin/env python3
import sys
import zmq

with open("/home/sahiti/bucket/jupyter-kernel/log", "w") as f:
    f.write(' '.join(sys.argv))
