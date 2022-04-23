# simple_kernel.py
# by Doug Blank <doug.blank@gmail.com>
#
# This sample kernel is meant to be able to demonstrate using zmq for
# implementing a language backend (called a kernel) for IPython. It is
# written in the most straightforward manner so that it can be easily
# translated into other programming languages. It doesn't use any code
# from IPython, but only standard Python libraries and zmq.
#
# It is also designed to be able to run, showing the details of the
# message handling system.
#
# To adjust debug output, set debug_level to:
#  0 - show no debugging information
#  1 - shows basic running information
#  2 - also shows loop details
#  3 - also shows message details
#
# Start with a command, such as:
# ipython console --KernelManager.kernel_cmd="['python', 'simple_kernel.py', '{connection_file}']"


## Comm messages:  https://jupyter-client.readthedocs.io/en/stable/messaging.html
# Kernel listens to comm  messages on shell cannel
# Frontend listens / Kernel sends comm messages on IOPub channel


# Widget handling as detailed by IHaskell folks:
# https://github.com/gibiansky/IHaskell/blob/master/ihaskell-display/ihaskell-widgets/MsgSpec.md

from __future__ import print_function

## General Python imports:
import sys
import json
import hmac
import uuid
import errno
import hashlib
import datetime
import threading
from pprint import pformat

# zmq specific imports:
import zmq
from zmq.eventloop import ioloop, zmqstream
from zmq.error import ZMQError

PYTHON3 = sys.version_info.major == 3

#Globals:
DELIM = b"<IDS|MSG>"

debug_level = 3 # 0 (none) to 3 (all) for various levels of detail
EXITING = False
ENGINE_ID = str(uuid.uuid4())

with open("simple_kernel.log", "a") as LOGFILE:
    print("vvvNEW SESSIONvvv", file=LOGFILE)

# Utility functions:
def shutdown():
    global EXITING
    EXITING = True
    ioloop.IOLoop.instance().stop()

def dprint(level, *args, **kwargs):
    """ Show debug information """
    if level <= debug_level:
        print("DEBUG:", *args, **kwargs)
        sys.stdout.flush()
        with open("simple_kernel.log", "a") as LOGFILE:
            print("DEBUG:", *args, **kwargs, file=LOGFILE)
            LOGFILE.flush()

def msg_id():
    """ Return a new uuid for message id """
    return str(uuid.uuid4())

def str_to_bytes(s):
    return s.encode('ascii') if PYTHON3 else bytes(s)

def sign(msg_lst):
    """
    Sign a message with a secure signature.
    """
    h = auth.copy()
    for m in msg_lst:
        h.update(m)
    return str_to_bytes(h.hexdigest())

def new_header(msg_type):
    """make a new header"""
    return {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": ENGINE_ID,
            "msg_type": msg_type,
            "version": "5.0",
        }

def send(stream, msg_type, content=None, parent_header=None, metadata=None, identities=None):
    header = new_header(msg_type)
    if content is None:
        content = {}
    if parent_header is None:
        parent_header = {}
    if metadata is None:
        metadata = {}

    def encode(msg):
        return str_to_bytes(json.dumps(msg))

    msg_lst = [
        encode(header),
        encode(parent_header),
        encode(metadata),
        encode(content),
    ]
    signature = sign(msg_lst)
    parts = [DELIM,
             signature,
             msg_lst[0],
             msg_lst[1],
             msg_lst[2],
             msg_lst[3]]
    if identities:
        parts = identities + parts
    dprint(3, "send parts:", parts)
    stream.send_multipart(parts)
    stream.flush()

def run_thread(loop, name):
    dprint(2, "Starting loop for '%s'..." % name)
    while not EXITING:
        dprint(2, "%s Loop!" % name)
        try:
            loop.start()
        except ZMQError as e:
            dprint(2, "%s ZMQError!" % name)
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        except Exception:
            dprint(2, "%s Exception!" % name)
            if EXITING:
                break
            else:
                raise
        else:
            dprint(2, "%s Break!" % name)
            break

def heartbeat_loop():
    dprint(2, "Starting loop for 'Heartbeat'...")
    while not EXITING:
        dprint(3, ".", end="")
        try:
            zmq.device(zmq.FORWARDER, heartbeat_socket, heartbeat_socket)
        except zmq.ZMQError as e:
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        else:
            break


# In [3]: def stdout_and_result(): print("stdout"); return "result"
# In [4]: stdout_and_result()
# stdout # <- stdout
# Out[4]: 'result' # <- response
class AsmLangResponse:
    def __init__(self, stdout, result):
        self.stdout = stdout# auxiliary data to be printed in stdout
        self.result = result # data shown as Out

# https://gist.github.com/rene-d/9e584a7dd2935d0f461904b9f2950007
class Colors:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"


global COMMS
COMMS = {}


class AsmLangException(Exception):
    def __init__(self, stdout:str, result:str):
        self.response = AsmLangResponse(stdout, result)

class AsmLangServer:
    def __init__(self):
        self.count = 0;
        self.regfile = {}


    def eval_expr(self, v):
        try:
            return int(v)
        except ValueError:
            if v in self.regfile:
                return self.regfile[v]
            else:
                stdout=f"{Colors.RED}ERROR:{Colors.END} unknown register |{v}|\n"
                raise AsmLangException(stdout=stdout, result={})

    @classmethod
    def assert_instruction_length(cls, code_splitted, expected_format):
        """
        code_splitted: list[str]
        expected_format: list[str]
        check that lengths are equal. if unequal, print what is missing
        """
        if len(code_splitted) == len(expected_format):
            return

        if len(code_splitted) > len(expected_format):
            stdout=f"{Colors.RED}ERROR:{Colors.END}" + \
                f"too many args. Expected: {expected_format} | found: {code_splitted}"
            raise AsmLangException(stdout=stdout, result={})

        if len(code_splitted) < len(expected_format):
            stdout=f"{Colors.RED}ERROR:{Colors.END} too few args. Expected: {expected_format} |" + \
                f"found: {code_splitted} | missing: [{' '.join(expected_format[len(code_splitted):])}]"
            raise AsmLangException(stdout=stdout, result={})

    def execute(self, code):
        code = code.strip()
        code = code.strip(";")
        code = code.split()

        self.count -= 1
        try:
            if len(code) == 0:
                ERROR_STR = f"{Colors.RED}ERROR:{Colors.END} unknown code |{code}|\n"
                raise AsmLangException(stdout=ERROR_STR, result={})
            if code[0] == "get":
                    self.assert_instruction_length(code, ["get", "var"])
                    var = code[1]
                    val = self.regfile[var]
                    r = {} # {"text/plain": "RESULT set"}
                    return AsmLangResponse(stdout=f"STDOUT: {var} = {val}\n", result=r)
            if code[0] == "set":
                    self.assert_instruction_length(code, ["set", "var", "val"])
                    self.regfile[code[1]] = self.eval_expr(code[2])
                    r = {} # {"text/plain": "RESULT set"}
                    return AsmLangResponse(stdout=f"STDOUT: {self.regfile[code[1]]}\n", result=r)
            elif code[0] == "add":
                    self.assert_instruction_length(code, ["add", "var", "val1", "val2"])
                    self.regfile[code[1]] = self.eval_expr(code[2]) + self.eval_expr(code[3])
                    r = {} # {"text/plain": "RESULT add"}
                    return AsmLangResponse(stdout=f"STDOUT: {self.regfile[code[1]]}\n", result=r)
            elif code[0] == "button":
                global COMMS
                comm_id = str(uuid.uuid4())
                # https://github.com/jupyter-widgets/ipywidgets/blob/master/packages/schema/jupyterwidgetmodels.v6.md#jupyterbutton
                r = {
                    'comm_id': comm_id,
                    'target_name': 'jupyter.widget',
                    'data': {
                        '_model_name': 'ButtonModel',
                        '_model_module': 'jupyter-js-widgets',
                        '_model_module_version': '~2.1.0',
                        '_view_module':'jupyter-js-widgets',
                        '_view_module_version':'~2.1.0',
                        '_view_name':'ButtonView',
                        'description': 'click me, I am a cute button'
                    }
                }
                COMMS[comm_id] = r
                return AsmLangResponse(stdout="", result=r)
            elif len(code) == 1:
                r = {"text/plain": f"{self.eval_expr(code[0])}",
                     "text/html": "<a href='https://pixel-druid.com'><i>i</i><b>tal</b><u>ic</u></a>"}
                return AsmLangResponse(stdout="", result=r)
            else:
                raise AsmLangException(stdout=f"{Colors.RED}ERROR:{Colors.END}" + \
                                       f"Unknown command: |{code[0]}|\n",
                                       result={})
        except AsmLangException as e:
           return e.response


LANG_SERVER = AsmLangServer()


# In general, the ROUTER/DEALER sockets follow a request-reply pattern:
# --------------------------------------------------------------------

# 1. The client sends an <action>_request message (such as execute_request) on its
# shell (DEALER) socket.
# 
# 2. The kernel receives that request and immediately
# publishes a status: busy message on IOPub.
# 
# 3. The kernel then processes the
# request and sends the appropriate <action>_reply message, such as
# execute_reply. 
# 
# 4. After processing the request and publishing associated IOPub
# messages, if any, the kernel publishes a status: idle message. 
# 
# 5. This idle status message indicates that IOPub messages
# associated with a given request have all been received.



# Socket Handlers:
def shell_handler(msg):
    global EXECUTION_COUNT
    global LANG_SERVER
    dprint(1, "shell received:", msg)
    position = 0
    identities, msg = deserialize_wire_msg(msg)

    # process request:

    if msg['header']["msg_type"] == "execute_request":
        content = {
            'execution_state': "busy",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
        #######################################################################
        msg_content_code = msg['content']['code']
        dprint(1, "simple_kernel Executing:", pformat(msg_content_code))
        lang_server_response = LANG_SERVER.execute(msg_content_code)
        dprint(1, "executed code.")

        ## vvv TODO: what does this do? This tells the notebook what is being executed
        ## https://jupyter-client.readthedocs.io/en/stable/messaging.html#code-inputs
        content = {
            'execution_count': EXECUTION_COUNT,
            'code': msg_content_code
        }
        send(iopub_stream, 'execute_input', content, parent_header=msg['header'])
        #######################################################################
        content = {
            'name': "stdout",
            'text': lang_server_response.stdout
        }
        send(iopub_stream, 'stream', content, parent_header=msg['header'])
        #######################################################################
        content = {
            'execution_count': EXECUTION_COUNT,
            'data': lang_server_response.result,
            'metadata': {}
        }
        send(iopub_stream, 'execute_result', content, parent_header=msg['header'])
        #######################################################################
        content = {
            'execution_state': "idle",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
        #######################################################################
        metadata = {
            "dependencies_met": True,
            "engine": ENGINE_ID,
            "status": "ok",
            "started": datetime.datetime.now().isoformat(),
        }
        content = {
            "status": "ok",
            "execution_count": EXECUTION_COUNT,
            "user_variables": {},
            "payload": [],
            "user_expressions": {},
        }
        send(shell_stream, 'execute_reply', content, metadata=metadata,
            parent_header=msg['header'], identities=identities)
        ##################################################################
        EXECUTION_COUNT += 1
    elif msg['header']["msg_type"] == "kernel_info_request":
        content = {
            "protocol_version": "5.0",
            "ipython_version": [1, 1, 0, ""],
            "language_version": [0, 0, 1],
            "language": "simple_kernel",
            "implementation": "simple_kernel",
            "implementation_version": "1.1",
            "language_info": {
                "name": "simple_kernel",
                "version": "1.0",
                'mimetype': "",
                'file_extension': ".py",
                'pygments_lexer': "",
                'codemirror_mode': "",
                'nbconvert_exporter': "",
            },
            "banner": ""
        }
        send(shell_stream, 'kernel_info_reply', content, parent_header=msg['header'], identities=identities)
        content = {
            'execution_state': "idle",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
    elif msg['header']["msg_type"] == "history_request":
        dprint(1, "unhandled history request")
    elif msg['header']["msg_type"] == "complete_request":
        # https://jupyter-client.readthedocs.io/en/stable/messaging.html#completion
        # dprint(1, "unhandled tab complete request")
        #### 
        content = {
            'execution_state': "busy",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
        #######################################################################
        #dprint(1, "handling complete request...")
        completion_request_code = msg['content']['code']
        completion_request_cursor_pos = int(msg['content']['cursor_pos'])
        #content = {
        #    'execution_count': EXECUTION_COUNT,
        #    "matches": ["comp1", "comp2"],
        #    "cursor_start": completion_request_cursor_pos,
        #    "cursor_end": completion_request_cursor_pos,
        #    'metadata': {}
        #}
        #send(iopub_stream, 'complete_result', content, parent_header=msg['header'])
        ###########################################################################
        metadata = {
            "dependencies_met": True,
            "engine": ENGINE_ID,
            "status": "ok",
            "started": datetime.datetime.now().isoformat(),
        }
        content = {
            "status": "ok",
            "matches": ["comp1", "comp2", "comp3"],
            "cursor_start": completion_request_cursor_pos,
            "cursor_end": completion_request_cursor_pos,
            'metadata': {}

        }
        send(shell_stream, 'complete_reply', content, metadata=metadata,
            parent_header=msg['header'], identities=identities)
        #######################################################################
        content = {
            'execution_state': "idle",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
        #######################################################################
        EXECUTION_COUNT += 1
    elif msg['header']["msg_type"] == "is_complete_request":
        ## Return if line is complete. We say yes if ends if semicolon.
        # https://jupyter-client.readthedocs.io/en/stable/messaging.html#completion
        content = {
            'execution_state': "busy",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
        #######################################################################
        is_complete_request_code = msg['content']['code'].strip()
        metadata = {
            "dependencies_met": True,
            "engine": ENGINE_ID,
            "status": "ok",
            "started": datetime.datetime.now().isoformat(),
        }
        ends_with_semicolon = False
        if is_complete_request_code:
            ends_with_semicolon = is_complete_request_code[-1] == ';'

        content = {
            "status": 'complete' if ends_with_semicolon else 'incomplete',
            "indent": "  " # two space indentation

        }
        send(shell_stream, 'is_complete_reply', content, metadata=metadata,
            parent_header=msg['header'], identities=identities)
        #######################################################################
        content = {
            'execution_state': "idle",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
        #######################################################################

    else:
        dprint(1, "unknown msg_type:", msg['header']["msg_type"])

def deserialize_wire_msg(wire_msg):
    """split the routing prefix and message frames from a message on the wire"""
    delim_idx = wire_msg.index(DELIM)
    identities = wire_msg[:delim_idx]
    m_signature = wire_msg[delim_idx + 1]
    msg_frames = wire_msg[delim_idx + 2:]

    def decode(msg):
        return json.loads(msg.decode('ascii') if PYTHON3 else msg)

    m = {}
    m['header']        = decode(msg_frames[0])
    m['parent_header'] = decode(msg_frames[1])
    m['metadata']      = decode(msg_frames[2])
    m['content']       = decode(msg_frames[3])
    # bollu:only necessary for paranoia.
    check_sig = sign(msg_frames)
    if check_sig != m_signature:
        raise ValueError("Signatures do not match")

    return identities, m

def control_handler(wire_msg):
    global EXITING
    dprint(1, "control received:", wire_msg)
    identities, msg = deserialize_wire_msg(wire_msg)
    # Control message handler:
    if msg['header']["msg_type"] == "shutdown_request":
        shutdown()

def iopub_handler(msg):
    raise RuntimeError("DIE IO PUB HANDLER")
    dprint(1, "iopub received:", msg)

def stdin_handler(msg):
    dprint(1, "stdin received:", msg)

def bind(socket, connection, port):
    if port <= 0:
        return socket.bind_to_random_port(connection)
    else:
        socket.bind("%s:%s" % (connection, port))
    return port

## Initialize:
ioloop.install()

if len(sys.argv) > 1:
    dprint(1, "Loading simple_kernel with args:", sys.argv)
    dprint(1, "Reading config file '%s'..." % sys.argv[1])
    config = json.loads("".join(open(sys.argv[1]).readlines()))
else:
    dprint(1, "Starting simple_kernel with default args...")
    config = {
        'control_port'      : 0,
        'hb_port'           : 0,
        'iopub_port'        : 0,
        'ip'                : '127.0.0.1',
        'key'               : str(uuid.uuid4()),
        'shell_port'        : 0,
        'signature_scheme'  : 'hmac-sha256',
        'stdin_port'        : 0,
        'transport'         : 'tcp'
    }

connection = config["transport"] + "://" + config["ip"]
secure_key = str_to_bytes(config["key"])
signature_schemes = {"hmac-sha256": hashlib.sha256}
auth = hmac.HMAC(
    secure_key,
    digestmod=signature_schemes[config["signature_scheme"]])
EXECUTION_COUNT = 1

##########################################
# Heartbeat:
ctx = zmq.Context()
heartbeat_socket = ctx.socket(zmq.REP)
config["hb_port"] = bind(heartbeat_socket, connection, config["hb_port"])

##########################################
# IOPub/Sub:
# aslo called SubSocketChannel in IPython sources
iopub_socket = ctx.socket(zmq.PUB)
config["iopub_port"] = bind(iopub_socket, connection, config["iopub_port"])
iopub_stream = zmqstream.ZMQStream(iopub_socket)
iopub_stream.on_recv(iopub_handler)

##########################################
# Control:
control_socket = ctx.socket(zmq.ROUTER)
config["control_port"] = bind(control_socket, connection, config["control_port"])
control_stream = zmqstream.ZMQStream(control_socket)
control_stream.on_recv(control_handler)

##########################################
# Stdin:
stdin_socket = ctx.socket(zmq.ROUTER)
config["stdin_port"] = bind(stdin_socket, connection, config["stdin_port"])
stdin_stream = zmqstream.ZMQStream(stdin_socket)
stdin_stream.on_recv(stdin_handler)

##########################################
# Shell:
shell_socket = ctx.socket(zmq.ROUTER)
config["shell_port"] = bind(shell_socket, connection, config["shell_port"])
shell_stream = zmqstream.ZMQStream(shell_socket)
shell_stream.on_recv(shell_handler)

dprint(1, "Config:", json.dumps(config))
dprint(1, "Starting loops...")

hb_thread = threading.Thread(target=heartbeat_loop)
hb_thread.daemon = True
hb_thread.start()

dprint(1, "Ready! Listening...")

ioloop.IOLoop.instance().start()
