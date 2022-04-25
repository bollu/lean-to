#include <zmq.h>
#include <string>
#include <chrono>
#include <thread>
#include <iostream>
// #include <zmq.hpp>
// #include "picohash.h"
#include <iostream>
#include <sstream>
#include <fstream>
// #include "uuid.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "json.hpp"
#include "lean/lean.h"
#include "lean/config.h"

// ZMQ guide for C devs:
// https://lqhl.me/resources/zguide-c.pdf


using namespace nlohmann;

// using lean_object = void;
extern "C" {
    lean_object* mk_init_state(lean_object*);
    lean_object* run_code(lean_object*, lean_object*, lean_object*);
    lean_object* tuple_fst(lean_object*);
    lean_object* tuple_snd(lean_object*);
    // https://github.com/leanprover/lean4/blob/6a880fecc996895ee39b54ac206b1bae8f98a54c/stage0/src/initialize/init.cpp
    // /* Initializes the Lean runtime. Before executing any code which uses the Lean package,
    // you must first call this function, and then `lean::io_mark_end_initialization`. Inbetween
    // these two calls, you may also have to run additional initializers for your own modules. */
    void lean_initialize();
    // void lean_initialize_runtime_module();
    lean_object* lean_io_error_to_string(lean_object * err);
    lean_object* initialize_REPLLib(lean_object* w);
    // static inline char const * lean_string_cstr(b_lean_obj_arg o) {
    // LEAN_SHARED lean_obj_res lean_mk_string(char const * s);

};

// Unwrap the IO object, throwing an error if an IO error occured.
lean_object* lean_unwrap_io(lean_object *o) {
    if (lean_io_result_is_error(o)) {
        lean_io_result_show_error(o);
        assert(false && "execution error");
    } else {
        assert(lean_io_result_is_ok(o));
        return lean_io_result_get_value(o);
    }
}

json json_empty_object() {
    // https://github.com/nlohmann/json/issues/2046#issuecomment-868980645
    return json(json::value_t::object);
}

json json_empty_list() {
    return json(json::value_t::array);
}

std::string uuid4() {
    char v[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    //3fb17ebc-bc38-4939-bc8b-74f2443281d4
    //8 dash 4 dash 4 dash 4 dash 12
    static char buf[37] = {0};

    //gen random for all spaces because lazy
    for(int i = 0; i < 36; ++i) {
        buf[i] = v[rand()%16];
    }

    //put dashes in place
    buf[8] = '-';
    buf[13] = '-';
    buf[18] = '-';
    buf[23] = '-';

    //needs end byte
    buf[36] = '\0';
    return std::string(buf);
}

// TODO: actually learn how to create a datetime.
std::string datetime_now_isoformat() {
    return "2022-04-24T02:20:01.512817Z"; 
}


using ll = long long;


// Jupyter delimiter between the prefix with routing information and
// the suffix with real informatoin
const char DELIM []= "<IDS|MSG>";

// Sockets to be polled from.
enum PolledSocketKind {
    HEARTBEAT,
    CONTROL,
    STDIN,
    SHELL,
    NPOLLEDSOCKETS
};

const char *polled_socket_kind_to_str(PolledSocketKind k) {
    switch(k) {
        case HEARTBEAT: return "heartbeat";
        case CONTROL: return "control";
        case STDIN: return "stdin";
        case SHELL: return "shell";
        case NPOLLEDSOCKETS: assert(false && "not a type of socket");
    }
    assert(false && "unreachable");
}

// information a shell request possess.
struct ShellRequest {
    json header;
    json parent_header;
    json metadata;
    json content;
    // we must maintain real buffers
    std::vector<std::tuple<void *, int, std::string>> identities;
};

// information to be sent back to jupyter via ZMQ
struct JupyterResponse {
    std::string msg_type; // string of message type
    json content; // content in message.
    json parent_header; // header of previous message we are replying to.
    json metadata; // '''metadata''' as per jupyter protocol demands.
    // TODO: should this be a list? will this ever be a list?
    // we must maintain real buffers
    std::vector<std::tuple<void *, int, std::string>> identities; // routing information extracted from request.
};

// information that is sent back when a shell response is made.
struct ShellExecutionResponse {
    // eg. evaluating |IO.println "foo"| will have val as unit, stdout as "foo".
    std::string out; // stdout.
    std::string err; // stderr.
    std::string val; // value of the execution. 
    ShellExecutionResponse(std::string out, std::string err, std::string val) 
        :out(out), err(err), val(val) {};
};

// unique state held across session
struct GlobalState {
    std::string key; // signing key is some random UUID
    std::string engine_id; // engine ID is some random UUID
    int shell_execution_count = 0;
    lean_object *shell_state = nullptr;
};

// custom free function to free memory from zmq
void free_c_string_for_zmq (void *data, void *hint) {
    free (data);
}


int zmq_msg_send_str(void *s_, std::string s, int flags) {
    int rc = 0;
    zmq_msg_t msg;
    rc = zmq_msg_init(&msg);
    assert(rc == 0);
    rc = zmq_msg_init_size(&msg, s.size()+1);
    assert (rc == 0);
    /* Fill in message content with 'AAAAAA' */
    const char *data = strdup(s.c_str());
    zmq_msg_init_data(&msg, (void*)data, strlen(data), free_c_string_for_zmq, NULL);
    rc = zmq_msg_send(&msg, s_, flags);
    assert(rc != -1);
    return rc;
}

// send response structure the way Jupyter expects them.
void send_jupyter_response(void *socket, const GlobalState &globals, 
        const JupyterResponse &response) {
    json header;
    header["date"] = datetime_now_isoformat();
    header["msg_id"] = uuid4(); // TODO:ouch!
    header["username"] = "kernel"; 
    header["session"] = globals.engine_id;
    header["msg_type"] = response.msg_type;
    header["version"] = "5.0";

    std::cout << "[KERNEL] [RESPONSE] ==" << "msg: |" << response.msg_type << "| " << 
        "hmac key: |" << globals.key << "|==\n";
    HMAC_CTX *h = HMAC_CTX_new();
    int status = HMAC_Init(h, globals.key.c_str(), globals.key.size(), EVP_sha256());
    assert(status == 1);

    // def sign(msg_lst):
    //   h = auth.copy()l for m in msg_lst: h.update(m)
    //   return str_to_bytes(h.hexdigest())
    //   ----------------------
    // auth = hmac.HMAC(
    //     secure_key,
    //     digestmod=signature_schemes[config["signature_scheme"]])
    // msg_lst = [ encode(header), encode(parent_header), encode(metadata), encode(content) ]
    // signature = sign(msg_lst)
    assert(!response.parent_header.is_null());
    assert(!response.metadata.is_null());
    assert(!response.content.is_null());
    std::vector<std::string> msg_list = {
        header.dump(),
        response.parent_header.dump(),
        response.metadata.dump(),
        response.content.dump()
    };

    for(std::string m : msg_list) {
        status = HMAC_Update(h, (const unsigned char *) m.c_str(), m.size());
        assert(status == 1);
    }

    unsigned char rawsig[1024];
    unsigned int siglen;
    status = HMAC_Final(h, rawsig, &siglen);
    assert(status == 1);
    assert(siglen < 512);
    rawsig[siglen] = 0;

    // TODO: think what happens if rawsig actually has zeroes in the middle.
    // This is important, since it might cause the string to be empty...
    std::stringstream signature;
    for(int i = 0; i < siglen; ++i) {
        signature << std::setw(2) << std::setfill('0') << std::hex << (0xFF & rawsig[i]);
    }


    // msg_lst = [ encode(header), encode(parent_header), encode(metadata), encode(content) ]
    // parts = [DELIM, signature, msg_lst[0], msg_lst[1], msg_lst[2], msg_lst[3]]
    // if identities: parts = identities + parts
    // dprint(3, "send parts:", parts)
    // stream.send_multipart(parts)
    // stream.flush()
    // construct response.
    std::vector<std::string> parts;
    // parts.insert(parts.end(), response.identities.begin(), response.identities.end());
    //
    for(int i = 0; i < response.identities.size(); ++i) {
        void *data = std::get<0>(response.identities[i]);
        const int size = std::get<1>(response.identities[i]);
        int rc = 0;
        zmq_msg_t msg;
        rc = zmq_msg_init(&msg);
        assert(rc == 0);
        rc = zmq_msg_init_size(&msg, size);
        assert (rc == 0);
        /* Fill in message content with 'AAAAAA' */
        // NOTE: data will be freed here!
        zmq_msg_init_data(&msg, (void*)data, size, free_c_string_for_zmq, NULL);
        rc = zmq_msg_send(&msg, socket, ZMQ_SNDMORE);
        assert(rc != -1);
    }
    parts.push_back(DELIM);
    parts.push_back(signature.str());
    parts.insert(parts.end(), msg_list.begin(), msg_list.end());
    int rc = 0;
    for(int i = 0; i < parts.size(); ++i) {
        std::cout << "[KERNEL] [RESPONSE] sent [" << i << "] |" << parts[i] << "|\n"; 
        const int flag = i == parts.size() - 1 ? 0 : ZMQ_SNDMORE;
        rc = zmq_msg_send_str(socket, parts[i], flag);
        assert(rc != -1);
    }
}


// handle shell request by replying on iopub and shell sockets
// NOTE: we mutate execution counts stored in global_state
void shell_handler(void *iopub_socket, void *shell_socket, 
    GlobalState &global_state, const ShellRequest request) {
    std::cout << "[SHELL HANDLER] identities: ";
    for(int i = 0; i < request.identities.size(); ++i) {
        std::cout << "|" << std::get<2>(request.identities[i]) << "|";
    }

    std::cout << "\n";
    std::cout << "[SHELL HANDLER] header: |" << request.header << "|\n";
    std::cout << "[SHELL HANDLER] parent_header: |" << request.parent_header << "|\n";
    std::cout << "[SHELL HANDLER] metadata: |" << request.metadata << "|\n";
    std::cout << "[SHELL HANDLER] content: |" << request.content << "|\n";

    const std::string msg_type = request.header["msg_type"].get<std::string>();
    std::cout << "[SHELL HANDLER] message type: |" << msg_type << "|\n";
    if (msg_type == "kernel_info_request") {
        {
            JupyterResponse response;
            response.msg_type = "kernel_info_reply";
            // TODO: is this mapping between request and response the same?
            response.identities = request.identities;
            response.parent_header = request.header;
            response.content["protocol_version"] = "5.0";
            response.content["ipython_version"] = {1, 1, 0, ""};
            response.content["language_version"] = {0, 0, 1};
            response.content["language"] = "simple_kernel";
            response.content["implementation"] = "simple_kernel";
            response.content["implementation_version"] = "1.1";
            response.content["language_info"]["name"] = "simple_kernel";
            response.content["language_info"]["version"] = "1.0";
            response.content["language_info"]["mimetype"] = "";
            response.content["language_info"]["file_extension"] = ".py";
            response.content["language_info"]["pygments_lexer"] = "";
            response.content["language_info"]["codemirror_mode"] = "";
            response.content["language_info"]["nbconvert_exporter"] = "";
            response.content["banner"] = "";
            response.metadata = json::parse("{}");
            std::cout << "response.content: |" << response.content << "|\n";
            send_jupyter_response(shell_socket, global_state, response);
        }
        {
            JupyterResponse response;
            response.msg_type = "status";
            // TODO: is this mapping between request and response the same?
            response.parent_header = request.header;
            response.content["execution_state"] = "idle";
            response.metadata = json::parse("{}");
            send_jupyter_response(iopub_socket, global_state, response);
        }
    } 
    else if (msg_type == "history_request") {
        std::cout << "[shlll handler] unhandled history request\n";
    }
    else if (msg_type == "is_complete_request") {
        // ## Return if line is complete. We say yes if ends if semicolon.
        // # https://jupyter-client.readthedocs.io/en/stable/messaging.html#completion
        // content = {
        //      'execution_state': "busy",
        // }
        // send(iopub_stream, 'status', content, parent_header=msg['header'])
        // #######################################################################
        // is_complete_request_code = msg['content']['code'].strip()
        const std::string is_complete_request_code = request.content["code"];
        {
            JupyterResponse response;
            // metadata = {
            //     "dependencies_met": True,
            //     "engine": ENGINE_ID,
            //     "status": "ok",
            //     "started": datetime.datetime.now().isoformat(),
            // }
            response.metadata["dependencies_met"] = true;
            response.metadata["engine"] = global_state.engine_id;
            response.metadata["status"] = "ok";
            response.metadata["started"] = datetime_now_isoformat();
            // ends_with_semicolon = False
            // if is_complete_request_code:
            //     ends_with_semicolon = is_complete_request_code[-1] == ';'

            // content = {
            //     "status": 'complete' if ends_with_semicolon else 'incomplete',
            //     "indent": "  " # two space indentation
            // }
            response.content["status"] = "complete";
            response.content["indent"] = "  "; // two space indent
            //
            // send(shell_stream, 'is_complete_reply', content, metadata=metadata,
            //     parent_header=msg['header'], identities=identities)
            response.msg_type = "is_complete_reply";
            response.metadata = json_empty_object();
            response.parent_header = request.header;
            response.identities = request.identities;
            send_jupyter_response(shell_socket, global_state, response);
        }
        // #######################################################################
        // content = {
        //     'execution_state': "idle",
        // }
        // send(iopub_stream, 'status', content, parent_header=msg['header'])
        // #######################################################################
        {
            JupyterResponse response;
            response.content["execution_state"] = "idle";
            response.metadata = json::parse("{}");
            response.parent_header = request.header;
            response.msg_type = "status";
            send_jupyter_response(iopub_socket, global_state, response);
        }
    } 
    else if (msg_type == "execute_request") {
        {
            // content = {
            //     'execution_state': "busy",
            // }
            // send(iopub_stream, 'status', content, parent_header=msg['header'])
            // #######################################################################
            JupyterResponse response;
            response.content["execution_state"] = "busy";
            response.metadata = json::parse("{}");
            response.parent_header = request.header;
            response.msg_type = "status";
            send_jupyter_response(iopub_socket, global_state, response);
        }

        const std::string code_to_execute = request.content["code"];
        // TODO: hook into lean here!
        
        std::cout << "[SHELL HANDLER] run_code..........." << std::flush;
        assert(global_state.shell_state);
        lean_object *run_return = run_code(global_state.shell_state, lean_mk_string(code_to_execute.c_str()), lean_io_mk_world());
        // TODO: figure out WTF is going on here.
        run_return = lean_unwrap_io(run_return);
        std::cout << "!\n" << std::flush;

        std::string val(lean_string_cstr(lean_ctor_get(run_return, 0)));
        std::cout << "val: |" << val << "|\n";

        run_return = lean_ctor_get(run_return, 1);
        std::string out(lean_string_cstr(lean_ctor_get(run_return, 0)));
        std::cout << "out: |" << out << "|\n";

        run_return = lean_ctor_get(run_return, 1);
        std::string err(lean_string_cstr(lean_ctor_get(run_return, 0)));
        std::cout << "err: |" << err << "|\n";

        global_state.shell_state = lean_ctor_get(run_return, 1);
        // const ShellExecutionResponse lang_server_response(out, err, out);
        const ShellExecutionResponse lang_server_response(out, err, val);

        {
            // This tells the notebook what is being executed
            // ## https://jupyter-client.readthedocs.io/en/stable/messaging.html#code-inputs
            JupyterResponse response;
            // code_to_execute = msg['content']['code']
            // dprint(1, "simple_kernel Executing:", pformat(code_to_execute))
            // lang_server_response = LANG_SERVER.execute(code_to_execute)
            // dprint(1, "executed code.")

            // content = {
            //     'execution_count': EXECUTION_COUNT,
            //     'code': code_to_execute
            // }
            // send(iopub_stream, 'execute_input', content, parent_header=msg['header'])
            // #######################################################################
            response.content["execution_count"] = global_state.shell_execution_count;
            response.content["code"] = code_to_execute;
            response.metadata = json::parse("{}");
            response.parent_header = request.header;
            response.msg_type = "execute_input";
            send_jupyter_response(iopub_socket, global_state, response);
        }
        {
            JupyterResponse response;
            // content = {
            //     'name': "stdout",
            //     'text': lang_server_response.stdout
            // }
            // send(iopub_stream, 'stream', content, parent_header=msg['header'])
            response.content["name"] = "stdout";
            response.content["text"] = lang_server_response.out;
            response.msg_type = "stream";
            response.parent_header = request.header;
            response.metadata = json_empty_object();
            send_jupyter_response(iopub_socket, global_state, response);
        }

        if (lang_server_response.err.size()) {
            JupyterResponse response;
            // content = {
            //     'name': "stdout",
            //     'text': lang_server_response.stdout
            // }
            // send(iopub_stream, 'stream', content, parent_header=msg['header'])
            response.content["name"] = "stderr";
            response.content["text"] = lang_server_response.err;
            response.msg_type = "stream";
            response.parent_header = request.header;
            response.metadata = json_empty_object();
            send_jupyter_response(iopub_socket, global_state, response);
        }

        {
            JupyterResponse response;
            // content = {
            //     'execution_count': EXECUTION_COUNT,
            //     'data': lang_server_response.result,
            //     'metadata': {}
            // }
            // send(iopub_stream, 'execute_result', content, parent_header=msg['header'])
            response.content["execution_count"] = global_state.shell_execution_count;
            response.content["data"] = lang_server_response.val;
            response.content["metadata"] = json_empty_object();
            response.parent_header = request.header;
            response.msg_type = "execute_result";
            response.metadata = json_empty_object();
            response.parent_header = request.header;
            send_jupyter_response(iopub_socket, global_state, response);

        }

        // if (lang_server_response.err.size()) {
        //     // https://jupyter-client.readthedocs.io/en/stable/messaging.html#execution-errors
        //     JupyterResponse response;
        //     // content = {
        //     //     'execution_count': EXECUTION_COUNT,
        //     //     'data': lang_server_response.result,
        //     //     'metadata': {}
        //     // }
        //     // send(iopub_stream, 'execute_result', content, parent_header=msg['header'])
        //     response.content["data"] = lang_server_response.err;
        //     response.content["metadata"] = json_empty_object();
        //     response.parent_header = request.header;
        //     response.msg_type = "error";
        //     response.metadata = json_empty_object();
        //     response.parent_header = request.header;
        //     send_jupyter_response(iopub_socket, global_state, response);
        // }

        {
            // content = {
            //     'execution_state': "idle",
            // }
            // send(iopub_stream, 'status', content, parent_header=msg['header'])
            //
            JupyterResponse response;
            response.content["execution_state"] = "idle";
            response.metadata = json_empty_object();
            response.parent_header = request.header;
            response.msg_type = "status";
            send_jupyter_response(iopub_socket, global_state, response);
        }
        {

            JupyterResponse response;
            // metadata = {
            //     "dependencies_met": True,
            //     "engine": ENGINE_ID,
            //     "status": "ok",
            //     "started": datetime.datetime.now().isoformat(),
            // }
            response.metadata["dependencies_met"] = true;
            response.metadata["engine"] = global_state.engine_id;
            response.metadata["status"] = "ok";
            response.metadata["started"] = datetime_now_isoformat();
            // content = {
            //     "status": "ok",
            //     "execution_count": EXECUTION_COUNT,
            //     "user_variables": {},
            //     "payload": [],
            //     "user_expressions": {},
            // }
            // send(shell_stream, 'execute_reply', content, metadata=metadata,
            //     parent_header=msg['header'], identities=identities)
            // ##################################################################
            if (err.size()) {
                response.content["status"] = "err";
                response.content["execution_count"] = global_state.shell_execution_count;
                response.content["ename"] = "<<Error Name>>";
                response.content["evalue"] = lang_server_response.err;
                response.content["traceback"] = json_empty_list();
                response.msg_type = "execute_reply";
                response.identities = request.identities;
                response.parent_header = request.header;
            } else {
                response.content["status"] = "ok";
                response.content["execution_count"] = global_state.shell_execution_count;
                response.content["user_variable"] = json_empty_object();
                response.content["payload"] = json_empty_list();
                response.content["user_expressions"] = json_empty_object();
                response.msg_type = "execute_reply";
                response.identities = request.identities;
                response.parent_header = request.header;
            }
            send_jupyter_response(shell_socket, global_state, response);
        }
        global_state.shell_execution_count++;


    }
    else if (msg_type == "comm_info_request") {
        std::cout << "[SHELL HANDLER] Not handing comm_info_request";
    }
    else {
        std::cout << "[SHELL HANDLER] ===unknown message type: |" << msg_type << "|\n";
        assert(false && "unknown message type");
    }
};


// ZMQ wrapper to recieve a message and wrap in a std::string.
std::tuple<void*, int, std::string> zmq_msg_recv_str(void *s_) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    int rc = zmq_msg_recv(&msg, s_, 0);
    assert(rc != -1);
    int size = zmq_msg_size(&msg);
    char *s = (char *)calloc(size + 1, sizeof(unsigned char));
    memcpy(s, zmq_msg_data(&msg), size * sizeof(unsigned char));
    s[size] = 0;
    std::string out(s);
    // TODO: we're leaking s here!
    return {s, size, out};
}



int main(int argc, char **argv) {
    srand(0);
    // TODO: need to parse argv for json file.
    assert(argc == 2  && "expected config JSON file path");
    std::stringstream config_buffer;
    {
        std::cout << "Starting up C++ kernel...path: |" << argv[1] << "|\n";
        std::ifstream config_file(argv[1]);
        config_buffer << config_file.rdbuf();
    }
    json config = json::parse(config_buffer.str());
    std::cout << "Starting up C++ kernel...json:\n";
    std::cout << config << "\n";


    using namespace std::chrono_literals;
    const std::string connection = 
        config["transport"].get<std::string>() + "://" + config["ip"].get<std::string>();
    const std::string heartbeat_port = std::to_string(config["hb_port"].get<ll>());
    const std::string iopub_port = std::to_string(config["iopub_port"].get<ll>());
    const std::string control_port = std::to_string(config["control_port"].get<ll>());
    const std::string stdin_port = std::to_string(config["stdin_port"].get<ll>());
    const std::string shell_port = std::to_string(config["shell_port"].get<ll>());
    const std::string signature_scheme = config["signature_scheme"].get<std::string>();
    assert(signature_scheme == "hmac-sha256");

    GlobalState global_state;
    global_state.key = config["key"].get<std::string>();
    global_state.engine_id = uuid4();
    lean_initialize();
    // lean_initialize_runtime_module();
    initialize_REPLLib(lean_io_mk_world());
    // initialize_ir_interpreter();
    lean_io_mark_end_initialization();

    global_state.shell_state = lean_unwrap_io(mk_init_state(lean_io_mk_world()));

    // https://github.com/kazuho/picohash/blob/master/picohash.h
    // auth = hmac.HMAC(
    //     secure_key,
    //     digestmod=signature_schemes[config["signature_scheme"]])

    // initialize the zmq ctx with a single IO thread
    int rc = 0; // return code
    void *ctx = zmq_ctx_new ();
    // zmq::context_t ctx{1};

    void *sockets[NPOLLEDSOCKETS];
    // ##########################################
    // # Heartbeat:
    sockets[HEARTBEAT] = zmq_socket(ctx, ZMQ_REP);
    {
        const std::string s = connection + ":" + heartbeat_port;
        rc = zmq_bind(sockets[HEARTBEAT], s.c_str());
        assert(rc == 0);
    }

    // ##########################################
    // # IOPub/Sub
    // # also called SubSocketChannel in IPython sources
    void *iopub_socket = zmq_socket(ctx, ZMQ_PUB);
    {
        const std::string s = connection + ":" + iopub_port;
        rc = zmq_bind(iopub_socket, s.c_str());
        assert(rc == 0);
    }
    // iopub_stream = zmqstream.ZMQStream(iopub_socket)
    // iopub_stream.on_recv(iopub_handler)


    // ##########################################
    // # Control:
    sockets[CONTROL] = zmq_socket(ctx, ZMQ_ROUTER);
    {
        const std::string s = connection + ":" + control_port;
        rc = zmq_bind(sockets[CONTROL], s.c_str());
        assert(rc == 0);
    }
 

    // ##########################################
    // # Stdin
    sockets[STDIN] = zmq_socket(ctx, ZMQ_ROUTER);
    {
        const std::string s = connection + ":" + stdin_port;
        rc = zmq_bind(sockets[STDIN], s.c_str());
        assert(rc == 0);
    }

    // ##########################################
    // # shell
    sockets[SHELL] = zmq_socket(ctx, ZMQ_ROUTER);
    {
        const std::string s = connection + ":" + shell_port;
        rc = zmq_bind(sockets[SHELL], s.c_str());
        assert(rc == 0);
    }


    std::cout << "[KERNEL] starting polling loop\n";
    // http://api.zeromq.org/master:zmq-poll
    zmq_pollitem_t items [NPOLLEDSOCKETS];
    for(int i = 0; i < NPOLLEDSOCKETS; ++i) {
        items[i].socket = sockets[i];
        items[i].events = ZMQ_POLLIN;
    }

    while(1) {
        // polling is too noisy
        // std::cout << "[KERNEL] polling\n";
        int rc = zmq_poll (items, NPOLLEDSOCKETS, -1);
        assert(rc >= 0); // did not error
        assert(rc > 0); // did not timeout.

        // heartbeat is too noisy.
        for(int i = HEARTBEAT+1; i < NPOLLEDSOCKETS; ++i) {
            if (items[i].revents != 0) {
                std::cout << "[KERNEL] got message on [" << 
                    polled_socket_kind_to_str((PolledSocketKind)i) << "]\n";
            }
        }

        if (items[HEARTBEAT].revents != 0) {
            // vvv quite noisy.
            // std::cout << "[KERNEL] [HEARTBEAT] bouncing\n";
            zmq_msg_t msg;
            rc = zmq_msg_init (&msg);
            assert (rc == 0);
            rc = zmq_recvmsg (sockets[HEARTBEAT], &msg, 0);
            assert (rc != -1);
            // Release message
            rc = zmq_msg_send(&msg, sockets[HEARTBEAT], 0);
            assert(rc != -1);
            zmq_msg_close (&msg);
            
        }
        if (items[CONTROL].revents & ZMQ_POLLIN) {
            std::cout << "[KERNEL] [CONTROL] has request [" << 
                items[CONTROL].revents << "]\n";
            assert(items[CONTROL].revents & ZMQ_POLLIN);
            std::string msg = std::get<2>(zmq_msg_recv_str(sockets[CONTROL]));
            std::cout << "[KERNEL] [CONTROL] |" << msg << "|\n";
        }
        if (items[SHELL].revents & ZMQ_POLLIN) {
            std::cout << "[KERNEL] [SHELL] has request\n";

            // http://api.zeromq.org/2-0:zmq-recv
            std::vector<std::tuple<void *, int, std::string>> messages;
            int64_t more = 0;
            do {
                std::tuple<void *, int, std::string> s = zmq_msg_recv_str(sockets[SHELL]);
                messages.push_back(s);
                size_t ll_size = sizeof(int64_t);
                rc = zmq_getsockopt(sockets[SHELL], ZMQ_RCVMORE, &more, &ll_size);
                assert(rc == 0);
            } while(more);

            // TODO: will delim_index ever not be equal to 1?
            int delim_index = -1; // index of delimiter
            for(int i = 0; i < messages.size(); ++i) {
                if (std::get<2>(messages[i]) == DELIM) { delim_index = i; }
                std::cout << "  - " << std::get<2>(messages[i]) << "\n";
            }
            assert(delim_index != -1 && "unable to find delimiter");
            assert(delim_index == 1 && "GUESS: delim_index will always be 1");
            // identities = messages[0:delim_index]
            // signature = messages[delim_index+1]
            // msg_frames = wire_msg[delim_idx + 2:]
            // m = {}
            // m['header']        = decode(msg_frames[0])
            // m['parent_header'] = decode(msg_frames[1])
            // m['metadata']      = decode(msg_frames[2])
            // m['content']       = decode(msg_frames[3])
            ShellRequest request;
            request.header = json::parse(std::get<2>(messages[delim_index + 2 + 0]));
            request.parent_header = json::parse(std::get<2>(messages[delim_index + 2 + 1]));
            request.metadata = json::parse(std::get<2>(messages[delim_index + 2 + 2]));
            request.content = json::parse(std::get<2>(messages[delim_index + 2 + 3]));

            // TODO: should this be a list? will this ever be a list?
            for(int i = 0; i < delim_index; ++i) {
                request.identities.push_back(messages[i]);
            }
            shell_handler(iopub_socket, sockets[SHELL], global_state, request);
        }


        
        // receive a request from client
        // socket.recv(request, zmq::recv_flags::none);
        // std::cout << "Received " << request.to_string() << "\n";

        // heartbeat
        // zmq_device(ZMQ_FORWARDER, sockets[HEARTBEAT].handle(), sockets[HEARTBEAT].handle());
        // std::cout << "Sent heartbeat.\n";

        // simulate work
        // std::this_thread::sleep_for(1s);

        // send the reply to the client
        // socket.send(zmq::buffer(data), zmq::send_flags::none);
    }

    return 0;
}


