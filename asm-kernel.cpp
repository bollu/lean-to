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
#include "uuid.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "json.hpp"

// ZMQ guide for C devs:
// https://lqhl.me/resources/zguide-c.pdf

using namespace nlohmann;

std::string uuid4() {
    // https://github.com/mariusbancila/stduuid/blob/master/include/uuid.h
    return "78d25e41-171d-494b-92f2-4fce84fb3524";
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
}

// information a shell event possess.
struct ShellEvent {
    json header;
    json parent_header;
    json metadata;
    json content;
    std::vector<std::string> identities;
};

struct ShellResponse {
    std::string msg_type;
    json content;
    json parent_header;
    json metadata;
    // TODO: should this be a list? will this ever be a list?
    std::vector<std::string> identities;
};

// unique state held across session
struct GlobalState {
    std::string key; // signing key is some random UUID
    std::string engine_id; // engine ID is some random UUID
};

int zmq_msg_send_str(void *s_, std::string s, int flags) {
    int rc = 0;
    zmq_msg_t msg;
    rc = zmq_msg_init(&msg);
    assert(rc == 0);
    rc = zmq_msg_init_size(&msg, s.size()+1);
    assert (rc == 0);
    /* Fill in message content with 'AAAAAA' */
    memcpy (zmq_msg_data(&msg), s.c_str(), s.size()+1);
    rc = zmq_msg_send(&msg, s_, flags);
    assert(rc != -1);
    return rc;
}

void send_shell_response(void *socket, GlobalState globals, const
        ShellResponse &response) {
    json header;
    header["date"] = "TODO-MAKEUP-DATE";
    header["msg_id"] = uuid4(); // TODO:ouch!
    header["username"] = "kernel"; 
    header["session"] = globals.engine_id;
    header["msg_type"] = response.msg_type;
    header["version"] = 5.0;

    HMAC_CTX *h = HMAC_CTX_new();
    HMAC_Init(h, globals.key.c_str(), globals.key.size(), EVP_sha256());

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

    for(std::string &m : msg_list) {
        HMAC_Update(h, (const unsigned char *) m.c_str(), m.size());
    }

    unsigned char rawsig[1024];
    unsigned int siglen;
    HMAC_Final(h, rawsig, &siglen);
    assert(siglen < 512);
    rawsig[siglen] = 0;

    std::stringstream signature;
    for(int i = 0; i < siglen; ++i) {
        signature << std::hex << (0xFF & rawsig[i]);
    }


    // msg_lst = [ encode(header), encode(parent_header), encode(metadata), encode(content) ]
    // parts = [DELIM, signature, msg_lst[0], msg_lst[1], msg_lst[2], msg_lst[3]]
    // if identities: parts = identities + parts
    // dprint(3, "send parts:", parts)
    // stream.send_multipart(parts)
    // stream.flush()
    // construct response.
    std::vector<std::string> parts;
    parts.insert(parts.end(), response.identities.begin(), response.identities.end());
    parts.push_back(DELIM);
    parts.push_back(signature.str());
    parts.insert(parts.end(), msg_list.begin(), msg_list.end());
    int rc = 0;
    for(int i = 0; i < parts.size(); ++i) {
        std::cout << "sent |[" << i << "]" << parts[i] << "|\n"; 
        rc = zmq_msg_send_str(socket, parts[i], i + 1 < parts.size() ? ZMQ_SNDMORE : 0);
        assert(rc != -1);
    }
}

// handle shell event by replying on iopub and shell sockets
void shell_handler(void *iopub_socket, void *shell_socket, 
    GlobalState global_state, ShellEvent event) {
    std::cout << "[SHELL HANDLER] identities: ";
    for(int i = 0; i < event.identities.size(); ++i) {
        std::cout << "|" << event.identities[i] << "|";
    }

    std::cout << "\n";
    std::cout << "[SHELL HANDLER] header: |" << event.header << "|\n";
    std::cout << "[SHELL HANDLER] parent_header: |" << event.parent_header << "|\n";
    std::cout << "[SHELL HANDLER] metadata: |" << event.metadata << "|\n";
    std::cout << "[SHELL HANDLER] content: |" << event.content << "|\n";

    const std::string msg_type = event.header["msg_type"].get<std::string>();
    std::cout << "[SHLLL HANDLER] message type: |" << msg_type << "|\n";
    if (msg_type == "kernel_info_request") {
        {
            ShellResponse response;
            response.msg_type = "kernel_info_reply";
            response.metadata = json::parse("{}");
            // TODO: is this mapping between event and response the same?
            response.identities = event.identities;
            response.parent_header = event.header;
            response.content["protocol_version"] = "5.0";
            response.content["ipython_version"] = {1, 1, 0, ""};
            response.content["language"] = "simple_kernel";
            response.content["implementation_version"] = "1.1";
            response.content["language_info"]["name"] = "simple_kernel";
            response.content["language_info"]["version"] = "1.0";
            response.content["language_info"]["mimetype"] = "";
            response.content["language_info"]["file_extension"] = ".py";
            response.content["language_info"]["pygments_lexer"] = "";
            response.content["language_info"]["codemirror_mode"] = "";
            response.content["language_info"]["nbconvert_exporter"] = "";
            response.content["banner"] = "";
            std::cout << "response.content: |" << response.content << "|\n";
            // = json::parse("{"
            //     "    'protocol_version': '5.0',"
            //     "    'ipython_version': [1, 1, 0, ''],"
            //     "    'language_version': [0, 0, 1],"
            //     "    'language': 'simple_kernel',"
            //     "    'implementation': 'simple_kernel',"
            //     "    'implementation_version': '1.1',"
            //     "    'language_info': {"
            //     "        'name': 'simple_kernel',"
            //     "        'version': '1.0',"
            //     "        'mimetype': '',"
            //     "        'file_extension': '.py',"
            //     "        'pygments_lexer': '',"
            //     "        'codemirror_mode': '',"
            //     "        'nbconvert_exporter': '',"
            //     "    },"
            //     "    'banner': ''"
            //     "}");
            send_shell_response(shell_socket, global_state, response);
        }
        {
            ShellResponse response;
            response.msg_type = "status";
            // TODO: is this mapping between event and response the same?
            response.parent_header = event.header;
            response.content["execution_state"] = "idle";
            response.metadata = json::parse("{}");
            send_shell_response(iopub_socket, global_state, response);
        }
    }
    else if (msg_type == "execute_request") {
    } else {
        assert(false && "unknown message type");
    }
};


// ZMQ wrapper to recieve a message and wrap in a std::string.
std::string zmq_msg_recv_str(void *s_) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    int rc = zmq_msg_recv(&msg, s_, 0);
    assert(rc != -1);
    int size = zmq_msg_size(&msg);
    char *s = (char *)calloc(size + 1, sizeof(unsigned char));
    memcpy(s, zmq_msg_data(&msg), size * sizeof(unsigned char));
    s[size] = 0;
    std::string out(s);
    free(s);
    return out;
}

int main(int argc, char **argv) {
    // TODO: need to parse argv for json file.
    assert(argc == 2  && "expected config JSON file path");
    std::stringstream config_buffer;
    {
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

    for (;;) {
        // zmq::message_t request;
        std::cout << "[KERNEL] polling\n";
        int rc = zmq_poll (items, NPOLLEDSOCKETS, -1);
        assert(rc >= 0); // did not error
        assert(rc > 0); // did not timeout.

        for(int i = 0; i < NPOLLEDSOCKETS; ++i) {
            if (items[i].revents != 0) {
                std::cout << "[KERNEL] got message on [" << 
                    polled_socket_kind_to_str((PolledSocketKind)i) << "]\n";
            }
        }

        if (items[HEARTBEAT].revents != 0) {
            std::cout << "[KERNEL] [HEARTBEAT] bouncing\n";
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
            std::cout << "[KERNEL] [CONTROL] has event [" << 
                items[CONTROL].revents << "]\n";
            assert(items[CONTROL].revents & ZMQ_POLLIN);
            std::string msg = zmq_msg_recv_str(sockets[CONTROL]);
            std::cout << "[KERNEL] [CONTROL] |" << msg << "|\n";
        }
        if (items[SHELL].revents & ZMQ_POLLIN) {
            std::cout << "[KERNEL] [SHELL] has event\n";

            // http://api.zeromq.org/2-0:zmq-recv
            std::vector<std::string> messages;
            int64_t more = 0;
            do {
                std::string s = zmq_msg_recv_str(sockets[SHELL]);
                messages.push_back(s);
                size_t ll_size = sizeof(int64_t);
                rc = zmq_getsockopt(sockets[SHELL], ZMQ_RCVMORE, &more, &ll_size);
                assert(rc == 0);
            } while(more);

            // TODO: will delim_index ever not be equal to 1?
            int delim_index = -1; // index of delimiter
            for(int i = 0; i < messages.size(); ++i) {
                if (messages[i] == DELIM) { delim_index = i; }
                std::cout << "  - " << messages[i] << "\n";
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
            ShellEvent event;
            event.header = json::parse(messages[delim_index + 2 + 0]);
            event.parent_header = json::parse(messages[delim_index + 2 + 1]);
            event.metadata = json::parse(messages[delim_index + 2 + 2]);
            event.content = json::parse(messages[delim_index + 2 + 3]);

            // TODO: should this be a list? will this ever be a list?
            for(int i = 0; i < delim_index; ++i) {
                event.identities.push_back(messages[i]);
            }
            shell_handler(iopub_socket, sockets[SHELL], global_state, event);
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


