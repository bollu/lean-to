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

using namespace nlohmann;

std::string uuid4() {
    // https://github.com/mariusbancila/stduuid/blob/master/include/uuid.h
    return "78d25e41-171d-494b-92f2-4fce84fb3524";
}
using ll = long long;

enum SocketKind {
    HEARTBEAT,
    IOPUB,
    CONTROL,
    STDIN,
    SHELL,
    NSOCKETKIND
};

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
    const std::string key = uuid4();//
    const std::string signature_scheme = "hmac-sha256";
    // const char *secure_key = key.c_str();
    const std::string heartbeat_port = std::to_string(config["hb_port"].get<ll>());
    const std::string iopub_port = std::to_string(config["iopub_port"].get<ll>());
    const std::string control_port = std::to_string(config["control_port"].get<ll>());
    const std::string stdin_port = std::to_string(config["stdin_port"].get<ll>());
    const std::string shell_port = std::to_string(config["shell_port"].get<ll>());


    // https://github.com/kazuho/picohash/blob/master/picohash.h
    // auth = hmac.HMAC(
    //     secure_key,
    //     digestmod=signature_schemes[config["signature_scheme"]])

    // initialize the zmq ctx with a single IO thread
    int rc = 0; // return code
    void *ctx = zmq_ctx_new ();
    // zmq::context_t ctx{1};

    void *sockets[NSOCKETKIND];
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
    sockets[IOPUB] = zmq_socket(ctx, ZMQ_PUB);
    {
        const std::string s = connection + ":" + iopub_port;
        rc = zmq_bind(sockets[IOPUB], s.c_str());
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
    zmq_pollitem_t items [5];
    items[0].socket = sockets[HEARTBEAT];
    items[0].events = ZMQ_POLLIN;
    for (;;) {
        // zmq::message_t request;
        std::cout << "[KERNEL] polling heartbeat\n";
        int rc = zmq_poll (items, 1, -1);
        assert (items[0].revents != 0);
        assert(rc > 0); // did not timeout.
        assert(rc >= 0);
        if (items[0].revents != 0) {
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


