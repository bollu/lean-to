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

enum PolledSocketKinds {
    HEARTBEAT,
    CONTROL,
    STDIN,
    SHELL,
    NPOLLEDSOCKETS
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
        assert(rc > 0); // did not timeout.
        assert(rc >= 0);

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
            char buf[1025];
            rc = zmq_recv(sockets[CONTROL],buf, 1024, 0);
            buf[1024] = 0;
            assert(rc != -1);
            std::cout << "[KERNEL] [CONTROL] |" << buf << "|\n";

            // zmq_msg_t msg;
            // rc = zmq_msg_init (&msg);
            // assert (rc == 0);
            // std::cout << "\trecieving..." << std::flush;
            // rc = zmq_msg_recv (&msg, sockets[CONTROL], 0);
            // assert (rc != -1);
            // std::cout << "done!\n";
            // unsigned char *data = (unsigned char *)zmq_msg_data(&msg);
            // int size = zmq_msg_size(&msg);
            // std::cout << "[KERNEL] [CONTROL] size=" << size << "\n";
            // zmq_msg_close (&msg);
        }
        if (items[SHELL].revents & ZMQ_POLLIN) {
            std::cout << "[KERNEL] [SHELL] has event\n";

            char buf[1025];
            rc = zmq_recv(sockets[SHELL],buf, 1024, 0);
            buf[1024] = 0;
            assert(rc != -1);
            std::cout << "[KERNEL] [SHELL] |" << buf << "|\n";
        }
        for(int i = 2; i < NPOLLEDSOCKETS; ++i) {
            if (items[i].revents != 0) {
                std::cout << "GOT MESSAGE ON [" << i << "]\n";
            }
            assert(items[i].revents == 0);
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


