#include <string>
#include <chrono>
#include <thread>
#include <iostream>
#include <zmq.h>
#include <zmq.hpp>
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
    zmq::context_t ctx{1};

    // ##########################################
    // # Heartbeat:
    zmq::socket_t heartbeat_socket{ctx, zmq::socket_type::rep};
    heartbeat_socket.bind(connection + ":" + heartbeat_port); // we might need 127.0.0.1

    // ##########################################
    // # IOPub/Sub
    // # also called SubSocketChannel in IPython sources
    zmq::socket_t iopub_socket{ctx, zmq::socket_type::pub};
    iopub_socket.bind(connection + ":" + iopub_port);
    // iopub_stream = zmqstream.ZMQStream(iopub_socket)
    // iopub_stream.on_recv(iopub_handler)


    // ##########################################
    // # Control:
    zmq::socket_t control_socket{ctx, zmq::socket_type::router};
    control_socket.bind(connection + ":" + control_port);

    // ##########################################
    // # Stdin
    zmq::socket_t stdin_socket{ctx, zmq::socket_type::router};
    control_socket.bind(connection + ":" + stdin_port);

    // ##########################################
    // # shell
    zmq::socket_t shell_socket{ctx, zmq::socket_type::router};
    shell_socket.bind(connection + ":" + shell_port);

    // prepare some static data for responses
    const std::string data{"World"};

    for (;;) {
        zmq::message_t request;
        
        // receive a request from client
        // socket.recv(request, zmq::recv_flags::none);
        std::cout << "Received " << request.to_string() << std::endl;

        // heartbeat
        zmq_device(ZMQ_FORWARDER, heartbeat_socket.handle(), heartbeat_socket.handle());

        // simulate work
        // std::this_thread::sleep_for(1s);

        // send the reply to the client
        // socket.send(zmq::buffer(data), zmq::send_flags::none);
    }

    return 0;
}


