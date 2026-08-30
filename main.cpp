#include <chrono>
#include <iostream>
#include <map>
#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol/messages.h"


struct Peer {
    uint64_t node_id;
    Endpoint private_endpoint;
    Endpoint public_endpoint;
    std::chrono::steady_clock::time_point last_seen;
};

Notify build_notify(Peer& peer) {
    Notify notify{};
    notify.header.type = MessageType::NOTIFY;
    notify.header.node_id = peer.node_id;
    notify.public_endpoint = peer.public_endpoint;
    notify.private_endpoint = peer.private_endpoint;
    return notify;
}

int main() {
    std::unordered_map<uint64_t, Peer> peers;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
        perror("bind");
        exit(1);
    }

    std::cout << "Listening on port 9999" << std::endl;

    while (true) {
        uint8_t buf[1024];
        sockaddr_in sender{};
        socklen_t sender_len = sizeof(sender);

        ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&sender), &sender_len);

        if (n <= 0) continue;
        if (n < sizeof(Header)) continue;

        auto* header = reinterpret_cast<Header*>(buf);

        switch (static_cast<MessageType>(header->type)) {
            case MessageType::REGISTER: {
                auto* msg = reinterpret_cast<Register*>(buf);
                Peer peer{};

                peer.node_id = header->node_id;
                peer.public_endpoint.ip = sender.sin_addr.s_addr;
                peer.public_endpoint.port = sender.sin_port;
                peer.private_endpoint.ip = msg->private_endpoint.ip;
                peer.private_endpoint.port = msg->private_endpoint.port;
                peer.last_seen = std::chrono::steady_clock::now();

                peers[header->node_id] = peer;

                printf("Registered peer %lu - public: %s:%d\n",
                    peer.node_id, inet_ntoa(sender.sin_addr), ntohs(sender.sin_port));

                break;
            }

            case MessageType::KEEPALIVE: {
                auto it = peers.find(header->node_id);
                if (it == peers.end()) break;

                it->second.last_seen = std::chrono::steady_clock::now();
                it->second.public_endpoint.ip = sender.sin_addr.s_addr;
                it->second.public_endpoint.port = sender.sin_port;

                printf("Keepalive peer %lu\n", header->node_id);
                break;
            }

            case MessageType::REQUEST: {
                auto* msg = reinterpret_cast<Request*>(buf);

                // finding target peer
                auto it = peers.find(msg->target_node_id);
                if (it == peers.end()) break;
                Peer& target = it->second;

                // building requester A
                Peer requester{};
                requester.node_id = header->node_id;
                requester.public_endpoint.ip = sender.sin_addr.s_addr;
                requester.public_endpoint.port = sender.sin_port;
                requester.private_endpoint = msg->private_endpoint;

                // notify A about B's endpoints
                auto notify_a = build_notify(target);
                ::sendto(fd, &notify_a, sizeof(notify_a), 0, reinterpret_cast<sockaddr*>(&sender),
                    sizeof(sender));


                // notify B about A's endpoints
                sockaddr_in target_addr{};
                target_addr.sin_family = AF_INET;
                target_addr.sin_port = target.public_endpoint.port;
                target_addr.sin_addr.s_addr = target.public_endpoint.ip;

                auto notify_b = build_notify(requester);
                ::sendto(fd, &notify_b, sizeof(notify_b), 0, reinterpret_cast<sockaddr*>(&target_addr),
                    sizeof(target_addr));

                printf("Coordinated punch: %lu <==> %lu\n", header->node_id, msg->target_node_id);

                break;

            }
        }


    }

}