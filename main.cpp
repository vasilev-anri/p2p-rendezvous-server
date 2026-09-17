#include <chrono>
#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol/rendezvous_codec.h"
#include "protocol/messages.h"
#include "security/hmac_utils.h"


constexpr auto PEER_TIMEOUT = std::chrono::seconds(90);

struct Peer {
    uint64_t node_id;
    Endpoint private_endpoint;
    Endpoint public_endpoint;
    std::chrono::steady_clock::time_point last_seen;
};

Notify build_notify(Peer& peer) {
    Notify notify{};
    notify.header.type = RendezvousMessageType::NOTIFY;
    notify.header.node_id = peer.node_id;
    notify.public_endpoint = peer.public_endpoint;
    notify.private_endpoint = peer.private_endpoint;
    return notify;
}

void expire_peers(std::unordered_map<uint64_t, Peer>& peers) {
    auto now = std::chrono::steady_clock::now();
    std::erase_if(peers, [&](const auto& pair) {
        return now - pair.second.last_seen > PEER_TIMEOUT;
    });
}

int main() {
    auto secret = HMACAuth::load_secret();

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

    printf("Listening on port 9999\n");

    struct timeval tv{};
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (true) {
        uint8_t buf[1024];
        sockaddr_in sender{};
        socklen_t sender_len = sizeof(sender);

        ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&sender), &sender_len);

        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                expire_peers(peers);
            }
            continue;
        }

        auto verified = HMACAuth::verify_and_strip(secret, std::span<const uint8_t>(buf, n));
        if (!verified) {
            printf("Dropped unauthenticated packet\n");
            continue;
        }

        if (verified->size() < Header::HEADER_SIZE) continue;

        auto header = RendezvousCodec::decode_header(std::span<const uint8_t>(*verified));

        switch (header.type) {
            case RendezvousMessageType::REGISTER: {
                auto msg = RendezvousCodec::decode_register(std::span<const uint8_t>(*verified));

                Peer peer{};

                peer.node_id = header.node_id;
                peer.public_endpoint.ip = ntohl(sender.sin_addr.s_addr);
                peer.public_endpoint.udp_port = ntohs(sender.sin_port);
                peer.public_endpoint.tcp_port = msg.private_endpoint.tcp_port;

                peer.private_endpoint.ip = msg.private_endpoint.ip;
                peer.private_endpoint.udp_port = msg.private_endpoint.udp_port;
                peer.private_endpoint.tcp_port = msg.private_endpoint.tcp_port;

                peer.last_seen = std::chrono::steady_clock::now();

                peers[header.node_id] = peer;

                printf("Registered peer %lu - public: %s:%d\n",
                    peer.node_id, inet_ntoa(sender.sin_addr), ntohs(sender.sin_port));

                break;
            }

            case RendezvousMessageType::KEEPALIVE: {
                auto it = peers.find(header.node_id);
                if (it == peers.end()) break;

                it->second.last_seen = std::chrono::steady_clock::now();
                it->second.public_endpoint.ip = ntohl(sender.sin_addr.s_addr);
                it->second.public_endpoint.udp_port = ntohs(sender.sin_port);

                break;
            }

            case RendezvousMessageType::REQUEST: {
                auto msg = RendezvousCodec::decode_request(std::span<const uint8_t>(*verified));

                // finding target peer
                auto it = peers.find(msg.target_node_id);
                if (it == peers.end()) break;
                Peer& target = it->second;

                // building requester A
                Peer requester{};
                requester.node_id = header.node_id;
                requester.public_endpoint.ip = ntohl(sender.sin_addr.s_addr);
                requester.public_endpoint.udp_port = ntohs(sender.sin_port);
                requester.public_endpoint.tcp_port = msg.private_endpoint.tcp_port;

                requester.private_endpoint = msg.private_endpoint;

                // notify A about B's endpoints
                auto notify_a = build_notify(target);
                auto data_a = RendezvousCodec::encode_notify(notify_a);
                auto data_a_signed = HMACAuth::sign(secret, data_a);
                ::sendto(fd, data_a_signed.data(), data_a_signed.size(), 0, reinterpret_cast<sockaddr*>(&sender),
                         sizeof(sender));


                // notify B about A's endpoints
                sockaddr_in target_addr{};
                target_addr.sin_family = AF_INET;
                target_addr.sin_port = htons(target.public_endpoint.udp_port);
                target_addr.sin_addr.s_addr = htonl(target.public_endpoint.ip);

                auto notify_b = build_notify(requester);
                auto data_b = RendezvousCodec::encode_notify(notify_b);
                auto data_b_signed = HMACAuth::sign(secret, data_b);
                ::sendto(fd, data_b_signed.data(), data_b_signed.size(), 0, reinterpret_cast<sockaddr*>(&target_addr),
                    sizeof(target_addr));

                printf("Coordinated punch: %lu <==> %lu\n", header.node_id, msg.target_node_id);

                break;

            }
        }
    }
}