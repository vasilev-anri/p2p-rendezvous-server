#pragma once
#include <cstdint>


enum class MessageType : uint8_t {
    REGISTER,
    KEEPALIVE,
    REQUEST,
    NOTIFY,
};

struct Header {
    uint64_t node_id;
    MessageType type;
} __attribute__((packed));

struct Endpoint {
    uint32_t ip;
    uint16_t port;
} __attribute__((packed));

struct Register {
    Header header;
    Endpoint private_endpoint;
} __attribute__((packed));

struct Request {
    Header header;
    uint64_t target_node_id;
    Endpoint private_endpoint;
} __attribute__((packed));

struct Notify {
    Header header;

    Endpoint public_endpoint;
    Endpoint private_endpoint;
} __attribute__((packed));