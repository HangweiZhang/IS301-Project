#ifndef HEADERINFO_H
#define HEADERINFO_H

typedef unsigned char u_char ;      // 1 byte
typedef unsigned short u_short ;     // 2 byte
typedef unsigned int u_int ;        // 4 byte

// Ethernet header
typedef struct ether_header{   // 14 byte
    u_char ether_des[6];  // destination address [6 byte]
    u_char ether_src[6];  // source address [6 byte]
    u_short ether_type;        // type [2 byte]
}ETHER_HEADER;

// Ipv4 header
typedef struct ip_header{           // 20 byte
    u_char ver_h_length;    // version [4 bit] and length of header [4 bit]
    u_char TOS;                     // TOS/DS_byte [1 byte]
    u_short total_length;           // ip package total length [2 byte]
    u_short identification;         // identification [2 byte]
    u_short flag_offset;            // flag [3 bit] and offset [13 bit]
    u_char ttl;                     // TTL [1 byte]
    u_char protocol;                // protocal [1 byte]
    u_short checksum;               // checksum [2 byte]
    u_int src_addr;                 // source address [4 byte]
    u_int des_addr;                 // destination address [4 byte]
}IP_HEADER;

// Tcp header
typedef struct tcp_header{    // 20 byte
    u_short src_port;         // source port [2 byte]
    u_short des_port;         // destination [2 byte]
    u_int sequence;           // sequence number [4 byte]
    u_int ack;                // Confirm serial number [4 byte]
    u_char header_length;     // header length [4 bit]
    u_char reserve;               // reserve [6 bit]
    u_char flags;             // flags [6 bit]
    u_short window_size;      // size of window [2 byte]
    u_short checksum;         // checksum [2 byte]
    u_short urgent;           // urgent pointer [2 byte]
}TCP_HEADER;

// Udp header
typedef struct udp_header{ // 8 byte
    u_short src_port;      // source port [2 byte]
    u_short des_port;      // destination port [2 byte]
    u_short data_length;   // data length [2 byte]
    u_short checksum;      // checksum [2 byte]

}UDP_HEADER;

// Icmp header
typedef struct icmp_header{         // at least 8 byte
    u_char type;                    // type [1 byte]
    u_char code;                    // code [1 byte]
    u_short checksum;               // checksum [2 byte]
    u_short identification;         // identification [2 byte]
    u_short sequence;               // sequence [2 byte]
}ICMP_HEADER;

// Arp header
typedef struct arp_header{   // 28 byte
    u_short hardware_type;   // hardware type [2 byte]
    u_short protocol_type;   // protocol [2 byte]
    u_char mac_length;       // MAC address length [1 byte]
    u_char ip_length;        // IP address length [1 byte]
    u_short op_code;         // operation code [2 byte]

    u_char src_eth_addr[6];  // source ether address [6 byte]
    u_char src_ip_addr[4];   // source ip address [4 byte]
    u_char des_eth_addr[6];  // destination ether address [6 byte]
    u_char des_ip_addr[4];   // destination ip address [4 byte]

}ARP_HEADER;

#endif // HEADERINFO_H
