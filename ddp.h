#ifndef __DDP_H__
#define __DDP_H__

#define DDPTYPE_RTMPRD  1
#define DDPTYPE_NBP     2
#define DDPTYPE_ATP     3
#define DDPTYPE_AEP     4
#define DDPTYPE_RTMPR   5
#define DDPTYPE_ZIP     6
#define DDPTYPE_ADSP    7

#define NBPOP_BRRQ       0x1
#define NBPOP_LKUP       0x2
#define NBPOP_LKUPREPLY  0x3
#define NBPOP_FWD        0x4
#define NBPOP_RGSTR      0x7
#define NBPOP_UNRGSTR    0x8
#define NBPOP_CONFIRM    0x9
#define NBPOP_OK         0xa  /* NBPOP_STATUS_REPLY */
#define NBPOP_CLOSE_NOTE 0xb

#define NBPOP_ERROR      0xf

#define NBPMATCH_NOGLOB (1<<1)
#define NBPMATCH_NOZONE (1<<2)

#define APPLETALK_DATA_PACKET 0x809b
#define AARP_PACKET 0x80f3

typedef struct __attribute__((packed)) {
	uint8_t dest_addr[6];
	uint8_t src_addr[6];
	uint16_t len;
} _802_3_header;

typedef struct __attribute__((packed)) {
	uint8_t dest_sap;
	uint8_t src_sap;
	uint8_t control;
} _802_2_header;

typedef struct __attribute__((packed)) {
	uint8_t protocol[3];
	uint16_t packet_type;
} SNAP_protocol_discriminator;

typedef struct __attribute__((packed)) {
	_802_3_header eth_802_3_header;
	_802_2_header eth_802_2_header;
	SNAP_protocol_discriminator snap_protocol_discriminator;
} ELAP_header;

typedef struct __attribute__((packed)) {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_addr_len;
	uint8_t protocol_addr_len;
	uint16_t function;
	uint8_t src_hw_addr[6];
	uint8_t src_at_addr[4];
	uint8_t dest_hw_addr[6];
	uint8_t dest_at_addr[4];
} AARP_packet;

typedef struct __attribute__((packed)) {
	uint16_t len; // & 0x03ff
	uint8_t dest_socket_number;
	uint8_t src_socket_number;
	uint8_t type;
} DDP_short_header;

typedef struct __attribute__((packed)) {
	uint16_t len; // & 0x03ff -- hops = & 0x3c00
	uint16_t checksum;
	uint16_t dest_network_number;
	uint16_t src_network_number;
	uint8_t dest_node_id;
	uint8_t src_node_id;
	uint8_t dest_socket_number;
	uint8_t src_socket_number;
	uint8_t type;
} DDP_extended_header;

typedef struct __attribute__((packed)) {
	// based on LLAPtype 1 = short, 2 = extended
	union {
		DDP_short_header short_header;
		DDP_extended_header extended_header;
	} header;
	unsigned char data[];
} DDP_packet;

typedef struct __attribute__((packed)) {
	ELAP_header elap_header;
	union {
		AARP_packet aarp_packet;
		DDP_packet ddp_packet;
	} data;
} ELAP_packet;

typedef struct __attribute__((packed)) {
	uint8_t len;
	char name[];
} NBP_tuple_name;

typedef struct __attribute__((packed)) {
	uint16_t network_number;
	uint8_t node_id;
	uint8_t socket_number;
	uint8_t enumerator;
	NBP_tuple_name name[];
} NBP_tuple;

typedef struct __attribute__((packed)) {
	uint8_t info; // & 0xf0 >> 4 = function, & 0x0f = tuple count
	uint8_t id;
	NBP_tuple tuples[];
} NBP_header;

// return types for parser

typedef struct NBPResult {
	uint16_t net;
	uint8_t nodeId;
	uint8_t socket;
	uint8_t enumerator;
	char object[64];
	char type[64];
	char zone[64];
} NBPResult;

typedef struct DDPPacketInfo {
	char error[256];
	size_t len;
	size_t elapLen;
	char elapSrc[18];
	char elapDest[18];
	uint16_t type;
	char *typeString;
	uint16_t ddpLen;
	uint8_t ddpHops;
	uint8_t ddpType;
	char *ddpTypeString;
	uint16_t ddpSrcNet;
	uint16_t ddpDestNet;
	uint8_t ddpSrcNodeId;
	uint8_t ddpDestNodeId;
	uint8_t ddpSrcSocket;
	uint8_t ddpDestSocket;
	uint8_t nbpCount;
	uint8_t nbpFunction;
	char *nbpFunctionString;
	NBPResult *nbpResult;
	uint16_t aarpFunction;
	char *aarpFunctionString;
	char aarpSrc[18];
	char aarpDest[18];
	uint16_t aarpSrcNet;
	uint16_t aarpDestNet;
	uint8_t aarpSrcNodeId;
	uint8_t aarpDestNodeId;
	uint8_t aarpSrcSocket;
	uint8_t aarpDestSocket;
} DDPPacketInfo;

void parseMAC(char *buf, size_t bufLen, uint8_t *addr);

DDPPacketInfo *ddpParsePacket(uint8_t *packet, size_t len);
void freePacketInfo(DDPPacketInfo *pkt);

void printPacketDetails(DDPPacketInfo *pkt);
void printPacketInfo(DDPPacketInfo *pkt);

#endif
