#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "ddp.h"
#include "log.h"

static const uint8_t APPLE_OUI[3] = { 0x08, 0x00, 0x07 };
static const uint8_t AARP_OUI[3] = { 0x00, 0x00, 0x00 };

#define LLC_SNAP_LEN 8 // 802.2 LLC (3) + SNAP (5)

void parseMAC(char *buf, size_t bufLen, const uint8_t *addr) {
	snprintf(buf, bufLen, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

bool isAppleTalkFrame(const uint8_t *frame, size_t len) {
	if(frame == 0 || len < ETHER_HEADER_LEN || len > ETHER_MAX_FRAME)
		return false;

	uint16_t typeOrLen = (uint16_t)((frame[12] << 8) | frame[13]);
	if(typeOrLen >= 0x0600) // Ethernet II (AppleTalk phase 1)
		return typeOrLen == APPLETALK_DATA_PACKET || typeOrLen == AARP_PACKET;

	// 802.3 + 802.2 SNAP (AppleTalk phase 2); the frame may be longer than the
	// length field because of Ethernet minimum-size padding, but never shorter
	if(typeOrLen < LLC_SNAP_LEN || typeOrLen > ETHER_MAX_PAYLOAD || len < sizeof(ELAP_header) || ETHER_HEADER_LEN + (size_t)typeOrLen > len)
		return false;

	const ELAP_header *h = (const ELAP_header *)frame;
	if(h->eth_802_2_header.dest_sap != 0xaa || h->eth_802_2_header.src_sap != 0xaa || h->eth_802_2_header.control != 3)
		return false;

	uint16_t type = ntohs(h->snap_protocol_discriminator.packet_type);
	const uint8_t *oui = h->snap_protocol_discriminator.protocol;
	if(type == APPLETALK_DATA_PACKET && memcmp(oui, APPLE_OUI, 3) == 0)
		return true;
	if(type == AARP_PACKET && memcmp(oui, AARP_OUI, 3) == 0)
		return true;
	return false;
}

// Copy a length-prefixed NBP name into buf, replacing anything that isn't
// printable ASCII so remote data can't inject terminal escape sequences.
// Returns a pointer past the name, or 0 if it runs past end.
static const uint8_t *parseTuple(char *buf, size_t bufLen, const uint8_t *p, const uint8_t *end) {
	if(p >= end)
		return 0;
	size_t len = *p++;
	if(len > (size_t)(end - p))
		return 0;

	size_t out = 0;
	for(size_t i = 0; i < len && out + 1 < bufLen; i++)
		buf[out++] = (p[i] >= 0x20 && p[i] < 0x7f) ? (char)p[i] : '?';
	buf[out] = 0;
	return p + len;
}

static DDPPacketInfo *packetError(DDPPacketInfo *pkt, const char *error) {
	snprintf(pkt->error, sizeof(pkt->error), "%s", error);
	return pkt;
}

static void parseNBP(DDPPacketInfo *pkt, const uint8_t *data, size_t dataLen) {
	if(dataLen < 2) {
		packetError(pkt, "Truncated NBP header");
		return;
	}

	uint8_t info = data[0];
	pkt->nbpFunction = (info >> 4) & 0x0f;
	uint8_t count = info & 0x0f;

	switch(pkt->nbpFunction) {
		case NBPOP_BRRQ: pkt->nbpFunctionString = "BRRQ"; break;
		case NBPOP_LKUP: pkt->nbpFunctionString = "LKUP"; break;
		case NBPOP_LKUPREPLY: pkt->nbpFunctionString = "LKUPREPLY"; break;
		case NBPOP_FWD: pkt->nbpFunctionString = "FWD"; break;
		case NBPOP_RGSTR: pkt->nbpFunctionString = "RGSTR"; break;
		case NBPOP_UNRGSTR: pkt->nbpFunctionString = "UNRGSTR"; break;
		case NBPOP_CONFIRM: pkt->nbpFunctionString = "CONFIRM"; break;
		case NBPOP_OK: pkt->nbpFunctionString = "OK"; break;
		case NBPOP_CLOSE_NOTE: pkt->nbpFunctionString = "CLOSE_NOTE"; break;
		default: pkt->nbpFunctionString = 0; break;
	}

	if(count == 0)
		return;

	pkt->nbpResult = calloc(count, sizeof(NBPResult));
	if(pkt->nbpResult == 0) {
		packetError(pkt, "Out of memory");
		return;
	}

	const uint8_t *p = data + 2;
	const uint8_t *end = data + dataLen;
	for(uint8_t i = 0; i < count; i++) {
		NBPResult *r = &pkt->nbpResult[i];
		if(end - p < 5) {
			packetError(pkt, "Truncated NBP tuple");
			return;
		}
		r->net = (uint16_t)((p[0] << 8) | p[1]);
		r->nodeId = p[2];
		r->socket = p[3];
		r->enumerator = p[4];
		p += 5;

		if((p = parseTuple(r->object, sizeof(r->object), p, end)) == 0 ||
				(p = parseTuple(r->type, sizeof(r->type), p, end)) == 0 ||
				(p = parseTuple(r->zone, sizeof(r->zone), p, end)) == 0) {
			packetError(pkt, "Truncated NBP tuple");
			return;
		}
		pkt->nbpCount = i + 1;
	}
}

static void parseDDP(DDPPacketInfo *pkt, const uint8_t *payload, size_t payloadLen) {
	if(payloadLen < sizeof(DDP_extended_header)) {
		packetError(pkt, "Truncated DDP header");
		return;
	}

	const DDP_extended_header *ddp = (const DDP_extended_header *)payload;
	uint16_t lenField = ntohs(ddp->len);
	pkt->ddpLen = lenField & 0x03ff;
	pkt->ddpHops = (lenField >> 10) & 0x0f;
	pkt->ddpType = ddp->type;

	if(pkt->ddpLen < sizeof(DDP_extended_header) || pkt->ddpLen > payloadLen) {
		packetError(pkt, "Invalid DDP length");
		return;
	}

	switch(pkt->ddpType) {
		case DDPTYPE_RTMPRD: pkt->ddpTypeString = "RTMPRD"; break;
		case DDPTYPE_NBP: pkt->ddpTypeString = "NBP"; break;
		case DDPTYPE_ATP: pkt->ddpTypeString = "ATP"; break;
		case DDPTYPE_AEP: pkt->ddpTypeString = "AEP"; break;
		case DDPTYPE_RTMPR: pkt->ddpTypeString = "RTMPR"; break;
		case DDPTYPE_ZIP: pkt->ddpTypeString = "ZIP"; break;
		case DDPTYPE_ADSP: pkt->ddpTypeString = "ADSP"; break;
		default: pkt->ddpTypeString = 0; break;
	}

	// the checksum covers everything after the checksum field; 0 means "not computed"
	uint16_t inputChecksum = ntohs(ddp->checksum);
	if(inputChecksum != 0) {
		uint32_t cksum = 0;
		for(size_t i = 4; i < pkt->ddpLen; i++) {
			cksum = (cksum + payload[i]) << 1;
			if(cksum & 0x00010000)
				cksum++;
			cksum &= 0x0000ffff;
		}
		if(cksum == 0)
			cksum = 0x0000ffff;
		if(inputChecksum != (uint16_t)cksum) {
			packetError(pkt, "Invalid checksum");
			return;
		}
	}

	pkt->ddpSrcNet = ntohs(ddp->src_network_number);
	pkt->ddpDestNet = ntohs(ddp->dest_network_number);
	pkt->ddpSrcNodeId = ddp->src_node_id;
	pkt->ddpDestNodeId = ddp->dest_node_id;
	pkt->ddpSrcSocket = ddp->src_socket_number;
	pkt->ddpDestSocket = ddp->dest_socket_number;

	if(pkt->ddpType == DDPTYPE_NBP)
		parseNBP(pkt, payload + sizeof(DDP_extended_header), pkt->ddpLen - sizeof(DDP_extended_header));
}

static void parseAARP(DDPPacketInfo *pkt, const uint8_t *payload, size_t payloadLen) {
	if(payloadLen < sizeof(AARP_packet)) {
		packetError(pkt, "Truncated AARP packet");
		return;
	}

	const AARP_packet *aarp = (const AARP_packet *)payload;
	if(ntohs(aarp->hardware_type) != 1 || ntohs(aarp->protocol_type) != APPLETALK_DATA_PACKET || aarp->hardware_addr_len != 6 || aarp->protocol_addr_len != 4) {
		packetError(pkt, "Invalid AARP packet");
		return;
	}

	pkt->aarpFunction = ntohs(aarp->function);
	switch(pkt->aarpFunction) {
		case 1: pkt->aarpFunctionString = "Request"; break;
		case 2: pkt->aarpFunctionString = "Response"; break;
		case 3: pkt->aarpFunctionString = "Probe"; break;
		default: pkt->aarpFunctionString = 0; break;
	}
	parseMAC(pkt->aarpSrc, sizeof(pkt->aarpSrc), aarp->src_hw_addr);
	parseMAC(pkt->aarpDest, sizeof(pkt->aarpDest), aarp->dest_hw_addr);

	pkt->aarpSrcNet = (uint16_t)((aarp->src_at_addr[1] << 8) + aarp->src_at_addr[2]);
	pkt->aarpSrcNodeId = aarp->src_at_addr[3];
	pkt->aarpSrcSocket = aarp->src_at_addr[0];

	pkt->aarpDestNet = (uint16_t)((aarp->dest_at_addr[1] << 8) + aarp->dest_at_addr[2]);
	pkt->aarpDestNodeId = aarp->dest_at_addr[3];
	pkt->aarpDestSocket = aarp->dest_at_addr[0];
}

DDPPacketInfo *ddpParsePacket(const uint8_t *packet, size_t len) {
	if(packet == 0 || len < sizeof(ELAP_header))
		return 0;

	DDPPacketInfo *pkt = calloc(1, sizeof(DDPPacketInfo));
	if(pkt == 0)
		return 0;
	pkt->len = len;

	const ELAP_header *h = (const ELAP_header *)packet;
	pkt->elapLen = ntohs(h->eth_802_3_header.len);
	parseMAC(pkt->elapSrc, sizeof(pkt->elapSrc), h->eth_802_3_header.src_addr);
	parseMAC(pkt->elapDest, sizeof(pkt->elapDest), h->eth_802_3_header.dest_addr);

	if(pkt->elapLen >= 0x0600) {
		if(pkt->elapLen == APPLETALK_DATA_PACKET || pkt->elapLen == AARP_PACKET)
			return packetError(pkt, "Ethernet II (AppleTalk phase 1) frames are not decoded");
		return packetError(pkt, "Not an AppleTalk frame");
	}
	if(h->eth_802_2_header.src_sap != 0xaa || h->eth_802_2_header.dest_sap != 0xaa)
		return packetError(pkt, "Invalid SAP mapping");
	if(h->eth_802_2_header.control != 3)
		return packetError(pkt, "Invalid SAP control code");

	// trust the 802.3 length over the frame length, which may include padding
	const uint8_t *payload = packet + sizeof(ELAP_header);
	size_t payloadLen = len - sizeof(ELAP_header);
	if(pkt->elapLen < LLC_SNAP_LEN || pkt->elapLen - LLC_SNAP_LEN > payloadLen)
		return packetError(pkt, "Invalid 802.3 length");
	payloadLen = pkt->elapLen - LLC_SNAP_LEN;

	pkt->type = ntohs(h->snap_protocol_discriminator.packet_type);
	const uint8_t *oui = h->snap_protocol_discriminator.protocol;
	if(pkt->type == APPLETALK_DATA_PACKET && memcmp(oui, APPLE_OUI, 3) == 0) {
		pkt->typeString = "data";
		parseDDP(pkt, payload, payloadLen);
	} else if(pkt->type == AARP_PACKET && memcmp(oui, AARP_OUI, 3) == 0) {
		pkt->typeString = "aarp";
		parseAARP(pkt, payload, payloadLen);
	} else {
		packetError(pkt, "Invalid packet type");
	}
	return pkt;
}

void printPacketDetails(DDPPacketInfo *pkt) {
	if(pkt == 0)
		return;
	logDebug("------------------------------");
	logDebug("Ethernet Packet Length: %zu", pkt->len);
	logDebug("ELAP: %s -> %s (%zu bytes)", pkt->elapSrc, pkt->elapDest, pkt->elapLen);
	logDebug("Packet Type: %04x (%s)", pkt->type, pkt->typeString ? pkt->typeString : "unknown");
	if(pkt->error[0]) {
		logError("Packet Error: %s", pkt->error);
	} else {
		if(pkt->type == APPLETALK_DATA_PACKET && pkt->ddpLen > 0) {
			if(pkt->nbpFunction != 0) {
				logDebug("--- NBP %s", pkt->nbpFunctionString ? pkt->nbpFunctionString : "unknown");
				if(pkt->nbpResult) {
					for(int i = 0; i < pkt->nbpCount; i++) {
						logDebug("--> %u.%u (%u) - %s:%s@%s", pkt->nbpResult[i].net, pkt->nbpResult[i].nodeId, pkt->nbpResult[i].socket, pkt->nbpResult[i].object, pkt->nbpResult[i].type, pkt->nbpResult[i].zone);
						logDebug("--> [%d] %s:%s@%s", i + 1, pkt->nbpResult[i].object, pkt->nbpResult[i].type, pkt->nbpResult[i].zone);
					}
				}
			} else {
				logDebug("-- DDP Length is %u, %u hops", pkt->ddpLen, pkt->ddpHops);
				logDebug("-- DDP %s (%u bytes)", pkt->ddpTypeString ? pkt->ddpTypeString : "unknown", pkt->ddpLen);
				logDebug("-- DDP Address %u.%u (%u) -> %u.%u (%u)", pkt->ddpSrcNet, pkt->ddpSrcNodeId, pkt->ddpSrcSocket, pkt->ddpDestNet, pkt->ddpDestNodeId, pkt->ddpDestSocket);
			}
		}

		if(pkt->type == AARP_PACKET && pkt->aarpFunction != 0) {
			logDebug("AARP %s", pkt->aarpFunctionString ? pkt->aarpFunctionString : "unknown");
			logDebug("-- AARP HW Address %s -> %s", pkt->aarpSrc, pkt->aarpDest);
			logDebug("-- AARP AT Address %u.%u (%u) -> %u.%u (%u)", pkt->aarpSrcNet, pkt->aarpSrcNodeId, pkt->aarpSrcSocket, pkt->aarpDestNet, pkt->aarpDestNodeId, pkt->aarpDestSocket);
		}
	}
}

void printPacketInfo(DDPPacketInfo *pkt) {
	if(pkt == 0)
		return;

	char date[255];
	struct tm t;
	time_t now = time(NULL);
	localtime_r(&now, &t);

	strftime(date, sizeof(date), "%F %r", &t);

	if(pkt->error[0]) {
		logError("Packet Error: %s", pkt->error);
	} else {
		if(pkt->type == APPLETALK_DATA_PACKET && pkt->ddpLen > 0) {
			if(pkt->nbpFunction != 0) {
				logMessage("%s - NBP %s", date, pkt->nbpFunctionString ? pkt->nbpFunctionString : "unknown");
				if(pkt->nbpResult) {
					for(int i = 0; i < pkt->nbpCount; i++)
						logDebug("--> [%d] %s:%s@%s", i + 1, pkt->nbpResult[i].object, pkt->nbpResult[i].type, pkt->nbpResult[i].zone);
				}
			} else
				logMessage("%s - %s (%u bytes)", date, pkt->ddpTypeString ? pkt->ddpTypeString : "unknown", pkt->ddpLen);
		}

		if(pkt->type == AARP_PACKET && pkt->aarpFunction != 0)
			logMessage("%s - AARP %s", date, pkt->aarpFunctionString ? pkt->aarpFunctionString : "unknown");
	}
}

void freePacketInfo(DDPPacketInfo *pkt) {
	if(pkt == 0)
		return;

	if(pkt->nbpResult)
		free(pkt->nbpResult);
	pkt->nbpResult = 0;
	free(pkt);
}
