#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include "ddp.h"
#include "log.h"

void parseMAC(char *buf, size_t bufLen, uint8_t *addr) {
	snprintf(buf, bufLen, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

uint8_t *parseTuple(char *buf, size_t bufLen, uint8_t *tuple_ptr) {
	NBP_tuple_name *tuple = (NBP_tuple_name*)tuple_ptr;
	uint8_t len = tuple->len;
	snprintf(buf, bufLen, "%.*s", len, tuple->name);
	return tuple_ptr + 1 + len;
}

DDPPacketInfo *ddpParsePacket(uint8_t *packet, size_t len) {
	if(len > sizeof(ELAP_packet)) {
		DDPPacketInfo *pkt = (DDPPacketInfo*)malloc(sizeof(DDPPacketInfo));
		memset(pkt, 0, sizeof(DDPPacketInfo));
		pkt->len = len;

		ELAP_packet *p = (ELAP_packet*)packet;
		pkt->elapLen = (size_t)ntohs(p->elap_header.eth_802_3_header.len);
		parseMAC(pkt->elapSrc, sizeof(pkt->elapSrc), p->elap_header.eth_802_3_header.src_addr);
		parseMAC(pkt->elapDest, sizeof(pkt->elapDest), p->elap_header.eth_802_3_header.dest_addr);

		if(p->elap_header.eth_802_2_header.src_sap != 0xaa || p->elap_header.eth_802_2_header.dest_sap != 0xaa) {
			strncpy(pkt->error, "Invalid SAP mapping", sizeof(pkt->error));
			return pkt;
		}
		if(p->elap_header.eth_802_2_header.control != 3) {
			strncpy(pkt->error, "Invalid SAP control code", sizeof(pkt->error));
			return pkt;
		}

		pkt->type = ntohs(p->elap_header.snap_protocol_discriminator.packet_type);
		if(pkt->type == APPLETALK_DATA_PACKET && p->elap_header.snap_protocol_discriminator.protocol[0] == 8 && p->elap_header.snap_protocol_discriminator.protocol[1] == 0 && p->elap_header.snap_protocol_discriminator.protocol[2] == 7) {
			pkt->typeString = "data";
			// max length 586 bytes
			DDP_packet *ddp = &(p->data.ddp_packet);

			pkt->ddpLen = ntohs(ddp->header.extended_header.len) & 0x03ff;
			pkt->ddpHops = (ntohs(ddp->header.extended_header.len) & 0x3c00) >> 10;
			pkt->ddpType = ddp->header.extended_header.type;

			switch(pkt->ddpType) {
				case DDPTYPE_RTMPRD:
					pkt->ddpTypeString = "RTMPRD";
					break;
				case DDPTYPE_NBP:
					pkt->ddpTypeString = "NBP";
					break;
				case DDPTYPE_ATP:
					pkt->ddpTypeString = "ATP";
					break;
				case DDPTYPE_AEP:
					pkt->ddpTypeString = "AEP";
					break;
				case DDPTYPE_RTMPR:
					pkt->ddpTypeString = "RTMPR";
					break;
				case DDPTYPE_ZIP:
					pkt->ddpTypeString = "ZIP";
					break;
				case DDPTYPE_ADSP:
					pkt->ddpTypeString = "ADSP";
					break;
				default:
					pkt->ddpTypeString = 0;
					break;
			}

			uint16_t input_checksum = ntohs(ddp->header.extended_header.checksum);
			if(input_checksum != 0) {
				uint32_t cksum = 0;
				unsigned char *p = ((unsigned char*)&(ddp->header.extended_header.checksum)) + 2;
				for(int i = 0; i < pkt->ddpLen - 4; i++) { // subtract 4 bytes for checksum and header
					cksum = (cksum + *(p++)) << 1;
					if(cksum & 0x00010000)
						cksum++;
					cksum &= 0x0000ffff;
				}
				if(cksum == 0)
					cksum = 0x0000ffff;
				uint16_t verify_checksum = (uint16_t)cksum;
				if(input_checksum != verify_checksum) {
					strncpy(pkt->error, "Invalid checksum", sizeof(pkt->error));
					return pkt;
				}
			}

			pkt->ddpSrcNet = ntohs(ddp->header.extended_header.src_network_number);
			pkt->ddpDestNet = ntohs(ddp->header.extended_header.dest_network_number);
			pkt->ddpSrcNodeId = ddp->header.extended_header.src_node_id;
			pkt->ddpDestNodeId = ddp->header.extended_header.dest_node_id;
			pkt->ddpSrcSocket = ddp->header.extended_header.src_socket_number;
			pkt->ddpDestSocket = ddp->header.extended_header.dest_socket_number;

			if(ddp->header.extended_header.type == DDPTYPE_NBP) {
				NBP_header *nbp = (NBP_header*)ddp->data;
				pkt->nbpCount = nbp->info & 0xf;
				pkt->nbpFunction = nbp->info & 0xf0 >> 4;
				switch(pkt->nbpFunction) {
					case NBPOP_BRRQ:
						pkt->nbpFunctionString = "BRRQ";
						break;
					case NBPOP_LKUP:
						pkt->nbpFunctionString = "LKUP";
						break;
					case NBPOP_LKUPREPLY:
						pkt->nbpFunctionString = "LKUPREPLY";
						break;
					case NBPOP_FWD:
						pkt->nbpFunctionString = "FWD";
						break;
					case NBPOP_RGSTR:
						pkt->nbpFunctionString = "RGSTR";
						break;
					case NBPOP_UNRGSTR:
						pkt->nbpFunctionString = "UNRGSTR";
						break;
					case NBPOP_CONFIRM:
						pkt->nbpFunctionString = "CONFIRM";
						break;
					case NBPOP_OK:
						pkt->nbpFunctionString = "OK";
						break;
					case NBPOP_CLOSE_NOTE:
						pkt->nbpFunctionString = "CLOSE_NOTE";
						break;
					default:
						pkt->nbpFunctionString = 0;
						break;
				}
				uint8_t *tuple_ptr = (uint8_t*)nbp->tuples;
				NBP_tuple *tuple = (NBP_tuple*)tuple_ptr;
				pkt->nbpResult = (NBPResult*)malloc(sizeof(NBPResult) * pkt->nbpCount);
				for(int i = 0; i < pkt->nbpCount; i++) {
					pkt->nbpResult[i].net = ntohs(tuple->network_number);
					pkt->nbpResult[i].nodeId = tuple->node_id;
					pkt->nbpResult[i].socket = tuple->socket_number;
					pkt->nbpResult[i].enumerator = tuple->enumerator;

					tuple_ptr += 5;
					tuple_ptr = parseTuple(pkt->nbpResult[i].object, sizeof(pkt->nbpResult[i].object), tuple_ptr);
					tuple_ptr = parseTuple(pkt->nbpResult[i].type, sizeof(pkt->nbpResult[i].type), tuple_ptr);
					tuple_ptr = parseTuple(pkt->nbpResult[i].zone, sizeof(pkt->nbpResult[i].zone), tuple_ptr);
					tuple = (NBP_tuple*)tuple_ptr;
				}
			}
		} else if(pkt->type == AARP_PACKET && p->elap_header.snap_protocol_discriminator.protocol[0] == 0 && p->elap_header.snap_protocol_discriminator.protocol[1] == 0 && p->elap_header.snap_protocol_discriminator.protocol[2] == 0) {
			pkt->typeString = "aarp";
			AARP_packet *aarp = &(p->data.aarp_packet);
			if(ntohs(aarp->hardware_type) != 1 || ntohs(aarp->protocol_type) != APPLETALK_DATA_PACKET || aarp->hardware_addr_len != 6 || aarp->protocol_addr_len != 4) {
				strncpy(pkt->error, "Invalid AARP packet", sizeof(pkt->error));
				return pkt;
			}

			pkt->aarpFunction = ntohs(aarp->function);
			switch(pkt->aarpFunction) {
				case 1:
					pkt->aarpFunctionString = "Request";
					break;
				case 2:
					pkt->aarpFunctionString = "Response";
					break;
				case 3:
					pkt->aarpFunctionString = "Probe";
					break;
				default:
					pkt->aarpFunctionString = 0;
					break;
			}
			parseMAC(pkt->aarpSrc, sizeof(pkt->aarpSrc), aarp->src_hw_addr);
			parseMAC(pkt->aarpDest, sizeof(pkt->aarpDest), aarp->dest_hw_addr);

			pkt->aarpSrcNet = (aarp->src_at_addr[1] << 8) + aarp->src_at_addr[2];
			pkt->aarpSrcNodeId = aarp->src_at_addr[3];
			pkt->aarpSrcSocket = aarp->src_at_addr[0];

			pkt->aarpDestNet = (aarp->dest_at_addr[1] << 8) + aarp->dest_at_addr[2];
			pkt->aarpDestNodeId = aarp->dest_at_addr[3];
			pkt->aarpDestSocket = aarp->dest_at_addr[0];
		} else {
			pkt->typeString = 0;
			strncpy(pkt->error, "Invalid packet type", sizeof(pkt->error));
		}
		return pkt;
	}
	return 0;
}

void printPacketDetails(DDPPacketInfo *pkt) {
	if(pkt == 0)
		return;
	logDebug("------------------------------");
	logDebug("Ethernet Packet Length: %ld", pkt->len);
	logDebug("ELAP: %s -> %s (%ld bytes)", pkt->elapSrc, pkt->elapDest, pkt->elapLen);
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
	time_t now = time(NULL);
	struct tm *t = localtime(&now);

	strftime(date, sizeof(date) - 1, "%F %r", t);

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
