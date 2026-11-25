/*
 * fuzz_packet_parser.c — libFuzzer harness for packetdrill's raw-packet decoder.
 *
 * packetdrill reads packets off the wire (TUN device / packet socket) and decodes them with
 * parse_packet() (Ethernet/IPv4/IPv6/GRE/MPLS/UDP-encap/TCP/UDP/ICMP header walk and TCP option
 * iteration), then renders them with packet_to_string() when logging or reporting a mismatch.
 * This harness drives the same two public entry points the upstream unit tests
 * (packet_parser_test.c, packet_to_string_test.c) use, on fuzzer bytes.
 *
 * Input layout: byte 0 selects the layer the bytes start at (bit 0: 0 = layer 3 IP,
 * 1 = layer 2 Ethernet — the two values of enum packet_layer_t); the rest is the packet as it
 * would arrive from the wire. Every successfully parsed packet is rendered in all three dump
 * formats. No state survives an input: each packet is allocated and freed per call.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "packet.h"
#include "packet_parser.h"
#include "packet_to_string.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return -1;	/* need the layer selector byte */

	enum packet_layer_t layer = (data[0] & 1) ? PACKET_LAYER_2_ETHERNET
						  : PACKET_LAYER_3_IP;
	data++;
	size--;

	struct packet *packet = packet_new(size);
	memcpy(packet->buffer, data, size);

	char *error = NULL;
	int result = parse_packet(packet, size, layer, &error);
	free(error);
	error = NULL;

	if (result == PACKET_OK) {
		static const enum dump_format_t formats[] = {
			DUMP_SHORT, DUMP_FULL, DUMP_VERBOSE,
		};
		for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
			char *dump = NULL;
			packet_to_string(packet, formats[i], &dump, &error);
			free(dump);
			free(error);
			error = NULL;
		}
	}

	packet_free(packet);
	return result == PACKET_BAD ? -1 : 0;
}
