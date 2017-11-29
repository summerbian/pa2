/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "sr_arpcache.h"
#ifndef SR_UTILS_H
#define SR_UTILS_H

uint16_t cksum(const void *_data, int len);
uint32_t tcp_cksum(sr_ip_hdr_t *ipHdr, sr_tcp_hdr_t *tcpHdr, int total_len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);
int is_icmp_echo_reply(sr_icmp_hdr_t *icmpHdr);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

/* Helper methods to extract headers from packets */
sr_arp_hdr_t *packet_get_arp_hdr(uint8_t *packet);
sr_ethernet_hdr_t *packet_get_eth_hdr(uint8_t *packet);
sr_ip_hdr_t *packet_get_ip_hdr(uint8_t *packet);
sr_tcp_hdr_t *packet_get_tcp_hdr(uint8_t *packet);
sr_icmp_hdr_t *packet_get_icmp_hdr(uint8_t *packet);
sr_icmp_t3_hdr_t *packet_get_icmp_t3_hdr(uint8_t *packet);

struct sr_if* sr_iface_for_dst(struct sr_instance *sr, uint32_t dst);

struct sr_if* get_outgoing_iface(struct sr_instance *sr, uint8_t *addr);

struct sr_rt *calculate_LPM(struct sr_instance *sr, uint32_t destination_ip);

void sr_forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t* dest_mac, struct sr_if *out_iface);

void sr_send_icmp(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t *packet, int len, struct sr_if *rec_iface, struct sr_if* target_iface);

void sr_send_icmp_t3_to(struct sr_instance *sr, uint8_t *receiver, uint8_t icmp_type, uint8_t icmp_code, struct sr_if* rec_iface, struct sr_if* target_iface);

void sr_send_arp_req(struct sr_instance *sr, struct sr_arpreq *req);
int sr_send_arp_rep(struct sr_instance *sr, sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if* rec_iface);


uint8_t sanity_check_arp_packet_len_ok(unsigned int len);
uint8_t sanity_check_ip_packet_len_ok(unsigned int len);
uint8_t sanity_check_icmp_packet_len_ok(unsigned int len);

uint8_t is_ip_chksum_ok(sr_ip_hdr_t *ip_hdr);
uint8_t is_icmp_chksum_ok(uint16_t ip_len, sr_icmp_hdr_t *icmp_hdr);



#endif /* -- SR_UTILS_H -- */
