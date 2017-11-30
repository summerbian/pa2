#include <stdlib.h>
#include <string.h>
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_handle_arp.h"

void construct_arp_rep_hdr_at(uint8_t *buf, sr_arp_hdr_t *arp_hdr,
    struct sr_if *rec_iface) {
}

void sr_handle_arp(struct sr_instance* sr,
    uint8_t *packet, unsigned int len, struct sr_if *rec_iface) {
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);

  if(!sanity_check_arp_packet_len_ok(len)) {
    Debug("Sanity check for ARP packet length failed! Ignoring ARP.\n");
    return;
  }

  Debug("Sensed an ARP frame, processing it\n");

  switch(ntohs(arp_hdr->ar_op)) {
    case arp_op_request:
      sr_handle_arp_req(sr, eth_hdr, arp_hdr, rec_iface);
      break;
    case arp_op_reply:
      sr_handle_arp_rep(sr, packet, rec_iface);
      break;
    default:
      Debug("Didn't get an ARP frame I understood, quitting!\n");
      return;
  }
}

/*
 * ARP reply processing. Based on the pseudocode given in
 * the header file sr_arpcache.h
 */
void sr_handle_arp_rep(struct sr_instance* sr, uint8_t *packet,
    struct sr_if* rec_iface) {

  sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);
  uint32_t coming_from = arp_hdr->ar_sip;

  struct sr_if *out = sr_get_interface(sr, rec_iface->name);

  struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, coming_from);
  if(request) {
    struct sr_packet *packet_queue = request->packets;
    sr_ethernet_hdr_t *eth_hdr;

    while(packet_queue) {
      eth_hdr = packet_get_eth_hdr(packet_queue->buf);
      
      memcpy(eth_hdr->ether_dhost, (uint8_t *) arp_hdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, (uint8_t *) out->addr, sizeof(uint8_t) * ETHER_ADDR_LEN); 
      struct sr_if *interface = get_outgoing_iface(sr, eth_hdr->ether_shost);
      Debug("sending out of %s\n", out->name);
      sr_send_packet(sr, packet_queue->buf, packet_queue->len, interface->name);
      packet_queue = packet_queue->next; 
    }
    sr_arpreq_destroy(&sr->cache, request);
  }
  return;
}

/*
 * ARP request processing. If we get a request, respond to it. Cache
 * it regardless of it was to us or not.
 */
void sr_handle_arp_req(struct sr_instance* sr,sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if* rec_iface) {

  // Insert this host into our ARP cache regardless if for me or not
 // sr_arpcache_insert(&sr->cache, req_arp_hdr->ar_sha, req_arp_hdr->ar_sip);

  // If the ARP req was for this me, respond with ARP reply
 // sr_send_arp_rep(sr, req_eth_hdr, req_arp_hdr, rec_iface);

  // I could also compare ethernet addresses here
 // if(req_arp_hdr->ar_tip == rec_iface->ip) {
 //   Debug("\tGot ARP request at interfce %s, constructing reply\n", rec_iface->name);

//  }


  uint32_t looking_for = req_arp_hdr->ar_tip;
  struct sr_if* ourInterfaceList = sr->if_list;

  while(ourInterfaceList) {
    if (ourInterfaceList->ip == looking_for) {
      sr_send_arp_rep(sr, req_eth_hdr, req_arp_hdr, ourInterfaceList);
      return;
    }
    ourInterfaceList = ourInterfaceList->next;
  }
}

