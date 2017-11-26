#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"


uint16_t cksum(const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}

uint32_t tcp_cksum(sr_ip_hdr_t *ipHdr, sr_tcp_hdr_t *tcpHdr, int total_len) {

  uint8_t *full_tcp;
  sr_tcp_psuedo_hdr_t *tcp_psuedo_hdr;

  int tcp_len = total_len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  int full_tcp_len = sizeof(sr_tcp_psuedo_hdr_t) + tcp_len;

  tcp_psuedo_hdr = malloc(sizeof(sr_tcp_psuedo_hdr_t));
  memset(tcp_psuedo_hdr, 0, sizeof(sr_tcp_psuedo_hdr_t));

  tcp_psuedo_hdr->ip_src = ipHdr->ip_src;
  tcp_psuedo_hdr->ip_dst = ipHdr->ip_dst;
  tcp_psuedo_hdr->ip_p = ipHdr->ip_p;
  tcp_psuedo_hdr->tcp_len = htons(tcp_len);

  uint16_t currcksum = tcpHdr->sum;
  tcpHdr->sum = 0;

  full_tcp = malloc(sizeof(sr_tcp_psuedo_hdr_t) + tcp_len);
  memcpy(full_tcp, (uint8_t *) tcp_psuedo_hdr, sizeof(sr_tcp_psuedo_hdr_t));
  memcpy(&(full_tcp[sizeof(sr_tcp_psuedo_hdr_t)]), (uint8_t *) tcpHdr, tcp_len);
  tcpHdr->sum = currcksum;

  uint16_t calcCksum = cksum(full_tcp, full_tcp_len);

  /* Clear out memory used for creation of complete tcp packet */
  free(tcp_psuedo_hdr);
  free(full_tcp);

  return calcCksum;
}



/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

sr_ethernet_hdr_t *packet_get_eth_hdr(uint8_t *packet) {
  return (sr_ethernet_hdr_t *)packet;
}

sr_arp_hdr_t *packet_get_arp_hdr(uint8_t *packet) {
    return (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}

sr_ip_hdr_t *packet_get_ip_hdr(uint8_t *packet) {
  return (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}

sr_icmp_hdr_t *packet_get_icmp_hdr(uint8_t *packet) {
  return (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

sr_icmp_t3_hdr_t *packet_get_icmp_t3_hdr(uint8_t *packet) {
  return (sr_icmp_t3_hdr_t *)packet_get_icmp_hdr(packet);
}

/* Uses routing table to find the subnet where we a destination
 * IP is located.
 * Implementation of algorithm on page 222 in book,
 * don't need to use LPM when we have a routing table.
*/

struct sr_if* sr_iface_for_dst(struct sr_instance *sr, uint32_t dst) {
  
  // current entry 
  struct sr_rt* rt_walker = sr->routing_table; 

  while(rt_walker) {
    uint32_t d1 = rt_walker->mask.s_addr & dst;

    if(d1 == rt_walker->dest.s_addr)
       return sr_get_interface(sr, rt_walker->interface);

    rt_walker = rt_walker->next;
  }
  return NULL;
  
}

struct sr_if *get_outgoing_iface(struct sr_instance *sr, uint8_t *addr)
{
    struct sr_if *curr_iface = sr->if_list;
    struct sr_if *dest_iface = NULL;
    short match, i;
    while (curr_iface) {
        match = 1;
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            if (curr_iface->addr[i] != addr[i]) {
                match = 0;
                break;
            }
        }

        if (match) {
            dest_iface = curr_iface;
            break;
        }
        curr_iface = curr_iface->next;
    }
    return dest_iface;
}


struct sr_rt *calculate_LPM(struct sr_instance *sr, uint32_t destination_ip)
{
  struct sr_rt * rt = sr->routing_table;
  struct sr_rt *closestMatch = NULL; 
	while (rt != NULL) {
		uint32_t mask = rt->mask.s_addr;
		if ((destination_ip & mask) == (rt->dest.s_addr & mask)) {
			if (closestMatch == NULL || (mask > closestMatch->mask.s_addr)) {
				closestMatch = rt;
			}
		}
		rt = rt->next;
	}
	return closestMatch;
  /*
    struct sr_rt *routing_table_node = sr->routing_table;
    struct sr_rt *best_match = NULL;
    while (routing_table_node) {
        if ((routing_table_node->dest.s_addr & routing_table_node->mask.s_addr) == (destination_ip & routing_table_node->mask.s_addr)) {
            if (!best_match || (routing_table_node->mask.s_addr > best_match->mask.s_addr)) {
                best_match = routing_table_node;
            }
        }
        routing_table_node = routing_table_node->next;
    }
    return best_match;

    */
}


void sr_forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t* dest_mac, struct sr_if *out_iface) {
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);

  memcpy(eth_hdr->ether_dhost, dest_mac, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  // Recompute checksum
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t)); 

  // Send 
  sr_send_packet(sr, packet, len, out_iface->name);
}

/*
 * Modifies the given ICMP packet and sends it back out, not
 * adding a data section to the packet (only used when we
 * get and need to resend an ICMP echo req in sr_handle_ip.c)
 */
void sr_send_icmp(struct sr_instance *sr, uint8_t icmp_type,
    uint8_t icmp_code, uint8_t *packet, int len, 
    struct sr_if * rec_iface, struct sr_if* target_iface) {
  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

  
  struct sr_if *out_iface = sr_get_interface(sr, rec_iface->name);

  

  uint32_t req_src = ip_hdr->ip_src;
  ip_hdr->ip_src = target_iface->ip; // src is this interface's ip
  ip_hdr->ip_dst = req_src; // dest is requester's ip

  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  icmp_hdr->icmp_sum = 0; // compute checksum of hdr
  icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)); 

  struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
  if (!entry) {
    struct sr_arpreq *request = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, 
      len, out_iface->name);
    handle_arpreq(sr, request);
    return;
  }

  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) *ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, sizeof(uint8_t) *ETHER_ADDR_LEN);
  sr_send_packet(sr, packet, len, out_iface->name);
  
}

// Sends an ICMP error message from sr out of interface iface
// to receiver noted in the uint8_t receiver IP packet.
void sr_send_icmp_t3_to(struct sr_instance *sr, uint8_t *receiver,
    uint8_t icmp_type, uint8_t icmp_code, 
    struct sr_if *rec_iface, struct sr_if* target_iface) {
    
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *packet = (uint8_t *)malloc(len);
  bzero(packet, len);

  sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  sr_icmp_t3_hdr_t *icmp_hdr = packet_get_icmp_t3_hdr(packet);

  // Get original sender (the receiver) header info
  sr_ethernet_hdr_t *rec_eth_hdr = packet_get_eth_hdr(receiver);
  sr_ip_hdr_t *rec_ip_hdr = packet_get_ip_hdr(receiver);

  // Find interface we should be sending the packet out on
  struct sr_if *out_iface = sr_get_interface(sr, rec_iface->name);

  // Construct ethernet hdr
  memcpy(eth_hdr->ether_dhost, rec_eth_hdr->ether_shost, sizeof(uint8_t) *ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, sizeof(uint8_t) *ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  // Construct IP hdr
  ip_hdr->ip_hl = rec_ip_hdr->ip_hl;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_tos = rec_ip_hdr->ip_tos;
  ip_hdr->ip_off = htons(IP_DF); 
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_v = rec_ip_hdr->ip_v;
  //ip_hdr->ip_src = rec_iface->ip;
 // ip_hdr->ip_dst = rec_ip_hdr->ip_src;
  ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
 

  if (target_iface){
    ip_hdr->ip_src = target_iface->ip;
  }
  else {
    ip_hdr->ip_src = out_iface->ip;
  }

  ip_hdr->ip_dst = rec_ip_hdr->ip_src;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  // Construct ICMP header
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  memcpy(icmp_hdr->data, rec_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  sr_send_packet(sr, packet, len, out_iface->name);
  ;
}

void sr_send_arp_req(struct sr_instance *sr, struct sr_arpreq *req) {
  // Allocate space for a new ARP request  packet
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *packet = (uint8_t *)malloc(len);
  bzero(packet, len);

  // Find interface we should be sending the packet out on
  struct sr_if *out_iface = sr_get_interface(sr, req->packets->iface);

  struct sr_ethernet_hdr *eth_hdr = packet_get_eth_hdr(packet);
  struct sr_arp_hdr *arp_hdr = packet_get_arp_hdr(packet);

  // Fill in header information
  memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op = htons(arp_op_request);
  memcpy(arp_hdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = out_iface->ip;
  memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = req->ip;

  sr_send_packet(sr, packet, len, out_iface->name);
  
}

int sr_send_arp_rep(struct sr_instance *sr, sr_ethernet_hdr_t *req_eth_hdr,
    sr_arp_hdr_t *req_arp_hdr, struct sr_if* rec_iface) {
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *rep_packet = (uint8_t *)malloc(len);
  bzero(rep_packet, len);

  // Get headers of our new packet
  sr_ethernet_hdr_t *rep_eth_hdr = packet_get_eth_hdr(rep_packet);
  sr_arp_hdr_t *rep_arp_hdr = packet_get_arp_hdr(rep_packet);

  // Fill eth header entries
  // set destination to origin
  memcpy(rep_eth_hdr->ether_dhost,
      req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  //set source to our interface's eth addr
  memcpy(rep_eth_hdr->ether_shost,
      rec_iface->addr, ETHER_ADDR_LEN);
  // ethernet type is ARP
  rep_eth_hdr->ether_type = ntohs(ethertype_arp);

  // Fill ARP hdr entries
  rep_arp_hdr->ar_hrd = req_arp_hdr->ar_hrd; // 1 for ethernet
  rep_arp_hdr->ar_pro = req_arp_hdr->ar_pro; // protocol format is IPv4 (0x800)
  rep_arp_hdr->ar_hln = req_arp_hdr->ar_hln; // hardware length is same (6 = ETHER_ADDR_LEN)
  rep_arp_hdr->ar_pln = req_arp_hdr->ar_pln; // protocol length is same (4)
  rep_arp_hdr->ar_op = htons(arp_op_reply); // ARP reply
  memcpy(rep_arp_hdr->ar_sha,
      rec_iface->addr, ETHER_ADDR_LEN); // set hw addr
  rep_arp_hdr->ar_sip = rec_iface->ip; // setting us as sender
  memcpy(rep_arp_hdr->ar_tha,
      req_arp_hdr->ar_sha, ETHER_ADDR_LEN); // target
  rep_arp_hdr->ar_tip = req_arp_hdr->ar_sip;

  // Put our new (modified) packet back on the wire
  int res = sr_send_packet(sr, rep_packet, len, rec_iface->name);
  return res;
}

uint8_t sanity_check_arp_packet_len_ok(unsigned int len) {
  uint8_t under = len >= (sizeof(sr_ethernet_hdr_t) +
      sizeof(sr_arp_hdr_t));
  return under;
}

uint8_t sanity_check_ip_packet_len_ok(unsigned int len) {
  uint8_t under = len >= (sizeof(sr_ethernet_hdr_t) +
      sizeof(sr_ip_hdr_t));
  return under;
}

uint8_t sanity_check_icmp_packet_len_ok(unsigned int len) {
  uint8_t under = len >= (sizeof(sr_ethernet_hdr_t) +
      sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  return under;
}

// Returns 0 (false) if unequal, 1 (true) if it checks out
uint8_t is_ip_chksum_ok(sr_ip_hdr_t *ip_hdr) {
  uint16_t tmp_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0; // temporarily substitue with 0

  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t)) == tmp_sum) {
    ip_hdr->ip_sum = tmp_sum; // reset cheksum as if nothing happened...
    return 1;
  }
  else {
    ip_hdr->ip_sum = tmp_sum; // reset checksum as if nothing happened...
    return 0;
  }
}

// Like the previous function, returns 0 (false) if unequal, 1 (true) if
// checks out
uint8_t is_icmp_chksum_ok(uint16_t len, sr_icmp_hdr_t *icmp_hdr) {
  uint16_t tmp_sum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0; // temporarily substitute with 0
  
  if(cksum((uint8_t *)icmp_hdr, ntohs(len) - sizeof(sr_ip_hdr_t)) == tmp_sum) {
    icmp_hdr->icmp_sum = tmp_sum; // reset cheksum as if nothing happened...
    return 1;
  }
  else {
    icmp_hdr->icmp_sum = tmp_sum; // reset checksum as if nothing happened...
    return 0;
  }
}
