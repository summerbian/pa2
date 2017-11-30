#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_handle_ip.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"


/* Scope: local to this file
 * Given the IP header and the length of the entire packet, finds out
 * whether the length of the packet is at least what is required to fill the
 * header, along with making sure that the header checksum is calculated correctly
 */
uint8_t check_ip_packet_ok(sr_ip_hdr_t *ip_hdr, unsigned int len) {
  uint8_t we_good = 1; // assume all is well
  if(!sanity_check_ip_packet_len_ok(len)) {
    Debug("Sanity check for IP packet failed! Dropping packet.\n");
    we_good = 0;
  }
  if(!is_ip_chksum_ok(ip_hdr)) {
    Debug("Computed checksum IP is not same as given. Dropping packet.\n");
    we_good = 0;
  }
  return we_good;
}

/* Scope: local to this file
 * Serves same purpose as above, just for incoming ICMP packets and
 * their headers.
 */
uint8_t is_sanity_check_of_icmp_packet_ok(sr_ip_hdr_t *ip_hdr,
    sr_icmp_hdr_t *icmp_hdr, unsigned int len) {
  uint8_t we_good = 1;

  if(!sanity_check_icmp_packet_len_ok(len)) {
    Debug("Received ICMP packet that was too small. Dropping packet.\n");
    we_good = 0;
  }
  if(!is_icmp_chksum_ok(ip_hdr->ip_len, icmp_hdr)) {
    Debug("Computed ICMP checksum is not same as given. Dropping packet.\n"); 
    we_good = 0;
  }
  return we_good;
}

void sr_handle_ip(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, struct sr_if *rec_iface) {
 
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
      
  //sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  //uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  //uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  
  struct sr_ip_hdr *iphdr = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));

  if(!check_ip_packet_ok(ip_hdr, len)){
    return;
  } 
  struct sr_rt *match = calculate_LPM(sr, iphdr->ip_dst);
  uint32_t packetDst = iphdr->ip_dst;
  //if is in nat node
  if(sr->nat_mode == 1){
    //check if is from internal or external interface
    if(strcmp(rec_iface->name, "eth1") == 0){
      struct sr_if* ourInterfaceList = sr->if_list;
      while(ourInterfaceList) {
        if (ourInterfaceList->ip == packetDst) {
          Debug("the packet is for us\n"); 
          sr_handle_ip_rec(sr, packet, len, rec_iface, ourInterfaceList);
          return;
        }
        ourInterfaceList = ourInterfaceList->next;
      }

      if (iphdr->ip_p == ip_protocol_icmp) {
        sr_icmp_hdr_t *icmpHdr = packet_get_icmp_hdr(packet);
        struct sr_nat_mapping *findNat = sr_nat_lookup_internal(&(sr->nat), iphdr->ip_src, 
            icmpHdr->icmp_hdr_idf, nat_mapping_icmp);
        if (!findNat) {
            findNat = sr_nat_insert_mapping(&(sr->nat), iphdr->ip_src, icmpHdr->icmp_hdr_idf,
                nat_mapping_icmp);
            findNat->ip_ext = sr_get_interface(sr, match->interface)->ip;
            findNat->aux_ext = get_icmp_id(&(sr->nat));
        }
        findNat->last_updated = time(NULL);
        icmpHdr->icmp_hdr_idf = findNat->aux_ext;
        icmpHdr->icmp_sum = 0;
        uint16_t newCksum = cksum(icmpHdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        icmpHdr->icmp_sum = newCksum;
        iphdr->ip_src = findNat->ip_ext;

        ip_hdr->ip_ttl -= 1;
        if(ip_hdr->ip_ttl <= 0) {        
          sr_send_icmp_t3_to(sr, packet,
              icmp_protocol_type_time_exceed, icmp_protocol_code_ttl_expired,
              rec_iface, NULL);
          return;
        }
        sr_do_forwarding(sr, packet, len, rec_iface);

      }

      else if (iphdr->ip_p == ip_protocol_tcp) {
        sr_tcp_hdr_t *tcpHdr = packet_get_tcp_hdr(packet);
        struct sr_nat_mapping *findNat = sr_nat_lookup_internal(&(sr->nat), iphdr->ip_src, 
            ntohs(tcpHdr->tcp_src_port), nat_mapping_tcp);
        if (!findNat) {
            findNat = sr_nat_insert_mapping(&(sr->nat), iphdr->ip_src, ntohs(tcpHdr->tcp_src_port), nat_mapping_tcp);
            findNat->ip_ext = sr_get_interface(sr, match->interface)->ip;
            findNat->aux_ext = get_tcp_port(&(sr->nat));
        }
        findNat->last_updated = time(NULL);

        pthread_mutex_lock(&((sr->nat).lock));
                    
        struct sr_nat_connection *connection = get_connection(findNat, iphdr->ip_dst);

        if (!connection) {
            connection = add_connection(findNat, iphdr->ip_dst);
        }
        connection->last_updated = time(NULL);
        
        if (connection->tcp_state == CLOSED) {
            if(ntohl(tcpHdr->ack_num) == 0 && tcpHdr->syn && 
            !tcpHdr->ack) {
              connection->client_isn = ntohl(tcpHdr->seq_num);
              connection->tcp_state = SYN_SENT;
            }
        }
        else if (connection->tcp_state == SYN_RCVD) {
          if(ntohl(tcpHdr->seq_num) == connection->client_isn + 1 && 
          ntohl(tcpHdr->ack_num) == connection->server_isn + 1 && 
          !tcpHdr->syn) {
            connection->client_isn = ntohl(tcpHdr->seq_num);
            connection->tcp_state = ESTABLISHED;
          }

          pthread_mutex_lock(&(sr->nat.lock));
          struct sr_tcp_syn *incomingSyn = sr->nat.incoming;
          while (incomingSyn){
            if ((incomingSyn->ip_src == iphdr->ip_src) && 
              (incomingSyn->src_port == tcpHdr->tcp_src_port)){
              break;
            }
            incomingSyn = incomingSyn->next;
          }

          if (!incomingSyn){
            struct sr_tcp_syn *newSyn = (struct sr_tcp_syn *) malloc(sizeof(struct sr_tcp_syn));
            newSyn->ip_src = iphdr->ip_src;
            newSyn->src_port = tcpHdr->tcp_src_port;
            newSyn->last_received = time(NULL);
            newSyn->packet = (uint8_t *) malloc(len);
            newSyn->interface = rec_iface->name;
            newSyn->len = len;
            memcpy(newSyn->packet, packet, len);
            newSyn->next = sr->nat.incoming;
            sr->nat.incoming = newSyn;
          }
          pthread_mutex_unlock(&(sr->nat.lock));
        }
        else if (connection->tcp_state == ESTABLISHED) {
            if (tcpHdr->fin && tcpHdr->ack) {
              connection->client_isn = ntohl(tcpHdr->seq_num);
              connection->tcp_state = CLOSED;
            }
        }

        pthread_mutex_unlock(&((sr->nat).lock));

        iphdr->ip_src = findNat->ip_ext;
        tcpHdr->tcp_src_port = htons(findNat->aux_ext);
        tcpHdr->sum = tcp_cksum(iphdr, tcpHdr, len);

        ip_hdr->ip_ttl -= 1;
        if(ip_hdr->ip_ttl <= 0) {        
          sr_send_icmp_t3_to(sr, packet,
              icmp_protocol_type_time_exceed, icmp_protocol_code_ttl_expired,
              rec_iface, NULL);
          return;
        }

        sr_do_forwarding(sr, packet, len, rec_iface);
      }

    }
    else {
   //   Debug("Received packet from external interface\n");
      
      if (iphdr->ip_p == ip_protocol_icmp) {
        sr_icmp_hdr_t *icmpHdr = packet_get_icmp_hdr(packet);
        struct sr_nat_mapping *findNat = sr_nat_lookup_external(&(sr->nat), icmpHdr->icmp_hdr_idf, 
            nat_mapping_icmp);
        if (findNat) {
          if (icmpHdr->icmp_type == icmp_protocol_type_echo_rep 
          && icmpHdr->icmp_code == icmp_protocol_code_empty) {

            iphdr->ip_dst = findNat->ip_int;
            icmpHdr->icmp_hdr_idf = findNat->aux_int;
            findNat->last_updated = time(NULL);

            icmpHdr->icmp_sum = 0;
            uint16_t calculatedCksum = cksum(icmpHdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            icmpHdr->icmp_sum = calculatedCksum;
            
            ip_hdr->ip_ttl -= 1;
            if(ip_hdr->ip_ttl <= 0) {        
              sr_send_icmp_t3_to(sr, packet,
                  icmp_protocol_type_time_exceed, icmp_protocol_code_ttl_expired,
                  rec_iface, NULL);
              return;
            }

            sr_do_forwarding(sr, packet, len, rec_iface);
          }

        }
      }

      else if (iphdr->ip_p == ip_protocol_tcp) {
        sr_tcp_hdr_t *tcpHdr = packet_get_tcp_hdr(packet);
        struct sr_nat_mapping *findNat = sr_nat_lookup_external(&(sr->nat), ntohs(tcpHdr->dst_port), 
        nat_mapping_tcp);
        
        if (findNat) {
          findNat->last_updated = time(NULL);
          
          pthread_mutex_lock(&((sr->nat).lock));
          struct sr_nat_connection *connection = get_connection(findNat, iphdr->ip_src);
          if (!connection) {
            connection = add_connection(findNat, iphdr->ip_src);
          }
          connection->last_updated = time(NULL);

          if (connection->tcp_state == SYN_SENT) {
            if (ntohl(tcpHdr->ack_num) == connection->client_isn + 1 && tcpHdr->syn && tcpHdr->ack) {
              connection->server_isn = ntohl(tcpHdr->seq_num);
              connection->tcp_state = SYN_RCVD;
            }
            else if (ntohl(tcpHdr->ack_num) == 0 && tcpHdr->syn && !tcpHdr->ack) {
              connection->server_isn = ntohl(tcpHdr->seq_num);
              connection->tcp_state = SYN_RCVD;
            }
          }
          else if (connection->tcp_state == SYN_RCVD) {
            pthread_mutex_lock(&(sr->nat.lock));
            struct sr_tcp_syn *incomingSyn = sr->nat.incoming;
            while (incomingSyn){
              if ((incomingSyn->ip_src == iphdr->ip_src) && 
                (incomingSyn->src_port == tcpHdr->tcp_src_port)){
                break;
              }
              incomingSyn = incomingSyn->next;
            }

            if (!incomingSyn){
              struct sr_tcp_syn *newSyn = (struct sr_tcp_syn *) malloc(sizeof(struct sr_tcp_syn));
              newSyn->ip_src = iphdr->ip_src;
              newSyn->src_port = tcpHdr->tcp_src_port;
              newSyn->last_received = time(NULL);
              newSyn->packet = (uint8_t *) malloc(len);
              newSyn->interface = rec_iface->name;
              newSyn->len = len;
              memcpy(newSyn->packet, packet, len);
              newSyn->next = sr->nat.incoming;
              sr->nat.incoming = newSyn;
            }
            pthread_mutex_unlock(&(sr->nat.lock));
          }
          pthread_mutex_unlock(&((sr->nat).lock));

          iphdr->ip_dst = findNat->ip_int;
          tcpHdr->dst_port = htons(findNat->aux_int);
          tcpHdr->sum = tcp_cksum(iphdr, tcpHdr, len);

          ip_hdr->ip_ttl -= 1;
          if(ip_hdr->ip_ttl <= 0) {        
            sr_send_icmp_t3_to(sr, packet,
                icmp_protocol_type_time_exceed, icmp_protocol_code_ttl_expired,
                rec_iface, NULL);
            return;
          }
          sr_do_forwarding(sr, packet, len, rec_iface);

        }
      }

    }

  }
  else{
    struct sr_if *iface_walker = sr->if_list;
    
    while(iface_walker) {
      // If we are the receiver, could also compare ethernet
      // addresses as an extra check
      if(iface_walker->ip == packetDst) {
        Debug("Got a packet destined the router at interface\n");
        sr_handle_ip_rec(sr, packet, len, rec_iface, iface_walker);
        return;
      }
      iface_walker = iface_walker->next;
    }

    // Not for me, do IP forwarding
    Debug("Got a packet not destined to the router, forwarding it\n");
    // Decrement TTL
    ip_hdr->ip_ttl -= 1;

    // If TTL now 0, drop and let sender know
    if(ip_hdr->ip_ttl <= 0) {
      Debug("\tDecremented a packet to TTL of 0, dropping and sending TTL expired ICMP\n");
      sr_send_icmp_t3_to(sr, packet,
          icmp_protocol_type_time_exceed, icmp_protocol_code_ttl_expired,
          rec_iface, NULL);
      return;
    }
    sr_do_forwarding(sr, packet, len, rec_iface);  
    
  }

}

/*
 * Finds the interface to forward this packet on, and forwards the
 * packet on it, sending an ICMP error message to the sender, if
 * we're unable to find the IP in the routing table
 */
void sr_do_forwarding(struct sr_instance *sr, uint8_t *packet,
    unsigned int len, struct sr_if *rec_iface) {
  // Get interface we need to send this packet out on
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  sr_ethernet_hdr_t *eh_dr = packet_get_eth_hdr(packet);

  struct sr_rt *next_hop_ip = calculate_LPM(sr, ip_hdr->ip_dst);
  if (!next_hop_ip){
    Debug("\t net unreachable\n");
    sr_send_icmp_t3_to(sr, packet, icmp_protocol_type_dest_unreach,
      icmp_protocol_code_net_unreach, rec_iface, NULL );
      return;
  }

  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip->gw.s_addr);
  
  if(!arp_entry){
    struct sr_arpreq *request = sr_arpcache_queuereq(&(sr->cache), next_hop_ip->gw.s_addr, packet, 
                                    len, next_hop_ip->interface);
    handle_arpreq(sr, request);
    return;
  }
  struct sr_if *out_if = sr_get_interface(sr, next_hop_ip->interface);

  memcpy(eh_dr->ether_shost, (uint8_t *) out_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eh_dr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
  free(arp_entry);

  sr_send_packet(sr, packet, len, out_if->name);
  return;
}

  


void sr_handle_ip_rec(struct sr_instance *sr, uint8_t *packet,
    unsigned int len, struct sr_if *rec_iface, struct sr_if* target_iface) {

  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  uint8_t ip_proto = ip_hdr->ip_p;

  switch(ip_proto) {
    // If packet is a TCP or UDP packet...
    case ip_protocol_tcp:
    case ip_protocol_udp:
      Debug("\tTCP/UDP request received on iface %s, sending port unreachable\n",
          rec_iface->name);
      // Send ICMP port unreachable
      sr_send_icmp_t3_to(sr, packet, icmp_protocol_type_dest_unreach,
          icmp_protocol_code_port_unreach, rec_iface, target_iface);
      break;
    
    case ip_protocol_icmp: ;
      Debug("is an icmp packet\n");
      sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

      // Check for too small packet length or wrong checksum
      if(!is_sanity_check_of_icmp_packet_ok(ip_hdr, icmp_hdr, len)) 
          return;

      if(icmp_hdr->icmp_type == icmp_protocol_type_echo_req &&
          icmp_hdr->icmp_code == icmp_protocol_code_empty) {
        
        // Send ICMP echo reply
        sr_send_icmp(sr, icmp_protocol_type_echo_rep,
        icmp_protocol_code_empty, packet, len, rec_iface, target_iface);
      }
      break;
    default:
      Debug("\tUnable to process packet with protocol number %d\n", ip_proto);
      return;
  }
}

