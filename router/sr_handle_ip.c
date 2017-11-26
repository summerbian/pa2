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
      
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);

  uint8_t ipProtocol = ipHdr->ip_p;
  uint32_t ipDst = ipHdr->ip_dst;
  uint32_t ipSrc = ipHdr->ip_src;

  struct sr_ip_hdr *ipHdr = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *myInterface = sr_get_interface_by_ip(sr, ipDst); 
  struct sr_rt *lpmEntry = sr_get_lpm_entry(sr->routing_table, ipDst);    

  if(!check_ip_packet_ok(ip_hdr, len)) return;

  if (sr->nat_mode) {
      struct sr_if *internal_interface = sr_get_interface(sr, NAT_INTERNAL_IFACE);
     // struct sr_if *internal_interface = sr_get_interface(sr, rec_iface);
      printf("Nat mode \n");
      if (sr_nat_is_iface_internal(rec_iface->name)) {
        
        //the packet is for the router or the internal interface 
        if (myInterface != NULL || sr_nat_is_iface_internal(lpmEntry->interface)) {
          sr_do_forwarding(sr, packet, len, rec_iface);
          
        
        // the packet is for the external interface 
        } else {
          if (ipProtocol == ip_protocol_icmp) {
            printf("Nat mode, icmp\n");
            sr_icmp_hdr_t *icmp_hdr = packet_get_icmp_hdr(packet);

            struct sr_nat_mapping *nat_lookup = sr_nat_lookup_internal(&(sr->nat), ipSrc, icmp_hdr->icmp_etc_hdr_1, nat_mapping_icmp);
            if (nat_lookup == NULL) {
              nat_lookup = sr_nat_insert_mapping(&(sr->nat), ipSrc, icmp_hdr->icmp_etc_hdr_1, nat_mapping_icmp);
              nat_lookup->ip_ext = sr_get_interface(sr, lpmEntry->interface)->ip;
              nat_lookup->aux_ext = generate_unique_icmp_identifier(&(sr->nat));
            }

            nat_lookup->last_updated = time(NULL);
            icmp_hdr->icmp_etc_hdr_1 = nat_lookup->aux_ext;
            ipHdr->ip_src = nat_lookup->ip_ext;

           
            ipHdr->ip_sum = 0;
            ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
            int icmpOffset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, len - icmpOffset);

            sr_do_forwarding(sr, packet, len, rec_iface);
         
          } else if (ipProtocol == ip_protocol_tcp) {
            printf("Nat mode, TCP part\n");
            sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_tcp_hdr_t));

            struct sr_nat_mapping *nat_lookup = sr_nat_lookup_internal(&(sr->nat), ipSrc, ntohs(tcp_hdr->src_port), nat_mapping_tcp);
            if (nat_lookup == NULL) {
              nat_lookup = sr_nat_insert_mapping(&(sr->nat), ipSrc, ntohs(tcp_hdr->src_port), nat_mapping_tcp);
              nat_lookup->ip_ext = sr_get_interface(sr, lpmEntry->interface)->ip;
              nat_lookup->aux_ext = generate_unique_port(&(sr->nat));
            }
            nat_lookup->last_updated = time(NULL);

            // Critical section, modify code under critical section. 
            pthread_mutex_lock(&((sr->nat).lock));

            struct sr_nat_connection *tcp_con = sr_nat_lookup_tcp_con(nat_lookup, ipDst);
            if (tcp_con == NULL) {
              tcp_con = sr_nat_insert_tcp_con(nat_lookup, ipDst);
            }
            tcp_con->last_updated = time(NULL);

            switch (tcp_con->tcp_state) {
              case CLOSED:
                if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack) {
                  tcp_con->client_isn = ntohl(tcp_hdr->seq_num);
                  tcp_con->tcp_state = SYN_SENT;
                }
                break;

              case SYN_RCVD:
                if (ntohl(tcp_hdr->seq_num) == tcp_con->client_isn + 1 && ntohl(tcp_hdr->ack_num) == tcp_con->server_isn + 1 && !tcp_hdr->syn) {
                  tcp_con->client_isn = ntohl(tcp_hdr->seq_num);
                  tcp_con->tcp_state = ESTABLISHED;
                }
                break;

              case ESTABLISHED:
                if (tcp_hdr->fin && tcp_hdr->ack) {
                  tcp_con->client_isn = ntohl(tcp_hdr->seq_num);
                  tcp_con->tcp_state = CLOSED;
                }
                break;

              default:
                break;
            }

            pthread_mutex_unlock(&((sr->nat).lock));
            //critical section end

            ipHdr->ip_src = nat_lookup->ip_ext;
            tcp_hdr->src_port = htons(nat_lookup->aux_ext);

            ipHdr->ip_sum = 0;
            ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
            tcp_hdr->sum = tcp_cksum(ipHdr, tcp_hdr, len);

            sr_do_forwarding(sr, packet, len, rec_iface);
          }
        }
      } else {
        printf("External Interface \n");

        // check if it is an external or fake internal                
        if (myInterface == NULL) {
          //if it is for external
          if (!sr_nat_is_iface_internal(lpmEntry->interface)) {
            sr_do_forwarding(sr, packet, len, rec_iface);
          }
        } else {
          if (ipProtocol == ip_protocol_icmp) {
            printf("external to internal icmp\n");
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            
            struct sr_nat_mapping *nat_lookup = sr_nat_lookup_external(&(sr->nat), icmp_hdr->icmp_etc_hdr_1, nat_mapping_icmp);
            if (nat_lookup != NULL) {
              if (is_icmp_echo_reply(icmp_hdr)) {
                ipHdr->ip_dst = nat_lookup->ip_int;
                icmp_hdr->icmp_etc_hdr_1 = nat_lookup->aux_int;
                nat_lookup->last_updated = time(NULL);

                 ipHdr->ip_sum = 0;
                ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
                int icmpOffset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, len - icmpOffset);

                sr_do_forwarding(sr, packet, len, rec_iface);
              }
            }
          } else if (ipProtocol == ip_protocol_tcp) {
            printf("tcp external to internal\n");
            sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            struct sr_nat_mapping *nat_lookup = sr_nat_lookup_external(&(sr->nat), ntohs(tcp_hdr->dst_port), nat_mapping_tcp);
            if (nat_lookup != NULL) {
              nat_lookup->last_updated = time(NULL);

              // critical section,lock, then modify code under critical section
              pthread_mutex_lock(&((sr->nat).lock));

              struct sr_nat_connection *tcp_con = sr_nat_lookup_tcp_con(nat_lookup, ipSrc);
              if (tcp_con == NULL) {
                tcp_con = sr_nat_insert_tcp_con(nat_lookup, ipSrc);
              }
              tcp_con->last_updated = time(NULL);

              switch (tcp_con->tcp_state) {
                case SYN_SENT:
                  if (ntohl(tcp_hdr->ack_num) == tcp_con->client_isn + 1 && tcp_hdr->syn && tcp_hdr->ack) {
                    tcp_con->server_isn = ntohl(tcp_hdr->seq_num);
                    tcp_con->tcp_state = SYN_RCVD;
                  
                  
                  } else if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack) {
                  tcp_con->server_isn = ntohl(tcp_hdr->seq_num);
                  tcp_con->tcp_state = SYN_RCVD;
                }
                break;
              
                default:
                  break;
              }

              pthread_mutex_unlock(&((sr->nat).lock));
            

              ipHdr->ip_dst = nat_lookup->ip_int;
              tcp_hdr->dst_port = htons(nat_lookup->aux_int);

              ipHdr->ip_sum = 0;
              ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
              tcp_hdr->sum = 0;
              tcp_hdr->sum = cksum(ipHdr, tcp_hdr, len);

              sr_do_forwarding(sr, packet, len, rec_iface);
            }
          }
        }
      }
    } 
    else{
      struct sr_if *iface_walker = sr->if_list;
    // Loop through all interfaces to see if it matches one
      while(iface_walker) {
        // If we are the receiver, could also compare ethernet
        // addresses as an extra check
        if(iface_walker->ip == ip_hdr->ip_dst) {
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

      // Sanity checks done, forward packet
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

  Debug("Got IP packet:\n");
  sr_ip_hdr_t *ip_hdr = packet_get_ip_hdr(packet);
  // Get IP protocol information
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
          icmp_protocol_type_echo_rep, packet, len, rec_iface, target_iface);
      }
      break;
    default:
      Debug("\tUnable to process packet with protocol number %d\n", ip_proto);
      return;
  }
}

