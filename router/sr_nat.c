
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    

    struct sr_nat_mapping *currMapping, *nextMapping;
    currMapping = nat->mappings;


    struct sr_tcp_syn *incoming = nat->incoming;
    struct sr_tcp_syn *prev_tcp_syn = NULL;
    while (incoming){
      if (difftime(curtime, incoming->last_received) > 6){
        int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t *reply_packet = malloc(len);

        sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
        memcpy(eth_hdr, (sr_ethernet_hdr_t *) incoming->packet, sizeof(sr_ethernet_hdr_t));

        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (incoming->packet + sizeof(sr_ethernet_hdr_t));

        // Determine if packet is directed to this router 
        struct sr_if *if_walker = 0;
        if_walker = nat->sr->if_list;

        while(if_walker){
          if(if_walker->ip == ip_hdr->ip_dst){
            break;
          }
        if_walker = if_walker->next;
        }

        // Make ethernet header 
        sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)reply_packet;
        memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(sr_ethernet_hdr_t));
        memcpy(reply_eth_hdr->ether_shost, sr_get_interface(nat->sr, incoming->interface)->addr, sizeof(sr_ethernet_hdr_t));
        reply_eth_hdr->ether_type = htons(ethertype_ip);


        // Make IP header 
        sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
        reply_ip_hdr->ip_v = 4;
        reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
        reply_ip_hdr->ip_tos = 0;
        reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        reply_ip_hdr->ip_id = htons(0);
        reply_ip_hdr->ip_off = htons(IP_DF);
        reply_ip_hdr->ip_ttl = 64;
        reply_ip_hdr->ip_dst = ip_hdr->ip_src;
        reply_ip_hdr->ip_p = ip_protocol_icmp;
        reply_ip_hdr->ip_src = if_walker->ip;
        reply_ip_hdr->ip_sum = 0;
        reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));

        // Make ICMP Header 
        sr_icmp_t3_hdr_t *reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        reply_icmp_hdr->icmp_type = ICMP_UNREACHABLE_REPLY;
        reply_icmp_hdr->icmp_code = 3;
        reply_icmp_hdr->unused = 0;
        reply_icmp_hdr->next_mtu = 0;
        reply_icmp_hdr->icmp_sum = 0;
        memcpy(reply_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        sr_send_packet(nat->sr, reply_packet, incoming->len, incoming->interface); 
    
        if (prev_tcp_syn){
          prev_tcp_syn->next = incoming->next;
        } else {
          nat->incoming = incoming->next;
        }

        struct sr_tcp_syn *temp = incoming;
        incoming = incoming->next;
        free(temp->packet);
        free(temp);
      } else {
        prev_tcp_syn = incoming;
        incoming = incoming->next;
      }
    }



    while (currMapping != NULL) {
      nextMapping = currMapping->next;

      //icmp
      if (currMapping->type == nat_mapping_icmp) { 
        if (difftime(curtime, currMapping->last_updated) > nat->icmp_query_timeout) {
          destroy_nat_mapping(nat, currMapping);
        }
        //tcp
      } else if (currMapping->type == nat_mapping_tcp) { 
        check_tcp_conns(nat, currMapping);
        if (currMapping->conns == NULL && difftime(curtime, currMapping->last_updated) > 0.5) {
          destroy_nat_mapping(nat, currMapping);
        }
      }
      currMapping = nextMapping;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
 // struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *currM, *foundM = NULL;
  currM = nat->mappings;

  while (currM != NULL) {
    if (currM->type == type && currM->aux_ext == aux_ext) {
      foundM = currM;
      break;
    }
    currM = currM->next;
  }
  
  pthread_mutex_unlock(&(nat->lock));
  return foundM;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  //struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *currM, *foundM = NULL;
  currM = nat->mappings;

  while (currM != NULL) {
    if (currM->type == type && currM->aux_int == aux_int && currM->ip_int == ip_int) {
      foundM = currM;
      break;
    }
    currM = currM->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return foundM;

}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  //struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *newMapping = malloc(sizeof(struct sr_nat_mapping)); 
  assert(newMapping != NULL);

  newMapping->type = type;
  newMapping->last_updated = time(NULL);
  newMapping->ip_int = ip_int;
  newMapping->aux_int = aux_int;
  newMapping->conns = NULL;

  struct sr_nat_mapping *currM = nat->mappings;
  nat->mappings = newMapping;
  newMapping->next = currM;

  pthread_mutex_unlock(&(nat->lock));
  return newMapping;
}

int sr_nat_is_iface_internal(char *iface) {
  return strcmp(iface, NAT_INTERNAL_IFACE) == 0 ? 1 : 0;
}

int generate_unique_port(struct sr_nat *nat) {

  pthread_mutex_lock(&(nat->lock));

  uint16_t *available_ports = nat->available_ports;
  int i;

  for (i = MIN_PORT; i <= TOTAL_PORTS; i++) {
    if (available_ports[i] == 0) {
      available_ports[i] = 1;
      printf("Allocated port: %d\n", i);

      pthread_mutex_unlock(&(nat->lock));
      return i;
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return -1;
}


int generate_unique_icmp_identifier(struct sr_nat *nat) {

  pthread_mutex_lock(&(nat->lock));

  uint16_t *available_icmp_identifiers = nat->available_icmp_identifiers;
  int i;

  for (i = MIN_ICMP_IDENTIFIER; i <= TOTAL_ICMP_IDENTIFIERS; i++) {
    if (available_icmp_identifiers[i] == 0) {
      available_icmp_identifiers[i] = 1;
      printf("Allocated ICMP identifier: %d\n", i);

      pthread_mutex_unlock(&(nat->lock));
      return i;
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return -1;
}

struct sr_nat_connection *sr_nat_lookup_tcp_con(struct sr_nat_mapping *mapping, uint32_t ip_con) {
  struct sr_nat_connection *currConn = mapping->conns;

  while (currConn != NULL) {
    if (currConn->ip == ip_con) {
      return currConn;
    }
    currConn = currConn->next;
  }

  return NULL;
}

//insert a new connection with the given ip in the nat entry
struct sr_nat_connection *sr_nat_insert_tcp_con(struct sr_nat_mapping *mapping, uint32_t ip_con) {
  struct sr_nat_connection *newConn = malloc(sizeof(struct sr_nat_connection));
  assert(newConn != NULL);
  memset(newConn, 0, sizeof(struct sr_nat_connection));

  newConn->last_updated = time(NULL);
  newConn->ip = ip_con;
  newConn->tcp_state = CLOSED;

  struct sr_nat_connection *currConn = mapping->conns;

  mapping->conns = newConn;
  newConn->next = currConn;

  return newConn;
}

void check_tcp_conns(struct sr_nat *nat, struct sr_nat_mapping *nat_mapping) {
  struct sr_nat_connection *currConn, *nextConn;
  time_t curtime = time(NULL);

  currConn = nat_mapping->conns;

  while (currConn != NULL) {
    nextConn = currConn->next;
    /* print_tcp_state(currConn->tcp_state); */

    if (currConn->tcp_state == ESTABLISHED) {
      if (difftime(curtime, currConn->last_updated) > nat->tcp_estb_timeout) {
        destroy_tcp_conn(nat_mapping, currConn);
      }
    } else {
      if (difftime(curtime, currConn->last_updated) > nat->tcp_trans_timeout) {
        destroy_tcp_conn(nat_mapping, currConn);
      }
    }

    currConn = nextConn;
  }
}

void destroy_tcp_conn(struct sr_nat_mapping *mapping, struct sr_nat_connection *conn) {
  printf("[REMOVE] TCP connection\n");
  struct sr_nat_connection *prevConn = mapping->conns;

  if (prevConn != NULL) {
    if (prevConn == conn) {
      mapping->conns = conn->next;
    } else {
      for (; prevConn->next != NULL && prevConn->next != conn; prevConn = prevConn->next) {}
        if (prevConn == NULL) { return; }
      prevConn->next = conn->next;
    }
    free(conn);
  }
}

void destroy_nat_mapping(struct sr_nat *nat, struct sr_nat_mapping *nat_mapping) {
  printf("[REMOVE] nat mapping\n");

  struct sr_nat_mapping *prevMapping = nat->mappings;

  if (prevMapping != NULL) {
    if (prevMapping == nat_mapping) {
      nat->mappings = nat_mapping->next;
    } else {
      for (; prevMapping->next != NULL && prevMapping->next != nat_mapping; prevMapping = prevMapping->next) {}
        if (prevMapping == NULL) {return;}
      prevMapping->next = nat_mapping->next;
    }

    if (nat_mapping->type == nat_mapping_icmp) { /* ICMP */
      nat->available_icmp_identifiers[nat_mapping->aux_ext] = 0;
    } else if (nat_mapping->type == nat_mapping_tcp) { /* TCP */
      nat->available_ports[nat_mapping->aux_ext] = 0;
    }

    struct sr_nat_connection *currConn, *nextConn;
    currConn = nat_mapping->conns;

    while (currConn != NULL) {
      nextConn = currConn->next;
      free(currConn);
      currConn = nextConn;
    }
    free(nat_mapping);
  }
}

