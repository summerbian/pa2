
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

//#define MAX_UINT 65535
//#define MIN_PORT 1024
//#define TOTAL_PORTS MAX_UINT - MIN_PORT
#define NUM_OF_ICMP_IDs 65535 - 1
#define NUM_OF_PORTS 65535 - 1024
//#define MIN_ICMP_IDENTIFIER 1
//#define TOTAL_ICMP_IDENTIFIERS MAX_UINT - MIN_ICMP_IDENTIFIER
#define NAT_INTERNAL_IFACE "eth1"

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>


typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  CLOSE_WAIT,
  CLOSED,
  CLOSING,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  LAST_ACK,
  LISTEN,
  SYN_RCVD,
  SYN_SENT,
  TIME_WAIT
} sr_tcp_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip;
  uint32_t client_isn;
  uint32_t server_isn;
  time_t last_updated;
  sr_tcp_state tcp_state;

  struct sr_nat_connection *next;

};

struct sr_tcp_syn {
  uint32_t ip_src;
  uint16_t src_port;
  time_t last_received;

  uint8_t *packet;
  unsigned int len;
  char *interface;
  struct sr_tcp_syn *next;
};


struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;

  unsigned int icmp_query_timeout;
  unsigned int tcp_estb_timeout;
  unsigned int tcp_trans_timeout;

  struct sr_tcp_syn *incoming;
  struct sr_instance *sr;

  //Mapping of available ports 
  uint16_t available_ports[NUM_OF_PORTS];
  // Mapping of available ICMP identifiers 
  uint16_t available_icmp_identifiers[NUM_OF_ICMP_IDs];

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

int sr_nat_is_iface_internal(char *iface);
int generate_unique_port(struct sr_nat *nat);
int generate_unique_icmp_identifier(struct sr_nat *nat);
struct sr_nat_connection *sr_nat_lookup_tcp_con(struct sr_nat_mapping *mapping, uint32_t ip_con);
struct sr_nat_connection *sr_nat_insert_tcp_con(struct sr_nat_mapping *mapping, uint32_t ip_con);
void check_tcp_conns(struct sr_nat *nat, struct sr_nat_mapping *nat_mapping);
struct sr_nat_connection *get_connection(struct sr_nat_mapping *mapping, uint32_t ip);
struct sr_nat_connection *add_connection(struct sr_nat_mapping *mapping, uint32_t ip);
void destroy_tcp_conn(struct sr_nat_mapping *mapping, struct sr_nat_connection *conn);
void destroy_nat_mapping(struct sr_nat *nat, struct sr_nat_mapping *nat_mapping);

int get_icmp_id(struct sr_nat *nat);
int get_tcp_port(struct sr_nat *nat);

#endif