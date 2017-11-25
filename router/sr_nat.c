
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

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

    /* handle periodic tasks here */

    struct sr_nat_mapping *currMapping, *nextMapping;
    currMapping = nat->mappings;

    while (currMapping != NULL) {
      nextMapping = currMapping->next;

      if (currMapping->type == nat_mapping_icmp) { /* ICMP */
        if (difftime(curtime, currMapping->last_updated) > nat->icmp_query_timeout) {
          destroy_nat_mapping(nat, currMapping);
        }
      } else if (currMapping->type == nat_mapping_tcp) { /* TCP */
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
