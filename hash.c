#include "hash.h"

/* modified the hash function so it's usuable even when
   starting to hash midway through the logfile */
uint32_t 
djb_hash(const char * data, size_t len, uint32_t hash)
{
	size_t i;
	for (i=0;i<len;data++,i++) {
		hash = ((hash << 5) + hash) + (*data);
	}
	return hash;
}
