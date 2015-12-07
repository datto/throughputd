/*
    Copyright (C) 2015 Datto Inc.

    This file is part of throughputd.

    This program is free software; you can redistribute it and/or modify it 
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation.
*/

#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "debug.h"
#include "hashtable.h"

#define HASH_FUNCTION_MULTIPLIER 96

void hashtable_destroy(struct hashtable *ht){
	PRINT_DEBUG("freeing buckets");
	if(ht->buckets) free(ht->buckets);
}

void hashtable_free(struct hashtable *ht){
	PRINT_DEBUG("destroying hashtable variables");
	hashtable_destroy(ht);
	
	PRINT_DEBUG("freeing hashtable struct");
	free(ht);
}

int hashtable_init(struct hashtable *ht, uint64_t array_size){
	int ret;
	uint32_t i;
	
	PRINT_DEBUG("allocating %llu buckets", (unsigned long long)array_size);
	ht->buckets = malloc(array_size * sizeof(struct list_link));
	if(!ht->buckets){
		ret = ENOMEM;
		PRINT_ERROR(ret, "error allocating hashtable backing array");
		goto error;
	}
	
	for(i = 0; i < array_size; i++){
		list_init(&ht->buckets[i]);
	}
	
	ht->array_size = array_size;
	ht->current_size = 0;
	
	return 0;
	
error:
	PRINT_ERROR(ret, "error initializing hashtable");
	if(ht->buckets) free(ht->buckets);
	return ret;
}

int hashtable_alloc(uint64_t array_size, struct hashtable **ht_out){
	int ret;
	struct hashtable *ht;
	
	PRINT_DEBUG("allocating hashtable struct");
	ht = malloc(sizeof(struct hashtable));
	if(!ht){
		ret = ENOMEM;
		PRINT_ERROR(ret, "error allocating hashtable");
		goto error;
	}
	
	PRINT_DEBUG("initializing hashtable struct");
	ret = hashtable_init(ht, array_size);
	if(ret)	goto error;
	
	*ht_out = ht;
	return 0;
	
error:
	PRINT_ERROR(ret, "error allocating and initializing hashtable");
	if(ht) free(ht);
	
	*ht_out = NULL;
	return ret;
}

static uint32_t __hashtable_hash(struct hashtable *ht, const char *key){
	const uint8_t *c;
	uint32_t hash = 0;
	
	if(!key) return 0;
	
	for (c = (uint8_t *)key; *c; c++){
		hash = hash * HASH_FUNCTION_MULTIPLIER + *c;
	}
	
	return hash % ht->array_size;
}

static struct hashtable_link *__hashtable_find(struct hashtable *ht, uint32_t hash, char *key){
	struct hashtable_link *cur;
	
	PRINT_DEBUG("searching bucket %d for key %s", hash, key);
	list_for_each_entry(cur, &ht->buckets[hash], link){
		if(!strcmp(key, cur->key)) return cur;
	}

	return NULL;
}

struct hashtable_link *hashtable_find(struct hashtable *ht, char *key){
	return __hashtable_find(ht, __hashtable_hash(ht, key), key);
}

int hashtable_insert(struct hashtable *ht, char *key, struct hashtable_link *hl){
	uint32_t hash = __hashtable_hash(ht, key);
	
	PRINT_DEBUG("searching for existing key");
	if(__hashtable_find(ht, hash, key) != NULL) return EEXIST;
	
	PRINT_DEBUG("key doesnt exist; adding element");
	hl->key = key;
	list_add_head(&hl->link, &ht->buckets[hash]);
	ht->current_size++;
	
	return 0;
}

struct hashtable_link *hashtable_delete(struct hashtable *ht, char *key){
	struct hashtable_link *cur;
	uint32_t hash = __hashtable_hash(ht, key);
	struct list_link *prev_link = &ht->buckets[hash];
	
	list_for_each_entry(cur, &ht->buckets[hash], link){
		if(!strcmp(key, cur->key)){
			list_del_next(prev_link);
			ht->current_size--;
			return cur;
		}
		
		prev_link = prev_link->next;
	}
	
	return NULL;
}

int hashtable_for_each_key(struct hashtable *ht, foreach_cb cb, void *data){
	int ret;
	uint32_t i;
	struct hashtable_link *cur, *n;
	
	for(i = 0; i < ht->array_size; i++){
		list_for_each_entry_safe(cur, n, &ht->buckets[i], link){
			ret = cb(ht, cur, data);
			if(ret) return ret;
		}
	}
	
	return 0;
}

void hashtable_print(struct hashtable *ht){
	uint32_t i;
	struct hashtable_link *cur;
	
	for(i = 0; i < ht->array_size; i++){
		printf("%d: ", i);
		list_for_each_entry(cur, &ht->buckets[i], link){
			printf("%s -> ", cur->key);
		}
		printf("\n");
	}
}
