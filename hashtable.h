/*
    Copyright (C) 2015 Datto Inc.

    This file is part of throughputd.

    This program is free software; you can redistribute it and/or modify it 
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation.
*/

#ifndef HASHTABLE_H_
#define HASHTABLE_H_

#include "list.h"

struct hashtable_link{
	char *key;
	struct list_link link;
};

struct hashtable{
	uint64_t array_size;
	uint64_t current_size;
	struct list_link *buckets;
};

typedef int (foreach_cb) (struct hashtable *, struct hashtable_link *, void *);

void hashtable_free(struct hashtable *);
void hashtable_destroy(struct hashtable *);
int hashtable_init(struct hashtable *, uint64_t);
int hashtable_alloc(uint64_t, struct hashtable **);

int hashtable_insert(struct hashtable *, char *, struct hashtable_link *);
struct hashtable_link *hashtable_find(struct hashtable *, char *);
struct hashtable_link *hashtable_delete(struct hashtable *, char *);

int hashtable_for_each_key(struct hashtable *, foreach_cb, void *);

void hashtable_print(struct hashtable *);

#endif
