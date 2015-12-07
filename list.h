/*
    Copyright (C) 2015 Datto Inc.

    This file is part of throughputd.

    This program is free software; you can redistribute it and/or modify it 
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation.
*/

#ifndef LIST_H_
#define LIST_H_

#include "util.h"

struct list_link{
	struct list_link *next;
};

//list manipulation functions
void list_init(struct list_link *);

int list_is_empty(struct list_link *);
int list_is_last(struct list_link *, struct list_link *);

void list_add_head(struct list_link *, struct list_link *);
struct list_link *list_del_next(struct list_link *);

//list iteration macros
#define list_for_each(cur, head) for ((cur) = (head)->next; (cur) != (head); (cur) = (cur)->next)
#define list_for_each_safe(cur, tmp, head) for ((cur) = (head)->next, (tmp) = (cur)->next; (cur) != (head);  (cur) = (tmp), (tmp) = (cur)->next)

#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)
#define list_next_entry(cur, member) list_entry((cur)->member.next, typeof(*(cur)), member)

#define list_for_each_entry(cur, head, member) for (cur = list_first_entry(head, typeof(*cur), member); &cur->member != (head); cur = list_next_entry(cur, member))
#define list_for_each_entry_safe(cur, tmp, head, member) for (cur = list_first_entry(head, typeof(*cur), member), tmp = list_next_entry(cur, member); &cur->member != (head); cur = tmp, tmp = list_next_entry(tmp, member))

#endif
