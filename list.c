/*
    Copyright (C) 2015 Datto Inc.

    This file is part of throughputd.

    This program is free software; you can redistribute it and/or modify it 
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation.
*/

#include <stddef.h>
#include "list.h"

void list_init(struct list_link *head){
	head->next = head;
}

int list_is_empty(struct list_link *head){
	return head->next == head;
}

int list_is_last(struct list_link *elem, struct list_link *head){
	return elem->next == head;
}

static void __list_add(struct list_link *elem, struct list_link *prev, struct list_link *next){
	elem->next = next;
	prev->next = elem;
}

void list_add_head(struct list_link *elem, struct list_link *head){
	__list_add(elem, head, head->next);
}

struct list_link *list_del_next(struct list_link *prev){
	struct list_link *elem;
	
	elem = prev->next;
	prev->next = elem->next;
	list_init(elem);
	
	return elem;
}
