/*
 * htable.c	hash table
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

#include <string.h>

#include "htable.h"
#include "xmalloc.h"

unsigned long str_hash(char *str)
{
	unsigned long hash = 0;
	int c;

	while (c = *str++)
		hash = c + (hash << 6) + (hash << 16) - hash;

	return hash;
}

struct htable *htable_alloc(int size)
{
	struct htable *ht = xmalloc(sizeof(struct htable));

	memset(ht, 0, sizeof(*ht));

	ht->size = size;
	ht->head = xmalloc(sizeof(struct hentry *) * size);
	memset(ht->head, 0, sizeof(struct hentry *) * size);

	return ht;
}

void htable_reset(struct htable *ht)
{
	memset(ht->head, 0, sizeof(struct hentry *) * ht->size);
	ht->cached = NULL;
}

void htable_free(struct htable *ht)
{
	xfree(ht->head);
	xfree(ht);
}

struct hentry *htable_find(struct htable *ht, unsigned long hash)
{
	struct hentry *entry;
	int i;

	if (ht->cached && ht->cached->hash == hash)
		return ht->cached;

	entry = ht->head[hash & (ht->size - 1)];
	while (entry && entry->hash != hash)
		entry = entry->next;

	if (entry && entry->hash != hash)
		return NULL;

	ht->cached = entry;
	return entry;
}

struct hentry *htable_find_name(struct htable *ht, char *name)
{
	return htable_find(ht, str_hash(name));
}

void htable_insert(struct htable *ht, struct hentry *entry, unsigned long hash)
{
	entry->next = ht->head[hash & (ht->size - 1)];
	entry->hash = hash;
	ht->head[hash & (ht->size - 1)] = entry;
}

void htable_insert_name(struct htable *ht, struct hentry *entry, char *name)
{
	htable_insert(ht, entry, str_hash(name));
}
