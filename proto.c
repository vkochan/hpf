/*
 * proto.c	protocol registering module
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

#include <stddef.h>

#include "utils.h"
#include "proto.h"
#include "htable.h"

#define PROTOS_HTABLE_SIZE	32
#define FIELDS_HTABLE_SIZE	256

static struct htable *protos;
static struct htable *fields;

static void __fields_register(struct proto *p, struct proto_field *f)
{
	for (; f->name; f++) {
		f->proto = p;
		htable_insert_name(fields, &f->hlist, f->name);
	}
}

void proto_register(struct proto *p)
{
	htable_insert_name(protos, &p->hlist, p->name);

	if (p->fields)
		__fields_register(p, p->fields);
}

struct proto *proto_lookup(char *name)
{
	struct hentry *entry = htable_find_name(protos, name);
	if (!entry)
		return NULL;

	return container_of(entry, struct proto, hlist);
}

struct proto_field *proto_field_lookup(char *name)
{
	struct hentry *entry = htable_find_name(fields, name);
	if (!entry)
		return NULL;

	return container_of(entry, struct proto_field, hlist);
}

void proto_init(void)
{
	protos = htable_alloc(PROTOS_HTABLE_SIZE);
	fields = htable_alloc(FIELDS_HTABLE_SIZE);
}

void proto_cleanup(void)
{
	htable_free(fields);
	htable_free(protos);
}
