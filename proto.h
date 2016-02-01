#ifndef __PROTO_H__
#define __PROTO_H__

#include "htable.h"
#include "compiler.h"

typedef enum {
	LAYER_LINK,
	LAYER_NETWORK,
	LAYER_TRANSPORT,
	LAYER_4,
	LAYER_5,

	/* must be last */
	LAYER_MAX,
} proto_layer_t;

struct proto_field;

struct proto {
	struct hentry hlist;
	int layer;
	char *name;
	int id;
	struct proto_field *fields;
	/* gen_proto_match */
	/* gen_proto_next */
};

struct proto_field {
	struct hentry hlist;
	struct proto *proto;
	char *name;
	int offset; /* in octets/bytes */
	int mask;
	int len;
};

void proto_init(void);
void proto_cleanup();

void proto_register(struct proto *proto);
struct proto *proto_lookup(char *name);
struct proto_field *proto_field_lookup(char *name);

#endif
