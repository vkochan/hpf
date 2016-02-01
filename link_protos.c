/*
 * link_protos.c link layer protocols
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

#include "proto.h"

#define ETH_NAME(fld) "ether."fld

struct proto_field ether_fields[] = {
	{
		.name	= ETH_NAME("type"),
		.offset = 12,
		.len = 2,
	},
	{},
};

struct proto ether_proto = {
	.layer	= LAYER_LINK,
	.name	= "ether",
	.fields = ether_fields,
};

void link_protos_register(void)
{
	proto_register(&ether_proto);
}
