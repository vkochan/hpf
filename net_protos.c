/*
 * net_protos.c	network layer protos
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

#include "proto.h"

#define IPV4_NAME(fld) "ipv4."fld

struct proto_field ipv4_fields[] = {
	{
		.name	= IPV4_NAME("ver"),
		.offset	= 0,
		.mask	= 0xf,
	},
	{
		.name	= IPV4_NAME("ihl"),
		.offset	= 0,
		.mask	= 0xf0,
	},
	{},
};

struct proto ipv4_proto = {
	.layer	= LAYER_NETWORK,
	.name	= "ipv4",
	.fields = ipv4_fields,
};

void net_protos_register(void)
{
	proto_register(&ipv4_proto);
};
