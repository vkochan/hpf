/*
 * main.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>

#include "bpf.h"
#include "proto.h"
#include "compiler.h"
#include "proto_registers.h"

static const char *opts = "de:O";

static const struct option long_opts[] = {
	{ "dump",		no_argument,	NULL,	'd' },
	{ "expr",		no_argument,	NULL,	'e' },
	{ "no-optimize",	no_argument,	NULL,	'O' },
	{ NULL, 0, NULL, 0 },
};

static void protos_register(void)
{
	/* should be called first */
	proto_init();

	link_protos_register();
	net_protos_register();
}

static void protos_unregister(void)
{
	/* should be called last */
	proto_cleanup();
}

int main(int argc, char **argv)
{
	struct sock_filter *f;
	bool do_optimize = true;
	bool show_dump = false;
	int ins_count;
	char *expr;
	int opt;
	int idx;

	while ((opt = getopt_long(argc, argv, opts, long_opts, &idx)) != EOF) {
		switch (opt) {
		case 'd':
			show_dump = true;
			break;
		case 'e':
			expr = strdup(optarg);
			break;
		case 'O':
			do_optimize = false;
			break;
		}
	}

	if (!expr) {
		printf("expresion is not specified '-e'\n");
		return -1;
	}

	protos_register();

	ins_count = compile_filter(expr, &f, do_optimize);
	if (ins_count && show_dump)
		bpf_dump(f, ins_count);

	protos_unregister();
}
