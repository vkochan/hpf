/*
 * xmalloc.c	memory alloc helpers
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>

void *xmalloc(size_t size)
{
	void *ptr;

	if (size == 0) {
		printf("xmalloc: size is 0\n");
		exit(-1);
	}

	ptr = malloc(size);
	if (ptr == NULL) {
		printf("xmalloc: Can't allocate %d bytes of memory\n", size);
		exit(-1);
	}
}

void xfree(void *ptr)
{
	if (!ptr) {
		printf("xfree: ptr is NULL\n");
		exit(-1);
	}

	free(ptr);
}
