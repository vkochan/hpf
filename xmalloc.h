#ifndef __XMALLOC_H__
#define __XMALLOC_H__

#include <stdlib.h>

void *xmalloc(size_t size);
void xfree(void *ptr);

#endif
