#ifndef __BPF_H__
#define __BPF_H__

#include <linux/filter.h>

void bpf_dump(struct sock_filter *bpf, int count);

#endif
