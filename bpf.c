/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2012 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Copyright 1990-1996 The Regents of the University of
 * California. All rights reserved. (3-clause BSD license)
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <linux/filter.h>

#include "utils.h"

#define BPF_LD_B	(BPF_LD   |    BPF_B)
#define BPF_LD_H	(BPF_LD   |    BPF_H)
#define BPF_LD_W	(BPF_LD   |    BPF_W)
#define BPF_LDX_B	(BPF_LDX  |    BPF_B)
#define BPF_LDX_W	(BPF_LDX  |    BPF_W)
#define BPF_JMP_JA	(BPF_JMP  |   BPF_JA)
#define BPF_JMP_JEQ	(BPF_JMP  |  BPF_JEQ)
#define BPF_JMP_JGT	(BPF_JMP  |  BPF_JGT)
#define BPF_JMP_JGE	(BPF_JMP  |  BPF_JGE)
#define BPF_JMP_JSET	(BPF_JMP  | BPF_JSET)
#define BPF_ALU_ADD	(BPF_ALU  |  BPF_ADD)
#define BPF_ALU_SUB	(BPF_ALU  |  BPF_SUB)
#define BPF_ALU_MUL	(BPF_ALU  |  BPF_MUL)
#define BPF_ALU_DIV	(BPF_ALU  |  BPF_DIV)
#define BPF_ALU_MOD	(BPF_ALU  |  BPF_MOD)
#define BPF_ALU_NEG	(BPF_ALU  |  BPF_NEG)
#define BPF_ALU_AND	(BPF_ALU  |  BPF_AND)
#define BPF_ALU_OR	(BPF_ALU  |   BPF_OR)
#define BPF_ALU_XOR	(BPF_ALU  |  BPF_XOR)
#define BPF_ALU_LSH	(BPF_ALU  |  BPF_LSH)
#define BPF_ALU_RSH	(BPF_ALU  |  BPF_RSH)
#define BPF_MISC_TAX	(BPF_MISC |  BPF_TAX)
#define BPF_MISC_TXA	(BPF_MISC |  BPF_TXA)

static const char *op_table[] = {
	[BPF_LD_B]	=	"ldb",
	[BPF_LD_H]	=	"ldh",
	[BPF_LD_W]	=	"ld",
	[BPF_LDX]	=	"ldx",
	[BPF_LDX_B]	=	"ldxb",
	[BPF_ST]	=	"st",
	[BPF_STX]	=	"stx",
	[BPF_JMP_JA]	=	"ja",
	[BPF_JMP_JEQ]	=	"jeq",
	[BPF_JMP_JGT]	=	"jgt",
	[BPF_JMP_JGE]	=	"jge",
	[BPF_JMP_JSET]	=	"jset",
	[BPF_ALU_ADD]	=	"add",
	[BPF_ALU_SUB]	=	"sub",
	[BPF_ALU_MUL]	=	"mul",
	[BPF_ALU_DIV]	=	"div",
	[BPF_ALU_MOD]	=	"mod",
	[BPF_ALU_NEG]	=	"neg",
	[BPF_ALU_AND]	=	"and",
	[BPF_ALU_OR]	=	"or",
	[BPF_ALU_XOR]	=	"xor",
	[BPF_ALU_LSH]	=	"lsh",
	[BPF_ALU_RSH]	=	"rsh",
	[BPF_RET]	=	"ret",
	[BPF_MISC_TAX]	=	"tax",
	[BPF_MISC_TXA]	=	"txa",
};

void bpf_dump_op_table(void)
{
	size_t i;
	for (i = 0; i < array_size(op_table); ++i) {
		if (op_table[i])
			printf("%s\n", op_table[i]);
	}
}

static const char *bpf_dump_linux_k(uint32_t k)
{
	switch (k) {
	default:
		return "[%d]";
	case SKF_AD_OFF + SKF_AD_PROTOCOL:
		return "proto";
	case SKF_AD_OFF + SKF_AD_PKTTYPE:
		return "type";
	case SKF_AD_OFF + SKF_AD_IFINDEX:
		return "ifidx";
	case SKF_AD_OFF + SKF_AD_NLATTR:
		return "nla";
	case SKF_AD_OFF + SKF_AD_NLATTR_NEST:
		return "nlan";
	case SKF_AD_OFF + SKF_AD_MARK:
		return "mark";
	case SKF_AD_OFF + SKF_AD_QUEUE:
		return "queue";
	case SKF_AD_OFF + SKF_AD_HATYPE:
		return "hatype";
	case SKF_AD_OFF + SKF_AD_RXHASH:
		return "rxhash";
	case SKF_AD_OFF + SKF_AD_CPU:
		return "cpu";
	case SKF_AD_OFF + SKF_AD_VLAN_TAG:
		return "vlant";
	case SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT:
		return "vlanp";
	case SKF_AD_OFF + SKF_AD_PAY_OFFSET:
		return "poff";
	}
}

static char *__bpf_dump(const struct sock_filter bpf, int n)
{
	int v;
	const char *fmt, *op;
	static char image[256];
	char operand[64];

	v = bpf.k;
	switch (bpf.code) {
	default:
		op = "unimp";
		fmt = "0x%x";
		v = bpf.code;
		break;
	case BPF_RET | BPF_K:
		op = op_table[BPF_RET];
		fmt = "#0x%x";
		break;
	case BPF_RET | BPF_A:
		op = op_table[BPF_RET];
		fmt = "a";
		break;
	case BPF_RET | BPF_X:
		op = op_table[BPF_RET];
		fmt = "x";
		break;
	case BPF_LD_W | BPF_ABS:
		op = op_table[BPF_LD_W];
		fmt = bpf_dump_linux_k(bpf.k);
		break;
	case BPF_LD_H | BPF_ABS:
		op = op_table[BPF_LD_H];
		fmt = bpf_dump_linux_k(bpf.k);
		break;
	case BPF_LD_B | BPF_ABS:
		op = op_table[BPF_LD_B];
		fmt = bpf_dump_linux_k(bpf.k);
		break;
	case BPF_LD_W | BPF_LEN:
		op = op_table[BPF_LD_W];
		fmt = "#len";
		break;
	case BPF_LD_W | BPF_IND:
		op = op_table[BPF_LD_W];
		fmt = "[x + %d]";
		break;
	case BPF_LD_H | BPF_IND:
		op = op_table[BPF_LD_H];
		fmt = "[x + %d]";
		break;
	case BPF_LD_B | BPF_IND:
		op = op_table[BPF_LD_B];
		fmt = "[x + %d]";
		break;
	case BPF_LD | BPF_IMM:
		op = op_table[BPF_LD_W];
		fmt = "#0x%x";
		break;
	case BPF_LDX | BPF_IMM:
		op = op_table[BPF_LDX];
		fmt = "#0x%x";
		break;
	case BPF_LDX_B | BPF_MSH:
		op = op_table[BPF_LDX_B];
		fmt = "4*([%d]&0xf)";
		break;
	case BPF_LD | BPF_MEM:
		op = op_table[BPF_LD_W];
		fmt = "M[%d]";
		break;
	case BPF_LDX | BPF_MEM:
		op = op_table[BPF_LDX];
		fmt = "M[%d]";
		break;
	case BPF_ST:
		op = op_table[BPF_ST];
		fmt = "M[%d]";
		break;
	case BPF_STX:
		op = op_table[BPF_STX];
		fmt = "M[%d]";
		break;
	case BPF_JMP_JA:
		op = op_table[BPF_JMP_JA];
		fmt = "%d";
		v = n + 1 + bpf.k;
		break;
	case BPF_JMP_JGT | BPF_K:
		op = op_table[BPF_JMP_JGT];
		fmt = "#0x%x";
		break;
	case BPF_JMP_JGE | BPF_K:
		op = op_table[BPF_JMP_JGE];
		fmt = "#0x%x";
		break;
	case BPF_JMP_JEQ | BPF_K:
		op = op_table[BPF_JMP_JEQ];
		fmt = "#0x%x";
		break;
	case BPF_JMP_JSET | BPF_K:
		op = op_table[BPF_JMP_JSET];
		fmt = "#0x%x";
		break;
	case BPF_JMP_JGT | BPF_X:
		op = op_table[BPF_JMP_JGT];
		fmt = "x";
		break;
	case BPF_JMP_JGE | BPF_X:
		op = op_table[BPF_JMP_JGE];
		fmt = "x";
		break;
	case BPF_JMP_JEQ | BPF_X:
		op = op_table[BPF_JMP_JEQ];
		fmt = "x";
		break;
	case BPF_JMP_JSET | BPF_X:
		op = op_table[BPF_JMP_JSET];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_X:
		op = op_table[BPF_ALU_ADD];
		fmt = "x";
		break;
	case BPF_ALU_SUB | BPF_X:
		op = op_table[BPF_ALU_SUB];
		fmt = "x";
		break;
	case BPF_ALU_MUL | BPF_X:
		op = op_table[BPF_ALU_MUL];
		fmt = "x";
		break;
	case BPF_ALU_DIV | BPF_X:
		op = op_table[BPF_ALU_DIV];
		fmt = "x";
		break;
	case BPF_ALU_MOD | BPF_X:
		op = op_table[BPF_ALU_MOD];
		fmt = "x";
		break;
	case BPF_ALU_AND | BPF_X:
		op = op_table[BPF_ALU_AND];
		fmt = "x";
		break;
	case BPF_ALU_OR | BPF_X:
		op = op_table[BPF_ALU_OR];
		fmt = "x";
		break;
	case BPF_ALU_XOR | BPF_X:
		op = op_table[BPF_ALU_XOR];
		fmt = "x";
		break;
	case BPF_ALU_LSH | BPF_X:
		op = op_table[BPF_ALU_LSH];
		fmt = "x";
		break;
	case BPF_ALU_RSH | BPF_X:
		op = op_table[BPF_ALU_RSH];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_K:
		op = op_table[BPF_ALU_ADD];
		fmt = "#%d";
		break;
	case BPF_ALU_SUB | BPF_K:
		op = op_table[BPF_ALU_SUB];
		fmt = "#%d";
		break;
	case BPF_ALU_MUL | BPF_K:
		op = op_table[BPF_ALU_MUL];
		fmt = "#%d";
		break;
	case BPF_ALU_DIV | BPF_K:
		op = op_table[BPF_ALU_DIV];
		fmt = "#%d";
		break;
	case BPF_ALU_MOD | BPF_K:
		op = op_table[BPF_ALU_MOD];
		fmt = "#%d";
		break;
	case BPF_ALU_AND | BPF_K:
		op = op_table[BPF_ALU_AND];
		fmt = "#0x%x";
		break;
	case BPF_ALU_OR | BPF_K:
		op = op_table[BPF_ALU_OR];
		fmt = "#0x%x";
		break;
	case BPF_ALU_XOR | BPF_K:
		op = op_table[BPF_ALU_XOR];
		fmt = "#0x%x";
		break;
	case BPF_ALU_LSH | BPF_K:
		op = op_table[BPF_ALU_LSH];
		fmt = "#%d";
		break;
	case BPF_ALU_RSH | BPF_K:
		op = op_table[BPF_ALU_RSH];
		fmt = "#%d";
		break;
	case BPF_ALU_NEG:
		op = op_table[BPF_ALU_NEG];
		fmt = "";
		break;
	case BPF_MISC_TAX:
		op = op_table[BPF_MISC_TAX];
		fmt = "";
		break;
	case BPF_MISC_TXA:
		op = op_table[BPF_MISC_TXA];
		fmt = "";
		break;
	}

	snprintf(operand, sizeof(operand), fmt, v);
	snprintf(image, sizeof(image),
			 (BPF_CLASS(bpf.code) == BPF_JMP &&
			  BPF_OP(bpf.code) != BPF_JA) ?
			 " L%d: %s %s, L%d, L%d" : " L%d: %s %s",
			 n, op, operand, n + 1 + bpf.jt, n + 1 + bpf.jf);
	return image;
}

void bpf_dump(struct sock_filter *bpf, int count)
{
	int i;

	for (i = 0; i < count; ++i)
		printf("%s\n", __bpf_dump(bpf[i], i));
}
