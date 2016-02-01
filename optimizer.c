/*
 * optimizer.c	bpf code optimizer
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

#include "htable.h"
#include "xmalloc.h"
#include "compiler.h"

#include <stdio.h>
#include <string.h>

#define BPF_LD_HASH (BPF_LD | BPF_IMM | BPF_W)

#define INSTR_HTABLE_SIZE	256

static int instr_count;
static bool is_code_modified;

struct regs_info {
	int src[2];
	int dst;
};

struct value {
	int32_t value;
	bool is_const;
};

struct value_instr {
	struct hentry hlist;
	int code;
	int arg0;
	int arg1;
	int value_idx;
};

static int max_values;
static int values_counter;

static struct value *values;
static struct value_instr *value_instrs;
static struct value_instr *value_instrs_new;
static struct htable *instrs;

static inline unsigned int instr_hash(int code, int arg0, int arg1)
{
    unsigned h = 0;

    h += code;
    h += (h << 10);
    h ^= (h >> 6);

    h += arg0;
    h += (h << 10);
    h ^= (h >> 6);

    h += arg1;
    h += (h << 10);
    h ^= (h >> 6);

    h += (h << 3);
    h ^= (h >> 11);
    h += (h << 15);

    return h;
}

static inline int value_new(void)
{
	return ++values_counter;
}

static void blocks_init(void)
{
	values_counter = 0;
	htable_reset(instrs);
	memset(values, 0, max_values * 3 * sizeof(struct value));
	memset(value_instrs, 0, max_values * 3 * sizeof(struct value_instr));
}

static void block_uninit(void)
{
}

static void instr_regs_info(struct instr *ins, struct regs_info *regs)
{
	regs->src[0] = regs->src[1] = regs->dst = -1;

	switch (BPF_CLASS(ins->code)) {
	case BPF_RET:
		if (BPF_RVAL(ins->code) == BPF_A)
			regs->src[0] = REG_A;
		else if (BPF_RVAL(ins->code) == BPF_X)
			regs->src[0] = REG_X;
		break;

	case BPF_LD:
		regs->dst = REG_A;
	case BPF_LDX:
		regs->dst = regs->dst < 0 ? REG_X : REG_A;

		if (BPF_MODE(ins->code) == BPF_IND)
			regs->src[0] = REG_X;
		else if (BPF_MODE(ins->code) == BPF_MEM)
			regs->src[0] = ins->k;
		break;

	case BPF_ST:
		regs->src[0] = REG_A;
		regs->dst = ins->k;
		break;
	case BPF_STX:
		regs->src[0] = REG_X;
		regs->dst = ins->k;
		break;

	case BPF_ALU:
		regs->dst = REG_A;
	case BPF_JMP:
		if (BPF_SRC(ins->code) == BPF_X) {
			regs->src[0] = REG_A;
			regs->src[1] = REG_X;
		} else {
			regs->src[0] = REG_A;
		}
		break;

	case BPF_MISC:
		if (BPF_MISCOP(ins->code) == BPF_TXA)
			regs->src[0] = REG_X;
		else
			regs->src[0] = REG_A;

		if (BPF_MISCOP(ins->code) == BPF_TAX)
			regs->dst = REG_X;
		else
			regs->dst = REG_A;
		break;
	}
}

static inline void instr_set_optimized(struct instr *ins)
{
	if (ins->is_optimized)
		return;

	instr_count--;
	is_code_modified = true;
	ins->is_optimized = true;
}

static inline void instr_modify(struct instr *ins,
		int code, int jt, int jf, int k)
{
	ins->code = code;
	ins->jt = jt > 0 ? jt : ins->jt;
	ins->jf = jf > 0 ? jf : ins->jf;
	ins->k = k;

	is_code_modified = true;
}

static int instr_eval(int code, int arg0, int arg1)
{
	unsigned int hash = instr_hash(code, arg0, arg1);
	struct value_instr *found;
	struct value_instr *new;
	struct hentry *entry;

	if ((entry = htable_find(instrs, hash))) {
		found = container_of(entry, struct value_instr, hlist);
		return found->value_idx;
	}

	new = value_instrs_new++;
	new->value_idx = value_new();
	new->code = code;
	new->arg0 = arg0;
	new->arg1 = arg1;

	htable_insert(instrs, &new->hlist, hash);

	return new->value_idx;
}

/* static inline bool instr_has_const(struct instr *ins) */
/* { */
/* 	if (BPF_MODE(ins->code) == BPF_IMM) { */
/* 		if (BPF_MODE(ins->code) == BPF_LD) */
/* 			return true; */
/* 		if (BPF_MODE(ins->code) == BPF_LDX) */
/* 			return true; */
/* 	} */

/* 	return false; */
/* } */

static inline void value_set(int idx, int32_t value)
{
	values[idx].value = value;
	values[idx].is_const = true;
}

static inline bool value_is_const(int idx)
{
	return values[idx].is_const;
}

static inline int32_t value_get(int idx)
{
	return values[idx].value;
}

static void optimize_reg(struct instr *ins, int *reg, int value)
{
	if (*reg == value)
		instr_set_optimized(ins);
	else
		*reg = value;
}

static void instr_calc_value(struct instr *ins, int val_idx0, int val_idx1)
{
	uint32_t val0 = value_get(val_idx0);
	uint32_t val1 = value_get(val_idx1);

	switch (BPF_OP(ins->code)) {
	case BPF_ADD:
		val0 += val1;
		break;

	case BPF_SUB:
		val0 -= val1;
		break;

	case BPF_MUL:
		val0 *= val1;
		break;
	case BPF_DIV:
		if (val1 == 0)
			printf("division by zero");
		val0 /= val1;
		break;

	case BPF_MOD:
		if (val1 == 0)
			printf("modulus by zero");
		val0 %= val1;
		break;

	case BPF_AND:
		val0 &= val1;
		break;

	case BPF_OR:
		val0 |= val1;
		break;

	case BPF_XOR:
		val0 ^= val0;
		break;

	case BPF_LSH:
		val0 <<= val1;
		break;

	case BPF_RSH:
		val0 >>= val1;
		break;
	}

	instr_modify(ins, BPF_LD | BPF_IMM, -1, -1, val0);
}

static void optimize_instr_eval(struct instr *ins, int regs[])
{
	int val_idx;

	if (ins->is_optimized)
		return;

	switch (ins->code) {
	case BPF_LD | BPF_IMM:
		val_idx = instr_eval(BPF_LD_HASH, ins->k, 0);
		optimize_reg(ins, &regs[REG_A], val_idx);
		value_set(val_idx, ins->k);
		break;
	case BPF_LDX | BPF_IMM:
		val_idx = instr_eval(BPF_LD_HASH, ins->k, 0);
		optimize_reg(ins, &regs[REG_X], val_idx);
		value_set(val_idx, ins->k);
		break;
	case BPF_LD | BPF_MEM:
		val_idx = regs[ins->k];

		if (value_is_const(val_idx)) {
			int val = value_get(val_idx);
			instr_modify(ins, BPF_LD | BPF_IMM, -1, -1, val);
		}
		optimize_reg(ins, &regs[REG_A], val_idx);
		break;
	case BPF_LDX | BPF_MEM:
		val_idx = regs[ins->k];

		if (value_is_const(val_idx)) {
			int val = value_get(val_idx);

			instr_modify(ins, BPF_LDX | BPF_IMM, -1, -1, val);
		}
		optimize_reg(ins, &regs[REG_X], val_idx);
		break;
	case BPF_ST:
		optimize_reg(ins, &regs[ins->k], regs[REG_A]);
		break;
	case BPF_STX:
		optimize_reg(ins, &regs[ins->k], regs[REG_X]);
		break;
	case BPF_ALU|BPF_ADD|BPF_K:
	case BPF_ALU|BPF_SUB|BPF_K:
	case BPF_ALU|BPF_MUL|BPF_K:
	case BPF_ALU|BPF_DIV|BPF_K:
	case BPF_ALU|BPF_MOD|BPF_K:
	case BPF_ALU|BPF_AND|BPF_K:
	case BPF_ALU|BPF_OR|BPF_K:
	case BPF_ALU|BPF_XOR|BPF_K:
	case BPF_ALU|BPF_LSH|BPF_K:
	case BPF_ALU|BPF_RSH|BPF_K:
		val_idx = instr_eval(BPF_LD_HASH, ins->k, 0);

		if (value_is_const(regs[REG_A])) {
			instr_calc_value(ins, regs[REG_A], val_idx);
			val_idx = instr_eval(BPF_LD_HASH, ins->k, 0);
			regs[REG_A] = val_idx;
			break;
		}

		regs[REG_A] = instr_eval(ins->code, regs[REG_A], val_idx);
		break;
	case BPF_ALU|BPF_ADD|BPF_X:
	case BPF_ALU|BPF_SUB|BPF_X:
	case BPF_ALU|BPF_MUL|BPF_X:
	case BPF_ALU|BPF_DIV|BPF_X:
	case BPF_ALU|BPF_MOD|BPF_X:
	case BPF_ALU|BPF_AND|BPF_X:
	case BPF_ALU|BPF_OR|BPF_X:
	case BPF_ALU|BPF_XOR|BPF_X:
	case BPF_ALU|BPF_LSH|BPF_X:
	case BPF_ALU|BPF_RSH|BPF_X:
		val_idx = instr_eval(BPF_LD_HASH, ins->k, 0);

		if (value_is_const(regs[REG_X])) {
			if (value_is_const(regs[REG_A])) {
				instr_calc_value(ins, regs[REG_A], regs[REG_X]);
				val_idx = instr_eval(BPF_LD_HASH, ins->k, 0);
				regs[REG_A] = val_idx;
			} else {
				int code = BPF_ALU | BPF_K | BPF_OP(ins->code);

				val_idx = value_get(regs[REG_X]);
				instr_modify(ins, code, -1, -1, val_idx);
				val_idx = instr_eval(BPF_LD_HASH, ins->k, 0);
				regs[REG_A] = instr_eval(ins->code,
						regs[REG_A], val_idx);
			}
			break;
		}
		break;
	case BPF_LD|BPF_ABS|BPF_W:
	case BPF_LD|BPF_ABS|BPF_H:
	case BPF_LD|BPF_ABS|BPF_B:
		val_idx = instr_eval(ins->code, ins->k, 0);
		optimize_reg(ins, &regs[REG_A], val_idx);
		break;
	case BPF_LD|BPF_IND|BPF_W:
	case BPF_LD|BPF_IND|BPF_H:
	case BPF_LD|BPF_IND|BPF_B:
		val_idx = regs[REG_X];

		if (value_is_const(val_idx)) {
			int code = BPF_LD | BPF_ABS | BPF_SIZE(ins->code);
			int offset = ins->k + value_get(val_idx);

			instr_modify(ins, code, -1, -1, offset);
			val_idx = instr_eval(ins->code, ins->k, 0);
		} else {
			val_idx = instr_eval(ins->code, ins->k, val_idx);
		}

		optimize_reg(ins, &regs[REG_A], val_idx);
		break;
	}
}

static void optimize_eval(struct block *blk)
{
	struct list_head *pos;

	list_for_each(pos, &blk->instrs->list) {
		struct instr *ins = container_of(pos, struct instr, list);

		optimize_instr_eval(ins, blk->regs);
	}
}

static void optimize_dead(struct instr *ins, struct instr *regs_instr[])
{
	struct regs_info regs;
	int i;

	if (ins->is_optimized)
		return;

	instr_regs_info(ins, &regs);

	for (i = 0; i < 2; i++)
		if (regs.src[i] >= 0) {
			regs_instr[regs.src[i]] = NULL;
		}

	if (regs.dst >= 0) {
		if (regs_instr[regs.dst])
			instr_set_optimized(regs_instr[regs.dst]);

		regs_instr[regs.dst] = ins;
	}
}

static void optimize_dead_instrs(struct block *blk)
{
	struct instr *regs_instr[REGS_MAX] = { NULL };
	struct list_head *pos;
	int i;

	list_for_each(pos, &blk->instrs->list) {
		struct instr *ins = container_of(pos, struct instr, list);

		optimize_dead(ins, regs_instr);
	}

	if (blk->jmp_instr)
		optimize_dead(blk->jmp_instr, regs_instr);

	for (i = 0; i < REGS_MAX; i++)
		if (regs_instr[i]) {
			instr_set_optimized(regs_instr[i]);
		}
}

static void optimize_block(struct block *blk)
{
	memset(blk->regs, 0, sizeof(blk->regs));

	optimize_eval(blk);
	optimize_dead_instrs(blk);
}

static void optimize_blocks(struct compiler *comp)
{
	struct list_head *pos;

	blocks_init();

	list_for_each(pos, &comp->blocks) {
		struct block *blk = container_of(pos, struct block, list);

		optimize_block(blk);
	}
}

static void optimize_init(void)
{
	values = xmalloc(max_values * 3 * sizeof(struct value));
	value_instrs_new = value_instrs = xmalloc(max_values * 3 *
			sizeof(struct value_instr));
	instrs = htable_alloc(INSTR_HTABLE_SIZE);
}

static void optimize_uninit(void)
{
	xfree(values);
	xfree(value_instrs);
	htable_free(instrs);
}

int optimize(struct compiler *comp)
{
	max_values = instr_count = comp->instr_count;

	optimize_init();

	do {
		is_code_modified = false;
		optimize_blocks(comp);
	} while (is_code_modified);

	optimize_uninit();

	return instr_count;
}
