/*
 * compiler.c	expression compiler
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

#include <stdio.h>
#include <string.h>

#include "proto.h"
#include "xmalloc.h"
#include "compiler.h"
#include "optimizer.h"

#define dbg(fmt, ...) printf("dbg: " fmt, ##__VA_ARGS__)

static int regs[REGS_MEM_MAX];

static struct block *root_block;

struct sock_filter *code_start;
struct sock_filter *code_end;

static int instr_count;
static int block_count;
static struct list_head blocks;

static inline int reg_get()
{
	int reg = 0;

	for (; reg < REGS_MEM_MAX; reg++) {
		if (!regs[reg]) {
			regs[reg] = 1;
			return reg;
		}
	}

	printf("no free registers\n");
	return -1;
}

static inline void reg_put(uint8_t reg)
{
	regs[reg] = 0;
}

static struct instr *instr_alloc(uint16_t code, uint8_t jt, uint8_t jf,
		uint32_t k)
{
	struct instr *ins = xmalloc(sizeof(struct instr));
	ins->is_optimized = false;
	ins->code = code;
	ins->jt	= jt;
	ins->jf	= jf;
	ins->k = k;

	INIT_LIST_HEAD(&ins->list);

	instr_count++;
	return ins;
}

static void instr_insert(struct instr *list, struct instr *ins)
{
	list_add_tail(&ins->list, &list->list);
}

static void instr_join(struct instr *to, struct instr *from)
{
	list_join_tail(&from->list, &to->list);
}

static struct instr *instr_val_load(uint32_t val)
{
	return instr_alloc(BPF_LD | BPF_IMM, 0, 0, val);
}

static struct instr *instr_store_a_mem(int mem)
{
	return instr_alloc(BPF_ST, 0, 0, mem);
}

static struct instr *instr_load_mem_x(int mem)
{
	return instr_alloc(BPF_LDX | BPF_MEM, 0, 0, mem);
}

static struct instr *instr_load_mem_a(int mem)
{
	return instr_alloc(BPF_LD | BPF_MEM, 0, 0, mem);
}

static struct instr *instr_load_offset(int offset, int size)
{
	int bpf_size = BPF_B;

	if (size == 2)
		bpf_size = BPF_H;
	else if (size == 4)
		bpf_size = BPF_W;

	return instr_alloc(BPF_LD | BPF_IND | bpf_size, 0, 0, offset);
}

static struct instr *instr_alu_x_a(int code)
{
	return instr_alloc(BPF_ALU | BPF_X | code, 0, 0, 0);
}

static int instr_count_calc(struct instr *list)
{
	struct list_head *pos;
	int count = 0;

	list_for_each(pos, &list->list) {
		struct instr *ins = container_of(pos, struct instr, list);
		if (ins->is_optimized)
			continue;

		count++;
	}

	return count;
}

static int oper_to_jmp_code(oper_t op)
{
	int jmp_code;

	switch (op) {
	case OP_LE:
		jmp_code = BPF_JGE;
		break;
	case OP_LEQ:
		jmp_code = BPF_JGT;
		break;
	case OP_EQ:
		jmp_code = BPF_JEQ;
		break;
	case OP_GR:
		jmp_code = BPF_JGT;
		break;
	case OP_GEQ:
		jmp_code = BPF_JGE;
		break;

	default: return 0;
	}

	return BPF_JMP | jmp_code | BPF_X;
}

static int oper_to_bpf_code(oper_t op)
{
	switch (op) {
	case OP_ADD: return BPF_ADD;
	case OP_SUB: return BPF_SUB;
	case OP_MUL: return BPF_MUL;
	case OP_DIV: return BPF_DIV;
	case OP_LSH: return BPF_LSH;
	case OP_RSH: return BPF_RSH;
	case OP_BAND: return BPF_AND;
	case OP_BOR: return BPF_OR;
	}

	return -1;
}

static struct block *block_alloc(void)
{
	struct block *blk = xmalloc(sizeof(struct block));
	memset(blk, 0, sizeof(*blk));

	blk->root = blk;
	blk->instrs = xmalloc(sizeof(struct instr));
	INIT_LIST_HEAD(&blk->instrs->list);
	INIT_LIST_HEAD(&blk->list);
	block_count++;

	if (block_count == 1)
		INIT_LIST_HEAD(&blocks);

	list_add_tail(&blk->list, &blocks);
	return blk;
}

static void block_free(struct block *blk)
{
	if (!blk)
		return;

	xfree(blk);
}

static struct block *build_return(int retcode)
{
	struct block *blk = block_alloc();

	blk->jmp_instr = instr_alloc(BPF_RET | BPF_K, 0, 0, retcode);
	return blk;
}

static struct block *build_drop(void)
{
	return build_return(0);
}

static struct block *build_accept(void)
{
	return build_return(-1);
}

static struct expr *expr_alloc(void)
{
	struct expr *e	= xmalloc(sizeof(struct expr));

	e->instrs = xmalloc(sizeof(struct instr));
	INIT_LIST_HEAD(&e->instrs->list);

	return e;
}

static void backpatch(struct block *l, struct block *r, bool list)
{
	struct block *next;
	struct block *blk = l;

	while (blk) {
		if (list == true) {
			next = blk->jmp_true.target;
			blk->jmp_true.target = r;
		} else {
			next = blk->jmp_false.target;
			blk->jmp_false.target = r;
		}
		blk = next;
	}
}

static void merge(struct block *left, struct block *right, bool list)
{
	struct block *blk = right;
	struct jmp_node *jmp = list == true ? &blk->jmp_true : &blk->jmp_false;

	while (jmp->target) {
		if (list == true)
			jmp = &jmp->target->jmp_true;
		else
			jmp = &jmp->target->jmp_false;
	}
	jmp->target = left;
}

static bool block_has_jmp(struct block *blk, bool jmp_type)
{
	return !!(jmp_type == true ? blk->jmp_true.target :
		blk->jmp_false.target);
}

static int jmp_offset_calc(struct block *blk, int ins_count, bool jmp_type)
{
	struct block *target;

	if (jmp_type == true)
		target = blk->jmp_true.target;
	else
		target = blk->jmp_false.target;

	if (!target)
		return 0;

	return target->offset - (blk->offset + ins_count);
}

struct block *block_build(struct expr *e)
{
	struct block *blk = block_alloc();

	instr_join(blk->instrs, e->instrs);

	xfree(e);
	return blk;
}

struct block *branch_merge(oper_t op, struct block *left, struct block *right)
{
	if (op == OP_LOR) {
		backpatch(left, right, left->is_reversed);
		merge(left, right, !left->is_reversed);
	} if (op == OP_LAND) {
		backpatch(left, right, !left->is_reversed);
		merge(left, right, left->is_reversed);
	}

	right->root = left->root;
	return right;
}

struct block *branch_not(struct block *blk)
{
	blk->is_reversed = !blk->is_reversed;
}

struct block *branch_build(oper_t jmp_op, struct expr *left, struct expr *right)
{
	struct block *blk = block_alloc();

	if (jmp_op == OP_LE || jmp_op == OP_LEQ)
		blk->is_reversed = true;

	blk->jmp_instr = instr_alloc(oper_to_jmp_code(jmp_op), 0, 0, 0);

	instr_join(blk->instrs, left->instrs);
	instr_join(blk->instrs, right->instrs);

	instr_insert(blk->instrs, instr_load_mem_a(left->reg));
	instr_insert(blk->instrs, instr_load_mem_x(right->reg));

	reg_put(left->reg);
	reg_put(right->reg);
	xfree(left);
	xfree(right);

	return blk;
}

struct expr *expr_build(oper_t op, struct expr *left, struct expr *right)
{
	int ret_reg = reg_get();
	int old_reg = left->reg;

	instr_join(left->instrs, right->instrs);

	instr_insert(left->instrs, instr_load_mem_a(left->reg));
	instr_insert(left->instrs, instr_load_mem_x(right->reg));
	instr_insert(left->instrs, instr_alu_x_a(oper_to_bpf_code(op)));
	instr_insert(left->instrs, instr_store_a_mem(ret_reg));

	left->reg = ret_reg;
	reg_put(old_reg);
	reg_put(right->reg);

	xfree(right);
	return left;
}

struct expr *expr_add(struct expr *l, struct expr *r)
{
	return expr_build(OP_ADD, l, r);
}

struct expr *expr_sub(struct expr *l, struct expr *r)
{
	return expr_build(OP_SUB, l, r);
}

struct expr *expr_mul(struct expr *l, struct expr *r)
{
	return expr_build(OP_MUL, l, r);
}

struct expr *expr_div(struct expr *l, struct expr *r)
{
	return expr_build(OP_DIV, l, r);
}

struct expr *expr_and(struct expr *l, struct expr *r)
{
	return expr_build(OP_BAND, l, r);
}

struct expr *expr_or(struct expr *l, struct expr *r)
{
	return expr_build(OP_BOR, l, r);
}

struct expr *expr_xor(struct expr *l, struct expr *r)
{
	return expr_build(OP_BXOR, l, r);
}

struct expr *expr_lsh(struct expr *l, struct expr *r)
{
	return expr_build(OP_LSH, l, r);
}

struct expr *expr_rsh(struct expr *l, struct expr *r)
{
	return expr_build(OP_RSH, l, r);
}

struct expr *expr_offset(struct expr *e, int size)
{
	int ret_reg = reg_get();
	int old_reg = e->reg;

	instr_insert(e->instrs, instr_load_mem_x(e->reg));
	instr_insert(e->instrs, instr_load_offset(0, size));
	instr_insert(e->instrs, instr_store_a_mem(ret_reg));

	reg_put(old_reg);
	e->reg = ret_reg;

	return e;
}

struct expr *expr_number(unsigned int value)
{
	struct expr *e	= expr_alloc();
	e->reg = reg_get();

	instr_insert(e->instrs, instr_val_load((uint32_t)value));
	instr_insert(e->instrs, instr_store_a_mem(e->reg));

	return e;
}

struct expr *expr_proto(char *name)
{
	struct expr *e;
	e = xmalloc(sizeof(struct block));
	return e;
}

struct expr *expr_proto_offset(char *name, struct expr *e)
{
	return expr_build(OP_INDX, expr_proto(name), e);
}

void parse_finish(struct block *blk)
{
	if (!blk)
		printf("parse_finish: input block is NULL\n");

	backpatch(blk, build_accept(), !blk->is_reversed);
	backpatch(blk, build_drop(), blk->is_reversed);

	root_block = blk->root;
	if (!root_block)
		printf("parse_finish: no root\n");
}

static void compile_block(struct block *blk)
{
	struct sock_filter *code;
	struct list_head *pos;
	int ins_count;

	if (!blk || blk->offset)
		return;

	compile_block(blk->jmp_false.target);
	compile_block(blk->jmp_true.target);

	ins_count = instr_count_calc(blk->instrs);
	ins_count += blk->jmp_instr ? 1 : 0;

	code = code_end -= ins_count;
	blk->offset = code - code_start;

	list_for_each(pos, &blk->instrs->list) {
		struct instr *ins = container_of(pos, struct instr, list);

		if (ins->is_optimized)
			continue;

		code->code = ins->code;
		code->jt = ins->jt;
		code->jf = ins->jf;
		code->k = ins->k;
		code++;
	}

	if (!blk->jmp_instr)
		return;

	if (block_has_jmp(blk, true))
		code->jt = jmp_offset_calc(blk, ins_count, true);
	else
		code->jt = blk->jmp_instr->jt;

	if (block_has_jmp(blk, false))
		code->jf = jmp_offset_calc(blk, ins_count, false);
	else
		code->jf = blk->jmp_instr->jf;

	code->code = blk->jmp_instr->code;
	code->k = blk->jmp_instr->k;
}

static void compiler_init(struct compiler *comp)
{
	memset(comp, 0, sizeof(*comp));
	INIT_LIST_HEAD(&comp->blocks);
}

int compile_filter(char *expr, struct sock_filter **filter, bool do_optimize)
{
	struct compiler comp;

	compiler_init(&comp);

	parse_filter(expr);

	if (!root_block)
		return 0;
	if (instr_count == 0)
		return 0;

	comp.instr_count = instr_count;
	comp.block_count = block_count;
	comp.root_block = root_block;
	list_join_tail(&blocks, &comp.blocks);

	if (do_optimize)
		instr_count = optimize(&comp);

	code_start = xmalloc(sizeof(struct sock_filter) * instr_count);
	code_end = code_start + instr_count;

	compile_block(root_block);

	*filter = code_start;
	return instr_count;
}
