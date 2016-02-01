#ifndef __COMPILER_H__
#define __COMPILER_H__

#include "list.h"

#include <stdint.h>
#include <stdbool.h>
#include <linux/filter.h>

#define REGS_MEM_MAX	16
#define REG_A		REGS_MEM_MAX
#define REG_X		REG_A + 1
#define REGS_MAX	REG_X + 1

typedef enum {
	OP_NONE	= 0,
	OP_GR,
	OP_LE,
	OP_EQ,
	OP_NEQ,
	OP_GEQ,
	OP_LEQ,
	OP_LAND,
	OP_LOR,
	OP_SUB,
	OP_ADD,
	OP_MUL,
	OP_DIV,
	OP_BAND,
	OP_BOR,
	OP_BXOR,
	OP_LSH,
	OP_RSH,
	OP_FIELD,
	OP_INDX,
} oper_t;

typedef enum {
	T_EXPR = 1,
	T_NUMB = 2,
	T_NAME = 3,
} node_t;

struct instr {
	struct list_head list;
	bool is_optimized;
	uint16_t code;
	uint8_t jt;
	uint8_t jf;
	uint32_t k;
};

struct expr {
	struct instr *instrs;
	int reg;
};

struct jmp_node {
	struct block *target;
};

struct block {
	bool is_reversed;
	struct list_head list;
	int offset;
	struct instr *jmp_instr;
	struct block *root;
	struct instr *instrs;
	struct jmp_node jmp_true;
	struct jmp_node jmp_false;
	int regs[REGS_MAX];
};

struct compiler {
	int instr_count;
	int block_count;
	struct list_head blocks;
	struct block *root_block;
};

struct block *block_build(struct expr *e);
struct block *branch_merge(oper_t op, struct block *l, struct block *r);
struct block *branch_not(struct block *blk);
struct block *branch_build(oper_t op, struct expr *l, struct expr *r);

struct expr *expr_build(oper_t op, struct expr *l, struct expr *r);
struct expr *expr_add(struct expr *l, struct expr *r);
struct expr *expr_sub(struct expr *l, struct expr *r);
struct expr *expr_mul(struct expr *l, struct expr *r);
struct expr *expr_div(struct expr *l, struct expr *r);
struct expr *expr_and(struct expr *l, struct expr *r);
struct expr *expr_or(struct expr *l, struct expr *r);
struct expr *expr_xor(struct expr *l, struct expr *r);
struct expr *expr_lsh(struct expr *l, struct expr *r);
struct expr *expr_rsh(struct expr *l, struct expr *r);
struct expr *expr_offset(struct expr *e, int size);
struct expr *expr_number(unsigned int value);
struct expr *expr_proto(char *name);
struct expr *expr_proto_offset(char *name, struct expr *e);

void parse_filter(char *expr);

int compile_filter(char *expr, struct sock_filter **f, bool do_optimize);
void parse_finish(struct block *blk);

#endif
