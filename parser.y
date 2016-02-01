/*
 * parser.y	expression syntax parser
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

%error-verbose

%{

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "compiler.h"

void yyerror(const char *s, ...);
void yy_scan_string(char *);
void yylex_destroy();
int yylex(void);

static int offs_size_parse(char *s)
{
	if (!s)
		return 1;

	if (strlen(s) == 1) {
		switch (*s) {
		case '1':
		case 'b':
			return 1;
		case '2':
		case 'h':
			return 2;
		case '4':
		case 'w':
			return 4;
		}

		return 1;
	}

	if (strcmp(s, "byte") == 0)
		return 1;
	else if (strcmp(s, "half") == 0)
		return 2;
	else if (strcmp(s, "word") == 0)
		return 4;

	return 1;
}

%}

%union {
	oper_t op;
	unsigned int value;
	char *name;
	struct block *blk;
	struct expr *exp;
}

%type <blk> stmt
%type <exp> expr

%token <value> NUMBER
%token <name> NAME
%token <op> CMP
%token LAND LOR

%left LOR LAND
%left CMP
%left '|'
%left '^'
%left '&'
%left LSH RSH
%left '+' '-'
%left '*' '/'

%start filter

%%
filter:
      | stmt			{ parse_finish($1); }
;

stmt: expr CMP expr		{ $$ = branch_build($2, $1, $3); }
   | stmt LAND stmt		{ $$ = branch_merge(OP_LAND, $1, $3); }
   | stmt LOR stmt		{ $$ = branch_merge(OP_LOR, $1, $3); }
   | expr			{ $$ = block_build($1); }
;

expr: expr '+' expr		{ $$ = expr_add($1, $3); }
   | expr '-' expr		{ $$ = expr_sub($1, $3); }
   | expr '*' expr		{ $$ = expr_mul($1, $3); }
   | expr '/' expr		{ $$ = expr_div($1, $3); }
   | expr '&' expr		{ $$ = expr_and($1, $3); }
   | expr '|' expr		{ $$ = expr_or($1, $3); }
   | expr '^' expr		{ $$ = expr_xor($1, $3); }
   | expr LSH expr		{ $$ = expr_lsh($1, $3); }
   | expr RSH expr		{ $$ = expr_rsh($1, $3); }
   | '(' expr ')'		{ $$ = $2; }
   | NUMBER			{ $$ = expr_number($1); }
   | '[' expr ']'   		{ $$ = expr_offset($2, 1); }
   | '[' expr ':' NUMBER ']'	{ $$ = expr_offset($2, $4); }
   | '[' expr ':' NAME ']'	{ $$ = expr_offset($2, offs_size_parse($4)); }
   | NAME '[' expr ']'  	{ $$ = expr_proto_offset($1, $3); }
   | NAME			{ $$ = expr_proto($1); }
;

%%

void yyerror(const char *s, ...)
{
	va_list ap;

	va_start(ap, s);
	fprintf(stderr, "error: ");
	vfprintf(stderr, s, ap);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

void parse_filter(char *s)
{
	yy_scan_string(s);
	yyparse();
	yylex_destroy();
}
