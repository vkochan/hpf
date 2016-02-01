/*
 * lexer.l	token scanner
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vadim Kochan <vadim4j@gmail.com>
 */

%option noyywrap nodefault yylineno

%{
#include <stdio.h>

#include "compiler.h"
#include "parser.h"
%}

%%

":" |
"!" |
"^" |
"&" |
"|" |
"+" |
"-" |
"*" |
"/" |
"#" |
"[" |
"]" |
"(" |
")"      					{ return yytext[0]; }

">"						{ yylval.op = OP_GR; return CMP; }
"<"						{ yylval.op = OP_LE; return CMP; }
"=="						{ yylval.op = OP_EQ; return CMP; }
"!=" 						{ yylval.op = OP_NEQ; return CMP; }
">="						{ yylval.op = OP_GEQ; return CMP; }
"<="						{ yylval.op = OP_LEQ; return CMP; } 
"&&" |
"and"						{ return LAND; }
"||" |
"or"						{ return LOR; }
"<<"						{ return LSH; }
">>"						{ return RSH; }
[ \r\n\t]					;
([0-9]+|(0X|0x)[0-9A-Fa-f]+)			{
						  yylval.value = strtol(yytext, NULL, 0);
					          if (errno != ERANGE)
						  	return NUMBER;

						  fprintf(stderr, "Wrong number (%s)\n", yytext);
						  return -1;
						}
[A-Za-z0-9]([-_.A-Za-z0-9]*[.A-Za-z0-9])?	{ yylval.name = strdup(yytext); return NAME; }

%%
