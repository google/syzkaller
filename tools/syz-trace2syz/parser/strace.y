%{
// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !codeanalysis

package parser

%}

%start syscall

%union {
    data string
    val_int int64
    val_double float64
    val_ret_type int64
    val_uint uint64
    val_constant Constant
    val_identifiers []*BufferType
    val_buf_type *BufferType
    val_group_type *GroupType
    val_type IrType
    val_types []IrType
    val_syscall *Syscall
}

%token <data> STRING_LITERAL IPV6 IDENTIFIER FLAG DATETIME SIGNAL_PLUS SIGNAL_MINUS MAC
%token <val_int> INT
%token <val_uint> UINT
%token <val_double> DOUBLE
%type <val_ret_type> ret_type
%type <val_buf_type> buf_type
%type <val_group_type> group_type
%type <val_constant> constant
%type <val_type> parenthetical, parentheticals, type, field_type
%type <val_types> types
%type <val_syscall> syscall

%token STRING_LITERAL MAC IDENTIFIER FLAG INT UINT QUESTION DOUBLE ARROW
%token OR AND LOR TIMES LAND LEQUAL ONESCOMP LSHIFT RSHIFT TIMES NOT MINUS PLUS
%token COMMA LBRACKET RBRACKET LBRACKET_SQUARE RBRACKET_SQUARE LPAREN RPAREN EQUALS
%token UNFINISHED RESUMED
%token SIGNAL_PLUS SIGNAL_MINUS NULL EQUALAT COLON FORWARDSLASH

%nonassoc LOWEST
%nonassoc NOFLAG
%nonassoc LBRACKET_SQUARE

%left OR
%left AND
%left LSHIFT RSHIFT
%left PLUS
%left MINUS
%left TIMES
%right NEG ONESCOMP
%left COLON
%left ARROW
%left EQUALS
%left EQUALAT
%%
syscall:
    IDENTIFIER LPAREN types UNFINISHED %prec NOFLAG { $$ = NewSyscall(-1, $1, $3, int64(-1), true, false);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED UNFINISHED RPAREN EQUALS QUESTION %prec NOFLAG
        {
            $$ = NewSyscall(-1, "tmp", nil, -1, true, true);
            Stracelex.(*Stracelexer).result = $$
        }
    | IDENTIFIER LPAREN RESUMED RPAREN EQUALS INT %prec NOFLAG
        {
            $$ = NewSyscall(-1, $1, nil, int64($6), false, false);
            Stracelex.(*Stracelexer).result = $$
        }

    | RESUMED types RPAREN EQUALS ret_type %prec NOFLAG { $$ = NewSyscall(-1, "tmp", $2, $5, false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS QUESTION %prec NOFLAG { $$ = NewSyscall(-1, "tmp", $2, -1, false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS ret_type LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", $2, $5, false, true);
                                                            Stracelex.(*Stracelexer).result = $$ }

    | RESUMED types RPAREN EQUALS ret_type FLAG LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", $2, $5, false, true);
                                                            Stracelex.(*Stracelexer).result = $$ }
    | IDENTIFIER LPAREN types RPAREN EQUALS ret_type %prec NOFLAG{
                                                        $$ = NewSyscall(-1, $1, $3, $6, false, false);
                                                        Stracelex.(*Stracelexer).result = $$}
    | IDENTIFIER LPAREN types RPAREN EQUALS QUESTION %prec NOFLAG {
                                                            $$ = NewSyscall(-1, $1, $3, -1, false, false);
                                                            Stracelex.(*Stracelexer).result = $$}
    | IDENTIFIER LPAREN types RPAREN EQUALS ret_type FLAG LPAREN parentheticals RPAREN {
                                                              $$ = NewSyscall(-1, $1, $3, $6, false, false);
                                                              Stracelex.(*Stracelexer).result = $$}
    | IDENTIFIER LPAREN types RPAREN EQUALS ret_type LPAREN parentheticals RPAREN {
                                                                  $$ = NewSyscall(-1, $1, $3, $6, false, false);
                                                                  Stracelex.(*Stracelexer).result = $$}
    | INT syscall {call := $2; call.Pid = $1; Stracelex.(*Stracelexer).result = call}

parentheticals:
    parenthetical {$$ = nil}
    | parentheticals parenthetical {$$ = nil}

parenthetical:
    COMMA {$$=nil}
    | OR {$$ = nil}
    | AND {$$ = nil}
    | LSHIFT {$$ = nil}
    | RSHIFT {$$ = nil}
    | IDENTIFIER {$$ = nil}
    | FORWARDSLASH {$$ = nil}
    | group_type {$$ = nil}
    | FLAG {$$ = nil}
    | INT {$$ = nil}
    | UINT {$$ = nil}

ret_type:
    INT {$$ = $1}
    | UINT {$$ = int64($1)}
    | MINUS INT {$$ = -1 * $2}

types:
      {$$ = []IrType{}}
    | types COMMA type {$1 = append($1, $3); $$ = $1}
    | types type {$1 = append($1, $2); $$ = $1}

type:
    buf_type {$$ = $1}
    | field_type {$$ = $1}
    | group_type {$$ = $1}
    | constant %prec LOWEST {$$ = $1}
    | ONESCOMP group_type {$$ = $2}

constant:
    INT {$$ = Constant($1)}
    | UINT {$$ = Constant($1)}
    | NULL {$$ = Constant(uint64(0))}
    | constant OR constant {$$ = $1 | $3}
    | constant AND constant {$$ = $1 & $3}
    | constant LSHIFT constant {$$ = $1 << $3}
    | constant RSHIFT constant {$$ = $1 >> $3}
    | LPAREN constant RPAREN {$$ = $2}
    | constant TIMES constant {$$ = $1 * $3}
    | constant MINUS constant {$$ = $1 - $3}
    | constant PLUS constant {$$ = $1 + $3}
    | ONESCOMP constant {$$ = ^$2}
    | MINUS constant %prec NEG {$$ = Constant(-int64($2))}

group_type:
    LBRACKET_SQUARE types RBRACKET_SQUARE {$$ = newGroupType($2)}
    | LBRACKET types RBRACKET {$$ = newGroupType($2)}
    | LBRACKET types COMMA RBRACKET {$$ = newGroupType($2)}

field_type:
    type COLON type {$$ = $3}
    | type EQUALAT type {$$ = $3}
    | type EQUALS type {$$ = $3}
    | type ARROW type {$$ = $1}
    | IDENTIFIER LBRACKET_SQUARE FLAG RBRACKET_SQUARE EQUALS type {$$ = $6}

buf_type:
    STRING_LITERAL {$$ = newBufferType($1)}
    | IDENTIFIER %prec LOWEST {$$ = newBufferType($1)}
    | DATETIME {$$ = newBufferType($1)}
    | MAC {$$ = newBufferType($1)}

