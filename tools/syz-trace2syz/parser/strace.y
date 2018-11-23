%{
// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// nolint
package parser

%}

%start syscall

%union {
    data string
    val_int int64
    val_double float64
    val_ret_type int64
    val_uint uint64
    val_call *Call
    val_identifiers []*BufferType
    val_buf_type *BufferType
    val_group_type *GroupType
    val_pointer_type *PointerType
    val_flag_type *flagType
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
%type <val_flag_type> flag_type
%type <val_call> call_type
%type <val_type> parenthetical, parentheticals, type, expr_type, flags, ints, field_type
%type <val_pointer_type> pointer_type
%type <val_types> types
%type <val_syscall> syscall

%token STRING_LITERAL MAC IDENTIFIER FLAG INT UINT QUESTION DOUBLE ARROW
%token OR AND LOR TIMES LAND LEQUAL ONESCOMP LSHIFT RSHIFT TIMES NOT MINUS PLUS
%token COMMA LBRACKET RBRACKET LBRACKET_SQUARE RBRACKET_SQUARE LPAREN RPAREN EQUALS
%token UNFINISHED RESUMED
%token SIGNAL_PLUS SIGNAL_MINUS NULL EQUALAT COLON FORWARDSLASH

%nonassoc NOTYPE
%nonassoc FLAG
%nonassoc NOFLAG

%left LOR
%left LAND
%left OR
%left AND
%left LEQUAL
%left LSHIFT RSHIFT
%left PLUS
%left TIMES
%left MINUS ONESCOMP
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
            Stracelex.(*Stracelexer).result = $$;
        }
    | IDENTIFIER LPAREN RESUMED RPAREN EQUALS INT %prec NOFLAG
        {
            $$ = NewSyscall(-1, $1, nil, int64($6), false, false);
            Stracelex.(*Stracelexer).result = $$;
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
                                                        Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS QUESTION %prec NOFLAG {
                                                            $$ = NewSyscall(-1, $1, $3, -1, false, false);
                                                            Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS ret_type FLAG LPAREN parentheticals RPAREN {
                                                              $$ = NewSyscall(-1, $1, $3, $6, false, false);
                                                              Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS ret_type LPAREN parentheticals RPAREN {
                                                                  $$ = NewSyscall(-1, $1, $3, $6, false, false);
                                                                  Stracelex.(*Stracelexer).result = $$;}
    | INT syscall {call := $2; call.Pid = $1; Stracelex.(*Stracelexer).result = call}

parentheticals:
    parenthetical {$$ = nil;}
    | parentheticals parenthetical {$$ = nil;}

parenthetical:
    COMMA {$$=nil}
    | OR {$$ = nil}
    | AND {$$ = nil}
    | LSHIFT {$$ = nil}
    | RSHIFT {$$ = nil}
    | IDENTIFIER {$$ = nil}
    | FORWARDSLASH {$$ = nil}
    | group_type {$$ = nil}
    | call_type {$$ = nil}
    | flag_type {$$ = nil}
    | INT {$$ = nil}
    | UINT {$$ = nil}


ret_type:
    INT {$$ = $1}
    | UINT {$$ = int64($1)}
    | MINUS INT {$$ = -1 * $2}

types: {$$ = make([]IrType, 0)}
    | type {$$ = []IrType{$1}}
    | types COMMA type {$1 = append($1, $3); $$ = $1;}


type:
    buf_type {$$ = $1}
    | field_type {$$ = $1}
    | pointer_type {$$ = $1}
    | group_type {$$ = $1}
    | expr_type {$$ = $1}
    | ONESCOMP group_type {$$ = $2}


expr_type:
    flags {$$ = $1}
    | ints {$$ = $1}
    | call_type {$$ = $1}
    | expr_type OR expr_type {$$ = newBinop($1, $3, orOp)}
    | expr_type AND expr_type {$$ = newBinop($1, $3, andOp)}
    | expr_type LSHIFT expr_type {$$ = newBinop($1, $3, lshiftOp)}
    | expr_type RSHIFT expr_type {$$ = newBinop($1, $3, rshiftOp)}
    | expr_type LOR expr_type {$$ = newBinop($1, $3, lorOp)}
    | expr_type LAND expr_type {$$ = newBinop($1, $3, landOp)}
    | expr_type LEQUAL expr_type {$$ = newBinop($1, $3, lequalOp)}
    | LPAREN expr_type RPAREN {$$ = $2}
    | expr_type TIMES expr_type {$$ = newBinop($1, $3, timesOp)}
    | expr_type MINUS expr_type {$$ = newBinop($1, $3, minusOp)}
    | expr_type PLUS expr_type {$$ = newBinop($1, $3, plusOp)}
    | ONESCOMP expr_type {$$ = newUnop($2, onescompOp)}
    | MINUS expr_type {$$ = newUnop($2, negOp)}

ints:
    INT {i := make(Ints, 1); i[0] = $1; $$ = i}
    | UINT {i := make(Ints, 1); i[0] = int64($1); $$ = i}
    | ints INT {$$ = append($1.(Ints), $2)}
    | ints UINT {$$ = append($1.(Ints), int64($2))}

flags:
    flag_type {f := make(Flags, 1); f[0] = $1; $$ = f}
    | flags flag_type {$$ = append($1.(Flags), $2)}

call_type:
    IDENTIFIER LPAREN types RPAREN {$$ = newCallType($1, $3)}
    | FLAG LPAREN types RPAREN {$$ = newCallType($1, $3)}
    
pointer_type:
    AND IDENTIFIER {$$ = nullPointer()}
    | AND UINT EQUALS type {$$ = NewPointerType($2, $4)}
    | NULL {$$ = nullPointer()}

group_type:
    LBRACKET_SQUARE types RBRACKET_SQUARE {$$ = newGroupType($2)}
    | LBRACKET types RBRACKET {$$ = newGroupType($2)}
    | LBRACKET types COMMA RBRACKET {$$ = newGroupType($2)}

field_type:
    type EQUALS %prec NOTYPE {$$ = nil}
    | type COLON type {$$ = $3}
    | type EQUALAT type {$$ = $3}
    | type EQUALS type {$$ = $3}
    | type ARROW type {$$ = $1}
    | IDENTIFIER LBRACKET_SQUARE FLAG RBRACKET_SQUARE EQUALS type {$$ = $6}

buf_type:
    STRING_LITERAL {$$ = newBufferType($1)}
    | IDENTIFIER {$$ = newBufferType($1)}
    | DATETIME {$$ = newBufferType($1)}
    | MAC {$$ = newBufferType($1)}


flag_type:
      FLAG {$$ = newFlagType($1)}

