%{
//nolint
package trace2syz

import (
    //"fmt"
)
%}

%start syscall

%union {
    data string
    val_int int64
    val_double float64
    val_uint uint64
    val_field *field
    val_call *call
    val_macro *macroType
    val_int_type *intType
    val_identifiers []*bufferType
    val_buf_type *bufferType
    val_struct_type *structType
    val_array_type *arrayType
    val_pointer_type *pointerType
    val_flag_type *flagType
    val_type irType
    val_ip_type *ipType
    val_types []irType
    val_parenthetical *parenthetical
    val_syscall *Syscall
}

%token <data> STRING_LITERAL IPV4 IPV6 IDENTIFIER FLAG DATETIME SIGNAL_PLUS SIGNAL_MINUS MAC
%token <val_int> INT
%token <val_uint> UINT
%token <val_double> DOUBLE
%type <val_field> field_type
%type <val_identifiers> identifiers
%type <val_int_type> int_type
%type <val_buf_type> buf_type
%type <val_struct_type> struct_type
%type <val_array_type> array_type
%type <val_flag_type> flag_type
%type <val_call> call_type
%type <val_parenthetical> parenthetical, parentheticals
%type <val_macro> macro_type
%type <val_type> type, expr_type, flags, ints
%type <val_pointer_type> pointer_type
%type <val_ip_type> ip_type
%type <val_types> types
%type <val_syscall> syscall

%token STRING_LITERAL IPV4 IPV6 MAC IDENTIFIER FLAG INT UINT QUESTION DOUBLE ARROW
%token OR AND LOR TIMES LAND LEQUAL ONESCOMP LSHIFT RSHIFT TIMES NOT
%token COMMA LBRACKET RBRACKET LBRACKET_SQUARE RBRACKET_SQUARE LPAREN RPAREN EQUALS
%token UNFINISHED RESUMED
%token SIGNAL_PLUS SIGNAL_MINUS NULL AT COLON KEYWORD

%nonassoc NOTYPE
%nonassoc FLAG
%nonassoc NOFLAG

%nonassoc EQUAL
%nonassoc ARROW

%left LOR
%left LAND
%left OR
%left AND
%left LEQUAL
%left LSHIFT RSHIFT
%left TIMES
%left ONESCOMP

%%
syscall:
    IDENTIFIER LPAREN UNFINISHED %prec NOFLAG { $$ = NewSyscall(-1, $1, nil, int64(-1), true, false);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | IDENTIFIER LPAREN types UNFINISHED %prec NOFLAG { $$ = NewSyscall(-1, $1, $3, int64(-1), true, false);
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
    | RESUMED RPAREN EQUALS INT %prec NOFLAG { $$ = NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED RPAREN EQUALS UINT %prec NOFLAG { $$ = NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED RPAREN EQUALS QUESTION %prec NOFLAG { $$ = NewSyscall(-1, "tmp", nil, -1, false, true);
                                                              Stracelex.(*Stracelexer).result = $$ }
    | RESUMED RPAREN EQUALS INT LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED RPAREN EQUALS UINT LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED RPAREN EQUALS INT FLAG LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                            Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS INT %prec NOFLAG { $$ = NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS UINT %prec NOFLAG { $$ = NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS QUESTION %prec NOFLAG { $$ = NewSyscall(-1, "tmp", $2, -1, false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS INT LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS UINT LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                        Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS UINT FLAG LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                            Stracelex.(*Stracelexer).result = $$ }
    | RESUMED types RPAREN EQUALS INT FLAG LPAREN parentheticals RPAREN { $$ = NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                            Stracelex.(*Stracelexer).result = $$ }
    | IDENTIFIER LPAREN RPAREN EQUALS INT %prec NOFLAG { $$ = NewSyscall(-1, $1, nil, $5, false, false);
                                                            Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN RPAREN EQUALS UINT %prec NOFLAG { $$ = NewSyscall(-1, $1, nil, int64($5), false, false);
                                                                Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS INT %prec NOFLAG{
                                                        $$ = NewSyscall(-1, $1, $3, $6, false, false);
                                                        Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS UINT %prec NOFLAG {
                                                        $$ = NewSyscall(-1, $1, $3, int64($6), false, false);
                                                        Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS QUESTION %prec NOFLAG {
                                                            $$ = NewSyscall(-1, $1, $3, -1, false, false);
                                                            Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS INT FLAG LPAREN parentheticals RPAREN {
                                                              $$ = NewSyscall(-1, $1, $3, $6, false, false);
                                                              Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS UINT FLAG LPAREN parentheticals RPAREN {
                                                              $$ = NewSyscall(-1, $1, $3, int64($6), false, false);
                                                              Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS INT LPAREN parentheticals RPAREN {
                                                                  $$ = NewSyscall(-1, $1, $3, $6, false, false);
                                                                  Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS UINT LPAREN parentheticals RPAREN {
                                                                  $$ = NewSyscall(-1, $1, $3, int64($6), false, false);
                                                                  Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN RPAREN EQUALS INT FLAG LPAREN parentheticals RPAREN {
                                                                      $$ = NewSyscall(-1, $1, nil, $5, false, false);
                                                                      Stracelex.(*Stracelexer).result = $$;}
    | IDENTIFIER LPAREN RPAREN EQUALS UINT FLAG LPAREN parentheticals RPAREN {
                                                                      $$ = NewSyscall(-1, $1, nil, int64($5), false, false);
                                                                      Stracelex.(*Stracelexer).result = $$;}
    | INT syscall {call := $2; call.Pid = $1; Stracelex.(*Stracelexer).result = call}

parentheticals:
    parenthetical {$$ = newParenthetical();}
    | parentheticals parenthetical {$$ = newParenthetical();}

parenthetical:
    COMMA {$$=newParenthetical();}
    | OR {$$ = newParenthetical();}
    | AND {$$ = newParenthetical();}
    | LSHIFT {$$ = newParenthetical();}
    | RSHIFT {$$ = newParenthetical();}
    | IDENTIFIER {$$ = newParenthetical();}
    | struct_type {$$ = newParenthetical();}
    | array_type {$$ = newParenthetical();}
    | flag_type {$$ = newParenthetical();}
    | int_type {$$ = newParenthetical();}


types:
    type {types := make([]irType, 0); types = append(types, $1); $$ = types;}
    | types COMMA type {$1 = append($1, $3); $$ = $1;}


type:
    buf_type {$$ = $1}
    | field_type {$$ = $1}
    | pointer_type {$$ = $1}
    | array_type {$$ = $1}
    | struct_type {$$ = $1}
    | call_type {$$ = $1}
    | ip_type {$$ = $1}
    | expr_type {$$ = $1}
    | expr_type ARROW type {$$ = newDynamicType($1, $3)}
    | ONESCOMP array_type {$$ = $2}


expr_type:
    flags {$$ = newExpression($1)}
    | ints {$$ = newExpression($1)}
    | macro_type {$$ = newExpression($1)}
    | expr_type OR expr_type {$$ = newExpression(newBinop($1, ORop, $3))}
    | expr_type AND expr_type {$$ = newExpression(newBinop($1, ANDop, $3))}
    | expr_type LSHIFT expr_type {$$ = newExpression(newBinop($1, LSHIFTop, $3))}
    | expr_type RSHIFT expr_type {$$ = newExpression(newBinop($1, RSHIFTop, $3))}
    | expr_type LOR expr_type {$$ = newExpression(newBinop($1, LORop, $3))}
    | expr_type LAND expr_type {$$ = newExpression(newBinop($1, LANDop, $3))}
    | expr_type LEQUAL expr_type {$$ = newExpression(newBinop($1, LEQUALop, $3))}
    | LPAREN expr_type RPAREN {$$ = $2}
    | expr_type TIMES expr_type {$$ = newExpression(newBinop($1, TIMESop, $3))}
    | ONESCOMP expr_type {$$ = newExpression(newUnop($2, ONESCOMPop))}

ints:
    int_type {i := make(ints, 1); i[0] = $1; $$ = i}
    | ints int_type {$$ = append($1.(ints), $2)}

flags:
    flag_type {f := make(flags, 1); f[0] = $1; $$ = f}
    | flags flag_type {$$ = append($1.(flags), $2)}

call_type:
    IDENTIFIER LPAREN types RPAREN {$$ = newCallType($1, $3)}

macro_type:
    FLAG LPAREN types RPAREN {$$ = newMacroType($1, $3)}
    | FLAG LPAREN identifiers RPAREN {$$ = newMacroType($1, nil)}
    | KEYWORD LPAREN KEYWORD IDENTIFIER RPAREN {$$ = newMacroType($4, nil)}

pointer_type:
    AND IDENTIFIER {$$ = nullPointer()}
    | AND UINT EQUALS type {$$ = newPointerType($2, $4)}
    | NULL {$$ = nullPointer()}

array_type:
    LBRACKET_SQUARE types RBRACKET_SQUARE {arr := newArrayType($2); $$ = arr}
    | LBRACKET_SQUARE RBRACKET_SQUARE {arr := newArrayType(nil); $$ = arr}

struct_type:
    LBRACKET types RBRACKET {$$ = newStructType($2)}
    | LBRACKET types COMMA RBRACKET {$$ = newStructType($2)}
    | LBRACKET RBRACKET {$$ = newStructType(nil)}

field_type:
     IDENTIFIER EQUALS %prec NOTYPE {$$ = newField($1, nil);}
    | IDENTIFIER EQUALS type {$$ = newField($1, $3);}
    | IDENTIFIER COLON type {$$ = newField($1, $3);}
    | IDENTIFIER EQUALS AT type {$$ = newField($1, $4);}
    | IDENTIFIER LBRACKET_SQUARE FLAG RBRACKET_SQUARE EQUALS type {$$ = newField($1, $6)}

buf_type:
    STRING_LITERAL {$$ = newBufferType($1)}
    | DATETIME {$$ = newBufferType($1)}


int_type:
      INT {$$ = newIntType($1)}
      | UINT {$$ = newIntType(int64($1))}

flag_type:
      FLAG {$$ = newFlagType($1)}

ip_type:
    IPV4 {$$ = newIPType($1)}
    | IPV6 {$$ = newIPType($1)}
    | MAC {$$ = newIPType($1)}

identifiers:
    IDENTIFIER {ids := make([]*bufferType, 0); ids = append(ids, newBufferType($1)); $$ = ids}
    | IDENTIFIER identifiers {$2 = append($2, newBufferType($1)); $$ = $2}

