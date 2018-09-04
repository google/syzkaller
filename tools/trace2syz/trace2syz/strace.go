//line strace.y:2

//nolint
package trace2syz

import __yyfmt__ "fmt"

//line strace.y:3
import (
//"fmt"
)

//line strace.y:12
type StraceSymType struct {
	yys               int
	data              string
	val_int           int64
	val_double        float64
	val_uint          uint64
	val_field         *field
	val_call          *call
	val_macro         *macroType
	val_int_type      *intType
	val_identifiers   []*bufferType
	val_buf_type      *bufferType
	val_struct_type   *structType
	val_array_type    *arrayType
	val_pointer_type  *pointerType
	val_flag_type     *flagType
	val_type          irType
	val_ip_type       *ipType
	val_types         []irType
	val_parenthetical *parenthetical
	val_syscall       *Syscall
}

const STRING_LITERAL = 57346
const IPV4 = 57347
const IPV6 = 57348
const IDENTIFIER = 57349
const FLAG = 57350
const DATETIME = 57351
const SIGNAL_PLUS = 57352
const SIGNAL_MINUS = 57353
const MAC = 57354
const INT = 57355
const UINT = 57356
const DOUBLE = 57357
const QUESTION = 57358
const ARROW = 57359
const OR = 57360
const AND = 57361
const LOR = 57362
const TIMES = 57363
const LAND = 57364
const LEQUAL = 57365
const ONESCOMP = 57366
const LSHIFT = 57367
const RSHIFT = 57368
const NOT = 57369
const COMMA = 57370
const LBRACKET = 57371
const RBRACKET = 57372
const LBRACKET_SQUARE = 57373
const RBRACKET_SQUARE = 57374
const LPAREN = 57375
const RPAREN = 57376
const EQUALS = 57377
const UNFINISHED = 57378
const RESUMED = 57379
const NULL = 57380
const AT = 57381
const COLON = 57382
const KEYWORD = 57383
const NOTYPE = 57384
const NOFLAG = 57385
const EQUAL = 57386

var StraceToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"STRING_LITERAL",
	"IPV4",
	"IPV6",
	"IDENTIFIER",
	"FLAG",
	"DATETIME",
	"SIGNAL_PLUS",
	"SIGNAL_MINUS",
	"MAC",
	"INT",
	"UINT",
	"DOUBLE",
	"QUESTION",
	"ARROW",
	"OR",
	"AND",
	"LOR",
	"TIMES",
	"LAND",
	"LEQUAL",
	"ONESCOMP",
	"LSHIFT",
	"RSHIFT",
	"NOT",
	"COMMA",
	"LBRACKET",
	"RBRACKET",
	"LBRACKET_SQUARE",
	"RBRACKET_SQUARE",
	"LPAREN",
	"RPAREN",
	"EQUALS",
	"UNFINISHED",
	"RESUMED",
	"NULL",
	"AT",
	"COLON",
	"KEYWORD",
	"NOTYPE",
	"NOFLAG",
	"EQUAL",
}
var StraceStatenames = [...]string{}

const StraceEofCode = 1
const StraceErrCode = 2
const StraceInitialStackSize = 16

//line yacctab:1
var StraceExca = [...]int{
	-1, 1,
	1, -1,
	-2, 0,
}

const StracePrivate = 57344

const StraceLast = 942

var StraceAct = [...]int{

	137, 146, 127, 108, 47, 33, 154, 33, 35, 2,
	77, 8, 76, 37, 38, 4, 110, 41, 109, 63,
	33, 60, 100, 61, 59, 84, 33, 33, 62, 80,
	79, 70, 9, 32, 33, 136, 66, 68, 47, 3,
	47, 36, 128, 45, 125, 155, 120, 126, 78, 33,
	33, 33, 33, 33, 33, 33, 33, 33, 33, 44,
	158, 33, 33, 33, 33, 147, 63, 47, 60, 34,
	61, 34, 95, 46, 173, 62, 33, 106, 156, 171,
	85, 86, 153, 151, 34, 159, 105, 115, 169, 167,
	34, 34, 161, 160, 96, 98, 72, 148, 34, 33,
	116, 47, 33, 157, 33, 101, 56, 152, 150, 75,
	74, 5, 114, 34, 34, 34, 34, 34, 34, 34,
	34, 34, 34, 122, 113, 34, 34, 34, 34, 102,
	121, 103, 133, 123, 135, 85, 134, 163, 49, 50,
	34, 56, 54, 55, 56, 51, 52, 99, 51, 52,
	163, 64, 149, 145, 111, 112, 33, 13, 65, 13,
	71, 130, 131, 34, 132, 163, 34, 163, 34, 163,
	37, 38, 57, 163, 128, 163, 163, 163, 13, 13,
	163, 129, 163, 163, 164, 163, 166, 170, 168, 117,
	118, 16, 119, 172, 1, 174, 175, 176, 12, 39,
	144, 13, 13, 179, 14, 181, 14, 182, 56, 184,
	55, 30, 51, 52, 13, 13, 13, 17, 81, 82,
	34, 83, 29, 31, 15, 14, 14, 10, 13, 11,
	49, 50, 53, 56, 54, 55, 58, 51, 52, 0,
	0, 0, 0, 0, 0, 0, 104, 0, 14, 14,
	73, 13, 49, 50, 13, 56, 13, 55, 0, 51,
	52, 14, 14, 14, 0, 0, 0, 87, 88, 89,
	90, 91, 92, 93, 94, 14, 0, 58, 0, 0,
	19, 26, 27, 21, 35, 20, 0, 0, 28, 37,
	38, 0, 0, 0, 0, 22, 0, 0, 14, 0,
	18, 14, 0, 14, 0, 25, 0, 24, 13, 32,
	43, 0, 40, 42, 23, 0, 0, 36, 0, 19,
	26, 27, 21, 35, 20, 0, 0, 28, 37, 38,
	0, 50, 0, 56, 22, 55, 0, 51, 52, 18,
	0, 0, 0, 0, 25, 0, 24, 0, 32, 7,
	0, 6, 0, 23, 0, 14, 36, 19, 26, 27,
	21, 35, 20, 0, 0, 28, 37, 38, 0, 0,
	0, 0, 22, 0, 0, 0, 0, 18, 0, 0,
	0, 0, 25, 124, 24, 0, 32, 0, 0, 0,
	0, 23, 0, 0, 36, 19, 26, 27, 21, 35,
	20, 0, 0, 28, 37, 38, 0, 0, 0, 0,
	22, 0, 0, 0, 0, 18, 0, 0, 0, 0,
	25, 0, 24, 0, 32, 0, 0, 0, 0, 23,
	97, 0, 36, 19, 26, 27, 21, 35, 20, 0,
	0, 28, 37, 38, 0, 0, 0, 0, 22, 0,
	0, 0, 0, 18, 0, 0, 0, 0, 25, 69,
	24, 0, 32, 0, 0, 0, 0, 23, 0, 0,
	36, 19, 26, 27, 21, 35, 20, 0, 0, 28,
	37, 38, 0, 0, 0, 0, 22, 0, 0, 0,
	0, 18, 0, 0, 0, 0, 25, 0, 24, 67,
	32, 0, 0, 0, 0, 23, 0, 0, 36, 19,
	26, 27, 21, 35, 20, 0, 0, 28, 37, 38,
	0, 0, 0, 0, 22, 0, 0, 0, 0, 18,
	0, 0, 0, 0, 25, 0, 24, 0, 32, 0,
	0, 0, 0, 23, 0, 0, 36, 19, 26, 27,
	107, 35, 20, 0, 35, 28, 37, 38, 0, 37,
	38, 0, 22, 0, 0, 0, 0, 18, 0, 0,
	59, 0, 25, 0, 24, 0, 32, 24, 0, 32,
	0, 23, 143, 71, 36, 0, 0, 36, 37, 38,
	0, 0, 0, 139, 140, 0, 0, 0, 0, 0,
	141, 142, 0, 138, 25, 0, 24, 143, 71, 191,
	0, 0, 0, 37, 38, 0, 0, 0, 139, 140,
	0, 0, 0, 0, 0, 141, 142, 0, 138, 25,
	0, 24, 143, 71, 190, 0, 0, 0, 37, 38,
	0, 0, 0, 139, 140, 0, 0, 0, 0, 0,
	141, 142, 0, 138, 25, 0, 24, 143, 71, 189,
	0, 0, 0, 37, 38, 0, 0, 0, 139, 140,
	0, 0, 0, 0, 0, 141, 142, 0, 138, 25,
	0, 24, 143, 71, 188, 0, 0, 0, 37, 38,
	0, 0, 0, 139, 140, 0, 0, 0, 0, 0,
	141, 142, 0, 138, 25, 0, 24, 143, 71, 187,
	0, 0, 0, 37, 38, 0, 0, 0, 139, 140,
	0, 0, 0, 0, 0, 141, 142, 0, 138, 25,
	0, 24, 143, 71, 186, 0, 0, 0, 37, 38,
	0, 0, 0, 139, 140, 0, 0, 0, 0, 0,
	141, 142, 0, 138, 25, 0, 24, 143, 71, 185,
	0, 0, 0, 37, 38, 0, 0, 0, 139, 140,
	0, 0, 0, 0, 0, 141, 142, 0, 138, 25,
	0, 24, 143, 71, 183, 0, 0, 0, 37, 38,
	0, 0, 0, 139, 140, 0, 0, 0, 0, 0,
	141, 142, 0, 138, 25, 0, 24, 143, 71, 180,
	0, 0, 0, 37, 38, 0, 0, 0, 139, 140,
	0, 0, 0, 0, 0, 141, 142, 0, 138, 25,
	0, 24, 143, 71, 178, 0, 0, 0, 37, 38,
	0, 0, 0, 139, 140, 0, 0, 0, 0, 0,
	141, 142, 0, 138, 25, 0, 24, 143, 71, 177,
	0, 0, 0, 37, 38, 0, 0, 0, 139, 140,
	0, 0, 0, 0, 0, 141, 142, 0, 138, 25,
	0, 24, 143, 71, 165, 0, 0, 0, 37, 38,
	0, 0, 0, 139, 140, 0, 0, 0, 0, 0,
	141, 142, 0, 138, 25, 0, 24, 143, 71, 162,
	0, 0, 0, 37, 38, 0, 0, 0, 139, 140,
	0, 0, 0, 0, 0, 141, 142, 0, 138, 25,
	0, 24, 48, 49, 50, 53, 56, 54, 55, 0,
	51, 52,
}
var StracePact = [...]int{

	2, -1000, 78, 315, 2, 276, 25, 8, 39, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, 915, 546, -1000,
	-1000, -12, 144, -1000, 467, 429, -1000, -1000, -1000, 152,
	157, -1000, 0, -1000, -1000, 77, 76, -1000, -1000, -1000,
	-1000, -24, 14, -5, -6, 205, -10, 505, 505, 0,
	0, 0, 0, 0, 0, 0, 0, -1000, -1000, 0,
	505, 391, 505, 139, -1000, -13, 73, -1000, 101, -1000,
	-1000, -1000, -1000, 212, 543, -38, -1000, -17, -19, 141,
	108, 79, 67, -1000, 176, -1000, -1000, 312, 187, 85,
	85, 120, 234, 123, -1000, 12, -1000, 505, -1000, 91,
	505, -1000, 353, -1000, -1000, 10, 13, 35, 174, 148,
	119, 128, 126, -1000, 900, 64, 900, 75, 74, -1000,
	-1000, -1000, -29, -1000, -1000, -1000, -1000, -1000, 167, 11,
	70, 52, -1000, -1000, 60, 59, 875, -1000, -1000, -1000,
	-1000, -1000, -1000, -1000, -1000, -1000, -1000, -1000, 900, 850,
	900, 56, 900, 55, 505, -1000, 46, 900, 41, 900,
	900, 900, -1000, -1000, 825, -1000, 800, 900, 775, 900,
	-1000, 900, 750, 900, 725, 700, 675, -1000, -1000, 650,
	-1000, 625, 600, -1000, 575, -1000, -1000, -1000, -1000, -1000,
	-1000, -1000,
}
var StracePgo = [...]int{

	0, 194, 229, 2, 65, 227, 200, 153, 1, 224,
	0, 35, 223, 32, 217, 222, 211, 198, 191, 11,
}
var StraceR1 = [...]int{

	0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	11, 11, 10, 10, 10, 10, 10, 10, 10, 10,
	10, 10, 19, 19, 13, 13, 13, 13, 13, 13,
	13, 13, 13, 13, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 16, 16, 15,
	15, 9, 12, 12, 12, 17, 17, 17, 7, 7,
	6, 6, 6, 2, 2, 2, 2, 2, 5, 5,
	4, 4, 8, 18, 18, 18, 3, 3,
}
var StraceR2 = [...]int{

	0, 3, 4, 5, 6, 4, 4, 4, 7, 7,
	8, 5, 5, 5, 8, 8, 9, 9, 5, 5,
	6, 6, 6, 10, 10, 9, 9, 9, 9, 2,
	1, 2, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 3, 1, 1, 1, 1, 1, 1,
	1, 1, 3, 2, 1, 1, 1, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 2, 1, 2, 1,
	2, 4, 4, 4, 5, 2, 4, 1, 3, 2,
	3, 4, 2, 2, 3, 3, 4, 6, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 2,
}
var StraceChk = [...]int{

	-1000, -1, 7, 37, 13, 33, 36, 34, -19, -13,
	-5, -2, -17, -7, -6, -9, -18, -14, 24, 4,
	9, 7, 19, 38, 31, 29, 5, 6, 12, -15,
	-16, -12, 33, -8, -4, 8, 41, 13, 14, -1,
	36, -19, 37, 34, 34, 35, 34, 28, 17, 18,
	19, 25, 26, 20, 22, 23, 21, -7, -14, 24,
	33, 35, 40, 31, 7, 14, -19, 32, -19, 30,
	-8, 8, -4, -14, 33, 33, 36, 34, 34, 35,
	35, 13, 14, 16, 35, -13, -13, -14, -14, -14,
	-14, -14, -14, -14, -14, -19, -13, 39, -13, 8,
	35, 32, 28, 30, 34, -19, -3, 7, 41, 35,
	35, 13, 14, 16, 33, 8, 33, 13, 14, 16,
	34, -13, 32, -13, 30, 34, 34, -3, 7, 7,
	13, 14, 16, 13, 8, 8, -11, -10, 28, 18,
	19, 25, 26, 7, -6, -7, -8, -4, 33, -11,
	33, 8, 33, 8, 35, 34, 8, 33, 8, 33,
	33, 33, 34, -10, -11, 34, -11, 33, -11, 33,
	-13, 33, -11, 33, -11, -11, -11, 34, 34, -11,
	34, -11, -11, 34, -11, 34, 34, 34, 34, 34,
	34, 34,
}
var StraceDef = [...]int{

	0, -2, 0, 0, 0, 0, 0, 0, 0, 42,
	44, 45, 46, 47, 48, 49, 50, 51, 0, 88,
	89, 0, 0, 77, 0, 0, 93, 94, 95, 54,
	55, 56, 0, 69, 67, 92, 0, 90, 91, 29,
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 53, 66, 0,
	0, 83, 0, 0, 75, 0, 0, 79, 0, 82,
	70, 92, 68, 0, 0, 0, 2, 0, 0, 0,
	0, 5, 6, 7, 0, 43, 52, 57, 58, 59,
	60, 61, 62, 63, 65, 0, 84, 0, 85, 0,
	0, 78, 0, 80, 64, 0, 0, 96, 0, 0,
	0, 18, 19, 3, 0, 0, 0, 11, 12, 13,
	71, 86, 0, 76, 81, 72, 73, 97, 96, 0,
	20, 21, 22, 4, 0, 0, 0, 30, 32, 33,
	34, 35, 36, 37, 38, 39, 40, 41, 0, 0,
	0, 0, 0, 0, 0, 74, 0, 0, 0, 0,
	0, 0, 8, 31, 0, 9, 0, 0, 0, 0,
	87, 0, 0, 0, 0, 0, 0, 10, 14, 0,
	15, 0, 0, 25, 0, 26, 27, 28, 17, 16,
	23, 24,
}
var StraceTok1 = [...]int{

	1,
}
var StraceTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44,
}
var StraceTok3 = [...]int{
	0,
}

var StraceErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

//line yaccpar:1

/*	parser for yacc output	*/

var (
	StraceDebug        = 0
	StraceErrorVerbose = false
)

type StraceLexer interface {
	Lex(lval *StraceSymType) int
	Error(s string)
}

type StraceParser interface {
	Parse(StraceLexer) int
	Lookahead() int
}

type StraceParserImpl struct {
	lval  StraceSymType
	stack [StraceInitialStackSize]StraceSymType
	char  int
}

func (p *StraceParserImpl) Lookahead() int {
	return p.char
}

func StraceNewParser() StraceParser {
	return &StraceParserImpl{}
}

const StraceFlag = -1000

func StraceTokname(c int) string {
	if c >= 1 && c-1 < len(StraceToknames) {
		if StraceToknames[c-1] != "" {
			return StraceToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func StraceStatname(s int) string {
	if s >= 0 && s < len(StraceStatenames) {
		if StraceStatenames[s] != "" {
			return StraceStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func StraceErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !StraceErrorVerbose {
		return "syntax error"
	}

	for _, e := range StraceErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + StraceTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := StracePact[state]
	for tok := TOKSTART; tok-1 < len(StraceToknames); tok++ {
		if n := base + tok; n >= 0 && n < StraceLast && StraceChk[StraceAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if StraceDef[state] == -2 {
		i := 0
		for StraceExca[i] != -1 || StraceExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; StraceExca[i] >= 0; i += 2 {
			tok := StraceExca[i]
			if tok < TOKSTART || StraceExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if StraceExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += StraceTokname(tok)
	}
	return res
}

func Stracelex1(lex StraceLexer, lval *StraceSymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = StraceTok1[0]
		goto out
	}
	if char < len(StraceTok1) {
		token = StraceTok1[char]
		goto out
	}
	if char >= StracePrivate {
		if char < StracePrivate+len(StraceTok2) {
			token = StraceTok2[char-StracePrivate]
			goto out
		}
	}
	for i := 0; i < len(StraceTok3); i += 2 {
		token = StraceTok3[i+0]
		if token == char {
			token = StraceTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = StraceTok2[1] /* unknown char */
	}
	if StraceDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", StraceTokname(token), uint(char))
	}
	return char, token
}

func StraceParse(Stracelex StraceLexer) int {
	return StraceNewParser().Parse(Stracelex)
}

func (Stracercvr *StraceParserImpl) Parse(Stracelex StraceLexer) int {
	var Stracen int
	var StraceVAL StraceSymType
	var StraceDollar []StraceSymType
	_ = StraceDollar // silence set and not used
	StraceS := Stracercvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	Stracestate := 0
	Stracercvr.char = -1
	Stracetoken := -1 // Stracercvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		Stracestate = -1
		Stracercvr.char = -1
		Stracetoken = -1
	}()
	Stracep := -1
	goto Stracestack

ret0:
	return 0

ret1:
	return 1

Stracestack:
	/* put a state and value onto the stack */
	if StraceDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", StraceTokname(Stracetoken), StraceStatname(Stracestate))
	}

	Stracep++
	if Stracep >= len(StraceS) {
		nyys := make([]StraceSymType, len(StraceS)*2)
		copy(nyys, StraceS)
		StraceS = nyys
	}
	StraceS[Stracep] = StraceVAL
	StraceS[Stracep].yys = Stracestate

Stracenewstate:
	Stracen = StracePact[Stracestate]
	if Stracen <= StraceFlag {
		goto Stracedefault /* simple state */
	}
	if Stracercvr.char < 0 {
		Stracercvr.char, Stracetoken = Stracelex1(Stracelex, &Stracercvr.lval)
	}
	Stracen += Stracetoken
	if Stracen < 0 || Stracen >= StraceLast {
		goto Stracedefault
	}
	Stracen = StraceAct[Stracen]
	if StraceChk[Stracen] == Stracetoken { /* valid shift */
		Stracercvr.char = -1
		Stracetoken = -1
		StraceVAL = Stracercvr.lval
		Stracestate = Stracen
		if Errflag > 0 {
			Errflag--
		}
		goto Stracestack
	}

Stracedefault:
	/* default state action */
	Stracen = StraceDef[Stracestate]
	if Stracen == -2 {
		if Stracercvr.char < 0 {
			Stracercvr.char, Stracetoken = Stracelex1(Stracelex, &Stracercvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if StraceExca[xi+0] == -1 && StraceExca[xi+1] == Stracestate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			Stracen = StraceExca[xi+0]
			if Stracen < 0 || Stracen == Stracetoken {
				break
			}
		}
		Stracen = StraceExca[xi+1]
		if Stracen < 0 {
			goto ret0
		}
	}
	if Stracen == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			Stracelex.Error(StraceErrorMessage(Stracestate, Stracetoken))
			Nerrs++
			if StraceDebug >= 1 {
				__yyfmt__.Printf("%s", StraceStatname(Stracestate))
				__yyfmt__.Printf(" saw %s\n", StraceTokname(Stracetoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for Stracep >= 0 {
				Stracen = StracePact[StraceS[Stracep].yys] + StraceErrCode
				if Stracen >= 0 && Stracen < StraceLast {
					Stracestate = StraceAct[Stracen] /* simulate a shift of "error" */
					if StraceChk[Stracestate] == StraceErrCode {
						goto Stracestack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if StraceDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", StraceS[Stracep].yys)
				}
				Stracep--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if StraceDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", StraceTokname(Stracetoken))
			}
			if Stracetoken == StraceEofCode {
				goto ret1
			}
			Stracercvr.char = -1
			Stracetoken = -1
			goto Stracenewstate /* try again in the same state */
		}
	}

	/* reduction by production Stracen */
	if StraceDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", Stracen, StraceStatname(Stracestate))
	}

	Stracent := Stracen
	Stracept := Stracep
	_ = Stracept // guard against "declared and not used"

	Stracep -= StraceR2[Stracen]
	// Stracep is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if Stracep+1 >= len(StraceS) {
		nyys := make([]StraceSymType, len(StraceS)*2)
		copy(nyys, StraceS)
		StraceS = nyys
	}
	StraceVAL = StraceS[Stracep+1]

	/* consult goto table to find next state */
	Stracen = StraceR1[Stracen]
	Straceg := StracePgo[Stracen]
	Stracej := Straceg + StraceS[Stracep].yys + 1

	if Stracej >= StraceLast {
		Stracestate = StraceAct[Straceg]
	} else {
		Stracestate = StraceAct[Stracej]
		if StraceChk[Stracestate] != -Stracen {
			Stracestate = StraceAct[Straceg]
		}
	}
	// dummy call; replaced with literal code
	switch Stracent {

	case 1:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:78
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, nil, int64(-1), true, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 2:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:80
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, StraceDollar[3].val_types, int64(-1), true, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 3:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line strace.y:83
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", nil, -1, true, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 4:
		StraceDollar = StraceS[Stracept-6 : Stracept+1]
		//line strace.y:88
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, nil, int64(StraceDollar[6].val_int), false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 5:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:92
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", nil, int64(StraceDollar[4].val_int), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 6:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:94
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", nil, int64(StraceDollar[4].val_uint), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 7:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:96
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", nil, -1, false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 8:
		StraceDollar = StraceS[Stracept-7 : Stracept+1]
		//line strace.y:98
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", nil, int64(StraceDollar[4].val_int), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 9:
		StraceDollar = StraceS[Stracept-7 : Stracept+1]
		//line strace.y:100
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", nil, int64(StraceDollar[4].val_uint), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 10:
		StraceDollar = StraceS[Stracept-8 : Stracept+1]
		//line strace.y:102
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", nil, int64(StraceDollar[4].val_int), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 11:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line strace.y:104
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", StraceDollar[2].val_types, int64(StraceDollar[5].val_int), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 12:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line strace.y:106
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", StraceDollar[2].val_types, int64(StraceDollar[5].val_uint), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 13:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line strace.y:108
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", StraceDollar[2].val_types, -1, false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 14:
		StraceDollar = StraceS[Stracept-8 : Stracept+1]
		//line strace.y:110
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", StraceDollar[2].val_types, int64(StraceDollar[5].val_int), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 15:
		StraceDollar = StraceS[Stracept-8 : Stracept+1]
		//line strace.y:112
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", StraceDollar[2].val_types, int64(StraceDollar[5].val_uint), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 16:
		StraceDollar = StraceS[Stracept-9 : Stracept+1]
		//line strace.y:114
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", StraceDollar[2].val_types, int64(StraceDollar[5].val_uint), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 17:
		StraceDollar = StraceS[Stracept-9 : Stracept+1]
		//line strace.y:116
		{
			StraceVAL.val_syscall = NewSyscall(-1, "tmp", StraceDollar[2].val_types, int64(StraceDollar[5].val_int), false, true)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 18:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line strace.y:118
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, nil, StraceDollar[5].val_int, false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 19:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line strace.y:120
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, nil, int64(StraceDollar[5].val_uint), false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 20:
		StraceDollar = StraceS[Stracept-6 : Stracept+1]
		//line strace.y:122
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, StraceDollar[3].val_types, StraceDollar[6].val_int, false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 21:
		StraceDollar = StraceS[Stracept-6 : Stracept+1]
		//line strace.y:125
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, StraceDollar[3].val_types, int64(StraceDollar[6].val_uint), false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 22:
		StraceDollar = StraceS[Stracept-6 : Stracept+1]
		//line strace.y:128
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, StraceDollar[3].val_types, -1, false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 23:
		StraceDollar = StraceS[Stracept-10 : Stracept+1]
		//line strace.y:131
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, StraceDollar[3].val_types, StraceDollar[6].val_int, false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 24:
		StraceDollar = StraceS[Stracept-10 : Stracept+1]
		//line strace.y:134
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, StraceDollar[3].val_types, int64(StraceDollar[6].val_uint), false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 25:
		StraceDollar = StraceS[Stracept-9 : Stracept+1]
		//line strace.y:137
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, StraceDollar[3].val_types, StraceDollar[6].val_int, false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 26:
		StraceDollar = StraceS[Stracept-9 : Stracept+1]
		//line strace.y:140
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, StraceDollar[3].val_types, int64(StraceDollar[6].val_uint), false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 27:
		StraceDollar = StraceS[Stracept-9 : Stracept+1]
		//line strace.y:143
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, nil, StraceDollar[5].val_int, false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 28:
		StraceDollar = StraceS[Stracept-9 : Stracept+1]
		//line strace.y:146
		{
			StraceVAL.val_syscall = NewSyscall(-1, StraceDollar[1].data, nil, int64(StraceDollar[5].val_uint), false, false)
			Stracelex.(*Stracelexer).result = StraceVAL.val_syscall
		}
	case 29:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:149
		{
			call := StraceDollar[2].val_syscall
			call.Pid = StraceDollar[1].val_int
			Stracelex.(*Stracelexer).result = call
		}
	case 30:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:152
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 31:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:153
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 32:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:156
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 33:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:157
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 34:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:158
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 35:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:159
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 36:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:160
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 37:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:161
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 38:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:162
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 39:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:163
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 40:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:164
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 41:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:165
		{
			StraceVAL.val_parenthetical = newParenthetical()
		}
	case 42:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:169
		{
			types := make([]irType, 0)
			types = append(types, StraceDollar[1].val_type)
			StraceVAL.val_types = types
		}
	case 43:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:170
		{
			StraceDollar[1].val_types = append(StraceDollar[1].val_types, StraceDollar[3].val_type)
			StraceVAL.val_types = StraceDollar[1].val_types
		}
	case 44:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:174
		{
			StraceVAL.val_type = StraceDollar[1].val_buf_type
		}
	case 45:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:175
		{
			StraceVAL.val_type = StraceDollar[1].val_field
		}
	case 46:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:176
		{
			StraceVAL.val_type = StraceDollar[1].val_pointer_type
		}
	case 47:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:177
		{
			StraceVAL.val_type = StraceDollar[1].val_array_type
		}
	case 48:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:178
		{
			StraceVAL.val_type = StraceDollar[1].val_struct_type
		}
	case 49:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:179
		{
			StraceVAL.val_type = StraceDollar[1].val_call
		}
	case 50:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:180
		{
			StraceVAL.val_type = StraceDollar[1].val_ip_type
		}
	case 51:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:181
		{
			StraceVAL.val_type = StraceDollar[1].val_type
		}
	case 52:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:182
		{
			StraceVAL.val_type = newDynamicType(StraceDollar[1].val_type, StraceDollar[3].val_type)
		}
	case 53:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:183
		{
			StraceVAL.val_type = StraceDollar[2].val_array_type
		}
	case 54:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:187
		{
			StraceVAL.val_type = newExpression(StraceDollar[1].val_type)
		}
	case 55:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:188
		{
			StraceVAL.val_type = newExpression(StraceDollar[1].val_type)
		}
	case 56:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:189
		{
			StraceVAL.val_type = newExpression(StraceDollar[1].val_macro)
		}
	case 57:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:190
		{
			StraceVAL.val_type = newExpression(newBinop(StraceDollar[1].val_type, ORop, StraceDollar[3].val_type))
		}
	case 58:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:191
		{
			StraceVAL.val_type = newExpression(newBinop(StraceDollar[1].val_type, ANDop, StraceDollar[3].val_type))
		}
	case 59:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:192
		{
			StraceVAL.val_type = newExpression(newBinop(StraceDollar[1].val_type, LSHIFTop, StraceDollar[3].val_type))
		}
	case 60:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:193
		{
			StraceVAL.val_type = newExpression(newBinop(StraceDollar[1].val_type, RSHIFTop, StraceDollar[3].val_type))
		}
	case 61:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:194
		{
			StraceVAL.val_type = newExpression(newBinop(StraceDollar[1].val_type, LORop, StraceDollar[3].val_type))
		}
	case 62:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:195
		{
			StraceVAL.val_type = newExpression(newBinop(StraceDollar[1].val_type, LANDop, StraceDollar[3].val_type))
		}
	case 63:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:196
		{
			StraceVAL.val_type = newExpression(newBinop(StraceDollar[1].val_type, LEQUALop, StraceDollar[3].val_type))
		}
	case 64:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:197
		{
			StraceVAL.val_type = StraceDollar[2].val_type
		}
	case 65:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:198
		{
			StraceVAL.val_type = newExpression(newBinop(StraceDollar[1].val_type, TIMESop, StraceDollar[3].val_type))
		}
	case 66:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:199
		{
			StraceVAL.val_type = newExpression(newUnop(StraceDollar[2].val_type, ONESCOMPop))
		}
	case 67:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:202
		{
			i := make(ints, 1)
			i[0] = StraceDollar[1].val_int_type
			StraceVAL.val_type = i
		}
	case 68:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:203
		{
			StraceVAL.val_type = append(StraceDollar[1].val_type.(ints), StraceDollar[2].val_int_type)
		}
	case 69:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:206
		{
			f := make(flags, 1)
			f[0] = StraceDollar[1].val_flag_type
			StraceVAL.val_type = f
		}
	case 70:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:207
		{
			StraceVAL.val_type = append(StraceDollar[1].val_type.(flags), StraceDollar[2].val_flag_type)
		}
	case 71:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:210
		{
			StraceVAL.val_call = newCallType(StraceDollar[1].data, StraceDollar[3].val_types)
		}
	case 72:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:213
		{
			StraceVAL.val_macro = newMacroType(StraceDollar[1].data, StraceDollar[3].val_types)
		}
	case 73:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:214
		{
			StraceVAL.val_macro = newMacroType(StraceDollar[1].data, nil)
		}
	case 74:
		StraceDollar = StraceS[Stracept-5 : Stracept+1]
		//line strace.y:215
		{
			StraceVAL.val_macro = newMacroType(StraceDollar[4].data, nil)
		}
	case 75:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:218
		{
			StraceVAL.val_pointer_type = nullPointer()
		}
	case 76:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:219
		{
			StraceVAL.val_pointer_type = newPointerType(StraceDollar[2].val_uint, StraceDollar[4].val_type)
		}
	case 77:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:220
		{
			StraceVAL.val_pointer_type = nullPointer()
		}
	case 78:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:223
		{
			arr := newArrayType(StraceDollar[2].val_types)
			StraceVAL.val_array_type = arr
		}
	case 79:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:224
		{
			arr := newArrayType(nil)
			StraceVAL.val_array_type = arr
		}
	case 80:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:227
		{
			StraceVAL.val_struct_type = newStructType(StraceDollar[2].val_types)
		}
	case 81:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:228
		{
			StraceVAL.val_struct_type = newStructType(StraceDollar[2].val_types)
		}
	case 82:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:229
		{
			StraceVAL.val_struct_type = newStructType(nil)
		}
	case 83:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:232
		{
			StraceVAL.val_field = newField(StraceDollar[1].data, nil)
		}
	case 84:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:233
		{
			StraceVAL.val_field = newField(StraceDollar[1].data, StraceDollar[3].val_type)
		}
	case 85:
		StraceDollar = StraceS[Stracept-3 : Stracept+1]
		//line strace.y:234
		{
			StraceVAL.val_field = newField(StraceDollar[1].data, StraceDollar[3].val_type)
		}
	case 86:
		StraceDollar = StraceS[Stracept-4 : Stracept+1]
		//line strace.y:235
		{
			StraceVAL.val_field = newField(StraceDollar[1].data, StraceDollar[4].val_type)
		}
	case 87:
		StraceDollar = StraceS[Stracept-6 : Stracept+1]
		//line strace.y:236
		{
			StraceVAL.val_field = newField(StraceDollar[1].data, StraceDollar[6].val_type)
		}
	case 88:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:239
		{
			StraceVAL.val_buf_type = newBufferType(StraceDollar[1].data)
		}
	case 89:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:240
		{
			StraceVAL.val_buf_type = newBufferType(StraceDollar[1].data)
		}
	case 90:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:244
		{
			StraceVAL.val_int_type = newIntType(StraceDollar[1].val_int)
		}
	case 91:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:245
		{
			StraceVAL.val_int_type = newIntType(int64(StraceDollar[1].val_uint))
		}
	case 92:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:248
		{
			StraceVAL.val_flag_type = newFlagType(StraceDollar[1].data)
		}
	case 93:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:251
		{
			StraceVAL.val_ip_type = newIPType(StraceDollar[1].data)
		}
	case 94:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:252
		{
			StraceVAL.val_ip_type = newIPType(StraceDollar[1].data)
		}
	case 95:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:253
		{
			StraceVAL.val_ip_type = newIPType(StraceDollar[1].data)
		}
	case 96:
		StraceDollar = StraceS[Stracept-1 : Stracept+1]
		//line strace.y:256
		{
			ids := make([]*bufferType, 0)
			ids = append(ids, newBufferType(StraceDollar[1].data))
			StraceVAL.val_identifiers = ids
		}
	case 97:
		StraceDollar = StraceS[Stracept-2 : Stracept+1]
		//line strace.y:257
		{
			StraceDollar[2].val_identifiers = append(StraceDollar[2].val_identifiers, newBufferType(StraceDollar[1].data))
			StraceVAL.val_identifiers = StraceDollar[2].val_identifiers
		}
	}
	goto Stracestack /* stack new state and value */
}
