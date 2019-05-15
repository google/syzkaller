//line straceLex.rl:1
// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !codeanalysis

package parser

import (
	"encoding/hex"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"strconv"
	"strings"
)

//line lex.go:20
const strace_start int = 157
const strace_first_final int = 157
const strace_error int = 0

const strace_en_comment int = 207
const strace_en_main int = 157

//line straceLex.rl:22

type Stracelexer struct {
	result      *Syscall
	data        []byte
	p, pe, cs   int
	ts, te, act int
}

func newStraceLexer(data []byte) *Stracelexer {
	lex := &Stracelexer{
		data: data,
		pe:   len(data),
	}

//line lex.go:46
	{
		lex.cs = strace_start
		lex.ts = 0
		lex.te = 0
		lex.act = 0
	}

//line straceLex.rl:38
	return lex
}

func (lex *Stracelexer) Lex(out *StraceSymType) int {
	eof := lex.pe
	tok := 0

//line lex.go:62
	{
		if (lex.p) == (lex.pe) {
			goto _test_eof
		}
		switch lex.cs {
		case 157:
			goto st_case_157
		case 0:
			goto st_case_0
		case 1:
			goto st_case_1
		case 2:
			goto st_case_2
		case 158:
			goto st_case_158
		case 3:
			goto st_case_3
		case 4:
			goto st_case_4
		case 5:
			goto st_case_5
		case 6:
			goto st_case_6
		case 7:
			goto st_case_7
		case 8:
			goto st_case_8
		case 159:
			goto st_case_159
		case 160:
			goto st_case_160
		case 9:
			goto st_case_9
		case 161:
			goto st_case_161
		case 162:
			goto st_case_162
		case 10:
			goto st_case_10
		case 11:
			goto st_case_11
		case 12:
			goto st_case_12
		case 13:
			goto st_case_13
		case 14:
			goto st_case_14
		case 15:
			goto st_case_15
		case 16:
			goto st_case_16
		case 17:
			goto st_case_17
		case 18:
			goto st_case_18
		case 19:
			goto st_case_19
		case 20:
			goto st_case_20
		case 21:
			goto st_case_21
		case 22:
			goto st_case_22
		case 23:
			goto st_case_23
		case 24:
			goto st_case_24
		case 25:
			goto st_case_25
		case 26:
			goto st_case_26
		case 163:
			goto st_case_163
		case 27:
			goto st_case_27
		case 164:
			goto st_case_164
		case 165:
			goto st_case_165
		case 166:
			goto st_case_166
		case 167:
			goto st_case_167
		case 28:
			goto st_case_28
		case 29:
			goto st_case_29
		case 30:
			goto st_case_30
		case 168:
			goto st_case_168
		case 169:
			goto st_case_169
		case 31:
			goto st_case_31
		case 32:
			goto st_case_32
		case 170:
			goto st_case_170
		case 171:
			goto st_case_171
		case 172:
			goto st_case_172
		case 173:
			goto st_case_173
		case 33:
			goto st_case_33
		case 34:
			goto st_case_34
		case 35:
			goto st_case_35
		case 36:
			goto st_case_36
		case 174:
			goto st_case_174
		case 175:
			goto st_case_175
		case 37:
			goto st_case_37
		case 38:
			goto st_case_38
		case 39:
			goto st_case_39
		case 40:
			goto st_case_40
		case 41:
			goto st_case_41
		case 42:
			goto st_case_42
		case 43:
			goto st_case_43
		case 44:
			goto st_case_44
		case 45:
			goto st_case_45
		case 46:
			goto st_case_46
		case 47:
			goto st_case_47
		case 48:
			goto st_case_48
		case 49:
			goto st_case_49
		case 50:
			goto st_case_50
		case 176:
			goto st_case_176
		case 51:
			goto st_case_51
		case 52:
			goto st_case_52
		case 53:
			goto st_case_53
		case 54:
			goto st_case_54
		case 177:
			goto st_case_177
		case 55:
			goto st_case_55
		case 178:
			goto st_case_178
		case 179:
			goto st_case_179
		case 56:
			goto st_case_56
		case 57:
			goto st_case_57
		case 58:
			goto st_case_58
		case 59:
			goto st_case_59
		case 60:
			goto st_case_60
		case 61:
			goto st_case_61
		case 62:
			goto st_case_62
		case 63:
			goto st_case_63
		case 64:
			goto st_case_64
		case 65:
			goto st_case_65
		case 66:
			goto st_case_66
		case 67:
			goto st_case_67
		case 68:
			goto st_case_68
		case 69:
			goto st_case_69
		case 70:
			goto st_case_70
		case 71:
			goto st_case_71
		case 180:
			goto st_case_180
		case 181:
			goto st_case_181
		case 72:
			goto st_case_72
		case 73:
			goto st_case_73
		case 74:
			goto st_case_74
		case 75:
			goto st_case_75
		case 76:
			goto st_case_76
		case 77:
			goto st_case_77
		case 78:
			goto st_case_78
		case 79:
			goto st_case_79
		case 80:
			goto st_case_80
		case 81:
			goto st_case_81
		case 82:
			goto st_case_82
		case 83:
			goto st_case_83
		case 84:
			goto st_case_84
		case 85:
			goto st_case_85
		case 182:
			goto st_case_182
		case 86:
			goto st_case_86
		case 87:
			goto st_case_87
		case 88:
			goto st_case_88
		case 89:
			goto st_case_89
		case 90:
			goto st_case_90
		case 91:
			goto st_case_91
		case 92:
			goto st_case_92
		case 93:
			goto st_case_93
		case 94:
			goto st_case_94
		case 95:
			goto st_case_95
		case 96:
			goto st_case_96
		case 97:
			goto st_case_97
		case 98:
			goto st_case_98
		case 99:
			goto st_case_99
		case 100:
			goto st_case_100
		case 101:
			goto st_case_101
		case 102:
			goto st_case_102
		case 103:
			goto st_case_103
		case 104:
			goto st_case_104
		case 105:
			goto st_case_105
		case 106:
			goto st_case_106
		case 107:
			goto st_case_107
		case 108:
			goto st_case_108
		case 109:
			goto st_case_109
		case 110:
			goto st_case_110
		case 111:
			goto st_case_111
		case 112:
			goto st_case_112
		case 113:
			goto st_case_113
		case 114:
			goto st_case_114
		case 115:
			goto st_case_115
		case 116:
			goto st_case_116
		case 117:
			goto st_case_117
		case 118:
			goto st_case_118
		case 119:
			goto st_case_119
		case 120:
			goto st_case_120
		case 121:
			goto st_case_121
		case 122:
			goto st_case_122
		case 123:
			goto st_case_123
		case 124:
			goto st_case_124
		case 125:
			goto st_case_125
		case 126:
			goto st_case_126
		case 127:
			goto st_case_127
		case 128:
			goto st_case_128
		case 129:
			goto st_case_129
		case 130:
			goto st_case_130
		case 131:
			goto st_case_131
		case 132:
			goto st_case_132
		case 133:
			goto st_case_133
		case 134:
			goto st_case_134
		case 135:
			goto st_case_135
		case 136:
			goto st_case_136
		case 137:
			goto st_case_137
		case 138:
			goto st_case_138
		case 139:
			goto st_case_139
		case 140:
			goto st_case_140
		case 141:
			goto st_case_141
		case 142:
			goto st_case_142
		case 143:
			goto st_case_143
		case 144:
			goto st_case_144
		case 145:
			goto st_case_145
		case 146:
			goto st_case_146
		case 147:
			goto st_case_147
		case 148:
			goto st_case_148
		case 149:
			goto st_case_149
		case 150:
			goto st_case_150
		case 151:
			goto st_case_151
		case 152:
			goto st_case_152
		case 153:
			goto st_case_153
		case 154:
			goto st_case_154
		case 183:
			goto st_case_183
		case 155:
			goto st_case_155
		case 184:
			goto st_case_184
		case 185:
			goto st_case_185
		case 186:
			goto st_case_186
		case 187:
			goto st_case_187
		case 188:
			goto st_case_188
		case 189:
			goto st_case_189
		case 190:
			goto st_case_190
		case 191:
			goto st_case_191
		case 192:
			goto st_case_192
		case 193:
			goto st_case_193
		case 194:
			goto st_case_194
		case 195:
			goto st_case_195
		case 196:
			goto st_case_196
		case 197:
			goto st_case_197
		case 198:
			goto st_case_198
		case 199:
			goto st_case_199
		case 200:
			goto st_case_200
		case 201:
			goto st_case_201
		case 202:
			goto st_case_202
		case 203:
			goto st_case_203
		case 204:
			goto st_case_204
		case 205:
			goto st_case_205
		case 156:
			goto st_case_156
		case 206:
			goto st_case_206
		case 207:
			goto st_case_207
		case 208:
			goto st_case_208
		}
		goto st_out
	tr9:
//line NONE:1
		switch lex.act {
		case 0:
			{
				{
					goto st0
				}
			}
		case 3:
			{
				(lex.p) = (lex.te) - 1
				out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts:lex.te]), 0, 64)
				tok = INT
				{
					(lex.p)++
					lex.cs = 157
					goto _out
				}
			}
		case 4:
			{
				(lex.p) = (lex.te) - 1
				out.val_double, _ = strconv.ParseFloat(string(lex.data[lex.ts:lex.te]), 64)
				tok = DOUBLE
				{
					(lex.p)++
					lex.cs = 157
					goto _out
				}
			}
		case 7:
			{
				(lex.p) = (lex.te) - 1
				tok = NULL
				{
					(lex.p)++
					lex.cs = 157
					goto _out
				}
			}
		case 8:
			{
				(lex.p) = (lex.te) - 1
				out.data = string(lex.data[lex.ts:lex.te])
				tok = FLAG
				{
					(lex.p)++
					lex.cs = 157
					goto _out
				}
			}
		case 10:
			{
				(lex.p) = (lex.te) - 1
				out.data = string(lex.data[lex.ts:lex.te])
				tok = IDENTIFIER
				{
					(lex.p)++
					lex.cs = 157
					goto _out
				}
			}
		case 32:
			{
				(lex.p) = (lex.te) - 1
				tok = COMMA
				{
					(lex.p)++
					lex.cs = 157
					goto _out
				}
			}
		}

		goto st157
	tr11:
//line straceLex.rl:99
		(lex.p) = (lex.te) - 1
		{
			tok = COMMA
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr28:
//line straceLex.rl:78
		lex.te = (lex.p) + 1
		{
			tok = UNFINISHED
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr30:
//line straceLex.rl:89
		lex.te = (lex.p) + 1
		{
			tok = RBRACKET
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr36:
//line straceLex.rl:70
		(lex.p) = (lex.te) - 1
		{
			out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts:lex.te]), 0, 64)
			tok = INT
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr55:
//line straceLex.rl:103
		(lex.p) = (lex.te) - 1
		{
			out.data = string(lex.data[lex.ts:lex.te])
			tok = DATETIME
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr74:
//line straceLex.rl:80
		lex.te = (lex.p) + 1
		{
			out.data = string(lex.data[lex.ts:lex.te])
			tok = MAC
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr78:
//line straceLex.rl:95
		lex.te = (lex.p) + 1
		{
			tok = LSHIFT
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr94:
//line straceLex.rl:79
		(lex.p) = (lex.te) - 1
		{
			tok = RESUMED
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr95:
//line straceLex.rl:79
		lex.te = (lex.p) + 1
		{
			tok = RESUMED
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr162:
//line straceLex.rl:96
		lex.te = (lex.p) + 1
		{
			tok = RSHIFT
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr165:
//line straceLex.rl:106
		lex.te = (lex.p) + 1

		goto st157
	tr166:
//line straceLex.rl:93
		lex.te = (lex.p) + 1
		{
			tok = NOT
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr168:
//line straceLex.rl:92
		lex.te = (lex.p) + 1
		{
			tok = AND
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr170:
//line straceLex.rl:82
		lex.te = (lex.p) + 1
		{
			tok = LPAREN
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr171:
//line straceLex.rl:84
		lex.te = (lex.p) + 1
		{
			tok = RPAREN
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr172:
//line straceLex.rl:87
		lex.te = (lex.p) + 1
		{
			tok = TIMES
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr173:
//line straceLex.rl:101
		lex.te = (lex.p) + 1
		{
			tok = PLUS
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr183:
//line straceLex.rl:105
		lex.te = (lex.p) + 1
		{
			tok = QUESTION
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr187:
//line straceLex.rl:85
		lex.te = (lex.p) + 1
		{
			tok = LBRACKET_SQUARE
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr188:
//line straceLex.rl:86
		lex.te = (lex.p) + 1
		{
			tok = RBRACKET_SQUARE
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr190:
//line straceLex.rl:88
		lex.te = (lex.p) + 1
		{
			tok = LBRACKET
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr191:
//line straceLex.rl:90
		lex.te = (lex.p) + 1
		{
			tok = OR
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr192:
//line straceLex.rl:94
		lex.te = (lex.p) + 1
		{
			tok = ONESCOMP
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr193:
//line straceLex.rl:73
		lex.te = (lex.p)
		(lex.p)--
		{
			out.data = ParseString(string(lex.data[lex.ts+1 : lex.te-1]))
			tok = STRING_LITERAL
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr194:
//line straceLex.rl:77
		lex.te = (lex.p)
		(lex.p)--
		{
			out.data = string(lex.data[lex.ts:lex.te])
			tok = IDENTIFIER
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr195:
//line straceLex.rl:99
		lex.te = (lex.p)
		(lex.p)--
		{
			tok = COMMA
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr197:
//line straceLex.rl:100
		lex.te = (lex.p)
		(lex.p)--
		{
			tok = MINUS
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr198:
//line straceLex.rl:97
		lex.te = (lex.p) + 1
		{
			tok = ARROW
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr199:
//line straceLex.rl:102
		lex.te = (lex.p)
		(lex.p)--
		{
			tok = FORWARDSLASH
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr200:
//line straceLex.rl:104
		lex.te = (lex.p) + 1
		{
			{
				goto st207
			}
		}
		goto st157
	tr201:
//line straceLex.rl:70
		lex.te = (lex.p)
		(lex.p)--
		{
			out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts:lex.te]), 0, 64)
			tok = INT
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr206:
//line straceLex.rl:71
		lex.te = (lex.p)
		(lex.p)--
		{
			out.val_double, _ = strconv.ParseFloat(string(lex.data[lex.ts:lex.te]), 64)
			tok = DOUBLE
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr210:
//line straceLex.rl:77
		lex.te = (lex.p) + 1
		{
			out.data = string(lex.data[lex.ts:lex.te])
			tok = IDENTIFIER
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr218:
//line straceLex.rl:103
		lex.te = (lex.p)
		(lex.p)--
		{
			out.data = string(lex.data[lex.ts:lex.te])
			tok = DATETIME
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr221:
//line straceLex.rl:72
		lex.te = (lex.p)
		(lex.p)--
		{
			out.val_uint, _ = strconv.ParseUint(string(lex.data[lex.ts:lex.te]), 0, 64)
			tok = UINT
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr222:
//line straceLex.rl:79
		lex.te = (lex.p)
		(lex.p)--
		{
			tok = RESUMED
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr224:
//line straceLex.rl:81
		lex.te = (lex.p)
		(lex.p)--
		{
			tok = EQUALS
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr225:
//line straceLex.rl:98
		lex.te = (lex.p) + 1
		{
			tok = ARROW
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr226:
//line straceLex.rl:83
		lex.te = (lex.p) + 1
		{
			tok = EQUALAT
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	tr231:
//line straceLex.rl:75
		lex.te = (lex.p)
		(lex.p)--
		{
			out.data = string(lex.data[lex.ts:lex.te])
			tok = FLAG
			{
				(lex.p)++
				lex.cs = 157
				goto _out
			}
		}
		goto st157
	st157:
//line NONE:1
		lex.ts = 0

//line NONE:1
		lex.act = 0

		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof157
		}
	st_case_157:
//line NONE:1
		lex.ts = (lex.p)

//line lex.go:740
		switch lex.data[(lex.p)] {
		case 32:
			goto tr165
		case 33:
			goto tr166
		case 34:
			goto st1
		case 38:
			goto tr168
		case 39:
			goto tr169
		case 40:
			goto tr170
		case 41:
			goto tr171
		case 42:
			goto tr172
		case 43:
			goto tr173
		case 44:
			goto tr174
		case 45:
			goto st163
		case 46:
			goto st27
		case 47:
			goto st164
		case 48:
			goto tr177
		case 58:
			goto st160
		case 60:
			goto st72
		case 61:
			goto st183
		case 62:
			goto st155
		case 63:
			goto tr183
		case 78:
			goto st203
		case 91:
			goto tr187
		case 93:
			goto tr188
		case 95:
			goto st156
		case 123:
			goto tr190
		case 124:
			goto tr191
		case 125:
			goto tr30
		case 126:
			goto tr192
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 13:
				if 49 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto tr178
				}
			case lex.data[(lex.p)] >= 9:
				goto tr165
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] < 97:
				if 71 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 90 {
					goto tr185
				}
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			default:
				goto tr189
			}
		default:
			goto st184
		}
		goto st0
	st_case_0:
	st0:
		lex.cs = 0
		goto _out
	st1:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof1
		}
	st_case_1:
		switch lex.data[(lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st158
		case 35:
			goto st2
		case 39:
			goto st3
		case 78:
			goto st6
		case 92:
			goto st2
		case 95:
			goto st3
		}
		switch {
		case lex.data[(lex.p)] < 46:
			if 40 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 42 {
				goto st2
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st2
				}
			case lex.data[(lex.p)] >= 65:
				goto st4
			}
		default:
			goto st2
		}
		goto st0
	st2:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof2
		}
	st_case_2:
		switch lex.data[(lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st158
		case 35:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case lex.data[(lex.p)] < 46:
			if 39 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 42 {
				goto st2
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st2
				}
			case lex.data[(lex.p)] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st158:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof158
		}
	st_case_158:
		switch lex.data[(lex.p)] {
		case 39:
			goto st158
		case 46:
			goto st158
		}
		goto tr193
	st3:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof3
		}
	st_case_3:
		switch lex.data[(lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st158
		case 35:
			goto st2
		case 39:
			goto st3
		case 92:
			goto st2
		case 95:
			goto st3
		}
		switch {
		case lex.data[(lex.p)] < 46:
			if 40 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 42 {
				goto st2
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st2
				}
			case lex.data[(lex.p)] >= 65:
				goto st4
			}
		default:
			goto st2
		}
		goto st0
	st4:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof4
		}
	st_case_4:
		switch lex.data[(lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st158
		case 35:
			goto st2
		case 39:
			goto st5
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case lex.data[(lex.p)] < 48:
			switch {
			case lex.data[(lex.p)] > 42:
				if 46 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 47 {
					goto st2
				}
			case lex.data[(lex.p)] >= 40:
				goto st2
			}
		case lex.data[(lex.p)] > 57:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st2
				}
			case lex.data[(lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st5:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof5
		}
	st_case_5:
		switch lex.data[(lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st158
		case 35:
			goto st2
		case 39:
			goto st5
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case lex.data[(lex.p)] < 48:
			switch {
			case lex.data[(lex.p)] > 42:
				if 46 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 47 {
					goto st2
				}
			case lex.data[(lex.p)] >= 40:
				goto st2
			}
		case lex.data[(lex.p)] > 57:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st2
				}
			case lex.data[(lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st6:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof6
		}
	st_case_6:
		switch lex.data[(lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st158
		case 35:
			goto st2
		case 39:
			goto st5
		case 58:
			goto st2
		case 85:
			goto st7
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case lex.data[(lex.p)] < 48:
			switch {
			case lex.data[(lex.p)] > 42:
				if 46 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 47 {
					goto st2
				}
			case lex.data[(lex.p)] >= 40:
				goto st2
			}
		case lex.data[(lex.p)] > 57:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st2
				}
			case lex.data[(lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st7:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof7
		}
	st_case_7:
		switch lex.data[(lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st158
		case 35:
			goto st2
		case 39:
			goto st5
		case 58:
			goto st2
		case 76:
			goto st8
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case lex.data[(lex.p)] < 48:
			switch {
			case lex.data[(lex.p)] > 42:
				if 46 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 47 {
					goto st2
				}
			case lex.data[(lex.p)] >= 40:
				goto st2
			}
		case lex.data[(lex.p)] > 57:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st2
				}
			case lex.data[(lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st8:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof8
		}
	st_case_8:
		switch lex.data[(lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st158
		case 35:
			goto st2
		case 39:
			goto st5
		case 58:
			goto st2
		case 76:
			goto st4
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case lex.data[(lex.p)] < 48:
			switch {
			case lex.data[(lex.p)] > 42:
				if 46 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 47 {
					goto st2
				}
			case lex.data[(lex.p)] >= 40:
				goto st2
			}
		case lex.data[(lex.p)] > 57:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st2
				}
			case lex.data[(lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	tr169:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st159
	st159:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof159
		}
	st_case_159:
//line lex.go:1189
		switch lex.data[(lex.p)] {
		case 39:
			goto tr169
		case 42:
			goto st160
		case 95:
			goto tr169
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 65:
				goto st9
			}
		default:
			goto st160
		}
		goto tr194
	st160:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof160
		}
	st_case_160:
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st160
			}
		default:
			goto st160
		}
		goto tr194
	st9:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof9
		}
	st_case_9:
		switch lex.data[(lex.p)] {
		case 39:
			goto tr10
		case 95:
			goto tr10
		}
		switch {
		case lex.data[(lex.p)] > 57:
			if 65 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 90 {
				goto tr10
			}
		case lex.data[(lex.p)] >= 48:
			goto tr10
		}
		goto tr9
	tr10:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:75
		lex.act = 8
		goto st161
	tr248:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:74
		lex.act = 7
		goto st161
	st161:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof161
		}
	st_case_161:
//line lex.go:1281
		switch lex.data[(lex.p)] {
		case 39:
			goto tr10
		case 95:
			goto tr10
		}
		switch {
		case lex.data[(lex.p)] > 57:
			if 65 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 90 {
				goto tr10
			}
		case lex.data[(lex.p)] >= 48:
			goto tr10
		}
		goto tr9
	tr174:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:99
		lex.act = 32
		goto st162
	st162:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof162
		}
	st_case_162:
//line lex.go:1309
		if lex.data[(lex.p)] == 32 {
			goto st10
		}
		goto tr195
	st10:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof10
		}
	st_case_10:
		if lex.data[(lex.p)] == 32 {
			goto st11
		}
		goto tr11
	st11:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof11
		}
	st_case_11:
		if lex.data[(lex.p)] == 60 {
			goto st12
		}
		goto tr11
	st12:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof12
		}
	st_case_12:
		if lex.data[(lex.p)] == 117 {
			goto st13
		}
		goto tr11
	st13:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof13
		}
	st_case_13:
		if lex.data[(lex.p)] == 110 {
			goto st14
		}
		goto tr9
	st14:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof14
		}
	st_case_14:
		if lex.data[(lex.p)] == 102 {
			goto st15
		}
		goto tr9
	st15:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof15
		}
	st_case_15:
		if lex.data[(lex.p)] == 105 {
			goto st16
		}
		goto tr9
	st16:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof16
		}
	st_case_16:
		if lex.data[(lex.p)] == 110 {
			goto st17
		}
		goto tr9
	st17:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof17
		}
	st_case_17:
		if lex.data[(lex.p)] == 105 {
			goto st18
		}
		goto tr9
	st18:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof18
		}
	st_case_18:
		if lex.data[(lex.p)] == 115 {
			goto st19
		}
		goto tr9
	st19:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof19
		}
	st_case_19:
		if lex.data[(lex.p)] == 104 {
			goto st20
		}
		goto tr9
	st20:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof20
		}
	st_case_20:
		if lex.data[(lex.p)] == 101 {
			goto st21
		}
		goto tr9
	st21:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof21
		}
	st_case_21:
		if lex.data[(lex.p)] == 100 {
			goto st22
		}
		goto tr9
	st22:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof22
		}
	st_case_22:
		if lex.data[(lex.p)] == 32 {
			goto st23
		}
		goto tr9
	st23:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof23
		}
	st_case_23:
		if lex.data[(lex.p)] == 46 {
			goto st24
		}
		goto tr9
	st24:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof24
		}
	st_case_24:
		if lex.data[(lex.p)] == 46 {
			goto st25
		}
		goto tr9
	st25:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof25
		}
	st_case_25:
		if lex.data[(lex.p)] == 46 {
			goto st26
		}
		goto tr9
	st26:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof26
		}
	st_case_26:
		if lex.data[(lex.p)] == 62 {
			goto tr28
		}
		goto tr9
	st163:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof163
		}
	st_case_163:
		if lex.data[(lex.p)] == 62 {
			goto tr198
		}
		goto tr197
	st27:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof27
		}
	st_case_27:
		switch lex.data[(lex.p)] {
		case 46:
			goto st27
		case 125:
			goto tr30
		}
		goto st0
	st164:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof164
		}
	st_case_164:
		if lex.data[(lex.p)] == 42 {
			goto tr200
		}
		goto tr199
	tr177:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:70
		lex.act = 3
		goto st165
	st165:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof165
		}
	st_case_165:
//line lex.go:1509
		switch lex.data[(lex.p)] {
		case 46:
			goto st166
		case 120:
			goto st71
		}
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto tr203
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st70
			}
		default:
			goto st70
		}
		goto tr201
	st166:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof166
		}
	st_case_166:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto tr207
		}
		goto tr206
	tr207:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:71
		lex.act = 4
		goto st167
	st167:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof167
		}
	st_case_167:
//line lex.go:1550
		if lex.data[(lex.p)] == 46 {
			goto st28
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto tr208
		}
		goto tr206
	st28:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof28
		}
	st_case_28:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st29
		}
		goto tr9
	st29:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof29
		}
	st_case_29:
		if lex.data[(lex.p)] == 46 {
			goto st30
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st31
		}
		goto tr9
	st30:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof30
		}
	st_case_30:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st168
		}
		goto tr9
	st168:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof168
		}
	st_case_168:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st169
		}
		goto tr194
	st169:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof169
		}
	st_case_169:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto tr210
		}
		goto tr194
	st31:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof31
		}
	st_case_31:
		if lex.data[(lex.p)] == 46 {
			goto st30
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st32
		}
		goto tr9
	st32:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof32
		}
	st_case_32:
		if lex.data[(lex.p)] == 46 {
			goto st30
		}
		goto tr9
	tr208:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:71
		lex.act = 4
		goto st170
	st170:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof170
		}
	st_case_170:
//line lex.go:1639
		if lex.data[(lex.p)] == 46 {
			goto st28
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto tr211
		}
		goto tr206
	tr211:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:71
		lex.act = 4
		goto st171
	st171:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof171
		}
	st_case_171:
//line lex.go:1659
		if lex.data[(lex.p)] == 46 {
			goto st28
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st172
		}
		goto tr206
	st172:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof172
		}
	st_case_172:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st172
		}
		goto tr206
	tr203:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:70
		lex.act = 3
		goto st173
	st173:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof173
		}
	st_case_173:
//line lex.go:1688
		switch lex.data[(lex.p)] {
		case 46:
			goto st33
		case 58:
			goto st56
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto tr214
		}
		goto tr201
	st33:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof33
		}
	st_case_33:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st34
		}
		goto tr36
	st34:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof34
		}
	st_case_34:
		if lex.data[(lex.p)] == 46 {
			goto st28
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st35
		}
		goto tr36
	st35:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof35
		}
	st_case_35:
		if lex.data[(lex.p)] == 46 {
			goto st28
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st36
		}
		goto tr36
	st36:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof36
		}
	st_case_36:
		if lex.data[(lex.p)] == 46 {
			goto st28
		}
		goto tr36
	tr214:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:70
		lex.act = 3
		goto st174
	st174:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof174
		}
	st_case_174:
//line lex.go:1753
		if lex.data[(lex.p)] == 46 {
			goto st33
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto tr215
		}
		goto tr201
	tr215:
//line NONE:1
		lex.te = (lex.p) + 1

		goto st175
	st175:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof175
		}
	st_case_175:
//line lex.go:1771
		switch lex.data[(lex.p)] {
		case 45:
			goto st37
		case 47:
			goto st37
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st179
		}
		goto tr201
	st37:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof37
		}
	st_case_37:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st38
		}
		goto tr36
	st38:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof38
		}
	st_case_38:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st39
		}
		goto tr36
	st39:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof39
		}
	st_case_39:
		switch lex.data[(lex.p)] {
		case 45:
			goto st40
		case 47:
			goto st40
		}
		goto tr36
	st40:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof40
		}
	st_case_40:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st41
		}
		goto tr36
	st41:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof41
		}
	st_case_41:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st42
		}
		goto tr36
	st42:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof42
		}
	st_case_42:
		switch lex.data[(lex.p)] {
		case 45:
			goto st43
		case 84:
			goto st43
		}
		goto tr36
	st43:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof43
		}
	st_case_43:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st44
		}
		goto tr36
	st44:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof44
		}
	st_case_44:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st45
		}
		goto tr36
	st45:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof45
		}
	st_case_45:
		if lex.data[(lex.p)] == 58 {
			goto st46
		}
		goto tr36
	st46:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof46
		}
	st_case_46:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st47
		}
		goto tr36
	st47:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof47
		}
	st_case_47:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st48
		}
		goto tr36
	st48:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof48
		}
	st_case_48:
		if lex.data[(lex.p)] == 58 {
			goto st49
		}
		goto tr36
	st49:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof49
		}
	st_case_49:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st50
		}
		goto tr36
	st50:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof50
		}
	st_case_50:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto tr54
		}
		goto tr36
	tr54:
//line NONE:1
		lex.te = (lex.p) + 1

		goto st176
	st176:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof176
		}
	st_case_176:
//line lex.go:1924
		switch lex.data[(lex.p)] {
		case 43:
			goto st51
		case 45:
			goto st51
		case 46:
			goto st55
		}
		goto tr218
	st51:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof51
		}
	st_case_51:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st52
		}
		goto tr55
	st52:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof52
		}
	st_case_52:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st53
		}
		goto tr55
	st53:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof53
		}
	st_case_53:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st54
		}
		goto tr55
	st54:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof54
		}
	st_case_54:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto tr59
		}
		goto tr55
	tr59:
//line NONE:1
		lex.te = (lex.p) + 1

		goto st177
	st177:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof177
		}
	st_case_177:
//line lex.go:1980
		if lex.data[(lex.p)] == 46 {
			goto st55
		}
		goto tr218
	st55:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof55
		}
	st_case_55:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st178
		}
		goto tr55
	st178:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof178
		}
	st_case_178:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st178
		}
		goto tr218
	st179:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof179
		}
	st_case_179:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st179
		}
		goto tr201
	st56:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof56
		}
	st_case_56:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st57
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st57
			}
		default:
			goto st57
		}
		goto tr9
	st57:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof57
		}
	st_case_57:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st58
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st58
			}
		default:
			goto st58
		}
		goto tr9
	st58:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof58
		}
	st_case_58:
		if lex.data[(lex.p)] == 58 {
			goto st59
		}
		goto tr9
	st59:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof59
		}
	st_case_59:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st60
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st60
			}
		default:
			goto st60
		}
		goto tr9
	st60:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof60
		}
	st_case_60:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st61
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st61
			}
		default:
			goto st61
		}
		goto tr9
	st61:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof61
		}
	st_case_61:
		if lex.data[(lex.p)] == 58 {
			goto st62
		}
		goto tr9
	st62:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof62
		}
	st_case_62:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st63
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st63
			}
		default:
			goto st63
		}
		goto tr9
	st63:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof63
		}
	st_case_63:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st64
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st64
			}
		default:
			goto st64
		}
		goto tr9
	st64:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof64
		}
	st_case_64:
		if lex.data[(lex.p)] == 58 {
			goto st65
		}
		goto tr9
	st65:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof65
		}
	st_case_65:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st66
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st66
			}
		default:
			goto st66
		}
		goto tr9
	st66:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof66
		}
	st_case_66:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st67
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st67
			}
		default:
			goto st67
		}
		goto tr9
	st67:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof67
		}
	st_case_67:
		if lex.data[(lex.p)] == 58 {
			goto st68
		}
		goto tr9
	st68:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof68
		}
	st_case_68:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st69
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st69
			}
		default:
			goto st69
		}
		goto tr9
	st69:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof69
		}
	st_case_69:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto tr74
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto tr74
			}
		default:
			goto tr74
		}
		goto tr9
	st70:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof70
		}
	st_case_70:
		if lex.data[(lex.p)] == 58 {
			goto st56
		}
		goto tr9
	st71:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof71
		}
	st_case_71:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st180
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st180
			}
		default:
			goto st180
		}
		goto tr36
	st180:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof180
		}
	st_case_180:
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st180
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st180
			}
		default:
			goto st180
		}
		goto tr221
	tr178:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:70
		lex.act = 3
		goto st181
	st181:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof181
		}
	st_case_181:
//line lex.go:2285
		if lex.data[(lex.p)] == 46 {
			goto st166
		}
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto tr203
			}
		case lex.data[(lex.p)] > 70:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 102 {
				goto st70
			}
		default:
			goto st70
		}
		goto tr201
	st72:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof72
		}
	st_case_72:
		switch lex.data[(lex.p)] {
		case 46:
			goto st73
		case 60:
			goto tr78
		case 117:
			goto st13
		}
		goto st0
	st73:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof73
		}
	st_case_73:
		if lex.data[(lex.p)] == 46 {
			goto st74
		}
		goto st0
	st74:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof74
		}
	st_case_74:
		if lex.data[(lex.p)] == 46 {
			goto st75
		}
		goto st0
	st75:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof75
		}
	st_case_75:
		if lex.data[(lex.p)] == 32 {
			goto st76
		}
		goto st0
	st76:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof76
		}
	st_case_76:
		switch lex.data[(lex.p)] {
		case 39:
			goto st77
		case 58:
			goto st77
		case 114:
			goto st102
		}
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st87
			}
		case lex.data[(lex.p)] > 90:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st77:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof77
		}
	st_case_77:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st78:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof78
		}
	st_case_78:
		if lex.data[(lex.p)] == 114 {
			goto st79
		}
		goto st0
	st79:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof79
		}
	st_case_79:
		if lex.data[(lex.p)] == 101 {
			goto st80
		}
		goto st0
	st80:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof80
		}
	st_case_80:
		if lex.data[(lex.p)] == 115 {
			goto st81
		}
		goto st0
	st81:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof81
		}
	st_case_81:
		if lex.data[(lex.p)] == 117 {
			goto st82
		}
		goto st0
	st82:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof82
		}
	st_case_82:
		if lex.data[(lex.p)] == 109 {
			goto st83
		}
		goto st0
	st83:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof83
		}
	st_case_83:
		if lex.data[(lex.p)] == 101 {
			goto st84
		}
		goto st0
	st84:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof84
		}
	st_case_84:
		if lex.data[(lex.p)] == 100 {
			goto st85
		}
		goto st0
	st85:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof85
		}
	st_case_85:
		if lex.data[(lex.p)] == 62 {
			goto tr93
		}
		goto st0
	tr93:
//line NONE:1
		lex.te = (lex.p) + 1

		goto st182
	st182:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof182
		}
	st_case_182:
//line lex.go:2484
		if lex.data[(lex.p)] == 32 {
			goto st86
		}
		goto tr222
	st86:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof86
		}
	st_case_86:
		if lex.data[(lex.p)] == 44 {
			goto tr95
		}
		goto tr94
	st87:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof87
		}
	st_case_87:
		if lex.data[(lex.p)] == 46 {
			goto st88
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st100
		}
		goto st0
	st88:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof88
		}
	st_case_88:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st89
		}
		goto st0
	st89:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof89
		}
	st_case_89:
		if lex.data[(lex.p)] == 46 {
			goto st90
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st98
		}
		goto st0
	st90:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof90
		}
	st_case_90:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st91
		}
		goto st0
	st91:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof91
		}
	st_case_91:
		if lex.data[(lex.p)] == 46 {
			goto st92
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st96
		}
		goto st0
	st92:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof92
		}
	st_case_92:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st93
		}
		goto st0
	st93:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof93
		}
	st_case_93:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 58:
			goto st77
		}
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st94
			}
		case lex.data[(lex.p)] > 90:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st94:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof94
		}
	st_case_94:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 46:
			goto st88
		case 58:
			goto st77
		}
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st95
			}
		case lex.data[(lex.p)] > 90:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st95:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof95
		}
	st_case_95:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 46:
			goto st88
		case 58:
			goto st77
		}
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st87
			}
		case lex.data[(lex.p)] > 90:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st96:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof96
		}
	st_case_96:
		if lex.data[(lex.p)] == 46 {
			goto st92
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st97
		}
		goto st0
	st97:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof97
		}
	st_case_97:
		if lex.data[(lex.p)] == 46 {
			goto st92
		}
		goto st0
	st98:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof98
		}
	st_case_98:
		if lex.data[(lex.p)] == 46 {
			goto st90
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st99
		}
		goto st0
	st99:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof99
		}
	st_case_99:
		if lex.data[(lex.p)] == 46 {
			goto st90
		}
		goto st0
	st100:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof100
		}
	st_case_100:
		if lex.data[(lex.p)] == 46 {
			goto st88
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st101
		}
		goto st0
	st101:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof101
		}
	st_case_101:
		if lex.data[(lex.p)] == 46 {
			goto st88
		}
		goto st0
	st102:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof102
		}
	st_case_102:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		case 101:
			goto st103
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st103:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof103
		}
	st_case_103:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		case 115:
			goto st104
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st104:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof104
		}
	st_case_104:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		case 117:
			goto st105
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st105:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof105
		}
	st_case_105:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		case 109:
			goto st106
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st106:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof106
		}
	st_case_106:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		case 105:
			goto st107
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st107:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof107
		}
	st_case_107:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		case 110:
			goto st108
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st108:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof108
		}
	st_case_108:
		switch lex.data[(lex.p)] {
		case 32:
			goto st78
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		case 103:
			goto st109
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st109:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof109
		}
	st_case_109:
		switch lex.data[(lex.p)] {
		case 32:
			goto st110
		case 39:
			goto st77
		case 42:
			goto st77
		case 95:
			goto st77
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st77
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st77
				}
			case lex.data[(lex.p)] >= 65:
				goto st77
			}
		default:
			goto st77
		}
		goto st0
	st110:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof110
		}
	st_case_110:
		switch lex.data[(lex.p)] {
		case 39:
			goto st111
		case 58:
			goto st111
		case 114:
			goto st148
		}
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st133
			}
		case lex.data[(lex.p)] > 90:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st111:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof111
		}
	st_case_111:
		switch lex.data[(lex.p)] {
		case 32:
			goto st112
		case 39:
			goto st111
		case 42:
			goto st111
		case 95:
			goto st111
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st111
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st112:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof112
		}
	st_case_112:
		switch lex.data[(lex.p)] {
		case 39:
			goto st113
		case 58:
			goto st113
		}
		switch {
		case lex.data[(lex.p)] < 65:
			if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
				goto st118
			}
		case lex.data[(lex.p)] > 90:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st113
			}
		default:
			goto st113
		}
		goto st0
	st113:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof113
		}
	st_case_113:
		switch lex.data[(lex.p)] {
		case 32:
			goto st114
		case 39:
			goto st113
		case 42:
			goto st113
		case 95:
			goto st113
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st113
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st113
			}
		default:
			goto st113
		}
		goto st0
	st114:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof114
		}
	st_case_114:
		if lex.data[(lex.p)] == 46 {
			goto st115
		}
		goto st0
	st115:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof115
		}
	st_case_115:
		if lex.data[(lex.p)] == 46 {
			goto st116
		}
		goto st0
	st116:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof116
		}
	st_case_116:
		if lex.data[(lex.p)] == 46 {
			goto st117
		}
		goto st0
	st117:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof117
		}
	st_case_117:
		if lex.data[(lex.p)] == 62 {
			goto tr95
		}
		goto st0
	st118:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof118
		}
	st_case_118:
		if lex.data[(lex.p)] == 46 {
			goto st119
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st131
		}
		goto st0
	st119:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof119
		}
	st_case_119:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st120
		}
		goto st0
	st120:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof120
		}
	st_case_120:
		if lex.data[(lex.p)] == 46 {
			goto st121
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st129
		}
		goto st0
	st121:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof121
		}
	st_case_121:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st122
		}
		goto st0
	st122:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof122
		}
	st_case_122:
		if lex.data[(lex.p)] == 46 {
			goto st123
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st127
		}
		goto st0
	st123:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof123
		}
	st_case_123:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st124
		}
		goto st0
	st124:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof124
		}
	st_case_124:
		if lex.data[(lex.p)] == 32 {
			goto st114
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st125
		}
		goto st0
	st125:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof125
		}
	st_case_125:
		if lex.data[(lex.p)] == 32 {
			goto st114
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st126
		}
		goto st0
	st126:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof126
		}
	st_case_126:
		if lex.data[(lex.p)] == 32 {
			goto st114
		}
		goto st0
	st127:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof127
		}
	st_case_127:
		if lex.data[(lex.p)] == 46 {
			goto st123
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st128
		}
		goto st0
	st128:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof128
		}
	st_case_128:
		if lex.data[(lex.p)] == 46 {
			goto st123
		}
		goto st0
	st129:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof129
		}
	st_case_129:
		if lex.data[(lex.p)] == 46 {
			goto st121
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st130
		}
		goto st0
	st130:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof130
		}
	st_case_130:
		if lex.data[(lex.p)] == 46 {
			goto st121
		}
		goto st0
	st131:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof131
		}
	st_case_131:
		if lex.data[(lex.p)] == 46 {
			goto st119
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st132
		}
		goto st0
	st132:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof132
		}
	st_case_132:
		if lex.data[(lex.p)] == 46 {
			goto st119
		}
		goto st0
	st133:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof133
		}
	st_case_133:
		if lex.data[(lex.p)] == 46 {
			goto st134
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st146
		}
		goto st0
	st134:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof134
		}
	st_case_134:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st135
		}
		goto st0
	st135:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof135
		}
	st_case_135:
		if lex.data[(lex.p)] == 46 {
			goto st136
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st144
		}
		goto st0
	st136:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof136
		}
	st_case_136:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st137
		}
		goto st0
	st137:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof137
		}
	st_case_137:
		if lex.data[(lex.p)] == 46 {
			goto st138
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st142
		}
		goto st0
	st138:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof138
		}
	st_case_138:
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st139
		}
		goto st0
	st139:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof139
		}
	st_case_139:
		if lex.data[(lex.p)] == 32 {
			goto st112
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st140
		}
		goto st0
	st140:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof140
		}
	st_case_140:
		if lex.data[(lex.p)] == 32 {
			goto st112
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st141
		}
		goto st0
	st141:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof141
		}
	st_case_141:
		if lex.data[(lex.p)] == 32 {
			goto st112
		}
		goto st0
	st142:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof142
		}
	st_case_142:
		if lex.data[(lex.p)] == 46 {
			goto st138
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st143
		}
		goto st0
	st143:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof143
		}
	st_case_143:
		if lex.data[(lex.p)] == 46 {
			goto st138
		}
		goto st0
	st144:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof144
		}
	st_case_144:
		if lex.data[(lex.p)] == 46 {
			goto st136
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st145
		}
		goto st0
	st145:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof145
		}
	st_case_145:
		if lex.data[(lex.p)] == 46 {
			goto st136
		}
		goto st0
	st146:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof146
		}
	st_case_146:
		if lex.data[(lex.p)] == 46 {
			goto st134
		}
		if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
			goto st147
		}
		goto st0
	st147:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof147
		}
	st_case_147:
		if lex.data[(lex.p)] == 46 {
			goto st134
		}
		goto st0
	st148:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof148
		}
	st_case_148:
		switch lex.data[(lex.p)] {
		case 32:
			goto st112
		case 39:
			goto st111
		case 42:
			goto st111
		case 95:
			goto st111
		case 101:
			goto st149
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st111
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st149:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof149
		}
	st_case_149:
		switch lex.data[(lex.p)] {
		case 32:
			goto st112
		case 39:
			goto st111
		case 42:
			goto st111
		case 95:
			goto st111
		case 115:
			goto st150
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st111
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st150:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof150
		}
	st_case_150:
		switch lex.data[(lex.p)] {
		case 32:
			goto st112
		case 39:
			goto st111
		case 42:
			goto st111
		case 95:
			goto st111
		case 117:
			goto st151
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st111
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st151:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof151
		}
	st_case_151:
		switch lex.data[(lex.p)] {
		case 32:
			goto st112
		case 39:
			goto st111
		case 42:
			goto st111
		case 95:
			goto st111
		case 109:
			goto st152
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st111
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st152:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof152
		}
	st_case_152:
		switch lex.data[(lex.p)] {
		case 32:
			goto st112
		case 39:
			goto st111
		case 42:
			goto st111
		case 95:
			goto st111
		case 101:
			goto st153
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st111
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st153:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof153
		}
	st_case_153:
		switch lex.data[(lex.p)] {
		case 32:
			goto st112
		case 39:
			goto st111
		case 42:
			goto st111
		case 95:
			goto st111
		case 100:
			goto st154
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st111
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st154:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof154
		}
	st_case_154:
		switch lex.data[(lex.p)] {
		case 32:
			goto st112
		case 39:
			goto st111
		case 42:
			goto st111
		case 62:
			goto tr93
		case 95:
			goto st111
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st111
			}
		case lex.data[(lex.p)] > 58:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st111
			}
		default:
			goto st111
		}
		goto st0
	st183:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof183
		}
	st_case_183:
		switch lex.data[(lex.p)] {
		case 62:
			goto tr225
		case 64:
			goto tr226
		}
		goto tr224
	st155:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof155
		}
	st_case_155:
		if lex.data[(lex.p)] == 62 {
			goto tr162
		}
		goto st0
	st184:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof184
		}
	st_case_184:
		switch lex.data[(lex.p)] {
		case 39:
			goto tr227
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto tr227
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto st186
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] < 97:
				if 71 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 90 {
					goto tr10
				}
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			default:
				goto st202
			}
		default:
			goto tr229
		}
		goto tr194
	tr227:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:75
		lex.act = 8
		goto st185
	tr185:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st185
	st185:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof185
		}
	st_case_185:
//line lex.go:3736
		switch lex.data[(lex.p)] {
		case 39:
			goto tr227
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto tr227
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 57:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 65:
				goto tr10
			}
		default:
			goto tr227
		}
		goto tr9
	st186:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof186
		}
	st_case_186:
		switch lex.data[(lex.p)] {
		case 39:
			goto tr227
		case 42:
			goto st160
		case 58:
			goto tr232
		case 95:
			goto tr227
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 57:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 65:
				goto tr10
			}
		default:
			goto tr227
		}
		goto tr231
	tr232:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st187
	st187:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof187
		}
	st_case_187:
//line lex.go:3810
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto tr233
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto tr233
			}
		default:
			goto st57
		}
		goto tr194
	tr233:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st188
	st188:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof188
		}
	st_case_188:
//line lex.go:3856
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto st189
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto st189
			}
		default:
			goto st58
		}
		goto tr194
	st189:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof189
		}
	st_case_189:
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto tr235
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 57:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st160
			}
		default:
			goto st160
		}
		goto tr194
	tr235:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st190
	st190:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof190
		}
	st_case_190:
//line lex.go:3930
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto tr236
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto tr236
			}
		default:
			goto st60
		}
		goto tr194
	tr236:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st191
	st191:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof191
		}
	st_case_191:
//line lex.go:3976
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto st192
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto st192
			}
		default:
			goto st61
		}
		goto tr194
	st192:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof192
		}
	st_case_192:
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto tr238
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 57:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st160
			}
		default:
			goto st160
		}
		goto tr194
	tr238:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st193
	st193:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof193
		}
	st_case_193:
//line lex.go:4050
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto tr239
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto tr239
			}
		default:
			goto st63
		}
		goto tr194
	tr239:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st194
	st194:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof194
		}
	st_case_194:
//line lex.go:4096
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto st195
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto st195
			}
		default:
			goto st64
		}
		goto tr194
	st195:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof195
		}
	st_case_195:
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto tr241
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 57:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st160
			}
		default:
			goto st160
		}
		goto tr194
	tr241:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st196
	st196:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof196
		}
	st_case_196:
//line lex.go:4170
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto tr242
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto tr242
			}
		default:
			goto st66
		}
		goto tr194
	tr242:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st197
	st197:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof197
		}
	st_case_197:
//line lex.go:4216
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto st198
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto st198
			}
		default:
			goto st67
		}
		goto tr194
	st198:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof198
		}
	st_case_198:
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto tr244
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 57:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st160
			}
		default:
			goto st160
		}
		goto tr194
	tr244:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st199
	st199:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof199
		}
	st_case_199:
//line lex.go:4290
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto st200
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto st200
			}
		default:
			goto st69
		}
		goto tr194
	st200:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof200
		}
	st_case_200:
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 58:
			switch {
			case lex.data[(lex.p)] > 70:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 65:
				goto tr74
			}
		default:
			goto st160
		}
		goto tr194
	tr229:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:75
		lex.act = 8
		goto st201
	st201:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof201
		}
	st_case_201:
//line lex.go:4367
		switch lex.data[(lex.p)] {
		case 39:
			goto tr10
		case 58:
			goto st56
		case 95:
			goto tr10
		}
		switch {
		case lex.data[(lex.p)] > 57:
			if 65 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 90 {
				goto tr10
			}
		case lex.data[(lex.p)] >= 48:
			goto tr10
		}
		goto tr231
	st202:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof202
		}
	st_case_202:
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto tr232
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 57:
			if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
				goto st160
			}
		default:
			goto st160
		}
		goto tr194
	st203:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof203
		}
	st_case_203:
		switch lex.data[(lex.p)] {
		case 39:
			goto tr227
		case 42:
			goto st160
		case 58:
			goto st160
		case 85:
			goto st204
		case 95:
			goto tr227
		}
		switch {
		case lex.data[(lex.p)] < 48:
			if 45 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 46 {
				goto st160
			}
		case lex.data[(lex.p)] > 57:
			switch {
			case lex.data[(lex.p)] > 90:
				if 97 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 65:
				goto tr10
			}
		default:
			goto tr227
		}
		goto tr194
	st204:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof204
		}
	st_case_204:
		switch lex.data[(lex.p)] {
		case 39:
			goto tr10
		case 76:
			goto st205
		case 95:
			goto tr10
		}
		switch {
		case lex.data[(lex.p)] > 57:
			if 65 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 90 {
				goto tr10
			}
		case lex.data[(lex.p)] >= 48:
			goto tr10
		}
		goto tr231
	st205:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof205
		}
	st_case_205:
		switch lex.data[(lex.p)] {
		case 39:
			goto tr10
		case 76:
			goto tr248
		case 95:
			goto tr10
		}
		switch {
		case lex.data[(lex.p)] > 57:
			if 65 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 90 {
				goto tr10
			}
		case lex.data[(lex.p)] >= 48:
			goto tr10
		}
		goto tr231
	st156:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof156
		}
	st_case_156:
		switch lex.data[(lex.p)] {
		case 39:
			goto st156
		case 95:
			goto st156
		}
		if 65 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 90 {
			goto st9
		}
		goto st0
	tr189:
//line NONE:1
		lex.te = (lex.p) + 1

//line straceLex.rl:77
		lex.act = 10
		goto st206
	st206:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof206
		}
	st_case_206:
//line lex.go:4519
		switch lex.data[(lex.p)] {
		case 39:
			goto st160
		case 42:
			goto st160
		case 58:
			goto st160
		case 95:
			goto st160
		}
		switch {
		case lex.data[(lex.p)] < 65:
			switch {
			case lex.data[(lex.p)] > 46:
				if 48 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 57 {
					goto st202
				}
			case lex.data[(lex.p)] >= 45:
				goto st160
			}
		case lex.data[(lex.p)] > 70:
			switch {
			case lex.data[(lex.p)] > 102:
				if 103 <= lex.data[(lex.p)] && lex.data[(lex.p)] <= 122 {
					goto st160
				}
			case lex.data[(lex.p)] >= 97:
				goto st202
			}
		default:
			goto st70
		}
		goto tr194
	tr249:
//line straceLex.rl:65
		lex.te = (lex.p) + 1

		goto st207
	tr251:
//line straceLex.rl:65
		lex.te = (lex.p)
		(lex.p)--

		goto st207
	tr252:
//line straceLex.rl:66
		lex.te = (lex.p) + 1
		{
			{
				goto st157
			}
		}
		goto st207
	st207:
//line NONE:1
		lex.ts = 0

		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof207
		}
	st_case_207:
//line NONE:1
		lex.ts = (lex.p)

//line lex.go:4580
		if lex.data[(lex.p)] == 42 {
			goto st208
		}
		goto tr249
	st208:
		if (lex.p)++; (lex.p) == (lex.pe) {
			goto _test_eof208
		}
	st_case_208:
		if lex.data[(lex.p)] == 47 {
			goto tr252
		}
		goto tr251
	st_out:
	_test_eof157:
		lex.cs = 157
		goto _test_eof
	_test_eof1:
		lex.cs = 1
		goto _test_eof
	_test_eof2:
		lex.cs = 2
		goto _test_eof
	_test_eof158:
		lex.cs = 158
		goto _test_eof
	_test_eof3:
		lex.cs = 3
		goto _test_eof
	_test_eof4:
		lex.cs = 4
		goto _test_eof
	_test_eof5:
		lex.cs = 5
		goto _test_eof
	_test_eof6:
		lex.cs = 6
		goto _test_eof
	_test_eof7:
		lex.cs = 7
		goto _test_eof
	_test_eof8:
		lex.cs = 8
		goto _test_eof
	_test_eof159:
		lex.cs = 159
		goto _test_eof
	_test_eof160:
		lex.cs = 160
		goto _test_eof
	_test_eof9:
		lex.cs = 9
		goto _test_eof
	_test_eof161:
		lex.cs = 161
		goto _test_eof
	_test_eof162:
		lex.cs = 162
		goto _test_eof
	_test_eof10:
		lex.cs = 10
		goto _test_eof
	_test_eof11:
		lex.cs = 11
		goto _test_eof
	_test_eof12:
		lex.cs = 12
		goto _test_eof
	_test_eof13:
		lex.cs = 13
		goto _test_eof
	_test_eof14:
		lex.cs = 14
		goto _test_eof
	_test_eof15:
		lex.cs = 15
		goto _test_eof
	_test_eof16:
		lex.cs = 16
		goto _test_eof
	_test_eof17:
		lex.cs = 17
		goto _test_eof
	_test_eof18:
		lex.cs = 18
		goto _test_eof
	_test_eof19:
		lex.cs = 19
		goto _test_eof
	_test_eof20:
		lex.cs = 20
		goto _test_eof
	_test_eof21:
		lex.cs = 21
		goto _test_eof
	_test_eof22:
		lex.cs = 22
		goto _test_eof
	_test_eof23:
		lex.cs = 23
		goto _test_eof
	_test_eof24:
		lex.cs = 24
		goto _test_eof
	_test_eof25:
		lex.cs = 25
		goto _test_eof
	_test_eof26:
		lex.cs = 26
		goto _test_eof
	_test_eof163:
		lex.cs = 163
		goto _test_eof
	_test_eof27:
		lex.cs = 27
		goto _test_eof
	_test_eof164:
		lex.cs = 164
		goto _test_eof
	_test_eof165:
		lex.cs = 165
		goto _test_eof
	_test_eof166:
		lex.cs = 166
		goto _test_eof
	_test_eof167:
		lex.cs = 167
		goto _test_eof
	_test_eof28:
		lex.cs = 28
		goto _test_eof
	_test_eof29:
		lex.cs = 29
		goto _test_eof
	_test_eof30:
		lex.cs = 30
		goto _test_eof
	_test_eof168:
		lex.cs = 168
		goto _test_eof
	_test_eof169:
		lex.cs = 169
		goto _test_eof
	_test_eof31:
		lex.cs = 31
		goto _test_eof
	_test_eof32:
		lex.cs = 32
		goto _test_eof
	_test_eof170:
		lex.cs = 170
		goto _test_eof
	_test_eof171:
		lex.cs = 171
		goto _test_eof
	_test_eof172:
		lex.cs = 172
		goto _test_eof
	_test_eof173:
		lex.cs = 173
		goto _test_eof
	_test_eof33:
		lex.cs = 33
		goto _test_eof
	_test_eof34:
		lex.cs = 34
		goto _test_eof
	_test_eof35:
		lex.cs = 35
		goto _test_eof
	_test_eof36:
		lex.cs = 36
		goto _test_eof
	_test_eof174:
		lex.cs = 174
		goto _test_eof
	_test_eof175:
		lex.cs = 175
		goto _test_eof
	_test_eof37:
		lex.cs = 37
		goto _test_eof
	_test_eof38:
		lex.cs = 38
		goto _test_eof
	_test_eof39:
		lex.cs = 39
		goto _test_eof
	_test_eof40:
		lex.cs = 40
		goto _test_eof
	_test_eof41:
		lex.cs = 41
		goto _test_eof
	_test_eof42:
		lex.cs = 42
		goto _test_eof
	_test_eof43:
		lex.cs = 43
		goto _test_eof
	_test_eof44:
		lex.cs = 44
		goto _test_eof
	_test_eof45:
		lex.cs = 45
		goto _test_eof
	_test_eof46:
		lex.cs = 46
		goto _test_eof
	_test_eof47:
		lex.cs = 47
		goto _test_eof
	_test_eof48:
		lex.cs = 48
		goto _test_eof
	_test_eof49:
		lex.cs = 49
		goto _test_eof
	_test_eof50:
		lex.cs = 50
		goto _test_eof
	_test_eof176:
		lex.cs = 176
		goto _test_eof
	_test_eof51:
		lex.cs = 51
		goto _test_eof
	_test_eof52:
		lex.cs = 52
		goto _test_eof
	_test_eof53:
		lex.cs = 53
		goto _test_eof
	_test_eof54:
		lex.cs = 54
		goto _test_eof
	_test_eof177:
		lex.cs = 177
		goto _test_eof
	_test_eof55:
		lex.cs = 55
		goto _test_eof
	_test_eof178:
		lex.cs = 178
		goto _test_eof
	_test_eof179:
		lex.cs = 179
		goto _test_eof
	_test_eof56:
		lex.cs = 56
		goto _test_eof
	_test_eof57:
		lex.cs = 57
		goto _test_eof
	_test_eof58:
		lex.cs = 58
		goto _test_eof
	_test_eof59:
		lex.cs = 59
		goto _test_eof
	_test_eof60:
		lex.cs = 60
		goto _test_eof
	_test_eof61:
		lex.cs = 61
		goto _test_eof
	_test_eof62:
		lex.cs = 62
		goto _test_eof
	_test_eof63:
		lex.cs = 63
		goto _test_eof
	_test_eof64:
		lex.cs = 64
		goto _test_eof
	_test_eof65:
		lex.cs = 65
		goto _test_eof
	_test_eof66:
		lex.cs = 66
		goto _test_eof
	_test_eof67:
		lex.cs = 67
		goto _test_eof
	_test_eof68:
		lex.cs = 68
		goto _test_eof
	_test_eof69:
		lex.cs = 69
		goto _test_eof
	_test_eof70:
		lex.cs = 70
		goto _test_eof
	_test_eof71:
		lex.cs = 71
		goto _test_eof
	_test_eof180:
		lex.cs = 180
		goto _test_eof
	_test_eof181:
		lex.cs = 181
		goto _test_eof
	_test_eof72:
		lex.cs = 72
		goto _test_eof
	_test_eof73:
		lex.cs = 73
		goto _test_eof
	_test_eof74:
		lex.cs = 74
		goto _test_eof
	_test_eof75:
		lex.cs = 75
		goto _test_eof
	_test_eof76:
		lex.cs = 76
		goto _test_eof
	_test_eof77:
		lex.cs = 77
		goto _test_eof
	_test_eof78:
		lex.cs = 78
		goto _test_eof
	_test_eof79:
		lex.cs = 79
		goto _test_eof
	_test_eof80:
		lex.cs = 80
		goto _test_eof
	_test_eof81:
		lex.cs = 81
		goto _test_eof
	_test_eof82:
		lex.cs = 82
		goto _test_eof
	_test_eof83:
		lex.cs = 83
		goto _test_eof
	_test_eof84:
		lex.cs = 84
		goto _test_eof
	_test_eof85:
		lex.cs = 85
		goto _test_eof
	_test_eof182:
		lex.cs = 182
		goto _test_eof
	_test_eof86:
		lex.cs = 86
		goto _test_eof
	_test_eof87:
		lex.cs = 87
		goto _test_eof
	_test_eof88:
		lex.cs = 88
		goto _test_eof
	_test_eof89:
		lex.cs = 89
		goto _test_eof
	_test_eof90:
		lex.cs = 90
		goto _test_eof
	_test_eof91:
		lex.cs = 91
		goto _test_eof
	_test_eof92:
		lex.cs = 92
		goto _test_eof
	_test_eof93:
		lex.cs = 93
		goto _test_eof
	_test_eof94:
		lex.cs = 94
		goto _test_eof
	_test_eof95:
		lex.cs = 95
		goto _test_eof
	_test_eof96:
		lex.cs = 96
		goto _test_eof
	_test_eof97:
		lex.cs = 97
		goto _test_eof
	_test_eof98:
		lex.cs = 98
		goto _test_eof
	_test_eof99:
		lex.cs = 99
		goto _test_eof
	_test_eof100:
		lex.cs = 100
		goto _test_eof
	_test_eof101:
		lex.cs = 101
		goto _test_eof
	_test_eof102:
		lex.cs = 102
		goto _test_eof
	_test_eof103:
		lex.cs = 103
		goto _test_eof
	_test_eof104:
		lex.cs = 104
		goto _test_eof
	_test_eof105:
		lex.cs = 105
		goto _test_eof
	_test_eof106:
		lex.cs = 106
		goto _test_eof
	_test_eof107:
		lex.cs = 107
		goto _test_eof
	_test_eof108:
		lex.cs = 108
		goto _test_eof
	_test_eof109:
		lex.cs = 109
		goto _test_eof
	_test_eof110:
		lex.cs = 110
		goto _test_eof
	_test_eof111:
		lex.cs = 111
		goto _test_eof
	_test_eof112:
		lex.cs = 112
		goto _test_eof
	_test_eof113:
		lex.cs = 113
		goto _test_eof
	_test_eof114:
		lex.cs = 114
		goto _test_eof
	_test_eof115:
		lex.cs = 115
		goto _test_eof
	_test_eof116:
		lex.cs = 116
		goto _test_eof
	_test_eof117:
		lex.cs = 117
		goto _test_eof
	_test_eof118:
		lex.cs = 118
		goto _test_eof
	_test_eof119:
		lex.cs = 119
		goto _test_eof
	_test_eof120:
		lex.cs = 120
		goto _test_eof
	_test_eof121:
		lex.cs = 121
		goto _test_eof
	_test_eof122:
		lex.cs = 122
		goto _test_eof
	_test_eof123:
		lex.cs = 123
		goto _test_eof
	_test_eof124:
		lex.cs = 124
		goto _test_eof
	_test_eof125:
		lex.cs = 125
		goto _test_eof
	_test_eof126:
		lex.cs = 126
		goto _test_eof
	_test_eof127:
		lex.cs = 127
		goto _test_eof
	_test_eof128:
		lex.cs = 128
		goto _test_eof
	_test_eof129:
		lex.cs = 129
		goto _test_eof
	_test_eof130:
		lex.cs = 130
		goto _test_eof
	_test_eof131:
		lex.cs = 131
		goto _test_eof
	_test_eof132:
		lex.cs = 132
		goto _test_eof
	_test_eof133:
		lex.cs = 133
		goto _test_eof
	_test_eof134:
		lex.cs = 134
		goto _test_eof
	_test_eof135:
		lex.cs = 135
		goto _test_eof
	_test_eof136:
		lex.cs = 136
		goto _test_eof
	_test_eof137:
		lex.cs = 137
		goto _test_eof
	_test_eof138:
		lex.cs = 138
		goto _test_eof
	_test_eof139:
		lex.cs = 139
		goto _test_eof
	_test_eof140:
		lex.cs = 140
		goto _test_eof
	_test_eof141:
		lex.cs = 141
		goto _test_eof
	_test_eof142:
		lex.cs = 142
		goto _test_eof
	_test_eof143:
		lex.cs = 143
		goto _test_eof
	_test_eof144:
		lex.cs = 144
		goto _test_eof
	_test_eof145:
		lex.cs = 145
		goto _test_eof
	_test_eof146:
		lex.cs = 146
		goto _test_eof
	_test_eof147:
		lex.cs = 147
		goto _test_eof
	_test_eof148:
		lex.cs = 148
		goto _test_eof
	_test_eof149:
		lex.cs = 149
		goto _test_eof
	_test_eof150:
		lex.cs = 150
		goto _test_eof
	_test_eof151:
		lex.cs = 151
		goto _test_eof
	_test_eof152:
		lex.cs = 152
		goto _test_eof
	_test_eof153:
		lex.cs = 153
		goto _test_eof
	_test_eof154:
		lex.cs = 154
		goto _test_eof
	_test_eof183:
		lex.cs = 183
		goto _test_eof
	_test_eof155:
		lex.cs = 155
		goto _test_eof
	_test_eof184:
		lex.cs = 184
		goto _test_eof
	_test_eof185:
		lex.cs = 185
		goto _test_eof
	_test_eof186:
		lex.cs = 186
		goto _test_eof
	_test_eof187:
		lex.cs = 187
		goto _test_eof
	_test_eof188:
		lex.cs = 188
		goto _test_eof
	_test_eof189:
		lex.cs = 189
		goto _test_eof
	_test_eof190:
		lex.cs = 190
		goto _test_eof
	_test_eof191:
		lex.cs = 191
		goto _test_eof
	_test_eof192:
		lex.cs = 192
		goto _test_eof
	_test_eof193:
		lex.cs = 193
		goto _test_eof
	_test_eof194:
		lex.cs = 194
		goto _test_eof
	_test_eof195:
		lex.cs = 195
		goto _test_eof
	_test_eof196:
		lex.cs = 196
		goto _test_eof
	_test_eof197:
		lex.cs = 197
		goto _test_eof
	_test_eof198:
		lex.cs = 198
		goto _test_eof
	_test_eof199:
		lex.cs = 199
		goto _test_eof
	_test_eof200:
		lex.cs = 200
		goto _test_eof
	_test_eof201:
		lex.cs = 201
		goto _test_eof
	_test_eof202:
		lex.cs = 202
		goto _test_eof
	_test_eof203:
		lex.cs = 203
		goto _test_eof
	_test_eof204:
		lex.cs = 204
		goto _test_eof
	_test_eof205:
		lex.cs = 205
		goto _test_eof
	_test_eof156:
		lex.cs = 156
		goto _test_eof
	_test_eof206:
		lex.cs = 206
		goto _test_eof
	_test_eof207:
		lex.cs = 207
		goto _test_eof
	_test_eof208:
		lex.cs = 208
		goto _test_eof

	_test_eof:
		{
		}
		if (lex.p) == eof {
			switch lex.cs {
			case 158:
				goto tr193
			case 159:
				goto tr194
			case 160:
				goto tr194
			case 9:
				goto tr9
			case 161:
				goto tr9
			case 162:
				goto tr195
			case 10:
				goto tr11
			case 11:
				goto tr11
			case 12:
				goto tr11
			case 13:
				goto tr9
			case 14:
				goto tr9
			case 15:
				goto tr9
			case 16:
				goto tr9
			case 17:
				goto tr9
			case 18:
				goto tr9
			case 19:
				goto tr9
			case 20:
				goto tr9
			case 21:
				goto tr9
			case 22:
				goto tr9
			case 23:
				goto tr9
			case 24:
				goto tr9
			case 25:
				goto tr9
			case 26:
				goto tr9
			case 163:
				goto tr197
			case 164:
				goto tr199
			case 165:
				goto tr201
			case 166:
				goto tr206
			case 167:
				goto tr206
			case 28:
				goto tr9
			case 29:
				goto tr9
			case 30:
				goto tr9
			case 168:
				goto tr194
			case 169:
				goto tr194
			case 31:
				goto tr9
			case 32:
				goto tr9
			case 170:
				goto tr206
			case 171:
				goto tr206
			case 172:
				goto tr206
			case 173:
				goto tr201
			case 33:
				goto tr36
			case 34:
				goto tr36
			case 35:
				goto tr36
			case 36:
				goto tr36
			case 174:
				goto tr201
			case 175:
				goto tr201
			case 37:
				goto tr36
			case 38:
				goto tr36
			case 39:
				goto tr36
			case 40:
				goto tr36
			case 41:
				goto tr36
			case 42:
				goto tr36
			case 43:
				goto tr36
			case 44:
				goto tr36
			case 45:
				goto tr36
			case 46:
				goto tr36
			case 47:
				goto tr36
			case 48:
				goto tr36
			case 49:
				goto tr36
			case 50:
				goto tr36
			case 176:
				goto tr218
			case 51:
				goto tr55
			case 52:
				goto tr55
			case 53:
				goto tr55
			case 54:
				goto tr55
			case 177:
				goto tr218
			case 55:
				goto tr55
			case 178:
				goto tr218
			case 179:
				goto tr201
			case 56:
				goto tr9
			case 57:
				goto tr9
			case 58:
				goto tr9
			case 59:
				goto tr9
			case 60:
				goto tr9
			case 61:
				goto tr9
			case 62:
				goto tr9
			case 63:
				goto tr9
			case 64:
				goto tr9
			case 65:
				goto tr9
			case 66:
				goto tr9
			case 67:
				goto tr9
			case 68:
				goto tr9
			case 69:
				goto tr9
			case 70:
				goto tr9
			case 71:
				goto tr36
			case 180:
				goto tr221
			case 181:
				goto tr201
			case 182:
				goto tr222
			case 86:
				goto tr94
			case 183:
				goto tr224
			case 184:
				goto tr194
			case 185:
				goto tr9
			case 186:
				goto tr231
			case 187:
				goto tr194
			case 188:
				goto tr194
			case 189:
				goto tr194
			case 190:
				goto tr194
			case 191:
				goto tr194
			case 192:
				goto tr194
			case 193:
				goto tr194
			case 194:
				goto tr194
			case 195:
				goto tr194
			case 196:
				goto tr194
			case 197:
				goto tr194
			case 198:
				goto tr194
			case 199:
				goto tr194
			case 200:
				goto tr194
			case 201:
				goto tr231
			case 202:
				goto tr194
			case 203:
				goto tr194
			case 204:
				goto tr231
			case 205:
				goto tr231
			case 206:
				goto tr194
			case 208:
				goto tr251
			}
		}

	_out:
		{
		}
	}

//line straceLex.rl:110

	return tok
}

func (lex *Stracelexer) Error(e string) {
	fmt.Println("error:", e)
}

func ParseString(s string) string {
	var decoded []byte
	var err error
	var strippedStr string
	strippedStr = strings.Replace(s, `\x`, "", -1)
	strippedStr = strings.Replace(strippedStr, `"`, "", -1)

	if decoded, err = hex.DecodeString(strippedStr); err != nil {
		log.Logf(2, "failed to decode string: %s, with error: %s", s, err.Error())
		decoded = []byte(strippedStr)
	}
	return string(decoded)
}
