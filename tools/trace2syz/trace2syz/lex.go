
//line straceLex.rl:1
//nolint
package trace2syz

import (
    "fmt"
    "encoding/hex"
    "strconv"
    "strings"
    "github.com/google/syzkaller/pkg/log"
)


//line lex.go:16
const strace_start int = 174
const strace_first_final int = 174
const strace_error int = 0

const strace_en_comment int = 218
const strace_en_main int = 174


//line straceLex.rl:18


type Stracelexer struct {
    result *Syscall
    data []byte
    p, pe, cs int
    ts, te, act int
}

func newStraceLexer (data []byte) *Stracelexer {
    lex := &Stracelexer {
        data: data,
        pe: len(data),
    }

    
//line lex.go:42
	{
	 lex.cs = strace_start
	 lex.ts = 0
	 lex.te = 0
	 lex.act = 0
	}

//line straceLex.rl:34
    return lex
}

func (lex *Stracelexer) Lex(out *StraceSymType) int {
    eof := lex.pe
    tok := 0
    
//line lex.go:58
	{
	if ( lex.p) == ( lex.pe) {
		goto _test_eof
	}
	switch  lex.cs {
	case 174:
		goto st_case_174
	case 0:
		goto st_case_0
	case 1:
		goto st_case_1
	case 2:
		goto st_case_2
	case 175:
		goto st_case_175
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
	case 9:
		goto st_case_9
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
	case 27:
		goto st_case_27
	case 28:
		goto st_case_28
	case 29:
		goto st_case_29
	case 30:
		goto st_case_30
	case 31:
		goto st_case_31
	case 32:
		goto st_case_32
	case 33:
		goto st_case_33
	case 34:
		goto st_case_34
	case 35:
		goto st_case_35
	case 36:
		goto st_case_36
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
	case 51:
		goto st_case_51
	case 176:
		goto st_case_176
	case 52:
		goto st_case_52
	case 53:
		goto st_case_53
	case 177:
		goto st_case_177
	case 54:
		goto st_case_54
	case 55:
		goto st_case_55
	case 178:
		goto st_case_178
	case 179:
		goto st_case_179
	case 180:
		goto st_case_180
	case 181:
		goto st_case_181
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
	case 72:
		goto st_case_72
	case 73:
		goto st_case_73
	case 74:
		goto st_case_74
	case 182:
		goto st_case_182
	case 183:
		goto st_case_183
	case 184:
		goto st_case_184
	case 185:
		goto st_case_185
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
	case 86:
		goto st_case_86
	case 87:
		goto st_case_87
	case 88:
		goto st_case_88
	case 186:
		goto st_case_186
	case 89:
		goto st_case_89
	case 90:
		goto st_case_90
	case 91:
		goto st_case_91
	case 92:
		goto st_case_92
	case 187:
		goto st_case_187
	case 93:
		goto st_case_93
	case 188:
		goto st_case_188
	case 189:
		goto st_case_189
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
	case 195:
		goto st_case_195
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
	case 155:
		goto st_case_155
	case 156:
		goto st_case_156
	case 157:
		goto st_case_157
	case 158:
		goto st_case_158
	case 159:
		goto st_case_159
	case 160:
		goto st_case_160
	case 161:
		goto st_case_161
	case 162:
		goto st_case_162
	case 163:
		goto st_case_163
	case 164:
		goto st_case_164
	case 165:
		goto st_case_165
	case 166:
		goto st_case_166
	case 167:
		goto st_case_167
	case 168:
		goto st_case_168
	case 169:
		goto st_case_169
	case 170:
		goto st_case_170
	case 171:
		goto st_case_171
	case 172:
		goto st_case_172
	case 196:
		goto st_case_196
	case 173:
		goto st_case_173
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
	case 206:
		goto st_case_206
	case 207:
		goto st_case_207
	case 208:
		goto st_case_208
	case 209:
		goto st_case_209
	case 210:
		goto st_case_210
	case 211:
		goto st_case_211
	case 212:
		goto st_case_212
	case 213:
		goto st_case_213
	case 214:
		goto st_case_214
	case 215:
		goto st_case_215
	case 216:
		goto st_case_216
	case 217:
		goto st_case_217
	case 218:
		goto st_case_218
	case 219:
		goto st_case_219
	}
	goto st_out
tr18:
//line straceLex.rl:74
 lex.te = ( lex.p)+1
{out.data = string(lex.data[lex.ts+1:lex.te-1]); tok=IPV4; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr29:
//line straceLex.rl:75
 lex.te = ( lex.p)+1
{out.data = string(lex.data[lex.ts+1:lex.te-1]); tok=IPV6; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr60:
//line straceLex.rl:107
( lex.p) = ( lex.te) - 1
{tok = COMMA;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr64:
//line NONE:1
	switch  lex.act {
	case 0:
	{{goto st0 }}
	case 3:
	{( lex.p) = ( lex.te) - 1
out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;{( lex.p)++;  lex.cs = 174; goto _out }}
	case 5:
	{( lex.p) = ( lex.te) - 1
out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 8, 64); tok = INT; {( lex.p)++;  lex.cs = 174; goto _out }}
	case 10:
	{( lex.p) = ( lex.te) - 1
tok = NULL; {( lex.p)++;  lex.cs = 174; goto _out }}
	case 11:
	{( lex.p) = ( lex.te) - 1
out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG; {( lex.p)++;  lex.cs = 174; goto _out }}
	case 13:
	{( lex.p) = ( lex.te) - 1
out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;{( lex.p)++;  lex.cs = 174; goto _out }}
	case 16:
	{( lex.p) = ( lex.te) - 1
tok = KEYWORD; {( lex.p)++;  lex.cs = 174; goto _out }}
	case 18:
	{( lex.p) = ( lex.te) - 1
tok = OR; {( lex.p)++;  lex.cs = 174; goto _out }}
	case 40:
	{( lex.p) = ( lex.te) - 1
tok = COMMA;{( lex.p)++;  lex.cs = 174; goto _out }}
	}
	
	goto st174
tr78:
//line straceLex.rl:81
 lex.te = ( lex.p)+1
{tok = UNFINISHED; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr79:
//line straceLex.rl:103
 lex.te = ( lex.p)+1
{tok = ARROW; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr80:
//line straceLex.rl:109
 lex.te = ( lex.p)+1
{{goto st218 }}
	goto st174
tr95:
//line straceLex.rl:108
( lex.p) = ( lex.te) - 1
{out.data = string(lex.data[lex.ts:lex.te]); tok = DATETIME; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr101:
//line straceLex.rl:72
( lex.p) = ( lex.te) - 1
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 8, 64); tok = INT; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr117:
//line straceLex.rl:84
 lex.te = ( lex.p)+1
{out.data = string(lex.data[lex.ts : lex.te]); tok = MAC; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr122:
//line straceLex.rl:101
 lex.te = ( lex.p)+1
{tok = LSHIFT; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr137:
//line straceLex.rl:82
( lex.p) = ( lex.te) - 1
{tok = RESUMED; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr138:
//line straceLex.rl:82
 lex.te = ( lex.p)+1
{tok = RESUMED; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr183:
//line straceLex.rl:102
 lex.te = ( lex.p)+1
{tok = RSHIFT; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr184:
//line straceLex.rl:111
 lex.te = ( lex.p)+1

	goto st174
tr185:
//line straceLex.rl:99
 lex.te = ( lex.p)+1
{tok = NOT;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr188:
//line straceLex.rl:88
 lex.te = ( lex.p)+1
{tok = LPAREN;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr189:
//line straceLex.rl:90
 lex.te = ( lex.p)+1
{tok = RPAREN;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr190:
//line straceLex.rl:93
 lex.te = ( lex.p)+1
{tok = TIMES; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr197:
//line straceLex.rl:97
 lex.te = ( lex.p)+1
{tok = COLON; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr201:
//line straceLex.rl:110
 lex.te = ( lex.p)+1
{tok = QUESTION; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr202:
//line straceLex.rl:89
 lex.te = ( lex.p)+1
{tok = AT; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr206:
//line straceLex.rl:91
 lex.te = ( lex.p)+1
{tok = LBRACKET_SQUARE;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr207:
//line straceLex.rl:92
 lex.te = ( lex.p)+1
{tok = RBRACKET_SQUARE;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr212:
//line straceLex.rl:94
 lex.te = ( lex.p)+1
{tok = LBRACKET;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr214:
//line straceLex.rl:95
 lex.te = ( lex.p)+1
{tok = RBRACKET;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr215:
//line straceLex.rl:100
 lex.te = ( lex.p)+1
{tok = ONESCOMP; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr216:
//line straceLex.rl:76
 lex.te = ( lex.p)
( lex.p)--
{out.data = ParseString(string(lex.data[lex.ts+1:lex.te-1])); tok = STRING_LITERAL;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr217:
//line straceLex.rl:98
 lex.te = ( lex.p)
( lex.p)--
{tok = AND;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr218:
//line straceLex.rl:106
 lex.te = ( lex.p)+1
{tok = LAND;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr219:
//line straceLex.rl:71
 lex.te = ( lex.p)
( lex.p)--
{out.val_double, _ = strconv.ParseFloat(string(lex.data[lex.ts : lex.te]), 64); tok= DOUBLE; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr220:
//line straceLex.rl:70
 lex.te = ( lex.p)
( lex.p)--
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr222:
//line straceLex.rl:107
 lex.te = ( lex.p)
( lex.p)--
{tok = COMMA;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr224:
//line straceLex.rl:72
 lex.te = ( lex.p)
( lex.p)--
{out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 8, 64); tok = INT; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr232:
//line straceLex.rl:108
 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = DATETIME; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr235:
//line straceLex.rl:73
 lex.te = ( lex.p)
( lex.p)--
{out.val_uint, _ = strconv.ParseUint(string(lex.data[lex.ts:lex.te]), 0, 64); tok = UINT;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr239:
//line straceLex.rl:82
 lex.te = ( lex.p)
( lex.p)--
{tok = RESUMED; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr241:
//line straceLex.rl:86
 lex.te = ( lex.p)
( lex.p)--
{tok = EQUALS;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr242:
//line straceLex.rl:87
 lex.te = ( lex.p)+1
{tok = LEQUAL; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr243:
//line straceLex.rl:104
 lex.te = ( lex.p)+1
{tok = ARROW; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr244:
//line straceLex.rl:80
 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr249:
//line straceLex.rl:78
 lex.te = ( lex.p)
( lex.p)--
{out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG; {( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr263:
//line straceLex.rl:96
 lex.te = ( lex.p)
( lex.p)--
{tok = OR;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
tr264:
//line straceLex.rl:105
 lex.te = ( lex.p)+1
{tok = LOR;{( lex.p)++;  lex.cs = 174; goto _out }}
	goto st174
	st174:
//line NONE:1
 lex.ts = 0

//line NONE:1
 lex.act = 0

		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof174
		}
	st_case_174:
//line NONE:1
 lex.ts = ( lex.p)

//line lex.go:780
		switch  lex.data[( lex.p)] {
		case 32:
			goto tr184
		case 33:
			goto tr185
		case 34:
			goto st1
		case 38:
			goto st176
		case 39:
			goto st52
		case 40:
			goto tr188
		case 41:
			goto tr189
		case 42:
			goto tr190
		case 43:
			goto st54
		case 44:
			goto tr192
		case 45:
			goto st73
		case 47:
			goto st74
		case 48:
			goto tr195
		case 58:
			goto tr197
		case 60:
			goto st113
		case 61:
			goto st196
		case 62:
			goto st173
		case 63:
			goto tr201
		case 64:
			goto tr202
		case 78:
			goto st203
		case 91:
			goto tr206
		case 93:
			goto tr207
		case 95:
			goto st52
		case 111:
			goto st207
		case 115:
			goto st208
		case 123:
			goto tr212
		case 124:
			goto st217
		case 125:
			goto tr214
		case 126:
			goto tr215
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			switch {
			case  lex.data[( lex.p)] > 13:
				if 49 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
					goto tr196
				}
			case  lex.data[( lex.p)] >= 9:
				goto tr184
			}
		case  lex.data[( lex.p)] > 70:
			switch {
			case  lex.data[( lex.p)] < 97:
				if 71 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
					goto tr204
				}
			case  lex.data[( lex.p)] > 102:
				if 103 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto tr209
				}
			default:
				goto tr208
			}
		default:
			goto st197
		}
		goto st0
st_case_0:
	st0:
		 lex.cs = 0
		goto _out
	st1:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof1
		}
	st_case_1:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 39:
			goto st3
		case 47:
			goto st2
		case 58:
			goto st25
		case 78:
			goto st49
		case 92:
			goto st2
		case 95:
			goto st3
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 40 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st4
			}
		default:
			goto st6
		}
		goto st0
	st2:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof2
		}
	st_case_2:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 47:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 58:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st175:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof175
		}
	st_case_175:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st175
		case 46:
			goto st175
		}
		goto tr216
	st3:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof3
		}
	st_case_3:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
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
		case  lex.data[( lex.p)] < 47:
			if 40 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 58:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st4
			}
		default:
			goto st2
		}
		goto st0
	st4:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof4
		}
	st_case_4:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 39:
			goto st5
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 40 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st5:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof5
		}
	st_case_5:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 39:
			goto st5
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 40 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st6:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof6
		}
	st_case_6:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 46:
			goto st7
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st22
		}
		goto st0
	st7:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof7
		}
	st_case_7:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st8
		}
		goto st0
	st8:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof8
		}
	st_case_8:
		if  lex.data[( lex.p)] == 46 {
			goto st9
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st19
		}
		goto st0
	st9:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof9
		}
	st_case_9:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st10
		}
		goto st0
	st10:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof10
		}
	st_case_10:
		if  lex.data[( lex.p)] == 46 {
			goto st11
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st16
		}
		goto st0
	st11:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof11
		}
	st_case_11:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st12
		}
		goto st0
	st12:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof12
		}
	st_case_12:
		if  lex.data[( lex.p)] == 34 {
			goto tr18
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st13
		}
		goto st0
	st13:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof13
		}
	st_case_13:
		if  lex.data[( lex.p)] == 34 {
			goto tr18
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st14
		}
		goto st0
	st14:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof14
		}
	st_case_14:
		if  lex.data[( lex.p)] == 34 {
			goto tr18
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st15
		}
		goto st0
	st15:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof15
		}
	st_case_15:
		if  lex.data[( lex.p)] == 34 {
			goto tr18
		}
		goto st0
	st16:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof16
		}
	st_case_16:
		if  lex.data[( lex.p)] == 46 {
			goto st11
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st17
		}
		goto st0
	st17:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof17
		}
	st_case_17:
		if  lex.data[( lex.p)] == 46 {
			goto st11
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st18
		}
		goto st0
	st18:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof18
		}
	st_case_18:
		if  lex.data[( lex.p)] == 46 {
			goto st11
		}
		goto st0
	st19:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof19
		}
	st_case_19:
		if  lex.data[( lex.p)] == 46 {
			goto st9
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st20
		}
		goto st0
	st20:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof20
		}
	st_case_20:
		if  lex.data[( lex.p)] == 46 {
			goto st9
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st21
		}
		goto st0
	st21:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof21
		}
	st_case_21:
		if  lex.data[( lex.p)] == 46 {
			goto st9
		}
		goto st0
	st22:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof22
		}
	st_case_22:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 46:
			goto st7
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st23
		}
		goto st0
	st23:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof23
		}
	st_case_23:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 46:
			goto st7
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st24
		}
		goto st0
	st24:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof24
		}
	st_case_24:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 46:
			goto st7
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 47:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 58:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st25:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof25
		}
	st_case_25:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 58:
			goto st26
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 47:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st26:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof26
		}
	st_case_26:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto tr29
		case 35:
			goto st2
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			switch {
			case  lex.data[( lex.p)] > 42:
				if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
					goto st27
				}
			case  lex.data[( lex.p)] >= 39:
				goto st2
			}
		case  lex.data[( lex.p)] > 70:
			switch {
			case  lex.data[( lex.p)] < 97:
				if 71 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
					goto st2
				}
			case  lex.data[( lex.p)] > 102:
				if 103 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			default:
				goto st28
			}
		default:
			goto st28
		}
		goto st0
	st27:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof27
		}
	st_case_27:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto tr29
		case 35:
			goto st2
		case 47:
			goto st2
		case 58:
			goto st29
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			switch {
			case  lex.data[( lex.p)] > 42:
				if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
					goto st28
				}
			case  lex.data[( lex.p)] >= 39:
				goto st2
			}
		case  lex.data[( lex.p)] > 70:
			switch {
			case  lex.data[( lex.p)] < 97:
				if 71 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
					goto st2
				}
			case  lex.data[( lex.p)] > 102:
				if 103 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			default:
				goto st28
			}
		default:
			goto st28
		}
		goto st0
	st28:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof28
		}
	st_case_28:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 47:
			goto st2
		case 58:
			goto st29
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			switch {
			case  lex.data[( lex.p)] > 42:
				if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
					goto st28
				}
			case  lex.data[( lex.p)] >= 39:
				goto st2
			}
		case  lex.data[( lex.p)] > 70:
			switch {
			case  lex.data[( lex.p)] < 97:
				if 71 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
					goto st2
				}
			case  lex.data[( lex.p)] > 102:
				if 103 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			default:
				goto st28
			}
		default:
			goto st28
		}
		goto st0
	st29:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof29
		}
	st_case_29:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st30
		}
		goto st0
	st30:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof30
		}
	st_case_30:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 46:
			goto st31
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st46
		}
		goto st0
	st31:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof31
		}
	st_case_31:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st32
		}
		goto st0
	st32:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof32
		}
	st_case_32:
		if  lex.data[( lex.p)] == 46 {
			goto st33
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st43
		}
		goto st0
	st33:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof33
		}
	st_case_33:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st34
		}
		goto st0
	st34:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof34
		}
	st_case_34:
		if  lex.data[( lex.p)] == 46 {
			goto st35
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st40
		}
		goto st0
	st35:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof35
		}
	st_case_35:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st36
		}
		goto st0
	st36:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof36
		}
	st_case_36:
		if  lex.data[( lex.p)] == 34 {
			goto tr29
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st37
		}
		goto st0
	st37:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof37
		}
	st_case_37:
		if  lex.data[( lex.p)] == 34 {
			goto tr29
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st38
		}
		goto st0
	st38:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof38
		}
	st_case_38:
		if  lex.data[( lex.p)] == 34 {
			goto tr29
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st39
		}
		goto st0
	st39:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof39
		}
	st_case_39:
		if  lex.data[( lex.p)] == 34 {
			goto tr29
		}
		goto st0
	st40:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof40
		}
	st_case_40:
		if  lex.data[( lex.p)] == 46 {
			goto st35
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st41
		}
		goto st0
	st41:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof41
		}
	st_case_41:
		if  lex.data[( lex.p)] == 46 {
			goto st35
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st42
		}
		goto st0
	st42:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof42
		}
	st_case_42:
		if  lex.data[( lex.p)] == 46 {
			goto st35
		}
		goto st0
	st43:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof43
		}
	st_case_43:
		if  lex.data[( lex.p)] == 46 {
			goto st33
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st44
		}
		goto st0
	st44:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof44
		}
	st_case_44:
		if  lex.data[( lex.p)] == 46 {
			goto st33
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st45
		}
		goto st0
	st45:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof45
		}
	st_case_45:
		if  lex.data[( lex.p)] == 46 {
			goto st33
		}
		goto st0
	st46:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof46
		}
	st_case_46:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 46:
			goto st31
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st47
		}
		goto st0
	st47:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof47
		}
	st_case_47:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 46:
			goto st31
		case 47:
			goto st2
		case 58:
			goto st2
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st48
		}
		goto st0
	st48:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof48
		}
	st_case_48:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 46:
			goto st31
		case 92:
			goto st2
		case 95:
			goto st2
		}
		switch {
		case  lex.data[( lex.p)] < 47:
			if 39 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 58:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st2
			}
		default:
			goto st2
		}
		goto st0
	st49:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof49
		}
	st_case_49:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 39:
			goto st5
		case 47:
			goto st2
		case 58:
			goto st2
		case 85:
			goto st50
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 40 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st50:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof50
		}
	st_case_50:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 39:
			goto st5
		case 47:
			goto st2
		case 58:
			goto st2
		case 76:
			goto st51
		case 92:
			goto st2
		case 95:
			goto st5
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 40 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st51:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof51
		}
	st_case_51:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st2
		case 34:
			goto st175
		case 35:
			goto st2
		case 39:
			goto st5
		case 47:
			goto st2
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
		case  lex.data[( lex.p)] < 48:
			if 40 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 42 {
				goto st2
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st2
				}
			case  lex.data[( lex.p)] >= 65:
				goto st5
			}
		default:
			goto st5
		}
		goto st0
	st176:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof176
		}
	st_case_176:
		if  lex.data[( lex.p)] == 38 {
			goto tr218
		}
		goto tr217
	st52:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof52
		}
	st_case_52:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st52
		case 95:
			goto st52
		}
		if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
			goto st53
		}
		goto st0
	st53:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof53
		}
	st_case_53:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr56
		case 95:
			goto tr56
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto tr56
			}
		case  lex.data[( lex.p)] >= 48:
			goto tr56
		}
		goto st0
tr56:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:78
 lex.act = 11;
	goto st177
tr252:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:77
 lex.act = 10;
	goto st177
	st177:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof177
		}
	st_case_177:
//line lex.go:2137
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr56
		case 95:
			goto tr56
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto tr56
			}
		case  lex.data[( lex.p)] >= 48:
			goto tr56
		}
		goto tr64
	st54:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof54
		}
	st_case_54:
		if  lex.data[( lex.p)] == 48 {
			goto st55
		}
		if 49 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st179
		}
		goto st0
	st55:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof55
		}
	st_case_55:
		if  lex.data[( lex.p)] == 46 {
			goto st178
		}
		goto st0
	st178:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof178
		}
	st_case_178:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st178
		}
		goto tr219
	st179:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof179
		}
	st_case_179:
		if  lex.data[( lex.p)] == 46 {
			goto st178
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st180
		}
		goto tr220
	st180:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof180
		}
	st_case_180:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st180
		}
		goto tr220
tr192:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:107
 lex.act = 40;
	goto st181
	st181:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof181
		}
	st_case_181:
//line lex.go:2216
		if  lex.data[( lex.p)] == 32 {
			goto st56
		}
		goto tr222
	st56:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof56
		}
	st_case_56:
		if  lex.data[( lex.p)] == 32 {
			goto st57
		}
		goto tr60
	st57:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof57
		}
	st_case_57:
		if  lex.data[( lex.p)] == 60 {
			goto st58
		}
		goto tr60
	st58:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof58
		}
	st_case_58:
		if  lex.data[( lex.p)] == 117 {
			goto st59
		}
		goto tr60
	st59:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof59
		}
	st_case_59:
		if  lex.data[( lex.p)] == 110 {
			goto st60
		}
		goto tr64
	st60:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof60
		}
	st_case_60:
		if  lex.data[( lex.p)] == 102 {
			goto st61
		}
		goto tr64
	st61:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof61
		}
	st_case_61:
		if  lex.data[( lex.p)] == 105 {
			goto st62
		}
		goto tr64
	st62:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof62
		}
	st_case_62:
		if  lex.data[( lex.p)] == 110 {
			goto st63
		}
		goto tr64
	st63:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof63
		}
	st_case_63:
		if  lex.data[( lex.p)] == 105 {
			goto st64
		}
		goto tr64
	st64:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof64
		}
	st_case_64:
		if  lex.data[( lex.p)] == 115 {
			goto st65
		}
		goto tr64
	st65:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof65
		}
	st_case_65:
		if  lex.data[( lex.p)] == 104 {
			goto st66
		}
		goto tr64
	st66:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof66
		}
	st_case_66:
		if  lex.data[( lex.p)] == 101 {
			goto st67
		}
		goto tr64
	st67:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof67
		}
	st_case_67:
		if  lex.data[( lex.p)] == 100 {
			goto st68
		}
		goto tr64
	st68:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof68
		}
	st_case_68:
		if  lex.data[( lex.p)] == 32 {
			goto st69
		}
		goto tr64
	st69:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof69
		}
	st_case_69:
		if  lex.data[( lex.p)] == 46 {
			goto st70
		}
		goto tr64
	st70:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof70
		}
	st_case_70:
		if  lex.data[( lex.p)] == 46 {
			goto st71
		}
		goto tr64
	st71:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof71
		}
	st_case_71:
		if  lex.data[( lex.p)] == 46 {
			goto st72
		}
		goto tr64
	st72:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof72
		}
	st_case_72:
		if  lex.data[( lex.p)] == 62 {
			goto tr78
		}
		goto tr64
	st73:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof73
		}
	st_case_73:
		switch  lex.data[( lex.p)] {
		case 48:
			goto st55
		case 62:
			goto tr79
		}
		if 49 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st179
		}
		goto st0
	st74:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof74
		}
	st_case_74:
		if  lex.data[( lex.p)] == 42 {
			goto tr80
		}
		goto st0
tr195:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:72
 lex.act = 5;
	goto st182
	st182:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof182
		}
	st_case_182:
//line lex.go:2410
		switch  lex.data[( lex.p)] {
		case 46:
			goto st178
		case 120:
			goto st112
		}
		switch {
		case  lex.data[( lex.p)] < 56:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 55 {
				goto tr225
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 70:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
					goto st111
				}
			case  lex.data[( lex.p)] >= 65:
				goto st111
			}
		default:
			goto st110
		}
		goto tr224
tr225:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:72
 lex.act = 5;
	goto st183
	st183:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof183
		}
	st_case_183:
//line lex.go:2447
		if  lex.data[( lex.p)] == 58 {
			goto st96
		}
		switch {
		case  lex.data[( lex.p)] > 55:
			if 56 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st95
			}
		case  lex.data[( lex.p)] >= 48:
			goto tr229
		}
		goto tr224
tr229:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:72
 lex.act = 5;
	goto st184
	st184:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof184
		}
	st_case_184:
//line lex.go:2472
		switch {
		case  lex.data[( lex.p)] > 55:
			if 56 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st94
			}
		case  lex.data[( lex.p)] >= 48:
			goto tr230
		}
		goto tr224
tr230:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:72
 lex.act = 5;
	goto st185
	st185:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof185
		}
	st_case_185:
//line lex.go:2494
		switch  lex.data[( lex.p)] {
		case 45:
			goto st75
		case 47:
			goto st75
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 55 {
			goto st189
		}
		goto tr224
	st75:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof75
		}
	st_case_75:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st76
		}
		goto tr64
	st76:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof76
		}
	st_case_76:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st77
		}
		goto tr64
	st77:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof77
		}
	st_case_77:
		switch  lex.data[( lex.p)] {
		case 45:
			goto st78
		case 47:
			goto st78
		}
		goto tr64
	st78:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof78
		}
	st_case_78:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st79
		}
		goto tr64
	st79:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof79
		}
	st_case_79:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st80
		}
		goto tr64
	st80:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof80
		}
	st_case_80:
		switch  lex.data[( lex.p)] {
		case 45:
			goto st81
		case 84:
			goto st81
		}
		goto tr64
	st81:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof81
		}
	st_case_81:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st82
		}
		goto tr64
	st82:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof82
		}
	st_case_82:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st83
		}
		goto tr64
	st83:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof83
		}
	st_case_83:
		if  lex.data[( lex.p)] == 58 {
			goto st84
		}
		goto tr64
	st84:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof84
		}
	st_case_84:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st85
		}
		goto tr64
	st85:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof85
		}
	st_case_85:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st86
		}
		goto tr64
	st86:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof86
		}
	st_case_86:
		if  lex.data[( lex.p)] == 58 {
			goto st87
		}
		goto tr64
	st87:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof87
		}
	st_case_87:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st88
		}
		goto tr64
	st88:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof88
		}
	st_case_88:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto tr94
		}
		goto tr64
tr94:
//line NONE:1
 lex.te = ( lex.p)+1

	goto st186
	st186:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof186
		}
	st_case_186:
//line lex.go:2647
		switch  lex.data[( lex.p)] {
		case 43:
			goto st89
		case 45:
			goto st89
		case 46:
			goto st93
		}
		goto tr232
	st89:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof89
		}
	st_case_89:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st90
		}
		goto tr95
	st90:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof90
		}
	st_case_90:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st91
		}
		goto tr95
	st91:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof91
		}
	st_case_91:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st92
		}
		goto tr95
	st92:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof92
		}
	st_case_92:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto tr99
		}
		goto tr95
tr99:
//line NONE:1
 lex.te = ( lex.p)+1

	goto st187
	st187:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof187
		}
	st_case_187:
//line lex.go:2703
		if  lex.data[( lex.p)] == 46 {
			goto st93
		}
		goto tr232
	st93:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof93
		}
	st_case_93:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st188
		}
		goto tr95
	st188:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof188
		}
	st_case_188:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st188
		}
		goto tr232
	st189:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof189
		}
	st_case_189:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 55 {
			goto st189
		}
		goto tr224
	st94:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof94
		}
	st_case_94:
		switch  lex.data[( lex.p)] {
		case 45:
			goto st75
		case 47:
			goto st75
		}
		goto tr101
	st95:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof95
		}
	st_case_95:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st94
		}
		goto tr101
	st96:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof96
		}
	st_case_96:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st97
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st97
			}
		default:
			goto st97
		}
		goto tr64
	st97:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof97
		}
	st_case_97:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st98
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st98
			}
		default:
			goto st98
		}
		goto tr64
	st98:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof98
		}
	st_case_98:
		if  lex.data[( lex.p)] == 58 {
			goto st99
		}
		goto tr64
	st99:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof99
		}
	st_case_99:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st100
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st100
			}
		default:
			goto st100
		}
		goto tr64
	st100:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof100
		}
	st_case_100:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st101
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st101
			}
		default:
			goto st101
		}
		goto tr64
	st101:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof101
		}
	st_case_101:
		if  lex.data[( lex.p)] == 58 {
			goto st102
		}
		goto tr64
	st102:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof102
		}
	st_case_102:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st103
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st103
			}
		default:
			goto st103
		}
		goto tr64
	st103:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof103
		}
	st_case_103:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st104
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st104
			}
		default:
			goto st104
		}
		goto tr64
	st104:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof104
		}
	st_case_104:
		if  lex.data[( lex.p)] == 58 {
			goto st105
		}
		goto tr64
	st105:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof105
		}
	st_case_105:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st106
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st106
			}
		default:
			goto st106
		}
		goto tr64
	st106:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof106
		}
	st_case_106:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st107
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st107
			}
		default:
			goto st107
		}
		goto tr64
	st107:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof107
		}
	st_case_107:
		if  lex.data[( lex.p)] == 58 {
			goto st108
		}
		goto tr64
	st108:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof108
		}
	st_case_108:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st109
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st109
			}
		default:
			goto st109
		}
		goto tr64
	st109:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof109
		}
	st_case_109:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto tr117
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto tr117
			}
		default:
			goto tr117
		}
		goto tr64
	st110:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof110
		}
	st_case_110:
		if  lex.data[( lex.p)] == 58 {
			goto st96
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st95
		}
		goto tr101
	st111:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof111
		}
	st_case_111:
		if  lex.data[( lex.p)] == 58 {
			goto st96
		}
		goto tr64
	st112:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof112
		}
	st_case_112:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st190
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st190
			}
		default:
			goto st190
		}
		goto tr101
	st190:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof190
		}
	st_case_190:
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto st190
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st190
			}
		default:
			goto st190
		}
		goto tr235
tr196:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:70
 lex.act = 3;
	goto st191
	st191:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof191
		}
	st_case_191:
//line lex.go:3041
		if  lex.data[( lex.p)] == 46 {
			goto st178
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
				goto tr236
			}
		case  lex.data[( lex.p)] > 70:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 102 {
				goto st111
			}
		default:
			goto st111
		}
		goto tr220
tr236:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:70
 lex.act = 3;
	goto st192
	st192:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof192
		}
	st_case_192:
//line lex.go:3070
		if  lex.data[( lex.p)] == 58 {
			goto st96
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st193
		}
		goto tr220
	st193:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof193
		}
	st_case_193:
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto tr238
		}
		goto tr220
tr238:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:70
 lex.act = 3;
	goto st194
	st194:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof194
		}
	st_case_194:
//line lex.go:3099
		switch  lex.data[( lex.p)] {
		case 45:
			goto st75
		case 47:
			goto st75
		}
		if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
			goto st180
		}
		goto tr220
	st113:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof113
		}
	st_case_113:
		switch  lex.data[( lex.p)] {
		case 46:
			goto st114
		case 60:
			goto tr122
		case 117:
			goto st59
		}
		goto st0
	st114:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof114
		}
	st_case_114:
		if  lex.data[( lex.p)] == 46 {
			goto st115
		}
		goto st0
	st115:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof115
		}
	st_case_115:
		if  lex.data[( lex.p)] == 46 {
			goto st116
		}
		goto st0
	st116:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof116
		}
	st_case_116:
		if  lex.data[( lex.p)] == 32 {
			goto st117
		}
		goto st0
	st117:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof117
		}
	st_case_117:
		if  lex.data[( lex.p)] == 114 {
			goto st128
		}
		switch {
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st118
			}
		case  lex.data[( lex.p)] >= 65:
			goto st118
		}
		goto st0
	st118:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof118
		}
	st_case_118:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st119
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st119:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof119
		}
	st_case_119:
		if  lex.data[( lex.p)] == 114 {
			goto st120
		}
		goto st0
	st120:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof120
		}
	st_case_120:
		if  lex.data[( lex.p)] == 101 {
			goto st121
		}
		goto st0
	st121:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof121
		}
	st_case_121:
		if  lex.data[( lex.p)] == 115 {
			goto st122
		}
		goto st0
	st122:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof122
		}
	st_case_122:
		if  lex.data[( lex.p)] == 117 {
			goto st123
		}
		goto st0
	st123:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof123
		}
	st_case_123:
		if  lex.data[( lex.p)] == 109 {
			goto st124
		}
		goto st0
	st124:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof124
		}
	st_case_124:
		if  lex.data[( lex.p)] == 101 {
			goto st125
		}
		goto st0
	st125:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof125
		}
	st_case_125:
		if  lex.data[( lex.p)] == 100 {
			goto st126
		}
		goto st0
	st126:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof126
		}
	st_case_126:
		if  lex.data[( lex.p)] == 62 {
			goto tr136
		}
		goto st0
tr136:
//line NONE:1
 lex.te = ( lex.p)+1

	goto st195
	st195:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof195
		}
	st_case_195:
//line lex.go:3283
		if  lex.data[( lex.p)] == 32 {
			goto st127
		}
		goto tr239
	st127:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof127
		}
	st_case_127:
		if  lex.data[( lex.p)] == 44 {
			goto tr138
		}
		goto tr137
	st128:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof128
		}
	st_case_128:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st119
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		case 101:
			goto st129
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st129:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof129
		}
	st_case_129:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st119
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		case 115:
			goto st130
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st130:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof130
		}
	st_case_130:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st119
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		case 117:
			goto st131
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st131:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof131
		}
	st_case_131:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st119
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		case 109:
			goto st132
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st132:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof132
		}
	st_case_132:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st119
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		case 105:
			goto st133
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st133:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof133
		}
	st_case_133:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st119
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		case 110:
			goto st134
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st134:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof134
		}
	st_case_134:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st119
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		case 103:
			goto st135
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st135:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof135
		}
	st_case_135:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st136
		case 39:
			goto st118
		case 42:
			goto st118
		case 95:
			goto st118
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st118
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto st118
				}
			case  lex.data[( lex.p)] >= 65:
				goto st118
			}
		default:
			goto st118
		}
		goto st0
	st136:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof136
		}
	st_case_136:
		switch  lex.data[( lex.p)] {
		case 111:
			goto st155
		case 114:
			goto st157
		case 115:
			goto st164
		}
		switch {
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		case  lex.data[( lex.p)] >= 65:
			goto st137
		}
		goto st0
	st137:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof137
		}
	st_case_137:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st138:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof138
		}
	st_case_138:
		switch  lex.data[( lex.p)] {
		case 111:
			goto st144
		case 115:
			goto st146
		}
		switch {
		case  lex.data[( lex.p)] > 90:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		case  lex.data[( lex.p)] >= 65:
			goto st139
		}
		goto st0
	st139:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof139
		}
	st_case_139:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st140:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof140
		}
	st_case_140:
		if  lex.data[( lex.p)] == 46 {
			goto st141
		}
		goto st0
	st141:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof141
		}
	st_case_141:
		if  lex.data[( lex.p)] == 46 {
			goto st142
		}
		goto st0
	st142:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof142
		}
	st_case_142:
		if  lex.data[( lex.p)] == 46 {
			goto st143
		}
		goto st0
	st143:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof143
		}
	st_case_143:
		if  lex.data[( lex.p)] == 62 {
			goto tr138
		}
		goto st0
	st144:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof144
		}
	st_case_144:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 114:
			goto st145
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st145:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof145
		}
	st_case_145:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st146:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof146
		}
	st_case_146:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 105:
			goto st147
		case 116:
			goto st151
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st147:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof147
		}
	st_case_147:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 122:
			goto st148
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 121 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st148:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof148
		}
	st_case_148:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 101:
			goto st149
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st149:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof149
		}
	st_case_149:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 111:
			goto st150
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st150:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof150
		}
	st_case_150:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 102:
			goto st145
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st151:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof151
		}
	st_case_151:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 114:
			goto st152
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st152:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof152
		}
	st_case_152:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 117:
			goto st153
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st153:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof153
		}
	st_case_153:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 99:
			goto st154
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st154:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof154
		}
	st_case_154:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st140
		case 39:
			goto st139
		case 42:
			goto st139
		case 95:
			goto st139
		case 116:
			goto st145
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st139
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st139
			}
		default:
			goto st139
		}
		goto st0
	st155:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof155
		}
	st_case_155:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 114:
			goto st156
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st156:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof156
		}
	st_case_156:
		switch  lex.data[( lex.p)] {
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st157:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof157
		}
	st_case_157:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 101:
			goto st158
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st158:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof158
		}
	st_case_158:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 115:
			goto st159
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st159:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof159
		}
	st_case_159:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 117:
			goto st160
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st160:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof160
		}
	st_case_160:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 109:
			goto st161
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st161:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof161
		}
	st_case_161:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 101:
			goto st162
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st162:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof162
		}
	st_case_162:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 100:
			goto st163
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st163:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof163
		}
	st_case_163:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 62:
			goto tr136
		case 95:
			goto st137
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st164:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof164
		}
	st_case_164:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 105:
			goto st165
		case 116:
			goto st169
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st165:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof165
		}
	st_case_165:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 122:
			goto st166
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 121 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st166:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof166
		}
	st_case_166:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 101:
			goto st167
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st167:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof167
		}
	st_case_167:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 111:
			goto st168
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st168:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof168
		}
	st_case_168:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 102:
			goto st156
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st169:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof169
		}
	st_case_169:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 114:
			goto st170
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st170:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof170
		}
	st_case_170:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 117:
			goto st171
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st171:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof171
		}
	st_case_171:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 99:
			goto st172
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st172:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof172
		}
	st_case_172:
		switch  lex.data[( lex.p)] {
		case 32:
			goto st138
		case 39:
			goto st137
		case 42:
			goto st137
		case 95:
			goto st137
		case 116:
			goto st156
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto st137
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto st137
			}
		default:
			goto st137
		}
		goto st0
	st196:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof196
		}
	st_case_196:
		switch  lex.data[( lex.p)] {
		case 61:
			goto tr242
		case 62:
			goto tr243
		}
		goto tr241
	st173:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof173
		}
	st_case_173:
		if  lex.data[( lex.p)] == 62 {
			goto tr183
		}
		goto st0
	st197:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof197
		}
	st_case_197:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr245
		case 42:
			goto tr209
		case 95:
			goto tr245
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			switch {
			case  lex.data[( lex.p)] > 46:
				if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
					goto tr246
				}
			case  lex.data[( lex.p)] >= 45:
				goto tr209
			}
		case  lex.data[( lex.p)] > 70:
			switch {
			case  lex.data[( lex.p)] < 97:
				if 71 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
					goto tr56
				}
			case  lex.data[( lex.p)] > 102:
				if 103 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto tr209
				}
			default:
				goto tr248
			}
		default:
			goto tr247
		}
		goto tr244
tr245:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:78
 lex.act = 11;
	goto st198
tr204:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:80
 lex.act = 13;
	goto st198
	st198:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof198
		}
	st_case_198:
//line lex.go:4655
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr245
		case 42:
			goto tr209
		case 95:
			goto tr245
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto tr209
				}
			case  lex.data[( lex.p)] >= 65:
				goto tr56
			}
		default:
			goto tr245
		}
		goto tr64
tr209:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:80
 lex.act = 13;
	goto st199
tr253:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:85
 lex.act = 18;
	goto st199
tr259:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:83
 lex.act = 16;
	goto st199
	st199:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof199
		}
	st_case_199:
//line lex.go:4708
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr64
tr246:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:78
 lex.act = 11;
	goto st200
	st200:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof200
		}
	st_case_200:
//line lex.go:4742
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr245
		case 42:
			goto tr209
		case 58:
			goto st96
		case 95:
			goto tr245
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto tr209
				}
			case  lex.data[( lex.p)] >= 65:
				goto tr56
			}
		default:
			goto tr245
		}
		goto tr249
tr247:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:78
 lex.act = 11;
	goto st201
	st201:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof201
		}
	st_case_201:
//line lex.go:4783
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr56
		case 58:
			goto st96
		case 95:
			goto tr56
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto tr56
			}
		case  lex.data[( lex.p)] >= 48:
			goto tr56
		}
		goto tr249
tr248:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:80
 lex.act = 13;
	goto st202
	st202:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof202
		}
	st_case_202:
//line lex.go:4813
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 58:
			goto st96
		case 95:
			goto tr209
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st203:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof203
		}
	st_case_203:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr245
		case 42:
			goto tr209
		case 85:
			goto st204
		case 95:
			goto tr245
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			switch {
			case  lex.data[( lex.p)] > 90:
				if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto tr209
				}
			case  lex.data[( lex.p)] >= 65:
				goto tr56
			}
		default:
			goto tr245
		}
		goto tr244
	st204:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof204
		}
	st_case_204:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr56
		case 76:
			goto st205
		case 95:
			goto tr56
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto tr56
			}
		case  lex.data[( lex.p)] >= 48:
			goto tr56
		}
		goto tr249
	st205:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof205
		}
	st_case_205:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr56
		case 76:
			goto tr252
		case 95:
			goto tr56
		}
		switch {
		case  lex.data[( lex.p)] > 57:
			if 65 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 90 {
				goto tr56
			}
		case  lex.data[( lex.p)] >= 48:
			goto tr56
		}
		goto tr249
tr208:
//line NONE:1
 lex.te = ( lex.p)+1

//line straceLex.rl:80
 lex.act = 13;
	goto st206
	st206:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof206
		}
	st_case_206:
//line lex.go:4926
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		}
		switch {
		case  lex.data[( lex.p)] < 65:
			switch {
			case  lex.data[( lex.p)] > 46:
				if 48 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 57 {
					goto tr248
				}
			case  lex.data[( lex.p)] >= 45:
				goto tr209
			}
		case  lex.data[( lex.p)] > 70:
			switch {
			case  lex.data[( lex.p)] > 102:
				if 103 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
					goto tr209
				}
			case  lex.data[( lex.p)] >= 97:
				goto tr248
			}
		default:
			goto st111
		}
		goto tr244
	st207:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof207
		}
	st_case_207:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 114:
			goto tr253
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st208:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof208
		}
	st_case_208:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 105:
			goto st209
		case 116:
			goto st213
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st209:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof209
		}
	st_case_209:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 122:
			goto st210
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 121 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st210:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof210
		}
	st_case_210:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 101:
			goto st211
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st211:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof211
		}
	st_case_211:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 111:
			goto st212
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st212:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof212
		}
	st_case_212:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 102:
			goto tr259
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st213:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof213
		}
	st_case_213:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 114:
			goto st214
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st214:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof214
		}
	st_case_214:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 117:
			goto st215
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st215:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof215
		}
	st_case_215:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 99:
			goto st216
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st216:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof216
		}
	st_case_216:
		switch  lex.data[( lex.p)] {
		case 39:
			goto tr209
		case 42:
			goto tr209
		case 95:
			goto tr209
		case 116:
			goto tr259
		}
		switch {
		case  lex.data[( lex.p)] < 48:
			if 45 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 46 {
				goto tr209
			}
		case  lex.data[( lex.p)] > 57:
			if 97 <=  lex.data[( lex.p)] &&  lex.data[( lex.p)] <= 122 {
				goto tr209
			}
		default:
			goto tr209
		}
		goto tr244
	st217:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof217
		}
	st_case_217:
		if  lex.data[( lex.p)] == 124 {
			goto tr264
		}
		goto tr263
tr265:
//line straceLex.rl:65
 lex.te = ( lex.p)+1

	goto st218
tr267:
//line straceLex.rl:65
 lex.te = ( lex.p)
( lex.p)--

	goto st218
tr268:
//line straceLex.rl:66
 lex.te = ( lex.p)+1
{{goto st174 }}
	goto st218
	st218:
//line NONE:1
 lex.ts = 0

		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof218
		}
	st_case_218:
//line NONE:1
 lex.ts = ( lex.p)

//line lex.go:5276
		if  lex.data[( lex.p)] == 42 {
			goto st219
		}
		goto tr265
	st219:
		if ( lex.p)++; ( lex.p) == ( lex.pe) {
			goto _test_eof219
		}
	st_case_219:
		if  lex.data[( lex.p)] == 47 {
			goto tr268
		}
		goto tr267
	st_out:
	_test_eof174:  lex.cs = 174; goto _test_eof
	_test_eof1:  lex.cs = 1; goto _test_eof
	_test_eof2:  lex.cs = 2; goto _test_eof
	_test_eof175:  lex.cs = 175; goto _test_eof
	_test_eof3:  lex.cs = 3; goto _test_eof
	_test_eof4:  lex.cs = 4; goto _test_eof
	_test_eof5:  lex.cs = 5; goto _test_eof
	_test_eof6:  lex.cs = 6; goto _test_eof
	_test_eof7:  lex.cs = 7; goto _test_eof
	_test_eof8:  lex.cs = 8; goto _test_eof
	_test_eof9:  lex.cs = 9; goto _test_eof
	_test_eof10:  lex.cs = 10; goto _test_eof
	_test_eof11:  lex.cs = 11; goto _test_eof
	_test_eof12:  lex.cs = 12; goto _test_eof
	_test_eof13:  lex.cs = 13; goto _test_eof
	_test_eof14:  lex.cs = 14; goto _test_eof
	_test_eof15:  lex.cs = 15; goto _test_eof
	_test_eof16:  lex.cs = 16; goto _test_eof
	_test_eof17:  lex.cs = 17; goto _test_eof
	_test_eof18:  lex.cs = 18; goto _test_eof
	_test_eof19:  lex.cs = 19; goto _test_eof
	_test_eof20:  lex.cs = 20; goto _test_eof
	_test_eof21:  lex.cs = 21; goto _test_eof
	_test_eof22:  lex.cs = 22; goto _test_eof
	_test_eof23:  lex.cs = 23; goto _test_eof
	_test_eof24:  lex.cs = 24; goto _test_eof
	_test_eof25:  lex.cs = 25; goto _test_eof
	_test_eof26:  lex.cs = 26; goto _test_eof
	_test_eof27:  lex.cs = 27; goto _test_eof
	_test_eof28:  lex.cs = 28; goto _test_eof
	_test_eof29:  lex.cs = 29; goto _test_eof
	_test_eof30:  lex.cs = 30; goto _test_eof
	_test_eof31:  lex.cs = 31; goto _test_eof
	_test_eof32:  lex.cs = 32; goto _test_eof
	_test_eof33:  lex.cs = 33; goto _test_eof
	_test_eof34:  lex.cs = 34; goto _test_eof
	_test_eof35:  lex.cs = 35; goto _test_eof
	_test_eof36:  lex.cs = 36; goto _test_eof
	_test_eof37:  lex.cs = 37; goto _test_eof
	_test_eof38:  lex.cs = 38; goto _test_eof
	_test_eof39:  lex.cs = 39; goto _test_eof
	_test_eof40:  lex.cs = 40; goto _test_eof
	_test_eof41:  lex.cs = 41; goto _test_eof
	_test_eof42:  lex.cs = 42; goto _test_eof
	_test_eof43:  lex.cs = 43; goto _test_eof
	_test_eof44:  lex.cs = 44; goto _test_eof
	_test_eof45:  lex.cs = 45; goto _test_eof
	_test_eof46:  lex.cs = 46; goto _test_eof
	_test_eof47:  lex.cs = 47; goto _test_eof
	_test_eof48:  lex.cs = 48; goto _test_eof
	_test_eof49:  lex.cs = 49; goto _test_eof
	_test_eof50:  lex.cs = 50; goto _test_eof
	_test_eof51:  lex.cs = 51; goto _test_eof
	_test_eof176:  lex.cs = 176; goto _test_eof
	_test_eof52:  lex.cs = 52; goto _test_eof
	_test_eof53:  lex.cs = 53; goto _test_eof
	_test_eof177:  lex.cs = 177; goto _test_eof
	_test_eof54:  lex.cs = 54; goto _test_eof
	_test_eof55:  lex.cs = 55; goto _test_eof
	_test_eof178:  lex.cs = 178; goto _test_eof
	_test_eof179:  lex.cs = 179; goto _test_eof
	_test_eof180:  lex.cs = 180; goto _test_eof
	_test_eof181:  lex.cs = 181; goto _test_eof
	_test_eof56:  lex.cs = 56; goto _test_eof
	_test_eof57:  lex.cs = 57; goto _test_eof
	_test_eof58:  lex.cs = 58; goto _test_eof
	_test_eof59:  lex.cs = 59; goto _test_eof
	_test_eof60:  lex.cs = 60; goto _test_eof
	_test_eof61:  lex.cs = 61; goto _test_eof
	_test_eof62:  lex.cs = 62; goto _test_eof
	_test_eof63:  lex.cs = 63; goto _test_eof
	_test_eof64:  lex.cs = 64; goto _test_eof
	_test_eof65:  lex.cs = 65; goto _test_eof
	_test_eof66:  lex.cs = 66; goto _test_eof
	_test_eof67:  lex.cs = 67; goto _test_eof
	_test_eof68:  lex.cs = 68; goto _test_eof
	_test_eof69:  lex.cs = 69; goto _test_eof
	_test_eof70:  lex.cs = 70; goto _test_eof
	_test_eof71:  lex.cs = 71; goto _test_eof
	_test_eof72:  lex.cs = 72; goto _test_eof
	_test_eof73:  lex.cs = 73; goto _test_eof
	_test_eof74:  lex.cs = 74; goto _test_eof
	_test_eof182:  lex.cs = 182; goto _test_eof
	_test_eof183:  lex.cs = 183; goto _test_eof
	_test_eof184:  lex.cs = 184; goto _test_eof
	_test_eof185:  lex.cs = 185; goto _test_eof
	_test_eof75:  lex.cs = 75; goto _test_eof
	_test_eof76:  lex.cs = 76; goto _test_eof
	_test_eof77:  lex.cs = 77; goto _test_eof
	_test_eof78:  lex.cs = 78; goto _test_eof
	_test_eof79:  lex.cs = 79; goto _test_eof
	_test_eof80:  lex.cs = 80; goto _test_eof
	_test_eof81:  lex.cs = 81; goto _test_eof
	_test_eof82:  lex.cs = 82; goto _test_eof
	_test_eof83:  lex.cs = 83; goto _test_eof
	_test_eof84:  lex.cs = 84; goto _test_eof
	_test_eof85:  lex.cs = 85; goto _test_eof
	_test_eof86:  lex.cs = 86; goto _test_eof
	_test_eof87:  lex.cs = 87; goto _test_eof
	_test_eof88:  lex.cs = 88; goto _test_eof
	_test_eof186:  lex.cs = 186; goto _test_eof
	_test_eof89:  lex.cs = 89; goto _test_eof
	_test_eof90:  lex.cs = 90; goto _test_eof
	_test_eof91:  lex.cs = 91; goto _test_eof
	_test_eof92:  lex.cs = 92; goto _test_eof
	_test_eof187:  lex.cs = 187; goto _test_eof
	_test_eof93:  lex.cs = 93; goto _test_eof
	_test_eof188:  lex.cs = 188; goto _test_eof
	_test_eof189:  lex.cs = 189; goto _test_eof
	_test_eof94:  lex.cs = 94; goto _test_eof
	_test_eof95:  lex.cs = 95; goto _test_eof
	_test_eof96:  lex.cs = 96; goto _test_eof
	_test_eof97:  lex.cs = 97; goto _test_eof
	_test_eof98:  lex.cs = 98; goto _test_eof
	_test_eof99:  lex.cs = 99; goto _test_eof
	_test_eof100:  lex.cs = 100; goto _test_eof
	_test_eof101:  lex.cs = 101; goto _test_eof
	_test_eof102:  lex.cs = 102; goto _test_eof
	_test_eof103:  lex.cs = 103; goto _test_eof
	_test_eof104:  lex.cs = 104; goto _test_eof
	_test_eof105:  lex.cs = 105; goto _test_eof
	_test_eof106:  lex.cs = 106; goto _test_eof
	_test_eof107:  lex.cs = 107; goto _test_eof
	_test_eof108:  lex.cs = 108; goto _test_eof
	_test_eof109:  lex.cs = 109; goto _test_eof
	_test_eof110:  lex.cs = 110; goto _test_eof
	_test_eof111:  lex.cs = 111; goto _test_eof
	_test_eof112:  lex.cs = 112; goto _test_eof
	_test_eof190:  lex.cs = 190; goto _test_eof
	_test_eof191:  lex.cs = 191; goto _test_eof
	_test_eof192:  lex.cs = 192; goto _test_eof
	_test_eof193:  lex.cs = 193; goto _test_eof
	_test_eof194:  lex.cs = 194; goto _test_eof
	_test_eof113:  lex.cs = 113; goto _test_eof
	_test_eof114:  lex.cs = 114; goto _test_eof
	_test_eof115:  lex.cs = 115; goto _test_eof
	_test_eof116:  lex.cs = 116; goto _test_eof
	_test_eof117:  lex.cs = 117; goto _test_eof
	_test_eof118:  lex.cs = 118; goto _test_eof
	_test_eof119:  lex.cs = 119; goto _test_eof
	_test_eof120:  lex.cs = 120; goto _test_eof
	_test_eof121:  lex.cs = 121; goto _test_eof
	_test_eof122:  lex.cs = 122; goto _test_eof
	_test_eof123:  lex.cs = 123; goto _test_eof
	_test_eof124:  lex.cs = 124; goto _test_eof
	_test_eof125:  lex.cs = 125; goto _test_eof
	_test_eof126:  lex.cs = 126; goto _test_eof
	_test_eof195:  lex.cs = 195; goto _test_eof
	_test_eof127:  lex.cs = 127; goto _test_eof
	_test_eof128:  lex.cs = 128; goto _test_eof
	_test_eof129:  lex.cs = 129; goto _test_eof
	_test_eof130:  lex.cs = 130; goto _test_eof
	_test_eof131:  lex.cs = 131; goto _test_eof
	_test_eof132:  lex.cs = 132; goto _test_eof
	_test_eof133:  lex.cs = 133; goto _test_eof
	_test_eof134:  lex.cs = 134; goto _test_eof
	_test_eof135:  lex.cs = 135; goto _test_eof
	_test_eof136:  lex.cs = 136; goto _test_eof
	_test_eof137:  lex.cs = 137; goto _test_eof
	_test_eof138:  lex.cs = 138; goto _test_eof
	_test_eof139:  lex.cs = 139; goto _test_eof
	_test_eof140:  lex.cs = 140; goto _test_eof
	_test_eof141:  lex.cs = 141; goto _test_eof
	_test_eof142:  lex.cs = 142; goto _test_eof
	_test_eof143:  lex.cs = 143; goto _test_eof
	_test_eof144:  lex.cs = 144; goto _test_eof
	_test_eof145:  lex.cs = 145; goto _test_eof
	_test_eof146:  lex.cs = 146; goto _test_eof
	_test_eof147:  lex.cs = 147; goto _test_eof
	_test_eof148:  lex.cs = 148; goto _test_eof
	_test_eof149:  lex.cs = 149; goto _test_eof
	_test_eof150:  lex.cs = 150; goto _test_eof
	_test_eof151:  lex.cs = 151; goto _test_eof
	_test_eof152:  lex.cs = 152; goto _test_eof
	_test_eof153:  lex.cs = 153; goto _test_eof
	_test_eof154:  lex.cs = 154; goto _test_eof
	_test_eof155:  lex.cs = 155; goto _test_eof
	_test_eof156:  lex.cs = 156; goto _test_eof
	_test_eof157:  lex.cs = 157; goto _test_eof
	_test_eof158:  lex.cs = 158; goto _test_eof
	_test_eof159:  lex.cs = 159; goto _test_eof
	_test_eof160:  lex.cs = 160; goto _test_eof
	_test_eof161:  lex.cs = 161; goto _test_eof
	_test_eof162:  lex.cs = 162; goto _test_eof
	_test_eof163:  lex.cs = 163; goto _test_eof
	_test_eof164:  lex.cs = 164; goto _test_eof
	_test_eof165:  lex.cs = 165; goto _test_eof
	_test_eof166:  lex.cs = 166; goto _test_eof
	_test_eof167:  lex.cs = 167; goto _test_eof
	_test_eof168:  lex.cs = 168; goto _test_eof
	_test_eof169:  lex.cs = 169; goto _test_eof
	_test_eof170:  lex.cs = 170; goto _test_eof
	_test_eof171:  lex.cs = 171; goto _test_eof
	_test_eof172:  lex.cs = 172; goto _test_eof
	_test_eof196:  lex.cs = 196; goto _test_eof
	_test_eof173:  lex.cs = 173; goto _test_eof
	_test_eof197:  lex.cs = 197; goto _test_eof
	_test_eof198:  lex.cs = 198; goto _test_eof
	_test_eof199:  lex.cs = 199; goto _test_eof
	_test_eof200:  lex.cs = 200; goto _test_eof
	_test_eof201:  lex.cs = 201; goto _test_eof
	_test_eof202:  lex.cs = 202; goto _test_eof
	_test_eof203:  lex.cs = 203; goto _test_eof
	_test_eof204:  lex.cs = 204; goto _test_eof
	_test_eof205:  lex.cs = 205; goto _test_eof
	_test_eof206:  lex.cs = 206; goto _test_eof
	_test_eof207:  lex.cs = 207; goto _test_eof
	_test_eof208:  lex.cs = 208; goto _test_eof
	_test_eof209:  lex.cs = 209; goto _test_eof
	_test_eof210:  lex.cs = 210; goto _test_eof
	_test_eof211:  lex.cs = 211; goto _test_eof
	_test_eof212:  lex.cs = 212; goto _test_eof
	_test_eof213:  lex.cs = 213; goto _test_eof
	_test_eof214:  lex.cs = 214; goto _test_eof
	_test_eof215:  lex.cs = 215; goto _test_eof
	_test_eof216:  lex.cs = 216; goto _test_eof
	_test_eof217:  lex.cs = 217; goto _test_eof
	_test_eof218:  lex.cs = 218; goto _test_eof
	_test_eof219:  lex.cs = 219; goto _test_eof

	_test_eof: {}
	if ( lex.p) == eof {
		switch  lex.cs {
		case 175:
			goto tr216
		case 176:
			goto tr217
		case 177:
			goto tr64
		case 178:
			goto tr219
		case 179:
			goto tr220
		case 180:
			goto tr220
		case 181:
			goto tr222
		case 56:
			goto tr60
		case 57:
			goto tr60
		case 58:
			goto tr60
		case 59:
			goto tr64
		case 60:
			goto tr64
		case 61:
			goto tr64
		case 62:
			goto tr64
		case 63:
			goto tr64
		case 64:
			goto tr64
		case 65:
			goto tr64
		case 66:
			goto tr64
		case 67:
			goto tr64
		case 68:
			goto tr64
		case 69:
			goto tr64
		case 70:
			goto tr64
		case 71:
			goto tr64
		case 72:
			goto tr64
		case 182:
			goto tr224
		case 183:
			goto tr224
		case 184:
			goto tr224
		case 185:
			goto tr224
		case 75:
			goto tr64
		case 76:
			goto tr64
		case 77:
			goto tr64
		case 78:
			goto tr64
		case 79:
			goto tr64
		case 80:
			goto tr64
		case 81:
			goto tr64
		case 82:
			goto tr64
		case 83:
			goto tr64
		case 84:
			goto tr64
		case 85:
			goto tr64
		case 86:
			goto tr64
		case 87:
			goto tr64
		case 88:
			goto tr64
		case 186:
			goto tr232
		case 89:
			goto tr95
		case 90:
			goto tr95
		case 91:
			goto tr95
		case 92:
			goto tr95
		case 187:
			goto tr232
		case 93:
			goto tr95
		case 188:
			goto tr232
		case 189:
			goto tr224
		case 94:
			goto tr101
		case 95:
			goto tr101
		case 96:
			goto tr64
		case 97:
			goto tr64
		case 98:
			goto tr64
		case 99:
			goto tr64
		case 100:
			goto tr64
		case 101:
			goto tr64
		case 102:
			goto tr64
		case 103:
			goto tr64
		case 104:
			goto tr64
		case 105:
			goto tr64
		case 106:
			goto tr64
		case 107:
			goto tr64
		case 108:
			goto tr64
		case 109:
			goto tr64
		case 110:
			goto tr101
		case 111:
			goto tr64
		case 112:
			goto tr101
		case 190:
			goto tr235
		case 191:
			goto tr220
		case 192:
			goto tr220
		case 193:
			goto tr220
		case 194:
			goto tr220
		case 195:
			goto tr239
		case 127:
			goto tr137
		case 196:
			goto tr241
		case 197:
			goto tr244
		case 198:
			goto tr64
		case 199:
			goto tr64
		case 200:
			goto tr249
		case 201:
			goto tr249
		case 202:
			goto tr244
		case 203:
			goto tr244
		case 204:
			goto tr249
		case 205:
			goto tr249
		case 206:
			goto tr244
		case 207:
			goto tr244
		case 208:
			goto tr244
		case 209:
			goto tr244
		case 210:
			goto tr244
		case 211:
			goto tr244
		case 212:
			goto tr244
		case 213:
			goto tr244
		case 214:
			goto tr244
		case 215:
			goto tr244
		case 216:
			goto tr244
		case 217:
			goto tr263
		case 219:
			goto tr267
		}
	}

	_out: {}
	}

//line straceLex.rl:115


    return tok;
}

func (lex *Stracelexer) Error(e string) {
    fmt.Println("error:", e)
}

func ParseString(s string) string{
	var decoded []byte
	var err error
	var strippedStr string
	strippedStr = strings.Replace(s, `\x`, "", -1)
	strippedStr = strings.Replace(strippedStr, ".", "", -1)
	strippedStr = strings.Replace(strippedStr, `"`, "", -1)
	if len(strippedStr) % 2 > 0 {
	    strippedStr += "0"
	}
	if decoded, err = hex.DecodeString(strippedStr); err != nil {
		log.Logf(2, "Failed to decode string: %s, with error: %s\n", s, err.Error())
		decoded = []byte(strippedStr)
	}
	decoded = append(decoded, '\x00')
	return string(decoded)
}
