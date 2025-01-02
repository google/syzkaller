/*
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package spansql

// This file holds the type definitions for the SQL dialect.

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/civil"
)

// TODO: More Position fields throughout; maybe in Query/Select.

// CreateTable represents a CREATE TABLE statement.
// https://cloud.google.com/spanner/docs/data-definition-language#create_table
type CreateTable struct {
	Name              ID
	IfNotExists       bool
	Columns           []ColumnDef
	Constraints       []TableConstraint
	PrimaryKey        []KeyPart
	Interleave        *Interleave
	RowDeletionPolicy *RowDeletionPolicy
	Synonym           ID // may be empty

	Position Position // position of the "CREATE" token
}

func (ct *CreateTable) String() string { return fmt.Sprintf("%#v", ct) }
func (*CreateTable) isDDLStmt()        {}
func (ct *CreateTable) Pos() Position  { return ct.Position }
func (ct *CreateTable) clearOffset() {
	for i := range ct.Columns {
		// Mutate in place.
		ct.Columns[i].clearOffset()
	}
	for i := range ct.Constraints {
		// Mutate in place.
		ct.Constraints[i].clearOffset()
	}
	ct.Position.Offset = 0
}

// TableConstraint represents a constraint on a table.
type TableConstraint struct {
	Name       ID // may be empty
	Constraint Constraint

	Position Position // position of the "CONSTRAINT" token, or Constraint.Pos()
}

func (tc TableConstraint) Pos() Position { return tc.Position }
func (tc *TableConstraint) clearOffset() {
	switch c := tc.Constraint.(type) {
	case ForeignKey:
		c.clearOffset()
		tc.Constraint = c
	case Check:
		c.clearOffset()
		tc.Constraint = c
	}
	tc.Position.Offset = 0
}

type Constraint interface {
	isConstraint()
	SQL() string
	Node
}

// Interleave represents an interleave clause of a CREATE TABLE statement.
type Interleave struct {
	Parent   ID
	OnDelete OnDelete
}

// RowDeletionPolicy represents an row deletion policy clause of a CREATE, ALTER TABLE statement.
type RowDeletionPolicy struct {
	Column  ID
	NumDays int64
}

// CreateIndex represents a CREATE INDEX statement.
// https://cloud.google.com/spanner/docs/data-definition-language#create-index
type CreateIndex struct {
	Name    ID
	Table   ID
	Columns []KeyPart

	Unique       bool
	NullFiltered bool
	IfNotExists  bool

	Storing    []ID
	Interleave ID

	Position Position // position of the "CREATE" token
}

func (ci *CreateIndex) String() string { return fmt.Sprintf("%#v", ci) }
func (*CreateIndex) isDDLStmt()        {}
func (ci *CreateIndex) Pos() Position  { return ci.Position }
func (ci *CreateIndex) clearOffset()   { ci.Position.Offset = 0 }

// CreateView represents a CREATE [OR REPLACE] VIEW statement.
// https://cloud.google.com/spanner/docs/data-definition-language#view_statements
type CreateView struct {
	Name         ID
	OrReplace    bool
	SecurityType SecurityType
	Query        Query

	Position Position // position of the "CREATE" token
}

func (cv *CreateView) String() string { return fmt.Sprintf("%#v", cv) }
func (*CreateView) isDDLStmt()        {}
func (cv *CreateView) Pos() Position  { return cv.Position }
func (cv *CreateView) clearOffset()   { cv.Position.Offset = 0 }

type SecurityType int

const (
	Invoker SecurityType = iota
	Definer
)

// CreateRole represents a CREATE Role statement.
// https://cloud.google.com/spanner/docs/reference/standard-sql/data-definition-language#create_role
type CreateRole struct {
	Name ID

	Position Position // position of the "CREATE" token
}

func (cr *CreateRole) String() string { return fmt.Sprintf("%#v", cr) }
func (*CreateRole) isDDLStmt()        {}
func (cr *CreateRole) Pos() Position  { return cr.Position }
func (cr *CreateRole) clearOffset()   { cr.Position.Offset = 0 }

// DropTable represents a DROP TABLE statement.
// https://cloud.google.com/spanner/docs/data-definition-language#drop_table
type DropTable struct {
	Name     ID
	IfExists bool

	Position Position // position of the "DROP" token
}

func (dt *DropTable) String() string { return fmt.Sprintf("%#v", dt) }
func (*DropTable) isDDLStmt()        {}
func (dt *DropTable) Pos() Position  { return dt.Position }
func (dt *DropTable) clearOffset()   { dt.Position.Offset = 0 }

// DropIndex represents a DROP INDEX statement.
// https://cloud.google.com/spanner/docs/data-definition-language#drop-index
type DropIndex struct {
	Name     ID
	IfExists bool

	Position Position // position of the "DROP" token
}

func (di *DropIndex) String() string { return fmt.Sprintf("%#v", di) }
func (*DropIndex) isDDLStmt()        {}
func (di *DropIndex) Pos() Position  { return di.Position }
func (di *DropIndex) clearOffset()   { di.Position.Offset = 0 }

// DropView represents a DROP VIEW statement.
// https://cloud.google.com/spanner/docs/data-definition-language#drop-view
type DropView struct {
	Name ID

	Position Position // position of the "DROP" token
}

func (dv *DropView) String() string { return fmt.Sprintf("%#v", dv) }
func (*DropView) isDDLStmt()        {}
func (dv *DropView) Pos() Position  { return dv.Position }
func (dv *DropView) clearOffset()   { dv.Position.Offset = 0 }

// DropRole represents a DROP ROLE statement.
// https://cloud.google.com/spanner/docs/reference/standard-sql/data-definition-language#drop_role
type DropRole struct {
	Name ID

	Position Position // position of the "DROP" token
}

func (dr *DropRole) String() string { return fmt.Sprintf("%#v", dr) }
func (*DropRole) isDDLStmt()        {}
func (dr *DropRole) Pos() Position  { return dr.Position }
func (dr *DropRole) clearOffset()   { dr.Position.Offset = 0 }

// GrantRole represents a GRANT statement.
// https://cloud.google.com/spanner/docs/reference/standard-sql/data-definition-language#grant_statement
type GrantRole struct {
	ToRoleNames       []ID
	GrantRoleNames    []ID
	Privileges        []Privilege
	TableNames        []ID
	TvfNames          []ID
	ViewNames         []ID
	ChangeStreamNames []ID

	Position Position // position of the "GRANT" token
}

func (gr *GrantRole) String() string { return fmt.Sprintf("%#v", gr) }
func (*GrantRole) isDDLStmt()        {}
func (gr *GrantRole) Pos() Position  { return gr.Position }
func (gr *GrantRole) clearOffset()   { gr.Position.Offset = 0 }

// RevokeRole represents a REVOKE statement.
// https://cloud.google.com/spanner/docs/reference/standard-sql/data-definition-language#revoke_statement
type RevokeRole struct {
	FromRoleNames     []ID
	RevokeRoleNames   []ID
	Privileges        []Privilege
	TableNames        []ID
	TvfNames          []ID
	ViewNames         []ID
	ChangeStreamNames []ID
	Position          Position // position of the "REVOKE" token
}

func (rr *RevokeRole) String() string { return fmt.Sprintf("%#v", rr) }
func (*RevokeRole) isDDLStmt()        {}
func (rr *RevokeRole) Pos() Position  { return rr.Position }
func (rr *RevokeRole) clearOffset()   { rr.Position.Offset = 0 }

// Privilege represents privilege to grant or revoke.
type Privilege struct {
	Type    PrivilegeType
	Columns []ID
}

// AlterTable represents an ALTER TABLE statement.
// https://cloud.google.com/spanner/docs/data-definition-language#alter_table
type AlterTable struct {
	Name       ID
	Alteration TableAlteration

	Position Position // position of the "ALTER" token
}

func (at *AlterTable) String() string { return fmt.Sprintf("%#v", at) }
func (*AlterTable) isDDLStmt()        {}
func (at *AlterTable) Pos() Position  { return at.Position }
func (at *AlterTable) clearOffset() {
	switch alt := at.Alteration.(type) {
	case AddColumn:
		alt.Def.clearOffset()
		at.Alteration = alt
	case AddConstraint:
		alt.Constraint.clearOffset()
		at.Alteration = alt
	}
	at.Position.Offset = 0
}

// TableAlteration is satisfied by AddColumn, DropColumn, AddConstraint,
// DropConstraint, SetOnDelete, AlterColumn,
// AddRowDeletionPolicy, ReplaceRowDeletionPolicy, DropRowDeletionPolicy,
// RenameTo, AddSynonym, and DropSynonym.
type TableAlteration interface {
	isTableAlteration()
	SQL() string
}

func (AddColumn) isTableAlteration()                {}
func (DropColumn) isTableAlteration()               {}
func (AddConstraint) isTableAlteration()            {}
func (DropConstraint) isTableAlteration()           {}
func (SetOnDelete) isTableAlteration()              {}
func (AlterColumn) isTableAlteration()              {}
func (AddRowDeletionPolicy) isTableAlteration()     {}
func (ReplaceRowDeletionPolicy) isTableAlteration() {}
func (DropRowDeletionPolicy) isTableAlteration()    {}
func (RenameTo) isTableAlteration()                 {}
func (AddSynonym) isTableAlteration()               {}
func (DropSynonym) isTableAlteration()              {}

type (
	AddColumn struct {
		IfNotExists bool
		Def         ColumnDef
	}
	DropColumn     struct{ Name ID }
	AddConstraint  struct{ Constraint TableConstraint }
	DropConstraint struct{ Name ID }
	SetOnDelete    struct{ Action OnDelete }
	AlterColumn    struct {
		Name       ID
		Alteration ColumnAlteration
	}
)

type (
	AddRowDeletionPolicy     struct{ RowDeletionPolicy RowDeletionPolicy }
	ReplaceRowDeletionPolicy struct{ RowDeletionPolicy RowDeletionPolicy }
	DropRowDeletionPolicy    struct{}
)

// ColumnAlteration is satisfied by SetColumnType and SetColumnOptions.
type ColumnAlteration interface {
	isColumnAlteration()
	SQL() string
}

func (SetColumnType) isColumnAlteration()    {}
func (SetColumnOptions) isColumnAlteration() {}
func (SetDefault) isColumnAlteration()       {}
func (DropDefault) isColumnAlteration()      {}

type SetColumnType struct {
	Type    Type
	NotNull bool
	Default Expr
}

type SetColumnOptions struct{ Options ColumnOptions }

type SetDefault struct {
	Default Expr
}

type DropDefault struct{}

type OnDelete int

const (
	NoActionOnDelete OnDelete = iota
	CascadeOnDelete
)

type (
	RenameTo struct {
		ToName  ID
		Synonym ID // may be empty
	}
	AddSynonym  struct{ Name ID }
	DropSynonym struct{ Name ID }
)

// RenameTable represents a RENAME TABLE statement.
type RenameTable struct {
	TableRenameOps []TableRenameOp

	Position Position // position of the "RENAME" token
}

type TableRenameOp struct {
	FromName ID
	ToName   ID
}

func (rt *RenameTable) String() string { return fmt.Sprintf("%#v", rt) }
func (*RenameTable) isDDLStmt()        {}
func (rt *RenameTable) Pos() Position  { return rt.Position }
func (rt *RenameTable) clearOffset()   { rt.Position.Offset = 0 }

// AlterDatabase represents an ALTER DATABASE statement.
// https://cloud.google.com/spanner/docs/data-definition-language#alter-database
type AlterDatabase struct {
	Name       ID
	Alteration DatabaseAlteration

	Position Position // position of the "ALTER" token
}

func (ad *AlterDatabase) String() string { return fmt.Sprintf("%#v", ad) }
func (*AlterDatabase) isDDLStmt()        {}
func (ad *AlterDatabase) Pos() Position  { return ad.Position }
func (ad *AlterDatabase) clearOffset()   { ad.Position.Offset = 0 }

type DatabaseAlteration interface {
	isDatabaseAlteration()
	SQL() string
}

type SetDatabaseOptions struct{ Options DatabaseOptions }

func (SetDatabaseOptions) isDatabaseAlteration() {}

// DatabaseOptions represents options on a database as part of a
// ALTER DATABASE statement.
type DatabaseOptions struct {
	OptimizerVersion           *int
	OptimizerStatisticsPackage *string
	VersionRetentionPeriod     *string
	EnableKeyVisualizer        *bool
	DefaultLeader              *string
}

// Delete represents a DELETE statement.
// https://cloud.google.com/spanner/docs/dml-syntax#delete-statement
type Delete struct {
	Table ID
	Where BoolExpr

	// TODO: Alias
}

func (d *Delete) String() string { return fmt.Sprintf("%#v", d) }
func (*Delete) isDMLStmt()       {}

// Insert represents an INSERT statement.
// https://cloud.google.com/spanner/docs/dml-syntax#insert-statement
type Insert struct {
	Table   ID
	Columns []ID
	Input   ValuesOrSelect
}

// Values represents one or more lists of expressions passed to an `INSERT` statement.
type Values [][]Expr

func (v Values) isValuesOrSelect() {}
func (v Values) String() string    { return fmt.Sprintf("%#v", v) }

type ValuesOrSelect interface {
	isValuesOrSelect()
	SQL() string
}

func (Select) isValuesOrSelect() {}

func (i *Insert) String() string { return fmt.Sprintf("%#v", i) }
func (*Insert) isDMLStmt()       {}

// Update represents an UPDATE statement.
// https://cloud.google.com/spanner/docs/dml-syntax#update-statement
type Update struct {
	Table ID
	Items []UpdateItem
	Where BoolExpr

	// TODO: Alias
}

func (u *Update) String() string { return fmt.Sprintf("%#v", u) }
func (*Update) isDMLStmt()       {}

type UpdateItem struct {
	Column ID
	Value  Expr // or nil for DEFAULT
}

// ColumnDef represents a column definition as part of a CREATE TABLE
// or ALTER TABLE statement.
type ColumnDef struct {
	Name    ID
	Type    Type
	NotNull bool

	Default   Expr // set if this column has a default value
	Generated Expr // set of this is a generated column

	Options ColumnOptions

	Position Position // position of the column name
}

func (cd ColumnDef) Pos() Position { return cd.Position }
func (cd *ColumnDef) clearOffset() { cd.Position.Offset = 0 }

// ColumnOptions represents options on a column as part of a
// CREATE TABLE or ALTER TABLE statement.
type ColumnOptions struct {
	// AllowCommitTimestamp represents a column OPTIONS.
	// `true` if query is `OPTIONS (allow_commit_timestamp = true)`
	// `false` if query is `OPTIONS (allow_commit_timestamp = null)`
	// `nil` if there are no OPTIONS
	AllowCommitTimestamp *bool
}

// ForeignKey represents a foreign key definition as part of a CREATE TABLE
// or ALTER TABLE statement.
type ForeignKey struct {
	Columns    []ID
	RefTable   ID
	RefColumns []ID
	OnDelete   OnDelete

	Position Position // position of the "FOREIGN" token
}

func (fk ForeignKey) Pos() Position { return fk.Position }
func (fk *ForeignKey) clearOffset() { fk.Position.Offset = 0 }
func (ForeignKey) isConstraint()    {}

// Check represents a check constraint as part of a CREATE TABLE
// or ALTER TABLE statement.
type Check struct {
	Expr BoolExpr

	Position Position // position of the "CHECK" token
}

func (c Check) Pos() Position { return c.Position }
func (c *Check) clearOffset() { c.Position.Offset = 0 }
func (Check) isConstraint()   {}

// Type represents a column type.
type Type struct {
	Array bool
	Base  TypeBase // Bool, Int64, Float64, Numeric, String, Bytes, Date, Timestamp
	Len   int64    // if Base is String or Bytes; may be MaxLen
}

// MaxLen is a sentinel for Type's Len field, representing the MAX value.
const MaxLen = math.MaxInt64

type TypeBase int

const (
	Bool TypeBase = iota
	Int64
	Float64
	Numeric
	String
	Bytes
	Date
	Timestamp
	JSON
)

type PrivilegeType int

const (
	PrivilegeTypeSelect PrivilegeType = iota
	PrivilegeTypeInsert
	PrivilegeTypeUpdate
	PrivilegeTypeDelete
)

// KeyPart represents a column specification as part of a primary key or index definition.
type KeyPart struct {
	Column ID
	Desc   bool
}

// Query represents a query statement.
// https://cloud.google.com/spanner/docs/query-syntax#sql-syntax
type Query struct {
	Select Select
	Order  []Order

	Limit, Offset LiteralOrParam
}

// Select represents a SELECT statement.
// https://cloud.google.com/spanner/docs/query-syntax#select-list
type Select struct {
	Distinct bool
	List     []Expr
	From     []SelectFrom
	Where    BoolExpr
	GroupBy  []Expr
	// TODO: Having

	// When the FROM clause has TABLESAMPLE operators,
	// TableSamples will be populated 1:1 with From;
	// FROM clauses without will have a nil value.
	TableSamples []*TableSample

	// If the SELECT list has explicit aliases ("AS alias"),
	// ListAliases will be populated 1:1 with List;
	// aliases that are present will be non-empty.
	ListAliases []ID
}

// SelectFrom represents the FROM clause of a SELECT.
// https://cloud.google.com/spanner/docs/query-syntax#from_clause
type SelectFrom interface {
	isSelectFrom()
	SQL() string
}

// SelectFromTable is a SelectFrom that specifies a table to read from.
type SelectFromTable struct {
	Table ID
	Alias ID // empty if not aliased
	Hints map[string]string
}

func (SelectFromTable) isSelectFrom() {}

// SelectFromJoin is a SelectFrom that joins two other SelectFroms.
// https://cloud.google.com/spanner/docs/query-syntax#join_types
type SelectFromJoin struct {
	Type     JoinType
	LHS, RHS SelectFrom

	// Join condition.
	// At most one of {On,Using} may be set.
	On    BoolExpr
	Using []ID

	// Hints are suggestions for how to evaluate a join.
	// https://cloud.google.com/spanner/docs/query-syntax#join-hints
	Hints map[string]string
}

func (SelectFromJoin) isSelectFrom() {}

type JoinType int

const (
	InnerJoin JoinType = iota
	CrossJoin
	FullJoin
	LeftJoin
	RightJoin
)

// SelectFromUnnest is a SelectFrom that yields a virtual table from an array.
// https://cloud.google.com/spanner/docs/query-syntax#unnest
type SelectFromUnnest struct {
	Expr  Expr
	Alias ID // empty if not aliased

	// TODO: Implicit
}

func (SelectFromUnnest) isSelectFrom() {}

// TODO: SelectFromSubquery, etc.

type Order struct {
	Expr Expr
	Desc bool
}

type TableSample struct {
	Method   TableSampleMethod
	Size     Expr
	SizeType TableSampleSizeType
}

type TableSampleMethod int

const (
	Bernoulli TableSampleMethod = iota
	Reservoir
)

type TableSampleSizeType int

const (
	PercentTableSample TableSampleSizeType = iota
	RowsTableSample
)

type BoolExpr interface {
	isBoolExpr()
	Expr
}

type Expr interface {
	isExpr()
	SQL() string
	addSQL(*strings.Builder)
}

// LiteralOrParam is implemented by integer literal and parameter values.
type LiteralOrParam interface {
	isLiteralOrParam()
	SQL() string
}

type ArithOp struct {
	Op       ArithOperator
	LHS, RHS Expr // only RHS is set for Neg, Plus, BitNot
}

func (ArithOp) isExpr() {}

type ArithOperator int

const (
	Neg    ArithOperator = iota // unary -
	Plus                        // unary +
	BitNot                      // unary ~
	Mul                         // *
	Div                         // /
	Concat                      // ||
	Add                         // +
	Sub                         // -
	BitShl                      // <<
	BitShr                      // >>
	BitAnd                      // &
	BitXor                      // ^
	BitOr                       // |
)

type LogicalOp struct {
	Op       LogicalOperator
	LHS, RHS BoolExpr // only RHS is set for Not
}

func (LogicalOp) isBoolExpr() {}
func (LogicalOp) isExpr()     {}

type LogicalOperator int

const (
	And LogicalOperator = iota
	Or
	Not
)

type ComparisonOp struct {
	Op       ComparisonOperator
	LHS, RHS Expr

	// RHS2 is the third operand for BETWEEN.
	// "<LHS> BETWEEN <RHS> AND <RHS2>".
	RHS2 Expr
}

func (ComparisonOp) isBoolExpr() {}
func (ComparisonOp) isExpr()     {}

type ComparisonOperator int

const (
	Lt ComparisonOperator = iota
	Le
	Gt
	Ge
	Eq
	Ne // both "!=" and "<>"
	Like
	NotLike
	Between
	NotBetween
)

type InOp struct {
	LHS    Expr
	Neg    bool
	RHS    []Expr
	Unnest bool

	// TODO: support subquery form
}

func (InOp) isBoolExpr() {} // usually
func (InOp) isExpr()     {}

type IsOp struct {
	LHS Expr
	Neg bool
	RHS IsExpr
}

func (IsOp) isBoolExpr() {}
func (IsOp) isExpr()     {}

type IsExpr interface {
	isIsExpr()
	Expr
}

// PathExp represents a path expression.
//
// The grammar for path expressions is not defined (see b/169017423 internally),
// so this captures the most common form only, namely a dotted sequence of identifiers.
type PathExp []ID

func (PathExp) isExpr() {}

// Func represents a function call.
type Func struct {
	Name string // not ID
	Args []Expr

	Distinct      bool
	NullsHandling NullsHandling
	Having        *AggregateHaving
}

func (Func) isBoolExpr() {} // possibly bool
func (Func) isExpr()     {}

// TypedExpr represents a typed expression in the form `expr AS type_name`, e.g. `'17' AS INT64`.
type TypedExpr struct {
	Type Type
	Expr Expr
}

func (TypedExpr) isBoolExpr() {} // possibly bool
func (TypedExpr) isExpr()     {}

type ExtractExpr struct {
	Part string
	Type Type
	Expr Expr
}

func (ExtractExpr) isBoolExpr() {} // possibly bool
func (ExtractExpr) isExpr()     {}

type AtTimeZoneExpr struct {
	Expr Expr
	Type Type
	Zone string
}

func (AtTimeZoneExpr) isBoolExpr() {} // possibly bool
func (AtTimeZoneExpr) isExpr()     {}

type IntervalExpr struct {
	Expr     Expr
	DatePart string
}

func (IntervalExpr) isBoolExpr() {} // possibly bool
func (IntervalExpr) isExpr()     {}

type SequenceExpr struct {
	Name ID
}

func (SequenceExpr) isExpr() {}

// NullsHandling represents the method of dealing with NULL values in aggregate functions.
type NullsHandling int

const (
	NullsHandlingUnspecified NullsHandling = iota
	RespectNulls
	IgnoreNulls
)

// AggregateHaving represents the HAVING clause specific to aggregate functions, restricting rows based on a maximal or minimal value.
type AggregateHaving struct {
	Condition AggregateHavingCondition
	Expr      Expr
}

// AggregateHavingCondition represents the condition (MAX or MIN) for the AggregateHaving clause.
type AggregateHavingCondition int

const (
	HavingMax AggregateHavingCondition = iota
	HavingMin
)

// Paren represents a parenthesised expression.
type Paren struct {
	Expr Expr
}

func (Paren) isBoolExpr() {} // possibly bool
func (Paren) isExpr()     {}

// Array represents an array literal.
type Array []Expr

func (Array) isExpr() {}

// ID represents an identifier.
// https://cloud.google.com/spanner/docs/lexical#identifiers
type ID string

func (ID) isBoolExpr() {} // possibly bool
func (ID) isExpr()     {}

// Param represents a query parameter.
type Param string

func (Param) isBoolExpr()       {} // possibly bool
func (Param) isExpr()           {}
func (Param) isLiteralOrParam() {}

type Case struct {
	Expr        Expr
	WhenClauses []WhenClause
	ElseResult  Expr
}

func (Case) isBoolExpr() {} // possibly bool
func (Case) isExpr()     {}

type WhenClause struct {
	Cond   Expr
	Result Expr
}

type Coalesce struct {
	ExprList []Expr
}

func (Coalesce) isBoolExpr() {} // possibly bool
func (Coalesce) isExpr()     {}

type If struct {
	Expr       Expr
	TrueResult Expr
	ElseResult Expr
}

func (If) isBoolExpr() {} // possibly bool
func (If) isExpr()     {}

type IfNull struct {
	Expr       Expr
	NullResult Expr
}

func (IfNull) isBoolExpr() {} // possibly bool
func (IfNull) isExpr()     {}

type NullIf struct {
	Expr        Expr
	ExprToMatch Expr
}

func (NullIf) isBoolExpr() {} // possibly bool
func (NullIf) isExpr()     {}

type BoolLiteral bool

const (
	True  = BoolLiteral(true)
	False = BoolLiteral(false)
)

func (BoolLiteral) isBoolExpr() {}
func (BoolLiteral) isIsExpr()   {}
func (BoolLiteral) isExpr()     {}

type NullLiteral int

const Null = NullLiteral(0)

func (NullLiteral) isIsExpr() {}
func (NullLiteral) isExpr()   {}

// IntegerLiteral represents an integer literal.
// https://cloud.google.com/spanner/docs/lexical#integer-literals
type IntegerLiteral int64

func (IntegerLiteral) isLiteralOrParam() {}
func (IntegerLiteral) isExpr()           {}

// FloatLiteral represents a floating point literal.
// https://cloud.google.com/spanner/docs/lexical#floating-point-literals
type FloatLiteral float64

func (FloatLiteral) isExpr() {}

// StringLiteral represents a string literal.
// https://cloud.google.com/spanner/docs/lexical#string-and-bytes-literals
type StringLiteral string

func (StringLiteral) isExpr() {}

// BytesLiteral represents a bytes literal.
// https://cloud.google.com/spanner/docs/lexical#string-and-bytes-literals
type BytesLiteral string

func (BytesLiteral) isExpr() {}

// DateLiteral represents a date literal.
// https://cloud.google.com/spanner/docs/lexical#date_literals
type DateLiteral civil.Date

func (DateLiteral) isExpr() {}

// TimestampLiteral represents a timestamp literal.
// https://cloud.google.com/spanner/docs/lexical#timestamp_literals
type TimestampLiteral time.Time

func (TimestampLiteral) isExpr() {}

// JSONLiteral represents a JSON literal
// https://cloud.google.com/spanner/docs/reference/standard-sql/lexical#json_literals
type JSONLiteral []byte

func (JSONLiteral) isExpr() {}

type StarExpr int

// Star represents a "*" in an expression.
const Star = StarExpr(0)

func (StarExpr) isExpr() {}

type statements interface {
	setFilename(string)
	getComments() []*Comment
	addComment(*Comment)
}

// DDL
// https://cloud.google.com/spanner/docs/data-definition-language#ddl_syntax

// DDL represents a Data Definition Language (DDL) file.
type DDL struct {
	List []DDLStmt

	Filename string // if known at parse time

	Comments []*Comment // all comments, sorted by position
}

func (d *DDL) clearOffset() {
	for _, stmt := range d.List {
		stmt.clearOffset()
	}
	for _, c := range d.Comments {
		c.clearOffset()
	}
}

func (d *DDL) setFilename(filename string) {
	d.Filename = filename
}

func (d *DDL) addComment(comment *Comment) {
	d.Comments = append(d.Comments, comment)
}

func (d *DDL) getComments() []*Comment {
	return d.Comments
}

// DML
// https://cloud.google.com/spanner/docs/reference/standard-sql/dml-syntax

// DML represents a Data Manipulation Language (DML) file.
type DML struct {
	List []DMLStmt

	Filename string // if known at parse time

	Comments []*Comment // all comments, sorted by position
}

func (d *DML) clearOffset() {
	for _, c := range d.Comments {
		c.clearOffset()
	}
}

func (d *DML) setFilename(filename string) {
	d.Filename = filename
}

func (d *DML) addComment(comment *Comment) {
	d.Comments = append(d.Comments, comment)
}

func (d *DML) getComments() []*Comment {
	return d.Comments
}

// DDLStmt is satisfied by a type that can appear in a DDL.
type DDLStmt interface {
	isDDLStmt()
	clearOffset()
	SQL() string
	Node
}

// DMLStmt is satisfied by a type that is a DML statement.
type DMLStmt interface {
	isDMLStmt()
	SQL() string
}

// Comment represents a comment.
type Comment struct {
	Marker   string // Opening marker; one of "#", "--", "/*".
	Isolated bool   // Whether this comment is on its own line.
	// Start and End are the position of the opening and terminating marker.
	Start, End Position
	Text       []string
}

func (c *Comment) String() string { return fmt.Sprintf("%#v", c) }
func (c *Comment) Pos() Position  { return c.Start }
func (c *Comment) clearOffset()   { c.Start.Offset, c.End.Offset = 0, 0 }

// Node is implemented by concrete types in this package that represent things
// appearing in a DDL file.
type Node interface {
	Pos() Position
	// clearOffset() is not included here because some types like ColumnDef
	// have the method on their pointer type rather than their natural value type.
	// This method is only invoked from within this package, so it isn't
	// important to enforce such things.
}

// Position describes a source position in an input DDL file.
// It is only valid if the line number is positive.
type Position struct {
	Line   int // 1-based line number
	Offset int // 0-based byte offset
}

func (pos Position) IsValid() bool { return pos.Line > 0 }
func (pos Position) String() string {
	if pos.Line == 0 {
		return ":<invalid>"
	}
	return fmt.Sprintf(":%d", pos.Line)
}

// LeadingComment returns the comment that immediately precedes a node,
// or nil if there's no such comment.
func (d *DDL) LeadingComment(n Node) *Comment {
	return getLeadingComment(d, n)
}

// InlineComment returns the comment on the same line as a node,
// or nil if there's no inline comment.
// The returned comment is guaranteed to be a single line.
func (d *DDL) InlineComment(n Node) *Comment {
	return getInlineComment(d, n)
}

// LeadingComment returns the comment that immediately precedes a node,
// or nil if there's no such comment.
func (d *DML) LeadingComment(n Node) *Comment {
	return getLeadingComment(d, n)
}

// InlineComment returns the comment on the same line as a node,
// or nil if there's no inline comment.
// The returned comment is guaranteed to be a single line.
func (d *DML) InlineComment(n Node) *Comment {
	return getInlineComment(d, n)
}

func getLeadingComment(stmts statements, n Node) *Comment {
	// Get the comment whose End position is on the previous line.
	lineEnd := n.Pos().Line - 1
	comments := stmts.getComments()
	ci := sort.Search(len(comments), func(i int) bool {
		return comments[i].End.Line >= lineEnd
	})
	if ci >= len(comments) || comments[ci].End.Line != lineEnd {
		return nil
	}
	if !comments[ci].Isolated {
		// This is an inline comment for a previous node.
		return nil
	}
	return comments[ci]
}

func getInlineComment(stmts statements, n Node) *Comment {
	// TODO: Do we care about comments like this?
	// 	string name = 1; /* foo
	// 	bar */

	pos := n.Pos()
	comments := stmts.getComments()
	ci := sort.Search(len(comments), func(i int) bool {
		return comments[i].Start.Line >= pos.Line
	})
	if ci >= len(comments) {
		return nil
	}
	c := comments[ci]
	if c.Start.Line != pos.Line {
		return nil
	}
	if c.Start.Line != c.End.Line || len(c.Text) != 1 {
		// Multi-line comment; don't return it.
		return nil
	}
	return c
}

// CreateChangeStream represents a CREATE CHANGE STREAM statement.
// https://cloud.google.com/spanner/docs/change-streams/manage
type CreateChangeStream struct {
	Name           ID
	Watch          []WatchDef
	WatchAllTables bool
	Options        ChangeStreamOptions

	Position Position
}

func (cs *CreateChangeStream) String() string { return fmt.Sprintf("%#v", cs) }
func (*CreateChangeStream) isDDLStmt()        {}
func (cs *CreateChangeStream) Pos() Position  { return cs.Position }
func (cs *CreateChangeStream) clearOffset() {
	for i := range cs.Watch {
		// Mutate in place.
		cs.Watch[i].clearOffset()
	}
	cs.Position.Offset = 0
}

// AlterChangeStream represents a ALTER CHANGE STREAM statement.
type AlterChangeStream struct {
	Name       ID
	Alteration ChangeStreamAlteration

	Position Position
}

func (acs *AlterChangeStream) String() string { return fmt.Sprintf("%#v", acs) }
func (*AlterChangeStream) isDDLStmt()         {}
func (acs *AlterChangeStream) Pos() Position  { return acs.Position }
func (acs *AlterChangeStream) clearOffset() {
	acs.Position.Offset = 0
}

type ChangeStreamAlteration interface {
	isChangeStreamAlteration()
	SQL() string
}

func (AlterWatch) isChangeStreamAlteration()               {}
func (DropChangeStreamWatch) isChangeStreamAlteration()    {}
func (AlterChangeStreamOptions) isChangeStreamAlteration() {}

type (
	AlterWatch struct {
		WatchAllTables bool
		Watch          []WatchDef
	}
	DropChangeStreamWatch    struct{}
	AlterChangeStreamOptions struct{ Options ChangeStreamOptions }
)

// DropChangeStream represents a DROP CHANGE STREAM statement.
type DropChangeStream struct {
	Name ID

	Position Position
}

func (dc *DropChangeStream) String() string { return fmt.Sprintf("%#v", dc) }
func (*DropChangeStream) isDDLStmt()        {}
func (dc *DropChangeStream) Pos() Position  { return dc.Position }
func (dc *DropChangeStream) clearOffset()   { dc.Position.Offset = 0 }

type WatchDef struct {
	Table        ID
	Columns      []ID
	WatchAllCols bool

	Position Position
}

func (wd WatchDef) Pos() Position { return wd.Position }
func (wd *WatchDef) clearOffset() { wd.Position.Offset = 0 }

type ChangeStreamOptions struct {
	RetentionPeriod  *string
	ValueCaptureType *string
}

// AlterStatistics represents an ALTER STATISTICS statement.
// https://cloud.google.com/spanner/docs/data-definition-language#alter-statistics
type AlterStatistics struct {
	Name       ID
	Alteration StatisticsAlteration

	Position Position // position of the "ALTER" token
}

func (as *AlterStatistics) String() string { return fmt.Sprintf("%#v", as) }
func (*AlterStatistics) isDDLStmt()        {}
func (as *AlterStatistics) Pos() Position  { return as.Position }
func (as *AlterStatistics) clearOffset()   { as.Position.Offset = 0 }

type StatisticsAlteration interface {
	isStatisticsAlteration()
	SQL() string
}

type SetStatisticsOptions struct{ Options StatisticsOptions }

func (SetStatisticsOptions) isStatisticsAlteration() {}

// StatisticsOptions represents options on a statistics as part of a ALTER STATISTICS statement.
type StatisticsOptions struct {
	AllowGC *bool
}

type AlterIndex struct {
	Name       ID
	Alteration IndexAlteration

	Position Position // position of the "ALTER" token
}

func (as *AlterIndex) String() string { return fmt.Sprintf("%#v", as) }
func (*AlterIndex) isDDLStmt()        {}
func (as *AlterIndex) Pos() Position  { return as.Position }
func (as *AlterIndex) clearOffset()   { as.Position.Offset = 0 }

type IndexAlteration interface {
	isIndexAlteration()
	SQL() string
}

func (AddStoredColumn) isIndexAlteration()  {}
func (DropStoredColumn) isIndexAlteration() {}

type (
	AddStoredColumn  struct{ Name ID }
	DropStoredColumn struct{ Name ID }
)

// CreateSequence represents an ALTER SEQUENCE statement.
// https://cloud.google.com/spanner/docs/reference/standard-sql/data-definition-language#create-sequence
type CreateSequence struct {
	Name        ID
	IfNotExists bool
	Options     SequenceOptions

	Position Position
}

func (cs *CreateSequence) String() string { return fmt.Sprintf("%#v", cs) }
func (*CreateSequence) isDDLStmt()        {}
func (cs *CreateSequence) Pos() Position  { return cs.Position }
func (cs *CreateSequence) clearOffset()   { cs.Position.Offset = 0 }

// AlterSequence represents an ALTER SEQUENCE statement.
// https://cloud.google.com/spanner/docs/reference/standard-sql/data-definition-language#alter-sequence
type AlterSequence struct {
	Name       ID
	Alteration SequenceAlteration

	Position Position
}

func (as *AlterSequence) String() string { return fmt.Sprintf("%#v", as) }
func (*AlterSequence) isDDLStmt()        {}
func (as *AlterSequence) Pos() Position  { return as.Position }
func (as *AlterSequence) clearOffset()   { as.Position.Offset = 0 }

type SequenceAlteration interface {
	isSequenceAlteration()
	SQL() string
}

type SetSequenceOptions struct{ Options SequenceOptions }

func (SetSequenceOptions) isSequenceAlteration() {}

// SequenceOptions represents options on a sequence as part of a CREATE SEQUENCE and ALTER SEQUENCE statement.
type SequenceOptions struct {
	SequenceKind     *string
	SkipRangeMin     *int
	SkipRangeMax     *int
	StartWithCounter *int
}

// DropSequence represents a DROP SEQUENCE statement.
// https://cloud.google.com/spanner/docs/reference/standard-sql/data-definition-language#drop-sequence
type DropSequence struct {
	Name     ID
	IfExists bool

	Position Position
}

func (ds *DropSequence) String() string { return fmt.Sprintf("%#v", ds) }
func (*DropSequence) isDDLStmt()        {}
func (ds *DropSequence) Pos() Position  { return ds.Position }
func (ds *DropSequence) clearOffset()   { ds.Position.Offset = 0 }
