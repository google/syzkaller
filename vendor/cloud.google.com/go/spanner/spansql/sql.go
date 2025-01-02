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

// This file holds SQL methods for rendering the types in types.go
// as the SQL dialect that this package parses.
//
// Every exported type has an SQL method that returns a string.
// Some also have an addSQL method that efficiently builds that string
// in a provided strings.Builder.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

func buildSQL(x interface{ addSQL(*strings.Builder) }) string {
	var sb strings.Builder
	x.addSQL(&sb)
	return sb.String()
}

func (ct CreateTable) SQL() string {
	str := "CREATE TABLE "
	if ct.IfNotExists {
		str += "IF NOT EXISTS "
	}
	str += ct.Name.SQL() + " (\n"
	for _, c := range ct.Columns {
		str += "  " + c.SQL() + ",\n"
	}
	for _, tc := range ct.Constraints {
		str += "  " + tc.SQL() + ",\n"
	}
	if len(ct.Synonym) > 0 {
		str += "  SYNONYM(" + ct.Synonym.SQL() + "),\n"
	}
	str += ") PRIMARY KEY("
	for i, c := range ct.PrimaryKey {
		if i > 0 {
			str += ", "
		}
		str += c.SQL()
	}
	str += ")"
	if il := ct.Interleave; il != nil {
		str += ",\n  INTERLEAVE IN PARENT " + il.Parent.SQL() + " ON DELETE " + il.OnDelete.SQL()
	}
	if rdp := ct.RowDeletionPolicy; rdp != nil {
		str += ",\n  " + rdp.SQL()
	}
	return str
}

func (ci CreateIndex) SQL() string {
	str := "CREATE"
	if ci.Unique {
		str += " UNIQUE"
	}
	if ci.NullFiltered {
		str += " NULL_FILTERED"
	}
	str += " INDEX "
	if ci.IfNotExists {
		str += "IF NOT EXISTS "
	}
	str += ci.Name.SQL() + " ON " + ci.Table.SQL() + "("
	for i, c := range ci.Columns {
		if i > 0 {
			str += ", "
		}
		str += c.SQL()
	}
	str += ")"
	if len(ci.Storing) > 0 {
		str += " STORING (" + idList(ci.Storing, ", ") + ")"
	}
	if ci.Interleave != "" {
		str += ", INTERLEAVE IN " + ci.Interleave.SQL()
	}
	return str
}

func (cv CreateView) SQL() string {
	str := "CREATE"
	if cv.OrReplace {
		str += " OR REPLACE"
	}
	str += " VIEW " + cv.Name.SQL() + " SQL SECURITY " + cv.SecurityType.SQL() + " AS " + cv.Query.SQL()
	return str
}

func (st SecurityType) SQL() string {
	switch st {
	case Invoker:
		return "INVOKER"
	case Definer:
		return "DEFINER"
	}
	panic("unknown SecurityType")
}

func (cr CreateRole) SQL() string {
	return "CREATE ROLE " + cr.Name.SQL()
}

func (cs CreateChangeStream) SQL() string {
	str := "CREATE CHANGE STREAM "
	str += cs.Name.SQL()
	if cs.WatchAllTables {
		str += " FOR ALL"
	} else {
		for i, table := range cs.Watch {
			if i == 0 {
				str += " FOR "
			} else {
				str += ", "
			}
			str += table.SQL()
		}
	}
	if cs.Options != (ChangeStreamOptions{}) {
		str += " " + cs.Options.SQL()
	}

	return str
}

func (w WatchDef) SQL() string {
	str := w.Table.SQL()
	if !w.WatchAllCols {
		str += "("
		for i, c := range w.Columns {
			if i > 0 {
				str += ", "
			}
			str += c.SQL()
		}
		str += ")"
	}
	return str
}

func (dt DropTable) SQL() string {
	str := "DROP TABLE "
	if dt.IfExists {
		str += "IF EXISTS "
	}
	str += dt.Name.SQL()
	return str
}

func (di DropIndex) SQL() string {
	str := "DROP INDEX "
	if di.IfExists {
		str += "IF EXISTS "
	}
	str += di.Name.SQL()
	return str
}

func (dv DropView) SQL() string {
	return "DROP VIEW " + dv.Name.SQL()
}

func (dr DropRole) SQL() string {
	return "DROP ROLE " + dr.Name.SQL()
}

func (gr GrantRole) SQL() string {
	sql := "GRANT "
	if gr.Privileges != nil {
		for i, priv := range gr.Privileges {
			if i > 0 {
				sql += ", "
			}
			sql += priv.Type.SQL()
			if priv.Columns != nil {
				sql += "(" + idList(priv.Columns, ", ") + ")"
			}
		}
		sql += " ON TABLE " + idList(gr.TableNames, ", ")
	} else if len(gr.TvfNames) > 0 {
		sql += "EXECUTE ON TABLE FUNCTION " + idList(gr.TvfNames, ", ")
	} else if len(gr.ViewNames) > 0 {
		sql += "SELECT ON VIEW " + idList(gr.ViewNames, ", ")
	} else if len(gr.ChangeStreamNames) > 0 {
		sql += "SELECT ON CHANGE STREAM " + idList(gr.ChangeStreamNames, ", ")
	} else {
		sql += "ROLE " + idList(gr.GrantRoleNames, ", ")
	}
	sql += " TO ROLE " + idList(gr.ToRoleNames, ", ")
	return sql
}

func (rr RevokeRole) SQL() string {
	sql := "REVOKE "
	if rr.Privileges != nil {
		for i, priv := range rr.Privileges {
			if i > 0 {
				sql += ", "
			}
			sql += priv.Type.SQL()
			if priv.Columns != nil {
				sql += "(" + idList(priv.Columns, ", ") + ")"
			}
		}
		sql += " ON TABLE " + idList(rr.TableNames, ", ")
	} else if len(rr.TvfNames) > 0 {
		sql += "EXECUTE ON TABLE FUNCTION " + idList(rr.TvfNames, ", ")
	} else if len(rr.ViewNames) > 0 {
		sql += "SELECT ON VIEW " + idList(rr.ViewNames, ", ")
	} else if len(rr.ChangeStreamNames) > 0 {
		sql += "SELECT ON CHANGE STREAM " + idList(rr.ChangeStreamNames, ", ")
	} else {
		sql += "ROLE " + idList(rr.RevokeRoleNames, ", ")
	}
	sql += " FROM ROLE " + idList(rr.FromRoleNames, ", ")
	return sql
}

func (dc DropChangeStream) SQL() string {
	return "DROP CHANGE STREAM " + dc.Name.SQL()
}

func (acs AlterChangeStream) SQL() string {
	return "ALTER CHANGE STREAM " + acs.Name.SQL() + " " + acs.Alteration.SQL()
}

func (scsw AlterWatch) SQL() string {
	str := "SET FOR "
	if scsw.WatchAllTables {
		return str + "ALL"
	}
	for i, table := range scsw.Watch {
		if i > 0 {
			str += ", "
		}
		str += table.SQL()
	}
	return str
}

func (ao AlterChangeStreamOptions) SQL() string {
	return "SET " + ao.Options.SQL()
}

func (dcsw DropChangeStreamWatch) SQL() string {
	return "DROP FOR ALL"
}

func (cso ChangeStreamOptions) SQL() string {
	str := "OPTIONS ("
	hasOpt := false
	if cso.RetentionPeriod != nil {
		hasOpt = true
		str += fmt.Sprintf("retention_period='%s'", *cso.RetentionPeriod)
	}
	if cso.ValueCaptureType != nil {
		if hasOpt {
			str += ", "
		}
		hasOpt = true
		str += fmt.Sprintf("value_capture_type='%s'", *cso.ValueCaptureType)
	}
	str += ")"
	return str
}

func (at AlterTable) SQL() string {
	return "ALTER TABLE " + at.Name.SQL() + " " + at.Alteration.SQL()
}

func (ac AddColumn) SQL() string {
	str := "ADD COLUMN "
	if ac.IfNotExists {
		str += "IF NOT EXISTS "
	}
	str += ac.Def.SQL()
	return str
}

func (dc DropColumn) SQL() string {
	return "DROP COLUMN " + dc.Name.SQL()
}

func (ac AddConstraint) SQL() string {
	return "ADD " + ac.Constraint.SQL()
}

func (dc DropConstraint) SQL() string {
	return "DROP CONSTRAINT " + dc.Name.SQL()
}

func (rt RenameTo) SQL() string {
	str := "RENAME TO " + rt.ToName.SQL()
	if len(rt.Synonym) > 0 {
		str += ", ADD SYNONYM " + rt.Synonym.SQL()
	}
	return str
}

func (as AddSynonym) SQL() string {
	return "ADD SYNONYM " + as.Name.SQL()
}

func (ds DropSynonym) SQL() string {
	return "DROP SYNONYM " + ds.Name.SQL()
}

func (sod SetOnDelete) SQL() string {
	return "SET ON DELETE " + sod.Action.SQL()
}

func (od OnDelete) SQL() string {
	switch od {
	case NoActionOnDelete:
		return "NO ACTION"
	case CascadeOnDelete:
		return "CASCADE"
	}
	panic("unknown OnDelete")
}

func (ac AlterColumn) SQL() string {
	return "ALTER COLUMN " + ac.Name.SQL() + " " + ac.Alteration.SQL()
}

func (ardp AddRowDeletionPolicy) SQL() string {
	return "ADD " + ardp.RowDeletionPolicy.SQL()
}

func (rrdp ReplaceRowDeletionPolicy) SQL() string {
	return "REPLACE " + rrdp.RowDeletionPolicy.SQL()
}

func (drdp DropRowDeletionPolicy) SQL() string {
	return "DROP ROW DELETION POLICY"
}

func (sct SetColumnType) SQL() string {
	str := sct.Type.SQL()
	if sct.NotNull {
		str += " NOT NULL"
	}
	if sct.Default != nil {
		str += " DEFAULT (" + sct.Default.SQL() + ")"
	}
	return str
}

func (sco SetColumnOptions) SQL() string {
	// TODO: not clear what to do for no options.
	return "SET " + sco.Options.SQL()
}

func (sd SetDefault) SQL() string {
	return "SET DEFAULT (" + sd.Default.SQL() + ")"
}

func (dp DropDefault) SQL() string {
	return "DROP DEFAULT"
}

func (co ColumnOptions) SQL() string {
	str := "OPTIONS ("
	if co.AllowCommitTimestamp != nil {
		if *co.AllowCommitTimestamp {
			str += "allow_commit_timestamp = true"
		} else {
			str += "allow_commit_timestamp = null"
		}
	}
	str += ")"
	return str
}

func (rt RenameTable) SQL() string {
	str := "RENAME TABLE "
	for i, op := range rt.TableRenameOps {
		if i > 0 {
			str += ", "
		}
		str += op.FromName.SQL() + " TO " + op.ToName.SQL()
	}
	return str
}

func (ad AlterDatabase) SQL() string {
	return "ALTER DATABASE " + ad.Name.SQL() + " " + ad.Alteration.SQL()
}

func (sdo SetDatabaseOptions) SQL() string {
	return "SET " + sdo.Options.SQL()
}

func (do DatabaseOptions) SQL() string {
	str := "OPTIONS ("
	hasOpt := false
	if do.OptimizerVersion != nil {
		hasOpt = true
		if *do.OptimizerVersion == 0 {
			str += "optimizer_version=null"
		} else {
			str += fmt.Sprintf("optimizer_version=%v", *do.OptimizerVersion)
		}
	}
	if do.OptimizerStatisticsPackage != nil {
		if hasOpt {
			str += ", "
		}
		hasOpt = true
		if *do.OptimizerStatisticsPackage == "" {
			str += "optimizer_statistics_package=null"
		} else {
			str += fmt.Sprintf("optimizer_statistics_package='%s'", *do.OptimizerStatisticsPackage)
		}
	}
	if do.VersionRetentionPeriod != nil {
		if hasOpt {
			str += ", "
		}
		hasOpt = true
		if *do.VersionRetentionPeriod == "" {
			str += "version_retention_period=null"
		} else {
			str += fmt.Sprintf("version_retention_period='%s'", *do.VersionRetentionPeriod)
		}
	}
	if do.EnableKeyVisualizer != nil {
		if hasOpt {
			str += ", "
		}
		hasOpt = true
		if *do.EnableKeyVisualizer {
			str += "enable_key_visualizer=true"
		} else {
			str += "enable_key_visualizer=null"
		}
	}
	if do.DefaultLeader != nil {
		if hasOpt {
			str += ", "
		}
		hasOpt = true
		if *do.DefaultLeader == "" {
			str += "default_leader=null"
		} else {
			str += fmt.Sprintf("default_leader='%s'", *do.DefaultLeader)
		}
	}
	str += ")"
	return str
}

func (as AlterStatistics) SQL() string {
	return "ALTER STATISTICS " + as.Name.SQL() + " " + as.Alteration.SQL()
}

func (sso SetStatisticsOptions) SQL() string {
	return "SET " + sso.Options.SQL()
}

func (sa StatisticsOptions) SQL() string {
	str := "OPTIONS ("
	if sa.AllowGC != nil {
		str += fmt.Sprintf("allow_gc=%v", *sa.AllowGC)
	}
	str += ")"
	return str
}

func (ai AlterIndex) SQL() string {
	return "ALTER INDEX " + ai.Name.SQL() + " " + ai.Alteration.SQL()
}

func (asc AddStoredColumn) SQL() string {
	return "ADD STORED COLUMN " + asc.Name.SQL()
}

func (dsc DropStoredColumn) SQL() string {
	return "DROP STORED COLUMN " + dsc.Name.SQL()
}

func (cs CreateSequence) SQL() string {
	str := "CREATE SEQUENCE "
	if cs.IfNotExists {
		str += "IF NOT EXISTS "
	}
	return str + cs.Name.SQL() + " " + cs.Options.SQL()
}

func (as AlterSequence) SQL() string {
	return "ALTER SEQUENCE " + as.Name.SQL() + " " + as.Alteration.SQL()
}

func (sa SetSequenceOptions) SQL() string {
	return "SET " + sa.Options.SQL()
}

func (so SequenceOptions) SQL() string {
	str := "OPTIONS ("
	hasOpt := false
	if so.SequenceKind != nil {
		hasOpt = true
		str += fmt.Sprintf("sequence_kind='%s'", *so.SequenceKind)
	}
	if so.SkipRangeMin != nil {
		if hasOpt {
			str += ", "
		}
		hasOpt = true
		str += fmt.Sprintf("skip_range_min=%v", *so.SkipRangeMin)
	}
	if so.SkipRangeMax != nil {
		if hasOpt {
			str += ", "
		}
		hasOpt = true
		str += fmt.Sprintf("skip_range_max=%v", *so.SkipRangeMax)
	}
	if so.StartWithCounter != nil {
		if hasOpt {
			str += ", "
		}
		hasOpt = true
		str += fmt.Sprintf("start_with_counter=%v", *so.StartWithCounter)
	}
	return str + ")"
}

func (do DropSequence) SQL() string {
	str := "DROP SEQUENCE "
	if do.IfExists {
		str += "IF EXISTS "
	}
	return str + do.Name.SQL()
}

func (d *Delete) SQL() string {
	return "DELETE FROM " + d.Table.SQL() + " WHERE " + d.Where.SQL()
}

func (u *Update) SQL() string {
	str := "UPDATE " + u.Table.SQL() + " SET "
	for i, item := range u.Items {
		if i > 0 {
			str += ", "
		}
		str += item.Column.SQL() + " = "
		if item.Value != nil {
			str += item.Value.SQL()
		} else {
			str += "DEFAULT"
		}
	}
	str += " WHERE " + u.Where.SQL()
	return str
}

func (i *Insert) SQL() string {
	str := "INSERT INTO " + i.Table.SQL() + " ("
	for i, column := range i.Columns {
		if i > 0 {
			str += ", "
		}
		str += column.SQL()
	}
	str += ") "
	str += i.Input.SQL()
	return str
}

func (v Values) SQL() string {
	str := "VALUES "
	for j, values := range v {
		if j > 0 {
			str += ", "
		}
		str += "("

		for k, value := range values {
			if k > 0 {
				str += ", "
			}
			str += value.SQL()
		}
		str += ")"
	}
	return str
}

func (cd ColumnDef) SQL() string {
	str := cd.Name.SQL() + " " + cd.Type.SQL()
	if cd.NotNull {
		str += " NOT NULL"
	}
	if cd.Default != nil {
		str += " DEFAULT (" + cd.Default.SQL() + ")"
	}
	if cd.Generated != nil {
		str += " AS (" + cd.Generated.SQL() + ") STORED"
	}
	if cd.Options != (ColumnOptions{}) {
		str += " " + cd.Options.SQL()
	}
	return str
}

func (tc TableConstraint) SQL() string {
	var str string
	if tc.Name != "" {
		str += "CONSTRAINT " + tc.Name.SQL() + " "
	}
	str += tc.Constraint.SQL()
	return str
}

func (rdp RowDeletionPolicy) SQL() string {
	return "ROW DELETION POLICY ( OLDER_THAN ( " + rdp.Column.SQL() + ", INTERVAL " + strconv.FormatInt(rdp.NumDays, 10) + " DAY ))"
}

func (fk ForeignKey) SQL() string {
	str := "FOREIGN KEY (" + idList(fk.Columns, ", ")
	str += ") REFERENCES " + fk.RefTable.SQL() + " ("
	str += idList(fk.RefColumns, ", ") + ")"
	str += " ON DELETE " + fk.OnDelete.SQL()
	return str
}

func (c Check) SQL() string {
	return "CHECK (" + c.Expr.SQL() + ")"
}

func (t Type) SQL() string {
	str := t.Base.SQL()
	if t.Len > 0 && (t.Base == String || t.Base == Bytes) {
		str += "("
		if t.Len == MaxLen {
			str += "MAX"
		} else {
			str += strconv.FormatInt(t.Len, 10)
		}
		str += ")"
	}
	if t.Array {
		str = "ARRAY<" + str + ">"
	}
	return str
}

func (tb TypeBase) SQL() string {
	switch tb {
	case Bool:
		return "BOOL"
	case Int64:
		return "INT64"
	case Float64:
		return "FLOAT64"
	case Numeric:
		return "NUMERIC"
	case String:
		return "STRING"
	case Bytes:
		return "BYTES"
	case Date:
		return "DATE"
	case Timestamp:
		return "TIMESTAMP"
	case JSON:
		return "JSON"
	}
	panic("unknown TypeBase")
}

func (pt PrivilegeType) SQL() string {
	switch pt {
	case PrivilegeTypeSelect:
		return "SELECT"
	case PrivilegeTypeInsert:
		return "INSERT"
	case PrivilegeTypeUpdate:
		return "UPDATE"
	case PrivilegeTypeDelete:
		return "DELETE"
	}
	panic("unknown PrivilegeType")
}
func (kp KeyPart) SQL() string {
	str := kp.Column.SQL()
	if kp.Desc {
		str += " DESC"
	}
	return str
}

func (q Query) SQL() string { return buildSQL(q) }
func (q Query) addSQL(sb *strings.Builder) {
	q.Select.addSQL(sb)
	if len(q.Order) > 0 {
		sb.WriteString(" ORDER BY ")
		for i, o := range q.Order {
			if i > 0 {
				sb.WriteString(", ")
			}
			o.addSQL(sb)
		}
	}
	if q.Limit != nil {
		sb.WriteString(" LIMIT ")
		sb.WriteString(q.Limit.SQL())
		if q.Offset != nil {
			sb.WriteString(" OFFSET ")
			sb.WriteString(q.Offset.SQL())
		}
	}
}

func (sel Select) SQL() string { return buildSQL(sel) }
func (sel Select) addSQL(sb *strings.Builder) {
	sb.WriteString("SELECT ")
	if sel.Distinct {
		sb.WriteString("DISTINCT ")
	}
	for i, e := range sel.List {
		if i > 0 {
			sb.WriteString(", ")
		}
		e.addSQL(sb)
		if len(sel.ListAliases) > 0 {
			alias := sel.ListAliases[i]
			if alias != "" {
				sb.WriteString(" AS ")
				sb.WriteString(alias.SQL())
			}
		}
	}
	if len(sel.From) > 0 {
		sb.WriteString(" FROM ")
		for i, f := range sel.From {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(f.SQL())
		}
	}
	if sel.Where != nil {
		sb.WriteString(" WHERE ")
		sel.Where.addSQL(sb)
	}
	if len(sel.GroupBy) > 0 {
		sb.WriteString(" GROUP BY ")
		addExprList(sb, sel.GroupBy, ", ")
	}
}

func (sft SelectFromTable) SQL() string {
	str := sft.Table.SQL()
	if len(sft.Hints) > 0 {
		str += "@{"
		kvs := make([]string, len(sft.Hints))
		i := 0
		for k, v := range sft.Hints {
			kvs[i] = fmt.Sprintf("%s=%s", k, v)
			i++
		}
		sort.Strings(kvs)
		str += strings.Join(kvs, ",")
		str += "}"
	}

	if sft.Alias != "" {
		str += " AS " + sft.Alias.SQL()
	}
	return str
}

func (sfj SelectFromJoin) SQL() string {
	// TODO: The grammar permits arbitrary nesting. Does this need to add parens?
	str := sfj.LHS.SQL() + " " + joinTypes[sfj.Type] + " JOIN "
	// TODO: hints go here
	str += sfj.RHS.SQL()
	if sfj.On != nil {
		str += " ON " + sfj.On.SQL()
	} else if len(sfj.Using) > 0 {
		str += " USING (" + idList(sfj.Using, ", ") + ")"
	}
	return str
}

var joinTypes = map[JoinType]string{
	InnerJoin: "INNER",
	CrossJoin: "CROSS",
	FullJoin:  "FULL",
	LeftJoin:  "LEFT",
	RightJoin: "RIGHT",
}

func (sfu SelectFromUnnest) SQL() string {
	str := "UNNEST(" + sfu.Expr.SQL() + ")"
	if sfu.Alias != "" {
		str += " AS " + sfu.Alias.SQL()
	}
	return str
}

func (o Order) SQL() string { return buildSQL(o) }
func (o Order) addSQL(sb *strings.Builder) {
	o.Expr.addSQL(sb)
	if o.Desc {
		sb.WriteString(" DESC")
	}
}

var arithOps = map[ArithOperator]string{
	// Binary operators only; unary operators are handled first.
	Mul:    "*",
	Div:    "/",
	Concat: "||",
	Add:    "+",
	Sub:    "-",
	BitShl: "<<",
	BitShr: ">>",
	BitAnd: "&",
	BitXor: "^",
	BitOr:  "|",
}

func (ao ArithOp) SQL() string { return buildSQL(ao) }
func (ao ArithOp) addSQL(sb *strings.Builder) {
	// Extra parens inserted to ensure the correct precedence.

	switch ao.Op {
	case Neg:
		sb.WriteString("-(")
		ao.RHS.addSQL(sb)
		sb.WriteString(")")
		return
	case Plus:
		sb.WriteString("+(")
		ao.RHS.addSQL(sb)
		sb.WriteString(")")
		return
	case BitNot:
		sb.WriteString("~(")
		ao.RHS.addSQL(sb)
		sb.WriteString(")")
		return
	}
	op, ok := arithOps[ao.Op]
	if !ok {
		panic("unknown ArithOp")
	}
	sb.WriteString("(")
	ao.LHS.addSQL(sb)
	sb.WriteString(")")
	sb.WriteString(op)
	sb.WriteString("(")
	ao.RHS.addSQL(sb)
	sb.WriteString(")")
}

func (lo LogicalOp) SQL() string { return buildSQL(lo) }
func (lo LogicalOp) addSQL(sb *strings.Builder) {
	switch lo.Op {
	default:
		panic("unknown LogicalOp")
	case And:
		lo.LHS.addSQL(sb)
		sb.WriteString(" AND ")
	case Or:
		lo.LHS.addSQL(sb)
		sb.WriteString(" OR ")
	case Not:
		sb.WriteString("NOT ")
	}
	lo.RHS.addSQL(sb)
}

var compOps = map[ComparisonOperator]string{
	Lt:         "<",
	Le:         "<=",
	Gt:         ">",
	Ge:         ">=",
	Eq:         "=",
	Ne:         "!=",
	Like:       "LIKE",
	NotLike:    "NOT LIKE",
	Between:    "BETWEEN",
	NotBetween: "NOT BETWEEN",
}

func (co ComparisonOp) SQL() string { return buildSQL(co) }
func (co ComparisonOp) addSQL(sb *strings.Builder) {
	op, ok := compOps[co.Op]
	if !ok {
		panic("unknown ComparisonOp")
	}
	co.LHS.addSQL(sb)
	sb.WriteString(" ")
	sb.WriteString(op)
	sb.WriteString(" ")
	co.RHS.addSQL(sb)
	if co.Op == Between || co.Op == NotBetween {
		sb.WriteString(" AND ")
		co.RHS2.addSQL(sb)
	}
}

func (io InOp) SQL() string { return buildSQL(io) }
func (io InOp) addSQL(sb *strings.Builder) {
	io.LHS.addSQL(sb)
	if io.Neg {
		sb.WriteString(" NOT")
	}
	sb.WriteString(" IN ")
	if io.Unnest {
		sb.WriteString("UNNEST")
	}
	sb.WriteString("(")
	addExprList(sb, io.RHS, ", ")
	sb.WriteString(")")
}

func (io IsOp) SQL() string { return buildSQL(io) }
func (io IsOp) addSQL(sb *strings.Builder) {
	io.LHS.addSQL(sb)
	sb.WriteString(" IS ")
	if io.Neg {
		sb.WriteString("NOT ")
	}
	io.RHS.addSQL(sb)
}

func (f Func) SQL() string { return buildSQL(f) }
func (f Func) addSQL(sb *strings.Builder) {
	sb.WriteString(f.Name)
	sb.WriteString("(")
	if f.Distinct {
		sb.WriteString("DISTINCT ")
	}
	addExprList(sb, f.Args, ", ")
	switch f.NullsHandling {
	case RespectNulls:
		sb.WriteString(" RESPECT NULLS")
	case IgnoreNulls:
		sb.WriteString(" IGNORE NULLS")
	}
	if ah := f.Having; ah != nil {
		sb.WriteString(" HAVING")
		switch ah.Condition {
		case HavingMax:
			sb.WriteString(" MAX")
		case HavingMin:
			sb.WriteString(" MIN")
		}
		sb.WriteString(" ")
		sb.WriteString(ah.Expr.SQL())
	}
	sb.WriteString(")")
}

func (te TypedExpr) SQL() string { return buildSQL(te) }
func (te TypedExpr) addSQL(sb *strings.Builder) {
	te.Expr.addSQL(sb)
	sb.WriteString(" AS ")
	sb.WriteString(te.Type.SQL())
}

func (ee ExtractExpr) SQL() string { return buildSQL(ee) }
func (ee ExtractExpr) addSQL(sb *strings.Builder) {
	sb.WriteString(ee.Part)
	sb.WriteString(" FROM ")
	ee.Expr.addSQL(sb)
}

func (aze AtTimeZoneExpr) SQL() string { return buildSQL(aze) }
func (aze AtTimeZoneExpr) addSQL(sb *strings.Builder) {
	aze.Expr.addSQL(sb)
	sb.WriteString(" AT TIME ZONE ")
	sb.WriteString(aze.Zone)
}

func (ie IntervalExpr) SQL() string { return buildSQL(ie) }
func (ie IntervalExpr) addSQL(sb *strings.Builder) {
	sb.WriteString("INTERVAL")
	sb.WriteString(" ")
	ie.Expr.addSQL(sb)
	sb.WriteString(" ")
	sb.WriteString(ie.DatePart)
}

func (se SequenceExpr) SQL() string { return buildSQL(se) }
func (se SequenceExpr) addSQL(sb *strings.Builder) {
	sb.WriteString("SEQUENCE ")
	sb.WriteString(se.Name.SQL())
}

func idList(l []ID, join string) string {
	var ss []string
	for _, s := range l {
		ss = append(ss, s.SQL())
	}
	return strings.Join(ss, join)
}

func addExprList(sb *strings.Builder, l []Expr, join string) {
	for i, s := range l {
		if i > 0 {
			sb.WriteString(join)
		}
		s.addSQL(sb)
	}
}

func addIDList(sb *strings.Builder, l []ID, join string) {
	for i, s := range l {
		if i > 0 {
			sb.WriteString(join)
		}
		s.addSQL(sb)
	}
}

func (pe PathExp) SQL() string { return buildSQL(pe) }
func (pe PathExp) addSQL(sb *strings.Builder) {
	addIDList(sb, []ID(pe), ".")
}

func (p Paren) SQL() string { return buildSQL(p) }
func (p Paren) addSQL(sb *strings.Builder) {
	sb.WriteString("(")
	p.Expr.addSQL(sb)
	sb.WriteString(")")
}

func (a Array) SQL() string { return buildSQL(a) }
func (a Array) addSQL(sb *strings.Builder) {
	sb.WriteString("[")
	addExprList(sb, []Expr(a), ", ")
	sb.WriteString("]")
}

func (id ID) SQL() string { return buildSQL(id) }
func (id ID) addSQL(sb *strings.Builder) {
	// https://cloud.google.com/spanner/docs/lexical#identifiers

	// TODO: If there are non-letters/numbers/underscores then this also needs quoting.

	// Naming Convention: Must be enclosed in backticks (`) if it's a reserved keyword or contains a hyphen.
	if IsKeyword(string(id)) || strings.Contains(string(id), "-") {
		// TODO: Escaping may be needed here.
		sb.WriteString("`")
		sb.WriteString(string(id))
		sb.WriteString("`")
		return
	}

	sb.WriteString(string(id))
}

func (p Param) SQL() string { return buildSQL(p) }
func (p Param) addSQL(sb *strings.Builder) {
	sb.WriteString("@")
	sb.WriteString(string(p))
}

func (c Case) SQL() string { return buildSQL(c) }
func (c Case) addSQL(sb *strings.Builder) {
	sb.WriteString("CASE ")
	if c.Expr != nil {
		fmt.Fprintf(sb, "%s ", c.Expr.SQL())
	}
	for _, w := range c.WhenClauses {
		fmt.Fprintf(sb, "WHEN %s THEN %s ", w.Cond.SQL(), w.Result.SQL())
	}
	if c.ElseResult != nil {
		fmt.Fprintf(sb, "ELSE %s ", c.ElseResult.SQL())
	}
	sb.WriteString("END")
}

func (c Coalesce) SQL() string { return buildSQL(c) }
func (c Coalesce) addSQL(sb *strings.Builder) {
	sb.WriteString("COALESCE(")
	for i, expr := range c.ExprList {
		if i > 0 {
			sb.WriteString(", ")
		}
		expr.addSQL(sb)
	}
	sb.WriteString(")")
}

func (i If) SQL() string { return buildSQL(i) }
func (i If) addSQL(sb *strings.Builder) {
	sb.WriteString("IF(")
	i.Expr.addSQL(sb)
	sb.WriteString(", ")
	i.TrueResult.addSQL(sb)
	sb.WriteString(", ")
	i.ElseResult.addSQL(sb)
	sb.WriteString(")")
}

func (in IfNull) SQL() string { return buildSQL(in) }
func (in IfNull) addSQL(sb *strings.Builder) {
	sb.WriteString("IFNULL(")
	in.Expr.addSQL(sb)
	sb.WriteString(", ")
	in.NullResult.addSQL(sb)
	sb.WriteString(")")
}

func (ni NullIf) SQL() string { return buildSQL(ni) }
func (ni NullIf) addSQL(sb *strings.Builder) {
	sb.WriteString("NULLIF(")
	ni.Expr.addSQL(sb)
	sb.WriteString(", ")
	ni.ExprToMatch.addSQL(sb)
	sb.WriteString(")")
}

func (b BoolLiteral) SQL() string { return buildSQL(b) }
func (b BoolLiteral) addSQL(sb *strings.Builder) {
	if b {
		sb.WriteString("TRUE")
	} else {
		sb.WriteString("FALSE")
	}
}

func (NullLiteral) SQL() string                { return buildSQL(NullLiteral(0)) }
func (NullLiteral) addSQL(sb *strings.Builder) { sb.WriteString("NULL") }

func (StarExpr) SQL() string                { return buildSQL(StarExpr(0)) }
func (StarExpr) addSQL(sb *strings.Builder) { sb.WriteString("*") }

func (il IntegerLiteral) SQL() string                { return buildSQL(il) }
func (il IntegerLiteral) addSQL(sb *strings.Builder) { fmt.Fprintf(sb, "%d", il) }

func (fl FloatLiteral) SQL() string                { return buildSQL(fl) }
func (fl FloatLiteral) addSQL(sb *strings.Builder) { fmt.Fprintf(sb, "%g", fl) }

// TODO: provide correct string quote method and use it.

func (sl StringLiteral) SQL() string                { return buildSQL(sl) }
func (sl StringLiteral) addSQL(sb *strings.Builder) { fmt.Fprintf(sb, "%q", sl) }

func (bl BytesLiteral) SQL() string                { return buildSQL(bl) }
func (bl BytesLiteral) addSQL(sb *strings.Builder) { fmt.Fprintf(sb, "B%q", bl) }

func (dl DateLiteral) SQL() string { return buildSQL(dl) }
func (dl DateLiteral) addSQL(sb *strings.Builder) {
	fmt.Fprintf(sb, "DATE '%04d-%02d-%02d'", dl.Year, dl.Month, dl.Day)
}

func (tl TimestampLiteral) SQL() string { return buildSQL(tl) }
func (tl TimestampLiteral) addSQL(sb *strings.Builder) {
	fmt.Fprintf(sb, "TIMESTAMP '%s'", time.Time(tl).Format("2006-01-02 15:04:05.000000-07:00"))
}

func (jl JSONLiteral) SQL() string { return buildSQL(jl) }
func (jl JSONLiteral) addSQL(sb *strings.Builder) {
	fmt.Fprintf(sb, "JSON '%s'", jl)
}
