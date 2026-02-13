// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef SYZ_INDEXER_OUTPUT_H
#define SYZ_INDEXER_OUTPUT_H

#include "json.h"
#include <vector>

// Note: these string names are exposed all way to LLMs,
// so keep them readable and meaningful.

constexpr char EntityKindFunction[] = "function";
constexpr char EntityKindStruct[] = "struct";
constexpr char EntityKindUnion[] = "union";
constexpr char EntityKindVariable[] = "variable";
constexpr char EntityKindGlobalVariable[] = "global_variable";
constexpr char EntityKindMacro[] = "macro";
constexpr char EntityKindEnum[] = "enum";
constexpr char EntityKindTypedef[] = "typedef";
constexpr char EntityKindField[] = "field";

// The uses reference is very generic, ideally we refine it in the future
// (e.g. "used as an argument type", "cast to this type", "includes field of this type", etc).
constexpr char RefKindUses[] = "uses";
constexpr char RefKindCall[] = "calls";
constexpr char RefKindRead[] = "reads";
constexpr char RefKindWrite[] = "writes";
constexpr char RefKindTakesAddr[] = "takes-address-of";

struct LineRange {
  std::string File;
  int StartLine = 0;
  int EndLine = 0;
};

struct Reference {
  const char* Kind;
  const char* EntityKind;
  std::string Name;
  int Line;
};

struct FieldInfo {
  std::string Name;
  uint64_t OffsetBits;
  uint64_t SizeBits;
};

struct Definition {
  const char* Kind; // one of Kind* consts
  std::string Name;
  std::string Type; // raw C type
  bool IsStatic = false;
  // If the kernel-doc comment is placed around the body,
  // then it's included in the body range.
  LineRange Body;
  // Location of the kernel-doc comment.
  LineRange Comment;
  std::vector<Reference> Refs;
  std::vector<FieldInfo> Fields;
};

inline void print(JSONPrinter& Printer, const LineRange& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("file", V.File);
  Printer.Field("start_line", V.StartLine);
  Printer.Field("end_line", V.EndLine, true);
}

inline void print(JSONPrinter& Printer, const Reference& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("kind", V.Kind);
  Printer.Field("entity_kind", V.EntityKind);
  Printer.Field("name", V.Name);
  Printer.Field("line", V.Line, true);
}

inline void print(JSONPrinter& Printer, const FieldInfo& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("offset", V.OffsetBits);
  Printer.Field("size", V.SizeBits, true);
}

inline void print(JSONPrinter& Printer, const Definition& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("kind", V.Kind);
  Printer.Field("name", V.Name);
  Printer.Field("type", V.Type);
  Printer.Field("is_static", V.IsStatic);
  Printer.Field("body", V.Body);
  Printer.Field("comment", V.Comment);
  Printer.Field("refs", V.Refs);
  Printer.Field("fields", V.Fields, true);
}

class Output {
public:
  void emit(Definition&& V) { Definitions.push_back(std::move(V)); }

  void print() const {
    JSONPrinter Printer;
    Printer.Field("definitions", Definitions, true);
  }

private:
  std::vector<Definition> Definitions;
};

#endif
