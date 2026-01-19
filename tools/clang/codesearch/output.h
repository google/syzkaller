// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef SYZ_INDEXER_OUTPUT_H
#define SYZ_INDEXER_OUTPUT_H

#include "json.h"
#include <vector>

constexpr char EntityKindFunction[] = "function";
constexpr char EntityKindStruct[] = "struct";
constexpr char EntityKindVariable[] = "variable";
constexpr char EntityKindMacro[] = "macro";
constexpr char EntityKindEnum[] = "enum";

constexpr char RefKindCall[] = "calls";
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

inline void print(JSONPrinter& Printer, const Definition& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("kind", V.Kind);
  Printer.Field("name", V.Name);
  Printer.Field("type", V.Type);
  Printer.Field("is_static", V.IsStatic);
  Printer.Field("body", V.Body);
  Printer.Field("comment", V.Comment);
  Printer.Field("refs", V.Refs, true);
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
