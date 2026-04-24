// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef SYZ_GLANCE_OUTPUT_H
#define SYZ_GLANCE_OUTPUT_H

#include "../json.h"
#include <string>
#include <vector>

struct GlanceFunction {
  std::string Name;
  std::string File;
  int StartLine = 0;
  int EndLine = 0;
  int Complexity = 0;
  std::vector<std::string> LocksUsed;
  bool IsExported = false;
};

struct GlanceSymbol {
  std::string Name;
  std::string Kind; // struct, macro, enum
  std::string Definition;
  std::string File;
};

inline void print(JSONPrinter& Printer, const GlanceFunction& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("file", V.File);
  Printer.Field("start_line", V.StartLine);
  Printer.Field("end_line", V.EndLine);
  Printer.Field("complexity", V.Complexity);
  Printer.Field("locks_used", V.LocksUsed);
  Printer.Field("is_exported", V.IsExported, true);
}

inline void print(JSONPrinter& Printer, const GlanceSymbol& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("kind", V.Kind);
  Printer.Field("definition", V.Definition);
  Printer.Field("file", V.File, true);
}

class Output {
public:
  void emit(GlanceFunction&& V) { Functions.push_back(std::move(V)); }
  void emit(GlanceSymbol&& V) { Symbols.push_back(std::move(V)); }
  void emitInclude(std::string I) { Includes.push_back(std::move(I)); }

  void print() const {
    JSONPrinter Printer;
    Printer.Field("functions", Functions);
    Printer.Field("missing_compile_command", MissingCompileCommand);
    Printer.Field("includes", Includes);
    Printer.Field("symbols", Symbols, true);
  }

  std::string MissingCompileCommand;

private:
  std::vector<GlanceFunction> Functions;
  std::vector<GlanceSymbol> Symbols;
  std::vector<std::string> Includes;
};

#endif
