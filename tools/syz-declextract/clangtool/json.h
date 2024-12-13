// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef SYZ_DECLEXTRACT_JSON_H
#define SYZ_DECLEXTRACT_JSON_H

#include <cassert>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

class JSONPrinter {
public:
  JSONPrinter() : Top(*this) {}

  template <typename T> void Field(const char* Name, const T& V, bool Last = false) {
    printf("%s\"%s\": ", Indent(), Name);
    print(*this, V);
    printf("%s\n", Last ? "" : ",");
  }

  const char* Indent() const {
    static std::string Indents;
    while (Indents.size() < Nesting)
      Indents.push_back('\t');
    return Indents.c_str() + Indents.size() - Nesting;
  }

  class Scope {
  public:
    Scope(JSONPrinter& Printer, bool Array = false) : Printer(Printer), Array(Array) {
      printf("%c\n", "{["[Array]);
      Printer.Nesting++;
      assert(Printer.Nesting < 1000);
    }

    ~Scope() {
      assert(Printer.Nesting > 0);
      Printer.Nesting--;
      printf("%s%c", Printer.Indent(), "}]"[Array]);
    }

  private:
    JSONPrinter& Printer;
    const bool Array;
  };

private:
  friend class Scope;
  size_t Nesting = 0;
  Scope Top;
};

inline void print(JSONPrinter& Printer, int V) { printf("%d", V); }
inline void print(JSONPrinter& Printer, unsigned V) { printf("%u", V); }
inline void print(JSONPrinter& Printer, int64_t V) { printf("%ld", V); }
inline void print(JSONPrinter& Printer, bool V) { printf("%s", V ? "true" : "false"); }
inline void print(JSONPrinter& Printer, const char* V) { printf("\"%s\"", V ? V : ""); }
inline void print(JSONPrinter& Printer, const std::string& V) { print(Printer, V.c_str()); }

template <typename E> void print(JSONPrinter& Printer, const std::unique_ptr<E>& V) {
  if (!V)
    printf("null");
  else
    print(Printer, *V);
}

template <typename E> void print(JSONPrinter& Printer, const std::vector<E>& V) {
  JSONPrinter::Scope Scope(Printer, true);
  size_t i = 0;
  for (const auto& Elem : V) {
    printf("%s", Printer.Indent());
    print(Printer, Elem);
    printf("%s\n", ++i == V.size() ? "" : ",");
  }
}

#endif
