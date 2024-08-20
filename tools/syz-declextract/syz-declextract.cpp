// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build ignore
#include "clang/AST/APValue.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/PrettyPrinter.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/Basic/LLVM.h"
#include "clang/Sema/Ownership.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <cstddef>
#include <filesystem>
#include <stdio.h>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

struct EnumData {
  std::string name;
  int value;
  std::string file;
};

struct Param {
  std::string type;
  std::string name;
};

class EnumMatcher : public MatchFinder::MatchCallback {
private:
  std::vector<EnumData> EnumDetails;

public:
  std::vector<EnumData> getEnumData() { return EnumDetails; }
  virtual void run(const MatchFinder::MatchResult &Result) override {
    const auto *enumValue = Result.Nodes.getNodeAs<ConstantExpr>("enum_value");
    if (!enumValue)
      return;
    const auto &name = enumValue->getEnumConstantDecl()->getNameAsString();
    const auto value = int(*enumValue->getAPValueResult().getInt().getRawData());
    const auto &path = std::filesystem::relative(
        Result.SourceManager->getFilename(enumValue->getEnumConstantDecl()->getSourceRange().getBegin()).data());
    EnumDetails.push_back({std::move(name), value, std::move(path)});
  }
};

class Matcher : public MatchFinder::MatchCallback {
private:
  const std::string nlaToSyz(const Expr *const policyType) {
    // NOTE:This check is for when the policy is missing the field `type`.
    // TODO:Gather information from other defined fields to better specify a type.
    if (!policyType->getEnumConstantDecl()) {
      return "intptr";
    }
    const auto type = policyType->getEnumConstantDecl()->getNameAsString().substr(4); // remove the NLA_ prefix
    // Loosely based on https://elixir.bootlin.com/linux/v6.10/source/lib/nlattr.c
    if (type == "U8" || type == "S8") {
      return "int8";
    }
    if (type == "U16" || type == "S16" || type == "BINARY") {
      return "int16";
    }
    if (type == "BE16") {
      return "int16be";
    }
    if (type == "U32" || type == "S32") {
      return "int32";
    }
    if (type == "BE32") {
      return "int32be";
    }
    if (type == "U64" || type == "S64" || type == "SINT" || type == "UINT" || type == "MSECS") {
      return "int64";
    }
    if (type == "FLAG") {
      return "void";
    }
    if (type == "STRING") {
      return "stringnoz";
    }
    if (type == "NUL_STRING") {
      return "string";
    }
    if (type == "BITFIELD32") { // TODO:Extract valued values from NLA_POLICY_BITFIELD32 macro.
      return "int32";
    }
    if (type == "UNSPEC" || type == "NESTED" || type == "NESTED_ARRAY" || type == "REJECT" || type == "TYPE_MAX") {
      return "intptr";
    }
    fprintf(stderr, "Unsupported netlink type %s\n", type.c_str());
    exit(1);
  }
  const std::string getSyzType(const std::string &type) { return "intptr"; }
  const std::string swapIfReservedKeyword(const std::string &word) {
    if (word == "resource")
      return "rsrc";
    return word;
  }

  void syscall(const MatchFinder::MatchResult &Result) {
    ASTContext *context = Result.Context;
    const auto *varDecl = Result.Nodes.getNodeAs<VarDecl>("syscall");
    if (!varDecl || !varDecl->getInit())
      return;

    // values contains the initializer list for the struct `syscall_metadata`
    auto values = llvm::dyn_cast<InitListExpr>(varDecl->getInit())->inits();
    if (values.empty())
      return;

    int argc = *values[2]->getIntegerConstantExpr(*context).value().getRawData();

    std::vector<Param> args(argc);
    if (argc) {
      int i = 0;
      for (const auto *type : // get parameter types
           llvm::dyn_cast<InitListExpr>(
               llvm::dyn_cast<VarDecl>(values[3]->getAsBuiltinConstantDeclRef(*context)->getUnderlyingDecl())
                   ->getInit())
               ->inits()) {
        args[i++].type = std::move(*type->tryEvaluateString(*context));
      }

      i = 0;
      for (const auto *name : // get parameter names
           llvm::dyn_cast<InitListExpr>(
               llvm::dyn_cast<VarDecl>(values[4]->getAsBuiltinConstantDeclRef(*context)->getUnderlyingDecl())
                   ->getInit())
               ->inits()) {
        args[i++].name = std::move(*name->tryEvaluateString(*context));
      }
    }

    printf("%s$auto(", values[0]->tryEvaluateString(*context).value().c_str() + 4); // name
    const char *sep = "";
    for (const auto &arg : args) {
      printf("%s%s %s", sep, swapIfReservedKeyword(arg.name).c_str(), getSyzType(arg.type).c_str());
      sep = ", ";
    }
    puts(") (automatic)");
  }

  void netlink(const MatchFinder::MatchResult &Result) {
    ASTContext *context = Result.Context;
    std::string output;
    const auto *netlinkDecl = Result.Nodes.getNodeAs<VarDecl>("netlink");
    if (!netlinkDecl) {
      return;
    }

    EnumMatcher enumMatcher;
    MatchFinder enumFinder;
    enumFinder.addMatcher(
        decl(forEachDescendant(designatedInitExpr(has(constantExpr(has(declRefExpr())).bind("enum_value"))))),
        &enumMatcher);
    enumFinder.match(*netlinkDecl, *context); // get enum details from the current subtree (nla_policy[])

    std::vector<std::vector<Expr *>> fields;
    for (const auto &policy : *llvm::dyn_cast<InitListExpr>(netlinkDecl->getInit())) {
      // The array could have an implicitly initialized policy (i.e. empty)
      if (policy->children().empty()) {
        continue;
      }
      fields.push_back(std::vector<Expr *>());
      for (const auto &member : policy->children()) {
        fields.back().push_back(llvm::dyn_cast<Expr>(member));
      }
    }

    const auto enumData = enumMatcher.getEnumData();
    for (const auto &item : enumData) {
      printf("include<%s>\n", item.file.c_str());
    }
    printf("%s$auto[\n", netlinkDecl->getDefinition()->getNameAsString().c_str());
    for (size_t i = 0; i < fields.size(); ++i) {
      printf("\t%s nlattr[%s, %s]\n", enumData[i].name.c_str(), enumData[i].name.c_str(),
             nlaToSyz(fields[i][0]).c_str());
    }
    puts("] [varlen]");
  }

public:
  virtual void run(const MatchFinder::MatchResult &Result) override {
    syscall(Result);
    netlink(Result);
  };
};

int main(int argc, const char **argv) {
  llvm::cl::OptionCategory SyzDeclExtractOptionCategory("SyzDeclExtract options");
  auto ExpectedParser = clang::tooling::CommonOptionsParser::create(argc, argv, SyzDeclExtractOptionCategory);

  if (!ExpectedParser) {
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }

  clang::tooling::CommonOptionsParser &OptionsParser = ExpectedParser.get();
  clang::tooling::ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

  Matcher Printer;
  MatchFinder Finder;
  Finder.addMatcher(
      varDecl(isExpandedFromMacro("SYSCALL_METADATA"), hasType(recordDecl(hasName("syscall_metadata"))), isDefinition())
          .bind("syscall"),
      &Printer);
  Finder.addMatcher(varDecl(hasType(constantArrayType(hasElementType(hasDeclaration(
                                                          recordDecl(hasName("nla_policy")).bind("nla_policy"))))
                                        .bind("nla_policy_array")),
                            isDefinition())
                        .bind("netlink"),
                    &Printer);

  return Tool.run(clang::tooling::newFrontendActionFactory(&Finder).get());
}
