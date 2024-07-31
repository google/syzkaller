// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build ignore
#include "clang/AST/APValue.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
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
#include <stdio.h>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

struct Param {
  std::string type;
  std::string name;
};

class Printer : public MatchFinder::MatchCallback {
public:
  virtual void run(const MatchFinder::MatchResult &Result) override {
    const auto *varDecl = Result.Nodes.getNodeAs<VarDecl>("Struct");
    auto *context = Result.Context;
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

    printf("==========SYSCALL Found==========\n");
    printf("%s\n", values[0]->tryEvaluateString(*context).value().c_str());
    for (const auto &arg : args) {
      printf("%s %s\n", arg.type.c_str(), arg.name.c_str());
    }
  }
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

  DeclarationMatcher MetaDataMatcher =
      varDecl(isExpandedFromMacro("SYSCALL_METADATA"), hasType(recordDecl(hasName("syscall_metadata")))).bind("Struct");

  Printer Printer;
  MatchFinder Finder;
  Finder.addMatcher(MetaDataMatcher, &Printer);
  return Tool.run(clang::tooling::newFrontendActionFactory(&Finder).get());
}
