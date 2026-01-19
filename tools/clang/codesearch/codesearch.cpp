// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "json.h"
#include "output.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Comment.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclarationName.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <unordered_map>

using namespace clang;

// MacroDef/MacroMap hold information about macros defined in the file.
struct MacroDef {
  std::string Value; // value as written in the source
  SourceRange Range; // source range of the value
};
using MacroMap = std::unordered_map<std::string, MacroDef>;

class Instance : public tooling::SourceFileCallbacks {
public:
  Instance(Output& Output) : Out(Output) {}
  std::unique_ptr<ASTConsumer> newASTConsumer();

private:
  Output& Out;
  MacroMap Macros;

  bool handleBeginSource(CompilerInstance& CI) override;
};

// PPCallbacksTracker records all macro definitions (name/value/source location).
class PPCallbacksTracker : public PPCallbacks {
public:
  PPCallbacksTracker(Preprocessor& PP, MacroMap& Macros) : SM(PP.getSourceManager()), Macros(Macros) {}

private:
  SourceManager& SM;
  MacroMap& Macros;

  void MacroDefined(const Token& MacroName, const MacroDirective* MD) override { (void)Macros; }
};

class IndexerAstConsumer : public ASTConsumer {
public:
  IndexerAstConsumer(Output& Output, const MacroMap& Macros) : Out(Output), Macros(Macros) {}

private:
  Output& Out;
  const MacroMap& Macros;

  void HandleTranslationUnit(ASTContext& context) override;
};

class Indexer : public RecursiveASTVisitor<Indexer> {
public:
  Indexer(ASTContext& Context, Output& Output, const MacroMap& Macros)
      : Context(Context), SM(Context.getSourceManager()), Out(Output) {}

  bool TraverseFunctionDecl(FunctionDecl*);
  bool TraverseCallExpr(CallExpr*);
  bool VisitDeclRefExpr(const DeclRefExpr*);

private:
  ASTContext& Context;
  SourceManager& SM;
  Output& Out;
  Definition* CurrentFunction = nullptr;
  bool InCallee = false;

  using Base = RecursiveASTVisitor<Indexer>;
};

bool Instance::handleBeginSource(CompilerInstance& CI) {
  Preprocessor& PP = CI.getPreprocessor();
  PP.addPPCallbacks(std::make_unique<PPCallbacksTracker>(PP, Macros));
  return true;
}

std::unique_ptr<ASTConsumer> Instance::newASTConsumer() { return std::make_unique<IndexerAstConsumer>(Out, Macros); }

void IndexerAstConsumer::HandleTranslationUnit(ASTContext& Context) {
  Indexer Indexer(Context, Out, Macros);
  Indexer.TraverseDecl(Context.getTranslationUnitDecl());
}

bool Indexer::TraverseFunctionDecl(FunctionDecl* Func) {
  if (!Func->doesThisDeclarationHaveABody())
    return Base::TraverseFunctionDecl(Func);

  auto Range = Func->getSourceRange();
  const std::string& SourceFile = std::filesystem::relative(SM.getFilename(SM.getExpansionLoc(Range.getBegin())).str());
  int StartLine = SM.getExpansionLineNumber(Range.getBegin());
  int EndLine = SM.getExpansionLineNumber(Range.getEnd());
  std::string CommentSourceFile;
  int CommentStartLine = 0;
  int CommentEndLine = 0;
  if (auto Comment = Context.getRawCommentForDeclNoCache(Func)) {
    const auto& begin = Comment->getBeginLoc();
    const auto& end = Comment->getEndLoc();
    CommentSourceFile = std::filesystem::relative(SM.getFilename(SM.getExpansionLoc(begin)).str());
    CommentStartLine = SM.getExpansionLineNumber(begin);
    CommentEndLine = SM.getExpansionLineNumber(end);
    // Expand body range to include the comment, if they intersect.
    if (SourceFile == CommentSourceFile &&
        std::max(StartLine, CommentStartLine) <= std::min(EndLine, CommentEndLine) + 1) {
      StartLine = std::min(StartLine, CommentStartLine);
      EndLine = std::max(EndLine, CommentEndLine);
    }
  }
  Definition Def{
      .Kind = EntityKindFunction,
      .Name = Func->getNameAsString(),
      .Type = Func->getType().getAsString(),
      .IsStatic = Func->isStatic(),
      .Body =
          LineRange{
              .File = SourceFile,
              .StartLine = StartLine,
              .EndLine = EndLine,
          },
      .Comment =
          LineRange{
              .File = CommentSourceFile,
              .StartLine = CommentStartLine,
              .EndLine = CommentEndLine,
          },
  };

  Definition* SavedCurrentFunction = CurrentFunction;
  CurrentFunction = &Def;
  if (!Base::TraverseFunctionDecl(Func))
    return false;
  CurrentFunction = SavedCurrentFunction;
  Out.emit(std::move(Def));
  return true;
}

bool Indexer::TraverseCallExpr(CallExpr* CE) {
  bool SavedInCallee = InCallee;
  InCallee = true;
  TraverseStmt(CE->getCallee());
  InCallee = SavedInCallee;

  for (auto* Arg : CE->arguments())
    TraverseStmt(Arg);
  return true;
}

bool Indexer::VisitDeclRefExpr(const DeclRefExpr* DeclRef) {
  const auto* Func = dyn_cast<FunctionDecl>(DeclRef->getDecl());
  if (!Func || !CurrentFunction)
    return true;
  CurrentFunction->Refs.push_back(Reference{
      .Kind = InCallee ? RefKindCall : RefKindTakesAddr,
      .EntityKind = EntityKindFunction,
      .Name = Func->getNameAsString(),
      .Line = static_cast<int>(SM.getExpansionLineNumber(DeclRef->getBeginLoc())),
  });
  return true;
}

int main(int argc, const char** argv) {
  llvm::cl::OptionCategory Options("syz-indexer options");
  auto OptionsParser = tooling::CommonOptionsParser::create(argc, argv, Options);
  if (!OptionsParser) {
    llvm::errs() << OptionsParser.takeError();
    return 1;
  }
  Output Output;
  Instance Instance(Output);
  tooling::ClangTool Tool(OptionsParser->getCompilations(), OptionsParser->getSourcePathList());
  if (Tool.run(tooling::newFrontendActionFactory(&Instance, &Instance).get()))
    return 1;
  Output.print();
  return 0;
}
