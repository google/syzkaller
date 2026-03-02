// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "output.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/PrettyPrinter.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/Lexer.h"
#include "clang/Lex/MacroArgs.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"

#include <string>
#include <vector>
#include <set>
#include <unordered_map>

using namespace clang;
using namespace clang::ast_matchers;

struct ComplexityVisitor : public RecursiveASTVisitor<ComplexityVisitor> {
  int Score = 1;
  bool VisitIfStmt(IfStmt* S) { Score++; return true; }
  bool VisitForStmt(ForStmt* S) { Score++; return true; }
  bool VisitWhileStmt(WhileStmt* S) { Score++; return true; }
  bool VisitDoStmt(DoStmt* S) { Score++; return true; }
  bool VisitCaseStmt(CaseStmt* S) { Score++; return true; }
  bool VisitDefaultStmt(DefaultStmt* S) { Score++; return true; }
  bool VisitBinaryOperator(BinaryOperator* S) {
    if (S->isLogicalOp()) Score++;
    return true;
  }
  bool VisitConditionalOperator(ConditionalOperator* S) { Score++; return true; }
};

struct LockVisitor : public RecursiveASTVisitor<LockVisitor> {
  std::set<std::string> Locks;
  bool VisitCallExpr(CallExpr* S) {
    if (FunctionDecl* FD = S->getDirectCallee()) {
      std::string Name = FD->getNameAsString();
      if (Name.find("lock") != std::string::npos || 
          Name.find("unlock") != std::string::npos ||
          Name.find("rcu_read") != std::string::npos) {
        Locks.insert(Name);
      }
    }
    return true;
  }
};

struct JITIVisitor : public RecursiveASTVisitor<JITIVisitor> {
  ASTContext& Context;
  Output& Output;
  std::set<std::string> SeenSymbols;

  JITIVisitor(ASTContext& Context, struct Output& Output) : Context(Context), Output(Output) {}

  bool VisitTypeLoc(TypeLoc TL) {
    QualType QT = TL.getType();
    if (const RecordType* RT = QT->getAs<RecordType>()) {
      RecordDecl* RD = RT->getDecl();
      emitSymbol(RD, "struct");
    } else if (const EnumType* ET = QT->getAs<EnumType>()) {
      EnumDecl* ED = ET->getDecl();
      emitSymbol(ED, "enum");
    }
    return true;
  }

  void emitSymbol(NamedDecl* D, const std::string& Kind) {
    if (!D || D->getNameAsString().empty()) return;
    if (SeenSymbols.count(D->getNameAsString())) return;
    
    SourceManager& SM = Context.getSourceManager();
    if (SM.isInMainFile(D->getLocation())) return;

    SeenSymbols.insert(D->getNameAsString());

    GlanceSymbol GS;
    GS.Name = D->getNameAsString();
    GS.Kind = Kind;
    GS.File = SM.getFilename(D->getLocation()).str();

    // Get the definition text
    SourceRange Range = D->getSourceRange();
    GS.Definition = getSourceText(Range);

    Output.emit(std::move(GS));
  }

  std::string getSourceText(SourceRange Range) {
    SourceManager& SM = Context.getSourceManager();
    CharSourceRange CSR = CharSourceRange::getTokenRange(Range);
    return Lexer::getSourceText(CSR, SM, Context.getLangOpts()).str();
  }
};

class GlanceExtractor : public MatchFinder::MatchCallback, public tooling::SourceFileCallbacks {
public:
  void run(const MatchFinder::MatchResult& Result) override {
    if (const FunctionDecl* FD = Result.Nodes.getNodeAs<FunctionDecl>("func")) {
      SourceManager& SM = *Result.SourceManager;
      if (!SM.isInMainFile(FD->getLocation())) return;

      GlanceFunction GF;
      GF.Name = FD->getNameAsString();
      GF.File = SM.getFilename(FD->getLocation()).str();
      GF.StartLine = SM.getExpansionLineNumber(FD->getBeginLoc());
      GF.EndLine = SM.getExpansionLineNumber(FD->getEndLoc());
      
      ComplexityVisitor CV;
      CV.TraverseStmt(FD->getBody());
      GF.Complexity = CV.Score;

      LockVisitor LV;
      LV.TraverseStmt(FD->getBody());
      for (const auto& Lock : LV.Locks) {
        GF.LocksUsed.push_back(Lock);
      }

      GF.IsExported = ExportedSymbols.count(GF.Name) > 0;

      Output.emit(std::move(GF));

      // Extract symbols used in this function body
      JITIVisitor JV(*Result.Context, Output);
      JV.TraverseStmt(FD->getBody());
    }
  }

  void print() { Output.print(); }

  MatchFinder Finder;
  Output Output;
  std::set<std::string> ExportedSymbols;
};

class GlancePPCallbacks : public PPCallbacks {
public:
  GlanceExtractor& Extractor;
  const SourceManager& SM;
  
  GlancePPCallbacks(GlanceExtractor& Extractor, const SourceManager& SM) : Extractor(Extractor), SM(SM) {}

  void MacroExpands(const Token& MacroNameTok, const MacroDefinition& MD, SourceRange Range, const MacroArgs* Args) override {
    if (!SM.isInMainFile(Range.getBegin())) return;

    std::string Name = MacroNameTok.getIdentifierInfo()->getName().str();
    if (Name == "EXPORT_SYMBOL" || Name == "EXPORT_SYMBOL_GPL") {
      if (Args && Args->getNumMacroArguments() > 0) {
        const Token* T = Args->getUnexpArgument(0);
        if (T && T->isAnyIdentifier()) {
             std::string Sym = T->getIdentifierInfo()->getName().str();
             Extractor.ExportedSymbols.insert(Sym);
        }
      }
    }
  }

  void InclusionDirective(SourceLocation HashLoc,
                          const Token &IncludeTok, StringRef FileName,
                          bool IsAngled, CharSourceRange FilenameRange,
                          OptionalFileEntryRef File,
                          StringRef SearchPath, StringRef RelativePath,
                          const Module *SuggestedModule,
                          bool ModuleImported,
                          SrcMgr::CharacteristicKind FileType) override {
    llvm::errs() << "DEBUG: InclusionDirective: " << FileName << " InMain: " << SM.isInMainFile(HashLoc) << "\n";
    if (!SM.isInMainFile(HashLoc)) return;
    Extractor.Output.emitInclude(FileName.str());
  }
};

class GlanceFrontendAction : public ASTFrontendAction {
public:
  GlanceExtractor& Extractor;
  GlanceFrontendAction(GlanceExtractor& Extractor) : Extractor(Extractor) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance& CI, StringRef File) override {
    CI.getPreprocessor().addPPCallbacks(std::make_unique<GlancePPCallbacks>(Extractor, CI.getSourceManager()));
    return Extractor.Finder.newASTConsumer();
  }
};

class GlanceActionFactory : public tooling::FrontendActionFactory {
public:
  GlanceExtractor& Extractor;
  GlanceActionFactory(GlanceExtractor& Extractor) : Extractor(Extractor) {}
  
  std::unique_ptr<FrontendAction> create() override {
    return std::make_unique<GlanceFrontendAction>(Extractor);
  }
};

static int Main(int argc, const char** argv) {
  llvm::cl::OptionCategory Options("glance options");
  auto OptionsParser = tooling::CommonOptionsParser::create(argc, argv, Options);
  if (!OptionsParser) return 1;
  tooling::ClangTool Tool(OptionsParser->getCompilations(), OptionsParser->getSourcePathList());
  
  GlanceExtractor Extractor;
  
  if (!OptionsParser->getSourcePathList().empty()) {
    std::string FirstFile = OptionsParser->getSourcePathList()[0];
    // Check if we have compile commands for this file
    // We need absolute path for getCompileCommands?
    // Actually getSourcePathList usually returns paths as passed.
    // Let's rely on how ClangTool does it.
    // ClangTool::run does this check internally and emits error.
    // But we want to intercept it or check beforehand.
    auto Cmds = OptionsParser->getCompilations().getCompileCommands(FirstFile);
    if (Cmds.empty()) {
       // Only if it's not a header file? Headers usually don't have compile commands.
       // But glance runs on .c files.
       Extractor.Output.MissingCompileCommand = FirstFile;
       // Inject a fallback command to ensure the tool runs.
       // We need to const_cast because getCompilations() returns const ref?
       // Actually, we can't easily modify the CompilationDatabase.
       // But we can create a FixedCompilationDatabase or just rely on ClangTool's behavior?
       // ClangTool::run() will error out if no command found.
       // We can append a "fake" command to the arguments?
       // No, ClangTool uses the database.
       // We can use `FixedCompilationDatabase::loadFromCommandLine` approach but we are already past that.
       // Wait, `tooling::ClangTool` has `appendArgumentsAdjuster`.
       // But that adjusts *existing* commands.
       // If there are NO commands, ClangTool fails.
       
       // We can try to construct a new ClangTool with a FixedCompilationDatabase if the original is empty for this file.
    }
  }

  // Check if we need to fallback
  if (!Extractor.Output.MissingCompileCommand.empty()) {
     std::string ErrorMsg;
     // Create a minimal compile command: clang -c <file> -I./include -I./arch/x86/include ...
     // It's hard to guess all flags. But for includes, we just need basic parsing.
     // Let's try to create a FixedCompilationDatabase.
     int Argc = 3;
     const char* Argv[] = {"glance", Extractor.Output.MissingCompileCommand.c_str(), "--"};
     // This doesn't help create the DB.
     
     // Actually, we can just *not* run the tool if we can't parse it?
     // OR, we can use `tooling::FixedCompilationDatabase`.
     std::vector<std::string> Args = {"clang", "-c", Extractor.Output.MissingCompileCommand};
     // Add some reasonable defaults for kernel?
     Args.push_back("-I.");
     Args.push_back("-Iinclude");
     Args.push_back("-Iarch/x86/include"); // Assumption!
     
     llvm::SmallString<128> Cwd;
     llvm::sys::fs::current_path(Cwd);
     
     auto FixedDB = std::make_unique<tooling::FixedCompilationDatabase>(Cwd, Args);
     tooling::ClangTool FallbackTool(*FixedDB, OptionsParser->getSourcePathList());
     
     llvm::errs() << "DEBUG: Running fallback tool for " << Extractor.Output.MissingCompileCommand << "\n";
     Extractor.Finder.addMatcher(functionDecl(isDefinition()).bind("func"), &Extractor);
     int Res = FallbackTool.run(std::make_unique<GlanceActionFactory>(Extractor).get());
     Extractor.print();
     return Res;
  }

  Extractor.Finder.addMatcher(functionDecl(isDefinition()).bind("func"), &Extractor);
  int Res = Tool.run(std::make_unique<GlanceActionFactory>(Extractor).get());
  Extractor.print();
  return Res;
}

__attribute__((constructor(1000))) static void ctor(int argc, const char** argv) {
  const char* run = getenv("SYZ_RUN_CLANGTOOL");
  if (run && !strcmp(run, "glance"))
    exit(Main(argc, argv));
}
