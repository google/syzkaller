// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Clang-based tool that indexes kernel source code to power
// pkg/aflow/tool/codesearcher/codesearcher.go agentic tool.

#include "json.h"
#include "output.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Comment.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclarationName.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/Version.h"
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
  bool TraverseRecordDecl(RecordDecl*);
  bool TraverseEnumDecl(EnumDecl*);
  bool TraverseTypedefDecl(TypedefDecl*);
  bool TraverseCallExpr(CallExpr*);
  bool TraverseCStyleCastExpr(CStyleCastExpr*);
  bool TraverseVarDecl(VarDecl*);
  bool TraverseParmVarDecl(ParmVarDecl*);
  bool VisitDeclRefExpr(const DeclRefExpr*);
  bool VisitTagType(const TagType*);
  bool VisitTypedefType(const TypedefType*);
  bool VisitMemberExpr(const MemberExpr*);

private:
  ASTContext& Context;
  SourceManager& SM;
  Output& Out;
  Definition* Current = nullptr;
  bool InCallee = false;
  // If set, record references to struct types as uses.
  SourceLocation TypeRefingLocation;

  const Stmt* GetParent(const Stmt* S) const;
  void EmitReference(SourceLocation Loc, const NamedDecl* Named, const char* EntityKind, const char* RefKind);
  void EmitReference(SourceLocation Loc, const std::string& Name, const char* EntityKind, const char* RefKind);

  struct NamedDeclEmitter {
    NamedDeclEmitter(Indexer* Parent, const NamedDecl* Decl, const char* Kind, const std::string& Type, bool IsStatic);
    ~NamedDeclEmitter();

    Indexer* const Parent;
    ASTContext& Context;
    SourceManager& SM;
    const NamedDecl* const Decl;
    Definition Def;
    Definition* SavedCurrent = nullptr;
  };

  using Base = RecursiveASTVisitor<Indexer>;
};

template <typename T> struct ScopedState {
  T* const Var;
  T Saved;
  ScopedState(T* Var, T ScopeValue) : Var(Var), Saved(*Var) { *Var = ScopeValue; }
  ~ScopedState() { *Var = Saved; }
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

Indexer::NamedDeclEmitter::NamedDeclEmitter(Indexer* Parent, const NamedDecl* Decl, const char* Kind,
                                            const std::string& Type, bool IsStatic)
    : Parent(Parent), Context(Parent->Context), SM(Parent->SM), Decl(Decl) {
  auto Range = Decl->getSourceRange();
  const std::string& SourceFile = std::filesystem::relative(SM.getFilename(SM.getExpansionLoc(Range.getBegin())).str());
  int StartLine = SM.getExpansionLineNumber(Range.getBegin());
  int EndLine = SM.getExpansionLineNumber(Range.getEnd());
  std::string CommentSourceFile;
  int CommentStartLine = 0;
  int CommentEndLine = 0;
  if (auto Comment = Context.getRawCommentForDeclNoCache(Decl)) {
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

  // Ensure StartLine and EndLine are in the same file.
  if (EndLine < StartLine ||
      SM.getFileID(SM.getExpansionLoc(Range.getBegin())) != SM.getFileID(SM.getExpansionLoc(Range.getEnd()))) {
    EndLine = StartLine;
  }

  Def = Definition{
      .Kind = Kind,
      .Name = Decl->getNameAsString(),
      .Type = Type,
      .IsStatic = IsStatic,
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

  SavedCurrent = Parent->Current;
  Parent->Current = &Def;
}

Indexer::NamedDeclEmitter::~NamedDeclEmitter() {
  Parent->Current = SavedCurrent;
  if (!Def.Name.empty())
    Parent->Out.emit(std::move(Def));
}

bool Indexer::TraverseFunctionDecl(FunctionDecl* Func) {
  if (!Func->doesThisDeclarationHaveABody())
    return Base::TraverseFunctionDecl(Func);
  NamedDeclEmitter Emitter(this, Func, EntityKindFunction, Func->getType().getAsString(), Func->isStatic());
  return Base::TraverseFunctionDecl(Func);
}

bool Indexer::TraverseCallExpr(CallExpr* CE) {
  {
    ScopedState<bool> Scoped(&InCallee, true);
    TraverseStmt(CE->getCallee());
  }
  for (auto* Arg : CE->arguments())
    TraverseStmt(Arg);
  return true;
}

bool Indexer::VisitDeclRefExpr(const DeclRefExpr* DeclRef) {
  if (const auto* Func = dyn_cast_if_present<FunctionDecl>(DeclRef->getDecl()))
    EmitReference(DeclRef->getBeginLoc(), DeclRef->getDecl(), EntityKindFunction,
                  InCallee ? RefKindCall : RefKindTakesAddr);
  return true;
}

bool Indexer::TraverseVarDecl(VarDecl* Decl) {
  if (Decl->isFileVarDecl() && Decl->isThisDeclarationADefinition() == VarDecl::Definition) {
    NamedDeclEmitter Emitter(this, Decl, EntityKindGlobalVariable, Decl->getType().getAsString(),
                             Decl->getStorageClass() == SC_Static);
    ScopedState<SourceLocation> Scoped(&TypeRefingLocation, Decl->getBeginLoc());
    return Base::TraverseVarDecl(Decl);
  }

  ScopedState<SourceLocation> Scoped(&TypeRefingLocation, Decl->getBeginLoc());
  return Base::TraverseVarDecl(Decl);
}

bool Indexer::TraverseParmVarDecl(ParmVarDecl* Decl) {
  ScopedState<SourceLocation> Scoped(&TypeRefingLocation, Decl->getBeginLoc());
  return Base::TraverseParmVarDecl(Decl);
}

bool Indexer::TraverseCStyleCastExpr(CStyleCastExpr* Cast) {
  ScopedState<SourceLocation> Scoped(&TypeRefingLocation, Cast->getBeginLoc());
  return Base::TraverseCStyleCastExpr(Cast);
}

bool Indexer::VisitTagType(const TagType* T) {
  if (TypeRefingLocation.isInvalid())
    return true;
  const auto* Tag = T->getAsTagDecl();
  const char* EntityKind = nullptr;
  if (Tag->isStruct())
    EntityKind = EntityKindStruct;
  else if (Tag->isUnion())
    EntityKind = EntityKindUnion;
  else if (Tag->isEnum())
    EntityKind = EntityKindEnum;
  else
    return true;
  EmitReference(TypeRefingLocation, Tag, EntityKind, RefKindUses);
  return true;
}

bool Indexer::VisitTypedefType(const TypedefType* T) {
  if (TypeRefingLocation.isInvalid())
    return true;
  EmitReference(TypeRefingLocation, T->getDecl(), EntityKindTypedef, RefKindUses);
  // If it's a struct typedef, also note the struct use.
  if (const auto* Tag = dyn_cast_if_present<TagType>(T->getCanonicalTypeInternal().getTypePtr()))
    VisitTagType(Tag);
  return true;
}

bool Indexer::VisitMemberExpr(const MemberExpr* E) {
  auto* Record = E->getBase()->getType()->getAsRecordDecl();
  if (auto* Ptr = dyn_cast_if_present<PointerType>(E->getBase()->getType()))
    Record = Ptr->getPointeeType()->getAsRecordDecl();
  if (!Record)
    return true;
  const std::string Field = Record->getNameAsString() + "::" + E->getMemberDecl()->getNameAsString();
  const char* RefKind = RefKindRead;
  const Stmt* P = GetParent(E);
  if (auto* BO = dyn_cast_if_present<BinaryOperator>(P)) {
    if (E == BO->getLHS() && (BO->isAssignmentOp() || BO->isCompoundAssignmentOp() || BO->isShiftAssignOp()))
      RefKind = RefKindWrite;
  }
  if (auto* UO = dyn_cast_if_present<UnaryOperator>(P))
    RefKind = RefKindTakesAddr;
  EmitReference(E->getMemberLoc(), Field, EntityKindField, RefKind);
  return true;
}

const Stmt* Indexer::GetParent(const Stmt* S) const {
  for (;;) {
    const auto& Parents = Context.getParents(*S);
    if (!Parents.empty())
      S = Parents[0].get<Stmt>();
    else
      S = nullptr;
    // Presumably ParentExpr is never interesting.
    if (S && isa<ParenExpr>(S))
      continue;
    return S;
  }
}

void Indexer::EmitReference(SourceLocation Loc, const NamedDecl* Named, const char* EntityKind, const char* RefKind) {
  if (Named)
    EmitReference(Loc, Named->getNameAsString(), EntityKind, RefKind);
}

void Indexer::EmitReference(SourceLocation Loc, const std::string& Name, const char* EntityKind, const char* RefKind) {
  if (!Current || Name.empty())
    return;
  Current->Refs.push_back(Reference{
      .Kind = RefKind,
      .EntityKind = EntityKind,
      .Name = Name,
      .Line = static_cast<int>(SM.getExpansionLineNumber(Loc)),
  });
}

bool Indexer::TraverseRecordDecl(RecordDecl* Decl) {
  if (!Decl->isThisDeclarationADefinition())
    return Base::TraverseRecordDecl(Decl);
  NamedDeclEmitter Emitter(this, Decl, Decl->isStruct() ? EntityKindStruct : EntityKindUnion, "", false);
  if (Decl->isCompleteDefinition()) {
    const auto& Layout = Context.getASTRecordLayout(Decl);
    for (const auto* Field : Decl->fields()) {
      uint64_t OffsetInBits = Layout.getFieldOffset(Field->getFieldIndex());
      uint64_t SizeInBits;
      if (Field->isBitField()) {
        SizeInBits = Field->getBitWidthValue(
#if CLANG_VERSION_MAJOR == 19
            Context
#endif
        );
      } else {
        TypeInfo Info = Context.getTypeInfo(Field->getType());
        SizeInBits = Info.Width;
      }
      Emitter.Def.Fields.push_back(FieldInfo{
          .Name = Field->getNameAsString(),
          .OffsetBits = OffsetInBits,
          .SizeBits = SizeInBits,
      });
    }
  }
  return Base::TraverseRecordDecl(Decl);
}

bool Indexer::TraverseEnumDecl(EnumDecl* Decl) {
  if (!Decl->isThisDeclarationADefinition())
    return Base::TraverseEnumDecl(Decl);
  NamedDeclEmitter Emitter(this, Decl, EntityKindEnum, "", false);
  return Base::TraverseEnumDecl(Decl);
}

bool Indexer::TraverseTypedefDecl(TypedefDecl* Decl) {
  NamedDeclEmitter Emitter(this, Decl, EntityKindTypedef, "", false);
  return Base::TraverseTypedefDecl(Decl);
}

static int Main(int argc, const char** argv) {
  llvm::cl::OptionCategory Options("codesearch options");
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
  fflush(stdout);
  return 0;
}

__attribute__((constructor(1000))) static void ctor(int argc, const char** argv) {
  const char* run = getenv("SYZ_RUN_CLANGTOOL");
  if (run && !strcmp(run, "codesearch"))
    exit(Main(argc, argv));
}
