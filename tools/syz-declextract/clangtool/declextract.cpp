// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "json.h"
#include "output.h"

#include "clang/AST/APValue.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Attrs.inc"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclarationName.h"
#include "clang/AST/Expr.h"
#include "clang/AST/PrettyPrinter.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Basic/LLVM.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TypeTraits.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stack>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <sys/ioctl.h>

using namespace clang;
using namespace clang::ast_matchers;

// MacroDef/MacroMap hold information about macros defined in the file.
struct MacroDef {
  std::string Value;       // value as written in the source
  SourceRange SourceRange; // soruce range of the value
};
using MacroMap = std::unordered_map<std::string, MacroDef>;

struct MacroDesc {
  std::string Name;
  std::string Value;
  SourceRange SourceRange;
  int64_t IntValue;
};

class Extractor : public MatchFinder, public tooling::SourceFileCallbacks {
public:
  Extractor() {
    match(&Extractor::matchFunctionDef, functionDecl(isDefinition()).bind("function"));

    match(&Extractor::matchSyscall,
          functionDecl(isExpandedFromMacro("SYSCALL_DEFINEx"), matchesName("__do_sys_.*")).bind("syscall"));

    match(&Extractor::matchIouring,
          translationUnitDecl(forEachDescendant(
              varDecl(hasType(constantArrayType(hasElementType(hasDeclaration(recordDecl(hasName("io_issue_def")))))),
                      isDefinition())
                  .bind("io_issue_defs"))));

    match(&Extractor::matchNetlinkPolicy,
          translationUnitDecl(forEachDescendant(
              varDecl(hasType(constantArrayType(hasElementType(hasDeclaration(recordDecl(hasName("nla_policy")))))),
                      isDefinition())
                  .bind("netlink_policy"))));

    match(&Extractor::matchNetlinkFamily, varDecl(hasType(recordDecl(hasName("genl_family")).bind("genl_family")),
                                                  has(initListExpr().bind("genl_family_init"))));

    match(&Extractor::matchFileOps,
          varDecl(forEachDescendant(initListExpr(hasType(recordDecl(hasName("file_operations")))).bind("init")))
              .bind("var"));
  }

  void print() const { Output.print(); }

private:
  friend struct FunctionAnalyzer;
  using MatchFunc = void (Extractor::*)();
  // Thunk that redirects MatchCallback::run method to one of the methods of the Extractor class.
  struct MatchCallbackThunk : MatchFinder::MatchCallback {
    Extractor& Ex;
    MatchFunc Action;
    MatchCallbackThunk(Extractor& Ex, MatchFunc Action) : Ex(Ex), Action(Action) {}
    void run(const MatchFinder::MatchResult& Result) override { Ex.run(Result, Action); }
  };
  std::vector<std::unique_ptr<MatchCallbackThunk>> Matchers;

  // These set to point to the Result of the current match (to avoid passing them through all methods).
  const BoundNodes* Nodes = nullptr;
  ASTContext* Context = nullptr;
  SourceManager* SourceManager = nullptr;

  Output Output;
  MacroMap Macros;
  std::unordered_map<std::string, bool> EnumDedup;
  std::unordered_map<std::string, bool> StructDedup;
  std::unordered_map<std::string, int> FileOpsDedup;

  void matchFunctionDef();
  void matchSyscall();
  void matchIouring();
  void matchNetlinkPolicy();
  void matchNetlinkFamily();
  void matchFileOps();
  bool handleBeginSource(CompilerInstance& CI) override;
  template <typename M> void match(MatchFunc Action, const M& Matcher);
  void run(const MatchFinder::MatchResult& Result, MatchFunc Action);
  template <typename T> const T* getResult(StringRef ID) const;
  FieldType extractRecord(QualType QT, const RecordType* Typ, const std::string& BackupName);
  std::string extractEnum(const EnumDecl* Decl);
  void emitConst(const std::string& Name, int64_t Val, SourceLocation Loc);
  std::string getDeclName(const Expr* Expr);
  const ValueDecl* getValueDecl(const Expr* Expr);
  std::string getDeclFileID(const Decl* Decl);
  std::string getUniqueDeclName(const NamedDecl* Decl);
  std::vector<std::pair<int, std::string>> extractDesignatedInitConsts(const VarDecl& ArrayDecl);
  FieldType genType(QualType Typ, const std::string& BackupName = "");
  std::unordered_map<std::string, unsigned> structFieldIndexes(const RecordDecl* Decl);
  template <typename T = int64_t> T evaluate(const Expr* E);
  template <typename T, typename Node, typename Condition>
  std::vector<const T*> findAllMatches(const Node* Expr, const Condition& Cond);
  template <typename T, typename Node, typename Condition>
  const T* findFirstMatch(const Node* Expr, const Condition& Cond);
  std::optional<QualType> getSizeofType(const Expr* E);
  int sizeofType(const Type* T);
  int alignofType(const Type* T);
  void extractIoctl(const Expr* Cmd, const MacroDesc& Macro);
  int getStmtLOC(const Stmt* S);
  std::optional<MacroDesc> isMacroRef(const Expr* E);
};

// PPCallbacksTracker records all macro definitions (name/value/source location).
class PPCallbacksTracker : public PPCallbacks {
public:
  PPCallbacksTracker(Preprocessor& PP, MacroMap& Macros) : SM(PP.getSourceManager()), Macros(Macros) {}

private:
  SourceManager& SM;
  MacroMap& Macros;

  void MacroDefined(const Token& MacroName, const MacroDirective* MD) override {
    const char* NameBegin = SM.getCharacterData(MacroName.getLocation());
    const char* NameEnd = SM.getCharacterData(MacroName.getEndLoc());
    std::string Name(NameBegin, NameEnd - NameBegin);
    const char* ValBegin = SM.getCharacterData(MD->getMacroInfo()->getDefinitionLoc());
    const char* ValEnd = SM.getCharacterData(MD->getMacroInfo()->getDefinitionEndLoc()) + 1;
    // Definition includes the macro name, remove it.
    ValBegin += std::min<size_t>(Name.size(), ValEnd - ValBegin);
    // Trim whitespace from both ends.
    while (ValBegin < ValEnd && isspace(*ValBegin))
      ValBegin++;
    while (ValBegin < ValEnd && isspace(*(ValEnd - 1)))
      ValEnd--;
    std::string Value(ValBegin, ValEnd - ValBegin);
    Macros[Name] = MacroDef{
        .Value = Value,
        .SourceRange = SourceRange(MD->getMacroInfo()->getDefinitionLoc(), MD->getMacroInfo()->getDefinitionEndLoc()),
    };
  }
};

bool Extractor::handleBeginSource(CompilerInstance& CI) {
  Preprocessor& PP = CI.getPreprocessor();
  PP.addPPCallbacks(std::make_unique<PPCallbacksTracker>(PP, Macros));
  return true;
}

template <typename M> void Extractor::match(MatchFunc Action, const M& Matcher) {
  Matchers.emplace_back(new MatchCallbackThunk(*this, Action));
  addMatcher(Matcher, Matchers.back().get());
}

void Extractor::run(const MatchFinder::MatchResult& Result, MatchFunc Action) {
  Nodes = &Result.Nodes;
  Context = Result.Context;
  SourceManager = Result.SourceManager;
  (this->*Action)();
}

template <typename T> const T* Extractor::getResult(StringRef ID) const { return Nodes->getNodeAs<T>(ID); }

// Top function that converts any clang type QT to our output type.
FieldType Extractor::genType(QualType QT, const std::string& BackupName) {
  const Type* T = QT.IgnoreParens().getUnqualifiedType().getDesugaredType(*Context).getTypePtr();
  if (auto* Typ = llvm::dyn_cast<BuiltinType>(T)) {
    return IntType{.ByteSize = sizeofType(T), .Name = QT.getAsString(), .Base = QualType(T, 0).getAsString()};
  }
  if (auto* Typ = llvm::dyn_cast<EnumType>(T)) {
    return IntType{.ByteSize = sizeofType(T), .Enum = extractEnum(Typ->getDecl())};
  }
  if (auto* Typ = llvm::dyn_cast<FunctionProtoType>(T)) {
    return PtrType{.Elem = TodoType(), .IsConst = true};
  }
  if (auto* Typ = llvm::dyn_cast<IncompleteArrayType>(T)) {
    return ArrType{.Elem = genType(Typ->getElementType(), BackupName)};
  }
  if (auto* Typ = llvm::dyn_cast<RecordType>(T)) {
    return extractRecord(QT, Typ, BackupName);
  }
  if (auto* Typ = llvm::dyn_cast<ConstantArrayType>(T)) {
    // TODO: the size may be a macro that is different for each arch, e.g.:
    //   long foo[FOOSIZE/sizeof(long)];
    int Size = Typ->getSize().getZExtValue();
    return ArrType{
        .Elem = genType(Typ->getElementType(), BackupName),
        .MinSize = Size,
        .MaxSize = Size,
        .Align = alignofType(Typ),
        .IsConstSize = true,
    };
  }
  if (auto* Typ = llvm::dyn_cast<PointerType>(T)) {
    FieldType Elem;
    const QualType& Pointee = Typ->getPointeeType();
    if (Pointee->isAnyCharacterType())
      Elem = BufferType{.IsString = true};
    else if (Pointee->isVoidType())
      Elem = ArrType{.Elem = TodoType()};
    else
      Elem = genType(Pointee, BackupName); // note: it may be an array as well
    return PtrType{
        .Elem = std::move(Elem),
        .IsConst = Pointee.isConstQualified(),
    };
  }
  QT.dump();
  llvm::report_fatal_error("unhandled type");
}

FieldType Extractor::extractRecord(QualType QT, const RecordType* Typ, const std::string& BackupName) {
  auto* Decl = Typ->getDecl()->getDefinition();
  if (!Decl)
    return TodoType(); // definition is in a different TU
  std::string Name = Decl->getDeclName().getAsString();
  // If it's a typedef of anon struct, we want to use the typedef name:
  //   typedef struct {...} foo_t;
  if (Name.empty() && QT->isTypedefNameType())
    Name = QualType(Typ, 0).getAsString();
  // If no other names, fallback to the parent-struct-based name.
  if (Name.empty()) {
    assert(!BackupName.empty());
    // The BackupName is supposed to be unique.
    assert(!StructDedup[BackupName]);
    Name = BackupName;
  }
  if (StructDedup[Name])
    return Name;
  StructDedup[Name] = true;
  std::vector<Field> Fields;
  for (const FieldDecl* F : Decl->fields()) {
    std::string FieldName = F->getNameAsString();
    std::string BackupFieldName = Name + "_" + FieldName;
    bool IsAnonymous = false;
    if (FieldName.empty()) {
      BackupFieldName = Name + "_" + std::to_string(F->getFieldIndex());
      FieldName = BackupFieldName;
      IsAnonymous = true;
    }
    FieldType FieldType = genType(F->getType(), BackupFieldName);
    int BitWidth = F->isBitField() ? F->getBitWidthValue(*Context) : 0;
    int CountedBy = F->getType()->isCountAttributedType()
                        ? llvm::dyn_cast<FieldDecl>(
                              F->getType()->getAs<CountAttributedType>()->getCountExpr()->getReferencedDeclOfCallee())
                              ->getFieldIndex()
                        : -1;
    Fields.push_back(Field{
        .Name = FieldName,
        .IsAnonymous = IsAnonymous,
        .BitWidth = BitWidth,
        .CountedBy = CountedBy,
        .Type = std::move(FieldType),
    });
  }
  int AlignAttr = 0;
  bool Packed = false;
  if (Decl->isStruct() && Decl->hasAttrs()) {
    for (const auto& A : Decl->getAttrs()) {
      if (auto* Attr = llvm::dyn_cast<AlignedAttr>(A))
        AlignAttr = Attr->getAlignment(*Context) / 8;
      else if (llvm::isa<PackedAttr>(A))
        Packed = true;
    }
  }
  Output.emit(Struct{
      .Name = Name,
      .ByteSize = sizeofType(Typ),
      .Align = alignofType(Typ),
      .IsUnion = Decl->isUnion(),
      .IsPacked = Packed,
      .AlignAttr = AlignAttr,
      .Fields = std::move(Fields),
  });
  return Name;
}

std::string Extractor::extractEnum(const EnumDecl* Decl) {
  const std::string& Name = Decl->getNameAsString();
  if (EnumDedup[Name])
    return Name;
  EnumDedup[Name] = true;
  std::vector<std::string> Values;
  for (const auto* Enumerator : Decl->enumerators()) {
    const std::string& Name = Enumerator->getNameAsString();
    emitConst(Name, Enumerator->getInitVal().getExtValue(), Decl->getBeginLoc());
    Values.push_back(Name);
  }
  Output.emit(Enum{
      .Name = Name,
      .Values = Values,
  });
  return Name;
}

void Extractor::emitConst(const std::string& Name, int64_t Val, SourceLocation Loc) {
  Output.emit(ConstInfo{
      .Name = Name,
      .Filename = std::filesystem::relative(SourceManager->getFilename(Loc).str()),
      .Value = Val,
  });
}

// Returns base part of the source file containing the canonical declaration.
// If the passed declaration is also a definition, then it will look for a preceeding declaration.
// This is used to generate unique names for static definitions that may have duplicate names
// across different TUs. We assume that the base part of the source file is enough
// to make them unique.
std::string Extractor::getDeclFileID(const Decl* Decl) {
  std::string file =
      std::filesystem::path(SourceManager->getFilename(Decl->getCanonicalDecl()->getSourceRange().getBegin()).str())
          .filename()
          .stem()
          .string();
  std::replace(file.begin(), file.end(), '-', '_');
  return file;
}

int Extractor::getStmtLOC(const Stmt* S) {
  return std::max<int>(0, SourceManager->getExpansionLineNumber(S->getSourceRange().getEnd()) -
                              SourceManager->getExpansionLineNumber(S->getSourceRange().getBegin()) - 1);
}

std::optional<MacroDesc> Extractor::isMacroRef(const Expr* E) {
  if (!E)
    return {};
  auto Range = Lexer::getAsCharRange(E->getSourceRange(), *SourceManager, Context->getLangOpts());
  const std::string& Str = Lexer::getSourceText(Range, *SourceManager, Context->getLangOpts()).str();
  auto MacroDef = Macros.find(Str);
  if (MacroDef == Macros.end())
    return {};
  int64_t Val = evaluate(E);
  emitConst(Str, Val, MacroDef->second.SourceRange.getBegin());
  return MacroDesc{
      .Name = Str,
      .Value = MacroDef->second.Value,
      .SourceRange = MacroDef->second.SourceRange,
      .IntValue = Val,
  };
}

template <typename Node> void matchHelper(MatchFinder& Finder, ASTContext* Context, const Node* Expr) {
  Finder.match(*Expr, *Context);
}

void matchHelper(MatchFinder& Finder, ASTContext* Context, const ASTContext* Expr) {
  assert(Context == Expr);
  Finder.matchAST(*Context);
}

// Returns all matches of Cond named "res" in Expr and returns them casted to T.
// Expr can point to Context for a global match.
template <typename T, typename Node, typename Condition>
std::vector<const T*> Extractor::findAllMatches(const Node* Expr, const Condition& Cond) {
  if (!Expr)
    return {};
  struct Matcher : MatchFinder::MatchCallback {
    std::vector<const T*> Matches;
    void run(const MatchFinder::MatchResult& Result) override {
      if (const T* M = Result.Nodes.getNodeAs<T>("res"))
        Matches.push_back(M);
    }
  };
  MatchFinder Finder;
  Matcher Matcher;
  Finder.addMatcher(Cond, &Matcher);
  matchHelper(Finder, Context, Expr);
  return std::move(Matcher.Matches);
}

// Returns the first match of Cond named "res" in Expr and returns it casted to T.
// If no match is found, returns nullptr.
template <typename T, typename Node, typename Condition>
const T* Extractor::findFirstMatch(const Node* Expr, const Condition& Cond) {
  const auto& Matches = findAllMatches<T>(Expr, Cond);
  return Matches.empty() ? nullptr : Matches[0];
}

// If expression refers to some identifier, returns the identifier name.
// Otherwise returns an empty string.
// For example, if the expression is `function_name`, returns "function_name" string.
// If AppendFile, then it also appends per-file suffix.
std::string Extractor::getDeclName(const Expr* Expr) {
  // The expression can be complex and include casts and e.g. InitListExpr,
  // to remove all of these we match the first/any DeclRefExpr.
  auto* Decl = getValueDecl(Expr);
  return Decl ? Decl->getNameAsString() : "";
}

// Returns the first ValueDecl in the expression.
const ValueDecl* Extractor::getValueDecl(const Expr* Expr) {
  // The expression can be complex and include casts and e.g. InitListExpr,
  // to remove all of these we match the first/any DeclRefExpr.
  auto* Decl = findFirstMatch<DeclRefExpr>(Expr, stmt(forEachDescendant(declRefExpr().bind("res"))));
  return Decl ? Decl->getDecl() : nullptr;
}

// Recursively finds first sizeof in the expression and return the type passed to sizeof.
std::optional<QualType> Extractor::getSizeofType(const Expr* E) {
  auto* Res = findFirstMatch<UnaryExprOrTypeTraitExpr>(
      E, stmt(forEachDescendant(unaryExprOrTypeTraitExpr(ofKind(UETT_SizeOf)).bind("res"))));
  if (!Res)
    return {};
  if (Res->isArgumentType())
    return Res->getArgumentType();
  return Res->getArgumentExpr()->getType();
}

// Returns map of field name -> field index.
std::unordered_map<std::string, unsigned> Extractor::structFieldIndexes(const RecordDecl* Decl) {
  // TODO: this is wrong for structs that contain unions and anonymous sub-structs (e.g. genl_split_ops).
  // To handle these we would need to look at InitListExpr::getInitializedFieldInUnion, and recurse
  // into anonymous structs.
  std::unordered_map<std::string, unsigned> Indexes;
  for (const auto& F : Decl->fields())
    Indexes[F->getNameAsString()] = F->getFieldIndex();
  return Indexes;
}

// Extracts enum info from array variable designated initialization.
// For example, for the following code:
//
//	enum Foo {
//		FooA = 11,
//		FooB = 42,
//	};
//
//	struct Bar bars[] = {
//		[FooA] = {...},
//		[FooB] = {...},
//	};
//
// it returns the following vector: {{11, "FooA"}, {42, "FooB"}}.
std::vector<std::pair<int, std::string>> Extractor::extractDesignatedInitConsts(const VarDecl& ArrayDecl) {
  const auto& Matches = findAllMatches<ConstantExpr>(
      &ArrayDecl,
      decl(forEachDescendant(designatedInitExpr(optionally(has(constantExpr(has(declRefExpr())).bind("res")))))));
  std::vector<std::pair<int, std::string>> Inits;
  for (auto* Match : Matches) {
    const int64_t Val = *Match->getAPValueResult().getInt().getRawData();
    const auto& Name = Match->getEnumConstantDecl()->getNameAsString();
    const auto& Loc = Match->getEnumConstantDecl()->getBeginLoc();
    emitConst(Name, Val, Loc);
    Inits.emplace_back(Val, Name);
  }
  return Inits;
}

int Extractor::sizeofType(const Type* T) { return static_cast<int>(Context->getTypeInfo(T).Width) / 8; }
int Extractor::alignofType(const Type* T) { return static_cast<int>(Context->getTypeInfo(T).Align) / 8; }

template <typename T> T Extractor::evaluate(const Expr* E) {
  Expr::EvalResult Res;
  E->EvaluateAsConstantExpr(Res, *Context);
  return static_cast<T>(Res.Val.getInt().getExtValue());
}

void Extractor::matchNetlinkPolicy() {
  const auto* PolicyArray = getResult<VarDecl>("netlink_policy");
  const auto* Init = llvm::dyn_cast_if_present<InitListExpr>(PolicyArray->getInit());
  if (!Init)
    return;
  const auto& InitConsts = extractDesignatedInitConsts(*PolicyArray);
  auto Fields = structFieldIndexes(Init->getInit(0)->getType()->getAsRecordDecl());
  std::vector<NetlinkAttr> Attrs;
  for (const auto& [I, Name] : InitConsts) {
    const auto* AttrInit = llvm::dyn_cast<InitListExpr>(Init->getInit(I));
    const std::string& AttrKind = getDeclName(AttrInit->getInit(Fields["type"]));
    if (AttrKind == "NLA_REJECT")
      continue;
    auto* LenExpr = AttrInit->getInit(Fields["len"]);
    int MaxSize = 0;
    std::string NestedPolicy;
    std::unique_ptr<FieldType> Elem;
    if (AttrKind == "NLA_NESTED" || AttrKind == "NLA_NESTED_ARRAY") {
      if (const auto* NestedDecl = getValueDecl(AttrInit->getInit(2)))
        NestedPolicy = getUniqueDeclName(NestedDecl);
    } else {
      MaxSize = evaluate<int>(LenExpr);
      if (auto SizeofType = getSizeofType(LenExpr))
        Elem = std::make_unique<FieldType>(genType(*SizeofType));
    }
    Attrs.push_back(NetlinkAttr{
        .Name = Name,
        .Kind = AttrKind,
        .MaxSize = MaxSize,
        .NestedPolicy = NestedPolicy,
        .Elem = std::move(Elem),
    });
  }
  Output.emit(NetlinkPolicy{
      .Name = getUniqueDeclName(PolicyArray),
      .Attrs = std::move(Attrs),
  });
}

void Extractor::matchNetlinkFamily() {
  const auto* FamilyInit = getResult<InitListExpr>("genl_family_init");
  auto Fields = structFieldIndexes(getResult<RecordDecl>("genl_family"));
  const std::string& FamilyName = llvm::dyn_cast<StringLiteral>(FamilyInit->getInit(Fields["name"]))->getString().str();
  std::string DefaultPolicy;
  if (const auto* PolicyDecl = FamilyInit->getInit(Fields["policy"])->getAsBuiltinConstantDeclRef(*Context))
    DefaultPolicy = getUniqueDeclName(PolicyDecl);
  std::vector<NetlinkOp> Ops;
  for (const auto& OpsName : {"ops", "small_ops", "split_ops"}) {
    const auto* OpsDecl =
        llvm::dyn_cast_if_present<VarDecl>(FamilyInit->getInit(Fields[OpsName])->getAsBuiltinConstantDeclRef(*Context));
    const auto NumOps = FamilyInit->getInit(Fields[std::string("n_") + OpsName])->getIntegerConstantExpr(*Context);
    // The ops variable may be defined in another TU.
    // TODO: extract variables from another TUs.
    if (!OpsDecl || !OpsDecl->getInit() || !NumOps)
      continue;
    const auto* OpsInit = llvm::dyn_cast<InitListExpr>(OpsDecl->getInit());
    auto OpsFields = structFieldIndexes(OpsInit->getInit(0)->getType()->getAsRecordDecl());
    for (int I = 0; I < *NumOps; I++) {
      const auto* OpInit = llvm::dyn_cast<InitListExpr>(OpsInit->getInit(I));
      const auto* CmdInit = OpInit->getInit(OpsFields["cmd"])->getEnumConstantDecl();
      if (!CmdInit)
        continue;
      const std::string& OpName = CmdInit->getNameAsString();
      emitConst(OpName, CmdInit->getInitVal().getExtValue(), CmdInit->getBeginLoc());
      std::string Policy;
      if (OpsFields.count("policy") != 0) {
        if (const auto* PolicyDecl = OpInit->getInit(OpsFields["policy"])->getAsBuiltinConstantDeclRef(*Context))
          Policy = getUniqueDeclName(PolicyDecl);
      }
      if (Policy.empty())
        Policy = DefaultPolicy;
      std::string Func = getDeclName(OpInit->getInit(OpsFields["doit"]));
      if (Func.empty())
        Func = getDeclName(OpInit->getInit(OpsFields["dumpit"]));
      int Flags = evaluate(OpInit->getInit(OpsFields["flags"]));
      const char* Access = AccessUser;
      constexpr int GENL_ADMIN_PERM = 0x01;
      constexpr int GENL_UNS_ADMIN_PERM = 0x10;
      if (Flags & GENL_ADMIN_PERM)
        Access = AccessAdmin;
      else if (Flags & GENL_UNS_ADMIN_PERM)
        Access = AccessNsAdmin;
      Ops.push_back(NetlinkOp{
          .Name = OpName,
          .Func = Func,
          .Access = Access,
          .Policy = Policy,
      });
    }
  }
  Output.emit(NetlinkFamily{
      .Name = FamilyName,
      .Ops = std::move(Ops),
  });
}

std::string Extractor::getUniqueDeclName(const NamedDecl* Decl) {
  return Decl->getNameAsString() + "_" + getDeclFileID(Decl);
}

const Expr* removeCasts(const Expr* E) {
  for (;;) {
    if (auto* P = dyn_cast<ParenExpr>(E))
      E = P->getSubExpr();
    else if (auto* C = dyn_cast<CastExpr>(E))
      E = C->getSubExpr();
    else
      break;
  }
  return E;
}

bool isInterestingCall(const CallExpr* Call) {
  auto* CalleeDecl = Call->getDirectCallee();
  // We don't handle indirect calls yet.
  if (!CalleeDecl)
    return false;
  // Builtins are not interesting and won't have a body.
  if (CalleeDecl->getBuiltinID() != Builtin::ID::NotBuiltin)
    return false;
  const std::string& Callee = CalleeDecl->getNameAsString();
  // There are too many of these and they should only be called at runtime in broken builds.
  if (Callee.rfind("__compiletime_assert", 0) == 0 || Callee == "____wrong_branch_error" ||
      Callee == "__bad_size_call_parameter")
    return false;
  return true;
}

struct FunctionAnalyzer : RecursiveASTVisitor<FunctionAnalyzer> {
  FunctionAnalyzer(Extractor* Extractor, const FunctionDecl* Func)
      : Extractor(Extractor), CurrentFunc(Func->getNameAsString()), Context(Extractor->Context),
        SourceManager(Extractor->SourceManager) {
    // The global function scope.
    Scopes.push_back(FunctionScope{.Arg = -1, .LOC = Extractor->getStmtLOC(Func->getBody())});
    Current = &Scopes[0];
    TraverseStmt(Func->getBody());
  }

  bool VisitBinaryOperator(const BinaryOperator* B) {
    if (B->isAssignmentOp())
      noteFact(getTypingEntity(B->getRHS()), getTypingEntity(B->getLHS()));
    return true;
  }

  bool VisitVarDecl(const VarDecl* D) {
    if (D->getStorageDuration() == SD_Automatic)
      noteFact(getTypingEntity(D->getInit()), getDeclTypingEntity(D));
    return true;
  }

  bool VisitReturnStmt(const ReturnStmt* Ret) {
    noteFact(getTypingEntity(Ret->getRetValue()), EntityReturn{.Func = CurrentFunc});
    return true;
  }

  bool VisitCallExpr(const CallExpr* Call) {
    if (isInterestingCall(Call)) {
      const std::string& Callee = Call->getDirectCallee()->getNameAsString();
      Current->Calls.push_back(Callee);
      for (unsigned AI = 0; AI < Call->getNumArgs(); AI++) {
        noteFact(getTypingEntity(Call->getArg(AI)), EntityArgument{
                                                        .Func = Callee,
                                                        .Arg = AI,
                                                    });
      }
    }
    return true;
  }

  bool VisitSwitchStmt(const SwitchStmt* S) {
    // We are only interested in switches on the function arguments
    // with cases that mention defines from uapi headers.
    // This covers ioctl/fcntl/prctl/ptrace/etc.
    bool IsInteresting = false;
    auto Param = getTypingEntity(S->getCond());
    if (Current == &Scopes[0] && Param && Param->Argument) {
      for (auto* C = S->getSwitchCaseList(); C; C = C->getNextSwitchCase()) {
        auto* Case = dyn_cast<CaseStmt>(C);
        if (!Case)
          continue;
        auto LMacro = Extractor->isMacroRef(Case->getLHS());
        auto RMacro = Extractor->isMacroRef(Case->getRHS());
        if (LMacro || RMacro) {
          IsInteresting = true;
          break;
        }
      }
    }

    int Begin = SourceManager->getExpansionLineNumber(S->getBeginLoc());
    int End = SourceManager->getExpansionLineNumber(S->getEndLoc());
    if (IsInteresting)
      Scopes[0].LOC = std::max<int>(0, Scopes[0].LOC - (End - Begin));
    SwitchStack.push({S, IsInteresting, IsInteresting ? static_cast<int>(Param->Argument->Arg) : -1, End});
    return true;
  }

  bool VisitSwitchCase(const SwitchCase* C) {
    if (!SwitchStack.top().IsInteresting)
      return true;
    // If there are several cases with the same "body", we want to create new scope
    // only for the first one:
    //   case FOO:
    //   case BAR:
    //     ... some code ...
    if (!C->getNextSwitchCase() || C->getNextSwitchCase()->getSubStmt() != C) {
      int Line = SourceManager->getExpansionLineNumber(C->getBeginLoc());
      if (Current != &Scopes[0])
        Current->LOC = Line - Current->LOC;
      Scopes.push_back(FunctionScope{
          .Arg = SwitchStack.top().Arg,
          .LOC = Line,
      });
      Current = &Scopes.back();
    }
    // Otherwise it's a default case, for which we don't add any values.
    if (auto* Case = dyn_cast<CaseStmt>(C)) {
      int64_t LVal = Extractor->evaluate(Case->getLHS());
      auto LMacro = Extractor->isMacroRef(Case->getLHS());
      if (LMacro) {
        Current->Values.push_back(LMacro->Name);
        Extractor->extractIoctl(Case->getLHS(), *LMacro);
      } else {
        Current->Values.push_back(std::to_string(LVal));
      }
      if (Case->caseStmtIsGNURange()) {
        // GNU range is:
        //   case FOO ... BAR:
        // Add all values in the range.
        int64_t RVal = Extractor->evaluate(Case->getRHS());
        auto RMacro = Extractor->isMacroRef(Case->getRHS());
        for (int64_t V = LVal + 1; V <= RVal - (RMacro ? 1 : 0); V++)
          Current->Values.push_back(std::to_string(V));
        if (RMacro)
          Current->Values.push_back(RMacro->Name);
      }
    }
    return true;
  }

  bool dataTraverseStmtPost(const Stmt* S) {
    if (SwitchStack.empty())
      return true;
    auto Top = SwitchStack.top();
    if (Top.S != S)
      return true;
    if (Top.IsInteresting) {
      Current->LOC = Top.EndLine - Current->LOC;
      Current = &Scopes[0];
    }
    SwitchStack.pop();
    return true;
  }

  void noteFact(std::optional<TypingEntity>&& Src, std::optional<TypingEntity>&& Dst) {
    if (Src && Dst)
      Current->Facts.push_back({std::move(*Src), std::move(*Dst)});
  }

  std::optional<TypingEntity> getTypingEntity(const Expr* E);
  std::optional<TypingEntity> getDeclTypingEntity(const Decl* Decl);

  struct SwitchDesc {
    const SwitchStmt* S;
    bool IsInteresting;
    int Arg;
    int EndLine;
  };

  Extractor* Extractor;
  std::string CurrentFunc;
  ASTContext* Context;
  SourceManager* SourceManager;
  std::vector<FunctionScope> Scopes;
  FunctionScope* Current = nullptr;
  std::unordered_map<const VarDecl*, int> LocalVars;
  std::unordered_map<std::string, int> LocalSeq;
  std::stack<SwitchDesc> SwitchStack;
};

void Extractor::matchFunctionDef() {
  const auto* Func = getResult<FunctionDecl>("function");
  if (!Func->getBody())
    return;
  const std::string& SourceFile = std::filesystem::relative(
      SourceManager->getFilename(SourceManager->getExpansionLoc(Func->getSourceRange().getBegin())).str());
  FunctionAnalyzer Analyzer(this, Func);
  Output.emit(Function{
      .Name = Func->getNameAsString(),
      .File = SourceFile,
      .IsStatic = Func->isStatic(),
      .Scopes = std::move(Analyzer.Scopes),
  });
}

std::optional<TypingEntity> FunctionAnalyzer::getTypingEntity(const Expr* E) {
  if (!E)
    return {};
  E = removeCasts(E);
  if (auto* DeclRef = dyn_cast<DeclRefExpr>(E)) {
    return getDeclTypingEntity(DeclRef->getDecl());
  } else if (auto* Member = dyn_cast<MemberExpr>(E)) {
    const Type* StructType =
        Member->getBase()->getType().IgnoreParens().getUnqualifiedType().getDesugaredType(*Context).getTypePtr();
    if (auto* T = dyn_cast<PointerType>(StructType))
      StructType = T->getPointeeType().IgnoreParens().getUnqualifiedType().getDesugaredType(*Context).getTypePtr();
    auto* StructDecl = dyn_cast<RecordType>(StructType)->getDecl();
    std::string StructName = StructDecl->getNameAsString();
    if (StructName.empty()) {
      // The struct may be anonymous, but we need some name.
      // Ideally we generate the same name we generate in struct definitions, then it will be possible
      // to match them between each other. However, it does not seem to be easy. We can use DeclContext::getParent
      // to get declaration of the enclosing struct, but we will also need to figure out the field index
      // and handle all corner cases. For now we just use the following quick hack: hash declaration file:line.
      // Note: the hash must be stable across different machines (for test golden files), so we take just
      // the last part of the file name.
      const std::string& SourceFile =
          std::filesystem::path(
              SourceManager->getFilename(SourceManager->getExpansionLoc(StructDecl->getBeginLoc())).str())
              .filename()
              .string();
      int Line = SourceManager->getExpansionLineNumber(StructDecl->getBeginLoc());
      StructName = std::to_string(std::hash<std::string>()(SourceFile) + std::hash<int>()(Line));
    }
    return EntityField{
        .Struct = StructName,
        .Field = Member->getMemberDecl()->getNameAsString(),
    };
  } else if (auto* Unary = dyn_cast<UnaryOperator>(E)) {
    if (Unary->getOpcode() == UnaryOperatorKind::UO_AddrOf) {
      if (auto* DeclRef = dyn_cast<DeclRefExpr>(removeCasts(Unary->getSubExpr()))) {
        if (auto* Var = dyn_cast<VarDecl>(DeclRef->getDecl())) {
          if (Var->hasGlobalStorage()) {
            return EntityGlobalAddr{
                .Name = Extractor->getUniqueDeclName(Var),
            };
          }
        }
      }
    }
  } else if (auto* Call = dyn_cast<CallExpr>(E)) {
    if (isInterestingCall(Call)) {
      return EntityReturn{
          .Func = Call->getDirectCallee()->getNameAsString(),
      };
    }
  }
  return {};
}

std::optional<TypingEntity> FunctionAnalyzer::getDeclTypingEntity(const Decl* Decl) {
  if (auto* Parm = dyn_cast<ParmVarDecl>(Decl)) {
    return EntityArgument{
        .Func = CurrentFunc,
        .Arg = Parm->getFunctionScopeIndex(),
    };
  } else if (auto* Var = dyn_cast<VarDecl>(Decl)) {
    if (Var->hasLocalStorage()) {
      std::string VarName = Var->getNameAsString();
      // Theoretically there can be several local vars with the same name.
      // Give them unique suffixes if that's the case.
      if (LocalVars.count(Var) == 0)
        LocalVars[Var] = LocalSeq[VarName]++;
      if (int Seq = LocalVars[Var])
        VarName += std::to_string(Seq);
      return EntityLocal{
          .Name = VarName,
      };
    }
  }
  return {};
}

void Extractor::matchSyscall() {
  const auto* Func = getResult<FunctionDecl>("syscall");
  std::vector<Field> Args;
  for (const auto& Param : Func->parameters()) {
    Args.push_back(Field{
        .Name = Param->getNameAsString(),
        .Type = genType(Param->getType()),
    });
  }
  Output.emit(Syscall{
      .Func = Func->getNameAsString(),
      .Args = std::move(Args),
  });
}

void Extractor::matchIouring() {
  const auto* IssueDefs = getResult<VarDecl>("io_issue_defs");
  const auto& InitConsts = extractDesignatedInitConsts(*IssueDefs);
  const auto* InitList = llvm::dyn_cast<InitListExpr>(IssueDefs->getInit());
  auto Fields = structFieldIndexes(InitList->getInit(0)->getType()->getAsRecordDecl());
  for (const auto& [I, Name] : InitConsts) {
    const auto& Init = llvm::dyn_cast<InitListExpr>(InitList->getInit(I));
    std::string Prep = getDeclName(Init->getInit(Fields["prep"]));
    if (Prep == "io_eopnotsupp_prep")
      continue;
    Output.emit(IouringOp{
        .Name = Name,
        .Func = getDeclName(Init->getInit(Fields["issue"])),
    });
  }
}

void Extractor::matchFileOps() {
  const auto* Fops = getResult<InitListExpr>("init");
  if (Fops->getNumInits() == 0 || isa<DesignatedInitExpr>(Fops->getInit(0))) {
    // Some code constructs produce init list with DesignatedInitExpr.
    // Unclear why, but it won't be handled by the following code, and is not necessary to handle.
    return;
  }
  const auto* Var = getResult<VarDecl>("var");
  std::string VarName = getUniqueDeclName(Var);
  int NameSeq = FileOpsDedup[VarName]++;
  if (NameSeq)
    VarName += std::to_string(NameSeq);
  auto Fields = structFieldIndexes(Fops->getType()->getAsRecordDecl());
  std::string Open = getDeclName(Fops->getInit(Fields["open"]));
  std::string Ioctl = getDeclName(Fops->getInit(Fields["unlocked_ioctl"]));
  std::string Read = getDeclName(Fops->getInit(Fields["read"]));
  if (Read.empty())
    Read = getDeclName(Fops->getInit(Fields["read_iter"]));
  std::string Write = getDeclName(Fops->getInit(Fields["write"]));
  if (Write.empty())
    Write = getDeclName(Fops->getInit(Fields["write_iter"]));
  std::string Mmap = getDeclName(Fops->getInit(Fields["mmap"]));
  if (Mmap.empty())
    Mmap = getDeclName(Fops->getInit(Fields["get_unmapped_area"]));
  Output.emit(FileOps{
      .Name = VarName,
      .Open = std::move(Open),
      .Read = std::move(Read),
      .Write = std::move(Write),
      .Mmap = std::move(Mmap),
      .Ioctl = std::move(Ioctl),
  });
}

void Extractor::extractIoctl(const Expr* Cmd, const MacroDesc& Macro) {
  // This is old style ioctl defined directly via a number.
  // We can't infer anything about it.
  if (Macro.Value.find("_IO") != 0)
    return;
  FieldType Type;
  auto Dir = _IOC_DIR(Macro.IntValue);
  if (Dir == _IOC_NONE) {
    Type = IntType{.ByteSize = 1, .IsConst = true};
  } else if (std::optional<QualType> Arg = getSizeofType(Cmd)) {
    Type = PtrType{
        .Elem = genType(*Arg),
        .IsConst = Dir == _IOC_READ,
    };
  } else {
    // It is an ioctl, but we failed to get the arg type.
    // Let the Go part figure out a good arg type.
    return;
  }
  Output.emit(Ioctl{
      .Name = Macro.Name,
      .Type = std::move(Type),
  });
}

int main(int argc, const char** argv) {
  llvm::cl::OptionCategory Options("syz-declextract options");
  auto OptionsParser = tooling::CommonOptionsParser::create(argc, argv, Options);
  if (!OptionsParser) {
    llvm::errs() << OptionsParser.takeError();
    return 1;
  }
  Extractor Ex;
  tooling::ClangTool Tool(OptionsParser->getCompilations(), OptionsParser->getSourcePathList());
  if (Tool.run(tooling::newFrontendActionFactory(&Ex, &Ex).get()))
    return 1;
  Ex.print();
  return 0;
}
