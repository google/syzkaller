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
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Basic/LLVM.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TypeTraits.h"
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
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

class Extractor : public MatchFinder {
public:
  Extractor() {
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
  }

  void print() const { Output.print(); }

private:
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
  std::unordered_map<std::string, bool> EnumDedup;
  std::unordered_map<std::string, bool> StructDedup;

  void matchSyscall();
  void matchIouring();
  void matchNetlinkPolicy();
  void matchNetlinkFamily();
  template <typename M> void match(MatchFunc Action, const M& Matcher);
  void run(const MatchFinder::MatchResult& Result, MatchFunc Action);
  template <typename T> const T* getResult(StringRef ID) const;
  FieldType extractRecord(QualType QT, const RecordType* Typ, const std::string& BackupName);
  std::string extractEnum(const EnumDecl* Decl);
  void noteConstUse(const std::string& Name, int64_t Val, const SourceRange& Range);
  std::string getDeclName(const Expr* Expr);
  const ValueDecl* getValueDecl(const Expr* Expr);
  std::string getDeclFileID(const Decl* Decl);
  std::string policyName(const ValueDecl* Decl);
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
};

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
    int Size = Typ->getSize().getZExtValue();
    return ArrType{
        .Elem = genType(Typ->getElementType(), BackupName),
        .MinSize = Size,
        .MaxSize = Size,
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
  int Align = 0;
  bool Packed = false;
  if (Decl->isStruct() && Decl->hasAttrs()) {
    for (const auto& A : Decl->getAttrs()) {
      if (auto* Attr = llvm::dyn_cast<AlignedAttr>(A))
        Align = Attr->getAlignment(*Context) / 8;
      else if (llvm::isa<PackedAttr>(A))
        Packed = true;
    }
  }
  Output.emit(Struct{
      .Name = Name,
      .ByteSize = sizeofType(Typ),
      .IsUnion = Decl->isUnion(),
      .IsPacked = Packed,
      .Align = Align,
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
    noteConstUse(Name, Enumerator->getInitVal().getExtValue(), Decl->getSourceRange());
    Values.push_back(Name);
  }
  Output.emit(Enum{
      .Name = Name,
      .Values = Values,
  });
  return Name;
}

void Extractor::noteConstUse(const std::string& Name, int64_t Val, const SourceRange& Range) {
  const std::string& Filename = std::filesystem::relative(SourceManager->getFilename(Range.getBegin()).str());
  // Include only uapi headers. Some ioctl commands defined in internal headers, or even in .c files.
  // They have high chances of breaking compilation during const extract.
  // If it's not defined in uapi, emit define with concrete value.
  // Note: the value may be wrong for other arches.
  if (Filename.find("/uapi/") != std::string::npos && Filename.back() == 'h') {
    Output.emit(Include{Filename});
    return;
  }
  Output.emit(Define{
      .Name = Name,
      .Value = std::to_string(Val),
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
    const auto& SR = Match->getEnumConstantDecl()->getSourceRange();
    noteConstUse(Name, Val, SR);
    Inits.emplace_back(Val, Name);
  }
  return Inits;
}

int Extractor::sizeofType(const Type* T) { return static_cast<int>(Context->getTypeInfo(T).Width) / 8; }

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
        NestedPolicy = policyName(NestedDecl);
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
      .Name = policyName(PolicyArray),
      .Attrs = std::move(Attrs),
  });
}

void Extractor::matchNetlinkFamily() {
  const auto* FamilyInit = getResult<InitListExpr>("genl_family_init");
  auto Fields = structFieldIndexes(getResult<RecordDecl>("genl_family"));
  const std::string& FamilyName = llvm::dyn_cast<StringLiteral>(FamilyInit->getInit(Fields["name"]))->getString().str();
  std::string DefaultPolicy;
  if (const auto* PolicyDecl = FamilyInit->getInit(Fields["policy"])->getAsBuiltinConstantDeclRef(*Context))
    DefaultPolicy = policyName(PolicyDecl);
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
      noteConstUse(OpName, CmdInit->getInitVal().getExtValue(), CmdInit->getSourceRange());
      std::string Policy;
      if (OpsFields.count("policy") != 0) {
        if (const auto* PolicyDecl = OpInit->getInit(OpsFields["policy"])->getAsBuiltinConstantDeclRef(*Context))
          Policy = policyName(PolicyDecl);
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

std::string Extractor::policyName(const ValueDecl* Decl) {
  // TODO: remove appending of $ sign here.
  return Decl->getNameAsString() + "$auto_" + getDeclFileID(Decl);
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

int main(int argc, const char** argv) {
  llvm::cl::OptionCategory Options("syz-declextract options");
  auto OptionsParser = tooling::CommonOptionsParser::create(argc, argv, Options);
  if (!OptionsParser) {
    llvm::errs() << OptionsParser.takeError();
    return 1;
  }
  Extractor Ex;
  tooling::ClangTool Tool(OptionsParser->getCompilations(), OptionsParser->getSourcePathList());
  if (Tool.run(tooling::newFrontendActionFactory(&Ex).get()))
    return 1;
  Ex.print();
  return 0;
}
