// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build ignore
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
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Basic/LLVM.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TypeTraits.h"
#include "clang/Lex/Lexer.h"
#include "clang/Sema/Ownership.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Frontend/OpenMP/OMP.h.inc"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

struct EnumData {
  std::string name;
  unsigned long long value;
  std::string file;
};

struct Param {
  std::string type;
  std::string name;
};

struct NetlinkOps {
  std::string cmd;
  std::optional<std::string> policy;
};

struct NetlinkType {
  RecordDecl *decl;
  int64_t len;
};

struct StructMember {
  std::string type;
  std::string name;
  unsigned int countedBy;
};

void emitInterface(const char *type, std::string_view name) {
  printf("\n#INTERFACE: %s %s\n\n", type, std::string(name).c_str());
}

struct SyzRecordDecl {
  std::string name;
  std::vector<StructMember> members;
  std::string attr;
  bool isUnion;
  bool isVarlen;
  bool operator==(const SyzRecordDecl &decl) { return name == decl.name; }
  bool operator<(const SyzRecordDecl &decl) { return name < decl.name; }
  void print() const {
    if (name.empty()) {
      return;
    }
    const char openBracket = isUnion ? '[' : '{';
    const char closeBracket = isUnion ? ']' : '}';
    printf("%s %c\n", name.c_str(), openBracket);
    for (const auto &member : members) {
      printf("\t%s %s\n", member.name.c_str(), member.type.c_str());
    }
    putchar(closeBracket);
    if (isUnion && isVarlen) {
      printf("[%s]", "varlen");
    } else if (!isUnion && !attr.empty()) {
      printf("[%s]", attr.c_str());
    }
    puts("");
  }
};

bool endsWith(const std::string_view &str, const std::string_view end) {
  size_t substrBegin = str.rfind(end);
  return substrBegin != std::string::npos && str.substr(substrBegin) == end;
}

bool beginsWith(const std::string_view &str, const std::string_view begin) {
  size_t substrBegin = str.find(begin);
  return substrBegin != std::string::npos && str.substr(0, begin.size()) == begin;
}

bool contains(const std::string_view &str, const std::string_view sub) { return str.find(sub) != std::string::npos; }

const std::string int8Subtype(const std::string &name) { return "int8"; }
const std::string int16Subtype(const std::string &name) {
  if (contains(name, "port")) {
    return "sock_port";
  }
  return "int16";
}
const std::string int32Subtype(const std::string &name) {
  if (contains(name, "ipv4")) {
    return "ipv4_addr";
  }
  if (endsWith(name, "_pid") || endsWith(name, "_tid") || name == "pid" || name == "tid") {
    return "pid";
  }
  if (endsWith(name, "dfd") && !endsWith(name, "oldfd")) {
    return "fd_dir";
  }
  if (endsWith(name, "_uid") || name == "uid") {
    return "uid";
  }
  if (endsWith(name, "_gid") || name == "gid") {
    return "gid";
  }
  if (endsWith(name, "fd") || beginsWith(name, "fd_")) {
    if (endsWith(name, "ns_fd")) {
      return "fd_namespace";
    }
    return "fd";
  }
  if (contains(name, "ifindex")) {
    return "ifindex";
  }
  return "int32";
}
const std::string stringSubtype(const std::string &name) {
  if (contains(name, "ifname") || endsWith(name, "dev_name")) {
    return "devname";
  }
  return "string";
}
const std::string int64Subtype(const std::string &name) { return "int64"; }

const std::string makeArray(const std::string &type, const size_t min = 0, const size_t max = -1) {
  if (max != size_t(-1)) {
    return "array[" + type + ", " + std::to_string(min) + ":" + std::to_string(max) + "]";
  }
  if (min == 1) {
    return type;
  }
  if (min) {
    return "array[" + type + ", " + std::to_string(min) + "]";
  }
  return "array[" + type + "]";
}

const std::string makePtr(const std::string &dir, const std::string &type, bool isOpt = false) {
  std::string ptr = "ptr[" + dir + ", " + type;
  if (isOpt) {
    return ptr + ", opt]";
  }
  return ptr + "]";
}

const std::string makeConst(const std::string &type, const std::string &val = "0") {
  if (type.empty()) {
    return "const[" + val + "]";
  }
  return "const[" + val + ", " + type + "]";
}

enum IntType {
  INVALID_INT = 0,
  INT_8 = 1,
  INT_16 = 2,
  INT_32 = 4,
  INT_64 = 8,
  INT_PTR,
};

IntType getIntType(const std::string &ctype, const bool isSyscallParam) {
  // TODO: Handle arm32 passing 64bit arguments
  if (!isSyscallParam && (contains(ctype, "long long") || contains(ctype, "64"))) {
    return INT_64;
  }
  if (contains(ctype, "16") || contains(ctype, "short")) {
    return INT_16;
  }
  if (contains(ctype, "8") || contains(ctype, "char")) {
    return INT_8;
  }
  if (contains(ctype, "32") || contains(ctype, "int")) {
    return INT_32;
  }
  if (contains(ctype, "long")) {
    return INT_PTR;
  }
  fprintf(stderr, "Unhandled int length for type: %s\n", ctype.c_str());
  exit(1);
}

const std::string intNCommonSubtype(const std::string &name, const IntType len) {
  const auto &byteLen = std::to_string(len * 8);
  if (endsWith(name, "enabled") || endsWith(name, "enable")) {
    return "bool" + byteLen;
  }
  return "int" + byteLen;
}

const std::string intNSubtype(const std::string &name, const IntType len) {
  switch (len) {
  case INT_8:
    return int8Subtype(name);
  case INT_16:
    return int16Subtype(name);
  case INT_32:
    return int32Subtype(name);
  case INT_64:
    return int64Subtype(name);
  default:
    fprintf(stderr, "invalid int type: %d\n", static_cast<int>(len));
    exit(1);
  }
}

bool isIntN(const std::string &syztype) {
  return !syztype.compare(0, 3, "int") && std::all_of(syztype.begin() + 3, syztype.end(), ::isDigit);
}

const std::string intSubtype(const std::string &name, const IntType len) {
  if (len == INVALID_INT) {
    fprintf(stderr, "Invalid int type\n");
    exit(1);
  } else if (len == INT_PTR) {
    return "intptr";
  }

  const std::string &subType = intNSubtype(name, len);
  return isIntN(subType) ? intNCommonSubtype(name, len) : subType;
}

const std::string getSyzType(const std::string &ctype, std::string name, const bool isSyscallParam,
                             const int bitFieldWidth = 0) {
  std::transform(name.begin(), name.end(), name.begin(), ::tolower);
  IntType len = getIntType(ctype, isSyscallParam);
  const int byteLen = len * 8;
  if (INT_8 <= len && len <= INT_64 && contains(ctype, "be")) {
    return "int" + std::to_string(byteLen) + "be";
  }

  std::string type;
  const bool isBitField = bitFieldWidth;
  if (isBitField) {
    type = "int" + std::to_string(byteLen);
    if (byteLen != bitFieldWidth) {
      type += ":" + std::to_string(bitFieldWidth);
    }
  } else {
    type = intSubtype(name, len);
  }

  if (isBitField || type == "intptr" || isIntN(type)) {
    if (name.empty() || contains(name, "pad") || contains(name, "unused") || contains(name, "_reserved")) {
      return makeConst(isSyscallParam ? "" : type);
    }
  }

  return type;
}

class RecordExtractor {
private:
  const SourceManager *const SM;
  std::vector<std::string> includes;
  std::vector<std::string> flags;
  std::unordered_map<std::string, SyzRecordDecl> extractedRecords;
  const std::string emptyStructType = "empty struct";
  const std::string autoTodo = "auto_todo";

  unsigned int getCountedBy(const FieldDecl *const &field) {
    return field->getType()->isCountAttributedType()
               ? llvm::dyn_cast<FieldDecl>(
                     field->getType()->getAs<CountAttributedType>()->getCountExpr()->getReferencedDeclOfCallee())
                     ->getFieldIndex()
               : UINT_MAX;
  }

  bool isFieldVarlen(const QualType &fieldType) {
    return fieldType->isIncompleteArrayType() ||
           (fieldType->isConstantArrayType() && llvm::dyn_cast<ConstantArrayType>(fieldType)->getSize().isZero());
  }

  std::string getStructAttr(const RecordDecl *const recordDecl, ASTContext *context) {
    if (recordDecl->isStruct() && recordDecl->hasAttrs()) {
      for (const auto &item : recordDecl->getAttrs()) {
        if (item->getKind() == clang::attr::Aligned) {
          return "align[" + std::to_string(llvm::dyn_cast<AlignedAttr>(item)->getAlignment(*context) / 8) + "]";
        } else if (item->getKind() == clang::attr::Packed) {
          return "packed";
        }
      }
    }
    return "";
  }

public:
  RecordExtractor(const SourceManager *const SM) : SM(SM){};
  std::string getFieldType(const QualType &fieldType, ASTContext *context, const std::string &fieldName,
                           const std::string &parent = "", bool isSyscallParam = false,
                           const std::string &fieldTypeName = "") {
    const auto &field = fieldType.IgnoreParens().getDesugaredType(*context);
    switch (fieldType.IgnoreParens()->getTypeClass()) {
    case clang::Type::Record: {
      std::string backupName;
      if (!parent.empty()) {
        backupName = parent + "_" + fieldName;
      } else if (!fieldTypeName.empty()) {
        backupName = fieldTypeName;
      } else {
        backupName = fieldName;
      }
      return extractRecord(field->getAsRecordDecl(), context, backupName);
    }
    case clang::Type::IncompleteArray: // Defined as type[]
      return makeArray(getFieldType(llvm::dyn_cast<IncompleteArrayType>(field)->getElementType(), context, fieldName));
    case clang::Type::ConstantArray: {
      const auto &array = llvm::dyn_cast<ConstantArrayType>(field);
      return makeArray(getFieldType(array->getElementType(), context, fieldName), array->getSize().getZExtValue());
    }
    case clang::Type::Pointer: {
      const auto &pointerType = llvm::dyn_cast<PointerType>(field);
      const auto &pointeeType = pointerType->getPointeeType();
      std::string fieldType;
      if (pointeeType->isAnyCharacterType()) {
        fieldType = stringSubtype(fieldName);
      } else if (pointeeType->isVoidType()) {
        fieldType = makeArray(autoTodo);
      } else {
        fieldType = getFieldType(pointeeType, context, fieldName);
      }
      const auto &ptrDir = pointeeType.isConstQualified() ? "in" : "inout"; // TODO: Infer direction of non-const.
      return makePtr(ptrDir, fieldType,
                     parent + "$auto_record" == fieldType); // Checks if the direct parent is the same as the node.
    }
    case clang::Type::Builtin:
      return getSyzType(field.getAsString(), fieldName, isSyscallParam);
    case clang::Type::CountAttributed:  // Has the attribute counted_by. Handled by getCountedBy
    case clang::Type::BTFTagAttributed: // Currently Unused
    case clang::Type::Typedef:
      return getFieldType(field, context, fieldName, parent, isSyscallParam, field.getAsString());
    case clang::Type::Elaborated:
      return getFieldType(llvm::dyn_cast<ElaboratedType>(fieldType)->desugar(), context, fieldName, parent,
                          isSyscallParam); // NOTE: The fieldType contains information we need, don't use field instead.
    case clang::Type::Enum: {
      const auto &enumDecl = llvm::dyn_cast<EnumType>(field)->getDecl();
      auto name = enumDecl->getNameAsString();
      flags.push_back(name);
      includes.push_back(std::filesystem::relative(SM->getFilename(enumDecl->getSourceRange().getBegin()).str()));
      const char *sep = " = ";
      for (const auto &enumerator : enumDecl->enumerators()) {
        flags.back() += sep + enumerator->getNameAsString();
        sep = ", ";
      }
      return "flags[" + name + "]";
    }
    case clang::Type::FunctionProto:
      return makePtr("in", autoTodo);
    default:
      field->dump();
      fprintf(stderr, "Unhandled field type %s\n", field->getTypeClassName());
      exit(1);
    }
  }

  std::string extractRecord(const RecordDecl *recordDecl, ASTContext *context, const std::string &backupName) {
    recordDecl = recordDecl->getDefinition();
    if (!recordDecl) { // When the definition is in a different translation unit.
      return autoTodo;
    }
    const auto &name = (recordDecl->getNameAsString().empty() ? backupName : recordDecl->getNameAsString());
    const auto &recordName = name + "$auto_record";
    if (extractedRecords.find(name) != extractedRecords.end()) { // Don't extract the same record twice.
      return recordName;
    }
    extractedRecords[name];
    bool isVarlen = false;
    std::vector<StructMember> members;
    for (const auto &field : recordDecl->fields()) {
      std::string fieldName;
      if (field->getName().empty()) {
        fieldName = name + "_" + std::to_string(field->getFieldIndex());
      } else if (field->isAnonymousStructOrUnion()) {
        fieldName = name;
      } else {
        fieldName = field->getNameAsString();
      }
      const std::string &parentName = field->isAnonymousStructOrUnion() ? "" : name;
      const std::string &fieldType =
          field->isBitField() ? getSyzType(field->getType().getAsString(), field->isUnnamedBitField() ? "" : fieldName,
                                           false, field->getBitWidthValue(*context))
                              : getFieldType(field->getType(), context, fieldName, parentName);
      if (fieldType == emptyStructType) {
        continue;
      }
      isVarlen |= isFieldVarlen(field->getType()) ||
                  (extractedRecords.find(fieldName) != extractedRecords.end() &&
                   !extractedRecords[fieldName].name.empty() && extractedRecords[fieldName].isVarlen);
      members.push_back({fieldType, fieldName, getCountedBy(field)});
    }
    if (members.empty()) { // Empty structs are not allowed in Syzlang.
      return emptyStructType;
    }
    extractedRecords[name] = {recordName, std::move(members), getStructAttr(recordDecl, context), recordDecl->isUnion(),
                              isVarlen};
    return recordName;
  }

  void print() {
    puts("type auto_todo intptr");
    for (const auto &inc : includes) {
      printf("include<%s>\n", inc.c_str());
    }
    for (const auto &flag : flags) {
      puts(flag.c_str());
    }
    for (auto &[_, decl] : extractedRecords) {
      for (auto &member : decl.members) {
        if (member.countedBy != UINT_MAX) {
          auto &type = decl.members[member.countedBy].type;
          type = "len[" + member.name + ", " + type + "]";
        }
      }
    }
    for (const auto &[_, decl] : extractedRecords) {
      decl.print();
    }
  }
};

class EnumMatcher : public MatchFinder::MatchCallback {
private:
  std::vector<EnumData> EnumDetails;

public:
  std::vector<EnumData> getEnumData() { return EnumDetails; }
  virtual void run(const MatchFinder::MatchResult &Result) override {
    const auto *enumValue = Result.Nodes.getNodeAs<ConstantExpr>("enum_value");
    if (!enumValue) {
      return;
    }
    const auto &name = enumValue->getEnumConstantDecl()->getNameAsString();
    const auto value = *enumValue->getAPValueResult().getInt().getRawData();
    const auto &path = std::filesystem::relative(
        Result.SourceManager->getFilename(enumValue->getEnumConstantDecl()->getSourceRange().getBegin()).str());
    EnumDetails.push_back({std::move(name), value, std::move(path)});
  }
};

class SyscallMatcher : public MatchFinder::MatchCallback {
private:
  const std::string swapIfReservedKeyword(const std::string &word) {
    if (word == "resource")
      return "rsrc";
    return word;
  }

public:
  void virtual run(const MatchFinder::MatchResult &Result) override {
    ASTContext *context = Result.Context;
    const auto *syscall = Result.Nodes.getNodeAs<FunctionDecl>("syscall");
    RecordExtractor recordExtractor(Result.SourceManager);

    const char *sep = "";
    const auto &name = syscall->getNameAsString().substr(9); // Remove "__do_sys_" prefix.
    emitInterface("SYSCALL", name);
    printf("%s(", name.c_str());
    for (const auto &param : syscall->parameters()) {
      const auto &type = recordExtractor.getFieldType(param->getType(), context, param->getNameAsString(), "", true);
      const auto &name = param->getNameAsString();
      printf("%s%s %s", sep, swapIfReservedKeyword(name).c_str(), type.c_str());
      sep = ", ";
    }
    printf(") (automatic)\n");
    recordExtractor.print();

    return;
  }
};

class NetlinkPolicyMatcher : public MatchFinder::MatchCallback {
private:
  // u8ToNlaEnum stores the Enum values to string conversions. This is later used to transfer types from an unnamed
  // integer to a readable form. E.g. 1 -> NLA_U8
  // See: https://elixir.bootlin.com/linux/v6.10/source/include/net/netlink.h#L172
  std::unordered_map<uint8_t, std::string> u8ToNlaEnum;
  void nlaEnum(const MatchFinder::MatchResult &Result) {
    const auto &num = Result.Nodes.getNodeAs<EnumDecl>("NLA_ENUM");
    if (!num || !u8ToNlaEnum.empty()) { // Don't evaluate the Enum twice
      return;
    }
    for (const auto &enumerator : num->enumerators()) {
      const auto &name = enumerator->getNameAsString();
      const auto val = uint8_t(enumerator->getValue().getZExtValue());
      u8ToNlaEnum[val] = name.substr(4); // Remove NLA_ prefix
    }
  }

  const std::string nlaArraySubtype(const std::string &name, const std::string &type, const size_t len,
                                    const std::string &typeOfLen) {
    if (!typeOfLen.empty()) {
      return len == 0 ? typeOfLen : makeArray(typeOfLen, 0, len);
    }
    switch (len) {
    case 0:
      return makeArray("int8");
    case 1:
    case 2:
    case 4:
    case 8:
      return intSubtype(name, IntType(len));
    default:
      if (contains(name, "IPV6")) {
        return "ipv6_addr";
      }
      if (type == "BINARY") {
        return makeArray("int8", 0, len);
      }
      return makeArray("int8", len);
    }
  }

  const std::string nlaToSyz(std::string name, const std::string &type, const size_t len,
                             const std::string &typeOfLen) {
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);
    // TODO:Gather information from other defined fields to better specify a type.
    // Loosely based on https://elixir.bootlin.com/linux/v6.10/source/lib/nlattr.c
    if (type == "U8" || type == "S8") {
      return intSubtype(name, INT_8);
    }
    if (type == "U16" || type == "S16") {
      return intSubtype(name, INT_16);
    }
    if (type == "U32" || type == "S32") {
      return intSubtype(name, INT_32);
    }
    if (type == "U64" || type == "S64" || type == "SINT" || type == "UINT" || type == "MSECS") {
      return intSubtype(name, INT_64);
    }
    if (type == "BINARY") {
      return nlaArraySubtype(name, type, len, typeOfLen);
    }
    if (type == "BE16") {
      return "int16be";
    }
    if (type == "BE32") {
      return "int32be";
    }
    if (type == "FLAG") {
      return "void";
    }
    if (type == "STRING") {
      return "stringnoz";
    }
    if (type == "NUL_STRING") {
      return stringSubtype(name);
    }
    if (type == "BITFIELD32") { // TODO:Extract valued values from NLA_POLICY_BITFIELD32 macro.
      return "int32";
    }
    if (type == "UNSPEC" || type == "NESTED" || type == "NESTED_ARRAY" || type == "REJECT" || type == "TYPE_MAX") {
      return nlaArraySubtype(name, type, len, typeOfLen);
    }
    fprintf(stderr, "Unsupported netlink type %s\n", type.c_str());
    exit(1);
  }

  RecordDecl *getStructFromSizeof(UnaryExprOrTypeTraitExpr *stmt) {
    if (!stmt || stmt->getKind() != clang::UETT_SizeOf) {
      return NULL;
    }
    return stmt->getTypeOfArgument()->getAsRecordDecl();
  }

  NetlinkType getStructAndLenFromBinary(BinaryOperator *stmt, ASTContext *context) {
    const auto &lhs = stmt->getLHS();
    const auto &rhs = stmt->getRHS();

    // NOTE: Usually happens in case of NESTED_POLICY which is not handled currently.
    // TODO: Handle NESTED_POLICY
    if (lhs->getStmtClass() == clang::Stmt::BinaryOperatorClass ||
        rhs->getStmtClass() == clang::Stmt::BinaryOperatorClass) {
      return {NULL, 0};
    }
    auto decl = getStructFromSizeof(llvm::dyn_cast<UnaryExprOrTypeTraitExpr>(lhs));
    Expr::EvalResult len;
    if (!decl) {
      decl = getStructFromSizeof(llvm::dyn_cast<UnaryExprOrTypeTraitExpr>(rhs));
      lhs->EvaluateAsConstantExpr(len, *context);
    } else {
      rhs->EvaluateAsConstantExpr(len, *context);
    }
    return NetlinkType{decl, len.Val.getInt().getExtValue()};
  }

  // Returns the struct type from .len field.
  // e.g. if .len = sizeof(struct x * LEN), returns the declaration of struct x and LEN
  NetlinkType getNetlinkStruct(clang::Expr *stmt, ASTContext *context) {
    stmt = stmt->IgnoreParens();
    Expr::EvalResult len;
    stmt->EvaluateAsConstantExpr(len, *context);
    switch (stmt->getStmtClass()) {
    case clang::Stmt::ImplicitValueInitExprClass:
      return NetlinkType{NULL, 0};
    case clang::Stmt::BinaryOperatorClass:
      return getStructAndLenFromBinary(llvm::dyn_cast<BinaryOperator>(stmt), context);
    case clang::Stmt::UnaryExprOrTypeTraitExprClass:
      return NetlinkType{getStructFromSizeof(llvm::dyn_cast<UnaryExprOrTypeTraitExpr>(stmt)), 0};
    case clang::Stmt::UnaryOperatorClass:
    case clang::Stmt::DeclRefExprClass:
    case clang::Stmt::CStyleCastExprClass:
    case clang::Stmt::IntegerLiteralClass:
      return NetlinkType{NULL, len.Val.getInt().getExtValue()};
    default:
      fprintf(stderr, "Unhandled .len case %s\n", stmt->getStmtClassName());
      exit(1);
    }
  }

  void netlink(const MatchFinder::MatchResult &Result) {
    ASTContext *context = Result.Context;
    const auto *netlinkDecl = Result.Nodes.getNodeAs<VarDecl>("netlink");
    if (!netlinkDecl) {
      return;
    }
    std::vector<std::vector<Expr *>> fields;

    const auto *init = netlinkDecl->getInit();
    if (!init) {
      return;
    }
    for (const auto &policy : *llvm::dyn_cast<InitListExpr>(init)) {
      fields.push_back(std::vector<Expr *>());
      for (const auto &member : policy->children()) {
        fields.back().push_back(llvm::dyn_cast<Expr>(member));
      }
    }

    EnumMatcher enumMatcher;
    MatchFinder enumFinder;
    enumFinder.addMatcher(
        decl(forEachDescendant(designatedInitExpr(optionally(has(constantExpr(has(declRefExpr())).bind("enum_value"))))
                                   .bind("designated_init"))),
        &enumMatcher);
    enumFinder.match(*netlinkDecl, *context); // get enum details from the current subtree (nla_policy[])

    auto unorderedEnumData = enumMatcher.getEnumData();
    if (unorderedEnumData.empty()) {
      return;
    }

    std::vector<EnumData> enumData(fields.size());
    for (auto &data : unorderedEnumData) {
      enumData.at(data.value) = std::move(data);
    }

    for (const auto &item : enumData) {
      if (item.file.empty()) {
        continue;
      }
      if (item.file.back() != 'h') { // only extract from "*.h" files
        return;
      }
      printf("include <%s>\n", item.file.c_str());
    }

    RecordExtractor recordExtractor(Result.SourceManager);
    printf("%s[\n", getPolicyName(Result, netlinkDecl)->c_str());
    for (size_t i = 0; i < fields.size(); ++i) {
      // The array could have an implicitly initialized policy (i.e. empty) or an unnamed attribute
      if (fields[i].empty() || enumData[i].name.empty()) {
        continue;
      }

      Expr::EvalResult evalResult;
      fields[i][0]->EvaluateAsConstantExpr(evalResult, *context); // This contains the NLA Enum type
      const auto &nlaEnum = u8ToNlaEnum[evalResult.Val.getInt().getZExtValue()];
      auto [structDecl, len] = getNetlinkStruct(fields[i][2]->IgnoreCasts(), context);
      std::string netlinkStruct;
      if (!structDecl) {
        fields[i][2]->EvaluateAsConstantExpr(evalResult, *context);
        len = evalResult.Val.getInt().getExtValue();
      } else {
        netlinkStruct = recordExtractor.extractRecord(structDecl, context, enumData[i].name);
      }
      printf("\t%s nlattr[%s, %s]\n", enumData[i].name.c_str(), enumData[i].name.c_str(),
             nlaToSyz(enumData[i].name, nlaEnum, len, netlinkStruct).c_str());
    }
    puts("] [varlen]");
    recordExtractor.print();
  }

  std::map<std::string, unsigned> genlFamilyMember;
  std::map<std::string, std::map<std::string, unsigned>> opsMember;

  std::optional<std::string> getPolicyName(const MatchFinder::MatchResult &Result, const ValueDecl *decl) {
    if (!decl) {
      return std::nullopt;
    }
    std::string filename =
        std::filesystem::path(
            Result.SourceManager->getFilename(decl->getCanonicalDecl()->getSourceRange().getBegin()).str())
            .filename()
            .stem()
            .string();
    std::replace(filename.begin(), filename.end(), '-', '_');
    return decl->getNameAsString() + "$auto_" + filename; // filename is added to address ambiguity
    // when multiple policies are named the same but have different definitions
  }

  std::vector<NetlinkOps> getOps(const MatchFinder::MatchResult &Result, const std::string opsName,
                                 const InitListExpr *init) {
    ASTContext *context = Result.Context;
    std::vector<NetlinkOps> ops;
    const auto n_ops = init->getInit(genlFamilyMember["n_" + opsName])->getIntegerConstantExpr(*context);
    const auto &opsRef = init->getInit(genlFamilyMember[opsName])->getAsBuiltinConstantDeclRef(*context);
    if (!n_ops || !opsRef) {
      return {};
    }
    const auto *opsDecl = llvm::dyn_cast<VarDecl>(opsRef);
    if (!opsDecl->getInit()) {
      // NOTE: This usually happens when the ops is defined as an extern variable
      // TODO: Extract extern variables
      return {};
    }
    const auto *opsInit = llvm::dyn_cast<InitListExpr>(opsDecl->getInit());
    for (const auto &field : opsInit->getInit(0)->getType()->getAsRecordDecl()->fields()) {
      opsMember[opsName][field->getNameAsString()] = field->getFieldIndex();
    }
    for (int i = 0; i < n_ops; ++i) {
      const auto &init = llvm::dyn_cast<InitListExpr>(opsInit->getInit(i));
      const auto &cmdInit = init->getInit(opsMember[opsName]["cmd"])->getEnumConstantDecl();
      if (!cmdInit) {
        continue;
      }
      const auto &cmd = cmdInit->getNameAsString();
      const ValueDecl *policyDecl = nullptr;
      if (opsName != "small_ops") {
        policyDecl = init->getInit(opsMember[opsName]["policy"])->getAsBuiltinConstantDeclRef(*context);
      }
      ops.push_back({std::move(cmd), getPolicyName(Result, policyDecl)});
    }
    return ops;
  }

  void genlFamily(const MatchFinder::MatchResult &Result) {
    ASTContext *context = Result.Context;
    const auto *genlFamilyInit = Result.Nodes.getNodeAs<InitListExpr>("genl_family_init");
    if (!genlFamilyInit) {
      return;
    }
    if (genlFamilyMember.empty()) {
      const auto *genlFamily = Result.Nodes.getNodeAs<RecordDecl>("genl_family");
      for (const auto &field : genlFamily->fields()) {
        genlFamilyMember[field->getNameAsString()] = field->getFieldIndex();
      }
    }

    auto name = llvm::dyn_cast<StringLiteral>(genlFamilyInit->getInit(genlFamilyMember["name"]))->getString().str();
    std::replace(name.begin(), name.end(), '.', '_'); // Illegal character.
    std::replace(name.begin(), name.end(), ' ', '_'); // Don't leave space in name.
    std::replace(name.begin(), name.end(), '-', '_'); // Not allowed in names
    const auto &globalPolicyName =
        genlFamilyInit->getInit(genlFamilyMember["policy"])->getAsBuiltinConstantDeclRef(*context);

    std::string familyPolicyName;
    if (globalPolicyName) {
      familyPolicyName = *getPolicyName(Result, globalPolicyName);
    }

    std::string msghdr = "msghdr_" + name + "_auto";
    bool printedCmds = false;
    for (const auto &opsType : {"ops", "small_ops", "split_ops"}) {
      for (auto &ops : getOps(Result, opsType, genlFamilyInit)) {
        const char *policyName;
        if (ops.policy) {
          policyName = ops.policy->c_str();
        } else if (globalPolicyName) {
          policyName = familyPolicyName.c_str();
        } else {
          continue;
        }
        emitInterface("NETLINK", ops.cmd);
        printf("sendmsg$auto_%s(fd sock_nl_generic, msg ptr[in, %s[%s, %s]], f flags[send_flags]) (automatic)\n",
               ops.cmd.c_str(), msghdr.c_str(), ops.cmd.c_str(), policyName);
        printedCmds = true;
      }
    }
    if (!printedCmds) { // Do not print resources and types if they're not used in any cmds
      return;
    }
    std::string resourceName = "genl_" + name + "_family_id_auto";
    printf("resource %s[int16]\n", resourceName.c_str());
    printf("type %s[CMD, POLICY] msghdr_netlink[netlink_msg_t[%s, genlmsghdr_t[CMD], POLICY]]\n", msghdr.c_str(),
           resourceName.c_str());
    printf("syz_genetlink_get_family_id$auto_%s(name ptr[in, string[\"%s\"]], fd sock_nl_generic) %s (automatic)\n",
           name.c_str(), name.c_str(), resourceName.c_str());
  }

public:
  virtual void run(const MatchFinder::MatchResult &Result) override {
    nlaEnum(Result); // NOTE: Must be executed first, as it generates maps that are used in the following methods.
    netlink(Result);
    genlFamily(Result);
  };
};

int main(int argc, const char **argv) {
  llvm::cl::OptionCategory SyzDeclExtractOptionCategory("syz-declextract options");
  auto ExpectedParser = clang::tooling::CommonOptionsParser::create(argc, argv, SyzDeclExtractOptionCategory);
  if (!ExpectedParser) {
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }

  clang::tooling::CommonOptionsParser &OptionsParser = ExpectedParser.get();
  clang::tooling::ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

  NetlinkPolicyMatcher NetlinkPolicyMatcher;
  SyscallMatcher SyscallMatcher;
  MatchFinder Finder;

  Finder.addMatcher(functionDecl(isExpandedFromMacro("SYSCALL_DEFINEx"), matchesName("__do_sys_.*")).bind("syscall"),
                    &SyscallMatcher);

  Finder.addMatcher(
      translationUnitDecl(
          hasDescendant(enumDecl(has(enumConstantDecl(hasName("__NLA_TYPE_MAX")))).bind("NLA_ENUM")),
          forEachDescendant(
              varDecl(hasType(constantArrayType(
                                  hasElementType(hasDeclaration(recordDecl(hasName("nla_policy")).bind("nla_policy"))))
                                  .bind("nla_policy_array")),
                      isDefinition())
                  .bind("netlink"))),
      &NetlinkPolicyMatcher);

  Finder.addMatcher(varDecl(hasType(recordDecl(hasName("genl_family")).bind("genl_family")),
                            has(initListExpr().bind("genl_family_init")))
                        .bind("genl_family_decl"),
                    &NetlinkPolicyMatcher);

  return Tool.run(clang::tooling::newFrontendActionFactory(&Finder).get());
}
