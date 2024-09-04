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
#include "clang/Lex/Lexer.h"
#include "clang/Sema/Ownership.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <stdio.h>
#include <string>
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

bool endsWith(const std::string_view &str, const std::string_view end) {
  size_t substrBegin = str.find(end);
  return substrBegin != std::string::npos && str.substr(substrBegin) == end;
}

bool beginsWith(const std::string_view &str, const std::string_view begin) {
  size_t substrBegin = str.find(begin);
  return substrBegin != std::string::npos && str.substr(0, begin.size()) == begin;
}

bool contains(const std::string_view &str, const std::string_view sub) { return str.find(sub) != std::string::npos; }

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
  const std::string getSyzType(const std::string &type) { return "intptr"; }
  const std::string swapIfReservedKeyword(const std::string &word) {
    if (word == "resource")
      return "rsrc";
    return word;
  }
  unsigned int nameIndex{0}, argcIndex{0}, typesIndex{0}, argsIndex{0};
  bool isInitialized{false};
  llvm::ArrayRef<Expr *> getVarDeclInitList(Expr *init, const ASTContext *context) {
    return llvm::dyn_cast<InitListExpr>(
               llvm::dyn_cast<VarDecl>(init->getAsBuiltinConstantDeclRef(*context)->getUnderlyingDecl())->getInit())
        ->inits();
  }

  std::vector<Param> getArgs(Expr *types, Expr *names, int argc, ASTContext *context) {
    std::vector<Param> args(argc);
    if (argc) {
      int i = 0;
      for (const auto *type : getVarDeclInitList(types, context)) { // get parameter types.
        args[i++].type = std::move(*type->tryEvaluateString(*context));
      }

      i = 0;
      for (const auto *name : getVarDeclInitList(names, context)) { // get parameter names
        args[i++].name = std::move(*name->tryEvaluateString(*context));
      }
    }
    return args;
  }

public:
  void virtual run(const MatchFinder::MatchResult &Result) override {
    ASTContext *context = Result.Context;
    const auto *initList = Result.Nodes.getNodeAs<InitListExpr>("initList");
    if (!isInitialized) {
      argcIndex = Result.Nodes.getNodeAs<FieldDecl>("nb_args")->getFieldIndex();
      typesIndex = Result.Nodes.getNodeAs<FieldDecl>("types")->getFieldIndex();
      argsIndex = Result.Nodes.getNodeAs<FieldDecl>("args")->getFieldIndex();
      nameIndex = Result.Nodes.getNodeAs<FieldDecl>("name")->getFieldIndex();
    }
    // values contains the initializer list for the struct `syscall_metadata`
    auto values = initList->inits();
    int argc = values[argcIndex]->getIntegerConstantExpr(*context)->getSExtValue();

    printf("%s$auto(", values[nameIndex]->tryEvaluateString(*context)->c_str() + 4); // name
    const char *sep = "";
    for (const auto &arg : getArgs(values[typesIndex], values[argsIndex], argc, context)) {
      printf("%s%s %s", sep, swapIfReservedKeyword(arg.name).c_str(), getSyzType(arg.type).c_str());
      sep = ", ";
    }
    puts(") (automatic)");
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

  const std::string nlaInt8Subtype(const std::string &name) {
    if (endsWith(name, "ENABLED") || endsWith(name, "ENABLE")) {
      return "bool8";
    }
    return "int8";
  }
  const std::string nlaInt16Subtype(const std::string &name) {
    if (contains(name, "PORT")) {
      return "sock_port";
    }
    return "int16";
  }
  const std::string nlaInt32Subtype(const std::string &name) {
    if (contains(name, "IPV4")) {
      return "ipv4_addr";
    }
    if (endsWith(name, "FD")) {
      if (endsWith(name, "NS_FD")) {
        return "fd_namespace";
      }
      return "fd";
    }
    if (contains(name, "IFINDEX")) {
      return "ifindex";
    }
    if (endsWith(name, "ENABLED") || endsWith(name, "ENABLE")) {
      return "bool32";
    }
    return "int32";
  }

  const std::string nlaStringSubtype(const std::string &name) {
    if (contains(name, "IFNAME") || endsWith(name, "DEV_NAME")) {
      return "devname";
    }
    return "string";
  }

  const std::string nlaInt64Subtype() { return "int64"; }

  const std::string nlaArraySubtype(const std::string &name, const std::string &type, const size_t len) {
    switch (len) {
    case 0:
      return "array[int8]";
    case 1:
      return nlaInt8Subtype(name);
    case 2:
      return nlaInt16Subtype(name);
    case 4:
      return nlaInt32Subtype(name);
    case 8:
      return nlaInt64Subtype();
    default:
      if (contains(name, "IPV6")) {
        return "ipv6_addr";
      }
      if (type == "BINARY") {
        return "array[int8, 0:" + std::to_string(len) + "]";
      }
      return "array[int8, " + std::to_string(len) + "]";
    }
  }

  const std::string nlaToSyz(const std::string &name, const std::string &type, const size_t len) {
    // TODO:Gather information from other defined fields to better specify a type.
    // Loosely based on https://elixir.bootlin.com/linux/v6.10/source/lib/nlattr.c
    if (type == "U8" || type == "S8") {
      return nlaInt8Subtype(name);
    }
    if (type == "U16" || type == "S16") {
      return nlaInt16Subtype(name);
    }
    if (type == "BINARY") {
      return nlaArraySubtype(name, type, len);
    }
    if (type == "BE16") {
      return "int16be";
    }
    if (type == "U32" || type == "S32") {
      return nlaInt32Subtype(name);
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
      return nlaStringSubtype(name);
    }
    if (type == "BITFIELD32") { // TODO:Extract valued values from NLA_POLICY_BITFIELD32 macro.
      return "int32";
    }
    if (type == "UNSPEC" || type == "NESTED" || type == "NESTED_ARRAY" || type == "REJECT" || type == "TYPE_MAX") {
      return nlaArraySubtype(name, type, len);
    }
    fprintf(stderr, "Unsupported netlink type %s\n", type.c_str());
    exit(1);
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
      printf("include<%s>\n", item.file.c_str());
    }

    printf("%s[\n", getPolicyName(Result, netlinkDecl)->c_str());
    for (size_t i = 0; i < fields.size(); ++i) {
      // The array could have an implicitly initialized policy (i.e. empty) or an unnamed attribute
      if (fields[i].empty() || enumData[i].name.empty()) {
        continue;
      }
      Expr::EvalResult type; // value for the field type
      Expr::EvalResult len;  // value for the field type
      fields[i][0]->EvaluateAsConstantExpr(type, *context);
      fields[i][2]->EvaluateAsConstantExpr(len, *context);
      printf("\t%s nlattr[%s, %s]\n", enumData[i].name.c_str(), enumData[i].name.c_str(),
             nlaToSyz(enumData[i].name, u8ToNlaEnum[type.Val.getInt().getZExtValue()], len.Val.getInt().getZExtValue())
                 .c_str());
    }
    puts("] [varlen]");
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
  llvm::cl::OptionCategory SyzDeclExtractOptionCategory("SyzDeclExtract options");
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

  Finder.addMatcher(
      varDecl(
          isExpandedFromMacro("SYSCALL_METADATA"),
          hasType(recordDecl(hasName("syscall_metadata"), has(fieldDecl(hasName("nb_args")).bind("nb_args")),
                             has(fieldDecl(hasName("types")).bind("types")),
                             has(fieldDecl(hasName("name")).bind("name")), has(fieldDecl(hasName("args")).bind("args")))
                      .bind("syscall_metadata")),
          has(initListExpr().bind("initList")))
          .bind("syscall"),
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
