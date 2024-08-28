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
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <stdio.h>
#include <string>
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

    int argc = *values[2]->getIntegerConstantExpr(*context)->getRawData();

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

    printf("%s$auto(", values[0]->tryEvaluateString(*context)->c_str() + 4); // name
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
      printf("\t%s nlattr[%s, %s]\n", enumData[i].name.c_str(), enumData[i].name.c_str(),
             nlaToSyz(fields[i][0]).c_str());
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
    const auto *genlFamily = Result.Nodes.getNodeAs<RecordDecl>("genl_family");
    if (!genlFamily) {
      return;
    }
    for (const auto &field : genlFamily->fields()) {
      genlFamilyMember[field->getNameAsString()] = field->getFieldIndex();
    }
    const auto *genlFamilyInit = Result.Nodes.getNodeAs<InitListExpr>("genl_family_init");
    if (!genlFamilyInit) {
      return;
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
    syscall(Result);
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
  Finder.addMatcher(varDecl(hasType(recordDecl(hasName("genl_family")).bind("genl_family")),
                            has(initListExpr().bind("genl_family_init")))
                        .bind("genl_family_decl"),
                    &Printer);

  return Tool.run(clang::tooling::newFrontendActionFactory(&Finder).get());
}
