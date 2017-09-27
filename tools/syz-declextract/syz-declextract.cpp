// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This is a very rough prototype of an utility that extracts syscall descriptions from header files.
// It needs to extract struct/union descriptions, better analyze types,
// analyze pointer directions (in, out), figure out len types (usually marked with sal).
// The easiest way to build it is to build it as part of clang. Add the following lines to CMakeLists.txt:
//   +add_clang_executable(syz-declextract syz-declextract/syz-declextract.cpp)
//   +target_link_libraries(syz-declextract clangTooling)
// It was used to extract windows descriptions:
//   syz-declextract -extra-arg="--driver-mode=cl" -extra-arg="-I/path/to/windows/headers" Windows.h

#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Driver/Options.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"

using namespace clang;
using namespace clang::tooling;

std::string convertType(ASTContext &C, QualType T) {
  auto name = T.getAsString();
  if (name == "HANDLE")
    return name;
  if (T->isIntegralOrEnumerationType()) {
    int size = C.getTypeSize(T);
    char buf[10];
    sprintf(buf, "int%d", size);
    return buf;
  }
  if (T->isVoidPointerType()) {
    return "ptr[inout, array[int8]]";
  }
  if (T->isPointerType()) {
    auto inner = convertType(C, T->getPointeeType());
    if (inner == "")
      return "ptr[inout, array[int8]]";
    char buf[1024];
    sprintf(buf, "ptr[inout, %s]", inner.c_str());
    return buf;
  }
  return "intptr";
}

class DeclExtractCallVisitor : public RecursiveASTVisitor<DeclExtractCallVisitor> {
 public:
  explicit DeclExtractCallVisitor(ASTContext *Context)
      : Context(*Context) {}

  bool VisitFunctionDecl(const FunctionDecl *D) {
    if (D->doesThisDeclarationHaveABody())
      return true;
    // TODO(dvyukov): need to select only stdcall (WINAPI) functions.
    // But the following 2 approaches do not work.
    if (false) {
      if (auto *FPT = D->getType()->getAs<FunctionProtoType>()) {
        if (FPT->getExtInfo().getCC() != CC_X86StdCall)
          return true;
      }
    }
    if (false) {
      if (!D->hasAttr<StdCallAttr>())
        return true;
    }
    // Tons of functions are bulk ignored below because they cause
    // static/dynamic link failures, reboot machine, etc.
    auto fn = D->getNameInfo().getAsString();
    if (fn.empty()) return true;
    if (*fn.rbegin() == 'W') return true; // Unicode versions.
    const char *ignore_prefixes[] {
      "_",
      "Rtl",
      "IBind",
      "Ndr",
      "NDR",
      "SCard",
    };
    for (auto prefix: ignore_prefixes) {
      if (strncmp(fn.c_str(), prefix, strlen(prefix)) == 0) return true;
    }
    const char *ignore_functions[] {
      "IEnum",
      "IStream",
      "IType",
      "IService",
      "IProperty",
      "ISequential",
      "IDispatch",
      "I_RPC",
      "I_Rpc",
      "CLEANLOCAL",
      "WinMain",
      "PropertySheet",
      "LookupAccountNameLocalA",
      "LookupAccountSidLocalA",
      "WTSGetServiceSessionId",
      "WTSIsServerContainer",
      "GetDisplayAutoRotationPreferencesByProcessId",
      "LoadStringByReference",
      "IdnToNameprepUnicode",
      "VerFindFileA",
      "VerInstallFileA",
      "GetFileVersionInfoSizeA",
      "GetFileVersionInfoA",
      "GetFileVersionInfoSizeExA",
      "GetFileVersionInfoExA",
      "VerQueryValueA",
      "sndOpenSound",
      "Netbios",
      "RpcBindingGetTrainingContextHandle",
      "RpcAsyncCleanupThread",
      "ShellMessageBoxA",
      "SHEnumerateUnreadMailAccountsA",
      "SHGetUnreadMailCountA",
      "SHSetUnreadMailCountA",
      "GetEncSChannel",
      "CryptExportPKCS8Ex",
      "FindCertsByIssuer",
      "CryptCancelAsyncRetrieval",
      "CryptGetTimeValidObject",
      "CryptFlushTimeValidObject",
      "CryptProtectDataNoUI",
      "CryptUnprotectDataNoUI",
      "NsServerBindSearch",
      "NsClientBindSearch",
      "NsClientBindDone",
      "GetOpenCardNameA",
      "SubscribeServiceChangeNotifications",
      "UnsubscribeServiceChangeNotifications",
      "GetThreadDescription",
      "SetThreadDescription",
      "DialogControlDpi",
      "SetDialogDpiChangeBehavior",
      "GetDialogDpiChangeBehavior",
      "RpcServer",
      "DecodePointer",
      "DecodeRemotePointer",
      "DecodeSystemPointer",
      "EncodePointer",
      "EncodeRemotePointer",
      "EncodeSystemPointer",
      "UnmapViewOfFile2",
      "MapViewOfFileNuma2",
      "DeriveCapabilitySidsFromName",
      "QueryAuxiliaryCounterFrequency",
      "ConvertPerformanceCounterToAuxiliaryCounter",
      "ConvertAuxiliaryCounterToPerformanceCounter",
      "FreePropVariantArray",
      "PropVariantCopy",
      "PropVariantClear",
      "InitiateShutdown",
      "ExitWindowsEx",
      "LockWorkStation",
      "InitiateSystemShutdown",
      "InitiateSystemShutdownEx",
      "shutdown",
    };
    for (auto func: ignore_functions) {
      if (strstr(fn.c_str(), func)) return true;
    }
    // These are already described:
    const char *ignore_exact[] {
      "CreateFileA",
      "CloseHandle",
      "VirtualAlloc",
    };
    for (auto func: ignore_exact) {
      if (strcmp(fn.c_str(), func) == 0) return true;
    }
    const char *ignore_files[] {
      "/um/ole",
      "htiface.h",
      "objbase.h",
      "HLink.h",
      "urlmon.h",
      "HlGuids.h",
      "unknwn.h",
      "unknwnbase.h",
      "coguid.h",
      "MsHtmHst.h",
      "msime.h",
      "ComSvcs.h",
      "combaseapi.h",
      "WbemGlue.h",
      "OCIdl.h",
      "mfapi.h",
      "CompPkgSup.h",
      "ole2.h",
      "Ole2.h",
      "oleidl.h",
      "ObjIdl.h",
      "WabDefs.h",
      "objidl.h",
    };
    auto src = D->getSourceRange().getBegin().printToString(Context.getSourceManager());
    if (strstr(src.c_str(), "/um/") == 0) return true;
    for (auto file: ignore_files) {
      if (strstr(src.c_str(), file)) return true;
    }
    for (const ParmVarDecl *P : D->parameters()) {
      auto typ = convertType(Context, P->getType());
      if (typ == "") {
        llvm::outs() << D->getNameInfo().getAsString() << ": UNKNOWN TYPE: " <<
            QualType(P->getType()).getAsString() << "\n";
        return true;
      }
    }
    if (Generated[D->getNameInfo().getAsString()])
      return true;
    Generated[D->getNameInfo().getAsString()] = true;

    llvm::outs() << D->getNameInfo().getAsString() << "(";
    int i = 0;
    for (const ParmVarDecl *P : D->parameters()) {
      if (i)
        llvm::outs() << ", ";
      auto name = P->getNameAsString();
      if (name == "") {
        char buf[10];
        sprintf(buf, "arg%d", i);
        name = buf;
      }
      llvm::outs() << name << " " << convertType(Context, P->getType());
      i++;
      if (i == 9)
        break;
    }
    llvm::outs() << ")";
    auto ret = convertType(Context, D->getReturnType());
    if (ret == "HANDLE")
      llvm::outs() << " " << ret;
    llvm::outs() << "\n";
    return true;
  }

 private:
  ASTContext &Context;
  std::map<std::string, bool> Generated;
};

class DeclExtractCallConsumer : public clang::ASTConsumer {
 public:
  explicit DeclExtractCallConsumer(ASTContext *Context)
      : Visitor(Context) {}

  virtual void HandleTranslationUnit(clang::ASTContext &Context) {
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
  }

 private:
  DeclExtractCallVisitor Visitor;
};

class DeclExtractCallAction : public clang::ASTFrontendAction {
 public:
  DeclExtractCallAction() {}

  virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
      clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
    return std::unique_ptr<clang::ASTConsumer>(
        new DeclExtractCallConsumer(&Compiler.getASTContext()));
  }
};

static llvm::cl::OptionCategory MyToolCategory("my-tool options");

int main(int argc, const char **argv) {
  CommonOptionsParser OptionsParser(argc, argv, MyToolCategory);
  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());
  return Tool.run(newFrontendActionFactory<DeclExtractCallAction>().get());
}
