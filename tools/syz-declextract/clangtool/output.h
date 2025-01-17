// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef SYZ_DECLEXTRACT_OUTPUT_H
#define SYZ_DECLEXTRACT_OUTPUT_H

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

const char* const AccessUnknown = "";
const char* const AccessUser = "user";
const char* const AccessNsAdmin = "ns_admin";
const char* const AccessAdmin = "admin";

struct IntType;
struct PtrType;
struct ArrType;
struct BufferType;

struct FieldType {
  std::unique_ptr<IntType> Int;
  std::unique_ptr<PtrType> Ptr;
  std::unique_ptr<ArrType> Array;
  std::unique_ptr<BufferType> Buffer;
  std::unique_ptr<std::string> Struct;

  FieldType() = default;
  FieldType(IntType&& Typ) : Int(std::make_unique<IntType>(std::move(Typ))) {}
  FieldType(PtrType&& Typ) : Ptr(std::make_unique<PtrType>(std::move(Typ))) {}
  FieldType(ArrType&& Typ) : Array(std::make_unique<ArrType>(std::move(Typ))) {}
  FieldType(BufferType&& Typ) : Buffer(std::make_unique<BufferType>(std::move(Typ))) {}
  FieldType(const std::string& Typ) : Struct(std::make_unique<std::string>(std::move(Typ))) {}
};

struct IntType {
  int ByteSize = 0;
  int64_t MinValue = 0;
  int64_t MaxValue = 0;
  bool IsConst = false;
  std::string Name;
  std::string Base;
  std::string Enum;
};

struct PtrType {
  FieldType Elem;
  bool IsConst = false;
};

struct ArrType {
  FieldType Elem;
  int MinSize = 0;
  int MaxSize = 0;
  int Align = 0;
  bool IsConstSize = false;
};

struct BufferType {
  int MinSize = 0;
  int MaxSize = 0;
  bool IsString = false;
  bool IsNonTerminated = false;
};

struct ConstInfo {
  std::string Name;
  std::string Filename;
  int64_t Value;
};

struct Field {
  std::string Name;
  bool IsAnonymous = false;
  int BitWidth = 0;
  int CountedBy = -1;
  FieldType Type;
};

struct Struct {
  std::string Name;
  int ByteSize = 0;
  int Align = 0;
  bool IsUnion = false;
  bool IsPacked = false;
  int AlignAttr = 0;
  std::vector<Field> Fields;
};

struct Enum {
  std::string Name;
  std::vector<std::string> Values;
};

struct Ioctl {
  std::string Name;
  FieldType Type;
};

struct FileOps {
  std::string Name;
  std::string Open;
  std::string Read;
  std::string Write;
  std::string Mmap;
  std::string Ioctl;
};

struct EntityReturn {
  std::string Func;
};

struct EntityArgument {
  std::string Func;
  unsigned Arg;
};

struct EntityField {
  std::string Struct;
  std::string Field;
};

struct EntityLocal {
  std::string Name;
};

struct EntityGlobalAddr {
  std::string Name;
};

struct EntityResource {
  std::string Type;
  std::string SubType;
};

struct TypingEntity {
  std::unique_ptr<EntityReturn> Return;
  std::unique_ptr<EntityArgument> Argument;
  std::unique_ptr<EntityField> Field;
  std::unique_ptr<EntityLocal> Local;
  std::unique_ptr<EntityGlobalAddr> GlobalAddr;
  std::unique_ptr<EntityResource> Resource;

  TypingEntity() = default;
  TypingEntity(EntityReturn&& E) : Return(std::make_unique<EntityReturn>(std::move(E))) {}
  TypingEntity(EntityArgument&& E) : Argument(std::make_unique<EntityArgument>(std::move(E))) {}
  TypingEntity(EntityField&& E) : Field(std::make_unique<EntityField>(std::move(E))) {}
  TypingEntity(EntityLocal&& E) : Local(std::make_unique<EntityLocal>(std::move(E))) {}
  TypingEntity(EntityGlobalAddr&& E) : GlobalAddr(std::make_unique<EntityGlobalAddr>(std::move(E))) {}
  TypingEntity(EntityResource&& E) : Resource(std::make_unique<EntityResource>(std::move(E))) {}
};

struct TypingFact {
  TypingEntity Src;
  TypingEntity Dst;
};

struct FunctionScope {
  int Arg = 0;
  int LOC = 0;
  std::vector<std::string> Values;
  std::vector<std::string> Calls;
  std::vector<TypingFact> Facts;
};

struct Function {
  std::string Name;
  std::string File;
  bool IsStatic = false;
  std::vector<FunctionScope> Scopes;
};

struct Syscall {
  std::string Func;
  std::vector<Field> Args;
};

struct IouringOp {
  std::string Name;
  std::string Func;
};

struct NetlinkOp {
  std::string Name;
  std::string Func;
  const char* Access = nullptr;
  std::string Policy;
};

struct NetlinkFamily {
  std::string Name;
  std::vector<NetlinkOp> Ops;
};

struct NetlinkAttr {
  std::string Name;
  std::string Kind;
  int MaxSize = 0;
  std::string NestedPolicy;
  std::unique_ptr<FieldType> Elem;
};

struct NetlinkPolicy {
  std::string Name;
  std::vector<NetlinkAttr> Attrs;
};

inline void print(JSONPrinter& Printer, const ConstInfo& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("filename", V.Filename);
  Printer.Field("value", V.Value, true);
}

inline void print(JSONPrinter& Printer, const Field& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("is_anonymous", V.IsAnonymous);
  Printer.Field("bit_width", V.BitWidth);
  Printer.Field("counted_by", V.CountedBy);
  Printer.Field("type", V.Type, true);
}

inline void print(JSONPrinter& Printer, const Struct& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("align", V.Align);
  Printer.Field("byte_size", V.ByteSize);
  Printer.Field("is_union", V.IsUnion);
  Printer.Field("is_packed", V.IsPacked);
  Printer.Field("align_attr", V.AlignAttr);
  Printer.Field("fields", V.Fields, true);
}

inline void print(JSONPrinter& Printer, const Enum& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("values", V.Values, true);
}

inline void print(JSONPrinter& Printer, const FieldType& V) {
  JSONPrinter::Scope Scope(Printer);
  if (V.Int)
    Printer.Field("int", *V.Int, true);
  else if (V.Ptr)
    Printer.Field("ptr", *V.Ptr, true);
  else if (V.Array)
    Printer.Field("array", *V.Array, true);
  else if (V.Buffer)
    Printer.Field("buffer", *V.Buffer, true);
  else
    Printer.Field("struct", *V.Struct, true);
}

inline void print(JSONPrinter& Printer, const IntType& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("byte_size", V.ByteSize);
  Printer.Field("min_value", V.MinValue);
  Printer.Field("max_value", V.MaxValue);
  Printer.Field("is_const", V.IsConst);
  Printer.Field("name", V.Name);
  Printer.Field("base", V.Base);
  Printer.Field("enum", V.Enum, true);
}

inline void print(JSONPrinter& Printer, const PtrType& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("elem", V.Elem);
  Printer.Field("is_const", V.IsConst, true);
}

inline void print(JSONPrinter& Printer, const ArrType& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("elem", V.Elem);
  Printer.Field("min_size", V.MinSize);
  Printer.Field("max_size", V.MaxSize);
  Printer.Field("align", V.Align);
  Printer.Field("is_const_size", V.IsConstSize, true);
}

inline void print(JSONPrinter& Printer, const BufferType& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("min_size", V.MinSize);
  Printer.Field("max_size", V.MaxSize);
  Printer.Field("is_string", V.IsString);
  Printer.Field("is_non_terminated", V.IsNonTerminated, true);
}

inline void print(JSONPrinter& Printer, const Ioctl& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("type", V.Type, true);
}

inline void print(JSONPrinter& Printer, const FileOps& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("open", V.Open);
  Printer.Field("read", V.Read);
  Printer.Field("write", V.Write);
  Printer.Field("mmap", V.Mmap);
  Printer.Field("ioctl", V.Ioctl, true);
}

inline void print(JSONPrinter& Printer, const EntityReturn& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("func", V.Func, true);
}

inline void print(JSONPrinter& Printer, const EntityArgument& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("func", V.Func);
  Printer.Field("arg", V.Arg, true);
}

inline void print(JSONPrinter& Printer, const EntityField& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("struct", V.Struct);
  Printer.Field("field", V.Field, true);
}

inline void print(JSONPrinter& Printer, const EntityLocal& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name, true);
}

inline void print(JSONPrinter& Printer, const EntityGlobalAddr& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name, true);
}

inline void print(JSONPrinter& Printer, const EntityResource& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("type", V.Type);
  Printer.Field("subtype", V.SubType, true);
}

inline void print(JSONPrinter& Printer, const TypingEntity& V) {
  JSONPrinter::Scope Scope(Printer);
  if (V.Return)
    Printer.Field("return", *V.Return, true);
  else if (V.Argument)
    Printer.Field("argument", *V.Argument, true);
  else if (V.Field)
    Printer.Field("field", *V.Field, true);
  else if (V.Local)
    Printer.Field("local", *V.Local, true);
  else if (V.GlobalAddr)
    Printer.Field("global_addr", *V.GlobalAddr, true);
  else
    Printer.Field("resource", *V.Resource, true);
}

inline void print(JSONPrinter& Printer, const TypingFact& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("src", V.Src);
  Printer.Field("dst", V.Dst, true);
}

inline void print(JSONPrinter& Printer, const FunctionScope& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("arg", V.Arg);
  Printer.Field("values", V.Values);
  Printer.Field("loc", V.LOC);
  Printer.Field("calls", V.Calls);
  Printer.Field("facts", V.Facts, true);
}

inline void print(JSONPrinter& Printer, const Function& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("file", V.File);
  Printer.Field("is_static", V.IsStatic);
  Printer.Field("scopes", V.Scopes, true);
}

inline void print(JSONPrinter& Printer, const Syscall& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("func", V.Func);
  Printer.Field("args", V.Args, true);
}

inline void print(JSONPrinter& Printer, const IouringOp& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("func", V.Func, true);
}

inline void print(JSONPrinter& Printer, const NetlinkOp& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("func", V.Func);
  Printer.Field("access", V.Access);
  Printer.Field("policy", V.Policy, true);
}

inline void print(JSONPrinter& Printer, const NetlinkFamily& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("ops", V.Ops, true);
}

inline void print(JSONPrinter& Printer, const NetlinkAttr& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("kind", V.Kind);
  Printer.Field("max_size", V.MaxSize);
  Printer.Field("nested_policy", V.NestedPolicy);
  Printer.Field("elem", V.Elem, true);
}

inline void print(JSONPrinter& Printer, const NetlinkPolicy& V) {
  JSONPrinter::Scope Scope(Printer);
  Printer.Field("name", V.Name);
  Printer.Field("attrs", V.Attrs, true);
}

// This type is used when we can't figure out the right type, but need some type to use.
inline FieldType TodoType() {
  return IntType{
      .ByteSize = 1,
      .Name = "TODO",
      .Base = "long",
  };
}

class Output {
public:
  void emit(Function&& V) { Functions.push_back(std::move(V)); }
  void emit(ConstInfo&& V) { Consts.push_back(std::move(V)); }
  void emit(Struct&& V) { Structs.push_back(std::move(V)); }
  void emit(Enum&& V) { Enums.push_back(std::move(V)); }
  void emit(Syscall&& V) { Syscalls.push_back(std::move(V)); }
  void emit(FileOps&& V) { FileOps.push_back(std::move(V)); }
  void emit(Ioctl&& V) { Ioctls.push_back(std::move(V)); }
  void emit(IouringOp&& V) { IouringOps.push_back(std::move(V)); }
  void emit(NetlinkFamily&& V) { NetlinkFamilies.push_back(std::move(V)); }
  void emit(NetlinkPolicy&& V) { NetlinkPolicies.push_back(std::move(V)); }

  void print() const {
    JSONPrinter Printer;
    Printer.Field("functions", Functions);
    Printer.Field("consts", Consts);
    Printer.Field("enums", Enums);
    Printer.Field("structs", Structs);
    Printer.Field("syscalls", Syscalls);
    Printer.Field("file_ops", FileOps);
    Printer.Field("ioctls", Ioctls);
    Printer.Field("iouring_ops", IouringOps);
    Printer.Field("netlink_families", NetlinkFamilies);
    Printer.Field("netlink_policies", NetlinkPolicies, true);
  }

private:
  std::vector<Function> Functions;
  std::vector<ConstInfo> Consts;
  std::vector<Enum> Enums;
  std::vector<Struct> Structs;
  std::vector<Syscall> Syscalls;
  std::vector<FileOps> FileOps;
  std::vector<Ioctl> Ioctls;
  std::vector<IouringOp> IouringOps;
  std::vector<NetlinkFamily> NetlinkFamilies;
  std::vector<NetlinkPolicy> NetlinkPolicies;
};

#endif
