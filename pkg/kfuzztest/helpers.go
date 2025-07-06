package kfuzztest

// Below are some helpers that are no longer compatible but that are being
// left in during WIP implementation as it might be handy to have them soon

// func GetKFuzzTestProgInfo(vmlinuxPath string) ([]*prog.Syscall, []prog.Type, error) {
// 	var (
// 		syscalls []*prog.Syscall
// 		types    []prog.Type
// 	)
// 	// create a new dwarf parser for the vmlinux binary
// 	dwarfParser, err := NewDwarfParser(vmlinuxPath)
// 	if err != nil {
// 		return syscalls, types, err
// 	}
//
// 	// get all of the relevant test cases - function names and argument types
// 	testCases, err := dwarfParser.LocateKFuzzTestCases()
// 	if err != nil {
// 		return syscalls, types, err
// 	}
//
// 	fmt.Printf("dumping test cases\n")
// 	for _, testCase := range testCases {
// 		fmt.Printf("%s -> %s\n", testCase.testName, testCase.argType)
// 	}
//
// 	// get the input type for each of the test cases
// 	structNameToDwarfType, err := dwarfParser.locateKFuzzInputStructs(testCases)
// 	if err != nil {
// 		return syscalls, types, err
// 	}
//
// 	fmt.Printf("dumping located types...\n")
// 	for name := range structNameToDwarfType {
// 		fmt.Printf("\t%s\n", name)
// 	}
//
// 	// build the dag of all of the structures that we found
// 	for _, structType := range structNameToDwarfType {
// 		err = dwarfParser.dwarfBuildStructDag(structType)
// 		if err != nil {
// 			return syscalls, types, err
// 		}
// 	}
//
// 	// gives us the structure types parsed from the program starting at the
// 	// leaves
// 	sortedTypes := dwarfParser.topologicalSortDag()
// 	fmt.Printf("dumping sorted...\n")
// 	for _, tpe := range sortedTypes {
// 		fmt.Printf("\t%s\n", tpe.String())
// 	}
//
// 	typeMap := buildTypesMap(sortedTypes)
//
// 	// create the syscalls that we return to the user
// 	types = []prog.Type{}
// 	syscalls = []*prog.Syscall{}
// 	for _, testCase := range testCases {
// 		syscall, createdTypes := buildSyscall(typeMap, testCase)
// 		syscalls = append(syscalls, syscall)
// 		types = append(types, createdTypes...)
// 	}
// 	for _, t := range typeMap {
// 		types = append(types, t) // add the mapped types to types
// 	}
//
// 	fmt.Printf("dumping all syscalls that were discovered\n")
// 	for _, syscall := range syscalls {
// 		fmt.Printf("\t%s with type %s\n", syscall.Name, syscall.Args[1].Type.String())
// 	}
// 	fmt.Printf("dumping all types that were discovered\n")
// 	for _, tpe := range types {
// 		fmt.Printf("\t%s\n", tpe.String())
// 	}
//
// 	return syscalls, types, err
// }
//
// func buildSyscall(typeMap map[string]prog.Type, testCase kFuzzTestCase) (*prog.Syscall, []prog.Type) {
// 	nameStrType := &prog.BufferType{
// 		TypeCommon: prog.TypeCommon{TypeName: "string", IsVarlen: true},
// 		Kind:       prog.BufferString,
// 		// This sets the constant value for the string.
// 		Values: []string{testCase.testName},
// 	}
// 	namePtrType := &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{TypeName: "ptr", TypeSize: 8},
// 		Elem:       nameStrType,
// 		ElemDir:    prog.DirIn,
// 	}
//
// 	elem := typeMap[testCase.argType]
// 	fmt.Printf("elem = %v, key = %s\n", elem, testCase.argType)
//
// 	dataType := &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{TypeName: "ptr", TypeSize: 8},
// 		Elem:       typeMap[testCase.argType],
// 		ElemDir:    prog.DirIn,
// 	}
// 	lenType := &prog.LenType{
// 		IntTypeCommon: prog.IntTypeCommon{
// 			TypeCommon: prog.TypeCommon{TypeName: "int64", TypeSize: 8},
// 		},
// 		// This Path links this field to the 'data' argument.
// 		Path: []string{"data"},
// 	}
// 	out := &prog.Syscall{
// 		ID:       0, // this must be updated by the caller
// 		NR:       0, // this is zero for pseudo-syscalls
// 		Name:     "syz_kfuzztest_run$" + testCase.testName,
// 		CallName: "syz_kfuzztest_run",
// 		Args: []prog.Field{
// 			{Name: "name", Type: namePtrType},
// 			{Name: "data", Type: dataType},
// 			{Name: "len", Type: lenType},
// 		},
// 		Ret: nil,
// 	}
// 	return out, []prog.Type{nameStrType, namePtrType, dataType, lenType}
// }
//
// takes as input a sorted slice of struct types (topologically sorted) and
// outputs a map of `prog.Type`s (name to type). We want a map so that we can
// map the function input type names to the related prog.type
// func buildTypesMap(inputTypes []*dwarf.StructType) map[string]prog.Type {
// 	typeMap := make(map[string]prog.Type)
//
// 	for _, tpe := range inputTypes {
// 		_ = buildType(tpe, &typeMap)
// 	}
//
// 	return typeMap
// }
//
// func buildType(dwarfType *dwarf.StructType, typeMap *map[string]prog.Type) prog.Type {
// 	outputType := &prog.StructType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: strings.TrimPrefix("struct ", dwarfType.StructName),
// 		},
// 	}
// 	fmt.Printf("visiting type %s, typename = %s\n", dwarfType.StructName, outputType.TypeName)
//
// 	hasVarlenField := false
// 	for _, field := range dwarfType.Field {
// 		var fieldType prog.Type
// 		fmt.Printf("field %s is of type %s\n", field.Name, field.Type.String())
//
// 		if typeIsStruct(field.Type.String()) {
// 			var ok bool
// 			fieldType, ok = (*typeMap)[field.Type.String()]
// 			if !ok {
// 				panic("unable to resolve nested struct field")
// 			}
// 		} else {
// 			// generate a primitive type...
// 			var err error
// 			fieldType, err = getPrimitiveTypeFromName(field.Type.String())
// 			if err != nil {
// 				fmt.Printf("%s\n", err.Error())
// 			}
// 		}
//
// 		newField := prog.Field{
// 			Name:         field.Name,
// 			Type:         fieldType,
// 			HasDirection: false,
// 			Direction:    prog.DirInOut,
// 		}
//
// 		outputType.Fields = append(outputType.Fields, newField)
// 	}
//
// 	// this is important because the structure could have a variable length
// 	// field such as a string of some buffer
// 	outputType.TypeCommon.IsVarlen = hasVarlenField
// 	// I am curious if this is the reason why the stuff wasn't working before
// 	outputType.TypeCommon.IsVarlen = true
//
// 	// TODO: figure out why we need to prepend "struct ", it isn't super clean
// 	// but this is what is expected. Mismatch between the type names in the
// 	// dwarf lib and the names in the prog types (which don't contain struct)
// 	(*typeMap)["struct "+dwarfType.StructName] = outputType
//
// 	// TODO: remove debug
// 	// fmt.Printf("added structType to typemap\n")
// 	// for name, tpe := range *typeMap {
// 	// 	fmt.Printf("\t%s -> %s\n", name, tpe.String())
// 	// }
//
// 	return outputType
// }
//
// // returns the relevant primitive type from a given type name, e.g. "int"
// // will return a syzkaller int32 common type
// func getPrimitiveTypeFromName(typename string) (prog.Type, error) {
// 	switch typename {
// 	case "int", "unsigned int":
// 		return &prog.IntType{
// 			IntTypeCommon: prog.IntTypeCommon{
// 				TypeCommon: prog.TypeCommon{TypeName: "int32", TypeSize: 4},
// 			},
// 		}, nil
// 	case "size_t", "long", "unsigned long", "long unsigned int":
// 		return &prog.IntType{
// 			IntTypeCommon: prog.IntTypeCommon{
// 				TypeCommon: prog.TypeCommon{TypeName: "int64", TypeSize: 8},
// 			},
// 		}, nil
// 	case "char":
// 		return &prog.IntType{
// 			IntTypeCommon: prog.IntTypeCommon{
// 				TypeCommon: prog.TypeCommon{TypeName: "int8", TypeSize: 1},
// 			},
// 		}, nil
// 	case "*const char":
// 		stringType := &prog.BufferType{
// 			TypeCommon: prog.TypeCommon{
// 				TypeName: "string",
// 				IsVarlen: true, // Strings have variable length.
// 			},
// 			Kind: prog.BufferString,
// 		}
// 		return &prog.PtrType{
// 			TypeCommon: prog.TypeCommon{
// 				TypeName: "ptr",
// 				TypeSize: 8, // Assuming a 64-bit architecture.
// 			},
// 			Elem:    stringType,
// 			ElemDir: prog.DirIn,
// 		}, nil
// 	default:
// 		return nil, fmt.Errorf("unrecognized type %s", typename)
// 	}
// }
//
// //nolint:all
// func MakeKFuzzTestSyscall(vmlinuxPath string) ([]*prog.Syscall, []prog.Type, error) {
// 	var (
// 		syscalls []*prog.Syscall
// 		types    []prog.Type
// 	)
// 	dwarfParser, err := NewDwarfParser(vmlinuxPath)
// 	if err != nil {
// 		return syscalls, types, err
// 	}
// 	testCases, err := dwarfParser.LocateKFuzzTestCases()
// 	if err != nil {
// 		return syscalls, types, err
// 	}
// 	structTypes, err := dwarfParser.locateKFuzzInputStructs(testCases)
// 	if err != nil {
// 		return syscalls, types, err
// 	}
//
// 	for _, structType := range structTypes {
// 		err = dwarfParser.dwarfBuildStructDag(structType)
// 		if err != nil {
// 			return syscalls, types, err
// 		}
// 	}
//
// 	for _, structType := range structTypes {
// 		fmt.Printf("%s: size = %d\n", structType.StructName, structType.Size())
// 	}
//
// 	syscalls, types, err = dwarfParser.getSyscallsAndTypes()
// 	return syscalls, types, nil
// }
//
// //nolint:all
// func GenerateKFuzzTestSyscall(testName, inputType string, typesMap map[string]*dwarf.StructType) {
//
// 	// common types that we will use
// 	_ = &prog.IntType{
// 		IntTypeCommon: prog.IntTypeCommon{
// 			TypeCommon: prog.TypeCommon{TypeName: "int64", TypeSize: 8},
// 		},
// 	}
// 	stringType := &prog.BufferType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: "string",
// 			IsVarlen: true, // Strings have variable length.
// 		},
// 		Kind: prog.BufferString,
// 	}
// 	_ = &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: "ptr",
// 			TypeSize: 8, // Assuming a 64-bit architecture.
// 		},
// 		Elem:    stringType,
// 		ElemDir: prog.DirIn,
// 	}
// }
//
// // MakeSprintOidSyscall dynamically constructs the prog.Syscall and related types
// // for the syz_kfuzztest_run$test_sprint_oid syscall definition.
// func MakeSprintOidSyscall() (*prog.Syscall, []prog.Type) {
// 	// -- Define types for the 'sprint_oid_arg' struct --
//
// 	// Common type for 64-bit integers used in the struct.
// 	int64Type := &prog.IntType{
// 		IntTypeCommon: prog.IntTypeCommon{
// 			TypeCommon: prog.TypeCommon{TypeName: "int64", TypeSize: 8},
// 		},
// 	}
//
// 	// The 'data' field within the struct is a pointer to a string.
// 	// First, define the underlying string type.
// 	stringType := &prog.BufferType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: "string",
// 			IsVarlen: true, // Strings have variable length.
// 		},
// 		Kind: prog.BufferString,
// 	}
//
// 	// Next, define the pointer type that points to the string.
// 	stringPtrType := &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: "ptr",
// 			TypeSize: 8, // Assuming a 64-bit architecture.
// 		},
// 		Elem:    stringType,
// 		ElemDir: prog.DirIn,
// 	}
//
// 	// Define a LenType for the 'datasize' field. This type's value will be
// 	// the length of the buffer pointed to by the 'data' field within the same struct.
// 	dataLenType := &prog.LenType{
// 		IntTypeCommon: prog.IntTypeCommon{
// 			TypeCommon: prog.TypeCommon{TypeName: "int64", TypeSize: 8},
// 		},
// 		// This path links this field to the 'data' field in the same struct.
// 		Path: []string{"data"},
// 	}
//
// 	// Assemble the fields into the final StructType for 'sprint_oid_arg'.
// 	sprintOidArgStruct := &prog.StructType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: "sprint_oid_arg",
// 			// IsVarlen is true because it contains a variable-length field (the string pointer).
// 			IsVarlen: true,
// 		},
// 		Fields: []prog.Field{
// 			{
// 				Name:         "data",
// 				Type:         stringPtrType,
// 				HasDirection: true,
// 				Direction:    prog.DirIn,
// 			},
// 			{
// 				Name: "datasize",
// 				Type: dataLenType, // *** Use the LenType here ***
// 			},
// 			{
// 				Name: "bufsize",
// 				Type: int64Type,
// 			},
// 		},
// 	}
//
// 	// -- Define types for the syscall arguments --
//
// 	// 1. Define the type for the 'name' argument.
// 	// It's a pointer to a string with a fixed constant value.
// 	nameStrType := &prog.BufferType{
// 		TypeCommon: prog.TypeCommon{TypeName: "string", IsVarlen: true},
// 		Kind:       prog.BufferString,
// 		Values:     []string{"test_sprint_oid"}, // The constant value.
// 	}
// 	namePtrType := &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{TypeName: "ptr", TypeSize: 8},
// 		Elem:       nameStrType,
// 		ElemDir:    prog.DirIn,
// 	}
//
// 	// 2. Define the type for the 'data' argument.
// 	// This is a pointer to the 'sprint_oid_arg' struct we defined above.
// 	dataStructPtrType := &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{TypeName: "ptr", TypeSize: 8},
// 		Elem:       sprintOidArgStruct,
// 		ElemDir:    prog.DirIn,
// 	}
//
// 	// 3. Define the type for the 'len' argument.
// 	// 'bytesize[data]' is a LenType whose value is the size of the 'data' argument.
// 	lenType := &prog.LenType{
// 		IntTypeCommon: prog.IntTypeCommon{
// 			TypeCommon: prog.TypeCommon{TypeName: "int64", TypeSize: 8},
// 		},
// 		// This path links the len field to the 'data' syscall argument.
// 		Path: []string{"data"},
// 	}
//
// 	// -- Assemble the final syscall --
//
// 	testSyscall := &prog.Syscall{
// 		// A dummy ID and syscall number, used internally by the fuzzer.
// 		ID: 0,
// 		NR: 0,
// 		// The full name, including the template part.
// 		Name: "syz_kfuzztest_run$test_sprint_oid",
// 		// The name of the function that gets called in the executor.
// 		CallName: "syz_kfuzztest_run",
// 		Args: []prog.Field{
// 			{Name: "name", Type: namePtrType},
// 			{Name: "data", Type: dataStructPtrType},
// 			{Name: "len", Type: lenType},
// 		},
// 		// This syscall does not have a return value.
// 		Ret: nil,
// 	}
//
// 	// Collect all custom types defined in this function. The fuzzer needs
// 	// this list to understand the types used in the syscall.
// 	allMyTypes := []prog.Type{
// 		int64Type,
// 		stringType,
// 		stringPtrType,
// 		dataLenType, // <-- Add the new LenType
// 		sprintOidArgStruct,
// 		nameStrType,
// 		namePtrType,
// 		dataStructPtrType,
// 		lenType,
// 	}
//
// 	// Optional: Print for verification
// 	fmt.Printf("Generated Syscall: %s\n", testSyscall.Name)
// 	for _, arg := range testSyscall.Args {
// 		fmt.Printf("  Arg: %s, Type: %s\n", arg.Name, arg.Type.String())
// 	}
// 	fmt.Println("\n-- Struct Definition --")
// 	fmt.Printf("Struct Name: %s\n", sprintOidArgStruct.Name())
// 	for _, field := range sprintOidArgStruct.Fields {
// 		fmt.Printf("  Field: %s, Type: %s\n", field.Name, field.Type.String())
// 	}
//
// 	return testSyscall, allMyTypes
// }
//
// func MakeSyscall() (*prog.Syscall, []prog.Type) {
// 	stringType := &prog.BufferType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: "string",
// 			IsVarlen: true, // Strings have variable length.
// 		},
// 		Kind: prog.BufferString,
// 	}
//
// 	// The 'buff' field is a pointer to that string.
// 	buffType := &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: "ptr",
// 			TypeSize: 8, // Assuming a 64-bit architecture.
// 		},
// 		Elem:    stringType,
// 		ElemDir: prog.DirIn,
// 	}
//
// 	// 3. Assemble the fields into the final StructType.
// 	parseQosArgStruct := &prog.StructType{
// 		TypeCommon: prog.TypeCommon{
// 			TypeName: "parse_qos_arg",
// 			// IsVarlen is true because it contains a variable-length field.
// 			IsVarlen: true,
// 		},
// 		Fields: []prog.Field{
// 			{
// 				Name: "buff",
// 				Type: buffType,
// 				// Direction can be set on the field itself.
// 				HasDirection: true,
// 				Direction:    prog.DirIn,
// 			},
// 		},
// 	}
//
// 	fmt.Printf("Struct Name: %s\n", parseQosArgStruct.Name())
// 	for _, field := range parseQosArgStruct.Fields {
// 		fmt.Printf("  Field: %s, Type: %s\n", field.Name, field.Type.String())
// 	}
//
// 	// 1. Define the type for the 'name' argument.
// 	// It's a pointer to a string with a fixed value.
// 	nameStrType := &prog.BufferType{
// 		TypeCommon: prog.TypeCommon{TypeName: "string", IsVarlen: true},
// 		Kind:       prog.BufferString,
// 		// This sets the constant value for the string.
// 		Values: []string{"test_parse_qos"},
// 	}
// 	namePtrType := &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{TypeName: "ptr", TypeSize: 8},
// 		Elem:       nameStrType,
// 		ElemDir:    prog.DirIn,
// 	}
//
// 	// 2. Define the type for the 'data' argument.
// 	// It's a pointer to the struct we already defined.
// 	dataType := &prog.PtrType{
// 		TypeCommon: prog.TypeCommon{TypeName: "ptr", TypeSize: 8},
// 		Elem:       parseQosArgStruct,
// 		ElemDir:    prog.DirIn,
// 	}
//
// 	// 3. Define the type for the 'len' argument.
// 	// 'bytesize[data]' is a LenType whose value is the size of the 'data' argument.
// 	lenType := &prog.LenType{
// 		IntTypeCommon: prog.IntTypeCommon{
// 			TypeCommon: prog.TypeCommon{TypeName: "int64", TypeSize: 8},
// 		},
// 		// This Path links this field to the 'data' argument.
// 		Path: []string{"data"},
// 	}
//
// 	allMyTypes := []prog.Type{
// 		stringType,
// 		buffType, // <--- Add this pointer type
// 		parseQosArgStruct,
// 		nameStrType,
// 		namePtrType,
// 		dataType, // <--- Add this pointer type
// 		lenType,
// 	}
//
// 	// 4. Assemble the syscall.
// 	testSyscall := &prog.Syscall{
// 		// A dummy ID and syscall number.
// 		ID: 0, // both of these fields are used internally by the fuzzer
// 		NR: 0, // not sure if this is used fro a pseudo-syscall like this
// 		// The full name, including the template part.
// 		Name: "syz_kfuzztest_run$test_parse_qos",
// 		// The name of the function that gets called in the executor.
// 		CallName: "syz_kfuzztest_run",
// 		Args: []prog.Field{
// 			{Name: "name", Type: namePtrType},
// 			{Name: "data", Type: dataType},
// 			{Name: "len", Type: lenType},
// 		},
// 		// A syscall can also have a return type.
// 		Ret: nil,
// 	}
//
// 	return testSyscall, allMyTypes
// }
