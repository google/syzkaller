package main

import (
	"flag"
	"log"
)

func main() {
	vmlinuxPath := flag.String("vmlinux", "", "Path to vmlinux binary.")
	flag.Parse()

	dwarfParser, err := newDwarfParser(*vmlinuxPath)
	if err != nil {
		log.Fatalf("Failed to create DWARF parser: %v", err)
	}

	log.Printf("Locating KFuzz test cases")
	fuzzTargets, err := dwarfParser.locateKFuzzTestCases()
	if err != nil {
		log.Fatalf("Failed to locate KFuzz targets in vmlinux: %v", err)
	}

	for _, target := range fuzzTargets {
		dwarfParser.addFunc(target.testName, target.argType)
	}

	log.Printf("Parsing KFuzz input structs")
	fuzzInputStructs, err := dwarfParser.locateKFuzzInputStructs(fuzzTargets)
	if err != nil {
		log.Fatalf("Failed to parse KFuzz input structs in vmlinux: %v", err)
	}

	log.Printf("Building dag of input structures")
	for _, structType := range fuzzInputStructs {
		err = dwarfParser.dwarfBuildStructDag(structType)
		if err != nil {
			log.Fatalf("Failed to traverse dependencies for %s: %v", structType.StructName, err)
		}
	}

	log.Printf("Dumping syzlang description of parsed types")
	description := dwarfParser.syzlangDescription()
	log.Printf("\n%s\n", description)
}
