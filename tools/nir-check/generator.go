package main

import (
	"bufio"
	"html/template"
	"os"
)

func generator() {

	// mainTemplate := `
	// #include <limits.h>
	// #include <stdio.h>

	// int main() {
	// 	{{.Content}}
	// }
	// `

	funcTemplate :=
		`
void test_struct_{{.StructName}} () {


	`

	fieldTemplate := `
	{{.StructName}}.{{.FieldName}} = INT_MAX +1;
	szl_{{.FieldName}} = INT_MAX +1;

	if ((float)szl_{{.FieldName}} != (float){{.StructName}}.{{.FieldName}}){
		Printf("{{.FieldName}} sign error");
	}

	szl_{{.FieldName}} =<< 16;
	{{.StructName}}.{{.FieldName}} =<< 16;

	if (szl_{{.FieldName}} != {{.StructName}}.{{.FieldName}}){
		Printf("{{.FieldName}} size error");
	}
	`

	TestField, err := template.New("FieldTest").Parse(fieldTemplate)
	if err != nil {
		panic(err)
	}

	data := map[string]interface{}{
		"StructName": "Test1",
		"FieldName":  "Field1",
	}

	TestStruct, err := template.New("TestStruct").Parse(funcTemplate)

	if err != nil {
		panic(err)
	}

	TestStruct.Execute(os.Stdout, data)
	TestField.Execute(os.Stdout, data)

	path := "./algo/test.c"

	file, err := os.OpenFile(path, os.O_RDWR, 0666)

	if err != nil {
		panic("file err")
	}

	TestStruct.Execute(file, data)
	TestField.Execute(file, data)

	_, err = file.Write([]byte("}"))
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)

	targetWord := "main"

	pos := 0

	for scanner.Scan() {
		word := scanner.Text()
		pos += len(word)

		if word == targetWord {
			break
		}
	}

	// position, err := file.Seek(int64(pos), 0)

	// if err != nil {
	// 	panic("seek err")
	// }

	// _, err = file.WriteAt([]byte("KYS KYS KYS KYS KYS "), int64(pos))

	// if err != nil {
	// 	panic(err)
	// }

	// data := map[string]interface{}{
	// 	"Name": "Deer",
	// }

	// queueTemplate := `Hello {{.Name}} please go kill yourself`

	// t, err := template.New("John").Parse(queueTemplate)

	// if err != nil {
	// 	panic(err)
	// }

	// err = t.Execute(os.Stdout, data)

	// if err != nil {
	// 	panic(err)
	// }
	// // fmt.Print()
}
