
void test_struct_Test1 () {


	
	Test1.Field1 = INT_MAX +1;
	szl_Field1 = INT_MAX +1;

	if ((float)szl_Field1 != (float)Test1.Field1){
		Printf("Field1 sign error");
	}

	szl_Field1 =\&lt;\&lt; 16;
	Test1.Field1 =\&lt;\&lt; 16;

	if (szl_Field1 != Test1.Field1){
		Printf("Field1 size error");
	}
	}