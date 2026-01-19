// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Common struct definitions that ressemble those sound in the kernel source
// under include/linux/kfuzztest.h. For testing purposes, it is only required
// that these have the same sizes and emitted metadata as the kernel
// definitions, and therefore there is no strict requirement that their fields
// match one-to-one.
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

struct kfuzztest_target {
	const char* name;
	const char* arg_type_name;
	uintptr_t write_input_cb;
} __attribute__((aligned(32)));

enum kfuzztest_constraint_type {
	EXPECT_EQ,
	EXPECT_NE,
	EXPECT_LT,
	EXPECT_LE,
	EXPECT_GT,
	EXPECT_GE,
	EXPECT_IN_RANGE,
};

struct kfuzztest_constraint {
	const char* input_type;
	const char* field_name;
	uintptr_t value1;
	uintptr_t value2;
	enum kfuzztest_constraint_type type;
} __attribute__((aligned(64)));

enum kfuzztest_annotation_attribute {
	ATTRIBUTE_LEN,
	ATTRIBUTE_STRING,
	ATTRIBUTE_ARRAY,
};

struct kfuzztest_annotation {
	const char* input_type;
	const char* field_name;
	const char* linked_field_name;
	enum kfuzztest_annotation_attribute attrib;
} __attribute__((aligned(32)));

#define DEFINE_FUZZ_TARGET(test_name, test_arg_type)                    \
	struct kfuzztest_target __fuzz_test__##test_name                \
	    __attribute__((section(".kfuzztest_target"), __used__)) = { \
		.name = #test_name,                                     \
		.arg_type_name = #test_arg_type,                        \
	};                                                              \
	/* Avoid the compiler optimizing out the struct definition. */  \
	static test_arg_type arg;

#define DEFINE_CONSTRAINT(arg_type, field, val1, val2, tpe)                  \
	static struct kfuzztest_constraint __constraint_##arg_type##_##field \
	    __attribute__((section(".kfuzztest_constraint"),                 \
			   __used__)) = {                                    \
		.input_type = "struct " #arg_type,                           \
		.field_name = #field,                                        \
		.value1 = (uintptr_t)val1,                                   \
		.value2 = (uintptr_t)val2,                                   \
		.type = tpe,                                                 \
	}

#define DEFINE_ANNOTATION(arg_type, field, linked_field, attribute)          \
	static struct kfuzztest_annotation __annotation_##arg_type##_##field \
	    __attribute__((section(".kfuzztest_annotation"),                 \
			   __used__)) = {                                    \
		.input_type = "struct " #arg_type,                           \
		.field_name = #field,                                        \
		.linked_field_name = #linked_field,                          \
		.attrib = attribute,                                         \
	}

#endif /* COMMON_H */
