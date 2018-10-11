LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := sandbox_test
LOCAL_SRC_FILES := sandbox_test.c
LOCAL_C_INCLUDES := ../../

include $(BUILD_EXECUTABLE)
