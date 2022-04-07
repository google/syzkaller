TARGET := libs/arm64-v8a/sandbox_test
SRC := jni/sandbox_test.c

all: $(TARGET)

$(TARGET): $(SRC)
	ndk-build

push: $(TARGET)
	adb push "$^" /data/local/tmp

run: push
	adb shell /data/local/tmp/sandbox_test

clean:
	rm -rf libs obj

.PHONY: all push run
