# Fake Linux kernel Makefile supporting both in-tree and out-of-tree (O=) builds.
# Each target runs scripts/check-sandbox to verify that it executes inside osutil.Sandbox,
# and scripts/plant-symlink to simulate malicious builds.
O ?= .

target:

oldconfig distclean:
	@./scripts/check-sandbox
	@echo "CONFIG_OLDCONFIG=y" >> .config
	@./scripts/plant-symlink $@

# Simulate a kernel build:
# - verify that git status works on the source tree from the sandbox user;
# - for in-tree builds, touch generated files that linux.cleanUntracked expects to clean up;
# - produce the build artifacts expected by pkg/build (bzImage, vmlinux, compile.h, compile_commands.json).
# The vmlinux target is used on the arches where vmlinux itself is the kernel image.
bzImage vmlinux compile_commands.json &:
	@./scripts/check-sandbox
	@git --no-optional-locks status --porcelain >/dev/null
	@if [ "$(abspath $(O))" = "$(CURDIR)" ]; then \
		{ [ ! -e .git ] || ! touch .git/escape 2>/dev/null; } && \
		touch .config certs/signing_key.pem scripts/gcc-plugins/randomize_layout_seed.h; \
	else \
		! touch escape 2>/dev/null; \
	fi
	@mkdir -p "$(O)/arch/x86/boot" "$(O)/include/generated"
	@echo "image" > "$(O)/arch/x86/boot/bzImage"
	@cp /bin/true "$(O)/vmlinux"
	@echo '#define LINUX_COMPILER "fake compiler"' > "$(O)/include/generated/compile.h"
	@echo "[]" > "$(O)/compile_commands.json"
	@echo "obj" > "$(O)/intermediate.o"
	@./scripts/plant-symlink bzImage
