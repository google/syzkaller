#define GOOS_linux 1
#define SYZ_SANDBOX_ANDROID_UNTRUSTED_APP 1
#define SYZ_USE_TMP_DIR 1
#define fail(...)   do { dprintf(2, __VA_ARGS__); dprintf(2, "\n"); perror("errno"); exit(1); } while(0)
#define error(...)  do { dprintf(2, __VA_ARGS__); } while(0)
#define debug(...)  do { dprintf(2, __VA_ARGS__); } while(0)

#include <stdlib.h>
#include <string.h>

void doexit(int status)
{
    exit(status);
}

static void loop() {
    exit(system("id"));
}

static void use_temporary_dir(void)
{
#if SYZ_SANDBOX_ANDROID_UNTRUSTED_APP
    char tmpdir_template[] = "/data/data/syzkaller/syzkaller.XXXXXX";
#else
    char tmpdir_template[] = "./syzkaller.XXXXXX";
#endif
    char* tmpdir = mkdtemp(tmpdir_template);
    if (!tmpdir)
        fail("failed to mkdtemp");
    if (chmod(tmpdir, 0777))
        fail("failed to chmod");
    if (chdir(tmpdir))
        fail("failed to chdir");
}



#include "executor/common_linux.h"

int main() {
    use_temporary_dir();
    do_sandbox_android_untrusted_app();
}
