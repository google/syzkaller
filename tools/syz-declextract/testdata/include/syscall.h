
#define SYSCALL_DEFINE1(NAME, ...) SYSCALL_DEFINEx(1, NAME, __VA_ARGS__)
#define SYSCALL_DEFINE2(NAME, ...) SYSCALL_DEFINEx(2, NAME, __VA_ARGS__)
#define SYSCALL_DEFINEx(NARGS, NAME, ...) long __do_sys_##NAME(__VA_ARGS__); \
long __do_sys_##NAME(__VA_ARGS__)
