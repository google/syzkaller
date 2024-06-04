// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <vector>

// Subprocess allows to start and wait for a subprocess.
class Subprocess
{
public:
	Subprocess(const char** argv, const std::vector<std::pair<int, int>>& fds)
	{
		posix_spawn_file_actions_t actions;
		if (posix_spawn_file_actions_init(&actions))
			fail("posix_spawn_file_actions_init failed");
		int max_fd = 0;
		for (auto pair : fds) {
			max_fd = std::max(max_fd, pair.second);
			if (pair.first != -1) {
				if (posix_spawn_file_actions_adddup2(&actions, pair.first, pair.second))
					fail("posix_spawn_file_actions_adddup2 failed");
			} else {
				if (posix_spawn_file_actions_addclose(&actions, pair.second))
					fail("posix_spawn_file_actions_addclose failed");
			}
		}
		for (int i = max_fd + 1; i < kFdLimit; i++) {
			if (posix_spawn_file_actions_addclose(&actions, i))
				fail("posix_spawn_file_actions_addclose failed");
		}

		posix_spawnattr_t attr;
		if (posix_spawnattr_init(&attr))
			fail("posix_spawnattr_init failed");
		// Create new process group so that we can kill all processes in the group.
		if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP))
			fail("posix_spawnattr_setflags failed");

		const char* child_envp[] = {
		    // Tell ASAN to not mess with our NONFAILING.
		    "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1",
		    // Disable rseq since we don't use it and we want to [ab]use it ourselves for kernel testing.
		    "GLIBC_TUNABLES=glibc.pthread.rseq=0",
		    nullptr};

		if (posix_spawn(&pid_, argv[0], &actions, &attr,
				const_cast<char**>(argv), const_cast<char**>(child_envp)))
			fail("posix_spawn failed");

		if (posix_spawn_file_actions_destroy(&actions))
			fail("posix_spawn_file_actions_destroy failed");
		if (posix_spawnattr_destroy(&attr))
			fail("posix_spawnattr_destroy failed");
	}

	~Subprocess()
	{
		if (pid_)
			KillAndWait();
	}

	int KillAndWait()
	{
		if (!pid_)
			fail("subprocess hasn't started or already waited");
		kill(-pid_, SIGKILL);
		kill(pid_, SIGKILL);
		int pid = 0;
		int wstatus = 0;
		do
			pid = waitpid(pid_, &wstatus, WAIT_FLAGS);
		while (pid == -1 && errno == EINTR);
		if (pid != pid_)
			failmsg("child wait failed", "pid_=%d pid=%d", pid_, pid);
		if (WIFSTOPPED(wstatus))
			failmsg("child stopped", "status=%d", wstatus);
		pid_ = 0;
		return ExitStatus(wstatus);
	}

	int WaitAndKill(uint64 timeout_ms)
	{
		if (!pid_)
			fail("subprocess hasn't started or already waited");
		uint64 start = current_time_ms();
		int wstatus = 0;
		for (;;) {
			sleep_ms(10);
			if (waitpid(pid_, &wstatus, WNOHANG | WAIT_FLAGS) == pid_)
				break;
			if (current_time_ms() - start > timeout_ms) {
				kill(-pid_, SIGKILL);
				kill(pid_, SIGKILL);
			}
		}
		pid_ = 0;
		return ExitStatus(wstatus);
	}

private:
	int pid_ = 0;

	static int ExitStatus(int wstatus)
	{
		if (WIFEXITED(wstatus))
			return WEXITSTATUS(wstatus);
		if (WIFSIGNALED(wstatus)) {
			// Map signal numbers to some reasonable exit statuses.
			// We only log them and compare to kFailStatus, so ensure it's not kFailStatus
			// and not 0, otherwise return the signal as is (e.g. exit status 11 is SIGSEGV).
			switch (WTERMSIG(wstatus)) {
			case kFailStatus:
				return kFailStatus - 1;
			case 0:
				return kFailStatus - 2;
			default:
				return WTERMSIG(wstatus);
			}
		}
		// This may be possible in WIFSTOPPED case for C programs.
		return kFailStatus - 3;
	}

	Subprocess(const Subprocess&) = delete;
	Subprocess& operator=(const Subprocess&) = delete;
};
