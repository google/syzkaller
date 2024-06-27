// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <deque>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

inline std::ostream& operator<<(std::ostream& ss, const rpc::ExecRequestRawT& req)
{
	return ss << "id=" << req.id
		  << " flags=0x" << std::hex << static_cast<uint64>(req.flags)
		  << " env_flags=0x" << std::hex << static_cast<uint64>(req.exec_opts->env_flags())
		  << " exec_flags=0x" << std::hex << static_cast<uint64>(req.exec_opts->exec_flags())
		  << " prod_data=" << std::dec << req.prog_data.size()
		  << "\n";
}

// Proc represents one subprocess that runs tests (re-execed syz-executor with 'exec' argument).
// The object is persistent and re-starts subprocess when it crashes.
class Proc
{
public:
	Proc(Connection& conn, const char* bin, int id, int max_signal_fd, int cover_filter_fd,
	     uint32 slowdown, uint32 syscall_timeout_ms, uint32 program_timeout_ms)
	    : conn_(conn),
	      bin_(bin),
	      id_(id),
	      max_signal_fd_(max_signal_fd),
	      cover_filter_fd_(cover_filter_fd),
	      slowdown_(slowdown),
	      syscall_timeout_ms_(syscall_timeout_ms),
	      program_timeout_ms_(program_timeout_ms),
	      req_shmem_(kMaxInput),
	      resp_shmem_(kMaxOutput),
	      resp_mem_(static_cast<OutputData*>(resp_shmem_.Mem()))
	{
		Start();
	}

	bool Execute(rpc::ExecRequestRawT& msg)
	{
		if (state_ != State::Started && state_ != State::Idle)
			return false;
		if (msg_)
			fail("already have pending msg");
		if (wait_start_)
			wait_end_ = current_time_ms();
		if (state_ == State::Idle &&
		    (exec_env_ != msg.exec_opts->env_flags() || sandbox_arg_ != msg.exec_opts->sandbox_arg()))
			Restart();
		attempts_ = 0;
		msg_ = std::move(msg);
		if (state_ == State::Started)
			Handshake();
		else
			Execute();
		return true;
	}

	void Arm(Select& select)
	{
		select.Arm(resp_pipe_);
		select.Arm(stdout_pipe_);
	}

	void Ready(Select& select, uint64 now, bool out_of_requests)
	{
		if (state_ == State::Handshaking || state_ == State::Executing) {
			// Check if the subprocess has hung.
#if SYZ_EXECUTOR_USES_FORK_SERVER
			// Child process has an internal timeout and protects against most hangs when
			// fork server is enabled, so we use quite large timeout. Child process can be slow
			// due to global locks in namespaces and other things, so let's better wait than
			// report false misleading crashes.
			uint64 timeout = 2 * program_timeout_ms_;
#else
			uint64 timeout = program_timeout_ms_;
#endif
			// Sandbox setup can take significant time.
			if (state_ == State::Handshaking)
				timeout = 60 * 1000 * slowdown_;
			if (now > exec_start_ + timeout) {
				Restart();
				return;
			}
		}

		if (select.Ready(stdout_pipe_) && !ReadOutput()) {
#if SYZ_EXECUTOR_USES_FORK_SERVER
			// In non-forking mode the subprocess exits after test execution
			// and the pipe read fails with EOF, so we rely on the resp_pipe_ instead.
			Restart();
			return;
#endif
		}
		if (select.Ready(resp_pipe_) && !ReadResponse(out_of_requests)) {
			Restart();
			return;
		}
		return;
	}

private:
	enum State : uint8 {
		// The process has just started.
		Started,
		// We sent the process env flags and waiting for handshake reply.
		Handshaking,
		// Handshaked and ready to execute programs.
		Idle,
		// Currently executing a test program.
		Executing,
	};

	Connection& conn_;
	const char* const bin_;
	const int id_;
	const int max_signal_fd_;
	const int cover_filter_fd_;
	const uint32 slowdown_;
	const uint32 syscall_timeout_ms_;
	const uint32 program_timeout_ms_;
	State state_ = State::Started;
	std::optional<Subprocess> process_;
	ShmemFile req_shmem_;
	ShmemFile resp_shmem_;
	OutputData* resp_mem_;
	int req_pipe_ = -1;
	int resp_pipe_ = -1;
	int stdout_pipe_ = -1;
	rpc::ExecEnv exec_env_ = rpc::ExecEnv::NONE;
	int64_t sandbox_arg_ = 0;
	std::optional<rpc::ExecRequestRawT> msg_;
	std::vector<uint8_t> output_;
	size_t debug_output_pos_ = 0;
	uint64 attempts_ = 0;
	uint64 freshness_ = 0;
	uint64 exec_start_ = 0;
	uint64 wait_start_ = 0;
	uint64 wait_end_ = 0;

	friend std::ostream& operator<<(std::ostream& ss, const Proc& proc)
	{
		ss << "id=" << proc.id_
		   << " state=" << static_cast<int>(proc.state_)
		   << " freshness=" << proc.freshness_
		   << " attempts=" << proc.attempts_
		   << " exec_start=" << current_time_ms() - proc.exec_start_
		   << "\n";
		if (proc.msg_)
			ss << "\tcurrent request: " << *proc.msg_;
		return ss;
	}

	void Restart()
	{
		debug("proc %d: restarting subprocess, current state %u attempts %llu\n", id_, state_, attempts_);
		int status = process_->KillAndWait();
		process_.reset();
		debug("proc %d: subprocess exit status %d\n", id_, status);
		if (++attempts_ > 20) {
			while (ReadOutput())
				;
			// Write the subprocess output first. If it contains own SYFAIL,
			// we want it to be before our SYZFAIL.
			ssize_t wrote = write(STDERR_FILENO, output_.data(), output_.size());
			if (wrote != static_cast<ssize_t>(output_.size()))
				fprintf(stderr, "output truncated: %zd/%zd (errno=%d)\n",
					wrote, output_.size(), errno);
			uint64 req_id = msg_ ? msg_->id : -1;
			failmsg("repeatedly failed to execute the program", "proc=%d req=%lld state=%d status=%d",
				id_, req_id, state_, status);
		}
		// Ignore all other errors.
		// Without fork server executor can legitimately exit (program contains exit_group),
		// with fork server the top process can exit with kFailStatus if it wants special handling.
		if (status != kFailStatus)
			status = 0;
		if (FailCurrentRequest(status == kFailStatus)) {
			// Read out all pening output until EOF.
			if (IsSet(msg_->flags, rpc::RequestFlag::ReturnOutput)) {
				while (ReadOutput())
					;
			}
			HandleCompletion(status);
		} else if (attempts_ > 3)
			sleep_ms(100 * attempts_);
		Start();
	}

	bool FailCurrentRequest(bool failed)
	{
		if (state_ == State::Handshaking)
			return IsSet(msg_->flags, rpc::RequestFlag::ReturnError);
		if (state_ == State::Executing)
			return !failed || IsSet(msg_->flags, rpc::RequestFlag::ReturnError);
		return false;
	}

	void Start()
	{
		state_ = State::Started;
		freshness_ = 0;
		int req_pipe[2];
		if (pipe(req_pipe))
			fail("pipe failed");
		int resp_pipe[2];
		if (pipe(resp_pipe))
			fail("pipe failed");
		int stdout_pipe[2];
		if (pipe(stdout_pipe))
			fail("pipe failed");

		std::vector<std::pair<int, int>> fds = {
		    {req_pipe[0], STDIN_FILENO},
		    {resp_pipe[1], STDOUT_FILENO},
		    {stdout_pipe[1], STDERR_FILENO},
		    {req_shmem_.FD(), kInFd},
		    {resp_shmem_.FD(), kOutFd},
		    {max_signal_fd_, kMaxSignalFd},
		    {cover_filter_fd_, kCoverFilterFd},
		};
		const char* argv[] = {bin_, "exec", nullptr};
		process_.emplace(argv, fds);

		Select::Prepare(resp_pipe[0]);
		Select::Prepare(stdout_pipe[0]);

		close(req_pipe[0]);
		close(resp_pipe[1]);
		close(stdout_pipe[1]);

		close(req_pipe_);
		close(resp_pipe_);
		close(stdout_pipe_);

		req_pipe_ = req_pipe[1];
		resp_pipe_ = resp_pipe[0];
		stdout_pipe_ = stdout_pipe[0];

		if (msg_)
			Handshake();
	}

	void Handshake()
	{
		if (state_ != State::Started || !msg_)
			fail("wrong handshake state");
		debug("proc %d: handshaking to execute request %llu\n", id_, static_cast<uint64>(msg_->id));
		state_ = State::Handshaking;
		exec_start_ = current_time_ms();
		exec_env_ = msg_->exec_opts->env_flags() & ~rpc::ExecEnv::ResetState;
		sandbox_arg_ = msg_->exec_opts->sandbox_arg();
		handshake_req req = {
		    .magic = kInMagic,
		    .flags = exec_env_,
		    .pid = static_cast<uint64>(id_),
		    .sandbox_arg = static_cast<uint64>(sandbox_arg_),
		};
		if (write(req_pipe_, &req, sizeof(req)) != sizeof(req)) {
			debug("request pipe write failed (errno=%d)\n", errno);
			Restart();
		}
	}

	void Execute()
	{
		if (state_ != State::Idle || !msg_)
			fail("wrong state for execute");

		debug("proc %d: start executing request %llu\n", id_, static_cast<uint64>(msg_->id));

		rpc::ExecutingMessageRawT exec;
		exec.id = msg_->id;
		exec.proc_id = id_;
		exec.try_ = attempts_;

		if (wait_start_) {
			exec.wait_duration = (wait_end_ - wait_start_) * 1000 * 1000;
			wait_end_ = wait_start_ = 0;
		}

		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(exec));
		conn_.Send(raw);

		uint64 all_call_signal = 0;
		bool all_extra_signal = false;
		for (int32_t call : msg_->all_signal) {
			// This code assumes that call indices can be represented as bits in uint64 all_call_signal.
			static_assert(kMaxCalls == 64);
			if (call < -1 || call >= static_cast<int32_t>(kMaxCalls))
				failmsg("bad all_signal call", "call=%d", call);
			if (call < 0)
				all_extra_signal = true;
			else
				all_call_signal |= 1ull << call;
		}
		memcpy(req_shmem_.Mem(), msg_->prog_data.data(), std::min(msg_->prog_data.size(), kMaxInput));
		execute_req req{
		    .magic = kInMagic,
		    .id = static_cast<uint64>(msg_->id),
		    .env_flags = exec_env_,
		    .exec_flags = static_cast<uint64>(msg_->exec_opts->exec_flags()),
		    .pid = static_cast<uint64>(id_),
		    .syscall_timeout_ms = syscall_timeout_ms_,
		    .program_timeout_ms = program_timeout_ms_,
		    .slowdown_scale = slowdown_,
		    .all_call_signal = all_call_signal,
		    .all_extra_signal = all_extra_signal,
		};
		exec_start_ = current_time_ms();
		state_ = State::Executing;
		if (write(req_pipe_, &req, sizeof(req)) != sizeof(req)) {
			debug("request pipe write failed (errno=%d)\n", errno);
			Restart();
		}
	}

	void HandleCompletion(uint32 status)
	{
		if (!msg_)
			fail("don't have executed msg");

		// Note: if the child process crashed during handshake and the request has ReturnError flag,
		// we have not started executing the request yet.
		uint64 elapsed = (current_time_ms() - exec_start_) * 1000 * 1000;
		uint8* prog_data = msg_->prog_data.data();
		input_data = prog_data;
		uint32 num_calls = read_input(&prog_data);

		int output_size = resp_mem_->size.load(std::memory_order_relaxed) ?: kMaxOutput;
		uint32 completed = resp_mem_->completed.load(std::memory_order_relaxed);
		completed = std::min(completed, kMaxCalls);
		debug("handle completion: completed=%u output_size=%u\n", completed, output_size);
		ShmemBuilder fbb(resp_mem_, output_size);
		auto empty_call = rpc::CreateCallInfoRawDirect(fbb, rpc::CallFlag::NONE, 998);
		std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> calls(num_calls, empty_call);
		std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> extra;
		for (uint32_t i = 0; i < completed; i++) {
			const auto& call = resp_mem_->calls[i];
			if (call.index == -1) {
				extra.push_back(call.offset);
				continue;
			}
			if (call.index < 0 || call.index >= static_cast<int>(num_calls) || call.offset.o > kMaxOutput) {
				debug("bad call index/offset: proc=%d req=%llu call=%d/%d completed=%d offset=%u",
				      id_, static_cast<uint64>(msg_->id), call.index, num_calls,
				      completed, call.offset.o);
				continue;
			}
			calls[call.index] = call.offset;
		}

		auto prog_info_off = rpc::CreateProgInfoRawDirect(fbb, &calls, &extra, 0, elapsed, freshness_++);

		flatbuffers::Offset<flatbuffers::String> error_off = 0;
		if (status == kFailStatus)
			error_off = fbb.CreateString("process failed");
		flatbuffers::Offset<flatbuffers::Vector<uint8_t>> output_off = 0;
		if (IsSet(msg_->flags, rpc::RequestFlag::ReturnOutput)) {
			if (status) {
				char tmp[128];
				snprintf(tmp, sizeof(tmp), "\nprocess exited with status %d\n", status);
				output_.insert(output_.end(), tmp, tmp + strlen(tmp));
			}
			output_off = fbb.CreateVector(output_);
		}
		auto exec_off = rpc::CreateExecResultRaw(fbb, msg_->id, output_off, error_off, prog_info_off);
		auto msg_off = rpc::CreateExecutorMessageRaw(fbb, rpc::ExecutorMessagesRaw::ExecResult,
							     flatbuffers::Offset<void>(exec_off.o));
		fbb.FinishSizePrefixed(msg_off);
		auto data = fbb.GetBufferSpan();
		conn_.Send(data.data(), data.size());

		resp_mem_->Reset();
		msg_.reset();
		output_.clear();
		debug_output_pos_ = 0;
		state_ = State::Idle;
#if !SYZ_EXECUTOR_USES_FORK_SERVER
		if (process_)
			Restart();
#endif
	}

	bool ReadResponse(bool out_of_requests)
	{
		uint32 status;
		ssize_t n = read(resp_pipe_, &status, sizeof(status));
		if (n == 0) {
			debug("proc %d: response pipe EOF\n", id_);
			return false;
		}
		if (n != sizeof(status))
			failmsg("proc resp pipe read failed", "n=%zd", n);
		if (state_ == State::Handshaking) {
			debug("proc %d: got handshake reply\n", id_);
			state_ = State::Idle;
			Execute();
		} else if (state_ == State::Executing) {
			debug("proc %d: got execute reply\n", id_);
			HandleCompletion(status);
			if (out_of_requests)
				wait_start_ = current_time_ms();
		} else {
			debug("got data on response pipe in wrong state %d\n", state_);
			return false;
		}
		return true;
	}

	bool ReadOutput()
	{
		const size_t kChunk = 1024;
		output_.resize(output_.size() + kChunk);
		ssize_t n = read(stdout_pipe_, output_.data() + output_.size() - kChunk, kChunk);
		output_.resize(output_.size() - kChunk + std::max<ssize_t>(n, 0));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				return true;
			fail("proc stdout read failed");
		}
		if (n == 0) {
			debug("proc %d: output pipe EOF\n", id_);
			return false;
		}
		if (flag_debug) {
			output_.resize(output_.size() + 1);
			debug("proc %d: got output: %s\n", id_, output_.data() + debug_output_pos_);
			output_.resize(output_.size() - 1);
			debug_output_pos_ = output_.size();
		}
		return true;
	}
};

// Runner manages a set of test subprocesses (Proc's), receives new test requests from the manager,
// and dispatches them to subprocesses.
class Runner
{
public:
	Runner(Connection& conn, const char* name, const char* bin)
	    : conn_(conn),
	      name_(name)
	{
		size_t num_procs = Handshake();
		int max_signal_fd = max_signal_ ? max_signal_->FD() : -1;
		int cover_filter_fd = cover_filter_ ? cover_filter_->FD() : -1;
		for (size_t i = 0; i < num_procs; i++)
			procs_.emplace_back(new Proc(conn, bin, i, max_signal_fd, cover_filter_fd,
						     slowdown_, syscall_timeout_ms_, program_timeout_ms_));

		for (;;)
			Loop();
	}

private:
	Connection& conn_;
	const char* const name_;
	std::optional<CoverFilter> max_signal_;
	std::optional<CoverFilter> cover_filter_;
	std::vector<std::unique_ptr<Proc>> procs_;
	std::deque<rpc::ExecRequestRawT> requests_;
	std::vector<std::string> leak_frames_;
	uint32 slowdown_ = 0;
	uint32 syscall_timeout_ms_ = 0;
	uint32 program_timeout_ms_ = 0;

	friend std::ostream& operator<<(std::ostream& ss, const Runner& runner)
	{
		ss << "procs:\n";
		for (const auto& proc : runner.procs_)
			ss << *proc;
		ss << "\nqueued requests (" << runner.requests_.size() << "):\n";
		for (const auto& req : runner.requests_)
			ss << req;
		return ss;
	}

	void Loop()
	{
		Select select;
		select.Arm(conn_.FD());
		for (auto& proc : procs_)
			proc->Arm(select);
		// Wait for ready host connection and subprocess pipes.
		// Timeout is for terminating hanged subprocesses.
		select.Wait(1000);
		uint64 now = current_time_ms();

		if (select.Ready(conn_.FD())) {
			rpc::HostMessageRawT raw;
			conn_.Recv(raw);
			if (auto* msg = raw.msg.AsExecRequest())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsSignalUpdate())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsStartLeakChecks())
				Handle(*msg);
			else if (auto* msg = raw.msg.AsStateRequest())
				Handle(*msg);
			else
				failmsg("unknown host message type", "type=%d", static_cast<int>(raw.msg.type));
		}

		for (auto& proc : procs_) {
			proc->Ready(select, now, requests_.empty());
			if (!requests_.empty()) {
				if (proc->Execute(requests_.front()))
					requests_.pop_front();
			}
		}
	}

	size_t Handshake()
	{
		rpc::ConnectRequestRawT conn_req;
		conn_req.name = name_;
		conn_req.arch = GOARCH;
		conn_req.git_revision = GIT_REVISION;
		conn_req.syz_revision = SYZ_REVISION;
		conn_.Send(conn_req);

		rpc::ConnectReplyRawT conn_reply;
		conn_.Recv(conn_reply);
		if (conn_reply.debug)
			flag_debug = true;
		debug("connected to manager: procs=%d slowdown=%d syscall_timeout=%u"
		      " program_timeout=%u features=0x%llx\n",
		      conn_reply.procs, conn_reply.slowdown, conn_reply.syscall_timeout_ms,
		      conn_reply.program_timeout_ms, static_cast<uint64>(conn_reply.features));
		leak_frames_ = conn_reply.leak_frames;
		slowdown_ = conn_reply.slowdown;
		syscall_timeout_ms_ = conn_reply.syscall_timeout_ms;
		program_timeout_ms_ = conn_reply.program_timeout_ms;
		if (conn_reply.cover)
			max_signal_.emplace();

		rpc::InfoRequestRawT info_req;
		info_req.files = ReadFiles(conn_reply.files);
		info_req.globs = ReadGlobs(conn_reply.globs);

		// This does any one-time setup for the requested features on the machine.
		// Note: this can be called multiple times and must be idempotent.
		// is_kernel_64_bit = detect_kernel_bitness();
#if SYZ_HAVE_FEATURES
		setup_sysctl();
		setup_cgroups();
#endif
#if SYZ_HAVE_SETUP_EXT
		// This can be defined in common_ext.h.
		setup_ext();
#endif
		for (const auto& feat : features) {
			if (!(conn_reply.features & feat.id))
				continue;
			debug("setting up feature %s\n", rpc::EnumNameFeature(feat.id));
			const char* reason = feat.setup();
			conn_reply.features &= ~feat.id;
			std::unique_ptr<rpc::FeatureInfoRawT> res(new rpc::FeatureInfoRawT);
			res->id = feat.id;
			res->need_setup = true;
			if (reason) {
				debug("failed: %s\n", reason);
				res->reason = reason;
			}
			info_req.features.push_back(std::move(res));
		}
		for (auto id : rpc::EnumValuesFeature()) {
			if (!(conn_reply.features & id))
				continue;
			std::unique_ptr<rpc::FeatureInfoRawT> res(new rpc::FeatureInfoRawT);
			res->id = id;
			res->need_setup = false;
			info_req.features.push_back(std::move(res));
		}

#if SYZ_HAVE_KCSAN
		setup_kcsan_filter(conn_reply.race_frames);
#endif

		conn_.Send(info_req);

		rpc::InfoReplyRawT info_reply;
		conn_.Recv(info_reply);
		debug("received info reply: covfilter=%zu\n", info_reply.cover_filter.size());
		if (!info_reply.cover_filter.empty()) {
			cover_filter_.emplace();
			for (auto pc : info_reply.cover_filter)
				cover_filter_->Insert(pc);
		}

		Select::Prepare(conn_.FD());
		return conn_reply.procs;
	}

	void Handle(rpc::ExecRequestRawT& msg)
	{
		debug("recv exec request %llu: flags=0x%llx env=0x%llx exec=0x%llx size=%zu\n",
		      static_cast<uint64>(msg.id),
		      static_cast<uint64>(msg.flags),
		      static_cast<uint64>(msg.exec_opts->env_flags()),
		      static_cast<uint64>(msg.exec_opts->exec_flags()),
		      msg.prog_data.size());
		if (IsSet(msg.flags, rpc::RequestFlag::IsBinary)) {
			ExecuteBinary(msg);
			return;
		}
		for (auto& proc : procs_) {
			if (proc->Execute(msg))
				return;
		}
		requests_.push_back(std::move(msg));
	}

	void Handle(const rpc::SignalUpdateRawT& msg)
	{
		debug("recv signal update: new=%zu\n", msg.new_max.size());
		if (!max_signal_)
			fail("signal update when no signal filter installed");
		for (auto pc : msg.new_max)
			max_signal_->Insert(pc);
	}

	void Handle(const rpc::StartLeakChecksRawT& msg)
	{
		// TODO: repair leak checking (#4728).
		debug("recv start leak checks\n");
	}

	void Handle(const rpc::StateRequestRawT& msg)
	{
		// Debug request about our internal state.
		std::ostringstream ss;
		ss << *this;
		const std::string& str = ss.str();
		rpc::StateResultRawT res;
		res.data.insert(res.data.begin(), str.data(), str.data() + str.size());
		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(res));
		conn_.Send(raw);
	}

	void ExecuteBinary(rpc::ExecRequestRawT& msg)
	{
		rpc::ExecutingMessageRawT exec;
		exec.id = msg.id;
		rpc::ExecutorMessageRawT raw;
		raw.msg.Set(std::move(exec));
		conn_.Send(raw);

		char dir_template[] = "syz-bin-dirXXXXXX";
		char* dir = mkdtemp(dir_template);
		if (dir == nullptr)
			fail("mkdtemp failed");
		if (chmod(dir, 0777))
			fail("chmod failed");
		auto [err, output] = ExecuteBinaryImpl(msg, dir);
		if (!err.empty()) {
			char tmp[64];
			snprintf(tmp, sizeof(tmp), " (errno %d: %s)", errno, strerror(errno));
			err += tmp;
		}
		remove_dir(dir);
		rpc::ExecResultRawT res;
		res.id = msg.id;
		res.error = std::move(err);
		res.output = std::move(output);
		raw.msg.Set(std::move(res));
		conn_.Send(raw);
	}

	std::tuple<std::string, std::vector<uint8_t>> ExecuteBinaryImpl(rpc::ExecRequestRawT& msg, const char* dir)
	{
		// For simplicity we just wait for binary tests to complete blocking everything else.
		std::string file = std::string(dir) + "/syz-executor";
		int fd = open(file.c_str(), O_WRONLY | O_CLOEXEC | O_CREAT, 0755);
		if (fd == -1)
			return {"binary file creation failed", {}};
		ssize_t wrote = write(fd, msg.prog_data.data(), msg.prog_data.size());
		close(fd);
		if (wrote != static_cast<ssize_t>(msg.prog_data.size()))
			return {"binary file write failed", {}};

		int stdin_pipe[2];
		if (pipe(stdin_pipe))
			fail("pipe failed");
		int stdout_pipe[2];
		if (pipe(stdout_pipe))
			fail("pipe failed");

		const char* argv[] = {file.c_str(), nullptr};
		std::vector<std::pair<int, int>> fds = {
		    {stdin_pipe[0], STDIN_FILENO},
		    {stdout_pipe[1], STDOUT_FILENO},
		    {stdout_pipe[1], STDERR_FILENO},
		};
		Subprocess process(argv, fds);

		close(stdin_pipe[0]);
		close(stdout_pipe[1]);

		int status = process.WaitAndKill(5 * program_timeout_ms_);

		std::vector<uint8_t> output;
		for (;;) {
			const size_t kChunk = 1024;
			output.resize(output.size() + kChunk);
			ssize_t n = read(stdout_pipe[0], output.data() + output.size() - kChunk, kChunk);
			output.resize(output.size() - kChunk + std::max<ssize_t>(n, 0));
			if (n <= 0)
				break;
		}
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);

		return {status == kFailStatus ? "process failed" : "", std::move(output)};
	}
};

static void SigintHandler(int sig)
{
	// GCE VM preemption is signalled as SIGINT, notify syz-manager.
	exitf("SYZ-EXECUTOR: PREEMPTED");
}

static void SigchldHandler(int sig)
{
	// We need just blocking syscall preemption.
}

static void SigsegvHandler(int sig, siginfo_t* info, void* ucontext)
{
	// Print minimal debugging info we can extract reasonably easy.
	uintptr_t pc = 0xdeadbeef;
#if GOOS_linux
	auto& mctx = static_cast<ucontext_t*>(ucontext)->uc_mcontext;
	(void)mctx;
#if GOARCH_amd64
	pc = mctx.gregs[REG_RIP];
#elif GOARCH_arm64
	pc = mctx.pc;
#endif
#endif
	// Print the current function PC so that it's possible to map the failing PC
	// to a symbol in the binary offline (we usually compile as PIE).
	failmsg("SIGSEGV", "sig:%d handler:%p pc:%p addr:%p",
		sig, SigsegvHandler, reinterpret_cast<void*>(pc), info->si_addr);
}

static void runner(char** argv, int argc)
{
	if (argc != 5)
		fail("usage: syz-executor runner <name> <manager-addr> <manager-port>");
	const char* const name = argv[2];
	const char* const manager_addr = argv[3];
	const char* const manager_port = argv[4];

	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kFdLimit;
	if (setrlimit(RLIMIT_NOFILE, &rlim))
		fail("setrlimit(RLIMIT_NOFILE) failed");

	// Ignore all signals we are not interested in.
	// In particular we want to ignore SIGPIPE, but also everything else since
	// test processes manage to send random signals using tracepoints with bpf programs.
	// This is not a bullet-proof protection, but it won't harm either.
	for (int sig = 0; sig <= 64; sig++)
		signal(sig, SIG_IGN);
	if (signal(SIGINT, SigintHandler) == SIG_ERR)
		fail("signal(SIGINT) failed");
	if (signal(SIGTERM, SigintHandler) == SIG_ERR)
		fail("signal(SIGTERM) failed");
	if (signal(SIGCHLD, SigchldHandler) == SIG_ERR)
		fail("signal(SIGCHLD) failed");
	struct sigaction act = {};
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = SigsegvHandler;
	if (sigaction(SIGSEGV, &act, nullptr))
		fail("signal(SIGSEGV) failed");
	if (sigaction(SIGBUS, &act, nullptr))
		fail("signal(SIGBUS) failed");

	Connection conn(manager_addr, manager_port);

	// This is required to make Subprocess fd remapping logic work.
	// kCoverFilterFd is the largest fd we set in the child processes.
	for (int fd = conn.FD(); fd < kCoverFilterFd;)
		fd = dup(fd);

	Runner(conn, name, argv[0]);
}
