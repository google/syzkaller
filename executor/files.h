// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static std::vector<std::string> Glob(const std::string& pattern)
{
	glob_t buf = {};
	buf.gl_opendir = reinterpret_cast<void* (*)(const char* name)>(opendir);
	buf.gl_closedir = reinterpret_cast<void (*)(void* dirp)>(closedir);
	// Use own readdir to ignore links. Links to files are not useful to us,
	// we will discover the target file itself. Links to directories are harmful
	// because they cause recursion, or lead outside of the target glob
	// (e.g. /proc/self/{root,cwd}).
	// However, we want to keep few links: /proc/self, /proc/thread-self,
	// /sys/kernel/slab/kmalloc-64 (may be a link with slab merging),
	// and cgroup links created in the test dir.
	// This is a hacky way to do it b/c e.g. "self" will be matched in all paths,
	// not just /proc. A proper fix would require writing completly custom version of glob
	// that would support recursion and would allow using/not using links on demand.

	buf.gl_readdir = [](void* dir) -> dirent* {
		for (;;) {
			struct dirent* ent = readdir(static_cast<DIR*>(dir));
			if (!ent || ent->d_type != DT_LNK ||
			    !strcmp(ent->d_name, "self") ||
			    !strcmp(ent->d_name, "thread-self") ||
			    !strcmp(ent->d_name, "kmalloc-64") ||
			    !strcmp(ent->d_name, "cgroup") ||
			    !strcmp(ent->d_name, "cgroup.cpu") ||
			    !strcmp(ent->d_name, "cgroup.net"))
				return ent;
		}
	};
	buf.gl_stat = stat;
	buf.gl_lstat = lstat;
	int res = glob(pattern.c_str(), GLOB_MARK | GLOB_NOSORT | GLOB_ALTDIRFUNC, nullptr, &buf);
	if (res != 0 && res != GLOB_NOMATCH)
		failmsg("glob failed", "pattern='%s' res=%d", pattern.c_str(), res);
	std::vector<std::string> files;
	for (size_t i = 0; i < buf.gl_pathc; i++) {
		const char* file = buf.gl_pathv[i];
		if (file[strlen(file) - 1] == '/')
			continue;
		files.push_back(file);
	}
	globfree(&buf);
	debug("glob %s resolved to %zu files\n", pattern.c_str(), files.size());
	return files;
}

static std::unique_ptr<rpc::FileInfoRawT> ReadFile(const std::string& file)
{
	auto info = std::make_unique<rpc::FileInfoRawT>();
	info->name = file;
	int fd = open(file.c_str(), O_RDONLY);
	if (fd == -1) {
		info->exists = errno != EEXIST && errno != ENOENT;
		info->error = strerror(errno);
	} else {
		info->exists = true;
		for (;;) {
			constexpr size_t kChunk = 4 << 10;
			info->data.resize(info->data.size() + kChunk);
			ssize_t n = read(fd, info->data.data() + info->data.size() - kChunk, kChunk);
			if (n < 0) {
				info->error = strerror(errno);
				break;
			}
			info->data.resize(info->data.size() - kChunk + n);
			if (n == 0)
				break;
		}
		close(fd);
	}
	debug("reading file %s: size=%zu exists=%d error=%s\n",
	      info->name.c_str(), info->data.size(), info->exists, info->error.c_str());
	return info;
}

static std::string ReadTextFile(const char* file_fmt, ...)
{
	char file[1024];
	va_list args;
	va_start(args, file_fmt);
	vsnprintf(file, sizeof(file), file_fmt, args);
	va_end(args);
	file[sizeof(file) - 1] = 0;
	auto data = ReadFile(file)->data;
	std::string str(data.begin(), data.end());
	while (!str.empty() && (str.back() == '\n' || str.back() == 0))
		str.resize(str.size() - 1);
	return str;
}

static std::vector<std::unique_ptr<rpc::FileInfoRawT>> ReadFiles(const std::vector<std::string>& files)
{
	std::vector<std::unique_ptr<rpc::FileInfoRawT>> results;
	for (const auto& file : files) {
		if (!strchr(file.c_str(), '*')) {
			results.push_back(ReadFile(file));
			continue;
		}
		for (const auto& match : Glob(file))
			results.push_back(ReadFile(match));
	}
	return results;
}
