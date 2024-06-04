// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <string.h>
#include <unistd.h>

static std::vector<std::string> Glob(const std::string& pattern)
{
	glob_t buf = {};
	int res = glob(pattern.c_str(), GLOB_MARK | GLOB_NOSORT, nullptr, &buf);
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

static std::vector<std::unique_ptr<rpc::GlobInfoRawT>> ReadGlobs(const std::vector<std::string>& patterns)
{
	std::vector<std::unique_ptr<rpc::GlobInfoRawT>> results;
	for (const auto& pattern : patterns) {
		auto info = std::make_unique<rpc::GlobInfoRawT>();
		info->name = pattern;
		info->files = Glob(pattern);
		results.push_back(std::move(info));
	}
	return results;
}
