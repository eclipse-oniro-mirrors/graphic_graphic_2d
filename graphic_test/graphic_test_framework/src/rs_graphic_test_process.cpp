/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "rs_graphic_test_process.h"

#include <cerrno>
#include <csignal>
#include <ctime>
#include <fcntl.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>
#include <utility>


namespace OHOS {
namespace Rosen {
namespace {

constexpr int MINIMUM_FD = 3;
constexpr int POLL_INTERVAL_MS = 10;
constexpr int NANOSECONDS_PER_MILLISECOND = 1000000;
constexpr int NANOSECONDS_PER_SECOND = 1000000000;
constexpr int MILLISECONDS_PER_SECOND = 1000;
constexpr mode_t LOG_FILE_MODE = 0600;

#if defined(__APPLE__) || defined(__OHOS__) || \
    (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 29)))
#define RS_GRAPHIC_TEST_HAS_SPAWN_CHDIR_NP 1
#else
#define RS_GRAPHIC_TEST_HAS_SPAWN_CHDIR_NP 0
#endif

#if defined(__OHOS__)
// Some OHOS libc versions omit this extension. A weak reference turns that into a runtime ENOTSUP error.
extern "C" int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t* actions, const char* path)
    __attribute__((weak));
#endif

class ScopedFd {
public:
    explicit ScopedFd(int fd) : fd_(fd) {}
    ~ScopedFd()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

private:
    int fd_;
};

class ScopedSpawnAttributes {
public:
    ScopedSpawnAttributes() : error_(posix_spawnattr_init(&attributes_)) {}
    ~ScopedSpawnAttributes()
    {
        if (error_ == 0) {
            posix_spawnattr_destroy(&attributes_);
        }
    }
    int Error() const
    {
        return error_;
    }
    posix_spawnattr_t* Get()
    {
        return &attributes_;
    }

private:
    posix_spawnattr_t attributes_;
    int error_;
};

class ScopedSpawnFileActions {
public:
    ScopedSpawnFileActions() : error_(posix_spawn_file_actions_init(&actions_)) {}
    ~ScopedSpawnFileActions()
    {
        if (error_ == 0) {
            posix_spawn_file_actions_destroy(&actions_);
        }
    }
    int Error() const
    {
        return error_;
    }
    posix_spawn_file_actions_t* Get()
    {
        return &actions_;
    }

private:
    posix_spawn_file_actions_t actions_;
    int error_;
};

struct SpawnVectors {
    std::vector<std::string> argumentStorage;
    std::vector<std::string> environmentStorage;
    std::vector<char*> argv;
    std::vector<char*> envp;
};

std::string ErrorText(int error)
{
    return std::to_string(error) + " (" + std::generic_category().message(error) + ")";
}

void SetError(ProcessResult& result, int error, const std::string& context)
{
    result.spawnError = error;
    result.error = context + ": " + ErrorText(error);
}

void AppendError(ProcessResult& result, const char* context, int error)
{
    if (!result.error.empty()) {
        result.error += "; ";
    }
    result.error += context;
    result.error += ": " + ErrorText(error);
}

bool HasEmbeddedNul(const std::string& value)
{
    return value.find('\0') != std::string::npos;
}

bool ValidateSpec(const ProcessSpec& spec, std::string& error)
{
    if (spec.executable.empty() || HasEmbeddedNul(spec.executable)) {
        error = "executable must be non-empty and contain no NUL";
        return false;
    }
    if (spec.logPath.empty() || HasEmbeddedNul(spec.logPath)) {
        error = "logPath must be non-empty and contain no NUL";
        return false;
    }
    if (spec.timeoutMs == 0) {
        error = "timeoutMs must be greater than zero";
        return false;
    }
    if (HasEmbeddedNul(spec.workingDirectory)) {
        error = "workingDirectory contains NUL";
        return false;
    }
    for (const auto& argument : spec.args) {
        if (HasEmbeddedNul(argument)) {
            error = "argument contains NUL";
            return false;
        }
    }
    for (const auto& [name, value] : spec.environment) {
        if (name.empty() || name.find('=') != std::string::npos || HasEmbeddedNul(name) || HasEmbeddedNul(value)) {
            error = "environment names must be non-empty and contain no '=' or NUL; values contain no NUL";
            return false;
        }
    }
    return true;
}

int OpenLogFile(const std::string& path)
{
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, LOG_FILE_MODE);
    if (fd < 0 || fd >= MINIMUM_FD) {
        return fd;
    }
    const int movedFd = fcntl(fd, F_DUPFD_CLOEXEC, MINIMUM_FD);
    const int savedErrno = errno;
    close(fd);
    errno = savedErrno;
    return movedFd;
}

int AddWorkingDirectory(posix_spawn_file_actions_t* actions, const std::string& directory)
{
    if (directory.empty()) {
        return 0;
    }
#if RS_GRAPHIC_TEST_HAS_SPAWN_CHDIR_NP
#if defined(__OHOS__)
    if (posix_spawn_file_actions_addchdir_np == nullptr) {
        return ENOTSUP;
    }
#endif
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    const int error = posix_spawn_file_actions_addchdir_np(actions, directory.c_str());
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic pop
#endif
    return error;
#else
    return ENOTSUP;
#endif
}

int PrepareFileActions(posix_spawn_file_actions_t* actions, int logFd, const std::string& workingDirectory)
{
    int error = posix_spawn_file_actions_adddup2(actions, logFd, STDOUT_FILENO);
    if (error != 0) {
        return error;
    }
    error = posix_spawn_file_actions_adddup2(actions, logFd, STDERR_FILENO);
    if (error != 0) {
        return error;
    }
    if (logFd >= MINIMUM_FD) {
        error = posix_spawn_file_actions_addclose(actions, logFd);
        if (error != 0) {
            return error;
        }
    }
    return AddWorkingDirectory(actions, workingDirectory);
}

std::vector<char*> MakePointers(std::vector<std::string>& storage)
{
    std::vector<char*> pointers;
    pointers.reserve(storage.size() + 1);
    for (auto& value : storage) {
        pointers.push_back(const_cast<char*>(value.c_str()));
    }
    pointers.push_back(nullptr);
    return pointers;
}

void BuildEnvironment(const ProcessEnvironment& overrides, std::vector<std::string>& storage)
{
    if (environ != nullptr) {
        for (size_t index = 0; environ[index] != nullptr; ++index) {
            const std::string entry = environ[index];
            const auto separator = entry.find('=');
            const std::string name = entry.substr(0, separator);
            if (overrides.find(name) == overrides.end()) {
                storage.push_back(entry);
            }
        }
    }
    for (const auto& [name, value] : overrides) {
        storage.push_back(name + "=" + value);
    }
}

void BuildSpawnVectors(const ProcessSpec& spec, SpawnVectors& vectors)
{
    vectors.argumentStorage.reserve(spec.args.size() + 1);
    vectors.argumentStorage.push_back(spec.executable);
    vectors.argumentStorage.insert(vectors.argumentStorage.end(), spec.args.begin(), spec.args.end());
    BuildEnvironment(spec.environment, vectors.environmentStorage);
    vectors.argv = MakePointers(vectors.argumentStorage);
    vectors.envp = MakePointers(vectors.environmentStorage);
}

bool SpawnProcess(const ProcessSpec& spec, pid_t& pid, ProcessResult& result)
{
    ScopedSpawnFileActions actions;
    ScopedSpawnAttributes attributes;
    if (actions.Error() != 0 || attributes.Error() != 0) {
        const int initializationError = actions.Error() != 0 ? actions.Error() : attributes.Error();
        SetError(result, initializationError, "posix_spawn initialization failed");
        return false;
    }
    const int logFd = OpenLogFile(spec.logPath);
    if (logFd < 0) {
        const int openError = errno;
        SetError(result, openError, "cannot open process log " + spec.logPath);
        return false;
    }
    ScopedFd logGuard(logFd);
    int error = PrepareFileActions(actions.Get(), logFd, spec.workingDirectory);
    if (error == 0) {
        error = posix_spawnattr_setpgroup(attributes.Get(), 0);
    }
    if (error == 0) {
        error = posix_spawnattr_setflags(attributes.Get(), POSIX_SPAWN_SETPGROUP);
    }
    if (error != 0) {
        SetError(result, error, "cannot configure posix_spawn");
        return false;
    }
    SpawnVectors vectors;
    BuildSpawnVectors(spec, vectors);
    error = posix_spawn(
        &pid, spec.executable.c_str(), actions.Get(), attributes.Get(), vectors.argv.data(), vectors.envp.data());
    if (error != 0) {
        SetError(result, error, "posix_spawn failed for " + spec.executable);
        return false;
    }
    return true;
}

uint64_t ElapsedMilliseconds(const timespec& start, const timespec& now)
{
    if (now.tv_sec < start.tv_sec || (now.tv_sec == start.tv_sec && now.tv_nsec < start.tv_nsec)) {
        return 0;
    }
    int64_t seconds = static_cast<int64_t>(now.tv_sec - start.tv_sec);
    int64_t nanoseconds = static_cast<int64_t>(now.tv_nsec) - start.tv_nsec;
    if (nanoseconds < 0) {
        --seconds;
        nanoseconds += NANOSECONDS_PER_SECOND;
    }
    const uint64_t wholeMilliseconds = static_cast<uint64_t>(seconds) * MILLISECONDS_PER_SECOND;
    return wholeMilliseconds + static_cast<uint64_t>(nanoseconds / NANOSECONDS_PER_MILLISECOND);
}

void DecodeWaitStatus(int status, ProcessResult& result)
{
    if (WIFEXITED(status)) {
        result.exitCode = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.termSignal = WTERMSIG(status);
    } else {
        AppendError(result, "waitpid returned an unexpected process state", 0);
    }
}

enum class WaitState {
    RUNNING,
    REAPED,
    ERROR,
};

WaitState PollChild(pid_t pid, int& status, int& error)
{
    pid_t waited;
    do {
        waited = waitpid(pid, &status, WNOHANG);
    } while (waited < 0 && errno == EINTR);
    if (waited == pid) {
        return WaitState::REAPED;
    }
    if (waited == 0) {
        return WaitState::RUNNING;
    }
    error = errno;
    return WaitState::ERROR;
}

void ReapAfterKill(pid_t pid, ProcessResult& result)
{
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited == pid) {
        DecodeWaitStatus(status, result);
    } else {
        AppendError(result, "waitpid failed while reaping killed child", errno);
    }
}

void KillAndReap(pid_t pid, ProcessResult& result)
{
    // pgroup == child pid. The group belongs to this child; never signal the runner's own process group.
    if (kill(-pid, SIGKILL) != 0 && errno != ESRCH) {
        AppendError(result, "cannot kill child process group", errno);
        if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
            AppendError(result, "cannot kill child process", errno);
        }
    }
    // Only the direct child is waitable here. Descendants remain group-kill targets, not owned waitpid subjects.
    ReapAfterKill(pid, result);
}

void SleepForPollInterval()
{
    timespec request = { 0, POLL_INTERVAL_MS * NANOSECONDS_PER_MILLISECOND };
    timespec remaining = {};
    while (nanosleep(&request, &remaining) != 0 && errno == EINTR) {
        request = remaining;
    }
}

// One poll of the child. Returns true once the child is reaped, killed or can no longer be waited for.
bool PollChildOnce(pid_t pid, const ProcessSpec& spec, const timespec& start, ProcessResult& result)
{
    int status = 0;
    int waitError = 0;
    const WaitState state = PollChild(pid, status, waitError);
    if (state == WaitState::REAPED) {
        DecodeWaitStatus(status, result);
        return true;
    }
    if (state == WaitState::ERROR) {
        AppendError(result, "waitpid failed", waitError);
        return true;
    }
    timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        AppendError(result, "CLOCK_MONOTONIC failed; killing child", errno);
        KillAndReap(pid, result);
        return true;
    }
    if (ElapsedMilliseconds(start, now) >= spec.timeoutMs) {
        result.timedOut = true;
        KillAndReap(pid, result);
        return true;
    }
    return false;
}

void WaitForProcess(pid_t pid, const ProcessSpec& spec, const timespec& start, ProcessResult& result)
{
    // Bounded by spec.timeoutMs: PollChildOnce kills and reaps the child once the timeout is reached.
    bool finished = PollChildOnce(pid, spec, start, result);
    while (!finished) {
        SleepForPollInterval();
        finished = PollChildOnce(pid, spec, start, result);
    }
}

void UpdateDuration(const timespec& start, ProcessResult& result)
{
    timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        result.durationMs = ElapsedMilliseconds(start, now);
    } else {
        AppendError(result, "cannot read final CLOCK_MONOTONIC value", errno);
    }
}

} // namespace

ProcessResult PosixProcessController::Run(const ProcessSpec& spec)
{
    ProcessResult result;
    timespec start = {};
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        SetError(result, errno, "CLOCK_MONOTONIC is required");
        return result;
    }
    std::string validationError;
    if (!ValidateSpec(spec, validationError)) {
        SetError(result, EINVAL, validationError);
        UpdateDuration(start, result);
        return result;
    }
    pid_t pid = 0;
    if (SpawnProcess(spec, pid, result)) {
        WaitForProcess(pid, spec, start, result);
    }
    UpdateDuration(start, result);
    return result;
}

} // namespace Rosen
} // namespace OHOS
