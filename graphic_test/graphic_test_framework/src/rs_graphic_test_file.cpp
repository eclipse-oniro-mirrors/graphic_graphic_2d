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

#include "rs_graphic_test_file.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <vector>

namespace OHOS {
namespace Rosen {
namespace {

constexpr size_t IO_BUFFER_SIZE = 16384;
constexpr const char* DEVICE_ROOT_PREFIX = "/data/local/tmp/";

void SetError(std::string* error, const std::string& message)
{
    if (error != nullptr) {
        *error = message;
    }
}

bool HasControlCharacter(const std::string& path)
{
    return std::any_of(path.begin(), path.end(), [](unsigned char ch) { return std::iscntrl(ch) != 0; });
}

bool HasParentTraversal(const std::string& path)
{
    size_t start = 0;
    for (size_t end = 0; end <= path.size(); ++end) {
        if (end != path.size() && path[end] != '/') {
            continue;
        }
        if (path.substr(start, end - start) == "..") {
            return true;
        }
        start = end + 1;
    }
    return false;
}

bool IsUsableFilePath(const std::string& path, std::string* error)
{
    if (path.empty() || HasControlCharacter(path) || HasParentTraversal(path)) {
        SetError(error, "path is empty, contains control characters, or contains parent traversal");
        return false;
    }
    return true;
}

bool WriteAll(int fd, const std::string& content)
{
    size_t offset = 0;
    while (offset < content.size()) {
        size_t chunk = std::min(IO_BUFFER_SIZE, content.size() - offset);
        ssize_t written = write(fd, content.data() + offset, chunk);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return true;
}

bool AtomicFailure(int fd, const std::string& tempPath, int savedErrno, std::string* error)
{
    if (fd >= 0) {
        close(fd);
    }
    unlink(tempPath.c_str());
    SetError(error, "atomic write failed: " + std::string(std::strerror(savedErrno)));
    return false;
}

bool MultiplyUint64(uint64_t left, uint64_t right, uint64_t& result)
{
    if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left) {
        return false;
    }
    result = left * right;
    return true;
}

std::filesystem::path FindExistingDirectory(const std::string& path)
{
    std::filesystem::path current(path);
    std::error_code filesystemError;
    while (!current.empty() && !std::filesystem::exists(current, filesystemError)) {
        const auto parent = current.parent_path();
        if (parent == current) {
            break;
        }
        current = parent;
        filesystemError.clear();
    }
    return current;
}

} // namespace

bool IsSafeRelativePath(const std::string& path)
{
    if (path.empty() || path.front() == '/' || HasControlCharacter(path)) {
        return false;
    }
    size_t start = 0;
    for (size_t end = 0; end <= path.size(); ++end) {
        if (end != path.size() && path[end] != '/') {
            continue;
        }
        std::string component = path.substr(start, end - start);
        if (component.empty() || component == "." || component == "..") {
            return false;
        }
        start = end + 1;
    }
    return true;
}

bool IsSafeDevicePath(const std::string& path)
{
    if (path.compare(0, std::strlen(DEVICE_ROOT_PREFIX), DEVICE_ROOT_PREFIX) != 0) {
        return false;
    }
    return IsSafeRelativePath(path.substr(std::strlen(DEVICE_ROOT_PREFIX)));
}

bool ReadTextFile(const std::string& path, std::string& content, std::string* error)
{
    content.clear();
    SetError(error, "");
    if (!IsUsableFilePath(path, error)) {
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        SetError(error, "failed to open " + path + ": " + std::strerror(errno));
        return false;
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (input.bad()) {
        SetError(error, "failed to read " + path);
        return false;
    }
    content = buffer.str();
    return true;
}

bool WriteTextFileAtomic(const std::string& path, const std::string& content, std::string* error)
{
    SetError(error, "");
    if (!IsUsableFilePath(path, error)) {
        return false;
    }
    std::string tempTemplate = path + ".tmp.XXXXXX";
    std::vector<char> tempPath(tempTemplate.begin(), tempTemplate.end());
    tempPath.push_back('\0');
    int fd = mkstemp(tempPath.data());
    if (fd < 0) {
        SetError(error, "failed to create temporary file: " + std::string(std::strerror(errno)));
        return false;
    }
    std::string tempName(tempPath.data());
    if (!WriteAll(fd, content)) {
        return AtomicFailure(fd, tempName, errno, error);
    }
    if (fsync(fd) != 0) {
        return AtomicFailure(fd, tempName, errno, error);
    }
    if (close(fd) != 0) {
        return AtomicFailure(-1, tempName, errno, error);
    }
    if (std::rename(tempName.c_str(), path.c_str()) != 0) {
        return AtomicFailure(-1, tempName, errno, error);
    }
    return true;
}

bool EnsureDirectory(const std::string& path, std::string* error)
{
    SetError(error, "");
    if (!IsUsableFilePath(path, error)) {
        return false;
    }
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        return true;
    }
    std::filesystem::create_directories(path, ec);
    if (!ec && std::filesystem::is_directory(path, ec)) {
        return true;
    }
    SetError(error, "failed to ensure directory " + path + ": " + (ec ? ec.message() : "path is not a directory"));
    return false;
}

bool FileSize(const std::string& path, uint64_t& size, std::string* error)
{
    size = 0;
    SetError(error, "");
    if (!IsUsableFilePath(path, error)) {
        return false;
    }
    struct stat info {};
    if (stat(path.c_str(), &info) != 0) {
        SetError(error, "failed to stat " + path + ": " + std::strerror(errno));
        return false;
    }
    if (!S_ISREG(info.st_mode) || info.st_size < 0) {
        SetError(error, "not a regular file: " + path);
        return false;
    }
    size = static_cast<uint64_t>(info.st_size);
    return true;
}

bool EvaluateSpaceBudget(
    uint64_t availableBytes, uint64_t plannedImages, uint64_t maxPngBytes, SpaceInfo& info, std::string& error)
{
    error.clear();
    info = { availableBytes, 0, plannedImages, maxPngBytes };
    if (!MultiplyUint64(plannedImages, maxPngBytes, info.requiredBytes)) {
        error = "space budget overflow: plannedImages * maxPngBytes exceeds uint64_t";
        return false;
    }
    if (info.requiredBytes > info.availableBytes) {
        error = "insufficient space: required " + std::to_string(info.requiredBytes) + " bytes, available " +
                std::to_string(info.availableBytes) + " bytes";
        return false;
    }
    return true;
}

bool CheckSpaceBudget(
    const std::string& path, uint64_t plannedImages, uint64_t maxPngBytes, std::string& error, SpaceInfo* info)
{
    error.clear();
    SpaceInfo current {};
    if (info != nullptr) {
        *info = current;
    }
    if (!IsUsableFilePath(path, &error)) {
        return false;
    }
    const auto statPath = FindExistingDirectory(path);
    if (statPath.empty()) {
        error = "cannot find an existing parent directory for " + path;
        return false;
    }
    struct statvfs filesystemInfo {};
    if (statvfs(statPath.c_str(), &filesystemInfo) != 0) {
        error = "statvfs failed for " + statPath.string() + ": " + std::strerror(errno);
        return false;
    }
    if (!MultiplyUint64(static_cast<uint64_t>(filesystemInfo.f_bavail), static_cast<uint64_t>(filesystemInfo.f_frsize),
            current.availableBytes)) {
        error = "available space calculation overflow";
        return false;
    }
    bool result = EvaluateSpaceBudget(current.availableBytes, plannedImages, maxPngBytes, current, error);
    if (info != nullptr) {
        *info = current;
    }
    return result;
}

} // namespace Rosen
} // namespace OHOS
