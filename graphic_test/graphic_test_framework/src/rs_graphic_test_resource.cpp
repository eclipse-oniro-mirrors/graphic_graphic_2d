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

#include "rs_graphic_test_resource.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#include "rs_graphic_test_file.h"

namespace OHOS {
namespace Rosen {
namespace {

constexpr const char* DEVICE_ROOT = "/data/local/tmp";

void AddIssue(std::vector<ResourceIssue>& issues, const std::string& code, const std::string& message,
    const std::string& devicePath = "", bool fatal = true)
{
    issues.push_back({ code, message, devicePath, fatal });
}

bool HasFatalIssue(const std::vector<ResourceIssue>& issues)
{
    return std::any_of(issues.begin(), issues.end(), [](const ResourceIssue& issue) { return issue.fatal; });
}

bool CanonicalPath(const std::string& path, std::string& canonical)
{
    if (path.empty() || path.size() >= PATH_MAX) {
        return false;
    }
    char buffer[PATH_MAX] = {};
    if (realpath(path.c_str(), buffer) == nullptr) {
        return false;
    }
    canonical = buffer;
    return true;
}

bool IsWithinRoot(const std::string& root, const std::string& path)
{
    if (root == "/") {
        return !path.empty() && path.front() == '/';
    }
    return path.compare(0, root.size(), root) == 0 && path.size() > root.size() && path[root.size()] == '/';
}

void AddMissingIssue(const ResourceEntry& entry, int errorNumber, std::vector<ResourceIssue>& issues)
{
    if (errorNumber == ENOENT || errorNumber == ENOTDIR) {
        std::string code = entry.required ? "missing_required" : "missing_optional";
        AddIssue(issues, code, entry.required ? "required resource is missing" : "optional resource is missing",
            entry.devicePath, entry.required);
        return;
    }
    AddIssue(
        issues, "io_error", "failed to inspect resource: " + std::string(std::strerror(errorNumber)), entry.devicePath);
}

void CheckFileIdentity(const ResourceEntry& entry, const std::string& path, std::vector<ResourceIssue>& issues)
{
    if (entry.size == 0) {
        // Presence-only mode: the regular-file and non-empty checks already ran in the caller.
        return;
    }
    uint64_t actualSize = 0;
    std::string error;
    if (!FileSize(path, actualSize, &error)) {
        AddIssue(issues, "io_error", error, entry.devicePath);
        return;
    }
    if (actualSize != entry.size) {
        AddIssue(issues, "size_mismatch",
            "size mismatch: expected " + std::to_string(entry.size) + ", actual " + std::to_string(actualSize),
            entry.devicePath);
    }
}

void ValidateResourceFile(const ResourceEntry& entry, const std::string& path, std::vector<ResourceIssue>& issues)
{
    struct stat linkInfo {};
    if (lstat(path.c_str(), &linkInfo) != 0) {
        AddMissingIssue(entry, errno, issues);
        return;
    }
    std::string resolved;
    if (!CanonicalPath(path, resolved)) {
        std::string code = S_ISLNK(linkInfo.st_mode) ? "invalid_symlink" : "io_error";
        AddIssue(issues, code, "failed to resolve an existing resource: " + std::string(std::strerror(errno)),
            entry.devicePath);
        return;
    }
    if (!IsWithinRoot(DEVICE_ROOT, resolved)) {
        AddIssue(issues, "symlink_escape", "resource resolves outside its allowed root", entry.devicePath);
        return;
    }
    struct stat info {};
    if (stat(resolved.c_str(), &info) != 0) {
        AddIssue(issues, "io_error", "failed to stat resolved resource", entry.devicePath);
        return;
    }
    if (!S_ISREG(info.st_mode)) {
        AddIssue(issues, "not_regular", "resource exists but is not a regular file", entry.devicePath);
        return;
    }
    if (entry.size == 0 && info.st_size == 0) {
        AddIssue(issues, "empty_file", "resource exists but is empty and has no expected size", entry.devicePath);
        return;
    }
    CheckFileIdentity(entry, resolved, issues);
}

bool ValidateMetadata(const ResourceEntry& entry, std::vector<ResourceIssue>& issues)
{
    if (!IsSafeDevicePath(entry.devicePath)) {
        AddIssue(issues, "invalid_path", "devicePath must stay under /data/local/tmp/", entry.devicePath);
        return false;
    }
    return true;
}

} // namespace

bool ResourceValidator::ValidateDevice(const std::vector<ResourceEntry>& entries)
{
    issues.clear();
    std::set<std::string> devicePaths;
    for (const ResourceEntry& entry : entries) {
        const bool metadataValid = ValidateMetadata(entry, issues);
        if (!devicePaths.insert(entry.devicePath).second) {
            AddIssue(issues, "duplicate_device", "duplicate devicePath: " + entry.devicePath, entry.devicePath);
            continue;
        }
        if (metadataValid) {
            ValidateResourceFile(entry, entry.devicePath, issues);
        }
    }
    return !HasFatalIssue(issues);
}

} // namespace Rosen
} // namespace OHOS
