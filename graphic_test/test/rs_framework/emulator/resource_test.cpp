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

#include <filesystem>
#include <limits>
#include <set>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

#include "gtest/gtest.h"
#include "rs_graphic_test_file.h"
#include "rs_graphic_test_resource.h"
#include "rs_graphic_test_resource_table.h"

namespace OHOS {
namespace Rosen {
namespace {

constexpr uint64_t SMALL_AVAILABLE_BYTES = 99;
constexpr uint64_t PNG_BUDGET_BYTES = 100;
constexpr uint64_t OVERFLOW_MULTIPLIER = 2;

std::string UniqueName(const std::string& prefix)
{
    static uint32_t sequence = 0;
    return prefix + std::to_string(getpid()) + "_" + std::to_string(sequence++);
}

const ResourceIssue* FindIssue(const std::vector<ResourceIssue>& issues, const std::string& code)
{
    for (const ResourceIssue& issue : issues) {
        if (issue.code == code) {
            return &issue;
        }
    }
    return nullptr;
}

class ResourceTest : public testing::Test {
protected:
    void SetUp() override
    {
        root_ = std::filesystem::temp_directory_path() / UniqueName("rs_graphic_resource_");
        std::string error;
        ASSERT_TRUE(EnsureDirectory(root_.string(), &error)) << error;
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(root_, ec);
        for (const std::string& path : deviceFiles_) {
            std::filesystem::remove(path, ec);
        }
    }

    std::filesystem::path WriteLocal(const std::string& relativePath, const std::string& content)
    {
        std::filesystem::path path = root_;
        path.append(relativePath);
        std::string error;
        EXPECT_TRUE(EnsureDirectory(path.parent_path().string(), &error)) << error;
        EXPECT_TRUE(WriteTextFileAtomic(path.string(), content, &error)) << error;
        return path;
    }

    std::filesystem::path root_;
    std::vector<std::string> deviceFiles_;
};

TEST_F(ResourceTest, FileHelpersAndAtomicFailureCleanup)
{
    std::filesystem::path path = WriteLocal("nested/abc.txt", "abc");
    std::string text;
    std::string error;
    ASSERT_TRUE(ReadTextFile(path.string(), text, &error)) << error;
    EXPECT_EQ(text, "abc");
    uint64_t size = 0;
    ASSERT_TRUE(FileSize(path.string(), size, &error)) << error;
    EXPECT_EQ(size, std::string("abc").size());
    EXPECT_TRUE(WriteTextFileAtomic(path.string(), "updated", &error)) << error;
    ASSERT_TRUE(ReadTextFile(path.string(), text, &error));
    EXPECT_EQ(text, "updated");

    std::filesystem::path directoryTarget = root_ / "directory-target";
    ASSERT_TRUE(EnsureDirectory(directoryTarget.string(), &error));
    EXPECT_FALSE(WriteTextFileAtomic(directoryTarget.string(), "must fail", &error));
    for (const auto& item : std::filesystem::directory_iterator(root_)) {
        EXPECT_EQ(item.path().filename().string().find("directory-target.tmp."), std::string::npos);
    }
}

TEST_F(ResourceTest, SafePathsRejectTraversalControlAndDevicePrefixEscape)
{
    EXPECT_TRUE(IsSafeRelativePath("images/p3/test.jpg"));
    EXPECT_FALSE(IsSafeRelativePath("../outside"));
    EXPECT_FALSE(IsSafeRelativePath("images/../outside"));
    EXPECT_FALSE(IsSafeRelativePath("images//test.jpg"));
    EXPECT_FALSE(IsSafeRelativePath("images/./test.jpg"));
    EXPECT_FALSE(IsSafeRelativePath("/absolute"));
    EXPECT_FALSE(IsSafeRelativePath(std::string("bad\0path", sizeof("bad\0path") - 1)));
    EXPECT_TRUE(IsSafeDevicePath("/data/local/tmp/images/test.jpg"));
    EXPECT_FALSE(IsSafeDevicePath("/data/local/tmp/../outside"));
    EXPECT_FALSE(IsSafeDevicePath("/data/local/tmp2/test.jpg"));
    EXPECT_FALSE(IsSafeDevicePath("/tmp/test.jpg"));
}

TEST_F(ResourceTest, BuiltinTableIsValid)
{
    const auto& entries = BuiltinResourceEntries();
    EXPECT_EQ(entries.size(), 42U);
    std::set<std::string> paths;
    for (const auto& entry : entries) {
        EXPECT_TRUE(IsSafeDevicePath(entry.devicePath)) << entry.devicePath;
        EXPECT_TRUE(entry.required);
        EXPECT_TRUE(paths.insert(entry.devicePath).second) << entry.devicePath;
    }
}

TEST_F(ResourceTest, DeviceValidationRejectsInvalidAndDuplicateEntries)
{
    ResourceEntry entry;
    entry.devicePath = "/tmp/not-a-device-resource.png";
    ResourceEntry duplicate = entry;
    ResourceValidator validator;
    EXPECT_FALSE(validator.ValidateDevice({ entry, duplicate }));
    EXPECT_NE(FindIssue(validator.issues, "invalid_path"), nullptr);
    EXPECT_NE(FindIssue(validator.issues, "duplicate_device"), nullptr);
}

TEST_F(ResourceTest, MissingOptionalWarnsButMissingRequiredFails)
{
    ResourceEntry optional;
    optional.devicePath = "/data/local/tmp/optional-missing.png";
    optional.required = false;
    ResourceEntry required;
    required.devicePath = "/data/local/tmp/required-missing.png";
    required.required = true;
    ResourceValidator validator;
    EXPECT_FALSE(validator.ValidateDevice({ optional, required }));
    const ResourceIssue* warning = FindIssue(validator.issues, "missing_optional");
    ASSERT_NE(warning, nullptr);
    EXPECT_FALSE(warning->fatal);
    EXPECT_NE(FindIssue(validator.issues, "missing_required"), nullptr);
}

TEST_F(ResourceTest, DeviceValidationUsesDevicePathDirectly)
{
    std::string path = "/data/local/tmp/" + UniqueName("rs_graphic_device_") + ".png";
    deviceFiles_.push_back(path);
    std::string error;
    if (!WriteTextFileAtomic(path, "device", &error)) {
        GTEST_SKIP() << "device temporary directory unavailable: " << error;
    }
    ResourceEntry entry;
    entry.devicePath = path;
    entry.size = std::string("device").size();
    ResourceValidator validator;
    EXPECT_TRUE(validator.ValidateDevice({ entry })) << validator.issues.size();

    entry.size = entry.size + 1;
    ResourceValidator sizeValidator;
    EXPECT_FALSE(sizeValidator.ValidateDevice({ entry }));
    EXPECT_NE(FindIssue(sizeValidator.issues, "size_mismatch"), nullptr);
}

TEST_F(ResourceTest, PresenceOnlyModeAcceptsNonEmptyFileWithoutExpectedSize)
{
    std::string path = "/data/local/tmp/" + UniqueName("rs_graphic_presence_") + ".png";
    deviceFiles_.push_back(path);
    std::string error;
    if (!WriteTextFileAtomic(path, "present", &error)) {
        GTEST_SKIP() << "device temporary directory unavailable: " << error;
    }
    ResourceEntry entry;
    entry.devicePath = path;
    entry.size = 0;
    ResourceValidator validator;
    EXPECT_TRUE(validator.ValidateDevice({ entry }));
}

TEST_F(ResourceTest, ExistingOptionalResourceSizeDamageIsFatal)
{
    std::string path = "/data/local/tmp/" + UniqueName("rs_graphic_optional_") + ".png";
    deviceFiles_.push_back(path);
    std::string error;
    if (!WriteTextFileAtomic(path, "optional", &error)) {
        GTEST_SKIP() << "device temporary directory unavailable: " << error;
    }
    ResourceEntry entry;
    entry.devicePath = path;
    entry.required = false;
    entry.size = std::string("optional").size() + 1;
    ResourceValidator validator;
    EXPECT_FALSE(validator.ValidateDevice({ entry }));
    const ResourceIssue* sizeIssue = FindIssue(validator.issues, "size_mismatch");
    ASSERT_NE(sizeIssue, nullptr);
    EXPECT_TRUE(sizeIssue->fatal);
}

TEST_F(ResourceTest, EmptyFileWithoutExpectedSizeIsFatal)
{
    std::string path = "/data/local/tmp/" + UniqueName("rs_graphic_empty_") + ".png";
    deviceFiles_.push_back(path);
    std::string error;
    if (!WriteTextFileAtomic(path, "", &error)) {
        GTEST_SKIP() << "device temporary directory unavailable: " << error;
    }
    ResourceEntry entry;
    entry.devicePath = path;
    ResourceValidator validator;
    EXPECT_FALSE(validator.ValidateDevice({ entry }));
    EXPECT_NE(FindIssue(validator.issues, "empty_file"), nullptr);
}

TEST_F(ResourceTest, SymlinkEscapeIsRejected)
{
    std::string path = "/data/local/tmp/" + UniqueName("rs_graphic_link_") + ".png";
    deviceFiles_.push_back(path);
    // A dangling link fails realpath() first and is reported as "invalid_symlink", so the target must exist.
    const std::string escapeTarget = "/proc/version";
    ASSERT_TRUE(std::filesystem::exists(escapeTarget)) << "symlink target is missing: " << escapeTarget;
    std::error_code ec;
    std::filesystem::create_symlink(escapeTarget, path, ec);
    if (ec) {
        GTEST_SKIP() << "symlink unavailable: " << ec.message();
    }
    ResourceEntry entry;
    entry.devicePath = path;
    ResourceValidator validator;
    EXPECT_FALSE(validator.ValidateDevice({ entry }));
    EXPECT_NE(FindIssue(validator.issues, "symlink_escape"), nullptr);
}

TEST_F(ResourceTest, SpaceBudgetStatvfsSmallBudgetAndOverflow)
{
    SpaceInfo info;
    std::string error;
    EXPECT_TRUE(CheckSpaceBudget(root_.string(), 1, 1, error, &info)) << error;
    EXPECT_GT(info.availableBytes, 0U);
    EXPECT_EQ(info.requiredBytes, 1U);
    EXPECT_EQ(info.plannedImages, 1U);
    EXPECT_EQ(info.maxBytesPerImage, 1U);

    EXPECT_TRUE(CheckSpaceBudget((root_ / "missing/child").string(), 1, 1, error, &info)) << error;
    EXPECT_GT(info.availableBytes, 0U);

    EXPECT_FALSE(EvaluateSpaceBudget(SMALL_AVAILABLE_BYTES, 1, PNG_BUDGET_BYTES, info, error));
    EXPECT_EQ(info.requiredBytes, PNG_BUDGET_BYTES);
    EXPECT_NE(error.find("required 100"), std::string::npos);
    EXPECT_NE(error.find("available 99"), std::string::npos);
    EXPECT_FALSE(EvaluateSpaceBudget(
        std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max(), OVERFLOW_MULTIPLIER, info, error));
    EXPECT_NE(error.find("overflow"), std::string::npos);
    EXPECT_TRUE(EvaluateSpaceBudget(0, 0, std::numeric_limits<uint64_t>::max(), info, error));
}

} // namespace
} // namespace Rosen
} // namespace OHOS
