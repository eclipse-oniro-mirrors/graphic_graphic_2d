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

#ifndef RS_GRAPHIC_TEST_FILE_H
#define RS_GRAPHIC_TEST_FILE_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Rosen {

bool ReadTextFile(const std::string& path, std::string& content, std::string* error = nullptr);
bool WriteTextFileAtomic(const std::string& path, const std::string& content, std::string* error = nullptr);
bool EnsureDirectory(const std::string& path, std::string* error = nullptr);
bool IsSafeRelativePath(const std::string& path);
bool IsSafeDevicePath(const std::string& path);
bool FileSize(const std::string& path, uint64_t& size, std::string* error = nullptr);

struct SpaceInfo {
    uint64_t availableBytes = 0;
    uint64_t requiredBytes = 0;
    uint64_t plannedImages = 0;
    uint64_t maxBytesPerImage = 0;
};

// Pure calculation used by the statvfs query and deterministic budget tests.
bool EvaluateSpaceBudget(
    uint64_t availableBytes, uint64_t plannedImages, uint64_t maxPngBytes, SpaceInfo& info, std::string& error);
bool CheckSpaceBudget(const std::string& path, uint64_t plannedImages, uint64_t maxPngBytes, std::string& error,
    SpaceInfo* info = nullptr);

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_FILE_H
