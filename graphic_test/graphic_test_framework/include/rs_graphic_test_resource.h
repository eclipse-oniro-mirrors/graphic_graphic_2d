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

#ifndef RS_GRAPHIC_TEST_RESOURCE_H
#define RS_GRAPHIC_TEST_RESOURCE_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
namespace Rosen {

struct ResourceEntry {
    std::string devicePath;
    bool required = true;
    // Empty size means presence-only checking; a filled size is verified exactly.
    uint64_t size = 0;
};

struct ResourceIssue {
    std::string code;
    std::string message;
    std::string devicePath;
    bool fatal = true;
};

// Device-side validation over a set of entries (the compiled-in table or test entries).
class ResourceValidator {
public:
    // Validation is read-only. A present but unreadable or damaged optional resource is still fatal.
    bool ValidateDevice(const std::vector<ResourceEntry>& entries);

    std::vector<ResourceIssue> issues;
};

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_RESOURCE_H
