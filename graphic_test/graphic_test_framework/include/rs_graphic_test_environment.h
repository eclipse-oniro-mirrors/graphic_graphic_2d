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

#ifndef RS_GRAPHIC_TEST_ENVIRONMENT_H
#define RS_GRAPHIC_TEST_ENVIRONMENT_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Rosen {

inline constexpr int32_t EMULATOR_EXPECTED_WIDTH = 1200;
inline constexpr int32_t EMULATOR_EXPECTED_HEIGHT = 2000;
inline constexpr const char* EMULATOR_PRODUCT_NAME = "x86_64_virt";

struct DisplayEnvironmentInfo {
    std::string product = "unknown";
    uint64_t screenId = 0;
    int32_t width = 0;
    int32_t height = 0;
    std::string renderMode = "unknown";
};

bool ProbeDisplayEnvironment(DisplayEnvironmentInfo& info, std::string& error);
bool ValidateEmulatorProduct(const DisplayEnvironmentInfo& info, std::string& error);
bool ValidateEmulatorEnvironment(const DisplayEnvironmentInfo& info, int32_t expectedWidth,
    int32_t expectedHeight, std::string& error);

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_ENVIRONMENT_H
