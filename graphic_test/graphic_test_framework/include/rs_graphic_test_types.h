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

#ifndef RS_GRAPHIC_TEST_TYPES_H
#define RS_GRAPHIC_TEST_TYPES_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace OHOS {
namespace Rosen {

enum class GraphicCaseMode : uint8_t {
    AUTOMATIC,
    MANUAL,
    DYNAMIC,
};

struct GraphicTestCaseInfo {
    std::string suite;
    std::string name;
    std::string type;
    GraphicCaseMode mode = GraphicCaseMode::AUTOMATIC;
    bool isMultiple = false;
    std::string sourcePath;
};

struct GraphicCatalogSummary {
    size_t suites = 0;
    size_t cases = 0;
    size_t automatic = 0;
    size_t manual = 0;
    size_t dynamic = 0;
    size_t multiple = 0;
};

std::string_view GraphicCaseModeToString(GraphicCaseMode mode);
bool GraphicCaseModeFromString(const std::string& value, GraphicCaseMode& mode);
GraphicCaseMode GraphicCaseModeFromTestMode(uint8_t mode);
bool IsAutomaticCaptureCandidate(GraphicCaseMode mode);
std::string MakeQualifiedCaseName(const std::string& suite, const std::string& name);

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_TYPES_H
