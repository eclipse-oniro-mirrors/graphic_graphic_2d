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

#include "rs_graphic_test_types.h"

#include "rs_graphic_test_ext.h"

namespace OHOS {
namespace Rosen {

std::string_view GraphicCaseModeToString(GraphicCaseMode mode)
{
    switch (mode) {
        case GraphicCaseMode::AUTOMATIC:
            return "automatic";
        case GraphicCaseMode::MANUAL:
            return "manual";
        case GraphicCaseMode::DYNAMIC:
            return "dynamic";
        default:
            return "unknown";
    }
}

bool GraphicCaseModeFromString(const std::string& value, GraphicCaseMode& mode)
{
    if (value == "automatic") {
        mode = GraphicCaseMode::AUTOMATIC;
        return true;
    }
    if (value == "manual") {
        mode = GraphicCaseMode::MANUAL;
        return true;
    }
    if (value == "dynamic") {
        mode = GraphicCaseMode::DYNAMIC;
        return true;
    }
    return false;
}

GraphicCaseMode GraphicCaseModeFromTestMode(uint8_t mode)
{
    if (mode == static_cast<uint8_t>(RSGraphicTestMode::MANUAL)) {
        return GraphicCaseMode::MANUAL;
    }
    if (mode == static_cast<uint8_t>(RSGraphicTestMode::DYNAMIC)) {
        return GraphicCaseMode::DYNAMIC;
    }
    return GraphicCaseMode::AUTOMATIC;
}

bool IsAutomaticCaptureCandidate(GraphicCaseMode mode)
{
    return mode != GraphicCaseMode::MANUAL;
}

std::string MakeQualifiedCaseName(const std::string& suite, const std::string& name)
{
    return suite + "." + name;
}

} // namespace Rosen
} // namespace OHOS
