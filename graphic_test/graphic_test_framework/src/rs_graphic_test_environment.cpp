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

#include "rs_graphic_test_environment.h"

#include "display_manager.h"
#include <parameters.h>
#include "pipeline/rs_uni_render_judgement.h"
#include "transaction/rs_interfaces.h"

namespace OHOS {
namespace Rosen {

bool ProbeDisplayEnvironment(DisplayEnvironmentInfo& info, std::string& error)
{
    info.product = system::GetParameter("const.product.name", "unknown");
    info.bootHardware = system::GetParameter("ohos.boot.hardware", "");
    info.screenId = RSInterfaces::GetInstance().GetDefaultScreenId();
    const auto display = DisplayManager::GetInstance().GetDefaultDisplay();
    if (display == nullptr) {
        error = "cannot get default display";
        return false;
    }
    info.width = display->GetWidth();
    info.height = display->GetHeight();
    info.renderMode = RSUniRenderJudgement::IsUniRender() ? "uni" : "divided";
    if (info.width <= 0 || info.height <= 0) {
        error = "default display has invalid dimensions";
        return false;
    }
    return true;
}

bool ValidateEmulatorProduct(const DisplayEnvironmentInfo& info, std::string& error)
{
    // Stock x86_64_virt images keep const.product.name at the base default ("OpenHarmony 3.2");
    // fall back to the boot hardware so prebuilt images pass the identity check.
    if (info.product != EMULATOR_PRODUCT_NAME && info.bootHardware != EMULATOR_HARDWARE_NAME) {
        error = "unexpected product identity: " + info.product;
        return false;
    }
    if (info.renderMode != "divided") {
        error = "render mode mismatch: expected divided, actual " + info.renderMode;
        return false;
    }
    return true;
}

bool ValidateEmulatorEnvironment(const DisplayEnvironmentInfo& info, int32_t expectedWidth,
    int32_t expectedHeight, std::string& error)
{
    if (expectedWidth <= 0 || expectedHeight <= 0) {
        error = "expected display dimensions must be positive";
        return false;
    }
    if (!ValidateEmulatorProduct(info, error)) {
        return false;
    }
    if (info.width != expectedWidth || info.height != expectedHeight) {
        error = "display size mismatch: expected " + std::to_string(expectedWidth) + "x" +
            std::to_string(expectedHeight) + ", actual " + std::to_string(info.width) + "x" +
            std::to_string(info.height);
        return false;
    }
    return true;
}

} // namespace Rosen
} // namespace OHOS
