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

#include "rs_graphic_test_health.h"

#include "display_manager.h"
#include "screen_manager/screen_types.h"
#include "transaction/rs_interfaces.h"

namespace OHOS {
namespace Rosen {

EmulatorHealthStatus DefaultEmulatorHealthProbe::Check()
{
    EmulatorHealthStatus status;
    const ScreenId screenId = RSInterfaces::GetInstance().GetDefaultScreenId();
    status.rsAlive = screenId != INVALID_SCREEN_ID &&
        RSInterfaces::GetInstance().GetConnectToRenderToken(screenId) != nullptr;
    status.screenOn = status.rsAlive && RSInterfaces::GetInstance().GetScreenPowerStatus(screenId) ==
        ScreenPowerStatus::POWER_STATUS_ON;
    status.screenUnlocked = DisplayManager::GetInstance().GetDisplayState(
        DisplayManager::GetInstance().GetDefaultDisplayId()) == DisplayState::ON;
    return status;
}

bool ValidateSuiteHealth(const EmulatorHealthStatus& status, std::string& error)
{
    if (!status.rsAlive) {
        error = "render service is unavailable";
        return false;
    }
    if (!status.screenOn) {
        error = "screen is not powered on";
        return false;
    }
    if (!status.screenUnlocked) {
        error = "screen is locked";
        return false;
    }
    return true;
}

} // namespace Rosen
} // namespace OHOS
