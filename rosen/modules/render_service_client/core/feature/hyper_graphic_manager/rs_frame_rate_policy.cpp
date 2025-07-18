/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "feature/hyper_graphic_manager/rs_frame_rate_policy.h"

#include "modifier/rs_modifier_type.h"
#include "platform/common/rs_log.h"
#include "rs_trace.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_ui_director.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr float INCH_2_MM = 25.4f;
static constexpr auto sendConsecutiveEventInterval = std::chrono::milliseconds(1000);
}

RSFrameRatePolicy* RSFrameRatePolicy::GetInstance()
{
    static RSFrameRatePolicy instance;
    return &instance;
}

RSFrameRatePolicy::~RSFrameRatePolicy()
{
}

void RSFrameRatePolicy::RegisterHgmConfigChangeCallback()
{
    auto callback =
        [this](std::shared_ptr<RSHgmConfigData> data) { this->RSFrameRatePolicy::HgmConfigChangeCallback(data); };
    if (RSInterfaces::GetInstance().RegisterHgmConfigChangeCallback(callback) != NO_ERROR) {
        ROSEN_LOGE("RegisterHgmConfigChangeCallback failed");
    }
}

const std::unordered_set<std::string>& RSFrameRatePolicy::GetPageNameList() const
{
    return pageNameList_;
}

void RSFrameRatePolicy::HgmConfigChangeCallback(std::shared_ptr<RSHgmConfigData> configData)
{
    if (configData == nullptr) {
        ROSEN_LOGE("RSFrameRatePolicy configData is null");
        return;
    }

    pageNameList_ = configData->GetPageNameList();
    auto data = configData->GetConfigData();
    if (data.empty()) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ppi_ = configData->GetPpi();
        xDpi_ = configData->GetXDpi();
        yDpi_ = configData->GetYDpi();
        for (auto item : data) {
            if (item.animType.empty() || item.animName.empty()) {
                return;
            }
            animAttributes_[item.animType][item.animName] = {item.minSpeed, item.maxSpeed, item.preferredFps};
            ROSEN_LOGD("RSFrameRatePolicy: config item type = %{public}s, name = %{public}s, "\
                "minSpeed = %{public}d, maxSpeed = %{public}d, preferredFps = %{public}d",
                item.animType.c_str(), item.animName.c_str(), static_cast<int>(item.minSpeed),
                static_cast<int>(item.maxSpeed), static_cast<int>(item.preferredFps));
        }
    }
}

void RSFrameRatePolicy::HgmRefreshRateModeChangeCallback(int32_t refreshRateMode)
{
    RSUIDirector::PostFrameRateTask([this, refreshRateMode]() {
        ROSEN_LOGD("HgmRefreshRateModeChangeCallback refreshRateMode: %{public}d", refreshRateMode);
        currentRefreshRateModeName_ = refreshRateMode;
    });
}

int32_t RSFrameRatePolicy::GetRefreshRateModeName() const
{
    return currentRefreshRateModeName_;
}

int32_t RSFrameRatePolicy::GetPreferredFps(const std::string& scene, float speed)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (animAttributes_.count(scene) == 0 || ppi_ == 0) {
        return 0;
    }
    float speedMM = speed / ppi_ * INCH_2_MM;
    const auto& attributes = animAttributes_[scene];
    auto iter = std::find_if(attributes.begin(), attributes.end(), [&speedMM](const auto& pair) {
        return speedMM >= pair.second.minSpeed && (speedMM < pair.second.maxSpeed ||
            pair.second.maxSpeed == -1);
    });
    if (iter != attributes.end()) {
        RS_TRACE_NAME_FMT("GetPreferredFps: scene: %s, speed: %f, rate: %d",
            scene.c_str(), speedMM, iter->second.preferredFps);
        return iter->second.preferredFps;
    }
    return 0;
}

int32_t RSFrameRatePolicy::GetExpectedFrameRate(const RSPropertyUnit unit, float velocity)
{
    switch (unit) {
        case RSPropertyUnit::PIXEL_POSITION:
            return GetPreferredFps("translate", velocity);
        case RSPropertyUnit::PIXEL_SIZE:
        case RSPropertyUnit::RATIO_SCALE:
            return GetPreferredFps("scale", velocity);
        case RSPropertyUnit::ANGLE_ROTATION:
            return GetPreferredFps("rotation", velocity);
        default:
            return 0;
    }
}

bool RSFrameRatePolicy::GetTouchOrPointerAction(int32_t pointerAction)
{
    if (pointerAction == TOUCH_CANCEL || pointerAction == TOUCH_DOWN ||
        pointerAction == TOUCH_UP || pointerAction == TOUCH_BUTTON_DOWN ||
        pointerAction == TOUCH_BUTTON_UP || pointerAction == TOUCH_PULL_DOWN ||
        pointerAction == TOUCH_PULL_UP || pointerAction == AXIS_BEGIN ||
        pointerAction == AXIS_END) {
        return true;
    }
    if (pointerAction == TOUCH_MOVE || pointerAction == TOUCH_PULL_MOVE) {
        auto now = std::chrono::steady_clock::now();
        if (now - sendMoveTime_.load() >= sendConsecutiveEventInterval) {
            sendMoveTime_.store(now);
            return true;
        }
        return false;
    }
    if (pointerAction == AXIS_UPDATE) {
        auto now = std::chrono::steady_clock::now();
        if (now - sendAxisUpdateTime_.load() >= sendConsecutiveEventInterval) {
            sendAxisUpdateTime_.store(now);
            return true;
        }
        return false;
    }
    return false;
}
} // namespace Rosen
} // namespace OHOS