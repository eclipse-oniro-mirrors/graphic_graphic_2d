/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "frame_collector.h"

#include <cinttypes>
#include <chrono>
#include <mutex>

#include <hilog/log.h>
#include <parameter.h>

namespace OHOS {
namespace Rosen {
namespace {
constexpr ::OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD001400, "FrameCollector" };
} // namespace

FrameCollector &FrameCollector::GetInstance()
{
    if (instance == nullptr) {
        static std::mutex mutex;
        std::lock_guard lock(mutex);
        if (instance == nullptr) {
            instance = std::unique_ptr<FrameCollector>(new FrameCollector());
        }
    }
    return *instance;
}

void FrameCollector::MarkFrameEvent(const FrameEventType &type, int64_t timeNs)
{
    if (enabled_ == false) {
        return;
    }

    const auto &index = static_cast<int32_t>(type);
    if (index >= static_cast<int32_t>(FrameEventType::Max)) {
        ::OHOS::HiviewDFX::HiLog::Warn(LABEL, "FrameCollector::MarkFrameEvent index(%{public}d) not exists", index);
        return;
    }

    if (timeNs == 0) {
        timeNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    currentFrameInfo_.times[index] = timeNs;
    ::OHOS::HiviewDFX::HiLog::Warn(LABEL, "FrameCollector::MarkFrameEvent index(%{public}d) occur at %{public}" PRIi64,
                                   index, timeNs);
    std::lock_guard lock(frameQueueMutex_);
    if (type == FrameEventType::LoopEnd) {
        frameQueue_.push_back(currentFrameInfo_);
        currentFrameInfo_ = {.frameNumber = ++currentFrameNumber_};
    }

    if (frameQueue_.size() > frameQueueMaxSize) {
        frameQueue_.pop_front();
    }
}

void FrameCollector::ClearEvents()
{
    std::lock_guard lock(frameQueueMutex_);
    frameQueue_.clear();
}

FrameCollector::FrameCollector()
{
    char value[0x20];
    GetParameter(switchRenderingText, "false", value, sizeof(value));
    SwitchFunction(switchRenderingText, value, this);
    WatchParameter(switchRenderingText, SwitchFunction, this);
}

void FrameCollector::SwitchFunction(const char *key, const char *value, void *context)
{
    auto &that = *reinterpret_cast<FrameCollector *>(context);
    constexpr auto stringLength = 4;
    if (strncmp(value, switchRenderingEnableText, stringLength) == 0) {
        that.ClearEvents();
        that.enabled_ = true;
    } else {
        that.enabled_ = false;
    }
}
} // namespace Rosen
} // namespace OHOS
