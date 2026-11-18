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

#include "rs_memory_res_sched_event_listener.h"

#ifdef RES_SCHED_ENABLE

#include <chrono>
#include <cinttypes>

#include "memory/rs_memory_manager.h"
#include "platform/common/rs_log.h"
#include "res_sched_client.h"
#include "res_value.h"

namespace OHOS::Rosen {
namespace {
constexpr uint64_t CLEAN_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

uint64_t SteadyNowMs()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
} // namespace

std::once_flag RSMemoryResSchedEventListener::createFlag_;
sptr<RSMemoryResSchedEventListener> RSMemoryResSchedEventListener::instance_ = nullptr;
std::once_flag RSMemoryResSchedEventListener::initFlag_;

sptr<RSMemoryResSchedEventListener> RSMemoryResSchedEventListener::GetInstance()
{
    std::call_once(createFlag_, []() {
        instance_ = new RSMemoryResSchedEventListener();
    });
    return instance_;
}

void RSMemoryResSchedEventListener::OnReceiveEvent(uint32_t eventType, uint32_t eventValue,
    std::unordered_map<std::string, std::string> extInfo)
{
    if (eventType == ResourceSchedule::ResType::EventType::EVENT_MIDNIGHT_CLEAN) {
        HandleMidnightClean();
    }
}

void RSMemoryResSchedEventListener::Init()
{
    // Idempotent: register the listener at most once even if Init() is called from multiple sites.
    std::call_once(initFlag_, []() {
        auto instance = GetInstance();
        if (instance == nullptr) {
            RS_LOGE("RSMemoryResSchedEventListener::Init instance is nullptr");
            return;
        }
        ResourceSchedule::ResSchedClient::GetInstance().RegisterEventListener(
            instance, ResourceSchedule::ResType::EventType::EVENT_MIDNIGHT_CLEAN);
        RS_LOGI("RSMemoryResSchedEventListener::Init register EVENT_MIDNIGHT_CLEAN listener");
    });
}

void RSMemoryResSchedEventListener::HandleMidnightClean()
{
    uint64_t nowMs = SteadyNowMs();
    {
        std::lock_guard<std::mutex> lock(lastCleanMutex_);
        // lastCleanTimeMs_ == 0 means never cleaned since boot; skip throttle so the first event
        // always triggers a clean. steady_clock starts at 0 on boot, otherwise the first 10 minutes
        // after boot would always be throttled and lastCleanTimeMs_ would stay 0 forever.
        if (lastCleanTimeMs_ != 0 && nowMs - lastCleanTimeMs_ < CLEAN_INTERVAL_MS) {
            RS_LOGD("RSMemoryResSchedEventListener::HandleMidnightClean throttled, last=%{public}" PRIu64
                " now=%{public}" PRIu64, lastCleanTimeMs_, nowMs);
            return;
        }
        lastCleanTimeMs_ = nowMs;
    }
    MemoryManager::PurgeMidnightClean();
}
} // namespace OHOS::Rosen

#endif // RES_SCHED_ENABLE
