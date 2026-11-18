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

#ifndef RS_MEMORY_RES_SCHED_EVENT_LISTENER_H
#define RS_MEMORY_RES_SCHED_EVENT_LISTENER_H

#ifdef RES_SCHED_ENABLE

#include <cstdint>
#include <mutex>

#include "nocopyable.h"
#include "res_sched_event_listener.h"

namespace OHOS::Rosen {
class RSMemoryResSchedEventListener : public ResourceSchedule::ResSchedEventListener {
public:
    static sptr<RSMemoryResSchedEventListener> GetInstance();
    ~RSMemoryResSchedEventListener() override = default;

    void OnReceiveEvent(uint32_t eventType, uint32_t eventValue,
        std::unordered_map<std::string, std::string> extInfo) override;

    void Init();

private:
    RSMemoryResSchedEventListener() = default;
    DISALLOW_COPY_AND_MOVE(RSMemoryResSchedEventListener);

    void HandleMidnightClean();

    static std::once_flag createFlag_;
    static sptr<RSMemoryResSchedEventListener> instance_;
    static std::once_flag initFlag_;

    std::mutex lastCleanMutex_;
    uint64_t lastCleanTimeMs_ { 0 };
};
} // namespace OHOS::Rosen

#endif // RES_SCHED_ENABLE
#endif // RS_MEMORY_RES_SCHED_EVENT_LISTENER_H
