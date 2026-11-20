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

#include "gpuComposition/rs_fence_wait_dfx.h"

#include <chrono>

#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
FenceWaitDfx::FenceWaitDfx() = default;

FenceWaitDfx::~FenceWaitDfx() = default;

FenceWaitDfx& FenceWaitDfx::Instance()
{
    static FenceWaitDfx instance;
    return instance;
}

void FenceWaitDfx::ResetFenceWaitTimeoutCount(uint64_t bufferId)
{
    auto& instance = Instance();
    if (instance.cntMapSize_.load(std::memory_order_acquire) == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(instance.mutex_);
    if (instance.cntMap_.erase(bufferId) != 0) {
        instance.cntMapSize_.fetch_sub(1, std::memory_order_release);
    }
}

void FenceWaitDfx::ReportFenceWaitTimeout(const char* caller, uint64_t bufferId, uint32_t seqNum,
    int32_t waitRet)
{
    auto& instance = Instance();
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    int32_t cnt = 0;
    bool isEscalated = false;
    {
        std::lock_guard<std::mutex> lock(instance.mutex_);
        auto [it, inserted] = instance.cntMap_.try_emplace(bufferId, 0);
        if (inserted) {
            instance.cntMapSize_.fetch_add(1, std::memory_order_release);
        }
        cnt = ++it->second;
        // throttle to one log per window shared across buffers; the escalation log
        // bypasses the window once so a stuck producer becomes visible
        isEscalated = cnt == FENCE_CONSECUTIVE_TIMEOUT_LIMIT;
        if (!isEscalated && instance.lastLogMs_ != 0 &&
            nowMs - instance.lastLogMs_ < FENCE_TIMEOUT_LOG_INTERVAL_MS) {
            return;
        }
        instance.lastLogMs_ = nowMs;
    }
    if (isEscalated) {
        RS_LOGE("%{public}s acquire fence wait timeout for [%{public}d] consecutive times on same buffer, "
            "producer may be stuck, bufferId:%{public}" PRIu64 ", seqNum:%{public}u, "
            "waitRet:%{public}d", caller, cnt, bufferId, seqNum, waitRet);
        return;
    }
    RS_LOGE("%{public}s acquire fence wait timeout after [%{public}d] ms, "
        "bufferId:%{public}" PRIu64 ", seqNum:%{public}u, waitRet:%{public}d, consecutiveCnt:%{public}d",
        caller, FENCE_WAIT_TIMEOUT_MS, bufferId, seqNum, waitRet, cnt);
}
} // namespace Rosen
} // namespace OHOS
