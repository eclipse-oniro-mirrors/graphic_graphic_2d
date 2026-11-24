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

#ifndef RENDER_SERVICE_COMPOSER_SERVICE_EXTERNAL_DEPEND_GPU_COMPOSITION_RS_FENCE_WAIT_DFX_H
#define RENDER_SERVICE_COMPOSER_SERVICE_EXTERNAL_DEPEND_GPU_COMPOSITION_RS_FENCE_WAIT_DFX_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace OHOS {
namespace Rosen {
// per-process fence wait DFX shared by the EGL and VK image managers
class FenceWaitDfx {
public:
    // fence not signaled in time means the producer (app/codec/camera) may be stuck or dead;
    // drawing continues with the possibly incomplete buffer, matching the historical behaviour
    static constexpr int32_t FENCE_WAIT_TIMEOUT_MS = 3000; // 3s
    // escalation threshold per bufferId: the same buffer timing out N times in a row
    static constexpr int32_t FENCE_CONSECUTIVE_TIMEOUT_LIMIT = 3;
    // log throttle window shared by all buffers to avoid per-frame log flooding
    static constexpr int64_t FENCE_TIMEOUT_LOG_INTERVAL_MS = 30000; // 30s

    // a successful wait clears the per-buffer consecutive count so one healthy buffer cannot mask
    // a stuck one (the global counter could never accumulate with multiple layers interleaving)
    static void ResetFenceWaitTimeoutCount(uint64_t bufferId);

    static void ReportFenceWaitTimeout(const char* caller, uint64_t bufferId, uint32_t seqNum,
        int32_t waitRet);

private:
    FenceWaitDfx();
    ~FenceWaitDfx();
    FenceWaitDfx(const FenceWaitDfx&) = delete;
    FenceWaitDfx& operator=(const FenceWaitDfx&) = delete;

    static FenceWaitDfx& Instance();

    std::mutex mutex_;
    std::unordered_map<uint64_t, int32_t> cntMap_;
    int64_t lastLogMs_ = 0;
    // number of entries in cntMap_; mutated only inside mutex_.
    // Timeouts are rare, so a zero load lets the success path skip the mutex entirely; the
    // fast path is conservative - a concurrent same-buffer timeout report may at most leave
    // a stale entry behind, which only skews a throttled DFX count
    std::atomic<size_t> cntMapSize_{0};
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_COMPOSER_SERVICE_EXTERNAL_DEPEND_GPU_COMPOSITION_RS_FENCE_WAIT_DFX_H
