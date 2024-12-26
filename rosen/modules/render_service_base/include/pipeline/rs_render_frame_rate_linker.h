/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_RENDER_FRAME_RATE_LINKER_H
#define RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_RENDER_FRAME_RATE_LINKER_H

#include <refbase.h>

#include "animation/rs_frame_rate_range.h"
#include "common/rs_common_def.h"
#include "common/rs_macros.h"

namespace OHOS {
namespace Rosen {
class RSIFrameRateLinkerExpectedFpsUpdateCallback;
class RSB_EXPORT RSRenderFrameRateLinker : public std::enable_shared_from_this<RSRenderFrameRateLinker> {
public:
    explicit RSRenderFrameRateLinker(FrameRateLinkerId id);
    explicit RSRenderFrameRateLinker();

    RSRenderFrameRateLinker(const RSRenderFrameRateLinker&) = delete;
    RSRenderFrameRateLinker(const RSRenderFrameRateLinker&&) = delete;
    RSRenderFrameRateLinker& operator=(const RSRenderFrameRateLinker&) = delete;
    RSRenderFrameRateLinker& operator=(const RSRenderFrameRateLinker&&) = delete;
    ~RSRenderFrameRateLinker();

    inline FrameRateLinkerId GetId() const
    {
        return id_;
    }

    inline int32_t GetAceAnimatorExpectedFrameRate() {
        return animatorExpectedFrameRate_;
    }

    void SetAnimatorExpectedFrameRate(int32_t animatorExpectedFrameRate);

    void SetExpectedRange(const FrameRateRange& range);
    const FrameRateRange& GetExpectedRange() const;
    void SetFrameRate(uint32_t rate);
    uint32_t GetFrameRate() const;

    void RegisterExpectedFpsUpdateCallback(pid_t pid, sptr<RSIFrameRateLinkerExpectedFpsUpdateCallback> callback);
private:
    static FrameRateLinkerId GenerateId();
    FrameRateLinkerId id_ = 0;
    FrameRateRange expectedRange_;
    uint32_t frameRate_ = 0;
    int32_t animatorExpectedFrameRate_ = -1;

    std::unordered_map<pid_t, sptr<RSIFrameRateLinkerExpectedFpsUpdateCallback>> expectedFpsChangeCallbacks_;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_RENDER_FRAME_RATE_LINKER_H
