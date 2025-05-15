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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_ANIMATION_MANAGER_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_ANIMATION_MANAGER_H

#include <list>
#include <memory>
#include <unordered_map>
#include <vector>

#include "common/rs_common_def.h"
#include "common/rs_macros.h"
#include "modifier/rs_modifier_type.h"
#include "rs_animation_rate_decider.h"
#include "rs_frame_rate_range.h"

namespace OHOS {
namespace Rosen {
class RSDirtyRegionManager;
class RSPaintFilterCanvas;
class RSProperties;
class RSRenderAnimation;
class RSRenderNode;

class RSB_EXPORT RSAnimationManager {
public:
    RSAnimationManager() = default;
    RSAnimationManager(const RSAnimationManager&) = delete;
    RSAnimationManager(const RSAnimationManager&&) = delete;
    RSAnimationManager& operator=(const RSAnimationManager&) = delete;
    RSAnimationManager& operator=(const RSAnimationManager&&) = delete;
    ~RSAnimationManager() = default;

    void DumpAnimations(std::string& out) const;
    void AddAnimation(const std::shared_ptr<RSRenderAnimation>& animation);
    void RemoveAnimation(AnimationId keyId);
    void CancelAnimationByPropertyId(PropertyId id);
    void AttemptCancelAnimationByAnimationId(const std::vector<AnimationId>& animations);
    const std::shared_ptr<RSRenderAnimation> GetAnimation(AnimationId id) const;
    void FilterAnimationByPid(pid_t pid);
    uint32_t GetAnimationsSize();
    pid_t GetAnimationPid() const;

    std::tuple<bool, bool, bool> Animate(
        int64_t time, int64_t& minLeftDelayTime, bool nodeIsOnTheTree, RSSurfaceNodeAbilityState abilityState);

    // spring animation related
    void RegisterSpringAnimation(PropertyId propertyId, AnimationId animId);
    void UnregisterSpringAnimation(PropertyId propertyId, AnimationId animId);
    std::shared_ptr<RSRenderAnimation> QuerySpringAnimation(PropertyId propertyId);
    // path animation related
    void RegisterPathAnimation(PropertyId propertyId, AnimationId animId);
    void UnregisterPathAnimation(PropertyId propertyId, AnimationId animId);
    std::shared_ptr<RSRenderAnimation> QueryPathAnimation(PropertyId propertyId);
    // particle animation related
    void RegisterParticleAnimation(PropertyId propertyId, AnimationId animId);
    void UnregisterParticleAnimation(PropertyId propertyId, AnimationId animId);
    const std::unordered_map<PropertyId, AnimationId>& GetParticleAnimations();
    std::shared_ptr<RSRenderAnimation> GetParticleAnimation();

    const FrameRateRange& GetFrameRateRange() const;
    const FrameRateRange& GetDecideFrameRateRange() const;

    void SetRateDeciderEnable(bool enabled, const FrameRateGetFunc& func);
    void SetRateDeciderSize(float width, float height);
    void SetRateDeciderScale(float scaleX, float scaleY);
    void SetRateDeciderAbsRect(int32_t width, int32_t height);

private:
    void OnAnimationFinished(const std::shared_ptr<RSRenderAnimation>& animation);

    std::unordered_map<AnimationId, std::shared_ptr<RSRenderAnimation>> animations_;
    std::unordered_map<PropertyId, AnimationId> springAnimations_;
    std::unordered_map<PropertyId, AnimationId> pathAnimations_;
    std::unordered_map<PropertyId, AnimationId> particleAnimations_;
    std::vector<AnimationId> pendingCancelAnimation_;
    friend class RSRenderNode;
#ifdef RS_PROFILER_ENABLED
    friend class RSProfiler;
#endif

    FrameRateRange rsRange_ = {0, 0, 0};
    RSAnimationRateDecider rateDecider_;
    FrameRateGetFunc frameRateGetFunc_;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_ANIMATION_MANAGER_H