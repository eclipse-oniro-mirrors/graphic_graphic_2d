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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_ANIMATION_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_ANIMATION_H

#include "rs_render_particle.h"

#include "animation/rs_interpolator.h"
#include "animation/rs_render_property_animation.h"
#include "modifier/rs_property.h"
#include "common/rs_macros.h"

namespace OHOS {
namespace Rosen {
class RSB_EXPORT RSRenderParticleAnimation : public RSRenderPropertyAnimation {
public:
    RSRenderParticleAnimation(AnimationId id, const RSRenderParticle renderParticle);

    virtual ~RSRenderParticleAnimation() = default;

    bool Marshalling(Parcel& parcel) const override;

    [[nodiscard]] static RSRenderParticleAnimation* Unmarshalling(Parcel& parcel);
protected:
    bool Animate(int64_t time) override;
    void AttachRenderProperty(const std::shared_ptr<RSRenderPropertyBase>& property) override;

    // void OnSetFraction(float fraction) override;
    // void OnAnimate(float fraction) override;
    // void InitValueEstimator() override;
    // void StartRenderAnimation(const std::shared_ptr<RSNode>& target);
    // RSAnimationFraction animationFraction_;
private:
    bool ParseParam(Parcel& parcel) override;
    RSRenderParticleAnimation() = default;
    // void OnAnimateInner(float fraction, const std::shared_ptr<RSInterpolator>& interpolator);

    // std::shared_ptr<RSRenderPropertyBase> startValue_ {};
    // std::shared_ptr<RSRenderPropertyBase> endValue_ {};
    // std::shared_ptr<RSInterpolator> interpolator_ { RSInterpolator::DEFAULT };
    // inline static std::shared_ptr<RSInterpolator> linearInterpolator_ { std::make_shared<LinearInterpolator>() };

    std::vector<ParticleParams> particlesParams_;
    RSRenderParticle renderParticle_;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_ANIMATION_H
