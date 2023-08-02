/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "animation/rs_render_particle_animation.h"

#include <memory>

#include "animation/rs_render_particle_system.h"
#include "animation/rs_render_particle_emitter.h"
#include "animation/rs_value_estimator.h"
#include "command/rs_animation_command.h"
#include "platform/common/rs_log.h"
#include "transaction/rs_marshalling_helper.h"

namespace OHOS {
namespace Rosen {
RSRenderParticleAnimation::RSRenderParticleAnimation(AnimationId id, const RSRenderParticle renderParticle)
{ 
    renderParticle_ = renderParticle;
}

bool RSRenderParticleAnimation::Animate(int64_t time)
{
    // time 就是当前的时间，GetLastFrameTime获取上一帧的时间，
    int64_t deltaTime = time - animationFraction_.GetLastFrameTime();
    auto particleSystem = RSRenderParticleSystem(particlesParams_);

    auto particles = particleSystem->simulation(deltaTime);

    property_ = std::make_shared<RSRenderProperty<std::vector<RSRenderParticle>>>(particles, GetPropertyId());
    SetAnimationValue(property_);
    // auto particleRenderModifier = std::make_shared<RSParticleRenderModifier>(particleRenderProperty);
    // property_->SetValue(particles);
    // auto target = GetTarget();
    // if (particles.size() != 0) {
    //     // if (target) {
    //     //     target->AddModifier(particleRenderModifier);
    //     // }
        
    // } else {
    //     //particles数组中没有活动的粒子了，动画结束
    //     if (target) {
    //         target->RemoveModifier(GetPropertyId());
    //     }
    // }
}

// void RSRenderParticleAnimation::AttachRenderProperty(const std::shared_ptr<RSRenderPropertyBase>& renderProperty)
// {
//     auto particleRenderProperty = std::make_shared<RSRenderProperty<std::vector<RSRenderParticle>>>(particles, GetPropertyId());
//     auto particleRenderModifier = std::make_shared<RSParticleRenderModifier>(particleRenderProperty);
//     auto target = GetTarget();
//     if (target) {
//         target->AddModifier(particleRenderModifier);
//     }
//     // 上述流程已经在animate方法中做了
//     // 动画结束的时候将modifier清掉
//     // node->RemoveModifier(PROPERTYid);
// }

bool RSRenderParticleAnimation::Marshalling(Parcel& parcel) const 
{
    // animationId, targetId
    if (!(parcel.WriteUint64(id_))) {
        ROSEN_LOGE("RSRenderAnimation::Marshalling, write id failed");
        return false;
    }
     if (!parcel.WriteUint64(propertyId_)) {
        ROSEN_LOGE("RSRenderPropertyAnimation::Marshalling, write PropertyId failed");
        return false;
    }
    if (!(RSRenderPropertyBase::Marshalling(parcel, originValue_) &&
            RSMarshallingHelper::Marshalling(parcel, particlesParams_))) {
        ROSEN_LOGE("RSRenderPropertyAnimation::Marshalling, write value failed");
        return false;
    }
    return true;
}

RSRenderParticleAnimation* RSRenderParticleAnimation::Unmarshalling(Parcel& parcel)
{
    RSRenderParticleAnimation* renderParticleAnimation = new RSRenderParticleAnimation();
    if (!renderParticleAnimation->ParseParam(parcel)) {
        ROSEN_LOGE("RSRenderParticleAnimation::Unmarshalling, failed");
        delete renderParticleAnimation;
        return nullptr;
    }
    return renderParticleAnimation;
}

bool RSRenderParticleAnimation::ParseParam(Parcel& parcel)
{
     if (!(parcel.ReadUint64(id_) && parcel.ReadUint64(propertyId_))) {
        ROSEN_LOGE("RSRenderPropertyAnimation::ParseParam, Unmarshalling failed");
        return false;
    }
    if (!RSRenderPropertyBase::Unmarshalling(parcel, originValue_)&&
            RSMarshallingHelper::Unmarshalling(parcel, particlesParams_)) {
        return false;
    }
    return true;
}

} // namespace Rosen
} // namespace OHOS
