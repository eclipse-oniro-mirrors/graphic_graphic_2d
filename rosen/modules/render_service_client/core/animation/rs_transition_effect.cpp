/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "animation/rs_transition_effect.h"

#include "animation/rs_render_transition_effect.h"
#include "modifier/rs_property.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
constexpr float DEGREE_TO_RADIAN = M_PI / 180;

const std::shared_ptr<const RSTransitionEffect> RSTransitionEffect::EMPTY = RSTransitionEffect::Create();

const std::shared_ptr<const RSTransitionEffect> RSTransitionEffect::OPACITY = RSTransitionEffect::Create()->Opacity(0);

const std::shared_ptr<const RSTransitionEffect> RSTransitionEffect::SCALE =
    RSTransitionEffect::Create()->Scale({ 0.f, 0.f, 0.f });

std::shared_ptr<RSTransitionEffect> RSTransitionEffect::Create()
{
    return std::shared_ptr<RSTransitionEffect>(new RSTransitionEffect());
}

std::shared_ptr<RSTransitionEffect> RSTransitionEffect::Asymmetric(
    const std::shared_ptr<RSTransitionEffect>& transitionIn, const std::shared_ptr<RSTransitionEffect>& transitionOut)
{
    return std::shared_ptr<RSTransitionEffect>(new RSTransitionEffect(transitionIn, transitionOut));
}

RSTransitionEffect::RSTransitionEffect(
    const std::shared_ptr<RSTransitionEffect>& transitionIn, const std::shared_ptr<RSTransitionEffect>& transitionOut)
    : transitionInEffects_(transitionIn->transitionInEffects_),
      transitionOutEffects_(transitionOut->transitionOutEffects_),
      customTransitionInEffects_(transitionIn->customTransitionInEffects_),
      customTransitionOutEffects_(transitionOut->customTransitionOutEffects_)
{}

std::shared_ptr<RSTransitionEffect> RSTransitionEffect::Opacity(float opacity)
{
    static uint32_t count = 0;
    if (ROSEN_EQ(opacity, 1.0f)) {
        // 10% probability to accept
        ROSEN_LOGI_IF(((count++) % 10) == 0, "RSTransitionEffect::Opacity: Skip empty transition effect");
        return shared_from_this();
    }
    auto opacityEffect = std::make_shared<RSTransitionFade>(opacity);
    transitionInEffects_.push_back(opacityEffect);
    transitionOutEffects_.push_back(opacityEffect);
    return shared_from_this();
}

std::shared_ptr<RSTransitionEffect> RSTransitionEffect::Scale(const Vector3f& scale)
{
    if (ROSEN_EQ(scale.x_, 1.0f) && ROSEN_EQ(scale.y_, 1.0f) && ROSEN_EQ(scale.z_, 1.0f)) {
        ROSEN_LOGI("RSTransitionEffect::Scale: Skip empty transition effect");
        return shared_from_this();
    }
    auto scaleEffect = std::make_shared<RSTransitionScale>(scale.x_, scale.y_, scale.z_);
    transitionInEffects_.push_back(scaleEffect);
    transitionOutEffects_.push_back(scaleEffect);
    return shared_from_this();
}

std::shared_ptr<RSTransitionEffect> RSTransitionEffect::Translate(const Vector3f& translate)
{
    if (ROSEN_EQ(translate.x_, 0.0f) && ROSEN_EQ(translate.y_, 0.0f) && ROSEN_EQ(translate.z_, 0.0f)) {
        ROSEN_LOGI("RSTransitionEffect::Translate: Skip empty transition effect");
        return shared_from_this();
    }
    auto translateEffect = std::make_shared<RSTransitionTranslate>(translate.x_, translate.y_, translate.z_);
    transitionInEffects_.push_back(translateEffect);
    transitionOutEffects_.push_back(translateEffect);
    return shared_from_this();
}

std::shared_ptr<RSTransitionEffect> RSTransitionEffect::Rotate(const Vector4f& axisAngle)
{
    if (ROSEN_EQ(axisAngle.w_, 0.0f)) {
        ROSEN_LOGI("RSTransitionEffect::Rotate: Skip empty transition effect");
        return shared_from_this();
    }
    auto angleRadian = axisAngle.w_ * DEGREE_TO_RADIAN;
    auto rotateEffect = std::make_shared<RSTransitionRotate>(axisAngle.x_, axisAngle.y_, axisAngle.z_, angleRadian);
    transitionInEffects_.push_back(rotateEffect);
    transitionOutEffects_.push_back(rotateEffect);
    return shared_from_this();
}

std::shared_ptr<RSTransitionEffect> RSTransitionEffect::Custom(const std::shared_ptr<RSTransitionModifier>& modifier)
{
    if (modifier == nullptr) {
        ROSEN_LOGI("RSTransitionEffect::Custom: Skip empty transition effect case modifier is nullptr");
        return shared_from_this();
    }
    auto customEffect = std::make_shared<RSCustomTransitionEffect>(modifier);
    customTransitionInEffects_.push_back(customEffect);
    customTransitionOutEffects_.push_back(customEffect);
    return shared_from_this();
}

void RSCustomTransitionEffect::Custom(const std::shared_ptr<RSPropertyBase>& property,
    const std::shared_ptr<RSPropertyBase>& startValue, const std::shared_ptr<RSPropertyBase>& endValue)
{
    properties_.emplace_back(property, endValue);
    auto customEffect = std::make_shared<RSTransitionCustom>(property->GetRenderProperty(),
        startValue->GetRenderProperty(), endValue->GetRenderProperty());
    customTransitionEffects_.push_back(customEffect);
}

void RSCustomTransitionEffect::Active()
{
    if (modifier_) {
        modifier_->Active();
    }
}

void RSCustomTransitionEffect::Identity()
{
    if (modifier_) {
        modifier_->Identity();
    }
}
} // namespace Rosen
} // namespace OHOS
