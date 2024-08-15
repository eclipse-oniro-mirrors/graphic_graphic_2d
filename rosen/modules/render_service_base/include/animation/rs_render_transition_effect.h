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

#ifndef RENDER_SERVICE_CLIENT_CORE_TRANSITION_RS_RENDER_TRANSITION_EFFECT_H
#define RENDER_SERVICE_CLIENT_CORE_TRANSITION_RS_RENDER_TRANSITION_EFFECT_H

#include <parcel.h>
#include <refbase.h>
#include <memory>
#include <cinttypes>

#include "animation/rs_animation_common.h"
#include "animation/rs_value_estimator.h"
#include "common/rs_macros.h"
#include "modifier/rs_render_property.h"

namespace OHOS {
namespace Rosen {
class RSB_EXPORT RSRenderTransitionEffect : public Parcelable {
public:
    RSRenderTransitionEffect() = default;
    virtual ~RSRenderTransitionEffect() = default;
    const std::shared_ptr<RSRenderModifier>& GetModifier();
    virtual void UpdateFraction(float valueFraction) const = 0;

    bool Marshalling(Parcel& parcel) const override
    {
        return false;
    }
    [[nodiscard]] static RSRenderTransitionEffect* Unmarshalling(Parcel& parcel);
private:
    std::shared_ptr<RSRenderModifier> modifier_;
    virtual const std::shared_ptr<RSRenderModifier> CreateModifier() = 0;
};

class RSB_EXPORT RSTransitionFade : public RSRenderTransitionEffect {
public:
    explicit RSTransitionFade(float alpha) : alpha_(alpha) {}
    ~RSTransitionFade() override = default;
    void UpdateFraction(float valueFraction) const override;

    bool Marshalling(Parcel& parcel) const override;
    [[nodiscard]] static RSRenderTransitionEffect* Unmarshalling(Parcel& parcel);
private:
    float alpha_;
    std::shared_ptr<RSRenderAnimatableProperty<float>> property_;
    const std::shared_ptr<RSRenderModifier> CreateModifier() override;
};

class RSB_EXPORT RSTransitionScale : public RSRenderTransitionEffect {
public:
    explicit RSTransitionScale(float scaleX = 0.0f, float scaleY = 0.0f, float scaleZ = 0.0f)
        : scaleX_(scaleX), scaleY_(scaleY), scaleZ_(scaleZ)
    {}
    ~RSTransitionScale() override = default;
    void UpdateFraction(float valueFraction) const override;

    bool Marshalling(Parcel& parcel) const override;
    [[nodiscard]] static RSRenderTransitionEffect* Unmarshalling(Parcel& parcel);
private:
    float scaleX_;
    float scaleY_;
    float scaleZ_;
    std::shared_ptr<RSRenderAnimatableProperty<Vector2<float>>> property_;
    const std::shared_ptr<RSRenderModifier> CreateModifier() override;
};

class RSB_EXPORT RSTransitionTranslate : public RSRenderTransitionEffect {
public:
    explicit RSTransitionTranslate(float translateX, float translateY, float translateZ)
        : translateX_(translateX), translateY_(translateY), translateZ_(translateZ)
    {}
    ~RSTransitionTranslate() override = default;
    void UpdateFraction(float valueFraction) const override;

    bool Marshalling(Parcel& parcel) const override;
    [[nodiscard]] static RSRenderTransitionEffect* Unmarshalling(Parcel& parcel);
private:
    float translateX_;
    float translateY_;
    float translateZ_;
    std::shared_ptr<RSRenderAnimatableProperty<Vector2<float>>> property_;
    const std::shared_ptr<RSRenderModifier> CreateModifier() override;
};

class RSB_EXPORT RSTransitionRotate : public RSRenderTransitionEffect {
public:
    explicit RSTransitionRotate(float dx, float dy, float dz, float radian) : dx_(dx), dy_(dy), dz_(dz), radian_(radian)
    {}
    ~RSTransitionRotate() override = default;
    void UpdateFraction(float valueFraction) const override;

    bool Marshalling(Parcel& parcel) const override;
    [[nodiscard]] static RSRenderTransitionEffect* Unmarshalling(Parcel& parcel);
private:
    float dx_;
    float dy_;
    float dz_;
    float radian_;
    std::shared_ptr<RSRenderAnimatableProperty<Quaternion>> property_;
    const std::shared_ptr<RSRenderModifier> CreateModifier() override;
};

class RSTransitionCustom : public RSRenderTransitionEffect {
public:
    RSTransitionCustom(std::shared_ptr<RSRenderPropertyBase> property, std::shared_ptr<RSRenderPropertyBase> startValue,
        std::shared_ptr<RSRenderPropertyBase> endValue)
        : property_(property), startValue_(startValue), endValue_(endValue)
    {
        InitValueEstimator();
    }
    ~RSTransitionCustom() override = default;

    void UpdateFraction(float valueFraction) const override
    {
        if (!valueEstimator_) {
            return;
        }
        valueEstimator_->UpdateAnimationValue(valueFraction, true);
    }

private:
    const std::shared_ptr<RSRenderModifier> CreateModifier() override
    {
        return nullptr;
    }

    void InitValueEstimator()
    {
        if (valueEstimator_ == nullptr) {
            valueEstimator_ = property_->CreateRSValueEstimator(RSValueEstimatorType::CURVE_VALUE_ESTIMATOR);
        }
        valueEstimator_->InitCurveAnimationValue(property_, endValue_, startValue_, startValue_);
    }

    std::shared_ptr<RSRenderPropertyBase> property_;
    std::shared_ptr<RSRenderPropertyBase> startValue_;
    std::shared_ptr<RSRenderPropertyBase> endValue_;
    std::shared_ptr<RSValueEstimator> valueEstimator_;
};
} // namespace Rosen
} // namespace OHOS

#endif
