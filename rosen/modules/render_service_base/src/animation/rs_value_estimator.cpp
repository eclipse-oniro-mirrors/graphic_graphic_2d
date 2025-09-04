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

#include "animation/rs_value_estimator.h"

#include "common/rs_common_def.h"
#include "pipeline/rs_draw_cmd_list.h"
#include "platform/common/rs_log.h"
#include "modifier/rs_render_property.h"
#include "render/rs_material_filter.h"

namespace OHOS {
namespace Rosen {

// explicit instantiation
#define DECLARE_PROPERTY(T, TYPE_ENUM)
#define DECLARE_ANIMATABLE_PROPERTY(T, TYPE_ENUM) \
    template class RSKeyframeValueEstimator<T>;   \
    template class RSCurveValueEstimator<T>;      \
    template class RSSpringValueEstimator<T>
#include "modifier/rs_property_def.in"
#undef DECLARE_PROPERTY
#undef DECLARE_ANIMATABLE_PROPERTY

Quaternion RSValueEstimator::Estimate(float fraction,
    const Quaternion& startValue, const Quaternion& endValue)
{
    auto value = startValue;
    return value.Slerp(endValue, fraction);
}

template<>
float RSCurveValueEstimator<float>::EstimateFraction(const std::shared_ptr<RSInterpolator>& interpolator)
{
    if (interpolator == nullptr) {
        ROSEN_LOGD("Interpolator is null, return FRACTION_MIN.");
        return FRACTION_MIN;
    }
    float start = FRACTION_MIN;
    float end = FRACTION_MAX;
    auto byValue = endValue_ - startValue_;
    while (end > start + EPSILON) {
        float mid = (start + end) / 2.0f;
        float fraction = interpolator->Interpolate(mid);
        auto interpolationValue = startValue_ * (1.0f - fraction) + endValue_ * fraction;
        if (lastValue_ < interpolationValue) {
            (byValue > 0) ? (end = mid) : (start = mid);
        } else {
            (byValue > 0) ? (start = mid) : (end = mid);
        }

        if (std::abs(lastValue_ - interpolationValue) <= EPSILON) {
            return mid;
        }
    }

    return FRACTION_MIN;
}

template<>
void RSCurveValueEstimator<Drawing::DrawCmdListPtr>::InitCurveAnimationValue(
    const std::shared_ptr<RSRenderPropertyBase>& property, const std::shared_ptr<RSRenderPropertyBase>& startValue,
    const std::shared_ptr<RSRenderPropertyBase>& endValue, const std::shared_ptr<RSRenderPropertyBase>& lastValue)
{
    auto animatableProperty = std::static_pointer_cast<RSRenderAnimatableProperty<Drawing::DrawCmdListPtr>>(property);
    auto animatableEndValue = std::static_pointer_cast<RSRenderAnimatableProperty<Drawing::DrawCmdListPtr>>(endValue);
    if (animatableProperty && animatableEndValue) {
        property_ = animatableProperty;
        auto rsDrawCmdList = std::make_shared<RSDrawCmdList>(animatableProperty->Get(), animatableEndValue->Get());
        animatableProperty->Set(rsDrawCmdList);
    }
}

template<>
void RSCurveValueEstimator<Drawing::DrawCmdListPtr>::UpdateAnimationValue(const float fraction, const bool isAdditive)
{
    if (property_ == nullptr) {
        return;
    }
    auto animationValue = property_->Get();
    if (animationValue && animationValue->GetType() == Drawing::CmdList::Type::RS_DRAW_CMD_LIST) {
        auto rsDrawCmdList = std::static_pointer_cast<RSDrawCmdList>(animationValue);
        rsDrawCmdList->Estimate(fraction);
        property_->Set(rsDrawCmdList);
    }
}
template class RSCurveValueEstimator<float>;
template class RSCurveValueEstimator<Drawing::DrawCmdListPtr>;
} // namespace Rosen
} // namespace OHOS
