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
#include "platform/common/rs_log.h"
#include "modifier/rs_render_property.h"
#include "render/rs_material_filter.h"

namespace OHOS {
namespace Rosen {
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

template class RSCurveValueEstimator<float>;
} // namespace Rosen
} // namespace OHOS
