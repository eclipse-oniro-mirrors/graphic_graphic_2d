/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

#include "animation/rs_steps_interpolator.h"

#include <algorithm>
#include <cmath>

#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
RSStepsInterpolator::RSStepsInterpolator(int32_t steps, StepsCurvePosition position)
    :steps_(steps <= 0 ? 1 : steps), position_(position){}

#ifdef ROSEN_OHOS
bool RSStepsInterpolator::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteUint16(InterpolatorType::STEPS)) {
        ROSEN_LOGE("RSStepsInterpolator::Marshalling, Write type failed");
        return false;
    }
    if (!(parcel.WriteInt32(steps_) && parcel.WriteInt32(static_cast<int32_t>(position_)))) {
        ROSEN_LOGE("RSStepsInterpolator::Marshalling, Write value failed");
        return false;
    }
    return true;
}

RSStepsInterpolator* RSStepsInterpolator::Unmarshalling(Parcel& parcel)
{
    int32_t steps, position;
    if (!(parcel.ReadInt32(steps) && parcel.ReadInt32(position))) {
        ROSEN_LOGE("RSStepsInterpolator::Unmarshalling, StepsInterpolator failed");
        return nullptr;
    }
    auto ret = new RSStepsInterpolator(steps, static_cast<StepsCurvePosition>(position));
    return ret;
}
#endif

float RSStepsInterpolator::Interpolate(float time) const
{
    if (time < fractionMin || time > fractionMax) {
        ROSEN_LOGE("StepsCurve MoveInternal: time is less than 0 or larger than 1, return 1");
        return fractionMax;
    }
    auto currentStep = static_cast<int32_t>(time * steps_);
    if (position_ == StepsCurvePosition::START) {
        currentStep++;
    }
    return static_cast<float>(currentStep) / steps_;
}
} // namespace Rosen
} // namespace OHOS
