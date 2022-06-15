/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "animation/rs_spring_model.h"

#include <algorithm>
#include <cmath>

#include "common/rs_color.h"
#include "common/rs_matrix3.h"
#include "common/rs_vector2.h"
#include "common/rs_vector4.h"
#include "platform/common/rs_log.h"
#include "render/rs_filter.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr float SPRING_MIN_DAMPING_RATIO = 1e-4f;
constexpr float SPRING_MAX_DAMPING_RATIO = 1e4f;
constexpr float SPRING_MIN_DURATION = 0.02f;
constexpr float SPRING_MAX_DURATION = 300.0f;
constexpr float SPRING_MIN_RESPONSE = 1e-8;
constexpr float SPRING_MIN_AMPLITUDE = 0.001f;
// helper function to simplify estimation of spring duration
template<typename RSAnimatableType>
float toFloat(RSAnimatableType value)
{
    return 1.f;
}
template<>
float toFloat(float value)
{
    return std::fabs(value);
}
template<>
float toFloat(Vector4f value)
{
    return value.GetLength();
}
template<>
float toFloat(Quaternion value)
{
    return value.GetLength();
}
template<>
float toFloat(Vector2f value)
{
    return value.GetLength();
}
} // namespace

template<typename RSAnimatableType>
RSSpringModel<RSAnimatableType>::RSSpringModel(float response, float dampingRatio,
    const RSAnimatableType& initialOffset, const RSAnimatableType& initialVelocity, float minimumAmplitude)
    : response_(response), dampingRatio_(dampingRatio), initialOffset_(initialOffset),
      initialVelocity_(initialVelocity), minimumAmplitude_(minimumAmplitude)
{
    CalculateSpringParameters();
}

template<typename RSAnimatableType>
void RSSpringModel<RSAnimatableType>::CalculateSpringParameters()
{
    // sanity check
    dampingRatio_ = std::clamp(dampingRatio_, SPRING_MIN_DAMPING_RATIO, SPRING_MAX_DAMPING_RATIO);
    if (response_ <= 0) {
        response_ = SPRING_MIN_RESPONSE;
    }
    if (minimumAmplitude_ <= 0) {
        minimumAmplitude_ = SPRING_MIN_AMPLITUDE;
    }

    // calculate internal parameters
    double naturalAngularVelocity = 2 * M_PI / response_;
    if (dampingRatio_ < 1) { // Under-damped Systems
        dampedAngularVelocity_ = naturalAngularVelocity * sqrt(1.0f - dampingRatio_ * dampingRatio_);
        coeffDecay_ = -dampingRatio_ * naturalAngularVelocity;
        coeffScale_ =
            (initialVelocity_ + initialOffset_ * dampingRatio_ * naturalAngularVelocity) * (1 / dampedAngularVelocity_);
    } else if (dampingRatio_ == 1) { // Critically-Damped Systems
        coeffDecay_ = -naturalAngularVelocity;
        coeffScale_ = initialVelocity_ + initialOffset_ * naturalAngularVelocity;
    } else { // Over-damped Systems
        double coeffTmp = sqrt(dampingRatio_ * dampingRatio_ - 1);
        coeffDecay_ = (-dampingRatio_ + coeffTmp) * naturalAngularVelocity;
        coeffScale_ = (initialOffset_ * ((dampingRatio_ + coeffTmp) * naturalAngularVelocity) + initialVelocity_) *
                      (0.5f / (naturalAngularVelocity * coeffTmp));
        coeffScaleAlt_ = (initialOffset_ * ((coeffTmp - dampingRatio_) * naturalAngularVelocity) - initialVelocity_) *
                         (0.5f / (naturalAngularVelocity * coeffTmp));
        coeffDecayAlt_ = (-dampingRatio_ - coeffTmp) * naturalAngularVelocity;
    }
}

template<typename RSAnimatableType>
void RSSpringModel<RSAnimatableType>::EstimateDuration()
{
    if (dampingRatio_ <= 0.0f) {
        ROSEN_LOGE("RSSpringModel::%s, uninitialized spring model", __func__);
        return;
    }

    // convert templated type to float, simplify estimation of spring duration
    float coeffScale = toFloat(coeffScale_);
    float initialOffset = toFloat(initialOffset_);
    float estimatedDuration = 0.0f;

    if (dampingRatio_ < 1) { // Under-damped
        estimatedDuration = log(fmax(coeffScale, initialOffset) / minimumAmplitude_) / -coeffDecay_;
    } else if (dampingRatio_ == 1) { // Critically-damped
        // critical damping spring will rest at 2 * natural period
        estimatedDuration_ = response_ * 2;
    } else { // Over-damped
        float coeffScaleAlt = toFloat(coeffScaleAlt_);
        double durationMain =
            (coeffScale <= minimumAmplitude_) ? 0 : (log(coeffScale / minimumAmplitude_) / -coeffDecay_);
        double durationAlt =
            (coeffScaleAlt <= minimumAmplitude_) ? 0 : (log(coeffScaleAlt / minimumAmplitude_) / -coeffDecayAlt_);
        estimatedDuration = fmax(durationMain, durationAlt);
    }
    estimatedDuration_ = std::clamp(estimatedDuration, SPRING_MIN_DURATION, SPRING_MAX_DURATION);
    ROSEN_LOGD("RSSpringModel::%s estimated duration = %.5f, clamped duration = %.5f", __func__, estimatedDuration,
        estimatedDuration_);
}

template<typename RSAnimatableType>
RSAnimatableType RSSpringModel<RSAnimatableType>::CalculateDisplacement(double time) const
{
    if (dampingRatio_ <= 0.0f) {
        ROSEN_LOGE("RSSpringModel::%s, uninitialized spring model", __func__);
        return {};
    }
    double coeffDecay = exp(coeffDecay_ * time);
    if (dampingRatio_ < 1) {
        // under-damped
        double rad = dampedAngularVelocity_ * time;
        RSAnimatableType coeffPeriod = initialOffset_ * cos(rad) + coeffScale_ * sin(rad);
        return coeffPeriod * coeffDecay;
    } else if (dampingRatio_ == 1) {
        // critical-damped
        return (initialOffset_ + coeffScale_ * time) * coeffDecay;
    } else {
        // over-damped
        double coeffDecayAlt = exp(coeffDecayAlt_ * time);
        return coeffScale_ * coeffDecay + coeffScaleAlt_ * coeffDecayAlt;
    }
}

template<typename RSAnimatableType>
RSAnimatableType RSSpringModel<RSAnimatableType>::GetInstantaneousVelocity(double time) const
{
    if (dampingRatio_ == 0.0f) {
        ROSEN_LOGE("RSSpringModel::%s, uninitialized spring model", __func__);
        return {};
    }
    // 1e-6f : 1 millisecond to seconds
    constexpr double DELTA_TIME = 1e-6f;
    // we use average velocity over 2 milliseconds as instantaneous velocity
    constexpr double DURATION = DELTA_TIME * 2;
    return (CalculateDisplacement(time + DELTA_TIME) - CalculateDisplacement(time - DELTA_TIME)) * (1 / DURATION);
}

template<typename RSAnimatableType>
float RSSpringModel<RSAnimatableType>::GetEstimatedDuration()
{
    if (estimatedDuration_ < SPRING_MIN_DURATION) {
        // during not estimated yet
        EstimateDuration();
    }
    return estimatedDuration_;
}
// explicit instantiation
template class RSSpringModel<float>;
template class RSSpringModel<Color>;
template class RSSpringModel<Matrix3f>;
template class RSSpringModel<Vector2f>;
template class RSSpringModel<Vector4f>;
template class RSSpringModel<Quaternion>;
template class RSSpringModel<std::shared_ptr<RSFilter>>;
template class RSSpringModel<Vector4<Color>>;
} // namespace Rosen
} // namespace OHOS
