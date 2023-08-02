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

#include "animation/rs_render_particle_effector.h"

#include <cmath>
#include <iostream>
#include <random>
namespace OHOS {
namespace Rosen {
RSRenderParticleEffector::RSRenderParticleEffector(ParticleParams particleParams)
{
    particleParams_ = particleParams;
}

void RSRenderParticleEffector::UpdateColor(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime)
{
    auto colorUpdator = particleParams_.GetColorUpdator();
    if (colorUpdator == ParticleUpdator::RANDOM) {
        float redSpeed = GetRandomValue(particleParams_.GetRedRandomStart(), particleParams_.GetRedRandomEnd());
        float greenSpeed = GetRandomValue(particleParams_.GetGreenRandomStart(), particleParams_.GetGreenRandomEnd());
        float blueSpeed = GetRandomValue(particleParams_.GetBlueRandomStart(), particleParams_.GetBlurRandomEnd());
        Color color = particle.GetColor();
        color.SetRed(color.GetRed() + redSpeed * deltaTime);
        color.SetGreen(color.GetGreen() + greenSpeed * deltaTime);
        color.SetBlue(color.GetBlue() + blueSpeed * deltaTime);
        particle.SetColor(color);
    } else if (colorUpdator == ParticleUpdator::CURVE) {
        auto valChangeOverLife = particleParams_.color_.valChangeOverLife_;
        for (int i = 0; i < valChangeOverLife.size(); i++) {
            auto colorCurve = valChangeOverLife[i].curve_;
            Color startValue = valChangeOverLife[i].fromValue_;
            Color endValue = valChangeOverLife[i].toValue_;
            int startTime = valChangeOverLife[i].startMillis_;
            int endTime = valChangeOverLife[i].endMillis_;
            if (activeTime >= startTime && activeTime < endTime) {
                Color value = GenerateValue(startValue, endValue, startTime, endTime, activeTime, colorCurve);
                particle.SetColor(value);
            }
        }
    }
}

void RSRenderParticleEffector::UpdateOpacity(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime)
{
    auto opacityUpdator = particleParams_.GetOpacityUpdator();
    if (opacityUpdator == ParticleUpdator::RANDOM) {
        float opacitySpeed = GetRandomValue(particleParams_.GetOpacityRandomStart(), particleParams_.GetOpacityRandomEnd());
        auto opacity = particle.GetOpacity();
        opacity += opacitySpeed * deltaTime;
        particle.SetOpacity(opacity);
    } else if (opacityUpdator == ParticleUpdator::CURVE) {
        auto valChangeOverLife = particleParams_.opacity_.valChangeOverLife_;
        for (int i = 0; i < valChangeOverLife.size(); i++) {
            auto opacityCurve = valChangeOverLife[i].curve_;
            float startValue = valChangeOverLife[i].fromValue_;
            float endValue = valChangeOverLife[i].toValue_;
            int startTime = valChangeOverLife[i].startMillis_;
            int endTime = valChangeOverLife[i].endMillis_;
            if (activeTime >= startTime && activeTime < endTime) {
                float value = GenerateValue(startValue, endValue, startTime, endTime, activeTime, opacityCurve);
                particle.SetOpacity(value);
            }
        }
    } 
    //color_.SetAlpha(color_.GetAlpha() * opacity_);
}

void RSRenderParticleEffector::UpdateScale(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime)
{
    auto scaleUpdator = particleParams_.GetScaleUpdator();
    if (scaleUpdator == ParticleUpdator::RANDOM) {
        float scaleSpeed = GetRandomValue(particleParams_.GetScaleRandomStart(), particleParams_.GetScaleRandomEnd());
        auto scale = particle.GetScale();
        scale += scaleSpeed * deltaTime;
        particle.SetScale(scale);
    } else if (scaleUpdator == ParticleUpdator::CURVE) {
        auto valChangeOverLife = particleParams_.scale_.valChangeOverLife_;
        for (int i = 0; i < valChangeOverLife.size(); i++) {
            auto scaleCurve = valChangeOverLife[i].curve_;
            float startValue = valChangeOverLife[i].fromValue_;
            float endValue = valChangeOverLife[i].toValue_;
            int startTime = valChangeOverLife[i].startMillis_;
            int endTime = valChangeOverLife[i].endMillis_;
            if (activeTime >= startTime && activeTime < endTime) {
                float value = GenerateValue(startValue, endValue, startTime, endTime, activeTime, scaleCurve);
                particle.SetScale(value);
            }
        }
    }
}
void RSRenderParticleEffector::UpdateSpin(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime)
{
    auto spinUpdator = particleParams_.GetSpinUpdator();
    if (spinUpdator == ParticleUpdator::RANDOM) {
        float spinSpeed = GetRandomValue(particleParams_.GetSpinRandomStart(), particleParams_.GetSpinRandomEnd());
        auto spin = particle.GetSpin();
        spin += spinSpeed * deltaTime;
        particle.SetSpin(spin);
    } else if (spinUpdator == ParticleUpdator::CURVE) {
        auto valChangeOverLife = particleParams_.spin_.valChangeOverLife_;
        for (int i = 0; i < valChangeOverLife.size(); i++) {
            auto spinCurve = valChangeOverLife[i].curve_;
            float startValue = valChangeOverLife[i].fromValue_;
            float endValue = valChangeOverLife[i].toValue_;
            int startTime = valChangeOverLife[i].startMillis_;
            int endTime = valChangeOverLife[i].endMillis_;
            if (activeTime >= startTime && activeTime < endTime) {
                float value = GenerateValue(startValue, endValue, startTime, endTime, activeTime, spinCurve);
                particle.SetSpin(value);
            }
        }
    }
}

void RSRenderParticleEffector::UpdateAccelerate(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime)
{
    auto acceValueUpdator = particleParams_.GetAccelerationValueUpdator();
    auto acceAngleUpdator = particleParams_.GetAccelerationAngleUpdator();
    float acceValueChange = 0.f;
    float acceAngleChange = 0.f;
    float value = 0.f;
    float Angle = 0.f;
    if (acceValueUpdator == ParticleUpdator::RANDOM) {
        float acceValueSpeed = GetRandomValue(particleParams_.GetAccelRandomValueStart(),
            particleParams_.GetAccelRandomValueEnd());
        float acceValueChange = acceValueSpeed * deltaTime;
    } else if (acceValueUpdator == ParticleUpdator::CURVE) {
        auto valChangeOverLife = particleParams_.acceleration.accelerationValue.valChangeOverLife_;
        for (int i = 0; i < valChangeOverLife.size(); i++) {
            auto acceValCurve = valChangeOverLife[i].curve;
            float startValue = valChangeOverLife[i].fromValue_;
            float endValue = valChangeOverLife[i].toValue_;
            int startTime = valChangeOverLife[i].startMillis_;
            int endTime = valChangeOverLife[i].endMillis_;
            if (activeTime >= startTime && activeTime < endTime) {
                value = GenerateValue(startValue, endValue, startTime, endTime, activeTime, acceValCurve);
            }
        }
    }
    if (acceAngleUpdator == ParticleUpdator::RANDOM) {
        float acceAngleSpeed = GetRandomValue(particleParams_.GetAccelRandomAngleStart(),
            particleParams_.GetAccelRandomAngleStart());
        float acceAngleChange = acceAngleSpeed * deltaTime;

    } else if (acceAngleUpdator == ParticleUpdator::CURVE) {
        auto valChangeOverLife = particleParams_.acceleration_.accelerationAngle.valChangeOverLife_;
        for (int i = 0; i < valChangeOverLife.size(); i++) {
            auto acceAngleCurve = valChangeOverLife[i].curve_;
            float startValue = valChangeOverLife[i].fromValue_;
            float endValue = valChangeOverLife[i].toValue_;
            int startTime = valChangeOverLife[i].startMillis_;
            int endTime = valChangeOverLife[i].endMillis_;
            if (activeTime >= startTime && activeTime < endTime) {
                Angle = GenerateValue(startValue, endValue, startTime, endTime, activeTime, acceAngleCurve);
            }
        }
    }
    if (acceValueUpdator == ParticleUpdator::RANDOM && acceAngleUpdator == ParticleUpdator::RANDOM) {
        auto acceleration = particle.GetAcceleration();
        acceleration.x_ += acceValueChange * cos(acceAngleChange);
        acceleration.y_ += acceValueChange * sin(acceAngleChange);
        particle.SetAcceleration(acceleration);
    } else if (acceValueUpdator == ParticleUpdator::CURVE && acceAngleUpdator == ParticleUpdator::CURVE) {
        // acceleration_.x_ = value * cos(Angle);
        // acceleration_.y_ = value * sin(Angle);
        particle.SetAcceleration({value * cos(Angle), value * sin(Angle)});
    } else if (acceValueUpdator == ParticleUpdator::RANDOM && acceAngleUpdator == ParticleUpdator::CURVE) {
        //待实现
    } else if (acceValueUpdator == ParticleUpdator::CURVE && acceAngleUpdator == ParticleUpdator::RANDOM) {
        //待实现
    }
}

// Apply effector to particle
void RSRenderParticleEffector::applyEffectorToParticle(RSRenderParticle& particle, int64_t deltaTime) const
{
    int64_t activeTime = particle.GetActiveTime();
    UpdateAccelerate(particle, deltaTime, activeTime);
    UpdateColor(particle, deltaTime, activeTime);
    UpdateOpacity(particle, deltaTime, activeTime);
    UpdateScale(particle, deltaTime, activeTime);
    UpdateSpin(particle, deltaTime, activeTime);

    auto acceleration = particle.GetAcceleration();
    Vector2f velocity = particle.GetVelocity();
    velocity.x_ += acceleration.x_ * deltaTime;
    velocity.y_ += acceleration.y_ * deltaTime;
    Vector2f position = particle.GetPosition();
    position.x_ += velocity.x_ * deltaTime;
    position.y_ += velocity.y_ * deltaTime;
    particle.SetVelocity(velocity);
    particle.SetPosition(position);
    float opacity = particle.GetOpacity();
    Color color = particle.GetColor();
    color.SetAlpha(color.GetAlpha() * opacity);

    auto scale = particle.GetScale();
    if (particle.GetParticleType() == ParticleType::POINTS) {
        auto radius = particle.GetRadius();
        radius *= scale;
    } else if (particle.GetParticleType() == ParticleType::IMAGES) {
        // auto rsImage = particle.GetRSImage();
        // auto width = rsImage.width_;
        // auto height = rsImage.height_;
        // width *= scale;
        // height *= scale;
        // rsImage.SetDstRect(RectF { 0.f, 0.f, width, height });
        // particle.SetRSImage(rsImage);
    }
    // 更新生存时间
    activeTime += deltaTime;
    particle.SetActiveTime(activeTime);
}

// 根据曲线类型和时间参数生成每帧的值
template<typename T>
T GenerateValue(T startValue, T endValue, int startTime, int endTime, int currentTime,
    RSAnimationTimingCurve curve)
{
    // 计算时间比例
    float t = (currentTime - startTime) / (endTime - startTime);
    auto interpolator = curve.GetInterpolator(endTime - startTime);
    float fraction = interpolator -> Interpolate(t);

    auto interpolationValue = RSValueEstimator::Estimate(fraction, startValue, endValue)

    // 根据曲线类型进行插值
    // if (curveType == LINEAR){
    //     if ( std::is_same<T, Color>::value ) {
    //         Color startColor = *reinterpret_cast<Color*>(&startValue);
    //         Color endColor = *reinterpret_cast<Color*>(&endValue);
            
    //         Color result;
    //         result.SetRed(startColor.GetRed() + t * (endColor.GetRed() - startColor.GetRed()));
    //         result.SetGreen(startColor.GetGreen() + t * (endColor.GetGreen() - startColor.GetGreen()));
    //         result.SetBlue(startColor.GetBlue() + t * (endColor.GetBlue() - startColor.GetBlue()));
    //         result.SetAlpha(startColor.GetAlpha() + t * (endColor.GetAlpha() - startColor.GetAlpha()));
    //         return *reinterpret_cast<T*>(&result);
    //     }
    //     return startValue + t * (endValue - startValue);
    // }
    return interpolationValue;
}

float GetRandomValue(float min, float max)
{
    static std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_real_distribution<float> dis(min, max);
    return dis(gen);
}


//属性之间的联动变化效果器待实现

} // namespace Rosen
} // namespace OHOS