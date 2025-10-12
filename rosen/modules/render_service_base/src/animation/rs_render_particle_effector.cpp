/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifdef ENABLE_RUST
#include "cxx.h"
#include "lib.rs.h"
#endif

#include "animation/rs_value_estimator.h"
namespace OHOS {
namespace Rosen {
constexpr float DEGREE_TO_RADIAN = M_PI / 180;
RSRenderParticleEffector::RSRenderParticleEffector() {}

Vector4<int16_t> RSRenderParticleEffector::CalculateColorInt(const std::shared_ptr<RSRenderParticle>& particle,
    Vector4<int16_t> colorInt, Vector4<float> colorF, Vector4<float> colorSpeed, float deltaTime)
{
    for (int i = 0; i < 4; i++) { // 4 is color tunnel count
        if (!((colorInt.data_[i] <= 0 && colorSpeed.data_[i] <= 0.f) ||
                (colorInt.data_[i] >= UINT8_MAX && colorSpeed.data_[i] >= 0.f))) {
            colorF.data_[i] += colorSpeed.data_[i] * deltaTime;
            if (std::abs(colorF.data_[i]) >= 1.f) {
                colorInt.data_[i] += static_cast<int16_t>(colorF.data_[i]);
                colorF.data_[i] -= std::floor(colorF.data_[i]);
            }
            if (particle != nullptr) {
                particle->SetRedF(colorF.data_[i]);
            }
            colorInt.data_[i] = std::clamp<int16_t>(colorInt.data_[i], 0, UINT8_MAX);
        }
    }
    return colorInt;
}

void RSRenderParticleEffector::UpdateCurveValue(
    float& value, const std::vector<std::shared_ptr<ChangeInOverLife<float>>>& valChangeOverLife, int64_t activeTime)
{
    for (size_t i = 0; i < valChangeOverLife.size(); i++) {
        if (valChangeOverLife[i] != nullptr) {
            int startTime = valChangeOverLife[i]->startMillis_;
            int endTime = valChangeOverLife[i]->endMillis_;
            if (activeTime < startTime || activeTime > endTime) {
                continue;
            }
            float startValue = valChangeOverLife[i]->fromValue_;
            float endValue = valChangeOverLife[i]->toValue_;
#ifdef ENABLE_RUST
            value = generate_value(startValue, endValue, startTime, endTime, activeTime);
#else
            if (endTime - startTime > 0) {
                float t = static_cast<float>(activeTime - startTime) / static_cast<float>(endTime - startTime);
                auto& interpolator = valChangeOverLife[i]->interpolator_;
                t = (interpolator != nullptr) ? interpolator->Interpolate(t) : t;
                value = startValue * (1.0f - t) + endValue * t;
            }
#endif
            break;
        }
    }
}

void RSRenderParticleEffector::UpdateColorCurveValue(
    Color& color, const std::vector<std::shared_ptr<ChangeInOverLife<Color>>>& valChangeOverLife, int64_t activeTime)
{
    for (size_t i = 0; i < valChangeOverLife.size(); i++) {
        if (valChangeOverLife[i] != nullptr) {
            int startTime = valChangeOverLife[i]->startMillis_;
            int endTime = valChangeOverLife[i]->endMillis_;
            if (activeTime < startTime || activeTime > endTime) {
                continue;
            }
            if (endTime - startTime > 0) {
                Color startValue = valChangeOverLife[i]->fromValue_;
                Color endValue = valChangeOverLife[i]->toValue_;
                float t = static_cast<float>(activeTime - startTime) / static_cast<float>(endTime - startTime);
                auto& interpolator = valChangeOverLife[i]->interpolator_;
                t = (interpolator != nullptr) ? interpolator->Interpolate(t) : t;
                color = RSRenderParticle::Lerp(startValue, endValue, t);
            }
            color = Color(color.AsRgbaInt());
            break;
        }
    }
}

void RSRenderParticleEffector::UpdateColor(const std::shared_ptr<RSRenderParticle>& particle, float deltaTime)
{
    if (particle == nullptr || particle->GetParticleType() == ParticleType::IMAGES) {
        return;
    }
    Color color = particle->GetColor();
    auto particleRenderParams = particle->GetParticleRenderParams();
    if (particleRenderParams != nullptr) {
        auto colorUpdator = particleRenderParams->GetColorUpdator();
        if (colorUpdator == ParticleUpdator::RANDOM) {
            auto colorInt = Vector4<int16_t>(color.GetRed(), color.GetGreen(), color.GetBlue(), color.GetAlpha());
            auto colorSpeed = Vector4f(particle->GetRedSpeed(), particle->GetGreenSpeed(), particle->GetBlueSpeed(),
                particle->GetAlphaSpeed());
            auto colorF =
                Vector4f(particle->GetRedF(), particle->GetGreenF(), particle->GetBlueF(), particle->GetAlphaF());
            colorInt = CalculateColorInt(particle, colorInt, colorF, colorSpeed, deltaTime);
            color.SetRed(colorInt.x_);
            color.SetGreen(colorInt.y_);
            color.SetBlue(colorInt.z_);
            color.SetAlpha(colorInt.w_);
        } else if (colorUpdator == ParticleUpdator::CURVE) {
            int64_t activeTime = particle->GetActiveTime() / NS_PER_MS;
            auto& valChangeOverLife = particleRenderParams->GetColorChangeOverLife();
            UpdateColorCurveValue(color, valChangeOverLife, activeTime);
        }
    }

    particle->SetColor(color);
}

void RSRenderParticleEffector::UpdateOpacity(const std::shared_ptr<RSRenderParticle>& particle, float deltaTime)
{
    if (particle == nullptr) {
        return;
    }
    auto opacity = particle->GetOpacity();
    auto particleRenderParams = particle->GetParticleRenderParams();
    if (particleRenderParams != nullptr) {
        auto opacityUpdator = particleRenderParams->GetOpacityUpdator();
        if (opacityUpdator == ParticleUpdator::RANDOM) {
            auto opacitySpeed = particle->GetOpacitySpeed();
            if (opacity <= 0 && opacitySpeed <= 0) {
                particle->SetIsDead();
                return;
            }
            if (opacity >= 1.0 && opacitySpeed >= 0.f) {
                return;
            }
            opacity += opacitySpeed * deltaTime;
            opacity = std::clamp<float>(opacity, 0.f, 1.f);
        } else if (opacityUpdator == ParticleUpdator::CURVE) {
            int64_t activeTime = particle->GetActiveTime() / NS_PER_MS;
            auto& valChangeOverLife = particleRenderParams->GetOpacityChangeOverLife();
            UpdateCurveValue(opacity, valChangeOverLife, activeTime);
        }
    }
    particle->SetOpacity(opacity);
}

void RSRenderParticleEffector::UpdateScale(const std::shared_ptr<RSRenderParticle>& particle, float deltaTime)
{
    if (particle == nullptr) {
        return;
    }
    auto scale = particle->GetScale();
    auto particleRenderParams = particle->GetParticleRenderParams();
    if (particleRenderParams != nullptr) {
        auto scaleUpdator = particleRenderParams->GetScaleUpdator();
        if (scaleUpdator == ParticleUpdator::RANDOM) {
            auto scaleSpeed = particle->GetScaleSpeed();
            if (scale <= 0 && scaleSpeed <= 0) {
                particle->SetIsDead();
                return;
            }
            scale += scaleSpeed * deltaTime;
        } else if (scaleUpdator == ParticleUpdator::CURVE) {
            int64_t activeTime = particle->GetActiveTime() / NS_PER_MS;
            auto& valChangeOverLife = particleRenderParams->GetScaleChangeOverLife();
            UpdateCurveValue(scale, valChangeOverLife, activeTime);
        }
    }
    particle->SetScale(scale);
}

void RSRenderParticleEffector::UpdateSpin(const std::shared_ptr<RSRenderParticle>& particle, float deltaTime)
{
    if (particle == nullptr) {
        return;
    }
    auto spin = particle->GetSpin();
    auto particleRenderParams = particle->GetParticleRenderParams();
    if (particleRenderParams != nullptr) {
        auto spinUpdator = particleRenderParams->GetSpinUpdator();
        if (spinUpdator == ParticleUpdator::RANDOM) {
            auto spinSpeed = particle->GetSpinSpeed();
            spin += spinSpeed * deltaTime;
        } else if (spinUpdator == ParticleUpdator::CURVE) {
            int64_t activeTime = particle->GetActiveTime() / NS_PER_MS;
            auto& valChangeOverLife = particleRenderParams->GetSpinChangeOverLife();
            UpdateCurveValue(spin, valChangeOverLife, activeTime);
        }
    }
    particle->SetSpin(spin);
}

void RSRenderParticleEffector::UpdateAccelerationAngle(
    const std::shared_ptr<RSRenderParticle>& particle, float deltaTime)
{
    if (particle == nullptr) {
        return;
    }
    auto accelerationAngle = particle->GetAccelerationAngle();
    auto particleRenderParams = particle->GetParticleRenderParams();
    if (particleRenderParams != nullptr) {
        auto acceAngleUpdator = particleRenderParams->GetAccelerationAngleUpdator();
        if (acceAngleUpdator == ParticleUpdator::RANDOM) {
            float acceAngleSpeed = particle->GetAccelerationAngleSpeed();
            accelerationAngle += acceAngleSpeed * deltaTime;
        } else if (acceAngleUpdator == ParticleUpdator::CURVE) {
            int64_t activeTime = particle->GetActiveTime() / NS_PER_MS;
            auto& valChangeOverLife = particleRenderParams->GetAcceAngChangeOverLife();
            UpdateCurveValue(accelerationAngle, valChangeOverLife, activeTime);
        }
    }
    particle->SetAccelerationAngle(accelerationAngle);
}

void RSRenderParticleEffector::UpdateAccelerationValue(
    const std::shared_ptr<RSRenderParticle>& particle, float deltaTime)
{
    if (particle == nullptr) {
        return;
    }
    auto accelerationValue = particle->GetAccelerationValue();
    auto particleRenderParams = particle->GetParticleRenderParams();
    if (particleRenderParams != nullptr) {
        auto acceValueUpdator = particleRenderParams->GetAccelerationValueUpdator();
        if (acceValueUpdator == ParticleUpdator::RANDOM) {
            float acceValueSpeed = particle->GetAccelerationValueSpeed();
            accelerationValue += acceValueSpeed * deltaTime;
        } else if (acceValueUpdator == ParticleUpdator::CURVE) {
            int64_t activeTime = particle->GetActiveTime() / NS_PER_MS;
            auto& valChangeOverLife = particleRenderParams->GetAcceValChangeOverLife();
            UpdateCurveValue(accelerationValue, valChangeOverLife, activeTime);
        }
    }
    particle->SetAccelerationValue(accelerationValue);
}

void RSRenderParticleEffector::UpdatePosition(const std::shared_ptr<RSRenderParticle>& particle,
    const std::shared_ptr<ParticleNoiseFields>& particleNoiseFields,
    const std::shared_ptr<ParticleRippleFields>& particleRippleFields,
    const std::shared_ptr<ParticleVelocityFields>& particleVelocityFields, float deltaTime)
{
    if (particle == nullptr) {
        return;
    }
    auto position = particle->GetPosition();
    auto fieldForce = Vector2f(0.f, 0.f);
    if (particleNoiseFields != nullptr) {
        fieldForce = particleNoiseFields->ApplyAllFields(position, deltaTime);
    }
    if (particleRippleFields != nullptr) {
        fieldForce += particleRippleFields->ApplyAllRippleFields(position, deltaTime);
    }
    if (particleVelocityFields != nullptr) {
        fieldForce += particleVelocityFields->ApplyAllVelocityFields(position, deltaTime);
    }
    auto accelerationValue = particle->GetAccelerationValue();
    auto accelerationAngle = particle->GetAccelerationAngle();
    accelerationAngle *= DEGREE_TO_RADIAN;
    auto acceleration =
        Vector2f { accelerationValue * std::cos(accelerationAngle), accelerationValue * std::sin(accelerationAngle) };
    particle->SetAcceleration(acceleration);

    Vector2f velocity = particle->GetVelocity();
    if (!(ROSEN_EQ(acceleration.x_, 0.f) && ROSEN_EQ(acceleration.y_, 0.f))) {
        velocity.x_ += acceleration.x_ * deltaTime;
        velocity.y_ += acceleration.y_ * deltaTime;
        particle->SetVelocity(velocity);
    }
    velocity += fieldForce;
    if (!(ROSEN_EQ(velocity.x_, 0.f) && ROSEN_EQ(velocity.y_, 0.f))) {
        position.x_ += velocity.x_ * deltaTime;
        position.y_ += velocity.y_ * deltaTime;
        particle->SetPosition(position);
    }
}

void RSRenderParticleEffector::UpdateActiveTime(const std::shared_ptr<RSRenderParticle>& particle, int64_t deltaTime)
{
    if (particle == nullptr) {
        return;
    }
    int64_t activeTime = particle->GetActiveTime();
    activeTime += deltaTime;
    particle->SetActiveTime(activeTime);
}

// Apply effector to particle
void RSRenderParticleEffector::Update(const std::shared_ptr<RSRenderParticle>& particle,
    const std::shared_ptr<ParticleNoiseFields>& particleNoiseFields,
    const std::shared_ptr<ParticleRippleFields>& particleRippleFields,
    const std::shared_ptr<ParticleVelocityFields>& particleVelocityFields, int64_t deltaTime)
{
    if (particle == nullptr) {
        return;
    }
    float dt = static_cast<float>(deltaTime) / NS_TO_S;
    UpdateAccelerationValue(particle, dt);
    UpdateAccelerationAngle(particle, dt);
    UpdateColor(particle, dt);
    UpdateOpacity(particle, dt);
    UpdateScale(particle, dt);
    UpdateSpin(particle, dt);
    UpdatePosition(particle, particleNoiseFields, particleRippleFields, particleVelocityFields, dt);
    UpdateActiveTime(particle, deltaTime);
}

} // namespace Rosen
} // namespace OHOS
