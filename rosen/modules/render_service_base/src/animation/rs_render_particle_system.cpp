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

#include "animation/rs_render_particle_system.h"

#include <cstddef>
namespace OHOS {
namespace Rosen {
RSRenderParticleSystem::RSRenderParticleSystem(
    const std::vector<std::shared_ptr<ParticleRenderParams>>& particlesRenderParams)
    : particlesRenderParams_(particlesRenderParams)
{
    CreateEmitter();
}

void RSRenderParticleSystem::CreateEmitter()
{
    size_t index = 0;
    for (size_t iter = 0; iter < particlesRenderParams_.size(); iter++) {
        auto& particleRenderParams = particlesRenderParams_[iter];
        if (particleRenderParams != nullptr) {
            if (particleRenderParams->GetParticleType() == ParticleType::IMAGES) {
                particleRenderParams->SetImageIndex(index++);
                auto& image = particleRenderParams->GetParticleImage();
                imageVector_.push_back(image);
            }
            emitters_.push_back(std::make_shared<RSRenderParticleEmitter>(particleRenderParams));
        }
    }
}

void RSRenderParticleSystem::ClearEmitter()
{
    emitters_.clear();
}

void RSRenderParticleSystem::Emit(int64_t deltaTime, std::vector<std::shared_ptr<RSRenderParticle>>& activeParticles,
    std::vector<std::shared_ptr<RSImage>>& imageVector)
{
    for (size_t iter = 0; iter < emitters_.size(); iter++) {
        if (emitters_[iter] != nullptr) {
            emitters_[iter]->EmitParticle(deltaTime);
            auto& particles = emitters_[iter]->GetParticles();
            activeParticles.insert(activeParticles.end(), particles.begin(), particles.end());
        }
    }
    imageVector = imageVector_;
}

void RSRenderParticleSystem::UpdateParticle(
    int64_t deltaTime, std::vector<std::shared_ptr<RSRenderParticle>>& activeParticles)
{
    if (activeParticles.empty()) {
        return;
    }
    if (particleRippleFields_ != nullptr) {
        particleRippleFields_->UpdateAllRipples(static_cast<float>(deltaTime) / NS_TO_S);
    }
    for (auto it = activeParticles.begin(); it != activeParticles.end();) {
        // std::shared_ptr<RSRenderParticle> particle = *it;
        if ((*it) == nullptr || !(*it)->IsAlive()) {
            it = activeParticles.erase(it);
        } else {
            Update((*it), particleNoiseFields_, particleRippleFields_, particleVelocityFields_, deltaTime);
            ++it;
        }
    }
}

bool RSRenderParticleSystem::IsFinish(const std::vector<std::shared_ptr<RSRenderParticle>>& activeParticles)
{
    bool finish = true;
    if (!activeParticles.empty()) {
        return false;
    }
    for (size_t iter = 0; iter < emitters_.size(); iter++) {
        if (emitters_[iter] != nullptr) {
            finish = finish && emitters_[iter]->IsEmitterFinish();
        }
    }
    return finish;
}

void RSRenderParticleSystem::UpdateEmitter(
    const std::vector<std::shared_ptr<ParticleRenderParams>>& particlesRenderParams)
{
    particlesRenderParams_ = particlesRenderParams;
}

void RSRenderParticleSystem::UpdateNoiseField(const std::shared_ptr<ParticleNoiseFields>& particleNoiseFields)
{
    particleNoiseFields_ = particleNoiseFields;
}

void RSRenderParticleSystem::UpdateRippleField(const std::shared_ptr<ParticleRippleFields>& particleRippleFields)
{
    if (!particleRippleFields) {
        particleRippleFields_ = nullptr;
        return;
    }

    if (!particleRippleFields_) {
        particleRippleFields_ = particleRippleFields;
        return;
    }

    auto& existingFields = particleRippleFields_->rippleFields_;
    auto& newFields = particleRippleFields->rippleFields_;

    std::vector<std::shared_ptr<ParticleRippleField>> mergedFields;

    for (const auto& newField : newFields) {
        if (!newField) continue;

        bool found = false;
        for (const auto& existingField : existingFields) {
            if (existingField &&
                existingField->center_ == newField->center_ &&
                ROSEN_EQ(existingField->amplitude_, newField->amplitude_) &&
                ROSEN_EQ(existingField->wavelength_, newField->wavelength_) &&
                ROSEN_EQ(existingField->waveSpeed_, newField->waveSpeed_) &&
                ROSEN_EQ(existingField->attenuation_, newField->attenuation_) &&
                existingField->regionShape_ == newField->regionShape_ &&
                existingField->regionPosition_ == newField->regionPosition_ &&
                existingField->regionSize_ == newField->regionSize_) {
                mergedFields.push_back(existingField);
                found = true;
                break;
            }
        }

        if (!found) {
            mergedFields.push_back(newField);
        }
    }

    particleRippleFields_->rippleFields_ = mergedFields;
}
void RSRenderParticleSystem::UpdateVelocityField(const std::shared_ptr<ParticleVelocityFields>& particleVelocityFields)
{
    particleVelocityFields_ = particleVelocityFields;
}
} // namespace Rosen
} // namespace OHOS
