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

#include "animation/rs_render_particle_system.h"
#include <cstddef>
namespace OHOS {
namespace Rosen {
RSRenderParticleSystem::RSRenderParticleSystem(const std::vector<std::shared_ptr<ParticleRenderParams>> particlesRenderParams)
    : particlesRenderParams_(particlesRenderParams)
{}

//有几个发射器就发射几次
void RSRenderParticleSystem::Emit(int64_t deltaTime) {
    for (std::size_t iter = 0; iter < particlesRenderParams_.size(); iter++) { 
        auto particleRenderParams = particlesRenderParams_[iter];
        //创建发射器
        auto emitter = std::make_shared<RSRenderParticleEmitter>(particleRenderParams);
        emitter->EmitParticle(deltaTime);
        // emitter->updateParticle(deltaTime);
    }
}
std::vector<std::shared_ptr<RSRenderParticle>> RSRenderParticleSystem::Simulation(int64_t deltaTime) {
    Emit(deltaTime);
    return RSRenderParticleEmitter::GetRenderParticles();
}
} // namespace Rosen
} // namespace OHOS