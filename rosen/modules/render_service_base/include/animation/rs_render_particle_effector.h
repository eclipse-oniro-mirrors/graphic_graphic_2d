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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_EFFECTOR_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_EFFECTOR_H

#include "rs_render_particle.h"
namespace OHOS {
namespace Rosen {

class RSRenderParticleEffector {
public:
    RSRenderParticleEffector(const std::shared_ptr<ParticleRenderParams> particleParams);

    void UpdateProperty(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime);
    void UpdateAccelerate(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime);
    void UpdateColor(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime);
    void UpdateOpacity(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime);
    void UpdateScale(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime);
    void UpdateSpin(RSRenderParticle& particle, int64_t deltaTime, int64_t activeTime);
    // Apply effector to particle
    void ApplyEffectorToParticle(RSRenderParticle& particle, int64_t deltaTime);

    template<typename T>
    T GenerateValue(T startValue, T endValue, int startTime, int endTime, int currentTime,
        std::shared_ptr<RSInterpolator> interpolator);

private:
    std::shared_ptr<ParticleRenderParams> particleParams_;
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_EFFECTOR_H