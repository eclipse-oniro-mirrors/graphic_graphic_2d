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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_EMITTER_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_EMITTER_H

#include "rs_render_particle.h"
#include "rs_render_particle_effector.h"
namespace OHOS {
namespace Rosen {

class RSRenderParticleEmitter {
public:
    RSRenderParticleEmitter(ParticleParams particleParams_);

    void EmitParticle(int64_t deltaTime);
    void UpdateParticle(int64_t deltaTime);
    // Setters
    void SetLiveTime(int liveTime);
    void SetEmitRate(int emitRate);
    void SetEmitShape(ShapeType emitShape);
    void SetPosition(const Vector2f& position);
    void SetEmitSize(const Size& emitSize);
    void SetParticleType(ParticleType type);
    void SetRadius(float radius);
    void SetImage(const RSImage& image);
    void SetSize(const Size& size);
    void SetImageFit(ImageFit imageFit);

    // Getters
    int GetMaxParticle() const;
    int GetActiveParticle() const;
    static const std::vector<RSRenderParticle>& GetParticles() const;
    const std::vector<RSRenderParticle*>& GetActiveParticles() const;
    int GetLiveTime() const;
    bool IsEmitting() const;
    int GetEmitRate() const;
    ShapeType GetEmitShape() const;
    const Vector2f& GetPosition() const;
    const Size& GetEmitSize() const;
    ParticleType GetParticleType() const;
    float GetRadius() const;
    // const RSImage& GetImage() const;
    // const Size& GetSize() const;
    // ImageFit GetImageFit() const;

private:
    int maxParticle_;
    int activeParticle_;
    static std::vector<RSRenderParticle> particles_;
    //std::vector<RSRenderParticle*> activeParticles_;
    int liveTime_;
    bool isEmitting_;
    int emitRate_;
    ShapeType emitShape_;   //发射区域的形状
    Vector2f position_;     //发射区域的位置
    Size emitSize_;         //发射区域大小
    ParticleType type_;
    float radius_;
    // RSImage image_;
    // Size size_;
    // ImageFit imageFit_;
    ParticleParams particleParams_;
    int64_t m_accumulatedTime;
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_EMITTER_H
