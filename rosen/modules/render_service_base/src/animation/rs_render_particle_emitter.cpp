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

#include "animation/rs_render_particle_emitter.h"
#include <vector>
namespace OHOS {
namespace Rosen {
    
constexpr int64_t NANOSECONDS_PER_ONE_SECOND = 1000000000;
std::vector<std::shared_ptr<RSRenderParticle>> RSRenderParticleEmitter::particles_ = {};
RSRenderParticleEmitter::RSRenderParticleEmitter(std::shared_ptr<ParticleRenderParams> particleParams)
    : particleParams_(particleParams)
{}

//一个发射器 发射粒子
void RSRenderParticleEmitter::EmitParticle(int64_t deltaTime)
{
    //configureEmitter 不用配置发射器属性，直接从emitterConfig中获取
    emitRate_ = particleParams_->GetEmitRate();
    maxParticle_ = particleParams_->GetParticleCount();
    m_accumulatedTime = 0; // 单位纳秒
    int particleNum = 0;
    m_accumulatedTime += deltaTime;

    // EmitParticle 发射粒子循环，加入粒子数组
    while (m_accumulatedTime >= (1.0 / emitRate_) * NANOSECONDS_PER_ONE_SECOND && particleNum < maxParticle_) {
        //创建粒子
        //particle.initProperty(particleParams);
        //此时粒子属性已经是初始属性，取过随机值的。将粒子加入粒子数组
        auto particle = std::make_shared<RSRenderParticle>(particleParams_); 
        //particle.GetActiveTime();
        particles_.push_back(particle);
        particleNum++;
        m_accumulatedTime += deltaTime;
    }

    //将此时的粒子数组作为particleRenderProperty
    // 更新并移除已消亡的粒子
    //update particle
    for (auto it = particles_.begin(); it != particles_.end();) {
        auto effect = RSRenderParticleEffector(particleParams_);
        effect.ApplyEffectorToParticle(*((*it).get()), deltaTime);
        if (!((*it)->IsAlive())) {
            it = particles_.erase(it);
            particleNum--;
        } else {
            ++it;
        }
    }
}

// Setters
void RSRenderParticleEmitter::SetLiveTime(int liveTime)
{
    liveTime_ = liveTime;
}

void RSRenderParticleEmitter::SetEmitRate(int emitRate)
{
    emitRate_ = emitRate;
}

void RSRenderParticleEmitter::SetEmitShape(ShapeType emitShape)
{
    emitShape_ = emitShape;
}

void RSRenderParticleEmitter::SetPosition(const Vector2f& position)
{
    position_ = position;
}

void RSRenderParticleEmitter::SetEmitSize(const Vector2f& emitSize)
{
    emitSize_ = emitSize;
}

void RSRenderParticleEmitter::SetParticleType(ParticleType type)
{
    type_ = type;
}

void RSRenderParticleEmitter::SetRadius(float radius)
{
    radius_ = radius;
}

// void RSRenderParticleEmitter::SetImage(const RSImage& image)
// {
//     image_ = image;
// }

// void RSRenderParticleEmitter::SetSize(const Size& size)
// {
//     size_ = size;
// }

// void RSRenderParticleEmitter::SetImageFit(ImageFit imageFit)
// {
//     imageFit_ = imageFit;
// }

// Getters
int RSRenderParticleEmitter::GetMaxParticle() const
{
    return maxParticle_;
}

int RSRenderParticleEmitter::GetActiveParticle() const
{
    return activeParticle_;
}

std::vector<std::shared_ptr<RSRenderParticle>> RSRenderParticleEmitter::GetRenderParticles()
{
    // std::vector<std::shared_ptr<RSRenderParticle>> a;
    return particles_;
    // return a;
}

std::vector<std::shared_ptr<RSRenderParticle>> RSRenderParticleEmitter::GetActiveParticles()
{
    return activeParticles_;
}

int RSRenderParticleEmitter::GetLiveTime() const
{
    return liveTime_;
}

bool RSRenderParticleEmitter::IsEmitting() const
{
    return isEmitting_;
}

int RSRenderParticleEmitter::GetEmitRate() const
{
    return emitRate_;
}

ShapeType RSRenderParticleEmitter::GetEmitShape() const
{
    return emitShape_;
}

const Vector2f& RSRenderParticleEmitter::GetPosition() const
{
    return position_;
}

const Vector2f& RSRenderParticleEmitter::GetEmitSize() const
{
    return emitSize_;
}

ParticleType RSRenderParticleEmitter::GetParticleType() const
{
    return type_;
}

float RSRenderParticleEmitter::GetRadius() const
{
    return radius_;
}

// const RSImage& RSRenderParticleEmitter::GetImage() const
// {
//     return image_;
// }

// const Size& RSRenderParticleEmitter::GetSize() const
// {
//     return size_;
// }

// ImageFit RSRenderParticleEmitter::GetImageFit() const
// {
//     return imageFit_;
// }
} // namespace Rosen
} // namespace OHOS