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

#ifndef RENDER_SERVICE_CLIENT_CORE_COMMON_RS_PARTICLE_H
#define RENDER_SERVICE_CLIENT_CORE_COMMON_RS_PARTICLE_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdint.h>
#include <sys/types.h>
#include <vector>

#include "animation/rs_render_particle.h"
#include "common/rs_vector2.h"

#include "animation/rs_animation_timing_curve.h"
#include "common/rs_color.h"
#include "common/rs_common_def.h"
#include "common/rs_macros.h"
#include "render/rs_image.h"

namespace OHOS {
namespace Rosen {
class RSInterpolator;

//enum class ParticleUpdator { NONE = 0, RANDOM, CURVE };

// enum class ShapeType {
//     RECT = 0,
//     CIRCLE,
//     ELLIPSE
// };

// enum class ParticleType {
//     POINTS,
//     IMAGES,
// };

// template<typename T>
// struct Range {
//     T start_, end_;
//     Range() : start_(), end_() {}
//     Range(T a, T b) : start_(a), end_(b) {}
//     bool operator==(const Range<T>& rhs) const
//     {
//         return start_ == rhs.start_ && end_ == rhs.end_;
//     }

//     T Width() const
//     {
//         return end_ - start_;
//     }
// };

template<typename T>
class RSB_EXPORT Change {
public:
    T fromValue_;
    T toValue_;
    int startMillis_;
    int endMillis_;
    RSAnimationTimingCurve curve_;
    Change(): fromValue_(), toValue_(), startMillis_(), endMillis_(), curve_(RSAnimationTimingCurve::LINEAR) {}
    Change(T fromValue, T toValue, int startMillis, int endMillis, RSAnimationTimingCurve& curve)
    {
        fromValue_ = fromValue;
        toValue_ = toValue;
        startMillis_ = startMillis;
        endMillis_ = endMillis;
        curve_ = curve;
    }
    Change(const Change& change) = default;
    Change& operator=(const Change& change) = default;
    ~Change() = default;
};

template<typename T>
class RSB_EXPORT ParticleParaType {
public:
    Range<T> val_;
    ParticleUpdator updator_;        //变化因子，是变化速度还是曲线
    Range<float> random_;            //随机变化速度，乘在属性值之上，用于表示沿着某一方向变化的趋势
    std::vector<Change<T>> valChangeOverLife_;            //变化曲线，可以设置多段曲线，由初始值，终止值，开始时间，结束时间，沿着某曲线变化组成
    ParticleParaType(Range<T>& val, ParticleUpdator updator, Range<float> random,
        std::vector<Change<T>>& valChangeOverLife)
    {
        val_ = val;
        updator_ = updator;
        random_ = random;
        for (size_t i = 0; i < valChangeOverLife.size(); i++) {
            auto change = valChangeOverLife[i];
            valChangeOverLife_.push_back(change);
        }
    }
    ParticleParaType(): val_(), updator_(ParticleUpdator::NONE), random_(), valChangeOverLife_(0)  {}
    ParticleParaType(const ParticleParaType& paraType) = default;
    ParticleParaType& operator=(const ParticleParaType& paraType) = default;
    ~ParticleParaType() = default;
};

// class RSB_EXPORT EmitterConfig {
// public:
//     int emitRate_;
//     ShapeType emitShape_;
//     Vector2f position_;
//     Vector2f emitSize_;
//     int particleCount_;
//     int lifeTime_;
//     ParticleType type_;
//     float radius_;
//     //std::shared_ptr<RSImage> image_ = nullptr;
//     //Drawing::Size size_;
//     //ImageFit imageFit_;

//     EmitterConfig(): emitRate_(5), emitShape_(ShapeType::RECT), position_(), emitSize_(), 
//         particleCount_(10), lifeTime_(100), type_(ParticleType::POINTS), radius_(0.1f)
//         // , image_(), size_(), imageFit_() 
//         {}
//     EmitterConfig(int emitRate, ShapeType emitShape, Vector2f position, Vector2f emitSize, 
//         int particleCount, int lifeTime, ParticleType type, float radius
//         //, std::shared_ptr<RSImageBase> rsImage,Drawing::Size size, ImageFit imageFit
//         )//: image_(rsImage)
//     {
//         emitRate_ = emitRate;
//         emitShape_ = emitShape;
//         position_ = position;
//         emitSize_ = emitSize;
//         particleCount_ = particleCount;
//         lifeTime_ = lifeTime;
//         type_ = type;
//         radius_ = radius;
//         //size_ = size;
//         //imageFit_ = imageFit;
//     }
//     EmitterConfig(const EmitterConfig& config) = default;
//     EmitterConfig& operator=(const EmitterConfig& config) = default;
//     ~EmitterConfig() = default;
// };

// class RSB_EXPORT ParticleVelocity {
// public:
//     Range<float> velocityValue_;
//     Range<float> velocityAngle_;
    
//     ParticleVelocity(): velocityValue_(), velocityAngle_() {}
//     ParticleVelocity(Range<float> velocityValue, Range<float> velocityAngle)
//     {
//         velocityValue_ = Range(velocityValue.start_, velocityValue.end_);
//         velocityAngle_ = Range(velocityAngle.start_, velocityAngle.end_);
//     }
//     ParticleVelocity(const ParticleVelocity& velocity) = default;
//     ParticleVelocity& operator=(const ParticleVelocity& velocity) = default;
//     ~ParticleVelocity() = default;
// };

class RSB_EXPORT ParticleAcceleration {
public:
    ParticleParaType<float> accelerationValue_; 
    ParticleParaType<float> accelerationAngle_;

    ParticleAcceleration() = default;
    ParticleAcceleration(ParticleParaType<float> accelerationValue, ParticleParaType<float> accelerationAngle)
    {
        accelerationValue_ = accelerationValue;
        accelerationAngle_ = accelerationAngle;
    }
    ParticleAcceleration(const ParticleAcceleration& acceleration) = default;
    ParticleAcceleration& operator=(const ParticleAcceleration& acceleration) = default;
    ~ParticleAcceleration() = default;
};

class RSB_EXPORT ParticleColorParaType
//:: OHOS::Rosen::ParticleParaType<Color>
{
public:
    Range<Color> colorVal_;
    ParticleUpdator updator_;
    Range<float> redRandom_;
    Range<float> greenRandom_;
    Range<float> blueRandom_;
    //Range<float> alphaRandom_;

    std::vector<Change<Color>> valChangeOverLife_;
    ParticleColorParaType(Range<Color>& colorVal,
        ParticleUpdator updator, 
        Range<float> redRandom,
        Range<float> greenRandom,
        Range<float> blueRandom,
        //Range<float> alphaRandom,
        std::vector<Change<Color>>& valChangeOverLife)
    {
        colorVal_ = colorVal;
        updator_ = updator;
        redRandom_ = redRandom;
        greenRandom_ = greenRandom;
        blueRandom_ = blueRandom;
        //alphaRandom_ = alphaRandom;
        for (size_t i = 0; i < valChangeOverLife.size(); i++) {
            auto change = valChangeOverLife[i];
            valChangeOverLife_.push_back(change);
        }
    }
    ParticleColorParaType(): colorVal_(), updator_(ParticleUpdator::NONE), 
        redRandom_(), greenRandom_(), blueRandom_(), valChangeOverLife_(0) {}
    ParticleColorParaType(const ParticleColorParaType& velocity) = default;
    ParticleColorParaType& operator=(const ParticleColorParaType& velocity) = default;
    ~ParticleColorParaType() = default;
};

class RSB_EXPORT ParticleParams {
public:
    EmitterConfig emitterConfig_;
    ParticleVelocity velocity_;
    ParticleAcceleration acceleration_;
    ParticleColorParaType color_;
    ParticleParaType<float> opacity_;
    ParticleParaType<float> scale_;
    ParticleParaType<float> spin_;
    explicit ParticleParams(EmitterConfig emitterConfig, ParticleVelocity velocity, 
        ParticleAcceleration acceleration, ParticleColorParaType color, ParticleParaType<float> opacity,
        ParticleParaType<float> scale, ParticleParaType<float> spin)
    {
        emitterConfig_ = emitterConfig;
        velocity_ = velocity;
        acceleration_ = acceleration;
        color_ = color;
        opacity_ = opacity;
        scale_ = scale;
        spin_ = spin;
    }
    ParticleParams() : emitterConfig_(), velocity_(), acceleration_(), color_(), opacity_(), scale_(), spin_(){};
    ParticleParams(const ParticleParams& params) = default;
    ParticleParams& operator=(const ParticleParams& params) = default;
    ~ParticleParams() = default;
    
    RenderParticleParaType<float> translateValToRender(const ParticleParaType<float>& val)
    {
        RenderParticleParaType<float> value;
        value.val_ = val.val_;
        value.updator_ = val.updator_;
        if (val.updator_ == ParticleUpdator::RANDOM) {
            value.random_ = val.random_;
        }else if (val.updator_ == ParticleUpdator::CURVE) {
            uint32_t size =  val.valChangeOverLife_.size();
            for (uint32_t i = 0; i < size; i++) {
                value.valChangeOverLife_[i].fromValue_ =  val.valChangeOverLife_[i].fromValue_;
                value.valChangeOverLife_[i].toValue_ =  val.valChangeOverLife_[i].toValue_;
                value.valChangeOverLife_[i].startMillis_ =  val.valChangeOverLife_[i].startMillis_;
                value.valChangeOverLife_[i].endMillis_ =  val.valChangeOverLife_[i].endMillis_;
                int duration = val.valChangeOverLife_[i].endMillis_ - val.valChangeOverLife_[i].startMillis_;
                RSAnimationTimingCurve curve = val.valChangeOverLife_[i].curve_;
                auto interpolator = curve.GetInterpolator(duration);
                value.valChangeOverLife_[i].interpolator_ = interpolator;
            }
        }
        return value;
    }

    RenderParticleColorParaType translateColorToRender(const ParticleColorParaType& val)
    {
        RenderParticleColorParaType color;
        color.colorVal_ = val.colorVal_;
        color.updator_ = val.updator_;
        if (color.updator_ == ParticleUpdator::RANDOM) {
            color.redRandom_ = val.redRandom_;
            color.greenRandom_ = val.greenRandom_;
            color.blueRandom_ = val.blueRandom_;
        }else if (color.updator_ == ParticleUpdator::CURVE) {
            uint32_t size =  val.valChangeOverLife_.size();
            for (uint32_t i = 0; i < size; i++) {
                color.valChangeOverLife_[i].fromValue_ =  val.valChangeOverLife_[i].fromValue_;
                color.valChangeOverLife_[i].toValue_ =  val.valChangeOverLife_[i].toValue_;
                color.valChangeOverLife_[i].startMillis_ =  val.valChangeOverLife_[i].startMillis_;
                color.valChangeOverLife_[i].endMillis_ =  val.valChangeOverLife_[i].endMillis_;
                int duration = val.valChangeOverLife_[i].endMillis_ - val.valChangeOverLife_[i].startMillis_;
                RSAnimationTimingCurve curve = val.valChangeOverLife_[i].curve_;
                auto interpolator = curve.GetInterpolator(duration);
                color.valChangeOverLife_[i].interpolator_ = interpolator;
            }
        }
        return color;
    }

    ParticleRenderParams& SetParamsToRenderParticle(ParticleParams) {
        auto particleRenderParams = std::make_shared<ParticleRenderParams>();
        particleRenderParams->SetEmitConfig(emitterConfig_);
        particleRenderParams->SetParticleVelocity(velocity_);
        //换算acceleration的曲线到插值器;
        auto acceleration = std::make_share<RenderParticleAcceleration>();
        acceleration->accelerationValue_ = translateValToRender(acceleration.accelerationValue_);
        acceleration->accelerationAngle_ = translateValToRender(acceleration.accelerationAngle_);
        particleRenderParams->SetParticleAcceleration(acceleration);
        particleRenderParams->SetParticleColor(translateColorToRender(color_));
        particleRenderParams->SetParticleOpacity(translateValToRender(opacity_));
        particleRenderParams->SetParticleScale(translateValToRender(scale_));
        particleRenderParams->SetParticleSpin(translateValToRender(spin_));
        // auto rSRenderParticle = RSRenderParticle();
        // rSRenderParticle.particleRenderParams_ = particleRenderParams;
        return particleRenderParams;
    }
};

ParticleParams
  
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_COMMON_RS_PARTICLES_H
