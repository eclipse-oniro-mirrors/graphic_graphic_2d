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
#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_H

#include <memory>
#include <sys/types.h>
#include <vector>

#include "common/rs_vector2.h"

#include "common/rs_color.h"
#include "common/rs_common_def.h"
#include "common/rs_macros.h"
#include "render/rs_image.h"
namespace OHOS {
namespace Rosen {

class RSInterpolator;
enum class ParticleUpdator { NONE = 0, RANDOM, CURVE };

enum class ShapeType {
    RECT = 0,
    CIRCLE,
    ELLIPSE
};

enum class ParticleType {
    POINTS,
    IMAGES,
};

template<typename T>
struct Range {
    T start_, end_;
    Range() : start_(), end_() {}
    Range(T a, T b) : start_(a), end_(b) {}
    bool operator==(const Range<T>& rhs) const
    {
        return start_ == rhs.start_ && end_ == rhs.end_;
    }

    T Width() const
    {
        return end_ - start_;
    }
};

template<typename T>
class RSB_EXPORT ChangeInOverLife {
public:
    T fromValue_;
    T toValue_;
    int startMillis_;
    int endMillis_;
    std::shared_ptr<RSInterpolator> interpolator_;
    ChangeInOverLife(): fromValue_(), toValue_(), startMillis_(), endMillis_(), interpolator_() {}
    ChangeInOverLife(T fromValue, T toValue, int startMillis, int endMillis, std::shared_ptr<RSInterpolator> interpolator)
    {
        fromValue_ = fromValue;
        toValue_ = toValue;
        startMillis_ = startMillis;
        endMillis_ = endMillis;
        interpolator_ = interpolator;
    }
    ChangeInOverLife(const ChangeInOverLife& change) = default;
    ChangeInOverLife& operator=(const ChangeInOverLife& change) = default;
    ~ChangeInOverLife() = default;
};

template<typename T>
class RSB_EXPORT RenderParticleParaType {
public:
    Range<T> val_;
    ParticleUpdator updator_;        //变化因子，是变化速度还是曲线
    Range<float> random_;            //随机变化速度，乘在属性值之上，用于表示沿着某一方向变化的趋势
    std::vector<ChangeInOverLife<T>> valChangeOverLife_;            //变化曲线，可以设置多段曲线，由初始值，终止值，开始时间，结束时间，沿着某曲线变化组成
    RenderParticleParaType(Range<T>& val, ParticleUpdator updator, Range<float> random,
        std::vector<ChangeInOverLife<T>>& valChangeOverLife)
    {
        val_ = val;
        updator_ = updator;
        random_ = random;
        for (size_t i = 0; i < valChangeOverLife.size(); i++) {
            auto change = valChangeOverLife[i];
            valChangeOverLife_.push_back(change);
        }
    }
    RenderParticleParaType(): val_(), updator_(ParticleUpdator::NONE), random_(), valChangeOverLife_(0)  {}
    RenderParticleParaType(const RenderParticleParaType& paraType) = default;
    RenderParticleParaType& operator=(const RenderParticleParaType& paraType) = default;
    ~RenderParticleParaType() = default;
};

class RSB_EXPORT EmitterConfig {
public:
    int emitRate_;
    ShapeType emitShape_;
    Vector2f position_;
    Vector2f emitSize_;
    int particleCount_;
    int lifeTime_;
    ParticleType type_;
    float radius_;
    //std::shared_ptr<RSImage> image_ = nullptr;
    //Drawing::Size size_;
    //ImageFit imageFit_;

    EmitterConfig(): emitRate_(5), emitShape_(ShapeType::RECT), position_(), emitSize_(), 
        particleCount_(10), lifeTime_(100), type_(ParticleType::POINTS), radius_(0.1f)
        // , image_(), size_(), imageFit_() 
        {}
    EmitterConfig(int emitRate, ShapeType emitShape, Vector2f position, Vector2f emitSize, 
        int particleCount, int lifeTime, ParticleType type, float radius
        //, std::shared_ptr<RSImageBase> rsImage,Drawing::Size size, ImageFit imageFit
        )//: image_(rsImage)
    {
        emitRate_ = emitRate;
        emitShape_ = emitShape;
        position_ = position;
        emitSize_ = emitSize;
        particleCount_ = particleCount;
        lifeTime_ = lifeTime;
        type_ = type;
        radius_ = radius;
        //size_ = size;
        //imageFit_ = imageFit;
    }
    EmitterConfig(const EmitterConfig& config) = default;
    EmitterConfig& operator=(const EmitterConfig& config) = default;
    ~EmitterConfig() = default;
};

class RSB_EXPORT ParticleVelocity {
public:
    Range<float> velocityValue_;
    Range<float> velocityAngle_;
    
    ParticleVelocity(): velocityValue_(), velocityAngle_() {}
    ParticleVelocity(Range<float> velocityValue, Range<float> velocityAngle)
    {
        velocityValue_ = Range(velocityValue.start_, velocityValue.end_);
        velocityAngle_ = Range(velocityAngle.start_, velocityAngle.end_);
    }
    ParticleVelocity(const ParticleVelocity& velocity) = default;
    ParticleVelocity& operator=(const ParticleVelocity& velocity) = default;
    ~ParticleVelocity() = default;
};

class RSB_EXPORT RenderParticleAcceleration {
public:
    RenderParticleParaType<float> accelerationValue_; 
    RenderParticleParaType<float> accelerationAngle_;

    RenderParticleAcceleration() = default;
    RenderParticleAcceleration(RenderParticleParaType<float> accelerationValue, RenderParticleParaType<float> accelerationAngle)
    {
        accelerationValue_ = accelerationValue;
        accelerationAngle_ = accelerationAngle;
    }
    RenderParticleAcceleration(const RenderParticleAcceleration& acceleration) = default;
    RenderParticleAcceleration& operator=(const RenderParticleAcceleration& acceleration) = default;
    ~RenderParticleAcceleration() = default;
};

class RSB_EXPORT RenderParticleColorParaType
//:: OHOS::Rosen::RenderParticleParaType<Color>
{
public:
    Range<Color> colorVal_;
    ParticleUpdator updator_;
    Range<float> redRandom_;
    Range<float> greenRandom_;
    Range<float> blueRandom_;
    //Range<float> alphaRandom_;

    std::vector<ChangeInOverLife<Color>> valChangeOverLife_;
    RenderParticleColorParaType(Range<Color>& colorVal,
        ParticleUpdator updator,
        Range<float> redRandom,
        Range<float> greenRandom,
        Range<float> blueRandom,
        //Range<float> alphaRandom,
        std::vector<ChangeInOverLife<Color>>& valChangeOverLife)
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
    RenderParticleColorParaType(): colorVal_(), updator_(ParticleUpdator::NONE), 
        redRandom_(), greenRandom_(), blueRandom_(), valChangeOverLife_(0) {}
    RenderParticleColorParaType(const RenderParticleColorParaType& velocity) = default;
    RenderParticleColorParaType& operator=(const RenderParticleColorParaType& velocity) = default;
    ~RenderParticleColorParaType() = default;
};

class RSB_EXPORT ParticleRenderParams {
public:
    EmitterConfig emitterConfig_;
    ParticleVelocity velocity_;
    RenderParticleAcceleration acceleration_;
    RenderParticleColorParaType color_;
    RenderParticleParaType<float> opacity_;
    RenderParticleParaType<float> scale_;
    RenderParticleParaType<float> spin_;
    explicit ParticleRenderParams(EmitterConfig emitterConfig, ParticleVelocity velocity, 
        RenderParticleAcceleration acceleration, RenderParticleColorParaType color, RenderParticleParaType<float> opacity,
        RenderParticleParaType<float> scale, RenderParticleParaType<float> spin)
    {
        emitterConfig_ = emitterConfig;
        velocity_ = velocity;
        acceleration_ = acceleration;
        color_ = color;
        opacity_ = opacity;
        scale_ = scale;
        spin_ = spin;
    }
    ParticleRenderParams() : emitterConfig_(), velocity_(), acceleration_(), color_(), opacity_(), scale_(), spin_(){};
    ParticleRenderParams(const ParticleRenderParams& params) = default;
    ParticleRenderParams& operator=(const ParticleRenderParams& params) = default;
    ~ParticleRenderParams() = default;
    
    int GetEmitRate() const;
    ShapeType GetEmitShape() const;
    Vector2f GetEmitPosition() const;
    Vector2f GetEmitSize() const;
    int GetParticleCount() const;
    int GetParticleLifeTime() const;
    ParticleType GetParticleType() const;
    float GetParticleRadius() const;
    // RSImage GetParticleImage();
    // Vector2f GetParticleImageSize();
    // ImageFit GetParticleImageFit();

    float GetVelocityStartValue() const;
    float GetVelocityEndValue() const;
    float GetVelocityStartAngle() const;
    float GetVelocityEndAngle() const;

    float GetAccelerationStartValue() const;
    float GetAccelerationEndValue() const;
    float GetAccelerationStartAngle() const;
    float GetAccelerationEndAngle() const;
    ParticleUpdator GetAccelerationValueUpdator();
    ParticleUpdator GetAccelerationAngleUpdator();
    float GetAccelRandomValueStart() const;
    float GetAccelRandomValueEnd() const;
    float GetAccelRandomAngleStart() const;
    float GetAccelRandomAngleEnd() const;

    Color GetColorStartValue();
    Color GetColorEndValue();
    ParticleUpdator GetColorUpdator();
    float GetRedRandomStart() const;
    float GetRedRandomEnd() const;
    float GetGreenRandomStart() const;
    float GetGreenRandomEnd() const;
    float GetBlueRandomStart() const;
    float GetBlurRandomEnd() const;

    float GetOpacityStartValue();
    float GetOpacityEndValue();
    ParticleUpdator GetOpacityUpdator();
    float GetOpacityRandomStart() const;
    float GetOpacityRandomEnd() const;

    float GetScaleStartValue();
    float GetScaleEndValue();
    ParticleUpdator GetScaleUpdator();
    float GetScaleRandomStart() const;
    float GetScaleRandomEnd() const;

    float GetSpinStartValue();
    float GetSpinEndValue();
    ParticleUpdator GetSpinUpdator();
    float GetSpinRandomStart() const;
    float GetSpinRandomEnd() const;

    void SetEmitConfig(EmitterConfig emitConfig);
    void SetParticleVelocity(ParticleVelocity velocity);
    void SetParticleAcceleration(RenderParticleAcceleration acceleration);
    void SetParticleColor(RenderParticleColorParaType color);
    void SetParticleOpacity(RenderParticleParaType<float> opacity);
    void SetParticleScale(RenderParticleParaType<float> scale);
    void SetParticleSpin(RenderParticleParaType<float> spin);
};

class RSB_EXPORT RSRenderParticle {
public:
   RSRenderParticle(ParticleRenderParams particleParams);
   RSRenderParticle() = default;

    // Set methods
    void SetPosition(Vector2f position);
    void SetVelocity(Vector2f velocity);
    void SetAcceleration(Vector2f acceleration);
    void SetSpin(float spin);
    void SetOpacity(float opacity);
    void SetColor(Color color);
    void SetScale(float scale);
    void SetRadius(float radius);
    // void SetRSImage(RSImage rsImage);
    // void SetParticleSize(Drawing::Size particleSize);
    void SetParticleType(ParticleType particleType);
    void SetActiveTime(int activeTime);

    // Get methods
    Vector2f GetPosition();
    Vector2f GetVelocity();
    Vector2f GetAcceleration();
    float GetSpin();
    float GetOpacity();
    Color GetColor();
    float GetScale();
    float GetRadius();
    // RSImage GetRSImage();
    // Drawing::Size GetRenderParticleSize();
    ParticleType GetParticleType();
    int GetActiveTime();

    // Other methods
    void InitProperty(ParticleRenderParams particleParams);
    void UpdateProperty(ParticleRenderParams particleParams, int64_t deltaTime);
    void UpdateAccelerate(ParticleRenderParams particleParams, int64_t deltaTime);
    void UpdateColor(ParticleRenderParams particleParams, int64_t deltaTime);
    void UpdateOpacity(ParticleRenderParams particleParams, int64_t deltaTime);
    void UpdateScale(ParticleRenderParams particleParams, int64_t deltaTime);
    void UpdateSpin(ParticleRenderParams particleParams, int64_t deltaTime);
    bool IsAlive() const;
    float GetRandomValue(float min, float max);
    Vector2f CalculateParticlePosition(ShapeType emitShape, Vector2f position, Vector2f emitSize);
    Color Lerp(const Color& start, const Color& end, float t);
    std::vector<std::shared_ptr<ParticleRenderParams>> particleRenderParams_;

private:
    Vector2f position_;
    Vector2f velocity_;
    Vector2f acceleration_;
    float scale_;
    float spin_;
    float opacity_;
    Color color_;
    float radius_;
    // RSImage rsImage_;
    // Drawing::Size particleSize_;
    ParticleType particleType_;
    int64_t activeTime_;
    int64_t lifeTime_;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_RENDER_PARTICLE_H