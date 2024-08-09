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
#include "animation/rs_render_particle.h"

#include <algorithm>
#include <cstdint>
#include <random>

#include "animation/rs_interpolator.h"
#include "animation/rs_render_particle_system.h"
#include "common/rs_color.h"
namespace OHOS {
namespace Rosen {
constexpr float DEGREE_TO_RADIAN = M_PI / 180;
constexpr int RAND_PRECISION = 10000;
constexpr float SIGMA = 3.f;

int ParticleRenderParams::GetEmitRate() const
{
    return emitterConfig_.emitRate_;
}

const ShapeType& ParticleRenderParams::GetEmitShape() const
{
    return emitterConfig_.emitShape_;
}

const Vector2f& ParticleRenderParams::GetEmitPosition() const
{
    return emitterConfig_.position_;
}

const Vector2f& ParticleRenderParams::GetEmitSize() const
{
    return emitterConfig_.emitSize_;
}

int32_t ParticleRenderParams::GetParticleCount() const
{
    return emitterConfig_.particleCount_;
}

int64_t ParticleRenderParams::GetLifeTimeStartValue() const
{
    if (emitterConfig_.lifeTime_.start_ > std::numeric_limits<int64_t>::max() / NS_PER_MS) {
        return std::numeric_limits<int64_t>::max();
    }
    return emitterConfig_.lifeTime_.start_ * NS_PER_MS;
}

int64_t ParticleRenderParams::GetLifeTimeEndValue() const
{
    if (emitterConfig_.lifeTime_.end_ > std::numeric_limits<int64_t>::max() / NS_PER_MS) {
        return std::numeric_limits<int64_t>::max();
    }
    return emitterConfig_.lifeTime_.end_ * NS_PER_MS;
}

const ParticleType& ParticleRenderParams::GetParticleType() const
{
    return emitterConfig_.type_;
}

float ParticleRenderParams::GetParticleRadius() const
{
    return emitterConfig_.radius_;
}

const std::shared_ptr<RSImage>& ParticleRenderParams::GetParticleImage()
{
    return emitterConfig_.image_;
}

const Vector2f& ParticleRenderParams::GetImageSize() const
{
    return emitterConfig_.imageSize_;
}

float ParticleRenderParams::GetVelocityStartValue() const
{
    return velocity_.velocityValue_.start_;
}

float ParticleRenderParams::GetVelocityEndValue() const
{
    return velocity_.velocityValue_.end_;
}

float ParticleRenderParams::GetVelocityStartAngle() const
{
    return velocity_.velocityAngle_.start_;
}

float ParticleRenderParams::GetVelocityEndAngle() const
{
    return velocity_.velocityAngle_.end_;
}

float ParticleRenderParams::GetAccelerationStartValue() const
{
    return acceleration_.accelerationValue_.val_.start_;
}

float ParticleRenderParams::GetAccelerationEndValue() const
{
    return acceleration_.accelerationValue_.val_.end_;
}

float ParticleRenderParams::GetAccelerationStartAngle() const
{
    return acceleration_.accelerationAngle_.val_.start_;
}

float ParticleRenderParams::GetAccelerationEndAngle() const
{
    return acceleration_.accelerationAngle_.val_.end_;
}

const ParticleUpdator& ParticleRenderParams::GetAccelerationValueUpdator()
{
    return acceleration_.accelerationValue_.updator_;
}

const ParticleUpdator& ParticleRenderParams::GetAccelerationAngleUpdator()
{
    return acceleration_.accelerationAngle_.updator_;
}

float ParticleRenderParams::GetAccelRandomValueStart() const
{
    return acceleration_.accelerationValue_.random_.start_;
}

float ParticleRenderParams::GetAccelRandomValueEnd() const
{
    return acceleration_.accelerationValue_.random_.end_;
}

float ParticleRenderParams::GetAccelRandomAngleStart() const
{
    return acceleration_.accelerationAngle_.random_.start_;
}

float ParticleRenderParams::GetAccelRandomAngleEnd() const
{
    return acceleration_.accelerationAngle_.random_.end_;
}

const Color& ParticleRenderParams::GetColorStartValue()
{
    return color_.colorVal_.start_;
}

const Color& ParticleRenderParams::GetColorEndValue()
{
    return color_.colorVal_.end_;
}

const DistributionType& ParticleRenderParams::GetColorDistribution()
{
    return color_.distribution_;
}

const ParticleUpdator& ParticleRenderParams::GetColorUpdator()
{
    return color_.updator_;
}

float ParticleRenderParams::GetRedRandomStart() const
{
    return color_.redRandom_.start_;
}

float ParticleRenderParams::GetRedRandomEnd() const
{
    return color_.redRandom_.end_;
}

float ParticleRenderParams::GetGreenRandomStart() const
{
    return color_.greenRandom_.start_;
}

float ParticleRenderParams::GetGreenRandomEnd() const
{
    return color_.greenRandom_.end_;
}

float ParticleRenderParams::GetBlueRandomStart() const
{
    return color_.blueRandom_.start_;
}

float ParticleRenderParams::GetBlueRandomEnd() const
{
    return color_.blueRandom_.end_;
}

float ParticleRenderParams::GetAlphaRandomStart() const
{
    return color_.alphaRandom_.start_;
}

float ParticleRenderParams::GetAlphaRandomEnd() const
{
    return color_.alphaRandom_.end_;
}

float ParticleRenderParams::GetOpacityStartValue()
{
    return opacity_.val_.start_;
}

float ParticleRenderParams::GetOpacityEndValue()
{
    return opacity_.val_.end_;
}

const ParticleUpdator& ParticleRenderParams::GetOpacityUpdator()
{
    return opacity_.updator_;
}

float ParticleRenderParams::GetOpacityRandomStart() const
{
    return opacity_.random_.start_;
}

float ParticleRenderParams::GetOpacityRandomEnd() const
{
    return opacity_.random_.end_;
}

float ParticleRenderParams::GetScaleStartValue()
{
    return scale_.val_.start_;
}

float ParticleRenderParams::GetScaleEndValue()
{
    return scale_.val_.end_;
}

const ParticleUpdator& ParticleRenderParams::GetScaleUpdator()
{
    return scale_.updator_;
}

float ParticleRenderParams::GetScaleRandomStart() const
{
    return scale_.random_.start_;
}

float ParticleRenderParams::GetScaleRandomEnd() const
{
    return scale_.random_.end_;
}

float ParticleRenderParams::GetSpinStartValue()
{
    return spin_.val_.start_;
}

float ParticleRenderParams::GetSpinEndValue()
{
    return spin_.val_.end_;
}

const ParticleUpdator& ParticleRenderParams::GetSpinUpdator()
{
    return spin_.updator_;
}

const std::vector<std::shared_ptr<ChangeInOverLife<float>>>& ParticleRenderParams::GetAcceValChangeOverLife()
{
    return acceleration_.accelerationValue_.valChangeOverLife_;
}

const std::vector<std::shared_ptr<ChangeInOverLife<float>>>& ParticleRenderParams::GetAcceAngChangeOverLife()
{
    return acceleration_.accelerationAngle_.valChangeOverLife_;
}

const std::vector<std::shared_ptr<ChangeInOverLife<float>>>& ParticleRenderParams::GetOpacityChangeOverLife()
{
    return opacity_.valChangeOverLife_;
}

const std::vector<std::shared_ptr<ChangeInOverLife<float>>>& ParticleRenderParams::GetScaleChangeOverLife()
{
    return scale_.valChangeOverLife_;
}

const std::vector<std::shared_ptr<ChangeInOverLife<float>>>& ParticleRenderParams::GetSpinChangeOverLife()
{
    return spin_.valChangeOverLife_;
}

const std::vector<std::shared_ptr<ChangeInOverLife<Color>>>& ParticleRenderParams::GetColorChangeOverLife()
{
    return color_.valChangeOverLife_;
}

float ParticleRenderParams::GetSpinRandomStart() const
{
    return spin_.random_.start_;
}

float ParticleRenderParams::GetSpinRandomEnd() const
{
    return spin_.random_.end_;
}

size_t ParticleRenderParams::GetImageIndex() const
{
    return imageIndex_;
}

void ParticleRenderParams::SetEmitConfig(const EmitterConfig& emiterConfig)
{
    emitterConfig_ = emiterConfig;
}

void ParticleRenderParams::SetParticleVelocity(const ParticleVelocity& velocity)
{
    velocity_ = velocity;
}

void ParticleRenderParams::SetParticleAcceleration(const RenderParticleAcceleration& acceleration)
{
    acceleration_ = acceleration;
}

void ParticleRenderParams::SetParticleColor(const RenderParticleColorParaType& color)
{
    color_ = color;
}

void ParticleRenderParams::SetParticleOpacity(const RenderParticleParaType<float>& opacity)
{
    opacity_ = opacity;
}

void ParticleRenderParams::SetParticleScale(const RenderParticleParaType<float>& scale)
{
    scale_ = scale;
}

void ParticleRenderParams::SetParticleSpin(const RenderParticleParaType<float>& spin)
{
    spin_ = spin;
}

void ParticleRenderParams::SetImageIndex(size_t imageIndex)
{
    imageIndex_ = imageIndex;
}

RSRenderParticle::RSRenderParticle(const std::shared_ptr<ParticleRenderParams>& particleParams)
    : particleParams_(particleParams)
{
    if (particleParams_ != nullptr) {
        InitProperty();
    }
}

// Set methods
void RSRenderParticle::SetPosition(const Vector2f& position)
{
    position_ = position;
}

void RSRenderParticle::SetVelocity(const Vector2f& velocity)
{
    velocity_ = velocity;
}

void RSRenderParticle::SetAcceleration(const Vector2f& acceleration)
{
    acceleration_ = acceleration;
}

void RSRenderParticle::SetSpin(const float& spin)
{
    spin_ = spin;
}

void RSRenderParticle::SetOpacity(const float& opacity)
{
    opacity_ = opacity;
}

void RSRenderParticle::SetColor(const Color& color)
{
    color_ = color;
}

void RSRenderParticle::SetScale(const float& scale)
{
    scale_ = scale;
}

void RSRenderParticle::SetRadius(const float& radius)
{
    radius_ = radius;
}

void RSRenderParticle::SetImage(const std::shared_ptr<RSImage>& image)
{
    image_ = image;
}

void RSRenderParticle::SetImageSize(const Vector2f& imageSize)
{
    imageSize_ = imageSize;
}

void RSRenderParticle::SetParticleType(const ParticleType& particleType)
{
    particleType_ = particleType;
}

void RSRenderParticle::SetActiveTime(const int64_t& activeTime)
{
    activeTime_ = activeTime;
}

void RSRenderParticle::SetAccelerationValue(float accelerationValue)
{
    accelerationValue_ = accelerationValue;
}

void RSRenderParticle::SetAccelerationAngle(float accelerationAngle)
{
    accelerationAngle_ = accelerationAngle;
}

void RSRenderParticle::SetRedF(float redF)
{
    redF_ = redF;
}

void RSRenderParticle::SetGreenF(float greenF)
{
    greenF_ = greenF;
}

void RSRenderParticle::SetBlueF(float blueF)
{
    blueF_ = blueF;
}

void RSRenderParticle::SetAlphaF(float alphaF)
{
    alphaF_ = alphaF;
}

// Get methods
const Vector2f& RSRenderParticle::GetPosition()
{
    return position_;
}

const Vector2f& RSRenderParticle::GetVelocity()
{
    return velocity_;
}

const Vector2f& RSRenderParticle::GetAcceleration()
{
    return acceleration_;
}

float RSRenderParticle::GetSpin()
{
    return spin_;
}

float RSRenderParticle::GetOpacity()
{
    return opacity_;
}

const Color& RSRenderParticle::GetColor()
{
    return color_;
}

float RSRenderParticle::GetScale()
{
    return scale_;
}

float RSRenderParticle::GetRadius()
{
    return radius_;
}

float RSRenderParticle::GetAccelerationValue()
{
    return accelerationValue_;
}

float RSRenderParticle::GetAccelerationAngle()
{
    return accelerationAngle_;
}

float RSRenderParticle::GetRedSpeed()
{
    return redSpeed_;
}

float RSRenderParticle::GetGreenSpeed()
{
    return greenSpeed_;
}

float RSRenderParticle::GetBlueSpeed()
{
    return blueSpeed_;
}

float RSRenderParticle::GetAlphaSpeed()
{
    return alphaSpeed_;
}

float RSRenderParticle::GetOpacitySpeed()
{
    return opacitySpeed_;
}

float RSRenderParticle::GetScaleSpeed()
{
    return scaleSpeed_;
}

float RSRenderParticle::GetSpinSpeed()
{
    return spinSpeed_;
}

float RSRenderParticle::GetAccelerationValueSpeed()
{
    return accelerationValueSpeed_;
}

float RSRenderParticle::GetAccelerationAngleSpeed()
{
    return accelerationAngleSpeed_;
}

float RSRenderParticle::GetRedF()
{
    return redF_;
}

float RSRenderParticle::GetGreenF()
{
    return greenF_;
}

float RSRenderParticle::GetBlueF()
{
    return blueF_;
}

float RSRenderParticle::GetAlphaF()
{
    return alphaF_;
}

const std::shared_ptr<RSImage>& RSRenderParticle::GetImage()
{
    return image_;
}

const Vector2f& RSRenderParticle::GetImageSize()
{
    return imageSize_;
}

const ParticleType& RSRenderParticle::GetParticleType()
{
    return particleType_;
}

int64_t RSRenderParticle::GetActiveTime()
{
    return activeTime_;
}

const std::shared_ptr<ParticleRenderParams>& RSRenderParticle::GetParticleRenderParams()
{
    return particleParams_;
}

size_t RSRenderParticle::GetImageIndex() const
{
    return imageIndex_;
}

void RSRenderParticle::InitProperty()
{
    if (particleParams_ == nullptr) {
        return;
    }
    position_ = CalculateParticlePosition(
        particleParams_->GetEmitShape(), particleParams_->GetEmitPosition(), particleParams_->GetEmitSize());

    float velocityValue =
        GetRandomValue(particleParams_->GetVelocityStartValue(), particleParams_->GetVelocityEndValue());
    float velocityAngle =
        GetRandomValue(particleParams_->GetVelocityStartAngle(), particleParams_->GetVelocityEndAngle());
    velocityAngle *= DEGREE_TO_RADIAN;
    velocity_ = Vector2f { velocityValue * std::cos(velocityAngle), velocityValue * std::sin(velocityAngle) };

    accelerationValue_ =
        GetRandomValue(particleParams_->GetAccelerationStartValue(), particleParams_->GetAccelerationEndValue());
    accelerationAngle_ =
        GetRandomValue(particleParams_->GetAccelerationStartAngle(), particleParams_->GetAccelerationEndAngle());
    acceleration_ = Vector2f { accelerationValue_ * std::cos(accelerationAngle_ * DEGREE_TO_RADIAN),
        accelerationValue_ * std::sin(accelerationAngle_ * DEGREE_TO_RADIAN) };

    spin_ = GetRandomValue(particleParams_->GetSpinStartValue(), particleParams_->GetSpinEndValue());
    opacity_ = GetRandomValue(particleParams_->GetOpacityStartValue(), particleParams_->GetOpacityEndValue());
    scale_ = GetRandomValue(particleParams_->GetScaleStartValue(), particleParams_->GetScaleEndValue());
    opacitySpeed_ = GetRandomValue(particleParams_->GetOpacityRandomStart(), particleParams_->GetOpacityRandomEnd());
    scaleSpeed_ = GetRandomValue(particleParams_->GetScaleRandomStart(), particleParams_->GetScaleRandomEnd());
    spinSpeed_ = GetRandomValue(particleParams_->GetSpinRandomStart(), particleParams_->GetSpinRandomEnd());
    accelerationValueSpeed_ =
        GetRandomValue(particleParams_->GetAccelRandomValueStart(), particleParams_->GetAccelRandomValueEnd());
    accelerationAngleSpeed_ =
        GetRandomValue(particleParams_->GetAccelRandomAngleStart(), particleParams_->GetAccelRandomAngleEnd());

    particleType_ = particleParams_->GetParticleType();
    if (particleType_ == ParticleType::POINTS) {
        SetColor();
        radius_ = particleParams_->GetParticleRadius();
    } else if (particleType_ == ParticleType::IMAGES) {
        image_ = particleParams_->GetParticleImage();
        imageSize_ = particleParams_->GetImageSize();
        imageIndex_ = particleParams_->GetImageIndex();
        if (image_ != nullptr) {
            auto pixelMap = image_->GetPixelMap();
            if (pixelMap != nullptr) {
                image_->SetDstRect(RectF(position_.x_, position_.y_, pixelMap->GetWidth(), pixelMap->GetHeight()));
            }
        }
    }
    activeTime_ = 0;
    lifeTime_ = GetRandomValue(particleParams_->GetLifeTimeStartValue(), particleParams_->GetLifeTimeEndValue());
}

bool RSRenderParticle::IsAlive() const
{
    if (dead_ == true) {
        return false;
    }

    if (particleParams_ != nullptr && particleParams_->GetLifeTimeStartValue() == (-1 * NS_PER_MS) &&
        particleParams_->GetLifeTimeEndValue() == (-1 * NS_PER_MS)) {
        return true;
    }
    return activeTime_ < lifeTime_;
}

void RSRenderParticle::SetIsDead()
{
    dead_ = true;
}

float RSRenderParticle::GetRandomValue(float min, float max)
{
    if (ROSEN_EQ(min, max)) {
        return min;
    }
    if (min > max) {
        std::swap(min, max);
    }
    int rand_int = rand() % RAND_PRECISION;
    float rand_float = min + (static_cast<float>(rand_int) / RAND_PRECISION) * (max - min);
    return rand_float;
}

void RSRenderParticle::SetColor()
{
    if (particleParams_ == nullptr) {
        return;
    }
    if (particleParams_->GetColorDistribution() == DistributionType::GAUSSIAN) {
        auto& colorStart = particleParams_->GetColorStartValue();
        auto& colorEnd = particleParams_->GetColorEndValue();
        auto redScale = std::abs(colorEnd.GetRed() - colorStart.GetRed());
        auto greenScale = std::abs(colorEnd.GetGreen() - colorStart.GetGreen());
        auto blueScale = std::abs(colorEnd.GetBlue() - colorStart.GetBlue());
        auto alphaScale = std::abs(colorEnd.GetAlpha() - colorStart.GetAlpha());
        auto meanRed = (colorStart.GetRed() + colorEnd.GetRed()) / 2;
        auto meanGreen = (colorStart.GetGreen() + colorEnd.GetGreen()) / 2;
        auto meanBlue = (colorStart.GetBlue() + colorEnd.GetBlue()) / 2;
        auto meanAlpha = (colorStart.GetAlpha() + colorEnd.GetAlpha()) / 2;

        color_.SetRed(GenerateColorComponent(meanRed, SIGMA * redScale));
        color_.SetGreen(GenerateColorComponent(meanGreen, SIGMA * greenScale));
        color_.SetBlue(GenerateColorComponent(meanBlue, SIGMA * blueScale));
        color_.SetAlpha(GenerateColorComponent(meanAlpha, SIGMA * alphaScale));
    } else {
        float colorRandomValue = GetRandomValue(0.0f, 1.0f);
        color_ = Lerp(particleParams_->GetColorStartValue(), particleParams_->GetColorEndValue(), colorRandomValue);
    }
    redSpeed_ = GetRandomValue(particleParams_->GetRedRandomStart(), particleParams_->GetRedRandomEnd());
    greenSpeed_ = GetRandomValue(particleParams_->GetGreenRandomStart(), particleParams_->GetGreenRandomEnd());
    blueSpeed_ = GetRandomValue(particleParams_->GetBlueRandomStart(), particleParams_->GetBlueRandomEnd());
    alphaSpeed_ = GetRandomValue(particleParams_->GetAlphaRandomStart(), particleParams_->GetAlphaRandomEnd());
}

// Generate color components that follow normal distribution
int RSRenderParticle::GenerateColorComponent(double mean, double stddev)
{
    // Creates a random number engine and a normal distribution object.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::normal_distribution<> dis(mean, stddev);

    double number = dis(gen);
    int component = static_cast<int>(std::round(std::abs(number)));
    component = std::max(0, std::min(component, 255)); // 255 is RGB Component max.
    return component;
}

Vector2f RSRenderParticle::CalculateParticlePosition(
    const ShapeType& emitShape, const Vector2f& position, const Vector2f& emitSize)
{
    float positionX = 0.f;
    float positionY = 0.f;
    if (emitShape == ShapeType::RECT) {
        float minX = position.x_;
        float maxX = position.x_ + emitSize.x_;
        positionX = GetRandomValue(minX, maxX);
        float minY = position.y_;
        float maxY = position.y_ + emitSize.y_;
        positionY = GetRandomValue(minY, maxY);
    }
    if (emitShape == ShapeType::CIRCLE || emitShape == ShapeType::ELLIPSE) {
        float dx = emitSize.x_;
        float dy = emitSize.y_;
        float x = position.x_ + dx / 2;
        float y = position.y_ + dy / 2;
        float theta = GetRandomValue(0.f, 2 * PI);
        if (emitShape == ShapeType::CIRCLE) {
            float d = std::min(emitSize.x_, emitSize.y_);
            float r = GetRandomValue(0.f, d) / 2;
            positionX = x + r * cos(theta);
            positionY = y + r * sin(theta);
        } else {
            float rx = GetRandomValue(0.f, dx) / 2;
            float ry = GetRandomValue(0.f, dy) / 2;
            positionX = x + rx * cos(theta);
            positionY = y + ry * sin(theta);
        }
    }
    return Vector2f { positionX, positionY };
}

void EmitterUpdater::Dump(std::string& out)
{
    out += "emitterIndex:" + std::to_string(emitterIndex_);
    if (position_) {
        out += " position[" + std::to_string(position_->x_) + " ";
        out += std::to_string(position_->y_) + "]";
    }
    if (emitSize_) {
        out += " emitSize[" + std::to_string(emitSize_->x_) + " ";
        out += std::to_string(emitSize_->y_) + "]";
    }
    if (emitRate_) {
        out += " emitRate:" + std::to_string(emitRate_.value());
    }
}
} // namespace Rosen
} // namespace OHOS
