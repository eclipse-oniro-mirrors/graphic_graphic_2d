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

#include <memory>
#include <vector>

#include "gtest/gtest.h"

#include "animation/rs_cubic_bezier_interpolator.h"
#include "animation/rs_render_particle_animation.h"
#include "common/rs_vector2.h"
#include "modifier/rs_render_property.h"
#include "pipeline/rs_canvas_render_node.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSRenderParticleEffectorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetEmitConfig();
    void SetColor();
    void SetOpacity();
    void SetUp() override;
    void TearDown() override;
    static constexpr uint64_t ANIMATION_ID = 12345;
    static constexpr uint64_t PROPERTY_ID = 54321;
    EmitterConfig emitterConfig_;
    ParticleVelocity velocity_;
    RenderParticleAcceleration acceleration_;
    RenderParticleColorParaType color_;
    RenderParticleParaType<float> opacity_;
    RenderParticleParaType<float> scale_;
    RenderParticleParaType<float> spin_;

    std::shared_ptr<ParticleRenderParams> params;
    std::shared_ptr<RSRenderParticle> particle;
    std::shared_ptr<RSRenderParticleEffector> effector;
    float deltaTime = 0.1f;
    int64_t activeTime = 100000;
};

void RSRenderParticleEffectorTest::SetUpTestCase() {}
void RSRenderParticleEffectorTest::TearDownTestCase() {}
void RSRenderParticleEffectorTest::SetEmitConfig()
{
    int emitRate = 20;
    ShapeType emitShape = ShapeType::RECT;
    Vector2f position = Vector2f(0.f, 0.f);
    Vector2f emitSize = Vector2f(10.f, 10.f);
    int particleCount = 20;
    Range<int64_t> lifeTime = Range<int64_t>(3000, 3000); // 3000 is lifeTime.
    ParticleType type = ParticleType::POINTS;
    float radius = 1;
    std::shared_ptr<RSImage> image;
    Vector2f imageSize = Vector2f(1.f, 1.f);
    emitterConfig_ =
        EmitterConfig(emitRate, emitShape, position, emitSize, particleCount, lifeTime, type, radius, image, imageSize);
}

void RSRenderParticleEffectorTest::SetColor()
{
    Color start = RSColor(200, 0, 0, 100);
    Color end = RSColor(255, 255, 255, 255);
    Range<Color> colorVal = Range<Color>(start, end);
    DistributionType distribution = DistributionType::UNIFORM;
    ParticleUpdator colorUpdator = ParticleUpdator::RANDOM;
    Range<float> redRandom = Range<float>(0.1f, 1.f);
    Range<float> greenRandom = Range<float>(0.1f, 1.f);
    Range<float> blueRandom = Range<float>(0.1f, 1.f);
    Range<float> alphaRandom = Range<float>(0.1f, 1.f);
    std::vector<std::shared_ptr<ChangeInOverLife<Color>>> colorChangeOverLife = {};
    color_ = RenderParticleColorParaType(
        colorVal, distribution, colorUpdator, redRandom, greenRandom, blueRandom, alphaRandom, colorChangeOverLife);
}

void RSRenderParticleEffectorTest::SetOpacity()
{
    Range<float> opacityVal = Range<float>(0.5, 1);
    ParticleUpdator opacityUpdator = ParticleUpdator::CURVE;
    Range<float> opacityRandom;
    float fromValue = 0.1f;
    float toValue = 1.f;
    int startMillis = 0;
    int endMillis = 3000;
    std::shared_ptr<RSInterpolator> interpolator = nullptr;
    auto change1 = std::make_shared<ChangeInOverLife<float>>(fromValue, toValue, startMillis, endMillis, interpolator);
    auto change2 =
        std::make_shared<ChangeInOverLife<float>>(toValue, fromValue, endMillis + 4000, endMillis + 7000, interpolator);
    std::vector<std::shared_ptr<ChangeInOverLife<float>>> opacityChangeOverLife;
    opacityChangeOverLife.push_back(change1);
    opacityChangeOverLife.push_back(change2);
    opacity_ = RenderParticleParaType(opacityVal, opacityUpdator, opacityRandom, opacityChangeOverLife);
}

void RSRenderParticleEffectorTest::SetUp()
{
    SetEmitConfig();
    SetColor();
    SetOpacity();
    Range<float> scaleVal = Range<float>(0.5, 1);
    ParticleUpdator scaleUpdator = ParticleUpdator::RANDOM;
    Range<float> scaleRandom = Range<float>(0.1f, 1.f);
    std::vector<std::shared_ptr<ChangeInOverLife<float>>> scaleChangeOverLife;
    scale_ = RenderParticleParaType(scaleVal, scaleUpdator, scaleRandom, scaleChangeOverLife);
    Range<float> spinRandom = Range<float>(1.f, 0.1f);
    spin_ = RenderParticleParaType(scaleVal, scaleUpdator, spinRandom, scaleChangeOverLife);
    params = std::make_shared<ParticleRenderParams>(
        emitterConfig_, velocity_, acceleration_, color_, opacity_, scale_, spin_);
    particle = std::make_shared<RSRenderParticle>(params);
    effector = std::make_shared<RSRenderParticleEffector>();
}
void RSRenderParticleEffectorTest::TearDown() {}

/**
 * @tc.name: UpdateColor001
 * @tc.desc: Verify the UpdateColor
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, UpdateColor001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateColor001 start";
    ASSERT_TRUE(effector != nullptr);
    ASSERT_TRUE(particle != nullptr);
    effector->UpdateColor(particle, deltaTime);
    EXPECT_TRUE(particle->GetColor() != Color::FromArgbInt(0x00000000));
    particle->SetParticleType(ParticleType::IMAGES);
    effector->UpdateColor(particle, deltaTime);
    std::shared_ptr<RSRenderParticle> particle1 = nullptr;
    effector->UpdateColor(particle1, deltaTime);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateColor001 end";
}

/**
 * @tc.name: UpdateOpacity001
 * @tc.desc: Verify the UpdateOpacity
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, UpdateOpacity001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateOpacity001 start";
    ASSERT_TRUE(effector != nullptr);
    effector->UpdateOpacity(particle, deltaTime);
    ASSERT_TRUE(particle != nullptr);
    EXPECT_TRUE(particle->GetOpacity() != 0.f);

    Range<float> opacityVal = Range<float>(0.0, 0.0);
    ParticleUpdator opacityUpdator = ParticleUpdator::RANDOM;
    Range<float> opacityRandom = Range<float>(0.0f, 0.0f);
    std::vector<std::shared_ptr<ChangeInOverLife<float>>> opacityChangeOverLife;
    auto opacity = RenderParticleParaType(opacityVal, opacityUpdator, opacityRandom, opacityChangeOverLife);

    auto renderParams = std::make_shared<ParticleRenderParams>(
        emitterConfig_, velocity_, acceleration_, color_, opacity, scale_, spin_);
    auto particle_opacity = std::make_shared<RSRenderParticle>(renderParams);
    effector->UpdateOpacity(particle_opacity, deltaTime);

    opacityRandom = Range<float>(1.0f, 1.0f);
    opacity = RenderParticleParaType(opacityVal, opacityUpdator, opacityRandom, opacityChangeOverLife);
    renderParams = std::make_shared<ParticleRenderParams>(
        emitterConfig_, velocity_, acceleration_, color_, opacity, scale_, spin_);
    particle_opacity = std::make_shared<RSRenderParticle>(renderParams);
    effector->UpdateOpacity(particle_opacity, deltaTime);

    opacityVal = Range<float>(1.0, 1.0);
    opacityRandom = Range<float>(0.0f, 0.0f);
    opacity = RenderParticleParaType(opacityVal, opacityUpdator, opacityRandom, opacityChangeOverLife);
    renderParams = std::make_shared<ParticleRenderParams>(
        emitterConfig_, velocity_, acceleration_, color_, opacity, scale_, spin_);
    particle_opacity = std::make_shared<RSRenderParticle>(renderParams);
    effector->UpdateOpacity(particle_opacity, deltaTime);

    std::shared_ptr<RSRenderParticle> particle1 = nullptr;
    effector->UpdateOpacity(particle1, deltaTime);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateOpacity001 end";
}

/**
 * @tc.name: UpdateScale001
 * @tc.desc: Verify the UpdateScale
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, UpdateScale001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateScale001 start";
    ASSERT_TRUE(effector != nullptr);
    effector->UpdateScale(particle, deltaTime);
    ASSERT_TRUE(particle != nullptr);
    EXPECT_TRUE(particle->GetScale() != 0.f);

    Range<float> scaleVal = Range<float>(0.0, 0.0);
    ParticleUpdator scaleUpdator = ParticleUpdator::RANDOM;
    Range<float> scaleRandom = Range<float>(0.0f, 0.0f);
    std::vector<std::shared_ptr<ChangeInOverLife<float>>> scaleChangeOverLife;
    auto scale = RenderParticleParaType(scaleVal, scaleUpdator, scaleRandom, scaleChangeOverLife);
    auto renderParams = std::make_shared<ParticleRenderParams>(
        emitterConfig_, velocity_, acceleration_, color_, opacity_, scale, spin_);
    auto particle_scale = std::make_shared<RSRenderParticle>(renderParams);
    effector->UpdateScale(particle_scale, deltaTime);

    scaleRandom = Range<float>(1.0f, 1.0f);
    scale = RenderParticleParaType(scaleVal, scaleUpdator, scaleRandom, scaleChangeOverLife);
    renderParams = std::make_shared<ParticleRenderParams>(
        emitterConfig_, velocity_, acceleration_, color_, opacity_, scale, spin_);
    particle_scale = std::make_shared<RSRenderParticle>(renderParams);
    effector->UpdateScale(particle_scale, deltaTime);

    scaleVal = Range<float>(1.0, 1.0);
    scaleRandom = Range<float>(0.0f, 0.0f);
    scale = RenderParticleParaType(scaleVal, scaleUpdator, scaleRandom, scaleChangeOverLife);
    renderParams = std::make_shared<ParticleRenderParams>(
        emitterConfig_, velocity_, acceleration_, color_, opacity_, scale, spin_);
    particle_scale = std::make_shared<RSRenderParticle>(renderParams);
    effector->UpdateScale(particle_scale, deltaTime);

    std::shared_ptr<RSRenderParticle> particle1 = nullptr;
    effector->UpdateScale(particle1, deltaTime);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateScale001 end";
}

/**
 * @tc.name: UpdateSpin001
 * @tc.desc: Verify the UpdateSpin
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, UpdateSpin001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateSpin001 start";
    ASSERT_TRUE(effector != nullptr);
    effector->UpdateSpin(particle, deltaTime);
    ASSERT_TRUE(particle != nullptr);
    EXPECT_TRUE(particle->GetSpin() != 0.f);
    std::shared_ptr<RSRenderParticle> particle1 = nullptr;
    effector->UpdateSpin(particle1, deltaTime);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateSpin001 end";
}

/**
 * @tc.name: UpdateEffect001
 * @tc.desc: Verify the UpdateSpin UpdateScale UpdateOpacity UpdateColor
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, UpdateEffect001, TestSize.Level1)
{
    Color start = RSColor(255, 255, 255, 255);
    Color end = RSColor(255, 255, 255, 255);
    Range<Color> colorVal = Range<Color>(start, end);
    ParticleUpdator randomUpdator = ParticleUpdator::RANDOM;
    ParticleUpdator curveUpdator = ParticleUpdator::CURVE;
    Range<float> redRandom = Range<float>(-1.0f, 0.f);
    Range<float> greenRandom = Range<float>(-1.0f, 0.f);
    Range<float> blueRandom = Range<float>(-1.0f, 0.f);
    Range<float> alphaRandom = Range<float>(-1.0f, 0.f);
    std::vector<std::shared_ptr<ChangeInOverLife<Color>>> colorChangeOverLife = {};
    RenderParticleColorParaType color = RenderParticleColorParaType(colorVal, DistributionType::GAUSSIAN, randomUpdator,
        redRandom, greenRandom, blueRandom, alphaRandom, colorChangeOverLife);
    Range<float> opacityVal = Range<float>(0.5f, 1.0f);
    Range<float> randomSpeed = Range<float>(0.1f, 1.f);
    Range<float> opacityRandom;
    float fromValue = 0.1f;
    float toValue = 1.f;
    int startMillis = 0;
    int endMillis = 3000;
    std::shared_ptr<RSInterpolator> interpolator =
        std::make_shared<RSCubicBezierInterpolator>(0.42f, 0.0f, 0.58f, 1.0f);
    auto change1 = std::make_shared<ChangeInOverLife<float>>(fromValue, toValue, startMillis, endMillis, interpolator);
    auto change2 =
        std::make_shared<ChangeInOverLife<float>>(toValue, fromValue, endMillis + 4000, endMillis + 7000, interpolator);
    std::vector<std::shared_ptr<ChangeInOverLife<float>>> valChangeOverLife;
    valChangeOverLife.push_back(change1);
    valChangeOverLife.push_back(change2);
    RenderParticleParaType<float> opacity =
        RenderParticleParaType(opacityVal, randomUpdator, randomSpeed, valChangeOverLife);
    RenderParticleParaType<float> scale =
        RenderParticleParaType(opacityVal, curveUpdator, randomSpeed, valChangeOverLife);
    Range<float> spinRandom = Range<float>(1.f, 0.1f);
    RenderParticleParaType<float> spin =
        RenderParticleParaType(opacityVal, curveUpdator, randomSpeed, valChangeOverLife);
    params =
        std::make_shared<ParticleRenderParams>(emitterConfig_, velocity_, acceleration_, color, opacity, scale, spin);
    particle = std::make_shared<RSRenderParticle>(params);
    effector = std::make_shared<RSRenderParticleEffector>();
    effector->UpdateColor(particle, deltaTime);
    ASSERT_TRUE(effector != nullptr);
    ASSERT_TRUE(particle != nullptr);
    EXPECT_TRUE(particle->GetColor() != Color::FromArgbInt(0x00000000));
    effector->UpdateOpacity(particle, deltaTime);
    EXPECT_TRUE(particle->GetOpacity() != 0.f);
    effector->UpdateScale(particle, deltaTime);
    EXPECT_TRUE(particle->GetScale() != 0.f);
    effector->UpdateSpin(particle, deltaTime);
    EXPECT_TRUE(particle->GetSpin() != 0.f);
}

/**
 * @tc.name: UpdateColorCurve001
 * @tc.desc: Verify the UpdateColorCurve
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, UpdateColorCurve001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateColorCurve001 start";
    int emitRate = 20;
    ShapeType emitShape = ShapeType::RECT;
    Vector2f position = Vector2f(0.f, 0.f);
    Vector2f emitSize = Vector2f(10.f, 10.f);
    int particleCount = 20;
    Range<int64_t> lifeTime = Range<int64_t>(1000, 3000); //  1000 is lifeTime range start, 3000 is lifeTime.
    ParticleType type = ParticleType::POINTS;
    float radius = 1;
    std::shared_ptr<RSImage> image;
    Vector2f imageSize = Vector2f(1.f, 1.f);
    EmitterConfig emitterConfig =
        EmitterConfig(emitRate, emitShape, position, emitSize, particleCount, lifeTime, type, radius, image, imageSize);
    ParticleVelocity velocity;
    RenderParticleAcceleration acceleration;
    RenderParticleParaType<float> opacity;
    RenderParticleParaType<float> scale;
    RenderParticleParaType<float> spin;
    Color start = RSColor(255, 255, 255, 255);
    Color end = RSColor(255, 255, 255, 255);
    Range<Color> colorVal = Range<Color>(start, end);
    DistributionType distribution = DistributionType::GAUSSIAN;
    ParticleUpdator curveUpdator = ParticleUpdator::CURVE;
    Range<float> redRandom = Range<float>(-1.0f, 0.f);
    Range<float> greenRandom = Range<float>(-1.0f, 0.f);
    Range<float> blueRandom = Range<float>(-1.0f, 0.f);
    Range<float> alphaRandom = Range<float>(-1.0f, 0.f);
    std::vector<std::shared_ptr<ChangeInOverLife<Color>>> colorChangeOverLife;
    Color colorFromValue = RSColor(0, 0, 0, 100);
    Color colorToValue = RSColor(100, 200, 100, 200);
    int startMillis = 0;
    int endMillis = 3000;
    std::shared_ptr<RSInterpolator> interpolator =
        std::make_shared<RSCubicBezierInterpolator>(0.42f, 0.0f, 0.58f, 1.0f);
    auto colorChange =
        std::make_shared<ChangeInOverLife<Color>>(colorFromValue, colorToValue, startMillis, endMillis, interpolator);
    colorChangeOverLife.push_back(colorChange);
    RenderParticleColorParaType color = RenderParticleColorParaType(
        colorVal, distribution, curveUpdator, redRandom, greenRandom, blueRandom, alphaRandom, colorChangeOverLife);
    params = std::make_shared<ParticleRenderParams>(emitterConfig, velocity, acceleration, color, opacity, scale, spin);
    particle = std::make_shared<RSRenderParticle>(params);
    effector = std::make_shared<RSRenderParticleEffector>();
    ASSERT_TRUE(effector != nullptr);
    ASSERT_TRUE(particle != nullptr);
    effector->UpdateColor(particle, deltaTime);
    EXPECT_TRUE(particle->GetColor() != Color::FromArgbInt(0x00000000));
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateColorCurve001 end";
}

/**
 * @tc.name: UpdateAccelerationRandom001
 * @tc.desc: Verify the UpdateAccelerationRandom
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, UpdateAccelerationRandom001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateAccelerationRandom001 start";
    ParticleVelocity velocity;
    RenderParticleAcceleration acceleration;
    RenderParticleParaType<float> opacity;
    RenderParticleParaType<float> scale;
    RenderParticleParaType<float> spin;
    RenderParticleColorParaType color;
    Range<float> velocityValue = Range<float>(1, 10);
    Range<float> velocityAngle = Range<float>(1, 10);
    velocity = ParticleVelocity(velocityValue, velocityAngle);
    ParticleUpdator randomUpdator = ParticleUpdator::RANDOM;
    Range<float> val = Range<float>(0.5, 1);
    Range<float> randomSpeed = Range<float>(-1.f, 0.f);
    std::vector<std::shared_ptr<ChangeInOverLife<float>>> valChangeOverLife;
    RenderParticleParaType<float> accelerationValue =
        RenderParticleParaType(val, randomUpdator, randomSpeed, valChangeOverLife);
    RenderParticleParaType<float> accelerationAngle =
        RenderParticleParaType(val, randomUpdator, randomSpeed, valChangeOverLife);
    acceleration = RenderParticleAcceleration(accelerationValue, accelerationAngle);
    params =
        std::make_shared<ParticleRenderParams>(emitterConfig_, velocity, acceleration, color, opacity, scale, spin);
    particle = std::make_shared<RSRenderParticle>(params);
    ASSERT_TRUE(particle != nullptr);
    particle->SetActiveTime(activeTime);
    effector = std::make_shared<RSRenderParticleEffector>();
    int fieldStrength = 10;
    ShapeType fieldShape = ShapeType::RECT;
    Vector2f fieldSize = { 200.f, 200.f };
    Vector2f fieldCenter = { 40.f, 50.f };
    uint16_t fieldFeather = 50;
    float noiseScale = 8.f;
    float noiseFrequency = 2.f;
    float noiseAmplitude = 4.f;
    auto noiseField = std::make_shared<ParticleNoiseField>(
        fieldStrength, fieldShape, fieldSize, fieldCenter, fieldFeather, noiseScale, noiseFrequency, noiseAmplitude);
    auto noiseFields = std::make_shared<ParticleNoiseFields>();
    ASSERT_TRUE(noiseFields != nullptr);
    ASSERT_TRUE(effector != nullptr);
    noiseFields->AddField(noiseField);
    effector->Update(particle, noiseFields, nullptr, nullptr, activeTime);
    EXPECT_TRUE(particle->GetActiveTime() == 200000);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateAccelerationRandom001 end";
}

/**
 * @tc.name: UpdateAccelerationCurve001
 * @tc.desc: Verify the UpdateAcceleration Curve
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, UpdateAccelerationCurve001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateAccelerationCurve001 start";
    ParticleVelocity velocity;
    RenderParticleAcceleration acceleration;
    RenderParticleParaType<float> opacity;
    RenderParticleParaType<float> scale;
    RenderParticleParaType<float> spin;
    RenderParticleColorParaType color;

    ParticleUpdator curveUpdator = ParticleUpdator::CURVE;
    Range<float> val = Range<float>(0.5, 1);
    Range<float> randomSpeed = Range<float>(-1.0f, 0.f);
    Range<float> opacityRandom;
    float fromValue = 0.1f;
    float toValue = 1.f;
    int startMillis = 0;
    int endMillis = 3000;
    std::shared_ptr<RSInterpolator> interpolator = nullptr;
    auto change1 = std::make_shared<ChangeInOverLife<float>>(fromValue, toValue, startMillis, endMillis, interpolator);
    auto change2 =
        std::make_shared<ChangeInOverLife<float>>(toValue, fromValue, endMillis + 4000, endMillis + 7000, interpolator);
    std::vector<std::shared_ptr<ChangeInOverLife<float>>> valChangeOverLife;
    valChangeOverLife.push_back(change1);
    valChangeOverLife.push_back(change2);
    RenderParticleParaType<float> accelerationValue =
        RenderParticleParaType(val, curveUpdator, randomSpeed, valChangeOverLife);
    RenderParticleParaType<float> accelerationAngle =
        RenderParticleParaType(val, curveUpdator, randomSpeed, valChangeOverLife);
    acceleration = RenderParticleAcceleration(accelerationValue, accelerationAngle);
    params =
        std::make_shared<ParticleRenderParams>(emitterConfig_, velocity, acceleration, color, opacity, scale, spin);
    auto particle1 = std::make_shared<RSRenderParticle>(params);
    ASSERT_TRUE(particle1 != nullptr);
    particle1->SetActiveTime(activeTime);
    effector = std::make_shared<RSRenderParticleEffector>();
    ASSERT_TRUE(effector != nullptr);
    effector->UpdateAccelerationValue(particle1, deltaTime);
    effector->UpdateAccelerationAngle(particle1, deltaTime);
    EXPECT_TRUE(particle1->GetAccelerationValue() != 0.f);
    EXPECT_TRUE(particle1->GetAccelerationAngle() != 0.f);
    particle1->particleParams_ = nullptr;
    effector->UpdateAccelerationValue(particle1, deltaTime);
    effector->UpdateAccelerationAngle(particle1, deltaTime);
    effector->UpdateScale(particle1, deltaTime);
    effector->UpdateSpin(particle1, deltaTime);
    effector->UpdateOpacity(particle1, deltaTime);
    effector->UpdateColor(particle1, deltaTime);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest UpdateAccelerationCurve001 end";
}

/**
 * @tc.name: Update001
 * @tc.desc: Verify the Update
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, Update001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest Update001 start";
    int fieldStrength = 0;
    ShapeType fieldShape = ShapeType::CIRCLE;
    Vector2f fieldSize = { 10.f, 10.f };
    Vector2f fieldCenter = { 40.f, 50.f };
    uint16_t fieldFeather = 50;
    float noiseScale = 8.f;
    float noiseFrequency = 2.f;
    float noiseAmplitude = 4.f;
    auto noiseField = std::make_shared<ParticleNoiseField>(
        fieldStrength, fieldShape, fieldSize, fieldCenter, fieldFeather, noiseScale, noiseFrequency, noiseAmplitude);
    auto noiseFields = std::make_shared<ParticleNoiseFields>();
    ASSERT_TRUE(noiseFields != nullptr);
    ASSERT_TRUE(effector != nullptr);
    ASSERT_TRUE(particle != nullptr);
    noiseFields->AddField(noiseField);
    effector->Update(particle, noiseFields, nullptr, nullptr, activeTime);
    EXPECT_TRUE(particle->GetActiveTime() == activeTime);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest Update001 end";
}

/**
 * @tc.name: Update002
 * @tc.desc: Verify the Update
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, Update002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest Update002 start";
    int fieldStrength = -10;
    ShapeType fieldShape = ShapeType::CIRCLE;
    Vector2f fieldSize = { 10.f, 10.f };
    Vector2f fieldCenter = { 40.f, 50.f };
    uint16_t fieldFeather = 50;
    float noiseScale = 8.f;
    float noiseFrequency = 2.f;
    float noiseAmplitude = 4.f;
    auto noiseField = std::make_shared<ParticleNoiseField>(
        fieldStrength, fieldShape, fieldSize, fieldCenter, fieldFeather, noiseScale, noiseFrequency, noiseAmplitude);
    auto noiseFields = std::make_shared<ParticleNoiseFields>();
    ASSERT_TRUE(noiseFields != nullptr);
    ASSERT_TRUE(effector != nullptr);
    ASSERT_TRUE(particle != nullptr);
    noiseFields->AddField(noiseField);
    effector->Update(particle, noiseFields, nullptr, nullptr, activeTime);
    EXPECT_TRUE(particle->GetActiveTime() == activeTime);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest Update002 end";
}

/**
 * @tc.name: Update003
 * @tc.desc: Verify the Update
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, Update003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest Update003 start";
    int fieldStrength = 10;
    ShapeType fieldShape = ShapeType::CIRCLE;
    Vector2f fieldSize = { 10.f, 10.f };
    Vector2f fieldCenter = { 40.f, 50.f };
    uint16_t fieldFeather = 50;
    float noiseScale = 8.f;
    float noiseFrequency = 2.f;
    float noiseAmplitude = 4.f;
    auto noiseField = std::make_shared<ParticleNoiseField>(
        fieldStrength, fieldShape, fieldSize, fieldCenter, fieldFeather, noiseScale, noiseFrequency, noiseAmplitude);
    auto noiseFields = std::make_shared<ParticleNoiseFields>();
    ASSERT_TRUE(noiseFields != nullptr);
    ASSERT_TRUE(effector != nullptr);
    ASSERT_TRUE(particle != nullptr);
    noiseFields->AddField(noiseField);
    effector->Update(particle, noiseFields, nullptr, nullptr, 0);
    EXPECT_TRUE(particle->GetActiveTime() == 0);
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest Update003 end";
}

/**
 * @tc.name: CalculateDistanceToRectangleEdge001
 * @tc.desc: Verify the CalculateDistanceToRectangleEdge
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, CalculateDistanceToRectangleEdge001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest CalculateDistanceToRectangleEdge001 start";
    int fieldStrength = 10;
    ShapeType fieldShape = ShapeType::RECT;
    Vector2f fieldSize = { 10.f, 10.f };
    Vector2f fieldCenter = { 5.f, 5.f };
    uint16_t fieldFeather = 50;
    float noiseScale = 8.f;
    float noiseFrequency = 2.f;
    float noiseAmplitude = 4.f;
    auto noiseField = std::make_shared<ParticleNoiseField>(
        fieldStrength, fieldShape, fieldSize, fieldCenter, fieldFeather, noiseScale, noiseFrequency, noiseAmplitude);

    Vector2f position = { 5.f, 5.f };
    Vector2f direction = { 0.f, 0.f };
    float distance = noiseField->CalculateDistanceToRectangleEdge(position, direction, fieldCenter, fieldSize);
    EXPECT_TRUE(ROSEN_EQ(distance, 0.f));
    direction = { 1.f, 0.f };
    distance = noiseField->CalculateDistanceToRectangleEdge(position, direction, fieldCenter, fieldSize);
    EXPECT_TRUE(ROSEN_EQ(distance, 5.f));
    direction = { 0.f, 1.f };
    distance = noiseField->CalculateDistanceToRectangleEdge(position, direction, fieldCenter, fieldSize);
    EXPECT_TRUE(ROSEN_EQ(distance, 5.f));
    direction = { 1.f, 1.f };
    distance = noiseField->CalculateDistanceToRectangleEdge(position, direction, fieldCenter, fieldSize);
    EXPECT_TRUE(distance > 5.f);

    float deltaTime = 10.f;
    Vector2f force = noiseField->ApplyField(position, deltaTime);
    EXPECT_TRUE(ROSEN_EQ(force.x_, 0.f) && ROSEN_EQ(force.y_, 0.f));

    deltaTime = 0.f;
    force = noiseField->ApplyField(position, deltaTime);
    EXPECT_TRUE(ROSEN_EQ(force.x_, 0.f) && ROSEN_EQ(force.y_, 0.f));
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest CalculateDistanceToRectangleEdge001 end";
}

/**
 * @tc.name: CalculateDistanceToEllipseEdge001
 * @tc.desc: Verify the CalculateDistanceToEllipseEdge
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, CalculateDistanceToEllipseEdge001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest CalculateDistanceToEllipseEdge001 start";
    int fieldStrength = 600;
    ShapeType fieldShape = ShapeType::RECT;
    Vector2f fieldSize = { 10.f, 20.f };
    Vector2f fieldCenter = { 5.f, 5.f };
    uint16_t fieldFeather = 50;
    float noiseScale = 8.f;
    float noiseFrequency = 2.f;
    float noiseAmplitude = 4.f;
    auto noiseField = std::make_shared<ParticleNoiseField>(
        fieldStrength, fieldShape, fieldSize, fieldCenter, fieldFeather, noiseScale, noiseFrequency, noiseAmplitude);

    Vector2f position = { 5.f, 5.f };
    Vector2f direction = { 0.f, 0.f };
    float distance = noiseField->CalculateDistanceToEllipseEdge(direction, fieldCenter, fieldSize);
    EXPECT_TRUE(ROSEN_EQ(distance, 0.f));
    direction = { 1.f, 0.f };
    distance = noiseField->CalculateDistanceToEllipseEdge(direction, fieldCenter, fieldSize);
    EXPECT_TRUE(ROSEN_EQ(distance, 5.f));
    direction = { 0.f, 1.f };
    distance = noiseField->CalculateDistanceToEllipseEdge(direction, fieldCenter, fieldSize);
    EXPECT_TRUE(ROSEN_EQ(distance, 10.f));

    float deltaTime = 10.f;
    Vector2f force = noiseField->ApplyField(position, deltaTime);
    EXPECT_TRUE(ROSEN_EQ(force.x_, 0.f) && ROSEN_EQ(force.y_, 0.f));
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest CalculateDistanceToRectangleEdge001 end";
}

/**
 * @tc.name: CalculateFeatherEffect001
 * @tc.desc: Verify the CalculateFeatherEffect
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, CalculateFeatherEffect001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest CalculateFeatherEffect001 start";
    int fieldStrength = -10;
    ShapeType fieldShape = ShapeType::CIRCLE;
    Vector2f fieldSize = { 10.f, 10.f };
    Vector2f fieldCenter = { 5.f, 5.f };
    uint16_t fieldFeather = 50;
    float noiseScale = 8.f;
    float noiseFrequency = 2.f;
    float noiseAmplitude = 4.f;
    auto noiseField = std::make_shared<ParticleNoiseField>(
        fieldStrength, fieldShape, fieldSize, fieldCenter, fieldFeather, noiseScale, noiseFrequency, noiseAmplitude);

    float distanceToEdge = 1.f;
    float featherWidth = 1.f;
    float distance = noiseField->CalculateFeatherEffect(distanceToEdge, featherWidth);
    EXPECT_TRUE(ROSEN_EQ(distance, 1.f));

    featherWidth = -1.f;
    distance = noiseField->CalculateFeatherEffect(distanceToEdge, featherWidth);
    EXPECT_TRUE(ROSEN_EQ(distance, 1.f));

    featherWidth = 0.f;
    distanceToEdge = -1.f;
    distance = noiseField->CalculateFeatherEffect(distanceToEdge, featherWidth);
    EXPECT_TRUE(ROSEN_EQ(distance, 1.f));

    Vector2f position = { 5.f, 5.f };
    float deltaTime = 10.f;
    Vector2f force = noiseField->ApplyField(position, deltaTime);
    EXPECT_TRUE(ROSEN_EQ(force.x_, 0.f) && ROSEN_EQ(force.y_, 0.f));

    deltaTime = 0.f;
    force = noiseField->ApplyField(position, deltaTime);
    EXPECT_TRUE(ROSEN_EQ(force.x_, 0.f) && ROSEN_EQ(force.y_, 0.f));
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest CalculateFeatherEffect001 end";
}

/**
 * @tc.name: ApplyField001
 * @tc.desc: Verify the ApplyField
 * @tc.type:FUNC
 * @tc.require: issueIA6IWR
 */
HWTEST_F(RSRenderParticleEffectorTest, ApplyField001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest ApplyField001 start";
    int fieldStrength = 0;
    ShapeType fieldShape = ShapeType::CIRCLE;
    Vector2f fieldSize = { 10.f, 10.f };
    Vector2f fieldCenter = { 5.f, 5.f };
    uint16_t fieldFeather = 50;
    float noiseScale = 8.f;
    float noiseFrequency = 2.f;
    float noiseAmplitude = 4.f;
    auto noiseField = std::make_shared<ParticleNoiseField>(
        fieldStrength, fieldShape, fieldSize, fieldCenter, fieldFeather, noiseScale, noiseFrequency, noiseAmplitude);

    Vector2f position = { 5.f, 5.f };
    float deltaTime = 10.f;
    Vector2f force = noiseField->ApplyField(position, deltaTime);
    EXPECT_TRUE(ROSEN_EQ(force.x_, 0.f) && ROSEN_EQ(force.y_, 0.f));

    position = { 15.f, 15.f };
    deltaTime = 0.f;
    force = noiseField->ApplyField(position, deltaTime);
    EXPECT_TRUE(ROSEN_EQ(force.x_, 0.f) && ROSEN_EQ(force.y_, 0.f));

    GTEST_LOG_(INFO) << "RSRenderParticleEffectorTest ApplyField001 end";
}
} // namespace Rosen
} // namespace OHOS