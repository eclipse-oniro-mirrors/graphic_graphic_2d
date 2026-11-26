/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "ui_effect/property/include/rs_ui_shader_base.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSUIShaderBaseTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSUIShaderBaseTest::SetUpTestCase() {}
void RSUIShaderBaseTest::TearDownTestCase() {}
void RSUIShaderBaseTest::SetUp() {}
void RSUIShaderBaseTest::TearDown() {}

/**
 * @tc.name: RSNGShaderBaseCreate001
 * @tc.desc: Calling Create(RSNGEffectType::AIBAR_GLOW)
 *           should return a non-null RSNGAIBarGlow instance
 * @tc.type:FUNC
 */
HWTEST_F(RSUIShaderBaseTest, RSNGShaderBaseCreate001, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::AIBAR_GLOW);
    EXPECT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::AIBAR_GLOW);
}

/**
 * @tc.name: RSNGShaderBaseCreate002
 * @tc.desc: Calling Create(RSNGEffectType::ROUNDED_RECT_FLOWLIGHT)
 *           should return a non-null RSNGRoundedRectFlowlight instance
 * @tc.type:FUNC
 */
HWTEST_F(RSUIShaderBaseTest, RSNGShaderBaseCreate002, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::ROUNDED_RECT_FLOWLIGHT);
    EXPECT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::ROUNDED_RECT_FLOWLIGHT);
}


/**
 * @tc.name: RSNGShaderBaseCreate003
 * @tc.desc: Calling Create(RSNGEffectType::GRADIENT_FLOW_COLORS)
 *           should return a non-null RSNGGradientFlowColors instance
 * @tc.type:FUNC
 */
HWTEST_F(RSUIShaderBaseTest, RSNGShaderBaseCreate003, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::GRADIENT_FLOW_COLORS);
    EXPECT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::GRADIENT_FLOW_COLORS);
}

/**
 * @tc.name: RSNGShaderBaseCreateCircleFlowlight
 * @tc.desc: Calling Create(RSNGEffectType::CIRCLE_FLOWLIGHT)
 *           should return a non-null RSNGCircleFlowlight instance
 * @tc.type:FUNC
 */
HWTEST_F(RSUIShaderBaseTest, RSNGShaderBaseCreateCircleFlowlight, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::CIRCLE_FLOWLIGHT);
    ASSERT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::CIRCLE_FLOWLIGHT);
}

/**
 * @tc.name: RSNGShaderBaseCreateFlowLightSweep
 * @tc.desc: Calling Create(RSNGEffectType::FLOW_LIGHT_SWEEP)
 *           should return a non-null RSNGFlowLightSweep instance
 * @tc.type:FUNC
 */
HWTEST_F(RSUIShaderBaseTest, RSNGShaderBaseCreateFlowLightSweep, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::FLOW_LIGHT_SWEEP);
    EXPECT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::FLOW_LIGHT_SWEEP);
}

/**
 * @tc.name: RSNGShaderBaseCreateAIBarRectHalo
 * @tc.desc: Calling Create(RSNGEffectType::AIBAR_RECT_HALO)
 *           should return a non-null RSNGAIBarRectHalo instance
 * @tc.type:FUNC
 */
HWTEST_F(RSUIShaderBaseTest, RSNGShaderBaseCreateAIBarRectHalo, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::AIBAR_RECT_HALO);
    EXPECT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::AIBAR_RECT_HALO);
}

/**
 * @tc.name: RSNGShaderBaseCreateBorderSDFShader
 * @tc.desc: Calling Create(RSNGEffectType::BORDER_SDF_SHADER)
 *           should return a non-null RSNGBorderSDFShader instance
 * @tc.type:FUNC
 */
HWTEST_F(RSUIShaderBaseTest, RSNGShaderBaseCreateBorderSDFShader, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::BORDER_SDF_SHADER);
    EXPECT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::BORDER_SDF_SHADER);
}

/**
 * @tc.name: RSNGShaderBaseCreateBorderSDFLGColor
 * @tc.desc: Calling Create(RSNGEffectType::BORDER_SDF_LG_COLOR)
 *           should return a non-null RSNGBorderSDFLGColor instance
 * @tc.type:FUNC
 */
HWTEST_F(RSUIShaderBaseTest, RSNGShaderBaseCreateBorderSDFLGColor, TestSize.Level1)
{
    auto shader = RSNGShaderBase::Create(RSNGEffectType::BORDER_SDF_LG_COLOR);
    EXPECT_NE(shader, nullptr);
    EXPECT_EQ(shader->GetType(), RSNGEffectType::BORDER_SDF_LG_COLOR);
}

/**
 * @tc.name: EnableCache_Chain_PropagatesToAllEffects
 * @tc.desc: Verify EnableCache propagates cache policy to all effects in the chain
 * @tc.type: FUNC
 */
HWTEST_F(RSUIShaderBaseTest, EnableCache_Chain_PropagatesToAllEffects, TestSize.Level1)
{
    auto head = RSNGShaderBase::Create(RSNGEffectType::AIBAR_GLOW);
    ASSERT_NE(head, nullptr);
    auto tail = RSNGShaderBase::Create(RSNGEffectType::FLOW_LIGHT_SWEEP);
    ASSERT_NE(tail, nullptr);
    head->nextEffect_ = tail;

    head->EnableCache(RSFrameCacheLevel::CONTAINER, { RSFrameSkipMode::FIXED_INTERVAL, 5 });

    EXPECT_EQ(head->GetFrameCacheLevel(), RSFrameCacheLevel::CONTAINER);
    EXPECT_EQ(head->GetFrameSkipPolicy().mode, RSFrameSkipMode::FIXED_INTERVAL);
    EXPECT_EQ(head->GetFrameSkipPolicy().skipInterval, 5u);

    EXPECT_EQ(tail->GetFrameCacheLevel(), RSFrameCacheLevel::CONTAINER);
    EXPECT_EQ(tail->GetFrameSkipPolicy().mode, RSFrameSkipMode::FIXED_INTERVAL);
    EXPECT_EQ(tail->GetFrameSkipPolicy().skipInterval, 5u);
}

/**
 * @tc.name: SetValue_CachePolicyNeedsSync_ReturnsFalse
 * @tc.desc: Verify SetValue returns false when cache policy changed since last GetRenderEffect commit
 * @tc.type: FUNC
 */
HWTEST_F(RSUIShaderBaseTest, SetValue_CachePolicyNeedsSync_ReturnsFalse, TestSize.Level1)
{
    auto oldShader = RSNGShaderBase::Create(RSNGEffectType::AIBAR_GLOW);
    ASSERT_NE(oldShader, nullptr);
    oldShader->EnableCache(RSFrameCacheLevel::PER_EFFECT, { RSFrameSkipMode::ON_PARAM_SAME, 2 });

    auto newShader = RSNGShaderBase::Create(RSNGEffectType::AIBAR_GLOW);
    ASSERT_NE(newShader, nullptr);
    newShader->EnableCache(RSFrameCacheLevel::CONTAINER, { RSFrameSkipMode::FIXED_INTERVAL, 3 });
    newShader->GetRenderEffect();

    RSNode node(false);
    EXPECT_FALSE(newShader->SetValue(oldShader, node, {}));
}
} // namespace OHOS::Rosen
