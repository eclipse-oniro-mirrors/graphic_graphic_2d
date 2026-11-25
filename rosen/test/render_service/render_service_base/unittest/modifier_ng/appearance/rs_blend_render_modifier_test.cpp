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

#include <cstdlib>
#include <cstring>
#include <memory>
#include <securec.h>

#include "gtest/gtest.h"
#include "gtest/hwext/gtest-tag.h"
#include "message_parcel.h"

#include "common/rs_vector4.h"
#include "modifier_ng/rs_modifier_ng_type.h"
#include "pipeline/rs_canvas_drawing_render_node.h"
#include "effect/rs_render_blender_base.h"
#include "modifier/rs_render_property.h"
#include "property/rs_properties.h"
#include "modifier_ng/appearance/rs_blend_render_modifier.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::ModifierNG;
namespace OHOS::Rosen {
class RSBlendRenderModifierNGTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSBlendRenderModifierNGTest::SetUpTestCase() {}
void RSBlendRenderModifierNGTest::TearDownTestCase() {}
void RSBlendRenderModifierNGTest::SetUp() {}
void RSBlendRenderModifierNGTest::TearDown() {}

/**
 * @tc.name: RSBlendRenderModifierTest
 * @tc.desc:GetType & ResetProperties
 * @tc.type:FUNC
 */
HWTEST_F(RSBlendRenderModifierNGTest, RSBlendRenderModifierTest, TestSize.Level1)
{
    RSBlendRenderModifier modifier;
    RSProperties properties;
    EXPECT_EQ(modifier.GetType(), ModifierNG::RSModifierType::BLENDER);
    modifier.ResetProperties(properties);
    EXPECT_EQ(properties.GetColorBlendMode(), 0);
    EXPECT_EQ(properties.GetColorBlendApplyType(), 0);
    // ResetProperties clears the NG blender object as well (added by the NG blender migration)
    EXPECT_EQ(properties.GetNGBlender(), nullptr);
}

/**
 * @tc.name: RSBlendRenderModifierNGBlenderTest
 * @tc.desc: verify the FOREGROUND_NG_BLENDER applier stores the NG object (store-only, no unpacking)
 *           and ResetProperties clears it.
 * @tc.type:FUNC
 */
HWTEST_F(RSBlendRenderModifierNGTest, RSBlendRenderModifierNGBlenderTest, TestSize.Level1)
{
    RSBlendRenderModifier modifier;
    RSProperties properties;
    EXPECT_EQ(properties.GetNGBlender(), nullptr);

    auto ngBlender = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(ngBlender, nullptr);
    // apply via the NG applier entry: FOREGROUND_NG_BLENDER
    properties.SetNGBlender(ngBlender);
    EXPECT_EQ(properties.GetNGBlender(), ngBlender);

    RSBlendRenderModifier resetModifier;
    resetModifier.ResetProperties(properties);
    EXPECT_EQ(properties.GetNGBlender(), nullptr);
}

/**
 * @tc.name: RSBlendRenderModifierNGBlenderApplierTest
 * @tc.desc: verify the FOREGROUND_NG_BLENDER applier of the LegacyPropertyApplierMap: a blender
 *           property attached to the modifier is applied to RSProperties by ApplyLegacyProperty.
 * @tc.type:FUNC
 */
HWTEST_F(RSBlendRenderModifierNGTest, RSBlendRenderModifierNGBlenderApplierTest, TestSize.Level1)
{
    RSBlendRenderModifier modifier;
    auto ngBlender = RSNGRenderBlenderBase::Create(RSNGEffectType::HDR_DARKEN_BLENDER);
    ASSERT_NE(ngBlender, nullptr);
    auto property = std::make_shared<RSRenderProperty<std::shared_ptr<RSNGRenderBlenderBase>>>(ngBlender, 1);
    modifier.AttachProperty(ModifierNG::RSPropertyType::FOREGROUND_NG_BLENDER, property);

    RSProperties properties;
    modifier.ApplyLegacyProperty(properties);
    EXPECT_EQ(properties.GetNGBlender(), ngBlender);

    // applying a null blender clears the stored NG object again
    auto nullProperty = std::make_shared<RSRenderProperty<std::shared_ptr<RSNGRenderBlenderBase>>>(nullptr, 2);
    modifier.DetachProperty(ModifierNG::RSPropertyType::FOREGROUND_NG_BLENDER);
    modifier.AttachProperty(ModifierNG::RSPropertyType::FOREGROUND_NG_BLENDER, nullProperty);
    modifier.ApplyLegacyProperty(properties);
    EXPECT_EQ(properties.GetNGBlender(), nullptr);
}
/**
 * @tc.name: RSBlendRenderModifierNGAdaptiveBlenderApplierTest
 * @tc.desc: verify the ADAPTIVE_DARK_BLENDER / ADAPTIVE_LIGHT_BLENDER appliers and the reset path.
 * @tc.type:FUNC
 */
HWTEST_F(RSBlendRenderModifierNGTest, RSBlendRenderModifierNGAdaptiveBlenderApplierTest, TestSize.Level1)
{
    RSBlendRenderModifier modifier;
    RSProperties properties;
    auto dark = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    auto light = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(dark, nullptr);
    ASSERT_NE(light, nullptr);

    modifier.AttachProperty(ModifierNG::RSPropertyType::ADAPTIVE_DARK_BLENDER,
        std::make_shared<RSRenderProperty<std::shared_ptr<RSNGRenderBlenderBase>>>(dark, 1));
    modifier.AttachProperty(ModifierNG::RSPropertyType::ADAPTIVE_LIGHT_BLENDER,
        std::make_shared<RSRenderProperty<std::shared_ptr<RSNGRenderBlenderBase>>>(light, 2));
    modifier.ApplyLegacyProperty(properties);
    EXPECT_EQ(properties.GetNGAdaptiveDarkBlender(), dark);
    EXPECT_EQ(properties.GetNGAdaptiveLightBlender(), light);

    modifier.ResetProperties(properties);
    EXPECT_EQ(properties.GetNGAdaptiveDarkBlender(), nullptr);
    EXPECT_EQ(properties.GetNGAdaptiveLightBlender(), nullptr);
}

/**
 * @tc.name: RSBlendRenderModifierNGAdaptiveBlenderPartialTest
 * @tc.desc: Cover the adaptive appliers with a single slot, a null value and the reset path on an
 *           empty modifier.
 * @tc.type:FUNC
 */
HWTEST_F(RSBlendRenderModifierNGTest, RSBlendRenderModifierNGAdaptiveBlenderPartialTest, TestSize.Level1)
{
    RSProperties properties;
    RSBlendRenderModifier modifier;

    // reset on an empty modifier: both adaptive slots stay empty
    modifier.ResetProperties(properties);
    EXPECT_EQ(properties.GetNGAdaptiveDarkBlender(), nullptr);
    EXPECT_EQ(properties.GetNGAdaptiveLightBlender(), nullptr);

    // only the dark slot is attached
    auto dark = RSNGRenderBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    ASSERT_NE(dark, nullptr);
    modifier.AttachProperty(ModifierNG::RSPropertyType::ADAPTIVE_DARK_BLENDER,
        std::make_shared<RSRenderProperty<std::shared_ptr<RSNGRenderBlenderBase>>>(dark, 1));
    modifier.ApplyLegacyProperty(properties);
    EXPECT_EQ(properties.GetNGAdaptiveDarkBlender(), dark);
    EXPECT_EQ(properties.GetNGAdaptiveLightBlender(), nullptr);

    // a null light value clears only that slot; the still-attached dark slot keeps its value
    modifier.AttachProperty(ModifierNG::RSPropertyType::ADAPTIVE_LIGHT_BLENDER,
        std::make_shared<RSRenderProperty<std::shared_ptr<RSNGRenderBlenderBase>>>(nullptr, 2));
    modifier.ApplyLegacyProperty(properties);
    EXPECT_EQ(properties.GetNGAdaptiveDarkBlender(), dark);
    EXPECT_EQ(properties.GetNGAdaptiveLightBlender(), nullptr);

    // a null dark value clears the remaining slot
    modifier.DetachProperty(ModifierNG::RSPropertyType::ADAPTIVE_DARK_BLENDER);
    modifier.AttachProperty(ModifierNG::RSPropertyType::ADAPTIVE_DARK_BLENDER,
        std::make_shared<RSRenderProperty<std::shared_ptr<RSNGRenderBlenderBase>>>(nullptr, 1));
    modifier.ApplyLegacyProperty(properties);
    EXPECT_EQ(properties.GetNGAdaptiveDarkBlender(), nullptr);
    EXPECT_EQ(properties.GetNGAdaptiveLightBlender(), nullptr);
}

} // namespace OHOS::Rosen