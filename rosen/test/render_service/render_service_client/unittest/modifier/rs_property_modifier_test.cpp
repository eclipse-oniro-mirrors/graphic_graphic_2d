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

#include <memory>
#include <ostream>
#include "gtest/gtest.h"
#include "modifier/rs_property.h"
#include "modifier/rs_property_modifier.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSPropertyModifierTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    const Vector2f INITIAL_VALUE_2F = Vector2f(0.f, 0.f);
    const Vector4f INITIAL_VALUE_4F = Vector4f(0.f, 0.f, 0.f, 0.f);
};

void RSPropertyModifierTest::SetUpTestCase() {}
void RSPropertyModifierTest::TearDownTestCase() {}
void RSPropertyModifierTest::SetUp() {}
void RSPropertyModifierTest::TearDown() {}

/**
 * @tc.name: GetModifierType
 * @tc.desc: RSEnvForegroundColorModifier Test
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, GetModifierType, TestSize.Level1)
{
    std::shared_ptr<RSPropertyBase> property = std::make_shared<RSPropertyBase>();
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSEnvForegroundColorModifier> colorModifier =
        std::make_shared<RSEnvForegroundColorModifier>(property);
    ASSERT_NE(colorModifier, nullptr);
    RSModifierType ModifierType = colorModifier->GetModifierType();
    EXPECT_EQ(ModifierType, RSModifierType::ENV_FOREGROUND_COLOR);
}

/**
 * @tc.name: CreateRenderModifier
 * @tc.desc: RSEnvForegroundColorModifier Test
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, CreateRenderModifier, TestSize.Level1)
{
    std::shared_ptr<RSPropertyBase> property = std::make_shared<RSPropertyBase>();
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSEnvForegroundColorModifier> colorModifier =
        std::make_shared<RSEnvForegroundColorModifier>(property);
    ASSERT_NE(colorModifier, nullptr);
    auto res = colorModifier->CreateRenderModifier();
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: GetModifierType02
 * @tc.desc: RSEnvForegroundColorStrategyModifier Test
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, GetModifierType02, TestSize.Level1)
{
    std::shared_ptr<RSPropertyBase> property = std::make_shared<RSPropertyBase>();
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSEnvForegroundColorStrategyModifier> colorStrategyModifier =
        std::make_shared<RSEnvForegroundColorStrategyModifier>(property);
    ASSERT_NE(colorStrategyModifier, nullptr);
    RSModifierType res = colorStrategyModifier->GetModifierType();
    EXPECT_EQ(res, RSModifierType::ENV_FOREGROUND_COLOR_STRATEGY);
}

/**
 * @tc.name: CreateRenderModifier02
 * @tc.desc: RSEnvForegroundColorStrategyModifier Test
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, CreateRenderModifier02, TestSize.Level1)
{
    std::shared_ptr<RSPropertyBase> property = std::make_shared<RSPropertyBase>();
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSEnvForegroundColorStrategyModifier> colorStrategyModifier =
        std::make_shared<RSEnvForegroundColorStrategyModifier>(property);
    ASSERT_NE(colorStrategyModifier, nullptr);
    auto renderModifier = colorStrategyModifier->CreateRenderModifier();
    EXPECT_NE(renderModifier, nullptr);
}

/**
 * @tc.name: Apply01
 * @tc.desc: RSBoundsModifier/RSBoundsSizeModifier/RSBoundsPositionModifier
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, Apply01, TestSize.Level1)
{
    std::shared_ptr<RSObjAbsGeometry> geometry = std::make_shared<RSObjAbsGeometry>();
    ASSERT_NE(geometry, nullptr);

    auto property = std::make_shared<RSProperty<Vector4f>>(INITIAL_VALUE_4F);
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSModifier> boundsModifier = std::make_shared<RSBoundsModifier>(property);
    ASSERT_NE(boundsModifier, nullptr);
    boundsModifier->Apply(geometry);

    auto property02 = std::make_shared<RSProperty<Vector2f>>(INITIAL_VALUE_2F);
    ASSERT_NE(property02, nullptr);
    std::shared_ptr<RSModifier> boundsSizeModifier = std::make_shared<RSBoundsSizeModifier>(property02);
    ASSERT_NE(boundsSizeModifier, nullptr);
    boundsSizeModifier->Apply(geometry);

    auto property03 = std::make_shared<RSProperty<Vector2f>>(INITIAL_VALUE_2F);
    ASSERT_NE(property03, nullptr);
    std::shared_ptr<RSModifier> boundsPositionModifier =
        std::make_shared<RSBoundsPositionModifier>(property03);
    ASSERT_NE(boundsPositionModifier, nullptr);
    boundsPositionModifier->Apply(geometry);
    EXPECT_EQ(geometry->x_, 0.f);
    EXPECT_EQ(geometry->y_, 0.f);
    EXPECT_EQ(geometry->z_, 0.f);
    EXPECT_EQ(geometry->width_, 0.f);
    EXPECT_EQ(geometry->height_, 0.f);
}

/**
 * @tc.name: Apply02
 * @tc.desc: RSPivotModifier/RSPivotZModifier/RSQuaternionModifier
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, Apply02, TestSize.Level1)
{
    std::shared_ptr<RSObjAbsGeometry> geometry = std::make_shared<RSObjAbsGeometry>();
    ASSERT_NE(geometry, nullptr);

    auto property = std::make_shared<RSProperty<Vector2f>>(INITIAL_VALUE_2F);
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSPivotModifier> pivotModifier = std::make_shared<RSPivotModifier>(property);
    ASSERT_NE(pivotModifier, nullptr);
    pivotModifier->Apply(geometry);

    auto property02 = std::make_shared<RSProperty<float>>(0.f);
    ASSERT_NE(property02, nullptr);
    std::shared_ptr<RSPivotZModifier> pivotZModifier = std::make_shared<RSPivotZModifier>(property02);
    ASSERT_NE(pivotZModifier, nullptr);
    pivotZModifier->Apply(geometry);

    Quaternion value = Quaternion(0, 0, 0, 0);
    auto property03 = std::make_shared<RSProperty<Quaternion>>(value);
    ASSERT_NE(property03, nullptr);
    std::shared_ptr<RSQuaternionModifier> quaternionModifier = std::make_shared<RSQuaternionModifier>(property03);
    ASSERT_NE(quaternionModifier, nullptr);
    quaternionModifier->Apply(geometry);
    EXPECT_EQ(geometry->z_, 0.f);
}

/**
 * @tc.name: Apply03
 * @tc.desc: RSRotationModifier/RSRotationXModifier/RSRotationYModifier
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, Apply03, TestSize.Level1)
{
    std::shared_ptr<RSObjAbsGeometry> geometry = std::make_shared<RSObjAbsGeometry>();
    ASSERT_NE(geometry, nullptr);

    auto property = std::make_shared<RSProperty<float>>(0.f);
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSRotationModifier> rotationModifier = std::make_shared<RSRotationModifier>(property);
    ASSERT_NE(rotationModifier, nullptr);
    rotationModifier->Apply(geometry);

    auto property02 = std::make_shared<RSProperty<float>>(0.f);
    ASSERT_NE(property02, nullptr);
    std::shared_ptr<RSRotationXModifier> rotationXModifier = std::make_shared<RSRotationXModifier>(property02);
    ASSERT_NE(rotationXModifier, nullptr);
    rotationXModifier->Apply(geometry);

    auto property03 = std::make_shared<RSProperty<float>>(0.f);
    ASSERT_NE(property03, nullptr);
    std::shared_ptr<RSRotationYModifier> rotationYModifier = std::make_shared<RSRotationYModifier>(property03);
    ASSERT_NE(rotationYModifier, nullptr);
    rotationYModifier->Apply(geometry);
    EXPECT_EQ(geometry->z_, 0.f);
}

/**
 * @tc.name: Apply04
 * @tc.desc: RSCameraDistanceModifier/RSScaleModifier/RSSkewModifier
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, Apply04, TestSize.Level1)
{
    std::shared_ptr<RSObjAbsGeometry> geometry = std::make_shared<RSObjAbsGeometry>();
    ASSERT_NE(geometry, nullptr);

    auto property = std::make_shared<RSProperty<float>>(0.f);
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSCameraDistanceModifier> cameraDistanceModifier =
        std::make_shared<RSCameraDistanceModifier>(property);
    ASSERT_NE(cameraDistanceModifier, nullptr);
    cameraDistanceModifier->Apply(geometry);

    auto property02 = std::make_shared<RSProperty<Vector2f>>(INITIAL_VALUE_2F);
    ASSERT_NE(property02, nullptr);
    std::shared_ptr<RSScaleModifier> scaleModifier = std::make_shared<RSScaleModifier>(property02);
    ASSERT_NE(scaleModifier, nullptr);
    scaleModifier->Apply(geometry);

    auto property03 = std::make_shared<RSProperty<Vector2f>>(INITIAL_VALUE_2F);
    ASSERT_NE(property03, nullptr);
    std::shared_ptr<RSSkewModifier> skewModifier = std::make_shared<RSSkewModifier>(property03);
    ASSERT_NE(skewModifier, nullptr);
    skewModifier->Apply(geometry);
    EXPECT_EQ(geometry->z_, 0.f);
}

/**
 * @tc.name: Apply05
 * @tc.desc: RSPerspModifier/RSTranslateModifier/RSTranslateZModifier
 * @tc.type: FUNC
 */
HWTEST_F(RSPropertyModifierTest, Apply05, TestSize.Level1)
{
    std::shared_ptr<RSObjAbsGeometry> geometry = std::make_shared<RSObjAbsGeometry>();
    ASSERT_NE(geometry, nullptr);

    std::shared_ptr<RSPropertyBase> property = std::make_shared<RSProperty<Vector2f>>(INITIAL_VALUE_2F);
    ASSERT_NE(property, nullptr);
    std::shared_ptr<RSPerspModifier> perspModifier = std::make_shared<RSPerspModifier>(property);
    ASSERT_NE(perspModifier, nullptr);
    perspModifier->Apply(geometry);

    std::shared_ptr<RSPropertyBase> property02 = std::make_shared<RSProperty<Vector2f>>(INITIAL_VALUE_2F);
    ASSERT_NE(property02, nullptr);
    std::shared_ptr<RSTranslateModifier> translateModifier = std::make_shared<RSTranslateModifier>(property02);
    ASSERT_NE(translateModifier, nullptr);
    translateModifier->Apply(geometry);

    std::shared_ptr<RSPropertyBase> property03 = std::make_shared<RSProperty<float>>(0.f);
    ASSERT_NE(property03, nullptr);
    std::shared_ptr<RSTranslateZModifier> translateZModifier = std::make_shared<RSTranslateZModifier>(property03);
    ASSERT_NE(translateZModifier, nullptr);
    translateZModifier->Apply(geometry);
    EXPECT_EQ(geometry->z_, 0.f);
}
} // namespace OHOS::Rosen