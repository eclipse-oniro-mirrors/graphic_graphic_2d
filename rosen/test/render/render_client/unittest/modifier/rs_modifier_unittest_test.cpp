/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "animation/rs_animation.h"
#include "core/transaction/rs_interfaces.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_ui_director.h"
#include "modifier/rs_modifier_manager.h"
#include "modifier/rs_property.h"
#include "modifier/rs_property_modifier.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
constexpr static float FLOAT_DATA_INIT = 0.5f;

class RsModifiersTest : public testing::Test {
public:
    constexpr static float floatData[] = {
        0.0f, 485.44f, -34.4f,
        std::numeric_limits<float>::max(), std::numeric_limits<float>::min(),
        };
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RsModifiersTest::SetUpTestCase() {}
void RsModifiersTest::TearDownTestCase() {}
void RsModifiersTest::SetUp() {}
void RsModifiersTest::TearDown() {}

/**
 * @tc.name: AddModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, AddModifier01, TestSize.Level1)
{
    auto prop = std::make_shared<RSAnimatableProperty<float>>(floatData[0]);
    auto modifier = std::make_shared<RSAlphaModifier>(prop);
    auto node = RSCanvasNode::Create();

    node->AddModifier(modifier);
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
}

/**
 * @tc.name: AddModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, AddModifier02, TestSize.Level1)
{
    auto prop = std::make_shared<RSAnimatableProperty<float>>(floatData[0]);
    auto modifier = std::make_shared<RSAlphaModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetAlpha(), floatData[0]);

    prop->Set(floatData[1]);
    ASSERT_EQ(node->GetStagingProperties().GetAlpha(), floatData[1]);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetAlpha(), node1->GetStagingProperties().GetAlpha());
}

/**
 * @tc.name: Modifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, Modifier01, TestSize.Level1)
{
    auto prop = std::make_shared<RSAnimatableProperty<float>>(floatData[0]);
    auto modifier = std::make_shared<RSAlphaModifier>(prop);
    ASSERT_TRUE(modifier != nullptr);
    ASSERT_EQ(modifier->GetPropertyId(), prop->GetId());
}


/**
 * @tc.name: Modifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, Modifier02, TestSize.Level1)
{
    auto prop = std::make_shared<RSAnimatableProperty<float>>(floatData[0]);
    auto modifier = std::make_shared<RSAlphaModifier>(prop);
    ASSERT_TRUE(modifier != nullptr);
    ASSERT_EQ(std::static_pointer_cast<RSAnimatableProperty<float>>(modifier->GetProperty())->Get(), floatData[0]);

    prop->Set(floatData[1]);
    ASSERT_EQ(std::static_pointer_cast<RSAnimatableProperty<float>>(modifier->GetProperty())->Get(), floatData[1]);
}
/**
 * @tc.name: FrameModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, FrameModifier01, TestSize.Level1)
{
    auto val = Vector4f(10.f);
    auto prop = std::make_shared<RSAnimatableProperty<Vector4f>>(val);
    auto modifier = std::make_shared<RSFrameModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetFrame(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetFrame(), node1->GetStagingProperties().GetFrame());
}

/**
 * @tc.name: FrameModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, FrameModifier02, TestSize.Level1)
{
    auto val = Vector4f();
    auto prop = std::make_shared<RSAnimatableProperty<Vector4f>>(val);
    auto modifier = std::make_shared<RSFrameModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetFrame(), val);
    auto str = node->GetStagingProperties().Dump();

    val = Vector4f(0.f, 0.f, 50.f, 60.f);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetFrame(), val);
    str = node->GetStagingProperties().Dump();
}

/**
 * @tc.name: PositionZModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, PositionZModifier01, TestSize.Level1)
{
    auto val = 2.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSPositionZModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetPositionZ(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetPositionZ(), node1->GetStagingProperties().GetPositionZ());
}

/**
 * @tc.name: PositionZModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, PositionZModifier02, TestSize.Level1)
{
    auto val = 0.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSPositionZModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetPositionZ(), val);

    val = -1.f;
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetPositionZ(), val);
}

/**
 * @tc.name: BoundsModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, BoundsModifier01, TestSize.Level1)
{
    auto val = Vector4f(10.f);
    auto prop = std::make_shared<RSAnimatableProperty<Vector4f>>(val);
    auto modifier = std::make_shared<RSBoundsModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetBounds(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetBounds(), node1->GetStagingProperties().GetBounds());
}

/**
 * @tc.name: BoundsModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, BoundsModifier02, TestSize.Level1)
{
    auto val = Vector4f();
    auto prop = std::make_shared<RSAnimatableProperty<Vector4f>>(val);
    auto modifier = std::make_shared<RSBoundsModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetBounds(), val);
    auto str = node->GetStagingProperties().Dump();

    val = Vector4f(0.f, 0.f, 50.f, 60.f);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetBounds(), val);
    str = node->GetStagingProperties().Dump();
}

/**
 * @tc.name: PivotModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, PivotModifier01, TestSize.Level1)
{
    auto val = Vector2f(1.f, 1.f);
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSPivotModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetPivot(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetPivot(), node1->GetStagingProperties().GetPivot());
}

/**
 * @tc.name: PivotModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, PivotModifier02, TestSize.Level1)
{
    auto val = Vector2f();
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSPivotModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetPivot(), val);

    val = Vector2f(0.5f, 0.5f);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetPivot(), val);
}

/**
 * @tc.name: RotationModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, RotationModifier01, TestSize.Level1)
{
    auto val = 90.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSRotationModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetRotation(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetRotation(), node1->GetStagingProperties().GetRotation());
}

/**
 * @tc.name: RotationModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, RotationModifier02, TestSize.Level1)
{
    auto val = 0.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSRotationModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetRotation(), val);

    val = -360.f;
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetRotation(), val);
}

/**
 * @tc.name: RotationXModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, RotationXModifier01, TestSize.Level1)
{
    auto val = 90.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSRotationXModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetRotationX(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetRotationX(), node1->GetStagingProperties().GetRotationX());
}

/**
 * @tc.name: RotationXModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, RotationXModifier02, TestSize.Level1)
{
    auto val = 0.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSRotationXModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetRotationX(), val);

    val = -360.f;
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetRotationX(), val);
}

/**
 * @tc.name: QuaternionModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, QuaternionModifier01, TestSize.Level1)
{
    auto val = Quaternion(0.382683, 0, 0, 0.92388);
    auto prop = std::make_shared<RSAnimatableProperty<Quaternion>>(val);
    auto modifier = std::make_shared<RSQuaternionModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetQuaternion(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetQuaternion(), node1->GetStagingProperties().GetQuaternion());
}

/**
 * @tc.name: QuaternionModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, QuaternionModifier02, TestSize.Level1)
{
    auto val = Quaternion();
    auto prop = std::make_shared<RSAnimatableProperty<Quaternion>>(val);
    auto modifier = std::make_shared<RSQuaternionModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetQuaternion(), val);

    val = Quaternion(0, 0, 0.382683, 0.92388);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetQuaternion(), val);
}

/**
 * @tc.name: RotationYModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, RotationYModifier01, TestSize.Level1)
{
    auto val = 90.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSRotationYModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetRotationY(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetRotationY(), node1->GetStagingProperties().GetRotationY());
}

/**
 * @tc.name: RotationYModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, RotationYModifier02, TestSize.Level1)
{
    auto val = 0.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSRotationYModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetRotationY(), val);

    val = -360.f;
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetRotationY(), val);
}

/**
 * @tc.name: SkewModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, SkewModifier01, TestSize.Level1)
{
    auto val = Vector2f(2.f, 2.f);
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSSkewModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetSkew(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetSkew(), node1->GetStagingProperties().GetSkew());
}

/**
 * @tc.name: SkewModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, SkewModifier02, TestSize.Level1)
{
    auto val = Vector2f();
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSSkewModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetSkew(), val);

    val = Vector2f(0.5f, 0.5f);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetSkew(), val);
}

/**
 * @tc.name: PerspModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, PerspModifier01, TestSize.Level1)
{
    auto val = Vector2f(FLOAT_DATA_INIT, FLOAT_DATA_INIT);
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSPerspModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetPersp(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetPersp(), node1->GetStagingProperties().GetPersp());
}

/**
 * @tc.name: PerspModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, PerspModifier02, TestSize.Level1)
{
    auto val = Vector2f();
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSPerspModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetPersp(), val);

    val = Vector2f(FLOAT_DATA_INIT, FLOAT_DATA_INIT);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetPersp(), val);
}

/**
 * @tc.name: ScaleModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, ScaleModifier01, TestSize.Level1)
{
    auto val = Vector2f(2.f, 2.f);
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSScaleModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetScale(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetScale(), node1->GetStagingProperties().GetScale());
}

/**
 * @tc.name: ScaleModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, ScaleModifier02, TestSize.Level1)
{
    auto val = Vector2f();
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSScaleModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetScale(), val);

    val = Vector2f(0.5f, 0.5f);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetScale(), val);
}

/**
 * @tc.name: TranslateModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, TranslateModifier01, TestSize.Level1)
{
    auto val = Vector2f(20.f, 30.f);
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSTranslateModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetTranslate(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetTranslate(), node1->GetStagingProperties().GetTranslate());
}

/**
 * @tc.name: TranslateModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, TranslateModifier02, TestSize.Level1)
{
    auto val = Vector2f();
    auto prop = std::make_shared<RSAnimatableProperty<Vector2f>>(val);
    auto modifier = std::make_shared<RSTranslateModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetTranslate(), val);

    val = Vector2f(-20.f, -30.f);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetTranslate(), val);
}

/**
 * @tc.name: TranslateZModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, TranslateZModifier01, TestSize.Level1)
{
    auto val = 20.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSTranslateZModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetTranslateZ(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetTranslateZ(), node1->GetStagingProperties().GetTranslateZ());
}

/**
 * @tc.name: TranslateZModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, TranslateZModifier02, TestSize.Level1)
{
    auto val = 0.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSTranslateZModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetTranslateZ(), val);

    val = -10.f;
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetTranslateZ(), val);
}

/**
 * @tc.name: CornerRadiusModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, CornerRadiusModifier01, TestSize.Level1)
{
    auto val = Vector4f(20.f);
    auto prop = std::make_shared<RSAnimatableProperty<Vector4f>>(val);
    auto modifier = std::make_shared<RSCornerRadiusModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetCornerRadius(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetCornerRadius(), node1->GetStagingProperties().GetCornerRadius());
}

/**
 * @tc.name: CornerRadiusModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, CornerRadiusModifier02, TestSize.Level1)
{
    auto val = Vector4f();
    auto prop = std::make_shared<RSAnimatableProperty<Vector4f>>(val);
    auto modifier = std::make_shared<RSCornerRadiusModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetCornerRadius(), val);

    val = Vector4f(-10.f);
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetCornerRadius(), val);
}

/**
 * @tc.name: AlphaModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, AlphaModifier01, TestSize.Level1)
{
    auto val = 0.5f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSAlphaModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetAlpha(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetAlpha(), node1->GetStagingProperties().GetAlpha());
}

/**
 * @tc.name: AlphaModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, AlphaModifier02, TestSize.Level1)
{
    auto val = 0.f;
    auto prop = std::make_shared<RSAnimatableProperty<float>>(val);
    auto modifier = std::make_shared<RSAlphaModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetAlpha(), val);
    auto str = node->GetStagingProperties().Dump();

    val = -1.f;
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetAlpha(), val);
    str = node->GetStagingProperties().Dump();
}

/**
 * @tc.name: AlphaOffscreenModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, AlphaOffscreenModifier01, TestSize.Level1)
{
    bool val = false;
    auto prop = std::make_shared<RSProperty<bool>>(val);
    auto modifier = std::make_shared<RSAlphaOffscreenModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetAlphaOffscreen(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetAlphaOffscreen(), node1->GetStagingProperties().GetAlphaOffscreen());
}

/**
 * @tc.name: AlphaOffscreenModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, AlphaOffscreenModifier02, TestSize.Level1)
{
    bool val = false;
    auto prop = std::make_shared<RSProperty<bool>>(val);
    auto modifier = std::make_shared<RSAlphaOffscreenModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetAlphaOffscreen(), val);

    val = true;
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetAlphaOffscreen(), val);
}

/**
 * @tc.name: ForegroundColorModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, ForegroundColorModifier01, TestSize.Level1)
{
    auto val = RgbPalette::Black();
    auto prop = std::make_shared<RSAnimatableProperty<Color>>(val);
    auto modifier = std::make_shared<RSForegroundColorModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetForegroundColor(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetForegroundColor(), node1->GetStagingProperties().GetForegroundColor());
}

/**
 * @tc.name: ForegroundColorModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, ForegroundColorModifier02, TestSize.Level1)
{
    auto val = RgbPalette::Transparent();
    auto prop = std::make_shared<RSAnimatableProperty<Color>>(val);
    auto modifier = std::make_shared<RSForegroundColorModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetForegroundColor(), val);

    val = RgbPalette::Red();
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetForegroundColor(), val);
}

/**
 * @tc.name: BackgroundColorModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, BackgroundColorModifier01, TestSize.Level1)
{
    auto val = RgbPalette::Black();
    auto prop = std::make_shared<RSAnimatableProperty<Color>>(val);
    auto modifier = std::make_shared<RSBackgroundColorModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetBackgroundColor(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetBackgroundColor(), node1->GetStagingProperties().GetBackgroundColor());
}

/**
 * @tc.name: BackgroundColorModifier02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, BackgroundColorModifier02, TestSize.Level1)
{
    auto val = RgbPalette::Transparent();
    auto prop = std::make_shared<RSAnimatableProperty<Color>>(val);
    auto modifier = std::make_shared<RSBackgroundColorModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetBackgroundColor(), val);
    auto str = node->GetStagingProperties().Dump();

    val = RgbPalette::Green();
    prop->Set(val);
    ASSERT_EQ(node->GetStagingProperties().GetBackgroundColor(), val);
    str = node->GetStagingProperties().Dump();
}

/**
 * @tc.name: BackgroundShaderModifier01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsModifiersTest, BackgroundShaderModifier01, TestSize.Level1)
{
    auto val = RSShader::CreateRSShader();
    auto prop = std::make_shared<RSProperty<std::shared_ptr<RSShader>>>(val);
    auto modifier = std::make_shared<RSBackgroundShaderModifier>(prop);

    auto node = RSCanvasNode::Create();
    node->AddModifier(modifier);
    ASSERT_TRUE(node != nullptr);
    ASSERT_EQ(node->GetStagingProperties().GetBackgroundShader(), val);

    node->RemoveModifier(modifier);
    auto node1 = RSCanvasNode::Create();
    ASSERT_EQ(node->GetStagingProperties().GetBackgroundShader(), node1->GetStagingProperties().GetBackgroundShader());
}

} // namespace OHOS::Rosen
