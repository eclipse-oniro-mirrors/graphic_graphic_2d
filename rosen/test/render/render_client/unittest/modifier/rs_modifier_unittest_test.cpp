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

} // namespace OHOS::Rosen
