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

#include <memory>
#include "gtest/gtest.h"
#include "animation/rs_animation.h"
#include "animation/rs_transition.h"
#include "modifier/rs_property_modifier.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_surface_node.h"
#include "ui_effect/effect/include/brightness_blender.h"
#include "animation/rs_animation_callback.h"
#include "animation/rs_implicit_animator_map.h"
#include "animation/rs_implicit_animator.h"
#include "animation/rs_implicit_animation_param.h"
#include "modifier/rs_modifier.h"
#include "common/rs_vector4.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
constexpr static float FLOAT_DATA_ZERO = 0.0f;
constexpr static float FLOAT_DATA_POSITIVE = 485.44f;
constexpr static float FLOAT_DATA_NEGATIVE = -34.4f;
constexpr static float FLOAT_DATA_MAX = std::numeric_limits<float>::max();
constexpr static float FLOAT_DATA_MIN = std::numeric_limits<float>::min();
constexpr static float FLOAT_DATA_INIT = 0.5f;
constexpr static float FLOAT_DATA_UPDATE = 1.0f;

class RSNodeTest : public testing::Test {
public:
    constexpr static float floatData[] = {
        FLOAT_DATA_ZERO, FLOAT_DATA_POSITIVE, FLOAT_DATA_NEGATIVE,
        FLOAT_DATA_MAX, FLOAT_DATA_MIN,
        };
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    Vector4f createV4fWithValue(float value) const
    {
        return {value, value, value, value};
    }
    void SetBorderDashParamsAndTest(float value) const
    {
        SetBorderDashParamsAndTest(createV4fWithValue(value));
    }
    void SetOutlineDashParamsAndTest(float value) const
    {
        SetOutlineDashParamsAndTest(createV4fWithValue(value));
    }
    void SetBorderDashParamsAndTest(const Vector4f& params) const
    {
        auto rsNode = RSCanvasNode::Create();
        rsNode->SetBorderDashWidth(params);
        rsNode->SetBorderDashGap(params);
        auto borderDashWidth = rsNode->GetStagingProperties().GetBorderDashWidth();
        auto borderDashGap = rsNode->GetStagingProperties().GetBorderDashGap();
        EXPECT_TRUE(borderDashWidth.IsNearEqual(params));
        EXPECT_TRUE(borderDashGap.IsNearEqual(params));
    }
    void SetOutlineDashParamsAndTest(const Vector4f& params) const
    {
        auto rsNode = RSCanvasNode::Create();
        rsNode->SetOutlineDashWidth(params);
        rsNode->SetOutlineDashGap(params);
        auto borderOutlineWidth = rsNode->GetStagingProperties().GetOutlineDashWidth();
        auto borderOutlineGap = rsNode->GetStagingProperties().GetOutlineDashGap();
        EXPECT_TRUE(borderOutlineWidth.IsNearEqual(params));
        EXPECT_TRUE(borderOutlineGap.IsNearEqual(params));
    }
};

void RSNodeTest::SetUpTestCase() {}
void RSNodeTest::TearDownTestCase() {}
void RSNodeTest::SetUp() {}
void RSNodeTest::TearDown() {}

/**
 * @tc.name: LifeCycle001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, LifeCycle001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSNode and add child
     */
    auto rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    auto child1 = RSCanvasNode::Create();
    auto child2 = RSCanvasNode::Create();
    auto child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    child1->AddChild(child3, 1);

    EXPECT_EQ(rootNode->GetId() + 2, child1->GetId());

    /**
     * @tc.steps: step2. remove child
     */
    rootNode->RemoveChild(child2);
}

/**
 * @tc.name: LifeCycle002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, LifeCycle002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSNode and add child
     */
    auto rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    auto child1 = RSCanvasNode::Create();
    auto child2 = RSCanvasNode::Create();
    auto child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    child1->AddChild(child3, 1);
    /**
     * @tc.steps: step2. remove child
     */
    rootNode->RemoveChild(child2);
}

/**
 * @tc.name: LifeCycle003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, LifeCycle003, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSNode and add child
     */
    auto rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    auto child1 = RSCanvasNode::Create();
    auto child2 = RSCanvasNode::Create();
    auto child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    child1->AddChild(child3, 1);
    /**
     * @tc.steps: step2. remove child
     */
    rootNode->RemoveFromTree();
}

/**
 * @tc.name: LifeCycle004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, LifeCycle004, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSNode and add child
     */
    auto rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    auto child1 = RSCanvasNode::Create();
    auto child2 = RSCanvasNode::Create();
    auto child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    child1->AddChild(child3, 1);
    /**
     * @tc.steps: step2. remove child
     */
    rootNode->ClearChildren();
}

/**
 * @tc.name: LifeCycle005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, LifeCycle005, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSNode and add child
     */
    auto rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    auto child1 = RSCanvasNode::Create();
    auto child2 = RSCanvasNode::Create();
    auto child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    child1->AddChild(child3, 1);
    /**
     * @tc.steps: step2. remove child
     */
    rootNode->RemoveChild(child3);
}

/**
 * @tc.name: Recording001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, Recording001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSNode and RSUIDirector
     */
    auto rsNode = RSCanvasNode::Create();

    /**
     * @tc.steps: step2. begin recording
     */
    EXPECT_FALSE(rsNode->IsRecording());
    rsNode->BeginRecording(500, 400);
    EXPECT_TRUE(rsNode->IsRecording());
}

/**
 * @tc.name: SetPaintOrder001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetPaintOrder001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create RSNode and RSUIDirector
     */
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetPaintOrder(true);
}

/**
 * @tc.name: SetBoundsandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBounds(floatData[0], floatData[1], floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().x_, floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().y_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().z_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().w_, floatData[3]));
}

/**
 * @tc.name: SetBoundsandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBounds(floatData[3], floatData[1], floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().y_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().z_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().w_, floatData[0]));
}

/**
 * @tc.name: SetBoundsandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBounds(floatData[3], floatData[2], floatData[1], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().y_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().z_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().w_, floatData[0]));
}

/**
 * @tc.name: SetBoundsWidthandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsWidthandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsWidth(floatData[1]);
    rsNode->SetBoundsWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().z_, floatData[1]));
}

/**
 * @tc.name: SetBoundsWidthandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsWidthandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsWidth(floatData[2]);
    rsNode->SetBoundsWidth(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().z_, floatData[2]));
}

/**
 * @tc.name: SetBoundsWidthandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsWidthandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsWidth(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().z_, floatData[3]));
}

/**
 * @tc.name: SetIlluminatedBorderWidthTest
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetIlluminatedBorderWidthTest, TestSize.Level1)
{
    auto rootNode = RSCanvasNode::Create();
    rootNode->SetIlluminatedBorderWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rootNode->GetStagingProperties().GetIlluminatedBorderWidth(), floatData[1]));
}

/**
 * @tc.name: SetBoundsWidthandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsWidthandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsWidth(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().z_, floatData[4]));
}

/**
 * @tc.name: SetBoundsWidthandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsWidthandGet005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsWidth(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().z_, floatData[0]));
}

/**
 * @tc.name: SetBoundsHeightandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsHeightandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsHeight(floatData[1]);
    rsNode->SetBoundsHeight(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().w_, floatData[1]));
}

/**
 * @tc.name: SetBoundsHeightandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsHeightandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsHeight(floatData[2]);
    rsNode->SetBoundsHeight(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().w_, floatData[2]));
}

/**
 * @tc.name: SetBoundsHeightandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsHeightandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsHeight(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().w_, floatData[3]));
}

/**
 * @tc.name: SetBoundsHeightandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsHeightandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsHeight(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().w_, floatData[4]));
}

/**
 * @tc.name: SetBoundsHeightandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetBoundsHeightandGet005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBoundsHeight(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBounds().w_, floatData[0]));
}

/**
 * @tc.name: SetFrameandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFrameandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFrame(floatData[0], floatData[1], floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().x_, floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().y_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().z_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().w_, floatData[3]));
}

/**
 * @tc.name: SetFrameandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFrameandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFrame(floatData[3], floatData[1], floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().y_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().z_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().w_, floatData[0]));
}

/**
 * @tc.name: SetFrameandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFrameandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFrame(floatData[3], floatData[2], floatData[1], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().y_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().z_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().w_, floatData[0]));
}

/**
 * @tc.name: SetFramePositionandGetX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetX001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionX(floatData[1]);
    rsNode->SetFramePositionX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().x_, floatData[1]));
}

/**
 * @tc.name: SetFramePositionandGetX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetX002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionX(floatData[2]);
    rsNode->SetFramePositionX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().x_, floatData[2]));
}

/**
 * @tc.name: SetFramePositionandGetX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetX003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().x_, floatData[3]));
}

/**
 * @tc.name: SetFramePositionandGetX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetX004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().x_, floatData[4]));
}

/**
 * @tc.name: SetFramePositionandGetX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetX005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().x_, floatData[0]));
}

/**
 * @tc.name: SetFramePositionandGetY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetY001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().y_, floatData[3]));
}

/**
 * @tc.name: SetFramePositionandGetY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetY002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().y_, floatData[4]));
}

/**
 * @tc.name: SetFramePositionandGetY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetY003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().y_, floatData[0]));
}

/**
 * @tc.name: SetFramePositionandGetY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetY004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionY(floatData[1]);
    rsNode->SetFramePositionY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().y_, floatData[1]));
}

/**
 * @tc.name: SetFramePositionandGetY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetFramePositionandGetY005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetFramePositionY(floatData[2]);
    rsNode->SetFramePositionY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetFrame().y_, floatData[2]));
}


/**
 * @tc.name: RSSetandGetPositionZ001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPositionZ001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetPositionZ(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetPositionZ(), floatData[3]));
}

/**
 * @tc.name: RSSetandGetPositionZ002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPositionZ002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetPositionZ(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetPositionZ(), floatData[4]));
}

/**
 * @tc.name: RSSetandGetPositionZ003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPositionZ003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetPositionZ(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetPositionZ(), floatData[0]));
}

/**
 * @tc.name: RSSetandGetPositionZ004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPositionZ004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetPositionZ(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetPositionZ(), floatData[1]));
}

/**
 * @tc.name: RSSetandGetPositionZ005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPositionZ005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetPositionZ(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetPositionZ(), floatData[2]));
}


/**
 * @tc.name: SetCornerRadiusandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetCornerRadiusandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetCornerRadius(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetCornerRadius().x_, floatData[3]));
}

/**
 * @tc.name: SetCornerRadiusandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetCornerRadiusandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetCornerRadius(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetCornerRadius().x_, floatData[4]));
}

/**
 * @tc.name: SetCornerRadiusandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetCornerRadiusandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetCornerRadius(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetCornerRadius().x_, floatData[0]));
}

/**
 * @tc.name: SetCornerRadiusandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetCornerRadiusandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetCornerRadius(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetCornerRadius().x_, floatData[1]));
}

/**
 * @tc.name: SetCornerRadiusandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetCornerRadiusandGet005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetCornerRadius(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetCornerRadius().x_, floatData[2]));
}


/**
 * @tc.name: SetOutlineRadiusandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetOutlineRadiusandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetOutlineRadius(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetOutlineRadius().x_, floatData[3]));
}

/**
 * @tc.name: SetOutlineRadiusandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetOutlineRadiusandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetOutlineRadius(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetOutlineRadius().x_, floatData[4]));
}

/**
 * @tc.name: SetOutlineRadiusandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetOutlineRadiusandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetOutlineRadius(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetOutlineRadius().x_, floatData[0]));
}
/**
 * @tc.name: SetOutlineRadiusandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetOutlineRadiusandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetOutlineRadius(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetOutlineRadius().x_, floatData[1]));
}

/**
 * @tc.name: SetOutlineRadiusandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, SetOutlineRadiusandGet005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetOutlineRadius(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetOutlineRadius().x_, floatData[2]));
}

/**
 * @tc.name: RSSetRotationandGetThree001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationandGetThree001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotation(floatData[1], floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotation(), floatData[1], floatData[2], floatData[3]));
}

/**
 * @tc.name: RSSetRotationandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotation(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotation(), floatData[3]));
}

/**
 * @tc.name: RSSetRotationandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotation(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotation(), floatData[4]));
}

/**
 * @tc.name: RSSetRotationandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotation(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotation(), floatData[0]));
}

/**
 * @tc.name: RSSetRotationandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotation(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotation(), floatData[1]));
}

/**
 * @tc.name: RSSetRotationandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationandGet005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotation(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotation(), floatData[2]));
}
/**
 * @tc.name: RSSetRotationXandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationXandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationX(), floatData[3]));
}

/**
 * @tc.name: RSSetRotationXandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationXandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationX(), floatData[4]));
}

/**
 * @tc.name: RSSetRotationXandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationXandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationX(), floatData[0]));
}

/**
 * @tc.name: RSSetRotationXandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationXandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationX(), floatData[1]));
}

/**
 * @tc.name: RSSetRotationXandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationXandGet005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationX(), floatData[2]));
}


/**
 * @tc.name: RSSetRotationYandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationYandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationY(), floatData[4]));
}

/**
 * @tc.name: RSSetRotationYandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationYandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationY(), floatData[0]));
}
/**
 * @tc.name: RSSetRotationYandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationYandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationY(), floatData[1]));
}

/**
 * @tc.name: RSSetRotationYandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationYandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationY(), floatData[2]));
}

/**
 * @tc.name: RSSetRotationYandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetRotationYandGet005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->RSSetRotationY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetRotationY(), floatData[3]));
}


/**
 * @tc.name: RSSetScaleandGetX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetX001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[1]));
}

/**
 * @tc.name: RSSetScaleandGetX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetX002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[2]));
}

/**
 * @tc.name: RSSetScaleandGetX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetX003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[3]));
}

/**
 * @tc.name: RSSetScaleandGetX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetX004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[4]));
}

/**
 * @tc.name: RSSetScaleandGetX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetX005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[0]));
}

/**
 * @tc.name: RSSetScaleandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScale(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: RSSetScaleandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScale(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[2]));
}

/**
 * @tc.name: RSSetScaleandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScale(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[3]));
}

/**
 * @tc.name: RSSetScaleandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScale(floatData[3], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[0]));
}

/**
 * @tc.name: RSSetScaleandGet0005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGet0005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScale(floatData[2], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: RSSetScaleandGetY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetY001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: RSSetScaleandGetY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetY002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[2]));
}

/**
 * @tc.name: RSSetScaleandGetY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetY003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[3]));
}

/**
 * @tc.name: RSSetScaleandGetY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetY004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[4]));
}

/**
 * @tc.name: RSSetScaleandGetY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetScaleandGetY005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetScaleY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetScale().y_, floatData[0]));
}


/**
 * @tc.name: RSSetandGetSkew001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkew001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[3], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[0]));
}

/**
 * @tc.name: RSSetandGetSkew0002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkew0002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[2], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: RSSetandGetSkew003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkew003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: RSSetandGetSkew004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkew004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[2]));
}

/**
 * @tc.name: RSSetandGetSkew005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkew005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[3]));
}

/**
 * @tc.name: RSSetandGetSkewX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkewX001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[3]));
}

/**
 * @tc.name: RSSetandGetSkewX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkewX002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[4]));
}

/**
 * @tc.name: RSSetandGetSkewX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkewX003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[1]));
}

/**
 * @tc.name: RSSetandGetSkewX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkewX004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[2]));
}

/**
 * @tc.name: RSSetandGetSkewX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetSkewX005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[0]));
}

/**
 * @tc.name: RSSetSkewYandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetSkewYandGet001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: RSSetSkewYandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetSkewYandGet002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[2]));
}

/**
 * @tc.name: RSSetSkewYandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetSkewYandGet003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[3]));
}

/**
 * @tc.name: RSSetSkewYandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetSkewYandGet004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[4]));
}

/**
 * @tc.name: RSSetSkewYandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetSkewYandGet005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[0]));
}

/**
 * @tc.name: RSSetandGetPersp001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPersp001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_POSITIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: RSSetandGetPersp002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPersp002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: RSSetandGetPersp003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPersp003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: RSSetandGetPersp004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPersp004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_MAX, FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: RSSetandGetPersp0005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPersp0005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_NEGATIVE, FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: RSSetPerspXandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetPerspXandGet001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: RSSetPerspXandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetPerspXandGet002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: RSSetPerspXandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetPerspXandGet003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: RSSetPerspXandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetPerspXandGet004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_MIN);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MIN));
}

/**
 * @tc.name: RSSetPerspXandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetPerspXandGet005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: RSSetandGetPerspY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPerspY001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: RSSetandGetPerspY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPerspY002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: RSSetandGetPerspY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPerspY003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: RSSetandGetPerspY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPerspY004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_MIN);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MIN));
}

/**
 * @tc.name: RSSetandGetPerspY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetPerspY005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: RSSetandGetAlphaOffscreen001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetAlphaOffscreen001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetAlphaOffscreen(true);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetAlphaOffscreen(), true));
}

/**
 * @tc.name: RSSetandGetAlphaOffscreen002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetAlphaOffscreen002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetAlphaOffscreen(false);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetAlphaOffscreen(), false));
}

/**
 * @tc.name: RSSetandGetAlpha001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetAlpha001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetAlpha(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetAlpha(), floatData[4]));
}

/**
 * @tc.name: RSSetandGetAlpha002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetAlpha002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetAlpha(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetAlpha(), floatData[0]));
}

/**
 * @tc.name: RSSetandGetAlpha003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetAlpha003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetAlpha(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetAlpha(), floatData[1]));
}

/**
 * @tc.name: RSSetandGetAlpha004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetAlpha004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetAlpha(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetAlpha(), floatData[2]));
}

/**
 * @tc.name: RSSetandGetAlpha003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetAlpha003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetAlpha(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetAlpha(), floatData[3]));
}

/**
 * @tc.name: RSSetandGetBgImageSize001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImageSize001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageSize(floatData[0], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageWidth(), floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: RSSetandGetBgImageSize002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImageSize002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageSize(floatData[3], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: RSSetandGetBgImageSize003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImageSize003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageSize(floatData[3], floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageHeight(), floatData[2]));
}

/**
 * @tc.name: RSSetBgImageWidthandGet001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetBgImageWidthandGet001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageWidth(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageWidth(), floatData[4]));
}

/**
 * @tc.name: RSSetBgImageWidthandGet002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetBgImageWidthandGet002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageWidth(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageWidth(), floatData[0]));
}

/**
 * @tc.name: RSSetBgImageWidthandGet003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetBgImageWidthandGet003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageWidth(), floatData[1]));
}

/**
 * @tc.name: RSSetBgImageWidthandGet004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetBgImageWidthandGet004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageWidth(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageWidth(), floatData[2]));
}

/**
 * @tc.name: RSSetBgImageWidthandGet005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetBgImageWidthandGet005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageWidth(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
}

/**
 * @tc.name: RSSetandGetBgImageHeight001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImageHeight001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageHeight(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: RSSetandGetBgImageHeight002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImageHeight002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageHeight(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageHeight(), floatData[2]));
}

/**
 * @tc.name: RSSetandGetBgImageHeight003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImageHeight003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageHeight(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageHeight(), floatData[3]));
}

/**
 * @tc.name: RSSetandGetBgImageHeight004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImageHeight004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageHeight(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageHeight(), floatData[4]));
}

/**
 * @tc.name: RSSetandGetBgImageHeight005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImageHeight005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImageHeight(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImageHeight(), floatData[0]));
}

/**
 * @tc.name: RSSetandSetBgImagePosition001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandSetBgImagePosition001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePosition(floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionY(), floatData[3]));
}

/**
 * @tc.name: RSSetandSetBgImagePosition002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandSetBgImagePosition002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePosition(floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionY(), floatData[0]));
}

/**
 * @tc.name: RSSetandSetBgImagePosition003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandSetBgImagePosition003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePosition(floatData[1], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionX(), floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionY(), floatData[3]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionX001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionX(), floatData[1]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionX002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionX003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionX(), floatData[3]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionX004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionX(), floatData[4]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionX005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionX(), floatData[0]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionY001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionY(), floatData[3]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionY002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionY(), floatData[4]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionY003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionY(), floatData[0]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionY004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionY(), floatData[1]));
}

/**
 * @tc.name: RSSetandGetBgImagePositionY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBgImagePositionY005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBgImagePositionY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBgImagePositionY(), floatData[2]));
}


/**
 * @tc.name: RSSetandGetBorderWidth001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBorderWidth001, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBorderWidth(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBorderWidth().x_, floatData[3]));
}

/**
 * @tc.name: RSSetandGetBorderWidth002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBorderWidth002, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBorderWidth(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBorderWidth().x_, floatData[4]));
}

/**
 * @tc.name: RSSetandGetBorderWidth003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBorderWidth003, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBorderWidth(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBorderWidth().x_, floatData[0]));
}

/**
 * @tc.name: RSSetandGetBorderWidth004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBorderWidth004, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBorderWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBorderWidth().x_, floatData[1]));
}

/**
 * @tc.name: RSSetandGetBorderWidth005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSNodeTest, RSSetandGetBorderWidth005, TestSize.Level1)
{
    auto rsNode = RSCanvasNode::Create();
    rsNode->SetBorderWidth(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(rsNode->GetStagingProperties().GetBorderWidth().x_, floatData[2]));
}