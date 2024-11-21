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
#include "draw/paint.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
constexpr static float FLOAT_DATA_ZERO = 0.0f;
constexpr static float FLOAT_DATA_POSITIVE = 485.44f;
constexpr static float FLOAT_DATA_NEGATIVE = -34.4f;
constexpr static float FLOAT_DATA_MAX = std::numeric_limits<float>::max();
constexpr static float FLOAT_DATA_MIN = std::numeric_limits<float>::min();

class RsCanvasNodesTest : public testing::Test {
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

void RsCanvasNodesTest::SetUpTestCase() {}
void RsCanvasNodesTest::TearDownTestCase() {}
void RsCanvasNodesTest::SetUp() {}
void RsCanvasNodesTest::TearDown() {}

/**
 * @tc.name: Create01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, Create01, TestSize.Level2)
{
	// return shared_ptr
    RSCanvasNode::SharedPtr rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);
}

/**
 * @tc.name: Create02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, Create02, TestSize.Level2)
{
	// return shared_ptr
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create(true);
    ASSERT_TRUE(canvasnode != nullptr);
}

/**
 * @tc.name: Create03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, Create03, TestSize.Level2)
{
	// return shared_ptr
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create(false);
    ASSERT_TRUE(canvasnode != nullptr);
}

/**
 * @tc.name: LifeCycle01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, LifeCycle01, TestSize.Level2)
{
    /**
     * @tc.steps: step1. create canvasnode and add child
     */
    RSCanvasNode::SharedPtr rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    RSCanvasNode::SharedPtr child1 = RSCanvasNode::Create();
    RSCanvasNode::SharedPtr child2 = RSCanvasNode::Create();
    RSCanvasNode::SharedPtr child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    child1->AddChild(child3, 1);

    /**
     * @tc.steps: step2. remove child
     */
    rootNode->RemoveChild(child2);
}

/**
 * @tc.name: Recording01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, Recording01, TestSize.Level2)
{
    /**
     * @tc.steps: step1. create canvasnode and RSUIDirector
     */
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();

    /**
     * @tc.steps: step2. begin recording
     */
    EXPECT_FALSE(canvasnode->IsRecording());
    canvasnode->BeginRecording(50, 40);
    EXPECT_TRUE(canvasnode->IsRecording());
}

/**
 * @tc.name: Recording02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, Recording02, TestSize.Level2)
{
    /**
     * @tc.steps: step1. create canvasnode and RSUIDirector
     */
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();

    /**
     * @tc.steps: step2. begin recording
     */
    EXPECT_FALSE(canvasnode->IsRecording());
    canvasnode->FinishRecording();
    canvasnode->BeginRecording(50, 40);
    EXPECT_TRUE(canvasnode->IsRecording());
    canvasnode->FinishRecording();
}

/**
 * @tc.name: SetPaintOrder01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetPaintOrder01, TestSize.Level2)
{
    /**
     * @tc.steps: step1. create canvasnode and RSUIDirector
     */
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPaintOrder(true);
}

/**
 * @tc.name: SetandGetBounds01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBounds01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBounds(floatData[0], floatData[1], floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[0], floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[1], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[2], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[3], floatData[3]));
}

/**
 * @tc.name: SetandGetBounds02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBounds02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBounds(floatData[3], floatData[1], floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[0], floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[1], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[2], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetBounds03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBounds03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBounds(floatData[3], floatData[2], floatData[1], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[0], floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[1], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[2], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[3], floatData[0]));
}

/**
 * @tc.name: LifeCycle02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, LifeCycle02, TestSize.Level2)
{
    /**
     * @tc.steps: step1. create canvasnode and add child
     */
    RSCanvasNode::SharedPtr rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    RSCanvasNode::SharedPtr child1 = RSCanvasNode::Create();
    RSCanvasNode::SharedPtr child2 = RSCanvasNode::Create();
    RSCanvasNode::SharedPtr child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    child1->AddChild(child3, 1);
    /**
     * @tc.steps: step2. remove child
     */
    rootNode->RemoveFromTree();
}

/**
 * @tc.name: LifeCycle03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, LifeCycle03, TestSize.Level2)
{
    /**
     * @tc.steps: step1. create canvasnode and add child
     */
    RSCanvasNode::SharedPtr rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    RSCanvasNode::SharedPtr child1 = RSCanvasNode::Create();
    RSCanvasNode::SharedPtr child2 = RSCanvasNode::Create();
    RSCanvasNode::SharedPtr child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    child1->AddChild(child3, 1);
    /**
     * @tc.steps: step2. remove child
     */
    rootNode->ClearChildren();
}

/**
 * @tc.name: LifeCycle04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, LifeCycle04, TestSize.Level2)
{
    /**
     * @tc.steps: step1. create canvasnode and add child
     */
    RSCanvasNode::SharedPtr rootNode = RSCanvasNode::Create();
    ASSERT_TRUE(rootNode != nullptr);

    RSCanvasNode::SharedPtr child1 = RSCanvasNode::Create();
    RSCanvasNode::SharedPtr child2 = RSCanvasNode::Create();
    RSCanvasNode::SharedPtr child3 = RSCanvasNode::Create();
    rootNode->AddChild(child1, -1);
    rootNode->AddChild(child2, 0);
    rootNode->DumpNode(1);
    child1->AddChild(child3, 1);
    child1->MoveChild(child2, 0);
    child1->MoveChild(child3, 1);
    child1->AddChild(child3, 1);
    child1->MoveChild(child3, -1);
    child1->AddChild(child2, -1);
    child1->MoveChild(child2, 3);
    /**
     * @tc.steps: step2. remove child
     */
    rootNode->RemoveChild(child3);
}

/**
 * @tc.name: SetandGetBoundsWidth01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsWidth01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[2], floatData[1]));
}

/**
 * @tc.name: SetandGetBoundsWidth02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsWidth02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsWidth(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[2], floatData[2]));
}

/**
 * @tc.name: SetandGetBoundsWidth03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsWidth03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsWidth(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[2], floatData[3]));
}

/**
 * @tc.name: SetandGetBoundsWidth04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsWidth04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsWidth(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[2], floatData[4]));
}

/**
 * @tc.name: SetandGetBoundsWidth05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsWidth05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsWidth(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[2], floatData[0]));
}

/**
 * @tc.name: SetandGetBoundsHeight01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsHeight01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsHeight(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[3], floatData[1]));
}

/**
 * @tc.name: SetandGetBoundsHeight02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsHeight02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsHeight(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[3], floatData[2]));
}

/**
 * @tc.name: SetandGetBoundsHeight03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsHeight03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsHeight(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[3], floatData[3]));
}

/**
 * @tc.name: SetandGetBoundsHeight04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsHeight04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsHeight(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[3], floatData[4]));
}

/**
 * @tc.name: SetandGetBoundsHeight05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBoundsHeight05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBoundsHeight(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBounds()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetFrame01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFrame01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFrame(floatData[0], floatData[1], floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[0], floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[1], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[2], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[3], floatData[3]));
}

/**
 * @tc.name: SetandGetFrame02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFrame02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFrame(floatData[3], floatData[1], floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[0], floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[1], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[2], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetFrame03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFrame03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFrame(floatData[3], floatData[2], floatData[1], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[0], floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[1], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[2], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetFramePositionX01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionX01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[0], floatData[1]));
}

/**
 * @tc.name: SetandGetFramePositionX02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionX02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[0], floatData[2]));
}

/**
 * @tc.name: SetandGetFramePositionX03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionX03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[0], floatData[3]));
}

/**
 * @tc.name: SetandGetFramePositionX04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionX04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[0], floatData[4]));
}

/**
 * @tc.name: SetandGetFramePositionX05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionX05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[0], floatData[0]));
}

/**
 * @tc.name: SetandGetFramePositionY01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionY01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[1], floatData[1]));
}

/**
 * @tc.name: SetandGetFramePositionY02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionY02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[1], floatData[2]));
}

/**
 * @tc.name: SetandGetFramePositionY03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionY03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[1], floatData[3]));
}

/**
 * @tc.name: SetandGetFramePositionY04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionY04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[1], floatData[4]));
}

/**
 * @tc.name: SetandGetFramePositionY05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetFramePositionY05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetFramePositionY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetFrame()[1], floatData[0]));
}

/**
 * @tc.name: SetandGetPositionZ01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPositionZ01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPositionZ(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPositionZ(), floatData[1]));
}

/**
 * @tc.name: SetandGetPositionZ02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPositionZ02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPositionZ(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPositionZ(), floatData[2]));
}

/**
 * @tc.name: SetandGetPositionZ03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPositionZ03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPositionZ(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPositionZ(), floatData[3]));
}

/**
 * @tc.name: SetandGetPositionZ04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPositionZ04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPositionZ(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPositionZ(), floatData[4]));
}

/**
 * @tc.name: SetandGetPositionZ05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPositionZ05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPositionZ(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPositionZ(), floatData[0]));
}

/**
 * @tc.name: SetandGetCornerRadius01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetCornerRadius01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetCornerRadius(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetCornerRadius().x_, floatData[1]));
}

/**
 * @tc.name: SetandGetCornerRadius02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetCornerRadius02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetCornerRadius(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetCornerRadius().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetCornerRadius03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetCornerRadius03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetCornerRadius(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetCornerRadius().z_, floatData[3]));
}

/**
 * @tc.name: SetandGetCornerRadius04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetCornerRadius04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetCornerRadius(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetCornerRadius().w_, floatData[4]));
}

/**
 * @tc.name: SetandGetCornerRadius05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetCornerRadius05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetCornerRadius(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetCornerRadius().x_, floatData[0]));
}

/**
 * @tc.name: SetandGetRotationThree01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationThree01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotation(floatData[1], floatData[2], floatData[3]);
}

/**
 * @tc.name: SetandGetRotation01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotation01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotation(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotation(), floatData[1]));
}

/**
 * @tc.name: SetandGetRotation02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotation02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotation(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotation(), floatData[2]));
}

/**
 * @tc.name: SetandGetRotation03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotation03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotation(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotation(), floatData[3]));
}

/**
 * @tc.name: SetandGetRotation04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotation04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotation(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotation(), floatData[4]));
}

/**
 * @tc.name: SetandGetRotation05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotation05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotation(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotation(), floatData[0]));
}

/**
 * @tc.name: SetandGetRotationX01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationX01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationX(), floatData[1]));
}

/**
 * @tc.name: SetandGetRotationX02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationX02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationX(), floatData[2]));
}

/**
 * @tc.name: SetandGetRotationX03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationX03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationX(), floatData[3]));
}

/**
 * @tc.name: SetandGetRotationX04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationX04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationX(), floatData[4]));
}

/**
 * @tc.name: SetandGetRotationX05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationX05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationX(), floatData[0]));
}

/**
 * @tc.name: SetandGetRotationY01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationY01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationY(), floatData[1]));
}

/**
 * @tc.name: SetandGetRotationY02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationY02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationY(), floatData[2]));
}

/**
 * @tc.name: SetandGetRotationY03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationY03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationY(), floatData[3]));
}

/**
 * @tc.name: SetandGetRotationY04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationY04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationY(), floatData[4]));
}

/**
 * @tc.name: SetandGetRotationY05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetRotationY05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetRotationY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetRotationY(), floatData[0]));
}


/**
 * @tc.name: SetandGetScaleX01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleX01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[1]));
}

/**
 * @tc.name: SetandGetScaleX02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleX02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[2]));
}

/**
 * @tc.name: SetandGetScaleX03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleX03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[3]));
}

/**
 * @tc.name: SetandGetScaleX04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleX04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[4]));
}

/**
 * @tc.name: SetandGetScaleX05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleX05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[0]));
}

/**
 * @tc.name: SetandGetScale01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScale01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScale(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetScale02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScale02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScale(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetScale03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScale03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScale(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[3]));
}

/**
 * @tc.name: SetandGetScale04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScale04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScale(floatData[3], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[0]));
}

/**
 * @tc.name: SetandGetScale005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScale005, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScale(floatData[2], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetScaleY01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleY01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetScaleY02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleY02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetScaleY03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleY03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[3]));
}

/**
 * @tc.name: SetandGetScaleY04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleY04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[4]));
}

/**
 * @tc.name: SetandGetScaleY05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetScaleY05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetScaleY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetScale().y_, floatData[0]));
}

/**
 * @tc.name: SetandGetSkew01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkew01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkew(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetSkew02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkew02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkew(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetSkew03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkew03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkew(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[3]));
}

/**
 * @tc.name: SetandGetSkew04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkew04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkew(floatData[3], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[0]));
}

/**
 * @tc.name: SetandGetSkew005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkew005, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkew(floatData[2], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetSkewX01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewX01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[1]));
}

/**
 * @tc.name: SetandGetSkewX02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewX02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[2]));
}

/**
 * @tc.name: SetandGetSkewX03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewX03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[3]));
}

/**
 * @tc.name: SetandGetSkewX04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewX04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[4]));
}

/**
 * @tc.name: SetandGetSkewX05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewX05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().x_, floatData[0]));
}

/**
 * @tc.name: SetandGetSkewY01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewY01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetSkewY02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewY02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetSkewY03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewY03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[3]));
}

/**
 * @tc.name: SetandGetSkewY04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewY04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[4]));
}

/**
 * @tc.name: SetandGetSkewY05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetSkewY05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetSkewY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetSkew().y_, floatData[0]));
}

/**
 * @tc.name: SetandGetPersp01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPersp01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPersp(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_POSITIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: SetandGetPersp02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPersp02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPersp(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: SetandGetPersp03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPersp03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPersp(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: SetandGetPersp04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPersp04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPersp(FLOAT_DATA_MAX, FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: SetandGetPersp005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPersp005, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPersp(FLOAT_DATA_NEGATIVE, FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: SetandGetPerspX01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspX01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspX(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: SetandGetPerspX02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspX02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspX(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: SetandGetPerspX03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspX03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspX(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: SetandGetPerspX04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspX04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspX(FLOAT_DATA_MIN);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MIN));
}

/**
 * @tc.name: SetandGetPerspX05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspX05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspX(FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: SetandGetPerspY01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspY01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspY(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: SetandGetPerspY02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspY02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspY(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: SetandGetPerspY03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspY03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspY(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: SetandGetPerspY04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspY04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspY(FLOAT_DATA_MIN);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MIN));
}

/**
 * @tc.name: SetandGetPerspY05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetPerspY05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetPerspY(FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: SetandGetAlpha01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetAlpha01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetAlpha(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetAlpha(), floatData[1]));
}

/**
 * @tc.name: SetandGetAlpha02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetAlpha02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetAlpha(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetAlpha(), floatData[2]));
}

/**
 * @tc.name: SetandGetAlpha03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetAlpha03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetAlpha(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetAlpha(), floatData[3]));
}

/**
 * @tc.name: SetandGetAlpha04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetAlpha04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetAlpha(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetAlpha(), floatData[4]));
}

/**
 * @tc.name: SetandGetAlpha05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetAlpha05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetAlpha(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetAlpha(), floatData[0]));
}

/**
 * @tc.name: SetandGetBgImageSize01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageSize01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageSize(floatData[0], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageWidth(), floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImageSize02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageSize02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageSize(floatData[3], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImageSize03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageSize03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageSize(floatData[3], floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageHeight(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImageWidth01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageWidth01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageWidth(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImageWidth02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageWidth02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageWidth(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageWidth(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImageWidth03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageWidth03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageWidth(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImageWidth04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageWidth04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageWidth(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageWidth(), floatData[4]));
}

/**
 * @tc.name: SetandGetBgImageWidth05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageWidth05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageWidth(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageWidth(), floatData[0]));
}

/**
 * @tc.name: SetandGetBgImageHeight01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageHeight01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageHeight(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImageHeight02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageHeight02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageHeight(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageHeight(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImageHeight03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageHeight03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageHeight(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageHeight(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImageHeight04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageHeight04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageHeight(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageHeight(), floatData[4]));
}

/**
 * @tc.name: SetandGetBgImageHeight05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImageHeight05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImageHeight(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImageHeight(), floatData[0]));
}

/**
 * @tc.name: SetandSetBgImagePosition01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandSetBgImagePosition01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePosition(floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionY(), floatData[3]));
}

/**
 * @tc.name: SetandSetBgImagePosition02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandSetBgImagePosition02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePosition(floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionY(), floatData[0]));
}

/**
 * @tc.name: SetandSetBgImagePosition03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandSetBgImagePosition03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePosition(floatData[1], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionX(), floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionY(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImagePositionX01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionX01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionX(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImagePositionX02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionX02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImagePositionX03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionX03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionX(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImagePositionX04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionX04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionX(), floatData[4]));
}

/**
 * @tc.name: SetandGetBgImagePositionX05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionX05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionX(), floatData[0]));
}

/**
 * @tc.name: SetandGetBgImagePositionY01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionY01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionY(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImagePositionY02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionY02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionY(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImagePositionY03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionY03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionY(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImagePositionY04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionY04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionY(), floatData[4]));
}

/**
 * @tc.name: SetandGetBgImagePositionY05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBgImagePositionY05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBgImagePositionY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBgImagePositionY(), floatData[0]));
}

/**
 * @tc.name: SetandGetBorderWidth01
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderWidth01, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBorderWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBorderWidth().x_, floatData[1]));
}

/**
 * @tc.name: SetandGetBorderWidth02
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderWidth02, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBorderWidth(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBorderWidth().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetBorderWidth03
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderWidth03, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBorderWidth(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBorderWidth().z_, floatData[3]));
}

/**
 * @tc.name: SetandGetBorderWidth04
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderWidth04, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBorderWidth(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBorderWidth().w_, floatData[4]));
}

/**
 * @tc.name: SetandGetBorderWidth05
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderWidth05, TestSize.Level2)
{
    RSCanvasNode::SharedPtr canvasnode = RSCanvasNode::Create();
    canvasnode->SetBorderWidth(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasnode->GetStagingProperties().GetBorderWidth().x_, floatData[0]));
}

/**
 * @tc.name: SetandGetBorderDashParams01
 * @tc.desc: Check for zero values
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderDashParams01, TestSize.Level2)
{
    SetBorderDashParamsAndTest(FLOAT_DATA_ZERO);
}

/**
 * @tc.name: SetandGetBorderDashParams02
 * @tc.desc: Check for positive values
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderDashParams02, TestSize.Level2)
{
    SetBorderDashParamsAndTest(FLOAT_DATA_POSITIVE);
}

/**
 * @tc.name: SetandGetBorderDashParams03
 * @tc.desc: Check for negative values
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderDashParams03, TestSize.Level2)
{
    SetBorderDashParamsAndTest(FLOAT_DATA_NEGATIVE);
}

/**
 * @tc.name: SetandGetBorderDashParams04
 * @tc.desc: Check for max values
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderDashParams04, TestSize.Level2)
{
    SetBorderDashParamsAndTest(FLOAT_DATA_MAX);
}

/**
 * @tc.name: SetandGetBorderDashParams05
 * @tc.desc: Check for min values
 * @tc.type:FUNC
 */
HWTEST_F(RsCanvasNodesTest, SetandGetBorderDashParams05, TestSize.Level2)
{
    SetBorderDashParamsAndTest(FLOAT_DATA_MIN);
}
} // namespace OHOS::Rosen
