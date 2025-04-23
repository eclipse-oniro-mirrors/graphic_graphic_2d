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

class RSCanvasUnitTest : public testing::Test {
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

void RSCanvasUnitTest::SetUpTestCase() {}
void RSCanvasUnitTest::TearDownTestCase() {}
void RSCanvasUnitTest::SetUp() {}
void RSCanvasUnitTest::TearDown() {}

/**
 * @tc.name: Create001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, Create001, TestSize.Level1)
{
    // return shared_ptr
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
}

/**
 * @tc.name: Create002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, Create002, TestSize.Level1)
{
    // return shared_ptr
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create(true);
    ASSERT_NE(canvasNode, nullptr);
}

/**
 * @tc.name: Create003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, Create003, TestSize.Level1)
{
    // return shared_ptr
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create(false);
    ASSERT_NE(canvasNode, nullptr);
}


/**
 * @tc.name: LifeCycle001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, LifeCycle001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create canvasNode and add child
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
 * @tc.name: LifeCycle002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, LifeCycle002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create canvasNode and add child
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
 * @tc.name: LifeCycle003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, LifeCycle003, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create canvasNode and add child
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
 * @tc.name: LifeCycle004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, LifeCycle004, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create canvasNode and add child
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
 * @tc.name: Recording001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, Recording001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create canvasNode and RSUIDirector
     */
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();

    /**
     * @tc.steps: step2. begin recording
     */
    EXPECT_FALSE(canvasNode->IsRecording());
    canvasNode->BeginRecording(500, 400);
    EXPECT_TRUE(canvasNode->IsRecording());
}

/**
 * @tc.name: Recording002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, Recording002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create canvasNode and RSUIDirector
     */
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();

    /**
     * @tc.steps: step2. begin recording
     */
    EXPECT_FALSE(canvasNode->IsRecording());
    canvasNode->FinishRecording();
    canvasNode->BeginRecording(500, 400);
    EXPECT_TRUE(canvasNode->IsRecording());
    canvasNode->FinishRecording();
}

/**
 * @tc.name: SetPaintOrder001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetPaintOrder001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. create canvasNode and RSUIDirector
     */
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    canvasNode->SetPaintOrder(true);
}

/**
 * @tc.name: SetandGetBounds001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBounds001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBounds(floatData[0], floatData[1], floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[0], floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[1], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[2], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[3], floatData[3]));
}

/**
 * @tc.name: SetandGetBounds002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBounds002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBounds(floatData[3], floatData[1], floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[0], floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[1], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[2], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetBounds003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBounds003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBounds(floatData[3], floatData[2], floatData[1], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[0], floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[1], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[2], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetBoundsWidth001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsWidth001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[2], floatData[1]));
}

/**
 * @tc.name: SetandGetBoundsWidth002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsWidth002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsWidth(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[2], floatData[2]));
}

/**
 * @tc.name: SetandGetBoundsWidth003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsWidth003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsWidth(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[2], floatData[3]));
}

/**
 * @tc.name: SetandGetBoundsWidth004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsWidth004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsWidth(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[2], floatData[4]));
}

/**
 * @tc.name: SetandGetBoundsWidth005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsWidth005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsWidth(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[2], floatData[0]));
}

/**
 * @tc.name: SetandGetBoundsHeight001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsHeight001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsHeight(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[3], floatData[1]));
}

/**
 * @tc.name: SetandGetBoundsHeight002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsHeight002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsHeight(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[3], floatData[2]));
}

/**
 * @tc.name: SetandGetBoundsHeight003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsHeight003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsHeight(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[3], floatData[3]));
}

/**
 * @tc.name: SetandGetBoundsHeight004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsHeight004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsHeight(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[3], floatData[4]));
}

/**
 * @tc.name: SetandGetBoundsHeight005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBoundsHeight005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBoundsHeight(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBounds()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetFrame001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFrame001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFrame(floatData[0], floatData[1], floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[0], floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[1], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[2], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[3], floatData[3]));
}

/**
 * @tc.name: SetandGetFrame002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFrame002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFrame(floatData[3], floatData[1], floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[0], floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[1], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[2], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetFrame003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFrame003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFrame(floatData[3], floatData[2], floatData[1], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[0], floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[1], floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[2], floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[3], floatData[0]));
}

/**
 * @tc.name: SetandGetFramePositionX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionX001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[0], floatData[1]));
}

/**
 * @tc.name: SetandGetFramePositionX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionX002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[0], floatData[2]));
}

/**
 * @tc.name: SetandGetFramePositionX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionX003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[0], floatData[3]));
}

/**
 * @tc.name: SetandGetFramePositionX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionX004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[0], floatData[4]));
}

/**
 * @tc.name: SetandGetFramePositionX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionX005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[0], floatData[0]));
}

/**
 * @tc.name: SetandGetFramePositionY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionY001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[1], floatData[1]));
}

/**
 * @tc.name: SetandGetFramePositionY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionY002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[1], floatData[2]));
}

/**
 * @tc.name: SetandGetFramePositionY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionY003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[1], floatData[3]));
}

/**
 * @tc.name: SetandGetFramePositionY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionY004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[1], floatData[4]));
}

/**
 * @tc.name: SetandGetFramePositionY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetFramePositionY005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetFramePositionY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetFrame()[1], floatData[0]));
}

/**
 * @tc.name: SetandGetPositionZ001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPositionZ001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPositionZ(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPositionZ(), floatData[1]));
}

/**
 * @tc.name: SetandGetPositionZ002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPositionZ002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPositionZ(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPositionZ(), floatData[2]));
}

/**
 * @tc.name: SetandGetPositionZ003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPositionZ003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPositionZ(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPositionZ(), floatData[3]));
}

/**
 * @tc.name: SetandGetPositionZ004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPositionZ004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPositionZ(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPositionZ(), floatData[4]));
}

/**
 * @tc.name: SetandGetPositionZ005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPositionZ005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPositionZ(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPositionZ(), floatData[0]));
}

/**
 * @tc.name: SetandGetCornerRadius001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetCornerRadius001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetCornerRadius(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetCornerRadius().x_, floatData[1]));
}

/**
 * @tc.name: SetandGetCornerRadius002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetCornerRadius002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetCornerRadius(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetCornerRadius().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetCornerRadius003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetCornerRadius003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetCornerRadius(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetCornerRadius().z_, floatData[3]));
}

/**
 * @tc.name: SetandGetCornerRadius004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetCornerRadius004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetCornerRadius(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetCornerRadius().w_, floatData[4]));
}

/**
 * @tc.name: SetandGetCornerRadius005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetCornerRadius005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetCornerRadius(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetCornerRadius().x_, floatData[0]));
}

/**
 * @tc.name: SetandGetRotationThree001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationThree001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    canvasNode->SetRotation(floatData[1], floatData[2], floatData[3]);
}

/**
 * @tc.name: SetandGetRotation001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotation001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotation(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotation(), floatData[1]));
}

/**
 * @tc.name: SetandGetRotation002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotation002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotation(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotation(), floatData[2]));
}

/**
 * @tc.name: SetandGetRotation003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotation003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotation(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotation(), floatData[3]));
}

/**
 * @tc.name: SetandGetRotation004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotation004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotation(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotation(), floatData[4]));
}

/**
 * @tc.name: SetandGetRotation005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotation005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotation(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotation(), floatData[0]));
}

/**
 * @tc.name: SetandGetRotationX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationX001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationX(), floatData[1]));
}

/**
 * @tc.name: SetandGetRotationX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationX002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationX(), floatData[2]));
}

/**
 * @tc.name: SetandGetRotationX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationX003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationX(), floatData[3]));
}

/**
 * @tc.name: SetandGetRotationX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationX004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationX(), floatData[4]));
}

/**
 * @tc.name: SetandGetRotationX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationX005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationX(), floatData[0]));
}

/**
 * @tc.name: SetandGetRotationY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationY001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationY(), floatData[1]));
}

/**
 * @tc.name: SetandGetRotationY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationY002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationY(), floatData[2]));
}

/**
 * @tc.name: SetandGetRotationY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationY003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationY(), floatData[3]));
}

/**
 * @tc.name: SetandGetRotationY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationY004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationY(), floatData[4]));
}

/**
 * @tc.name: SetandGetRotationY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetRotationY005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetRotationY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetRotationY(), floatData[0]));
}


/**
 * @tc.name: SetandGetScaleX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleX001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[1]));
}

/**
 * @tc.name: SetandGetScaleX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleX002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[2]));
}

/**
 * @tc.name: SetandGetScaleX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleX003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[3]));
}

/**
 * @tc.name: SetandGetScaleX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleX004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[4]));
}

/**
 * @tc.name: SetandGetScaleX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleX005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[0]));
}

/**
 * @tc.name: SetandGetScale001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScale001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScale(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetScale002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScale002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScale(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetScale003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScale003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScale(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[3]));
}

/**
 * @tc.name: SetandGetScale004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScale004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScale(floatData[3], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[0]));
}

/**
 * @tc.name: SetandGetScale0005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScale0005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScale(floatData[2], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetScaleY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleY001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetScaleY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleY002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetScaleY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleY003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[3]));
}

/**
 * @tc.name: SetandGetScaleY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleY004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[4]));
}

/**
 * @tc.name: SetandGetScaleY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetScaleY005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetScaleY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetScale().y_, floatData[0]));
}

/**
 * @tc.name: SetandGetSkew001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkew001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetSkew002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkew002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetSkew003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkew003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[3]));
}

/**
 * @tc.name: SetandGetSkew004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkew004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[3], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[0]));
}

/**
 * @tc.name: SetandGetSkew0005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkew0005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkew(floatData[2], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetSkewX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewX001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[1]));
}

/**
 * @tc.name: SetandGetSkewX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewX002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[2]));
}

/**
 * @tc.name: SetandGetSkewX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewX003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[3]));
}

/**
 * @tc.name: SetandGetSkewX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewX004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[4]));
}

/**
 * @tc.name: SetandGetSkewX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewX005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().x_, floatData[0]));
}

/**
 * @tc.name: SetandGetSkewY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewY001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[1]));
}

/**
 * @tc.name: SetandGetSkewY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewY002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[2]));
}

/**
 * @tc.name: SetandGetSkewY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewY003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[3]));
}

/**
 * @tc.name: SetandGetSkewY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewY004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[4]));
}

/**
 * @tc.name: SetandGetSkewY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetSkewY005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetSkewY(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetSkew().y_, floatData[0]));
}

/**
 * @tc.name: SetandGetPersp001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPersp001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_POSITIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: SetandGetPersp002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPersp002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: SetandGetPersp003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPersp003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: SetandGetPersp004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPersp004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_MAX, FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: SetandGetPersp0005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPersp0005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPersp(FLOAT_DATA_NEGATIVE, FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: SetandGetPerspX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspX001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: SetandGetPerspX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspX002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: SetandGetPerspX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspX003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: SetandGetPerspX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspX004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_MIN);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_MIN));
}

/**
 * @tc.name: SetandGetPerspX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspX005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspX(FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().x_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: SetandGetPerspY001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspY001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_POSITIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_POSITIVE));
}

/**
 * @tc.name: SetandGetPerspY002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspY002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_NEGATIVE);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_NEGATIVE));
}

/**
 * @tc.name: SetandGetPerspY003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspY003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_MAX);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MAX));
}

/**
 * @tc.name: SetandGetPerspY004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspY004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_MIN);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_MIN));
}

/**
 * @tc.name: SetandGetPerspY005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetPerspY005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetPerspY(FLOAT_DATA_ZERO);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetPersp().y_, FLOAT_DATA_ZERO));
}

/**
 * @tc.name: SetandGetAlpha001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetAlpha001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetAlpha(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetAlpha(), floatData[1]));
}

/**
 * @tc.name: SetandGetAlpha002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetAlpha002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetAlpha(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetAlpha(), floatData[2]));
}

/**
 * @tc.name: SetandGetAlpha003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetAlpha003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetAlpha(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetAlpha(), floatData[3]));
}

/**
 * @tc.name: SetandGetAlpha004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetAlpha004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetAlpha(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetAlpha(), floatData[4]));
}

/**
 * @tc.name: SetandGetAlpha005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetAlpha005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetAlpha(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetAlpha(), floatData[0]));
}

/**
 * @tc.name: SetandGetBgImageSize001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageSize001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageSize(floatData[0], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageWidth(), floatData[0]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImageSize002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageSize002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageSize(floatData[3], floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImageSize003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageSize003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageSize(floatData[3], floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageHeight(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImageWidth001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageWidth001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageWidth(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageWidth(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImageWidth002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageWidth002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageWidth(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageWidth(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImageWidth003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageWidth003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageWidth(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageWidth(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImageWidth004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageWidth004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageWidth(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageWidth(), floatData[4]));
}

/**
 * @tc.name: SetandGetBgImageWidth005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageWidth005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageWidth(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageWidth(), floatData[0]));
}

/**
 * @tc.name: SetandGetBgImageHeight001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageHeight001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageHeight(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageHeight(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImageHeight002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageHeight002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageHeight(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageHeight(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImageHeight003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageHeight003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageHeight(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageHeight(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImageHeight004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageHeight004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageHeight(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageHeight(), floatData[4]));
}

/**
 * @tc.name: SetandGetBgImageHeight005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImageHeight005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImageHeight(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImageHeight(), floatData[0]));
}

/**
 * @tc.name: SetandSetBgImagePosition001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandSetBgImagePosition001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImagePosition(floatData[2], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionY(), floatData[3]));
}

/**
 * @tc.name: SetandSetBgImagePosition002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandSetBgImagePosition002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImagePosition(floatData[2], floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionY(), floatData[0]));
}

/**
 * @tc.name: SetandSetBgImagePosition003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandSetBgImagePosition003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImagePosition(floatData[1], floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionX(), floatData[1]));
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionY(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImagePositionX001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImagePositionX001, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImagePositionX(floatData[1]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionX(), floatData[1]));
}

/**
 * @tc.name: SetandGetBgImagePositionX002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImagePositionX002, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImagePositionX(floatData[2]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionX(), floatData[2]));
}

/**
 * @tc.name: SetandGetBgImagePositionX003
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImagePositionX003, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImagePositionX(floatData[3]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionX(), floatData[3]));
}

/**
 * @tc.name: SetandGetBgImagePositionX004
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImagePositionX004, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImagePositionX(floatData[4]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionX(), floatData[4]));
}

/**
 * @tc.name: SetandGetBgImagePositionX005
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSCanvasUnitTest, SetandGetBgImagePositionX005, TestSize.Level1)
{
    RSCanvasNode::SharedPtr canvasNode = RSCanvasNode::Create();
    canvasNode->SetBgImagePositionX(floatData[0]);
    EXPECT_TRUE(ROSEN_EQ(canvasNode->GetStagingProperties().GetBgImagePositionX(), floatData[0]));
}
} // namespace OHOS::Rosen