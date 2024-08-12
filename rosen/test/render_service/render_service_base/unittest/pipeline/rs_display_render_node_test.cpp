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

#include "gtest/gtest.h"

#include "common/rs_obj_abs_geometry.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_render_thread_visitor.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSDisplayRenderNodeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static inline NodeId id;
    RSDisplayNodeConfig config;
    static inline std::weak_ptr<RSContext> context = {};
};

void RSDisplayRenderNodeTest::SetUpTestCase() {}
void RSDisplayRenderNodeTest::TearDownTestCase() {}
void RSDisplayRenderNodeTest::SetUp() {}
void RSDisplayRenderNodeTest::TearDown() {}

/**
 * @tc.name: PrepareTest
 * @tc.desc: test results of Prepare
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, PrepareTest, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    std::shared_ptr<RSNodeVisitor> visitor = nullptr;
    node->QuickPrepare(visitor);
    node->Prepare(visitor);

    visitor = std::make_shared<RSRenderThreadVisitor>();
    node->QuickPrepare(visitor);
    node->Prepare(visitor);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: SkipFrameTest001
 * @tc.desc: test SkipFrame for refreshRate 0 and skipFrameInterval 0
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SkipFrameTest001, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    uint32_t refreshRate = 0;
    uint32_t skipFrameInterval = 0;
    ASSERT_FALSE(node->SkipFrame(refreshRate, skipFrameInterval));
}

/**
 * @tc.name: SkipFrameTest002
 * @tc.desc: test SkipFrame for skipFrameInterval 0
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SkipFrameTest002, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    uint32_t refreshRate = 60; // 60hz
    uint32_t skipFrameInterval = 0;
    ASSERT_FALSE(node->SkipFrame(refreshRate, skipFrameInterval));
}

/**
 * @tc.name: SkipFrameTest003
 * @tc.desc: test SkipFrame for skipFrameInterval 1
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SkipFrameTest003, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    uint32_t refreshRate = 60; // 60hz
    uint32_t skipFrameInterval = 1;
    ASSERT_FALSE(node->SkipFrame(refreshRate, skipFrameInterval));
}

/**
 * @tc.name: SkipFrameTest004
 * @tc.desc: test SkipFrame for time within skipFrameInterval 2
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SkipFrameTest004, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    uint32_t refreshRate = 60; // 60hz
    uint32_t skipFrameInterval = 2; // skipFrameInterval 2
    node->SkipFrame(refreshRate, skipFrameInterval);
    ASSERT_TRUE(node->SkipFrame(refreshRate, skipFrameInterval));
}

/**
 * @tc.name: SkipFrameTest005
 * @tc.desc: test SkipFrame for time over skipFrameInterval 2
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SkipFrameTest005, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    uint32_t refreshRate = 60; // 60hz
    uint32_t skipFrameInterval = 2; // skipFrameInterval 2
    node->SkipFrame(refreshRate, skipFrameInterval);
    usleep(50000); // 50000us == 50ms
    ASSERT_FALSE(node->SkipFrame(refreshRate, skipFrameInterval));
}

/**
 * @tc.name: SkipFrameTest006
 * @tc.desc: test SkipFrame for time within skipFrameInterval 6
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SkipFrameTest006, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    uint32_t refreshRate = 60; // 60hz
    uint32_t skipFrameInterval = 6; // skipFrameInterval 6
    node->SkipFrame(refreshRate, skipFrameInterval);
    usleep(50000); // 50000us == 50ms
    ASSERT_TRUE(node->SkipFrame(refreshRate, skipFrameInterval));
}

/**
 * @tc.name: SkipFrameTest007
 * @tc.desc: test SkipFrame for time over skipFrameInterval 6
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SkipFrameTest007, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    uint32_t refreshRate = 60; // 60hz
    uint32_t skipFrameInterval = 6; // skipFrameInterval 6
    node->SkipFrame(refreshRate, skipFrameInterval);
    usleep(150000); // 150000us == 150ms
    ASSERT_FALSE(node->SkipFrame(refreshRate, skipFrameInterval));
}

/**
 * @tc.name: SetMirrorSourceTest
 * @tc.desc: test results of SetMirrorSource
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SetMirrorSourceTest, TestSize.Level1)
{
    std::shared_ptr<RSDisplayRenderNode> rsDisplayRenderNode = nullptr;
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    node->SetMirrorSource(rsDisplayRenderNode);

    node->isMirroredDisplay_ = true;
    node->SetMirrorSource(rsDisplayRenderNode);

    rsDisplayRenderNode = std::make_shared<RSDisplayRenderNode>(id + 1, config, context);
    node->SetMirrorSource(rsDisplayRenderNode);
    ASSERT_NE(node->mirrorSource_.lock(), nullptr);
}

/**
 * @tc.name: GetRotationTest
 * @tc.desc: test results of GetRotation
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, GetRotationTest, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    node->InitRenderParams();
    node->UpdateRotation();
    node->GetRotation();
    RSProperties& properties = const_cast<RSProperties&>(node->GetRenderProperties());
    properties.boundsGeo_.reset(new RSObjAbsGeometry());
    node->GetRotation();
    ASSERT_TRUE(true);
}

/**
 * @tc.name: IsRotationChangedTest
 * @tc.desc: test results of IsRotationChanged
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, IsRotationChangedTest, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    node->InitRenderParams();
    node->UpdateRotation();
    ASSERT_FALSE(node->IsRotationChanged());
    RSProperties& properties = const_cast<RSProperties&>(node->GetRenderProperties());
    properties.boundsGeo_.reset(new RSObjAbsGeometry());
    node->IsRotationChanged();
    ASSERT_TRUE(true);
}

/**
 * @tc.name: SetBootAnimationTest
 * @tc.desc:  test results of SetBootAnimation
 * @tc.type:FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSDisplayRenderNodeTest, SetBootAnimationTest, TestSize.Level1)
{
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(id, context);
    auto childNode = std::make_shared<RSDisplayRenderNode>(id + 1, config, context);
    node->AddChild(childNode);
    childNode->SetBootAnimation(true);
    ASSERT_EQ(childNode->GetBootAnimation(), true);
    node->SetBootAnimation(false);
    childNode->SetBootAnimation(false);
    ASSERT_FALSE(node->GetBootAnimation());
}

/**
 * @tc.name: GetBootAnimationTest
 * @tc.desc:  test results of GetBootAnimation
 * @tc.type:FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSDisplayRenderNodeTest, GetBootAnimationTest, TestSize.Level1)
{
    auto node = std::make_shared<RSDisplayRenderNode>(id, config, context);
    node->SetBootAnimation(true);
    ASSERT_TRUE(node->GetBootAnimation());
    node->SetBootAnimation(false);
    ASSERT_FALSE(node->GetBootAnimation());
}

/**
 * @tc.name: CollectSurface
 * @tc.desc:  test results of CollectSurface
 * @tc.type:FUNC
 * @tc.require:issueI981R9
 */
HWTEST_F(RSDisplayRenderNodeTest, CollectSurface, TestSize.Level2)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    RSContext* rsContext = new RSContext();
    std::shared_ptr<RSContext> sharedContext(rsContext);
    std::shared_ptr<RSBaseRenderNode> node = std::make_shared<RSRenderNode>(1, sharedContext);
    std::vector<RSBaseRenderNode::SharedPtr> vec;
    bool isUniRender = true;
    bool onlyFirstLevel = true;
    displayNode->CollectSurface(node, vec, isUniRender, onlyFirstLevel);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: ProcessTest
 * @tc.desc: test results of Process
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, ProcessTest, TestSize.Level1)
{
    std::shared_ptr<RSNodeVisitor> visitor = nullptr;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    displayNode->Process(visitor);

    visitor = std::make_shared<RSRenderThreadVisitor>();
    displayNode->Process(visitor);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: SetIsOnTheTree
 * @tc.desc: test results of SetIsOnTheTree
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SetIsOnTheTree, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    bool flag = true;
    displayNode->SetIsOnTheTree(flag, id, id, id, id);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: SetCompositeType
 * @tc.desc: test results of SetCompositeType
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SetCompositeType, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    RSDisplayRenderNode::CompositeType type = RSDisplayRenderNode::CompositeType::UNI_RENDER_COMPOSITE;
    displayNode->SetCompositeType(type);
    ASSERT_EQ(displayNode->GetCompositeType(), type);
}

/**
 * @tc.name: SetForceSoftComposite
 * @tc.desc: test results of SetForceSoftComposite
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, SetForceSoftComposite, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    bool flag = true;
    displayNode->SetForceSoftComposite(flag);
    ASSERT_EQ(displayNode->IsForceSoftComposite(), flag);
}

/**
 * @tc.name: UpdateRenderParams
 * @tc.desc: test results of UpdateRenderParams
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, UpdateRenderParams, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    displayNode->UpdateRenderParams();
    ASSERT_TRUE(true);
}

/**
 * @tc.name: UpdateScreenRenderParams
 * @tc.desc: test results of UpdateRenderParams
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, UpdateScreenRenderParams, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    RSDisplayRenderNode::ScreenRenderParams screenRenderParams;
    displayNode->UpdateScreenRenderParams(screenRenderParams);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: UpdatePartialRenderParams
 * @tc.desc: test results of UpdatePartialRenderParams
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, UpdatePartialRenderParams, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    displayNode->UpdatePartialRenderParams();
    ASSERT_TRUE(true);
}

/**
 * @tc.name: UpdateDisplayDirtyManager
 * @tc.desc: test results of UpdateDisplayDirtyManager
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, UpdateDisplayDirtyManager, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    int32_t bufferage = 1;
    bool useAlignedDirtyRegion = false;
    displayNode->UpdateDisplayDirtyManager(bufferage, useAlignedDirtyRegion);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: GetSortedChildren
 * @tc.desc: test results of GetSortedChildren
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDisplayRenderNodeTest, GetSortedChildren, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    displayNode->GetSortedChildren();
    displayNode->isNeedWaitNewScbPid_ = true;
    displayNode->GetSortedChildren();
    ASSERT_TRUE(true);
}

/**
 * @tc.name: GetDisappearedSurfaceRegionBelowCurrent001
 * @tc.desc: test results of GetDisappearedSurfaceRegionBelowCurrent
 * @tc.type:FUNC
 * @tc.require: issuesIA8LNR
 */
HWTEST_F(RSDisplayRenderNodeTest, GetDisappearedSurfaceRegionBelowCurrent001, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    ASSERT_NE(displayNode, nullptr);
    auto region = displayNode->GetDisappearedSurfaceRegionBelowCurrent(INVALID_NODEID);
    EXPECT_TRUE(region.IsEmpty());
}

/**
 * @tc.name: GetDisappearedSurfaceRegionBelowCurrent002
 * @tc.desc: test results of GetDisappearedSurfaceRegionBelowCurrent
 * @tc.type:FUNC
 * @tc.require: issuesIA8LNR
 */
HWTEST_F(RSDisplayRenderNodeTest, GetDisappearedSurfaceRegionBelowCurrent002, TestSize.Level1)
{
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config, context);
    ASSERT_NE(displayNode, nullptr);

    constexpr NodeId bottomSurfaceNodeId = 1;
    const RectI bottomSurfacePos(0, 0, 1, 1);
    const std::pair<NodeId, RectI> bottomSurface{ bottomSurfaceNodeId, bottomSurfacePos };
    constexpr NodeId topSurfaceNodeId = 2;
    const RectI topSurfacePos(0, 0, 2, 2);
    const std::pair<NodeId, RectI> topSurface{ topSurfaceNodeId, topSurfacePos };

    displayNode->UpdateSurfaceNodePos(topSurface.first, topSurface.second);
    displayNode->AddSurfaceNodePosByDescZOrder(topSurface.first, topSurface.second);
    displayNode->UpdateSurfaceNodePos(bottomSurface.first, bottomSurface.second);
    displayNode->AddSurfaceNodePosByDescZOrder(bottomSurface.first, bottomSurface.second);
    displayNode->ClearCurrentSurfacePos();
    displayNode->UpdateSurfaceNodePos(topSurface.first, topSurface.second);
    displayNode->AddSurfaceNodePosByDescZOrder(topSurface.first, topSurface.second);

    auto region = displayNode->GetDisappearedSurfaceRegionBelowCurrent(topSurface.first);
    EXPECT_TRUE(region.GetBound() == bottomSurface.second);
}
} // namespace OHOS::Rosen