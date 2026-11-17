/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "feature/drm/rs_drm_util.h"
#include "graphic_feature_param_manager.h"
#include "gtest/gtest.h"

#include "common/rs_common_def.h"
#include "composer/composer_client/pipeline/rs_composer_client_manager.h"
#include "drawable/rs_screen_render_node_drawable.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/rs_processor_factory.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_test_util.h"

using namespace testing;
using namespace testing::ext;

namespace {
constexpr uint32_t DEFAULT_CANVAS_WIDTH = 800;
constexpr uint32_t DEFAULT_CANVAS_HEIGHT = 600;
constexpr float CROSS_SCREEN_OFFSET_X = 3240.f;
constexpr int32_t CROSS_SCREEN_OFFSET_Y = 1854;
}

namespace OHOS::Rosen {
class RSDrmUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static NodeId GenerateNodeId()
    {
        static NodeId nextId = 1;
        return nextId++;
    }

    static ScreenId GenerateScreenId()
    {
        static ScreenId nextId = 1;
        return nextId++;
    }

    std::shared_ptr<DrawableV2::RSScreenRenderNodeDrawable> CreateScreenDrawable();
};

void RSDrmUtilTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}
void RSDrmUtilTest::TearDownTestCase() {}
void RSDrmUtilTest::SetUp() {}
void RSDrmUtilTest::TearDown() {}

std::shared_ptr<DrawableV2::RSScreenRenderNodeDrawable> RSDrmUtilTest::CreateScreenDrawable()
{
    static NodeId nodeId = GenerateNodeId();
    ScreenId screenId = GenerateScreenId();
    auto screenNode = std::make_shared<RSScreenRenderNode>(nodeId, screenId);
    auto screenDrawable = std::make_shared<DrawableV2::RSScreenRenderNodeDrawable>(std::move(screenNode));
    screenDrawable->renderParams_ = std::make_unique<RSScreenRenderParams>(screenId);
    return screenDrawable;
}

/**
 * Function: MarkBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkBlurIntersectWithDRM001, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> surfaceNode;
    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    RSDrmUtil::MarkBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    ASSERT_EQ(surfaceNode, nullptr);
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM001, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBCloneWallpaper";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    std::shared_ptr<RSScreenRenderNode> screenNode;
    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    ASSERT_EQ(screenNode, nullptr);
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM002, TestSize.Level1)
{
    DRMParam::AddBlackList("SCBCloneWallpaper");
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBCloneWallpaper";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    Color color(10, 10, 10, 110);
    surfaceNode->renderProperties_.SetBackgroundBlurMaskColor(color);
    std::shared_ptr<RSSurfaceRenderNode> drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(drmNode, nullptr);

    // let drm intersect with blur
    surfaceNode->GetFilterRegionInfo().filterRegion_ = RectT(0, 0, 1, 1);
    drmNode->GetRenderProperties().GetBoundsGeometry()->absRect_ = RectT(0, 0, 1, 1);

    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);

    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    drmNodes.push_back(drmNode);
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    ASSERT_FALSE(drmNodes.empty());
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM003, TestSize.Level1)
{
    DRMParam::AddBlackList("SCBCloneWallpaper");
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBCloneWallpaper";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    Color color(10, 10, 10, 10);
    surfaceNode->renderProperties_.SetBackgroundBlurMaskColor(color);
    std::shared_ptr<RSSurfaceRenderNode> drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(drmNode, nullptr);

    // let drm intersect with blur
    surfaceNode->GetFilterRegionInfo().filterRegion_ = RectT(0, 0, 1, 1);
    drmNode->GetRenderProperties().GetBoundsGeometry()->absRect_ = RectT(0, 0, 1, 1);

    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);

    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    drmNodes.push_back(drmNode);
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(1);
    ASSERT_FALSE(drmNodes.empty());
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM004, TestSize.Level1)
{
    DRMParam::AddBlackList("SCBCloneWallpaper");
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBCloneWallpaper";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    Color color(10, 10, 10, 10);
    surfaceNode->renderProperties_.SetBackgroundBlurMaskColor(color);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    std::shared_ptr<RSSurfaceRenderNode> drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(drmNode, nullptr);

    // let drm intersect with blur
    surfaceNode->GetFilterRegionInfo().filterRegion_ = RectT(0, 0, 1, 1);
    drmNode->GetRenderProperties().GetBoundsGeometry()->absRect_ = RectT(0, 0, 1, 1);

    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);

    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    drmNodes.push_back(drmNode);
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(1);
    ASSERT_FALSE(drmNodes.empty());
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM005, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBBannerNotification";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    Color color(10, 10, 10, 10);
    surfaceNode->renderProperties_.SetBackgroundBlurMaskColor(color);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    std::shared_ptr<RSSurfaceRenderNode> drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(drmNode, nullptr);
    drmNode->instanceRootNodeId_ = drmNode->GetId();
    Occlusion::Region region1({120, 50, 1000, 1500});
    drmNode->SetVisibleRegion(region1);

    // let drm intersect with blur
    surfaceNode->GetFilterRegionInfo().filterRegion_ = RectT(0, 0, 1, 1);
    drmNode->GetRenderProperties().GetBoundsGeometry()->absRect_ = RectT(0, 0, 1, 1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(drmNode);

    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(surfaceNode);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(drmNode);

    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    drmNodes.push_back(drmNode);
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(drmNode->GetId());
    ASSERT_FALSE(drmNodes.empty());
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM006, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBSmartDock";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    Color color(10, 10, 10, 10);
    surfaceNode->renderProperties_.SetBackgroundBlurMaskColor(color);
    surfaceNode->renderProperties_.SetBgBrightnessSaturation(1.5f);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    std::shared_ptr<RSSurfaceRenderNode> drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(drmNode, nullptr);
    drmNode->instanceRootNodeId_ = drmNode->GetId();
    Occlusion::Region region1({120, 50, 1000, 1500});
    drmNode->SetVisibleRegion(region1);

    // let drm intersect with blur
    surfaceNode->GetFilterRegionInfo().filterRegion_ = RectT(0, 0, 1, 1);
    drmNode->GetRenderProperties().GetBoundsGeometry()->absRect_ = RectT(0, 0, 1, 1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(drmNode);

    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(surfaceNode);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(drmNode);

    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    drmNodes.push_back(drmNode);
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(drmNode->GetId());
    ASSERT_FALSE(drmNodes.empty());
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM007, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBSmartDock";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    Color color(10, 10, 10, 10);
    surfaceNode->renderProperties_.SetBackgroundBlurMaskColor(color);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    std::shared_ptr<RSSurfaceRenderNode> drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(drmNode, nullptr);
    drmNode->instanceRootNodeId_ = drmNode->GetId();
    Occlusion::Region region1({120, 50, 1000, 1500});
    drmNode->SetVisibleRegion(region1);

    // let drm not intersect with blur
    surfaceNode->GetFilterRegionInfo().filterRegion_ = RectT(2, 2, 3, 3);
    drmNode->GetRenderProperties().GetBoundsGeometry()->absRect_ = RectT(0, 0, 1, 1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(drmNode);

    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(surfaceNode);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(drmNode);

    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    drmNodes.push_back(drmNode);
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(drmNode->GetId());
    ASSERT_FALSE(drmNodes.empty());
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM008, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBBannerNotification";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    Color color(10, 10, 10, 10);
    surfaceNode->renderProperties_.SetBackgroundBlurMaskColor(color);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    std::shared_ptr<RSSurfaceRenderNode> drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(drmNode, nullptr);
    drmNode->instanceRootNodeId_ = drmNode->GetId();
    // let drm visibleRegion empty
    Occlusion::Region region1({0, 0, 0, 0});
    drmNode->SetVisibleRegion(region1);

    // let drm intersect with blur
    surfaceNode->GetFilterRegionInfo().filterRegion_ = RectT(0, 0, 1, 1);
    drmNode->GetRenderProperties().GetBoundsGeometry()->absRect_ = RectT(0, 0, 1, 1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(drmNode);

    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(surfaceNode);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(drmNode);

    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    drmNodes.push_back(drmNode);
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(drmNode->GetId());
    ASSERT_FALSE(drmNodes.empty());
}

/**
 * Function: MarkAllBlurIntersectWithDRM
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, screenNode and drmNode
 *                  2. operation: MarkAllBlurIntersectWithDRM
 *                  3. result: surfaceNode drmNodes and screenNode are not nullptr
 */
HWTEST_F(RSDrmUtilTest, MarkAllBlurIntersectWithDRM009, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    surfaceConfig.name = "SCBBannerNotification";
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    Color color(10, 10, 10, 10);
    surfaceNode->renderProperties_.SetBackgroundBlurMaskColor(color);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    std::shared_ptr<RSSurfaceRenderNode> drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(drmNode, nullptr);
    drmNode->instanceRootNodeId_ = drmNode->GetId();
    Occlusion::Region region1({120, 50, 1000, 1500});
    drmNode->SetVisibleRegion(region1);

    // let drm intersect with blur
    surfaceNode->GetFilterRegionInfo().filterRegion_ = RectT(0, 0, 1, 1);
    drmNode->GetRenderProperties().GetBoundsGeometry()->absRect_ = RectT(0, 0, 1, 1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(drmNode);

    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(drmNode);
    screenNode->curMainAndLeashSurfaceNodes_.push_back(surfaceNode);

    std::vector<std::weak_ptr<RSSurfaceRenderNode>> drmNodes;
    drmNodes.push_back(drmNode);
    RSDrmUtil::MarkAllBlurIntersectWithDRM(surfaceNode, drmNodes, screenNode);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(1);
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(drmNode->GetId());
    ASSERT_FALSE(drmNodes.empty());
}

/**
 * Function: IsDRMNodesOnTheTree
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, set normal parameters
 *                  2. operation: IsDRMNodesOnTheTree
 *                  3. result: drmNodes is not OnTheTree
 */
HWTEST_F(RSDrmUtilTest, IsDRMNodesOnTheTree001, TestSize.Level1)
{
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->firstLevelNodeId_ = surfaceNode->GetId();
    surfaceNode->isOnTheTree_ = true;
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    RSDrmUtil::CollectDrmNodes(surfaceNode);
    EXPECT_TRUE(RSDrmUtil::IsDRMNodesOnTheTree());
    RSDrmUtil::ClearDrmNodes();
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(surfaceNode->GetId());
}

/**
 * Function: IsDRMNodesOnTheTree
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, set abnormal parameters
 *                  2. operation: IsDRMNodesOnTheTree
 *                  3. result: drmNodes is not OnTheTree
 */
HWTEST_F(RSDrmUtilTest, IsDRMNodesOnTheTree002, TestSize.Level1)
{
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->firstLevelNodeId_ = surfaceNode->GetId();
    surfaceNode->isOnTheTree_ = true;
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    RSDrmUtil::CollectDrmNodes(surfaceNode);
    EXPECT_FALSE(RSDrmUtil::IsDRMNodesOnTheTree());
    RSDrmUtil::ClearDrmNodes();
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(surfaceNode->GetId());
}

/**
 * Function: IsDRMNodesOnTheTree
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: CreateSurfaceNode, set abnormal parameters
 *                  2. operation: IsDRMNodesOnTheTree
 *                  3. result: drmNodes is not OnTheTree
 */
HWTEST_F(RSDrmUtilTest, IsDRMNodesOnTheTree003, TestSize.Level1)
{
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->firstLevelNodeId_ = surfaceNode->GetId();
    surfaceNode->isOnTheTree_ = true;
    surfaceNode->instanceRootNodeId_ = surfaceNode->GetId();
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().RegisterRenderNode(surfaceNode);
    RSDrmUtil::CollectDrmNodes(surfaceNode);
    surfaceNode->isOnTheTree_ = false;
    EXPECT_FALSE(RSDrmUtil::IsDRMNodesOnTheTree());
    RSDrmUtil::ClearDrmNodes();
    RSMainThread::Instance()->GetContext().GetMutableNodeMap().UnregisterRenderNode(surfaceNode->GetId());
}

/**
 * Function: PreAllocProtectedFrameBuffers
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: surfaceNode has no ancestor screen node
 *                  2. operation: PreAllocProtectedFrameBuffers
 *                  3. result: function returns without crash
 */
HWTEST_F(RSDrmUtilTest, PreAllocProtectedFrameBuffers002, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<RSComposerClientManager> clientManager = nullptr;
    RSDrmUtil::PreAllocProtectedFrameBuffers(surfaceNode, buffer, clientManager);
}

/**
 * Function: PreAllocProtectedFrameBuffers
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: surfaceNode has screen node, clientManager is nullptr
 *                  2. operation: PreAllocProtectedFrameBuffers
 *                  3. result: AddScreenHasProtectedLayerSet is called
 */
HWTEST_F(RSDrmUtilTest, PreAllocProtectedFrameBuffers003, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    
    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    ASSERT_NE(screenNode, nullptr);
    
    surfaceNode->ancestorScreenNode_ = screenNode;
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<RSComposerClientManager> clientManager = nullptr;
    RSDrmUtil::PreAllocProtectedFrameBuffers(surfaceNode, buffer, clientManager);
}

/**
 * Function: PreAllocProtectedFrameBuffers
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: surfaceNode has screen node, clientManager is valid
 *                  2. operation: PreAllocProtectedFrameBuffers
 *                  3. result: AddScreenHasProtectedLayerSet and clientManager->PreAllocProtectedFrameBuffers are called
 */
HWTEST_F(RSDrmUtilTest, PreAllocProtectedFrameBuffers004, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    
    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    ASSERT_NE(screenNode, nullptr);
    
    surfaceNode->ancestorScreenNode_ = screenNode;
    sptr<SurfaceBuffer> buffer = nullptr;
    auto clientManager = std::make_shared<RSComposerClientManager>();
    RSDrmUtil::PreAllocProtectedFrameBuffers(surfaceNode, buffer, clientManager);
}

/**
 * Function: PreAllocProtectedFrameBuffers
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: surfaceNode has screen node, buffer is valid, clientManager is valid
 *                  2. operation: PreAllocProtectedFrameBuffers
 *                  3. result: AddScreenHasProtectedLayerSet and clientManager->PreAllocProtectedFrameBuffers are called
 */
HWTEST_F(RSDrmUtilTest, PreAllocProtectedFrameBuffers005, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    
    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    ASSERT_NE(screenNode, nullptr);
    
    node->ancestorScreenNode_ = screenNode;

    auto clientManager = std::make_shared<RSComposerClientManager>();
    RSDrmUtil::PreAllocProtectedFrameBuffers(node, node->GetRSSurfaceHandler()->GetBuffer(), clientManager);
}

/**
 * Function: DealWithDRMNodes
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: surfaceNode, buffer, clientManager are valid
 *                  2. operation: DealWithDRMNodes
 *                  3. result: CollectDrmNodes and PreAllocProtectedFrameBuffers are called
 */
HWTEST_F(RSDrmUtilTest, DealWithDRMNodes001, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    
    sptr<SurfaceBuffer> buffer = nullptr;
    auto clientManager = std::make_shared<RSComposerClientManager>();
    RSDrmUtil::DealWithDRMNodes(surfaceNode, buffer, clientManager);
    RSDrmUtil::ClearDrmNodes();
}

/**
 * Function: DealWithDRMNodes
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: surfaceNode has screen node, buffer, clientManager are valid
 *                  2. operation: DealWithDRMNodes
 *                  3. result: CollectDrmNodes and PreAllocProtectedFrameBuffers are called
 */
HWTEST_F(RSDrmUtilTest, DealWithDRMNodes002, TestSize.Level1)
{
    RSSurfaceRenderNodeConfig surfaceConfig;
    surfaceConfig.id = 1;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
    ASSERT_NE(surfaceNode, nullptr);
    
    NodeId id = 0;
    ScreenId screenId = 0;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, rsContext);
    ASSERT_NE(screenNode, nullptr);
    
    surfaceNode->ancestorScreenNode_ = screenNode;
    
    sptr<SurfaceBuffer> buffer = nullptr;
    auto clientManager = std::make_shared<RSComposerClientManager>();
    RSDrmUtil::DealWithDRMNodes(surfaceNode, buffer, clientManager);
    RSDrmUtil::ClearDrmNodes();
}

/**
 * Function: HasDRMInVirtualScreen
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: ancestorDrawable is nullptr
 *                  2. operation: HasDRMInVirtualScreen
 *                  3. result: return false
 */
HWTEST_F(RSDrmUtilTest, HasDRMInVirtualScreen001, TestSize.Level2)
{
    RSSurfaceRenderParams surfaceParams(GenerateNodeId());
    surfaceParams.ancestorScreenDrawable_.reset();

    Drawing::Canvas canvas(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    RSPaintFilterCanvas filterCanvas(&canvas);

    auto result = RSDrmUtil::HasDRMInVirtualScreen(filterCanvas, surfaceParams);
    ASSERT_FALSE(result);
}

/**
 * Function: HasDRMInVirtualScreen
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: params is nullptr
 *                  2. operation: HasDRMInVirtualScreen
 *                  3. result: return false
 */
HWTEST_F(RSDrmUtilTest, HasDRMInVirtualScreen002, TestSize.Level2)
{
    auto screenDrawable = CreateScreenDrawable();
    ASSERT_NE(screenDrawable, nullptr);
    screenDrawable->renderParams_ = nullptr;

    RSSurfaceRenderParams surfaceParams(GenerateNodeId());
    surfaceParams.ancestorScreenDrawable_ = screenDrawable;

    Drawing::Canvas canvas(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    RSPaintFilterCanvas filterCanvas(&canvas);

    auto result = RSDrmUtil::HasDRMInVirtualScreen(filterCanvas, surfaceParams);
    ASSERT_FALSE(result);
}

/**
 * Function: HasDRMInVirtualScreen
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: screen is not virtual
 *                  2. operation: HasDRMInVirtualScreen
 *                  3. result: return false
 */
HWTEST_F(RSDrmUtilTest, HasDRMInVirtualScreen003, TestSize.Level2)
{
    auto screenDrawable = CreateScreenDrawable();
    ASSERT_NE(screenDrawable, nullptr);

    RSSurfaceRenderParams surfaceParams(GenerateNodeId());
    surfaceParams.ancestorScreenDrawable_ = screenDrawable;

    Drawing::Canvas canvas(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    RSPaintFilterCanvas filterCanvas(&canvas);

    auto result = RSDrmUtil::HasDRMInVirtualScreen(filterCanvas, surfaceParams);
    ASSERT_FALSE(result);
}

/**
 * Function: HasDRMInVirtualScreen
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: no protected layer
 *                  2. operation: HasDRMInVirtualScreen
 *                  3. result: return false
 */
HWTEST_F(RSDrmUtilTest, HasDRMInVirtualScreen004, TestSize.Level2)
{
    auto screenDrawable = CreateScreenDrawable();
    ASSERT_NE(screenDrawable, nullptr);

    auto screenParams = static_cast<RSScreenRenderParams*>(screenDrawable->renderParams_.get());
    ASSERT_NE(screenParams, nullptr);
    screenParams->screenProperty_.Set(ScreenPropertyType::IS_VIRTUAL,
        sptr<ScreenPropertyBase>(new ScreenProperty<bool>(true)));

    RSSurfaceRenderParams surfaceParams(GenerateNodeId());
    surfaceParams.ancestorScreenDrawable_ = screenDrawable;

    Drawing::Canvas canvas(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    RSPaintFilterCanvas filterCanvas(&canvas);

    auto result = RSDrmUtil::HasDRMInVirtualScreen(filterCanvas, surfaceParams);
    ASSERT_FALSE(result);
}

/**
 * Function: HasDRMInVirtualScreen
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: virtual screen with protected layer
 *                  2. operation: HasDRMInVirtualScreen
 *                  3. result: return true
 */
HWTEST_F(RSDrmUtilTest, HasDRMInVirtualScreen005, TestSize.Level2)
{
    auto screenDrawable = CreateScreenDrawable();
    ASSERT_NE(screenDrawable, nullptr);

    auto screenParams = static_cast<RSScreenRenderParams*>(screenDrawable->renderParams_.get());
    ASSERT_NE(screenParams, nullptr);
    screenParams->screenProperty_.Set(ScreenPropertyType::IS_VIRTUAL,
        sptr<ScreenPropertyBase>(new ScreenProperty<bool>(true)));

    RSSurfaceRenderParams surfaceParams(GenerateNodeId());
    surfaceParams.ancestorScreenDrawable_ = screenDrawable;
    surfaceParams.specialLayerManager_.Set(SpecialLayerType::PROTECTED, true);

    Drawing::Canvas canvas(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    RSPaintFilterCanvas filterCanvas(&canvas);

    auto result = RSDrmUtil::HasDRMInVirtualScreen(filterCanvas, surfaceParams);
    ASSERT_TRUE(result);
}

/**
 * Function: UpdateDrmCrossNodeConversion
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: drm node on the tree collected under the first level node of the cross node
 *                  2. operation: UpdateDrmCrossNodeConversion
 *                  3. result: the conversion is recorded on the drm node and on its staging params
 */
HWTEST_F(RSDrmUtilTest, UpdateDrmCrossNodeConversion001, TestSize.Level1)
{
    auto crossNode = RSTestUtil::CreateSurfaceNode();
    auto drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(crossNode, nullptr);
    ASSERT_NE(drmNode, nullptr);
    crossNode->firstLevelNodeId_ = crossNode->GetId();
    drmNode->isOnTheTree_ = true;
    drmNode->stagingRenderParams_ = std::make_unique<RSSurfaceRenderParams>(drmNode->GetId());
    RSDrmUtil::ClearDrmNodes();
    RSDrmUtil::drmNodes_[crossNode->GetId()].push_back(drmNode);

    const NodeId screenNodeId = GenerateNodeId();
    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    RSDrmUtil::UpdateDrmCrossNodeConversion(*crossNode, screenNodeId, conversion);

    const auto& nodeMatrices = drmNode->GetCrossNodeLayerConversionMatrices();
    auto nodeIt = nodeMatrices.find(screenNodeId);
    ASSERT_NE(nodeIt, nodeMatrices.end());
    EXPECT_TRUE(nodeIt->second == conversion);
    auto drmParams = static_cast<RSSurfaceRenderParams*>(drmNode->GetStagingRenderParams().get());
    ASSERT_NE(drmParams, nullptr);
    const auto& paramsMatrices = drmParams->GetCrossNodeLayerConversionMatrices();
    auto paramsIt = paramsMatrices.find(screenNodeId);
    ASSERT_NE(paramsIt, paramsMatrices.end());
    EXPECT_TRUE(paramsIt->second == conversion);
    RSDrmUtil::ClearDrmNodes();
}

/**
 * Function: UpdateDrmCrossNodeConversion
 * Type: Function
 * Rank: Important(2)
 * EnvCondition: N/A
 * CaseDescription: 1. preSetup: drm node collected under another first level node, or off the tree
 *                  2. operation: UpdateDrmCrossNodeConversion
 *                  3. result: the drm node is left unchanged
 */
HWTEST_F(RSDrmUtilTest, UpdateDrmCrossNodeConversion002, TestSize.Level1)
{
    auto crossNode = RSTestUtil::CreateSurfaceNode();
    auto otherNode = RSTestUtil::CreateSurfaceNode();
    auto drmNode = RSTestUtil::CreateSurfaceNode();
    auto offTreeDrmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(crossNode, nullptr);
    ASSERT_NE(otherNode, nullptr);
    ASSERT_NE(drmNode, nullptr);
    ASSERT_NE(offTreeDrmNode, nullptr);
    crossNode->firstLevelNodeId_ = crossNode->GetId();
    drmNode->isOnTheTree_ = true;
    offTreeDrmNode->isOnTheTree_ = false;
    RSDrmUtil::ClearDrmNodes();
    RSDrmUtil::drmNodes_[otherNode->GetId()].push_back(drmNode);
    RSDrmUtil::drmNodes_[crossNode->GetId()].push_back(offTreeDrmNode);

    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    RSDrmUtil::UpdateDrmCrossNodeConversion(*crossNode, GenerateNodeId(), conversion);

    EXPECT_TRUE(drmNode->GetCrossNodeLayerConversionMatrices().empty());
    EXPECT_TRUE(offTreeDrmNode->GetCrossNodeLayerConversionMatrices().empty());
    RSDrmUtil::ClearDrmNodes();
}

/**
 * @tc.name: CalcCrossNodeLayerConversion001
 * @tc.desc: Test no conversion is calculated for a cross node without drm node
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, CalcCrossNodeLayerConversion001, TestSize.Level1)
{
    auto crossNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(crossNode, nullptr);
    crossNode->firstLevelNodeId_ = crossNode->GetId();
    auto screenNode = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
    RSDrmUtil::ClearDrmNodes();
    Drawing::Matrix conversion;
    EXPECT_FALSE(RSDrmUtil::CalcCrossNodeLayerConversion(*crossNode, *crossNode, *screenNode, conversion));
}

/**
 * @tc.name: CalcCrossNodeLayerConversion002
 * @tc.desc: Test the conversion is calculated for a cross node with drm node
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, CalcCrossNodeLayerConversion002, TestSize.Level1)
{
    auto crossNode = RSTestUtil::CreateSurfaceNode();
    auto drmNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(crossNode, nullptr);
    ASSERT_NE(drmNode, nullptr);
    crossNode->firstLevelNodeId_ = crossNode->GetId();
    auto screenNode = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
    RSDrmUtil::ClearDrmNodes();
    RSDrmUtil::drmNodes_[crossNode->GetId()].push_back(drmNode);
    // without parents both frames are the frame of the node itself, so the conversion is identity
    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    EXPECT_TRUE(RSDrmUtil::CalcCrossNodeLayerConversion(*crossNode, *crossNode, *screenNode, conversion));
    EXPECT_TRUE(conversion.IsIdentity());
    RSDrmUtil::ClearDrmNodes();
}

/**
 * @tc.name: ConvertCrossNodeLayerInfo001
 * @tc.desc: Test the layer info is left unchanged when no conversion is recorded for the screen
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ConvertCrossNodeLayerInfo001, TestSize.Level1)
{
    RSSurfaceRenderParams params(GenerateNodeId());
    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    const NodeId screenNodeId = GenerateNodeId();
    params.SetCrossNodeLayerConversionMatrix(GenerateNodeId(), conversion);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 3300, 10, 100, 50 };
    EXPECT_FALSE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, screenNodeId, layerInfo));
    EXPECT_EQ(layerInfo.dstRect.x, 3300);
    EXPECT_EQ(layerInfo.dstRect.y, 10);
    EXPECT_TRUE(layerInfo.matrix.IsIdentity());
}

/**
 * @tc.name: ConvertCrossNodeLayerInfo002
 * @tc.desc: Test the dst rect and the matrix are converted with the conversion recorded for the screen
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ConvertCrossNodeLayerInfo002, TestSize.Level1)
{
    RSSurfaceRenderParams params(GenerateNodeId());
    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    const NodeId screenNodeId = GenerateNodeId();
    params.SetCrossNodeLayerConversionMatrix(screenNodeId, conversion);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 3300, 10, 100, 50 };
    EXPECT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, screenNodeId, layerInfo));
    EXPECT_EQ(layerInfo.dstRect.x, 60);
    EXPECT_EQ(layerInfo.dstRect.y, 10);
    EXPECT_EQ(layerInfo.dstRect.w, 100);
    EXPECT_EQ(layerInfo.dstRect.h, 50);
    EXPECT_FLOAT_EQ(layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_X), -CROSS_SCREEN_OFFSET_X);
}

/**
 * @tc.name: ConvertCrossNodeLayerInfo003
 * @tc.desc: Test a dst rect built on the composing screen only loses the offset, while the matrix is converted
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ConvertCrossNodeLayerInfo003, TestSize.Level1)
{
    RSSurfaceRenderParams params(GenerateNodeId());
    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    const NodeId screenNodeId = GenerateNodeId();
    params.SetCrossNodeLayerConversionMatrix(screenNodeId, conversion);
    params.SetLayerDstDisplay(screenNodeId, static_cast<int32_t>(CROSS_SCREEN_OFFSET_X), 0);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 3300, 10, 100, 50 };
    EXPECT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, screenNodeId, layerInfo));
    EXPECT_EQ(layerInfo.dstRect.x, 60);
    EXPECT_EQ(layerInfo.dstRect.y, 10);
    EXPECT_FLOAT_EQ(layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_X), -CROSS_SCREEN_OFFSET_X);
}

/**
 * @tc.name: ConvertCrossNodeLayerInfo004
 * @tc.desc: Test a dst rect built on the display owning the node loses that display offset before the conversion, even
 *           when no conversion is recorded for it
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ConvertCrossNodeLayerInfo004, TestSize.Level1)
{
    RSSurfaceRenderParams params(GenerateNodeId());
    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    const NodeId screenNodeId = GenerateNodeId();
    params.SetCrossNodeLayerConversionMatrix(screenNodeId, conversion);
    // the rect was built on the display owning the node, which records no conversion towards itself
    params.SetLayerDstDisplay(GenerateNodeId(), 0, CROSS_SCREEN_OFFSET_Y);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 3300, CROSS_SCREEN_OFFSET_Y + 10, 100, 50 };
    EXPECT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, screenNodeId, layerInfo));
    EXPECT_EQ(layerInfo.dstRect.x, 60);
    EXPECT_EQ(layerInfo.dstRect.y, 10);
    EXPECT_EQ(layerInfo.dstRect.w, 100);
    EXPECT_EQ(layerInfo.dstRect.h, 50);
    EXPECT_FLOAT_EQ(layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_X), -CROSS_SCREEN_OFFSET_X);
}

/**
 * @tc.name: ConvertCrossNodeLayerInfo005
 * @tc.desc: Test a dst rect built on another display composing the clone is moved back with that conversion first
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ConvertCrossNodeLayerInfo005, TestSize.Level1)
{
    RSSurfaceRenderParams params(GenerateNodeId());
    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    const NodeId screenNodeId = GenerateNodeId();
    params.SetCrossNodeLayerConversionMatrix(screenNodeId, conversion);
    Drawing::Matrix otherConversion;
    otherConversion.Translate(0, -CROSS_SCREEN_OFFSET_Y);
    const NodeId otherDisplayId = GenerateNodeId();
    params.SetCrossNodeLayerConversionMatrix(otherDisplayId, otherConversion);
    params.SetLayerDstDisplay(otherDisplayId, 0, CROSS_SCREEN_OFFSET_Y);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 3300, CROSS_SCREEN_OFFSET_Y + 10, 100, 50 };
    EXPECT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, screenNodeId, layerInfo));
    EXPECT_EQ(layerInfo.dstRect.x, 60);
    EXPECT_EQ(layerInfo.dstRect.y, CROSS_SCREEN_OFFSET_Y + 10);
    EXPECT_EQ(layerInfo.dstRect.w, 100);
    EXPECT_EQ(layerInfo.dstRect.h, 50);
}

/**
 * @tc.name: ApplyCrossNodeLayerConversion001
 * @tc.desc: Test cross node layer conversion with a translate only conversion matrix
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ApplyCrossNodeLayerConversion001, TestSize.Level1)
{
    Drawing::Matrix conversion;
    conversion.PostTranslate(100.0f, 50.0f);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 10, 20, 30, 40 };
    RSDrmUtil::ApplyCrossNodeLayerConversion(conversion, layerInfo);
    EXPECT_EQ(layerInfo.dstRect.x, 110);
    EXPECT_EQ(layerInfo.dstRect.y, 70);
    EXPECT_EQ(layerInfo.dstRect.w, 30);
    EXPECT_EQ(layerInfo.dstRect.h, 40);
    EXPECT_FLOAT_EQ(layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_X), 100.0f);
    EXPECT_FLOAT_EQ(layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_Y), 50.0f);
}

/**
 * @tc.name: ApplyCrossNodeLayerConversion002
 * @tc.desc: Test cross node layer conversion with a rotation conversion matrix
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ApplyCrossNodeLayerConversion002, TestSize.Level1)
{
    // source panel [0, 1080] x [0, 2400] rotated into the target screen frame [0, 2400] x [0, 1080]
    Drawing::Matrix conversion;
    conversion.PreRotate(90.0f);
    conversion.PreTranslate(0.0f, -2400.0f);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 100, 200, 300, 400 };
    RSDrmUtil::ApplyCrossNodeLayerConversion(conversion, layerInfo);
    EXPECT_EQ(layerInfo.dstRect.x, 1800);
    EXPECT_EQ(layerInfo.dstRect.y, 100);
    EXPECT_EQ(layerInfo.dstRect.w, 400);
    EXPECT_EQ(layerInfo.dstRect.h, 300);
    // The target screen layer keeps its own rotation correction instead of falling back to no rotation
    EXPECT_NE(layerInfo.transformType, GraphicTransformType::GRAPHIC_ROTATE_NONE);
}

/**
 * @tc.name: ApplyCrossNodeLayerConversion003
 * @tc.desc: Test the transform type is recalculated from the converted matrix, so an identity matrix drops the rotation
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ApplyCrossNodeLayerConversion003, TestSize.Level1)
{
    Drawing::Matrix conversion;
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 100, 200, 300, 400 };
    layerInfo.transformType = GraphicTransformType::GRAPHIC_ROTATE_270;
    RSDrmUtil::ApplyCrossNodeLayerConversion(conversion, layerInfo);
    EXPECT_EQ(layerInfo.dstRect.x, 100);
    EXPECT_EQ(layerInfo.dstRect.y, 200);
    EXPECT_EQ(layerInfo.dstRect.w, 300);
    EXPECT_EQ(layerInfo.dstRect.h, 400);
    EXPECT_TRUE(layerInfo.matrix.IsIdentity());
    EXPECT_EQ(layerInfo.transformType, GraphicTransformType::GRAPHIC_ROTATE_NONE);
}

/**
 * @tc.name: ApplyCrossNodeLayerConversion004
 * @tc.desc: Test a dst rect already in the frame of the composing screen is kept while the matrix is still converted
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, ApplyCrossNodeLayerConversion004, TestSize.Level1)
{
    Drawing::Matrix conversion;
    conversion.PostTranslate(100.0f, 50.0f);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 10, 20, 30, 40 };
    RSDrmUtil::ApplyCrossNodeLayerConversion(conversion, layerInfo, false);
    EXPECT_EQ(layerInfo.dstRect.x, 10);
    EXPECT_EQ(layerInfo.dstRect.y, 20);
    EXPECT_EQ(layerInfo.dstRect.w, 30);
    EXPECT_EQ(layerInfo.dstRect.h, 40);
    EXPECT_FLOAT_EQ(layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_X), 100.0f);
    EXPECT_FLOAT_EQ(layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_Y), 50.0f);
}

/**
 * @tc.name: RecordDstRectDisplay001
 * @tc.desc: Test the dst rect display is recorded for a drm node only, and is reset when there is none
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, RecordDstRectDisplay001, TestSize.Level1)
{
    auto crossNode = RSTestUtil::CreateSurfaceNode();
    auto drmNode = RSTestUtil::CreateSurfaceNode();
    auto otherNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(crossNode, nullptr);
    ASSERT_NE(drmNode, nullptr);
    ASSERT_NE(otherNode, nullptr);
    crossNode->firstLevelNodeId_ = crossNode->GetId();
    drmNode->firstLevelNodeId_ = crossNode->GetId();
    otherNode->firstLevelNodeId_ = crossNode->GetId();
    auto screenNode = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
    RSDrmUtil::ClearDrmNodes();
    RSDrmUtil::drmNodes_[crossNode->GetId()].push_back(drmNode);

    RSDrmUtil::RecordDstRectDisplay(*drmNode, screenNode);
    EXPECT_EQ(drmNode->GetDstRectDisplayNodeId(), screenNode->GetId());
    // a node that is not a drm node records no display, so it is never treated as a converted layer
    RSDrmUtil::RecordDstRectDisplay(*otherNode, screenNode);
    EXPECT_EQ(otherNode->GetDstRectDisplayNodeId(), INVALID_NODEID);
    // the record does not outlive the composition on another display
    RSDrmUtil::RecordDstRectDisplay(*drmNode, nullptr);
    EXPECT_EQ(drmNode->GetDstRectDisplayNodeId(), INVALID_NODEID);
    RSDrmUtil::ClearDrmNodes();
}

/**
 * @tc.name: CropCrossNodeLayerInfo001
 * @tc.desc: Test the source rect is cropped by the same proportion as the destination rect
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, CropCrossNodeLayerInfo001, TestSize.Level1)
{
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 0, 0, 400, 200 };
    layerInfo.srcRect = { 0, 0, 800, 400 };
    RSDrmUtil::CropCrossNodeLayerInfo(Drawing::Rect(0, 0, 400, 200), Drawing::Rect(0, 0, 300, 1000), layerInfo);
    EXPECT_EQ(layerInfo.dstRect.x, 0);
    EXPECT_EQ(layerInfo.dstRect.y, 0);
    EXPECT_EQ(layerInfo.dstRect.w, 300);
    EXPECT_EQ(layerInfo.dstRect.h, 200);
    EXPECT_EQ(layerInfo.srcRect.x, 0);
    EXPECT_EQ(layerInfo.srcRect.y, 0);
    EXPECT_EQ(layerInfo.srcRect.w, 600);
    EXPECT_EQ(layerInfo.srcRect.h, 400);
}

/**
 * @tc.name: CropCrossNodeLayerInfo002
 * @tc.desc: Test the source rect crop follows the rotation of the layer
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, CropCrossNodeLayerInfo002, TestSize.Level1)
{
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 0, 0, 400, 200 };
    layerInfo.srcRect = { 0, 0, 800, 400 };
    layerInfo.transformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    // the bottom quarter of the destination rect is out of the screen, it maps to the right quarter of the source
    RSDrmUtil::CropCrossNodeLayerInfo(Drawing::Rect(0, 0, 400, 200), Drawing::Rect(0, 0, 1000, 150), layerInfo);
    EXPECT_EQ(layerInfo.dstRect.x, 0);
    EXPECT_EQ(layerInfo.dstRect.y, 0);
    EXPECT_EQ(layerInfo.dstRect.w, 400);
    EXPECT_EQ(layerInfo.dstRect.h, 150);
    EXPECT_EQ(layerInfo.srcRect.x, 0);
    EXPECT_EQ(layerInfo.srcRect.y, 0);
    EXPECT_EQ(layerInfo.srcRect.w, 600);
    EXPECT_EQ(layerInfo.srcRect.h, 400);
}

/**
 * @tc.name: CropCrossNodeLayerInfo003
 * @tc.desc: Test the source rect crop follows the opposite rotation of the layer
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, CropCrossNodeLayerInfo003, TestSize.Level1)
{
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 0, 0, 400, 200 };
    layerInfo.srcRect = { 0, 0, 800, 400 };
    layerInfo.transformType = GraphicTransformType::GRAPHIC_ROTATE_270;
    // the layer matrix [0 1; -1 0] puts the left edge of the source at the bottom of the destination rect, so the
    // cropped bottom quarter maps to the left quarter of the source, as on a screen rotated by 90 degrees
    RSDrmUtil::CropCrossNodeLayerInfo(Drawing::Rect(0, 0, 400, 200), Drawing::Rect(0, 0, 1000, 150), layerInfo);
    EXPECT_EQ(layerInfo.srcRect.x, 200);
    EXPECT_EQ(layerInfo.srcRect.y, 0);
    EXPECT_EQ(layerInfo.srcRect.w, 600);
    EXPECT_EQ(layerInfo.srcRect.h, 400);
}

/**
 * @tc.name: CropCrossNodeLayerInfo004
 * @tc.desc: Test the layer info keeps unchanged when the destination rect is fully inside the screen
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, CropCrossNodeLayerInfo004, TestSize.Level1)
{
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 0, 0, 400, 200 };
    layerInfo.srcRect = { 10, 20, 800, 400 };
    RSDrmUtil::CropCrossNodeLayerInfo(Drawing::Rect(0, 0, 400, 200), Drawing::Rect(0, 0, 1000, 1000), layerInfo);
    EXPECT_EQ(layerInfo.dstRect.x, 0);
    EXPECT_EQ(layerInfo.dstRect.y, 0);
    EXPECT_EQ(layerInfo.dstRect.w, 400);
    EXPECT_EQ(layerInfo.dstRect.h, 200);
    EXPECT_EQ(layerInfo.srcRect.x, 10);
    EXPECT_EQ(layerInfo.srcRect.y, 20);
    EXPECT_EQ(layerInfo.srcRect.w, 800);
    EXPECT_EQ(layerInfo.srcRect.h, 400);
}

/**
 * @tc.name: CropCrossNodeLayerInfo005
 * @tc.desc: Test the layer info keeps unchanged when the destination rect is out of the screen
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSDrmUtilTest, CropCrossNodeLayerInfo005, TestSize.Level1)
{
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 500, 0, 400, 200 };
    layerInfo.srcRect = { 0, 0, 800, 400 };
    RSDrmUtil::CropCrossNodeLayerInfo(Drawing::Rect(500, 0, 900, 200), Drawing::Rect(0, 0, 400, 200), layerInfo);
    EXPECT_EQ(layerInfo.dstRect.x, 500);
    EXPECT_EQ(layerInfo.dstRect.w, 400);
    EXPECT_EQ(layerInfo.srcRect.x, 0);
    EXPECT_EQ(layerInfo.srcRect.w, 800);
    EXPECT_EQ(layerInfo.srcRect.h, 400);
}
}