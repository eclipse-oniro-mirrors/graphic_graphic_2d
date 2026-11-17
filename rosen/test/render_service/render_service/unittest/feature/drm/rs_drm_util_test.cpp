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
#include "common/rs_obj_abs_geometry.h"
#include "composer/composer_client/pipeline/rs_composer_client_manager.h"
#include "drawable/rs_screen_render_node_drawable.h"
#include "pipeline/hwc/rs_uni_hwc_visitor.h"
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
namespace {
struct DrmDragSample {
    float layerX;
    float layerY;
    float prepareX;
    float prepareY;
    int32_t offsetX;
    int32_t offsetY;
    GraphicIRect localDst;
    float targetX;
    float targetY;
    GraphicIRect targetDst;
    GraphicIRect croppedDst;
    GraphicIRect croppedSrc;
};

// 三组设备日志的同帧几何：matrix 为真实父链累计值，dst 已去除旧日志额外叠加的屏幕 offset。
const DrmDragSample DRM_DRAG_SAMPLES[] = {
    { 460, 2, 460, 2, 0, 0, { 844, -1333, 560, 1335 }, -2, 372,
        { -2, 756, 1335, 560 }, { 0, 756, 1333, 560 }, { 2, 0, 1918, 804 } },
    { 1564, 2503, -596, 2628, 125, 2160, { -212, 1293, 560, 1335 }, 793, 1564,
        { 793, 1948, 1335, 560 }, { 793, 1948, 1335, 212 }, { 0, 0, 1920, 305 } },
    { 1032, -410, 1032, 3430, 3840, 0, { 1416, 2095, 560, 1335 }, 3706, 1015,
        { 3706, 1399, 1335, 560 }, { 3706, 1399, 134, 560 }, { 0, 0, 193, 804 } },
};
const GraphicIRect DRM_VIDEO_SRC = { 0, 0, 1920, 804 };
const Drawing::Rect DRM_SECONDARY_SCREEN(0, 0, 3840, 2160);
const Drawing::Rect DRM_PRIMARY_SCREEN(0, 0, 2472, 3296);

Drawing::Matrix MakeDrmLayerMatrix(float x, float y)
{
    Drawing::Matrix matrix;
    matrix.SetMatrix(0, 1, x, -1, 0, y, 0, 0, 1);
    return matrix;
}

void ExpectDrmRect(const GraphicIRect& actual, const GraphicIRect& expected)
{
    EXPECT_EQ(actual.x, expected.x);
    EXPECT_EQ(actual.y, expected.y);
    EXPECT_EQ(actual.w, expected.w);
    EXPECT_EQ(actual.h, expected.h);
}

void CropDrmLayer(const Drawing::Rect& screen, RSLayerInfo& layer)
{
    const auto dst = layer.dstRect;
    RSDrmUtil::CropCrossNodeLayerInfo(Drawing::Rect(dst.x, dst.y, dst.x + dst.w, dst.y + dst.h), screen, layer);
}
} // namespace

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
    std::shared_ptr<RSSurfaceRenderNode> CreateRecordedDrmNode(const Drawing::Matrix& layerMatrix,
        const Drawing::Matrix& prepareMatrix, const std::shared_ptr<RSScreenRenderNode>& screen);
};

void RSDrmUtilTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}
void RSDrmUtilTest::TearDownTestCase() {}
void RSDrmUtilTest::SetUp()
{
    RSDrmUtil::ClearDrmNodes();
}
void RSDrmUtilTest::TearDown()
{
    RSDrmUtil::ClearDrmNodes();
}

std::shared_ptr<RSSurfaceRenderNode> RSDrmUtilTest::CreateRecordedDrmNode(const Drawing::Matrix& layerMatrix,
    const Drawing::Matrix& prepareMatrix, const std::shared_ptr<RSScreenRenderNode>& screen)
{
    auto node = RSTestUtil::CreateSurfaceNode();
    if (node == nullptr) {
        return nullptr;
    }
    node->firstLevelNodeId_ = node->GetId();
    node->isOnTheTree_ = true;
    node->SetHwcGlobalPositionEnabled(true);
    node->GetMutableRenderProperties().GetBoundsGeometry()->ReplaceMatrix(layerMatrix, prepareMatrix);
    RSDrmUtil::drmNodes_[node->GetId()].push_back(node);
    RSDrmUtil::RecordDstRectDisplay(*node, screen);
    return node;
}

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
    const NodeId preparedScreenId = GenerateNodeId();
    params.SetCrossNodeLayerConversionMatrix(preparedScreenId, Drawing::Matrix());
    params.SetLayerDstDisplay(preparedScreenId, 0, 0);
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
 * @tc.desc: 本屏产生的局部 dst 保持不变，matrix 仍需转换到本屏
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
    params.SetLayerDstDisplay(screenNodeId, 0, 0);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 60, 10, 100, 50 };
    EXPECT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, screenNodeId, layerInfo));
    EXPECT_EQ(layerInfo.dstRect.x, 60);
    EXPECT_EQ(layerInfo.dstRect.y, 10);
    EXPECT_FLOAT_EQ(layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_X), -CROSS_SCREEN_OFFSET_X);
}

/**
 * @tc.name: ConvertCrossNodeLayerInfo004
 * @tc.desc: 产生屏未记录转换时不假定 identity，失败时保持局部 dst 和 matrix 不变
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
    // 归属屏也必须提供转换，不能再沿用缺失即 identity 的假设。
    params.SetLayerDstDisplay(GenerateNodeId(), 0, 0);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 3300, 10, 100, 50 };
    const auto originalDst = layerInfo.dstRect;
    EXPECT_FALSE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, screenNodeId, layerInfo));
    ExpectDrmRect(layerInfo.dstRect, originalDst);
    EXPECT_TRUE(layerInfo.matrix.IsIdentity());
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
    params.SetLayerDstDisplay(otherDisplayId, 0, 0);
    RSLayerInfo layerInfo;
    layerInfo.dstRect = { 3300, 10, 100, 50 };
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
    drmNode->SetHwcGlobalPositionEnabled(true);
    otherNode->firstLevelNodeId_ = crossNode->GetId();
    otherNode->SetHwcGlobalPositionEnabled(true);
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

// 记录失效或矩阵不可逆时，dst、src、matrix 和 transform 均不得被部分改写。
HWTEST_F(RSDrmUtilTest, ConvertCrossNodeLayerInfoInvalidRecord, TestSize.Level1)
{
    RSSurfaceRenderParams params(GenerateNodeId());
    const NodeId targetId = GenerateNodeId();
    const NodeId preparedId = GenerateNodeId();
    Drawing::Matrix conversion;
    conversion.Translate(-CROSS_SCREEN_OFFSET_X, 0);
    params.SetCrossNodeLayerConversionMatrix(targetId, conversion);
    RSLayerInfo layer;
    layer.dstRect = DRM_DRAG_SAMPLES[0].localDst;
    layer.srcRect = DRM_VIDEO_SRC;
    layer.matrix = MakeDrmLayerMatrix(1, 1);
    layer.transformType = GraphicTransformType::GRAPHIC_ROTATE_270;
    const auto original = layer;
    EXPECT_FALSE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, targetId, layer));
    Drawing::Matrix singular;
    singular.Scale(0, 1, 0, 0);
    params.SetLayerDstDisplay(preparedId, 0, 0);
    params.SetCrossNodeLayerConversionMatrix(preparedId, singular);
    EXPECT_FALSE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, targetId, layer));
    params.SetCrossNodeLayerConversionMatrix(preparedId, Drawing::Matrix());
    params.SetCrossNodeLayerConversionMatrix(targetId, singular);
    EXPECT_FALSE(RSDrmUtil::ConvertCrossNodeLayerInfo(params, targetId, layer));
    ExpectDrmRect(layer.dstRect, original.dstRect);
    ExpectDrmRect(layer.srcRect, original.srcRect);
    EXPECT_TRUE(layer.matrix == original.matrix);
    EXPECT_EQ(layer.transformType, original.transformType);
}

// prepare 记录清除历史 offset；屏幕 offset 非零和重复调用均不能改写局部 dst。
HWTEST_F(RSDrmUtilTest, PrepareKeepsLocalDst, TestSize.Level1)
{
    auto visitor = std::make_shared<RSUniRenderVisitor>();
    ASSERT_NE(visitor->hwcVisitor_, nullptr);
    for (const auto& sample : DRM_DRAG_SAMPLES) {
        auto screen = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
        RSScreenProperty property;
        property.Set<ScreenPropertyType::OFFSET>({ sample.offsetX, sample.offsetY });
        screen->SetScreenProperty(property);
        visitor->curScreenNode_ = screen;
        const auto raw = MakeDrmLayerMatrix(sample.layerX, sample.layerY);
        auto node = CreateRecordedDrmNode(raw, MakeDrmLayerMatrix(sample.prepareX, sample.prepareY), screen);
        ASSERT_NE(node, nullptr);
        node->SetDstRectDisplay(screen->GetId(), sample.offsetX, sample.offsetY);
        node->SetHwcCrossNode(true);
        const RectI localDst(sample.localDst.x, sample.localDst.y, sample.localDst.w, sample.localDst.h);
        visitor->hwcVisitor_->UpdateDstRect(*node, localDst, localDst);
        visitor->hwcVisitor_->UpdateDstRectByGlobalPosition(*node);
        visitor->hwcVisitor_->UpdateDstRectByGlobalPosition(*node);
        EXPECT_EQ(node->GetDstRect(), localDst);
        EXPECT_EQ(node->GetDstRectDisplayNodeId(), screen->GetId());
        EXPECT_EQ(node->dstRectDisplayOffsetX_, 0);
        EXPECT_EQ(node->dstRectDisplayOffsetY_, 0);
        node->SetHwcGlobalPositionEnabled(false);
        visitor->hwcVisitor_->UpdateDstRectByGlobalPosition(*node);
        EXPECT_EQ(node->GetDstRect(), localDst);
        RSDrmUtil::RecordDstRectDisplay(*node, screen);
        EXPECT_EQ(node->GetDstRectDisplayNodeId(), INVALID_NODEID);
    }
}

// 三组实测数据经真实记录入口进入 staging params，再执行副屏转换与裁剪。
HWTEST_F(RSDrmUtilTest, ConvertCrossNodeLayerInfoDeviceSamples, TestSize.Level1)
{
    for (const auto& sample : DRM_DRAG_SAMPLES) {
        SCOPED_TRACE(sample.offsetX);
        auto screen = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
        const auto raw = MakeDrmLayerMatrix(sample.layerX, sample.layerY);
        auto node = CreateRecordedDrmNode(raw, MakeDrmLayerMatrix(sample.prepareX, sample.prepareY), screen);
        ASSERT_NE(node, nullptr);
        auto params = static_cast<RSSurfaceRenderParams*>(node->GetStagingRenderParams().get());
        ASSERT_NE(params, nullptr);
        ASSERT_EQ(node->GetDstRectDisplayNodeId(), screen->GetId());
        params->SetLayerDstDisplay(node->GetDstRectDisplayNodeId(), 0, 0);
        Drawing::Matrix target;
        target.Translate(sample.targetX, sample.targetY);
        Drawing::Matrix conversion;
        ASSERT_TRUE(raw.Invert(conversion));
        conversion.PostConcat(target);
        const NodeId targetId = GenerateNodeId();
        RSDrmUtil::UpdateDrmCrossNodeConversion(*node, targetId, conversion);
        RSLayerInfo layer;
        layer.matrix = raw;
        layer.dstRect = sample.localDst;
        layer.srcRect = DRM_VIDEO_SRC;
        layer.transformType = GraphicTransformType::GRAPHIC_ROTATE_270;
        params->SetLayerInfo(layer);
        ASSERT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(*params, targetId, layer));
        ExpectDrmRect(layer.dstRect, sample.targetDst);
        EXPECT_TRUE(layer.matrix == target);
        EXPECT_EQ(layer.transformType, GraphicTransformType::GRAPHIC_ROTATE_NONE);
        CropDrmLayer(DRM_SECONDARY_SCREEN, layer);
        ExpectDrmRect(layer.dstRect, sample.croppedDst);
        ExpectDrmRect(layer.srcRect, sample.croppedSrc);
        ExpectDrmRect(params->GetLayerInfo().dstRect, sample.localDst);
        EXPECT_TRUE(params->GetLayerInfo().matrix == raw);
    }
}

// 没有 clone 的主屏同样应命中转换，matrix 消除旋转后的 offset，局部 dst 保持不变。
HWTEST_F(RSDrmUtilTest, RecordDstRectDisplayPrimaryWithoutClone, TestSize.Level1)
{
    for (const auto& sample : DRM_DRAG_SAMPLES) {
        auto screen = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
        const auto raw = MakeDrmLayerMatrix(sample.layerX, sample.layerY);
        const auto prepare = MakeDrmLayerMatrix(sample.prepareX, sample.prepareY);
        auto node = CreateRecordedDrmNode(raw, prepare, screen);
        ASSERT_NE(node, nullptr);
        auto params = static_cast<RSSurfaceRenderParams*>(node->GetStagingRenderParams().get());
        ASSERT_NE(params, nullptr);
        params->SetLayerDstDisplay(node->GetDstRectDisplayNodeId(), 0, 0);
        RSLayerInfo layer;
        layer.matrix = raw;
        layer.dstRect = sample.localDst;
        layer.srcRect = DRM_VIDEO_SRC;
        ASSERT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(*params, screen->GetId(), layer));
        EXPECT_TRUE(layer.matrix == prepare);
        ExpectDrmRect(layer.dstRect, sample.localDst);
        EXPECT_EQ(layer.transformType, GraphicTransformType::GRAPHIC_ROTATE_270);
    }
}

// 产生屏先后变化时，同一帧的主副屏转换使用同一个真实父链基准，不依赖哪一屏最后 prepare。
HWTEST_F(RSDrmUtilTest, RecordDstRectDisplayPrepareOrder, TestSize.Level1)
{
    const auto& sample = DRM_DRAG_SAMPLES[1];
    auto primary = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
    auto secondary = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
    const auto raw = MakeDrmLayerMatrix(sample.layerX, sample.layerY);
    const auto primaryMatrix = MakeDrmLayerMatrix(sample.prepareX, sample.prepareY);
    Drawing::Matrix secondaryMatrix;
    secondaryMatrix.Translate(sample.targetX, sample.targetY);
    auto node = CreateRecordedDrmNode(raw, primaryMatrix, primary);
    ASSERT_NE(node, nullptr);
    auto params = static_cast<RSSurfaceRenderParams*>(node->GetStagingRenderParams().get());
    ASSERT_NE(params, nullptr);
    for (const bool preparePrimary : { false, true }) {
        auto screen = preparePrimary ? primary : secondary;
        node->ClearCrossNodeLayerConversionMatrices();
        params->crossNodeLayerConversionMatrices_.clear();
        node->GetMutableRenderProperties().GetBoundsGeometry()->SetAbsMatrix(
            preparePrimary ? primaryMatrix : secondaryMatrix);
        RSDrmUtil::RecordDstRectDisplay(*node, screen);
        Drawing::Matrix skippedConversion;
        ASSERT_TRUE(raw.Invert(skippedConversion));
        skippedConversion.PostConcat(preparePrimary ? secondaryMatrix : primaryMatrix);
        RSDrmUtil::UpdateDrmCrossNodeConversion(*node, (preparePrimary ? secondary : primary)->GetId(),
            skippedConversion);
        params->SetLayerDstDisplay(node->GetDstRectDisplayNodeId(), 0, 0);
        RSLayerInfo original;
        original.matrix = raw;
        original.dstRect = preparePrimary ? sample.localDst : sample.targetDst;
        for (const auto& target : { primary, secondary }) {
            auto layer = original;
            ASSERT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(*params, target->GetId(), layer));
            EXPECT_TRUE(layer.matrix == (target == primary ? primaryMatrix : secondaryMatrix));
            ExpectDrmRect(layer.dstRect, target == primary ? sample.localDst : sample.targetDst);
        }
    }
}

// 旋转和双轴 offset 必须通过矩阵换算，不能按某一种布局交换或硬编码 x/y。
HWTEST_F(RSDrmUtilTest, RecordDstRectDisplayQuarterTurns, TestSize.Level1)
{
    const float rotations[] = { RS_ROTATION_0, RS_ROTATION_90, RS_ROTATION_180, RS_ROTATION_270 };
    const Drawing::Point offsets[] = { { 0, 0 }, { 125, 2160 }, { 3840, 17 }, { -3840, -17 } };
    const GraphicIRect localDst = { 567, 789, 560, 1335 };
    constexpr float LAYER_X = 467;
    constexpr float LAYER_Y = 733;
    for (const auto rotation : rotations) {
        for (const auto& offset : offsets) {
            Drawing::Matrix raw;
            raw.PreRotate(rotation);
            raw.PostTranslate(LAYER_X, LAYER_Y);
            auto prepare = raw;
            prepare.PostTranslate(-raw.Get(Drawing::Matrix::SCALE_X) * offset.GetX() -
                raw.Get(Drawing::Matrix::SKEW_X) * offset.GetY(),
                -raw.Get(Drawing::Matrix::SKEW_Y) * offset.GetX() -
                raw.Get(Drawing::Matrix::SCALE_Y) * offset.GetY());
            auto screen = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
            auto node = CreateRecordedDrmNode(raw, prepare, screen);
            ASSERT_NE(node, nullptr);
            auto params = static_cast<RSSurfaceRenderParams*>(node->GetStagingRenderParams().get());
            ASSERT_NE(params, nullptr);
            params->SetLayerDstDisplay(node->GetDstRectDisplayNodeId(), 0, 0);
            RSLayerInfo layer;
            layer.matrix = raw;
            layer.dstRect = localDst;
            ASSERT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(*params, screen->GetId(), layer));
            EXPECT_TRUE(layer.matrix == prepare);
            ExpectDrmRect(layer.dstRect, localDst);
        }
    }
}

// 深层 DRM 节点不能使用父节点已被另一屏 prepare 改写的 AbsMatrix 作为 layer 的原始坐标系。
HWTEST_F(RSDrmUtilTest, RecordDstRectDisplayRealParentChain, TestSize.Level1)
{
    auto screen = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
    auto parent = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(parent, nullptr);
    const Drawing::Point childPosition(20, 30);
    const Drawing::Point parentPosition(40, 50);
    const Drawing::Point stalePosition(-700, 800);
    Drawing::Matrix local;
    local.Translate(childPosition.GetX(), childPosition.GetY());
    Drawing::Matrix parentLocal;
    parentLocal.Translate(parentPosition.GetX(), parentPosition.GetY());
    Drawing::Matrix staleParent;
    staleParent.Translate(stalePosition.GetX(), stalePosition.GetY());
    const auto screenMatrix = MakeDrmLayerMatrix(0, DRM_PRIMARY_SCREEN.GetHeight());
    screen->GetMutableRenderProperties().GetBoundsGeometry()->ReplaceMatrix(screenMatrix, screenMatrix);
    parent->GetMutableRenderProperties().GetBoundsGeometry()->ReplaceMatrix(parentLocal, staleParent);
    parent->parent_ = screen;
    auto raw = local;
    raw.PostConcat(parentLocal);
    raw.PostConcat(screenMatrix);
    auto prepare = raw;
    prepare.PostTranslate(-DRM_DRAG_SAMPLES[1].offsetY, DRM_DRAG_SAMPLES[1].offsetX);
    auto node = CreateRecordedDrmNode(local, prepare, screen);
    ASSERT_NE(node, nullptr);
    node->parent_ = parent;
    RSDrmUtil::RecordDstRectDisplay(*node, screen);
    auto params = static_cast<RSSurfaceRenderParams*>(node->GetStagingRenderParams().get());
    ASSERT_NE(params, nullptr);
    params->SetLayerDstDisplay(node->GetDstRectDisplayNodeId(), 0, 0);
    RSLayerInfo layer;
    layer.matrix = raw;
    layer.dstRect = DRM_DRAG_SAMPLES[0].localDst;
    ASSERT_TRUE(RSDrmUtil::ConvertCrossNodeLayerInfo(*params, screen->GetId(), layer));
    EXPECT_TRUE(layer.matrix == prepare);
    Drawing::Matrix conversion;
    ASSERT_TRUE(RSDrmUtil::CalcCrossNodeLayerConversion(*node, *node, *screen, conversion));
    auto cloneMatrix = local;
    cloneMatrix.PostConcat(staleParent);
    raw.PostConcat(conversion);
    EXPECT_TRUE(raw == cloneMatrix);
}

HWTEST_F(RSDrmUtilTest, RecordDstRectDisplayDisabledOrSingular, TestSize.Level1)
{
    const auto& sample = DRM_DRAG_SAMPLES[0];
    auto screen = std::make_shared<RSScreenRenderNode>(GenerateNodeId(), GenerateScreenId());
    const auto raw = MakeDrmLayerMatrix(sample.layerX, sample.layerY);
    auto node = CreateRecordedDrmNode(raw, raw, screen);
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->GetDstRectDisplayNodeId(), screen->GetId());
    node->SetHwcGlobalPositionEnabled(false);
    RSDrmUtil::RecordDstRectDisplay(*node, screen);
    EXPECT_EQ(node->GetDstRectDisplayNodeId(), INVALID_NODEID);
    node->SetHwcGlobalPositionEnabled(true);
    Drawing::Matrix singular;
    singular.Scale(0, 1, 0, 0);
    node->GetMutableRenderProperties().GetBoundsGeometry()->SetAbsMatrix(singular);
    RSDrmUtil::RecordDstRectDisplay(*node, screen);
    EXPECT_EQ(node->GetDstRectDisplayNodeId(), INVALID_NODEID);
    node->GetMutableRenderProperties().GetBoundsGeometry()->ReplaceMatrix(singular, raw);
    RSDrmUtil::RecordDstRectDisplay(*node, screen);
    EXPECT_EQ(node->GetDstRectDisplayNodeId(), INVALID_NODEID);
}

HWTEST_F(RSDrmUtilTest, CropCrossNodeLayerInfoQuarterTurns, TestSize.Level1)
{
    const GraphicIRect dst = { -100, -50, 400, 200 };
    const GraphicIRect src = { 0, 0, 800, 400 };
    const GraphicIRect expectedDst = { 0, 0, 300, 150 };
    const GraphicTransformType transforms[] = { GraphicTransformType::GRAPHIC_ROTATE_NONE,
        GraphicTransformType::GRAPHIC_ROTATE_90, GraphicTransformType::GRAPHIC_ROTATE_180,
        GraphicTransformType::GRAPHIC_ROTATE_270 };
    const GraphicIRect expectedSources[] = { { 200, 100, 600, 300 }, { 200, 0, 600, 300 },
        { 0, 0, 600, 300 }, { 0, 100, 600, 300 } };
    size_t index = 0;
    for (const auto transform : transforms) {
        RSLayerInfo layer;
        layer.dstRect = dst;
        layer.srcRect = src;
        layer.transformType = transform;
        CropDrmLayer(DRM_PRIMARY_SCREEN, layer);
        ExpectDrmRect(layer.dstRect, expectedDst);
        ExpectDrmRect(layer.srcRect, expectedSources[index++]);
    }
}

// 问题 1：刚越过边界和仅剩 2 像素时，不能继续把完整的 1920 像素源宽缩放进裁剪后的 dst。
HWTEST_F(RSDrmUtilTest, CropCrossNodeLayerInfoPrimaryCompression, TestSize.Level1)
{
    const GraphicIRect destinations[] = { { 919, -9, 560, 1335 }, { 844, -1333, 560, 1335 } };
    const GraphicIRect expectedSources[] = { { 0, 0, 1908, 804 }, { 0, 0, 3, 804 } };
    size_t index = 0;
    for (const auto& dst : destinations) {
        RSLayerInfo layer;
        layer.dstRect = dst;
        layer.srcRect = DRM_VIDEO_SRC;
        layer.transformType = GraphicTransformType::GRAPHIC_ROTATE_270;
        CropDrmLayer(DRM_PRIMARY_SCREEN, layer);
        ExpectDrmRect(layer.dstRect, { dst.x, 0, dst.w, dst.y + dst.h });
        ExpectDrmRect(layer.srcRect, expectedSources[index++]);
    }
}
}