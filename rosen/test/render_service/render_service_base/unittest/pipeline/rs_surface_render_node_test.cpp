/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "pipeline/rs_context.h"
#include "pipeline/rs_surface_render_node.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSSurfaceRenderNodeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static inline NodeId id;
    static inline std::weak_ptr<RSContext> context = {};
    static inline RSPaintFilterCanvas* canvas_;
    static inline Drawing::Canvas drawingCanvas_;
};

void RSSurfaceRenderNodeTest::SetUpTestCase()
{
    canvas_ = new RSPaintFilterCanvas(&drawingCanvas_);
}
void RSSurfaceRenderNodeTest::TearDownTestCase()
{
    delete canvas_;
    canvas_ = nullptr;
}
void RSSurfaceRenderNodeTest::SetUp() {}
void RSSurfaceRenderNodeTest::TearDown() {}

/**
 * @tc.name: SetContextMatrix001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetContextMatrix001, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    Drawing::Matrix matrix;
    bool sendMsg = false;
    surfaceRenderNode.SetContextMatrix(matrix, sendMsg);
}

/**
 * @tc.name: SetContextClipRegion001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetContextClipRegion001, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    Drawing::Rect clipRegion { 0, 0, 0, 0 };
    bool sendMsg = false;
    surfaceRenderNode.SetContextClipRegion(clipRegion, sendMsg);
}

/**
 * @tc.name: ConnectToNodeInRenderService001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, ConnectToNodeInRenderService001, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    surfaceRenderNode.ConnectToNodeInRenderService();
}

/**
 * @tc.name: ClearChildrenCache001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, ClearChildrenCache001, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    surfaceRenderNode.ResetParent();
}

/**
 * @tc.name: SetVisibleDirtyRegion
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I68IPR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetVisibleDirtyRegion, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    Occlusion::Rect rect {0, 0, 200, 200};
    Occlusion::Region region {rect};
    surfaceRenderNode.SetVisibleDirtyRegion(region);
    auto vdRegion = surfaceRenderNode.GetVisibleDirtyRegion();
}

/**
 * @tc.name: SetAlignedVisibleDirtyRegion
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I68IPR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetAlignedVisibleDirtyRegion, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    Occlusion::Rect rect {0, 0, 256, 256};
    Occlusion::Region region {rect};
    surfaceRenderNode.SetAlignedVisibleDirtyRegion(region);
    auto vdRegion = surfaceRenderNode.GetAlignedVisibleDirtyRegion();
}

/**
 * @tc.name: SetDirtyRegionBelowCurrentLayer
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I68IPR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetDirtyRegionBelowCurrentLayer, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    Occlusion::Rect rect {0, 0, 256, 256};
    Occlusion::Region region {rect};
    surfaceRenderNode.SetDirtyRegionBelowCurrentLayer(region);
    auto vdRegion = surfaceRenderNode.GetDirtyRegionBelowCurrentLayer();
}

/**
 * @tc.name: SetGlobalDirtyRegion
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I68IPR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetGlobalDirtyRegion, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    RectI rect {0, 0, 256, 256};
    surfaceRenderNode.SetGlobalDirtyRegion(rect);
}

/**
 * @tc.name: ResetSurfaceOpaqueRegion02
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I6HF6Y
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetSurfaceOpaqueRegion02, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    RectI screenRect {0, 0, 2560, 1600};
    RectI absRect {0, 100, 400, 500};
    surfaceRenderNode.SetAbilityBGAlpha(0);
    Vector4f cornerRadius;
    Vector4f::Max(
        surfaceRenderNode.GetWindowCornerRadius(), surfaceRenderNode.GetGlobalCornerRadius(), cornerRadius);
    Vector4<int> dstCornerRadius(static_cast<int>(std::ceil(cornerRadius.x_)),
                                 static_cast<int>(std::ceil(cornerRadius.y_)),
                                 static_cast<int>(std::ceil(cornerRadius.z_)),
                                 static_cast<int>(std::ceil(cornerRadius.w_)));
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_0, false, dstCornerRadius);
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_0, true, dstCornerRadius);
}

/**
 * @tc.name: ResetSurfaceOpaqueRegion03
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I6HF6Y
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetSurfaceOpaqueRegion03, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    RectI screenRect {0, 0, 2560, 1600};
    RectI absRect {0, 100, 400, 500};
    surfaceRenderNode.SetAbilityBGAlpha(255);
    surfaceRenderNode.SetGlobalAlpha(1.0f);
    surfaceRenderNode.SetSurfaceNodeType(RSSurfaceNodeType::APP_WINDOW_NODE);
    surfaceRenderNode.SetContainerWindow(true, 1.0f);
    Vector4f cornerRadius;
    Vector4f::Max(
        surfaceRenderNode.GetWindowCornerRadius(), surfaceRenderNode.GetGlobalCornerRadius(), cornerRadius);
    Vector4<int> dstCornerRadius(static_cast<int>(std::ceil(cornerRadius.x_)),
                                 static_cast<int>(std::ceil(cornerRadius.y_)),
                                 static_cast<int>(std::ceil(cornerRadius.z_)),
                                 static_cast<int>(std::ceil(cornerRadius.w_)));
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_0, false, dstCornerRadius);
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_0, true, dstCornerRadius);
}

/**
 * @tc.name: ResetSurfaceOpaqueRegion04
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I6HF6Y
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetSurfaceOpaqueRegion04, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    RectI screenRect {0, 0, 2560, 1600};
    RectI absRect {0, 100, 400, 500};
    surfaceRenderNode.SetAbilityBGAlpha(255);
    surfaceRenderNode.SetGlobalAlpha(1.0f);
    surfaceRenderNode.GetMutableRenderProperties().SetCornerRadius(Vector4f(15.0f));
    Vector4f cornerRadius;
    Vector4f::Max(
        surfaceRenderNode.GetWindowCornerRadius(), surfaceRenderNode.GetGlobalCornerRadius(), cornerRadius);
    Vector4<int> dstCornerRadius(static_cast<int>(std::ceil(cornerRadius.x_)),
                                 static_cast<int>(std::ceil(cornerRadius.y_)),
                                 static_cast<int>(std::ceil(cornerRadius.z_)),
                                 static_cast<int>(std::ceil(cornerRadius.w_)));
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_0, false, dstCornerRadius);
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_0, true, dstCornerRadius);
}

/**
 * @tc.name: ResetSurfaceOpaqueRegion05
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I6HF6Y
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetSurfaceOpaqueRegion05, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    RectI screenRect {0, 0, 2560, 1600};
    RectI absRect {0, 100, 400, 500};
    surfaceRenderNode.SetAbilityBGAlpha(255);
    surfaceRenderNode.SetGlobalAlpha(1.0f);
    surfaceRenderNode.SetSurfaceNodeType(RSSurfaceNodeType::APP_WINDOW_NODE);
    surfaceRenderNode.SetContainerWindow(true, 1.0f);
    Vector4f cornerRadius;
    Vector4f::Max(
        surfaceRenderNode.GetWindowCornerRadius(), surfaceRenderNode.GetGlobalCornerRadius(), cornerRadius);
    Vector4<int> dstCornerRadius(static_cast<int>(std::ceil(cornerRadius.x_)),
                                 static_cast<int>(std::ceil(cornerRadius.y_)),
                                 static_cast<int>(std::ceil(cornerRadius.z_)),
                                 static_cast<int>(std::ceil(cornerRadius.w_)));
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_90, false, dstCornerRadius);
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_90, true, dstCornerRadius);
}

/**
 * @tc.name: ResetSurfaceOpaqueRegion06
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I6HF6Y
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetSurfaceOpaqueRegion06, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    RectI screenRect {0, 0, 2560, 1600};
    RectI absRect {0, 100, 400, 500};
    surfaceRenderNode.SetAbilityBGAlpha(255);
    surfaceRenderNode.SetGlobalAlpha(1.0f);
    surfaceRenderNode.SetSurfaceNodeType(RSSurfaceNodeType::APP_WINDOW_NODE);
    surfaceRenderNode.SetContainerWindow(true, 1.0f);
    Vector4f cornerRadius;
    Vector4f::Max(
        surfaceRenderNode.GetWindowCornerRadius(), surfaceRenderNode.GetGlobalCornerRadius(), cornerRadius);
    Vector4<int> dstCornerRadius(static_cast<int>(std::ceil(cornerRadius.x_)),
                                 static_cast<int>(std::ceil(cornerRadius.y_)),
                                 static_cast<int>(std::ceil(cornerRadius.z_)),
                                 static_cast<int>(std::ceil(cornerRadius.w_)));
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_180, false, dstCornerRadius);
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_180, true, dstCornerRadius);
}

/**
 * @tc.name: ResetSurfaceOpaqueRegion07
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: I6HF6Y
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetSurfaceOpaqueRegion07, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    RectI screenRect {0, 0, 2560, 1600};
    RectI absRect {0, 100, 400, 500};
    surfaceRenderNode.SetAbilityBGAlpha(255);
    surfaceRenderNode.SetGlobalAlpha(1.0f);
    surfaceRenderNode.SetSurfaceNodeType(RSSurfaceNodeType::APP_WINDOW_NODE);
    surfaceRenderNode.SetContainerWindow(true, 1.0f);
    Vector4f cornerRadius;
    Vector4f::Max(
        surfaceRenderNode.GetWindowCornerRadius(), surfaceRenderNode.GetGlobalCornerRadius(), cornerRadius);
    Vector4<int> dstCornerRadius(static_cast<int>(std::ceil(cornerRadius.x_)),
                                 static_cast<int>(std::ceil(cornerRadius.y_)),
                                 static_cast<int>(std::ceil(cornerRadius.z_)),
                                 static_cast<int>(std::ceil(cornerRadius.w_)));
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_270, false, dstCornerRadius);
    surfaceRenderNode.ResetSurfaceOpaqueRegion(
        screenRect, absRect, ScreenRotation::ROTATION_270, true, dstCornerRadius);
}

/**
 * @tc.name: SetNodeCostTest
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: issueI6FZHQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetNodeCostTest, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    auto result = surfaceRenderNode.nodeCost_;
    ASSERT_EQ(0, result);
    surfaceRenderNode.SetNodeCost(6);
    result = surfaceRenderNode.nodeCost_;
    ASSERT_EQ(6, result);
}

/**
 * @tc.name: GetNodeCostTest
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require: issueI6FZHQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetNodeCostTest, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    auto result = surfaceRenderNode.nodeCost_;
    ASSERT_EQ(0, result);
    surfaceRenderNode.SetNodeCost(6);
    result = surfaceRenderNode.GetNodeCost();
    ASSERT_EQ(6, result);
}

/**
 * @tc.name: Fingerprint Test
 * @tc.desc: SetFingerprint and GetFingerprint
 * @tc.type:FUNC
 * @tc.require: issueI6Z3YK
 */
HWTEST_F(RSSurfaceRenderNodeTest, FingerprintTest, TestSize.Level1)
{
    RSSurfaceRenderNode surfaceRenderNode(id, context);
    surfaceRenderNode.SetFingerprint(true);
    auto result = surfaceRenderNode.GetFingerprint();
    ASSERT_EQ(true, result);
    surfaceRenderNode.SetFingerprint(false);
    result = surfaceRenderNode.GetFingerprint();
    ASSERT_EQ(false, result);
}

/**
 * @tc.name: ShouldPrepareSubnodesTest
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, ShouldPrepareSubnodesTest, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->ShouldPrepareSubnodes();
    ASSERT_TRUE(node->ShouldPrepareSubnodes());
}

/**
 * @tc.name: CollectSurfaceTest001
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, CollectSurfaceTest001, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    std::shared_ptr<RSBaseRenderNode> rsBaseRenderNode;
    std::vector<RSBaseRenderNode::SharedPtr> vec;
    bool isUniRender = true;
    node->nodeType_ = RSSurfaceNodeType::STARTING_WINDOW_NODE;
    node->CollectSurface(rsBaseRenderNode, vec, isUniRender, false);
    ASSERT_FALSE(vec.empty());
}

/**
 * @tc.name: CollectSurfaceTest
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, CollectSurfaceTest002, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    std::shared_ptr<RSBaseRenderNode> rsBaseRenderNode;
    std::vector<RSBaseRenderNode::SharedPtr> vec;
    bool isUniRender = true;
    node->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    node->CollectSurface(rsBaseRenderNode, vec, isUniRender, true);
    ASSERT_FALSE(vec.empty());
}

/**
 * @tc.name: ProcessAnimatePropertyBeforeChildrenTest
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, ProcessAnimatePropertyBeforeChildrenTest, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->ProcessAnimatePropertyBeforeChildren(*canvas_, true);
}

/**
 * @tc.name: ProcessAnimatePropertyAfterChildrenTest
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, ProcessAnimatePropertyAfterChildrenTest, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->ProcessAnimatePropertyAfterChildren(*canvas_);
}

/**
 * @tc.name: SetContextMatrixTest
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetContextMatrixTest, TestSize.Level1)
{
    std::optional<Drawing::Matrix> matrix;
    bool sendMsg = false;
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->SetContextMatrix(matrix, sendMsg);
}

/**
 * @tc.name: RegisterBufferAvailableListenerTest
 * @tc.desc: function test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, RegisterBufferAvailableListenerTest, TestSize.Level1)
{
    sptr<RSIBufferAvailableCallback> callback;
    bool isFromRenderThread = true;
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->RegisterBufferAvailableListener(callback, isFromRenderThread);
}

/**
 * @tc.name: SetBootAnimationTest
 * @tc.desc: SetBootAnimation and GetBootAnimation
 * @tc.type:FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetBootAnimationTest, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->SetBootAnimation(true);
    ASSERT_EQ(node->GetBootAnimation(), true);
    node->SetBootAnimation(false);
    ASSERT_FALSE(node->GetBootAnimation());
}

/**
 * @tc.name: AncestorDisplayNodeTest
 * @tc.desc: SetAncestorDisplayNode and GetAncestorDisplayNode
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeTest, AncestorDisplayNodeTest, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto displayNode = std::make_shared<RSBaseRenderNode>(0, context);
    node->SetAncestorDisplayNode(displayNode);
    ASSERT_EQ(node->GetAncestorDisplayNode().lock(), displayNode);
}

/**
 * @tc.name: UpdateSurfaceCacheContentStatic
 * @tc.desc: Set dirty subnode and check if surfacenode static
 * @tc.type:FUNC
 * @tc.require:I8W7ZS
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateSurfaceCacheContentStatic, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    subnode->isContentDirty_ = true;
    std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>> activeNodeIds = {{subnode->GetId(), subnode}};
    node->UpdateSurfaceCacheContentStatic(activeNodeIds);
    ASSERT_EQ(node->GetSurfaceCacheContentStatic(), false);
    ASSERT_EQ(node->IsContentDirtyNodeLimited(), true);
}

/**
 * @tc.name: SubNodeNeedDraw001
 * @tc.desc: check if subnode need draw when PartialRenderType is SET_DAMAGE_AND_DROP_OP，global dirty
 * @tc.type: FUNC
 * @tc.require: I999FR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SubNodeNeedDraw001, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    PartialRenderType partialRenderType = PartialRenderType::SET_DAMAGE_AND_DROP_OP;
    RectI rect = RectI(0, 0, 100, 100);
    subnode->oldDirtyInSurface_ = rect;
    node->visibleRegion_ = Occlusion::Region(rect);
    node->SetGlobalDirtyRegion(rect);
    bool needDraw = node->SubNodeNeedDraw(subnode->GetOldDirtyInSurface(), partialRenderType);
    ASSERT_EQ(needDraw, true);
}

/**
 * @tc.name: SubNodeNeedDraw002
 * @tc.desc: check if subnode need draw when PartialRenderType is SET_DAMAGE_AND_DROP_OP，visible dirty
 * @tc.type: FUNC
 * @tc.require: I999FR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SubNodeNeedDraw002, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    PartialRenderType partialRenderType = PartialRenderType::SET_DAMAGE_AND_DROP_OP;
    RectI rect = RectI(0, 0, 100, 100);
    subnode->oldDirtyInSurface_ = rect;
    node->SetVisibleDirtyRegion(Occlusion::Region(rect));
    bool needDraw = node->SubNodeNeedDraw(subnode->GetOldDirtyInSurface(), partialRenderType);
    ASSERT_EQ(needDraw, true);
}

/**
 * @tc.name: SubNodeNeedDraw003
 * @tc.desc: check if subnode need draw when PartialRenderType is SET_DAMAGE_AND_DROP_OP，transparent
 * @tc.type: FUNC
 * @tc.require: I999FR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SubNodeNeedDraw003, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    PartialRenderType partialRenderType = PartialRenderType::SET_DAMAGE_AND_DROP_OP;
    RectI rect = RectI(0, 0, 100, 100);
    subnode->oldDirtyInSurface_ = rect;
    node->oldDirtyInSurface_ = rect;
    node->SetGlobalAlpha(0.0f);
    Occlusion::Region region = Occlusion::Region(rect);
    node->SetDirtyRegionBelowCurrentLayer(region);
    bool needDraw = node->SubNodeNeedDraw(subnode->GetOldDirtyInSurface(), partialRenderType);
    ASSERT_EQ(needDraw, true);
}

/**
 * @tc.name: SubNodeNeedDraw004
 * @tc.desc: check if subnode need draw when PartialRenderType is SET_DAMAGE_AND_DROP_OP_OCCLUSION
 * @tc.type: FUNC
 * @tc.require: I999FR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SubNodeNeedDraw004, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    PartialRenderType partialRenderType = PartialRenderType::SET_DAMAGE_AND_DROP_OP_OCCLUSION;
    RectI rect = RectI(0, 0, 100, 100);
    subnode->oldDirtyInSurface_ = rect;
    node->visibleRegion_ = Occlusion::Region(rect);
    bool needDraw = node->SubNodeNeedDraw(subnode->GetOldDirtyInSurface(), partialRenderType);
    ASSERT_EQ(needDraw, true);
}

/**
 * @tc.name: SubNodeNeedDraw005
 * @tc.desc: check if subnode need draw when PartialRenderType is SET_DAMAGE_AND_DROP_OP_NOT_VISIBLEDIRTY
 * @tc.type: FUNC
 * @tc.require: I999FR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SubNodeNeedDraw005, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    PartialRenderType partialRenderType = PartialRenderType::SET_DAMAGE_AND_DROP_OP_NOT_VISIBLEDIRTY;
    RectI rect = RectI(0, 0, 100, 100);
    subnode->oldDirtyInSurface_ = rect;
    bool needDraw = node->SubNodeNeedDraw(subnode->GetOldDirtyInSurface(), partialRenderType);
    // Do not have any visible region
    ASSERT_EQ(needDraw, false);
}

/**
 * @tc.name: SubNodeNeedDraw006
 * @tc.desc: check if subnode need draw when PartialRenderType is SET_DAMAGE_AND_DROP_OP_NOT_VISIBLEDIRTY
 * @tc.type: FUNC
 * @tc.require: I999FR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SubNodeNeedDraw006, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    PartialRenderType partialRenderType = PartialRenderType::SET_DAMAGE_AND_DROP_OP_NOT_VISIBLEDIRTY;
    RectI rect = RectI(0, 0, 100, 100);
    subnode->oldDirtyInSurface_ = rect;
    node->oldDirtyInSurface_ = rect;
    Occlusion::Region region = Occlusion::Region(rect);
    node->visibleRegion_ = region;
    node->transparentRegion_ = region;
    node->SetDirtyRegionBelowCurrentLayer(region);
    bool needDraw = node->SubNodeNeedDraw(subnode->GetOldDirtyInSurface(), partialRenderType);
    ASSERT_EQ(needDraw, true);
}

/**
 * @tc.name: SubNodeNeedDraw007
 * @tc.desc: check if subnode need draw when PartialRenderType is DISABLED
 * @tc.type: FUNC
 * @tc.require: I999FR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SubNodeNeedDraw007, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    PartialRenderType partialRenderType = PartialRenderType::DISABLED;
    bool needDraw = node->SubNodeNeedDraw(subnode->GetOldDirtyInSurface(), partialRenderType);
    ASSERT_EQ(needDraw, true);
}

/**
 * @tc.name: SubNodeNeedDraw008
 * @tc.desc: check if subnode need draw when PartialRenderType is SET_DAMAGE
 * @tc.type: FUNC
 * @tc.require: I999FR
 */
HWTEST_F(RSSurfaceRenderNodeTest, SubNodeNeedDraw008, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    PartialRenderType partialRenderType = PartialRenderType::SET_DAMAGE;
    bool needDraw = node->SubNodeNeedDraw(subnode->GetOldDirtyInSurface(), partialRenderType);
    ASSERT_EQ(needDraw, true);
}

/**
 * @tc.name: IsContentDirtyNodeLimited
 * @tc.desc: Set content dirty subnode new on the tree and check if it is in count
 * @tc.type:FUNC
 * @tc.require:I8XIJH
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsContentDirtyNodeLimited, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto subnode = std::make_shared<RSRenderNode>(id + 1, context);
    if (node == nullptr || subnode == nullptr) {
        return;
    }
    node->AddChild(subnode, 0);
    subnode->isContentDirty_ = true;
    subnode->isNewOnTree_ = true;
    std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>> activeNodeIds = {{subnode->GetId(), subnode}};
    node->UpdateSurfaceCacheContentStatic(activeNodeIds);
    ASSERT_EQ(node->IsContentDirtyNodeLimited(), false);
}

/**
 * @tc.name: SetSkipLayer001
 * @tc.desc: Test SetSkipLayer for single surface node which is skip layer
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetSkipLayer001, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    ASSERT_NE(node, nullptr);

    node->SetSkipLayer(true);
    ASSERT_TRUE(node->GetSkipLayer());
}

/**
 * @tc.name: SetSkipLayer002
 * @tc.desc: Test SetSkipLayer for surface node which is skip layer
    and has leash window node as instant parent
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetSkipLayer002, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto parentNode = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    auto skipLayerNode = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    ASSERT_NE(parentNode, nullptr);
    ASSERT_NE(skipLayerNode, nullptr);

    rsContext->GetMutableNodeMap().renderNodeMap_[parentNode->GetId()] = parentNode;
    rsContext->GetMutableNodeMap().renderNodeMap_[skipLayerNode->GetId()] = skipLayerNode;

    parentNode->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    parentNode->AddChild(skipLayerNode);
    parentNode->SetIsOnTheTree(true);
    skipLayerNode->SetSkipLayer(true);

    ASSERT_TRUE(parentNode->GetSkipLayer() && parentNode->GetHasSkipLayer());
}

/**
 * @tc.name: SetSkipLayer003
 * @tc.desc: Test SetSkipLayer for surface node which is skip layer
        and don't have leash window node as instant parent
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetSkipLayer003, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto ancestorNode = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    auto parentNode = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    auto skipLayerNode = std::make_shared<RSSurfaceRenderNode>(id + 2, rsContext);
    ASSERT_NE(ancestorNode, nullptr);
    ASSERT_NE(parentNode, nullptr);
    ASSERT_NE(skipLayerNode, nullptr);

    rsContext->GetMutableNodeMap().renderNodeMap_[ancestorNode->GetId()] = ancestorNode;
    rsContext->GetMutableNodeMap().renderNodeMap_[parentNode->GetId()] = parentNode;
    rsContext->GetMutableNodeMap().renderNodeMap_[skipLayerNode->GetId()] = skipLayerNode;

    ancestorNode->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    ancestorNode->AddChild(parentNode);
    parentNode->AddChild(skipLayerNode);
    ancestorNode->SetIsOnTheTree(true);
    skipLayerNode->SetSkipLayer(true);

    ASSERT_TRUE(!ancestorNode->GetSkipLayer() && ancestorNode->GetHasSkipLayer());
}

/**
 * @tc.name: SetSecurityLayer001
 * @tc.desc: Test SetSecurityLayer for single surface node which is security layer
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetSecurityLayer001, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    ASSERT_NE(node, nullptr);

    node->SetSecurityLayer(true);
    ASSERT_TRUE(node->GetSecurityLayer());
}

/**
 * @tc.name: SetSecurityLayer002
 * @tc.desc: Test SetSecurityLayer for surface node which is security layer
    and has leash window node as instant parent
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetSecurityLayer002, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto parentNode = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    auto securityLayerNode = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    ASSERT_NE(parentNode, nullptr);
    ASSERT_NE(securityLayerNode, nullptr);

    rsContext->GetMutableNodeMap().renderNodeMap_[parentNode->GetId()] = parentNode;
    rsContext->GetMutableNodeMap().renderNodeMap_[securityLayerNode->GetId()] = securityLayerNode;

    parentNode->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    parentNode->AddChild(securityLayerNode);
    parentNode->SetIsOnTheTree(true);
    securityLayerNode->SetSecurityLayer(true);

    ASSERT_TRUE(parentNode->GetSecurityLayer() && parentNode->GetHasSecurityLayer());
}

/**
 * @tc.name: SetSecurityLayer003
 * @tc.desc: Test SetSecurityLayer for surface node which is security layer
        and don't have leash window node as instant parent
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetSecurityLayer003, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto ancestorNode = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    auto parentNode = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    auto securityLayerNode = std::make_shared<RSSurfaceRenderNode>(id + 2, rsContext);
    ASSERT_NE(ancestorNode, nullptr);
    ASSERT_NE(parentNode, nullptr);
    ASSERT_NE(securityLayerNode, nullptr);

    rsContext->GetMutableNodeMap().renderNodeMap_[ancestorNode->GetId()] = ancestorNode;
    rsContext->GetMutableNodeMap().renderNodeMap_[parentNode->GetId()] = parentNode;
    rsContext->GetMutableNodeMap().renderNodeMap_[securityLayerNode->GetId()] = securityLayerNode;

    ancestorNode->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    ancestorNode->AddChild(parentNode);
    parentNode->AddChild(securityLayerNode);
    ancestorNode->SetIsOnTheTree(true);
    securityLayerNode->SetSecurityLayer(true);

    ASSERT_TRUE(!ancestorNode->GetSecurityLayer() && ancestorNode->GetHasSecurityLayer());
}

/**
 * @tc.name: StoreMustRenewedInfo001
 * @tc.desc: Test StoreMustRenewedInfo while has filter
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, StoreMustRenewedInfo001, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);
    node->InitRenderParams();
    node->SetChildHasVisibleFilter(true);
    node->RSRenderNode::StoreMustRenewedInfo();
    node->StoreMustRenewedInfo();
    ASSERT_TRUE(node->HasMustRenewedInfo());
}

/**
 * @tc.name: StoreMustRenewedInfo002
 * @tc.desc: Test StoreMustRenewedInfo while has effect node
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, StoreMustRenewedInfo002, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetChildHasVisibleEffect(true);
    node->RSRenderNode::StoreMustRenewedInfo();
    node->StoreMustRenewedInfo();
    ASSERT_TRUE(node->HasMustRenewedInfo());
}

/**
 * @tc.name: StoreMustRenewedInfo003
 * @tc.desc: Test StoreMustRenewedInfo while has hardware node
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, StoreMustRenewedInfo003, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetHasHardwareNode(true);
    node->RSRenderNode::StoreMustRenewedInfo();
    node->StoreMustRenewedInfo();
    ASSERT_TRUE(node->HasMustRenewedInfo());
}

/**
 * @tc.name: StoreMustRenewedInfo004
 * @tc.desc: Test StoreMustRenewedInfo while is skip layer
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, StoreMustRenewedInfo004, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetSkipLayer(true);
    node->RSRenderNode::StoreMustRenewedInfo();
    node->StoreMustRenewedInfo();
    ASSERT_TRUE(node->HasMustRenewedInfo());
}

/**
 * @tc.name: StoreMustRenewedInfo005
 * @tc.desc: Test StoreMustRenewedInfo while is security layer
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, StoreMustRenewedInfo005, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetSecurityLayer(true);
    node->RSRenderNode::StoreMustRenewedInfo();
    node->StoreMustRenewedInfo();
    ASSERT_TRUE(node->HasMustRenewedInfo());
}

/**
 * @tc.name: StoreMustRenewedInfo006
 * @tc.desc: Test StoreMustRenewedInfo while is protected layer
 * @tc.type: FUNC
 * @tc.require: issueI7ZSC2
 */
HWTEST_F(RSSurfaceRenderNodeTest, StoreMustRenewedInfo006, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetProtectedLayer(true);
    node->RSRenderNode::StoreMustRenewedInfo();
    node->StoreMustRenewedInfo();
    ASSERT_TRUE(node->HasMustRenewedInfo());
}

/**
 * @tc.name: GetFirstLevelNodeId001
 * @tc.desc: Test GetFirstLevelNode for single app window node
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetFirstLevelNodeId001, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    ASSERT_NE(node, nullptr);

    rsContext->GetMutableNodeMap().renderNodeMap_[node->GetId()] = node;
    node->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    node->SetIsOnTheTree(true);
    ASSERT_EQ(node->GetFirstLevelNodeId(), node->GetId());
}

/**
 * @tc.name: GetFirstLevelNodeId002
 * @tc.desc: Test GetFirstLevelNode for app window node which parent is leash window node
 * @tc.type: FUNC
 * @tc.require: issueI9ABGS
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetFirstLevelNodeId002, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto childNode = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    auto parentNode = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    ASSERT_NE(childNode, nullptr);
    ASSERT_NE(parentNode, nullptr);

    rsContext->GetMutableNodeMap().renderNodeMap_[childNode->GetId()] = childNode;
    rsContext->GetMutableNodeMap().renderNodeMap_[parentNode->GetId()] = parentNode;

    parentNode->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    childNode->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    parentNode->AddChild(childNode);
    parentNode->SetIsOnTheTree(true);
    ASSERT_EQ(childNode->GetFirstLevelNodeId(), parentNode->GetId());
}

/**
 * @tc.name: SetHasSharedTransitionNode
 * @tc.desc: Test SetHasSharedTransitionNode
 * @tc.type: FUNC
 * @tc.require: issueI98VTC
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetHasSharedTransitionNode, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);
    node->SetHasSharedTransitionNode(true);
    
    ASSERT_EQ(node->GetHasSharedTransitionNode(), true);
}

/**
 * @tc.name: QuerySubAssignable001
 * @tc.desc: Test QuerySubAssignable
 * @tc.type: FUNC
 * @tc.require: issueI98VTC
 */
HWTEST_F(RSSurfaceRenderNodeTest, QuerySubAssignable001, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);
    
    ASSERT_EQ(node->QuerySubAssignable(false), true);
}

/**
 * @tc.name: QuerySubAssignable002
 * @tc.desc: Test QuerySubAssignable while has filter
 * @tc.type: FUNC
 * @tc.require: issueI98VTC
 */
HWTEST_F(RSSurfaceRenderNodeTest, QuerySubAssignable002, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);
    node->SetHasFilter(true);
    
    ASSERT_EQ(node->QuerySubAssignable(false), false);
}

/**
 * @tc.name: SetForceHardwareAndFixRotation001
 * @tc.desc: Test SetForceHardwareAndFixRotation true
 * @tc.type: FUNC
 * @tc.require: issueI9HWLB
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetForceHardwareAndFixRotation001, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetForceHardwareAndFixRotation(true);
    ASSERT_EQ(node->isForceHardwareByUser_, true);
}

/**
 * @tc.name: SetForceHardwareAndFixRotation002
 * @tc.desc: Test SetForceHardwareAndFixRotation false
 * @tc.type: FUNC
 * @tc.require: issueI9HWLB
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetForceHardwareAndFixRotation002, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetForceHardwareAndFixRotation(false);
    ASSERT_EQ(node->isForceHardwareByUser_, false);
}

/**
 * @tc.name: ProtectedLayer001
 * @tc.desc: Test ProtectedLayer when SetProtectedLayer is true.
 * @tc.type: FUNC
 * @tc.require: issueI7ZSC2
 */
HWTEST_F(RSSurfaceRenderNodeTest, ProtectedLayer001, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetProtectedLayer(true);
    bool result = node->GetProtectedLayer();
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: ProtectedLayer002
 * @tc.desc: Test ProtectedLayer when SetProtectedLayer is false.
 * @tc.type: FUNC
 * @tc.require: issueI7ZSC2
 */
HWTEST_F(RSSurfaceRenderNodeTest, ProtectedLayer002, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetProtectedLayer(false);
    bool result = node->GetProtectedLayer();
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: GetHasProtectedLayer001
 * @tc.desc: Test GetHasProtectedLayer when SetProtectedLayer is true.
 * @tc.type: FUNC
 * @tc.require: issueI7ZSC2
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetHasProtectedLayer001, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetProtectedLayer(true);
    bool result = node->GetHasProtectedLayer();
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: GetHasProtectedLayer002
 * @tc.desc: Test GetHasProtectedLayer when SetProtectedLayer is false.
 * @tc.type: FUNC
 * @tc.require: issueI7ZSC2
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetHasProtectedLayer002, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetProtectedLayer(false);
    bool result = node->GetHasProtectedLayer();
    ASSERT_EQ(result, false);
}
} // namespace Rosen
} // namespace OHOS
