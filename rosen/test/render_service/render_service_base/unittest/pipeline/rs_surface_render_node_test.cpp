/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_render_thread_visitor.h"
#include "pipeline/rs_effect_render_node.h"
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
    uint8_t MAX_ALPHA = 255;
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
 * @tc.desc: Test SetSkipLayer for surface node while skip Layer isn't first level node
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

    ASSERT_TRUE(parentNode->GetHasSkipLayer());
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
 * @tc.desc: Test SetSecurityLayer for surface node while security Layer isn't first level node
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

    ASSERT_TRUE(parentNode->GetHasSecurityLayer());
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

    node->InitRenderParams();
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
 * @tc.require: issueI9LOXQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, QuerySubAssignable002, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);
    
    if (RSUniRenderJudgement::IsUniRender()) {
        node->InitRenderParams();
    }
    node->SetHasFilter(true);
    
    ASSERT_EQ(node->QuerySubAssignable(false), false);
}

/**
 * @tc.name: QuerySubAssignable003
 * @tc.desc: Test QuerySubAssignable while node's child has filter and child is transparent
 * @tc.type: FUNC
 * @tc.require: issueI9LOXQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, QuerySubAssignable003, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto childNode = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    ASSERT_NE(node, nullptr);
    ASSERT_NE(childNode, nullptr);
    RSUniRenderJudgement::uniRenderEnabledType_ = UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL;
    if (RSUniRenderJudgement::IsUniRender()) {
        node->InitRenderParams();
        childNode->InitRenderParams();
    }
    childNode->SetHasFilter(true);
    node->SetChildHasVisibleFilter(true);
    
    ASSERT_EQ(node->QuerySubAssignable(false), false);
}

/**
 * @tc.name: QuerySubAssignable004
 * @tc.desc: Test QuerySubAssignable while node's child has filter and is not transparent
 * @tc.type: FUNC
 * @tc.require: issueI9LOXQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, QuerySubAssignable004, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto childNode = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    ASSERT_NE(node, nullptr);
    ASSERT_NE(childNode, nullptr);

    RSUniRenderJudgement::uniRenderEnabledType_ = UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL;
    if (RSUniRenderJudgement::IsUniRender()) {
        node->InitRenderParams();
        childNode->InitRenderParams();
    }
    childNode->SetHasFilter(true);
    node->SetChildHasVisibleFilter(true);
    node->SetAbilityBGAlpha(MAX_ALPHA);
    
    ASSERT_EQ(node->QuerySubAssignable(false), true);
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

    node->InitRenderParams();
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

    node->InitRenderParams();
    node->SetForceHardwareAndFixRotation(false);
    ASSERT_EQ(node->isForceHardwareByUser_, false);
}

/**
 * @tc.name: UpdateSrcRectTest
 * @tc.desc: test results of UpdateSrcRect
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateSrcRectTest, TestSize.Level1)
{
    Drawing::Canvas canvas;
    Drawing::RectI dstRect(0, 0, 100, 100);
    bool hasRotation = false;

    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    renderNode->UpdateSrcRect(canvas, dstRect, hasRotation);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: UpdateHwcDisabledBySrcRectTest
 * @tc.desc: test results of UpdateHwcDisabledBySrcRect
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateHwcDisabledBySrcRectTest, TestSize.Level1)
{
    bool hasRotation = false;
    auto buffer = SurfaceBuffer::Create();
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    renderNode->UpdateHwcDisabledBySrcRect(hasRotation);

    renderNode->GetRSSurfaceHandler()->buffer_.buffer = buffer;
    renderNode->UpdateHwcDisabledBySrcRect(hasRotation);
    ASSERT_FALSE(renderNode->isHardwareForcedDisabledBySrcRect_);
}

/**
 * @tc.name: IsYUVBufferFormatTest
 * @tc.desc: test results of IsYUVBufferFormat
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsYUVBufferFormatTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    EXPECT_FALSE(testNode->IsYUVBufferFormat());

    auto buffer = SurfaceBuffer::Create();
    testNode->GetRSSurfaceHandler()->buffer_.buffer = buffer;
    EXPECT_NE(testNode->GetRSSurfaceHandler()->GetBuffer(), nullptr);
    EXPECT_FALSE(testNode->IsYUVBufferFormat());
}

/**
 * @tc.name: ShouldPrepareSubnodesTest001
 * @tc.desc: test results of ShouldPrepareSubnodes
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ShouldPrepareSubnodesTest001, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->SetDstRect(RectI());
    testNode->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    EXPECT_FALSE(testNode->ShouldPrepareSubnodes());

    testNode->SetDstRect(RectI(0, 0, 100, 100));
    testNode->nodeType_ = RSSurfaceNodeType::SCB_SCREEN_NODE;
    EXPECT_TRUE(testNode->ShouldPrepareSubnodes());
}

/**
 * @tc.name: DirtyRegionDumpTest
 * @tc.desc: test results of DirtyRegionDump
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, DirtyRegionDumpTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->DirtyRegionDump();

    node->dirtyManager_.reset();
    std::string dump = node->DirtyRegionDump();
    ASSERT_NE(dump, "");
}

/**
 * @tc.name: PrepareRenderBeforeChildren
 * @tc.desc: test results of PrepareRenderBeforeChildren
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, PrepareRenderBeforeChildren, TestSize.Level1)
{
    Drawing::Canvas canvas;
    RSPaintFilterCanvas rsPaintFilterCanvas(&canvas);
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->InitRenderParams();
    node->PrepareRenderBeforeChildren(rsPaintFilterCanvas);
    ASSERT_NE(node->GetRenderProperties().GetBoundsGeometry(), nullptr);
}

/**
 * @tc.name: CollectSurfaceTest
 * @tc.desc: test results of CollectSurface
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, CollectSurfaceTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);

    testNode->nodeType_ = RSSurfaceNodeType::SCB_SCREEN_NODE;
    auto node = std::make_shared<RSBaseRenderNode>(id, context);
    Drawing::Canvas canvasArgs;
    RSPaintFilterCanvas canvas(&canvasArgs);
    std::vector<std::shared_ptr<RSRenderNode>> vec;
    testNode->CollectSurface(node, vec, true, false);

    testNode->nodeType_ = RSSurfaceNodeType::STARTING_WINDOW_NODE;
    testNode->CollectSurface(node, vec, true, false);
    testNode->CollectSurface(node, vec, false, false);
    testNode->nodeType_ = RSSurfaceNodeType::SCB_SCREEN_NODE;
    testNode->CollectSurface(node, vec, true, false);
    testNode->nodeType_ = RSSurfaceNodeType::SELF_DRAWING_NODE;
    testNode->CollectSurface(node, vec, true, true);
    ASSERT_FALSE(testNode->isSubSurfaceEnabled_);
}

/**
 * @tc.name: CollectSurfaceForUIFirstSwitchTest
 * @tc.desc: test results of CollectSurfaceForUIFirstSwitchTest
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, CollectSurfaceForUIFirstSwitchTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    uint32_t leashWindowCount = 0;
    uint32_t minNodeNum = 5;
    testNode->CollectSurfaceForUIFirstSwitch(leashWindowCount, minNodeNum);
    ASSERT_EQ(leashWindowCount, 0);
}

/**
 * @tc.name: ClearChildrenCache
 * @tc.desc: test results of ClearChildrenCache
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ClearChildrenCache, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->ClearChildrenCache();
    ASSERT_EQ(testNode->nodeType_, RSSurfaceNodeType::DEFAULT);
}

/**
 * @tc.name: OnTreeStateChangedTest
 * @tc.desc: test results of OnTreeStateChanged
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, OnTreeStateChangedTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->OnTreeStateChanged();
    node->nodeType_ = RSSurfaceNodeType::ABILITY_COMPONENT_NODE;
    node->OnTreeStateChanged();
    ASSERT_EQ(node->nodeType_, RSSurfaceNodeType::ABILITY_COMPONENT_NODE);
}

/**
 * @tc.name: OnResetParentTest
 * @tc.desc: test results of OnResetParent
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, OnResetParentTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id, context);

    node->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    node->OnResetParent();

    node->nodeType_ = RSSurfaceNodeType::SELF_DRAWING_NODE;
    node->OnResetParent();
    ASSERT_EQ(node->nodeType_, RSSurfaceNodeType::SELF_DRAWING_NODE);
}

/**
 * @tc.name: SetIsNotifyUIBufferAvailableTest
 * @tc.desc: test results of SetIsNotifyUIBufferAvailable
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetIsNotifyUIBufferAvailableTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->SetIsNotifyUIBufferAvailable(true);
    ASSERT_TRUE(node->isNotifyUIBufferAvailable_.load());
}

/**
 * @tc.name: IsSubTreeNeedPrepareTest
 * @tc.desc: test results of IsSubTreeNeedPrepare
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsSubTreeNeedPrepareTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->IsSubTreeNeedPrepare(false, false);
    node->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    EXPECT_TRUE(node->IsSubTreeNeedPrepare(true, true));
}

/**
 * @tc.name: PrepareTest
 * @tc.desc: test results of QuickPrepare
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, PrepareTest, TestSize.Level1)
{
    std::shared_ptr<RSRenderThreadVisitor> visitor;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    surfaceNode->QuickPrepare(visitor);

    visitor = std::make_shared<RSRenderThreadVisitor>();
    surfaceNode->QuickPrepare(visitor);
    ASSERT_EQ(surfaceNode->nodeType_, RSSurfaceNodeType::DEFAULT);
}

/**
 * @tc.name: PrepareTest
 * @tc.desc: test results of Process
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ProcessTest, TestSize.Level1)
{
    std::shared_ptr<RSRenderThreadVisitor> visitor;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    surfaceNode->Process(visitor);
    visitor = std::make_shared<RSRenderThreadVisitor>();
    surfaceNode->Process(visitor);
    ASSERT_EQ(surfaceNode->nodeType_, RSSurfaceNodeType::DEFAULT);
}

/**
 * @tc.name: ProcessAnimatePropertyBeforeChildren
 * @tc.desc: test results of ProcessAnimatePropertyBeforeChildren
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ProcessAnimatePropertyBeforeChildren, TestSize.Level1)
{
    Drawing::Canvas canvasArgs;
    auto canvas = std::make_shared<RSPaintFilterCanvas>(&canvasArgs);
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    surfaceNode->InitRenderParams();
    surfaceNode->ProcessAnimatePropertyBeforeChildren(*canvas, true);
    surfaceNode->cacheType_ = CacheType::ANIMATE_PROPERTY;
    surfaceNode->needDrawAnimateProperty_ = true;
    surfaceNode->ProcessAnimatePropertyBeforeChildren(*canvas, true);
    ASSERT_EQ(surfaceNode->nodeType_, RSSurfaceNodeType::DEFAULT);
}

/**
 * @tc.name: ProcessRenderAfterChildrenTest
 * @tc.desc: test results of ProcessRenderAfterChildren
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ProcessRenderAfterChildrenTest, TestSize.Level1)
{
    Drawing::Canvas canvasArgs;
    auto canvas = std::make_shared<RSPaintFilterCanvas>(&canvasArgs);
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->ProcessRenderAfterChildren(*canvas);
    EXPECT_FALSE(node->needDrawAnimateProperty_);
}

/**
 * @tc.name: SetContextAlphaTest
 * @tc.desc: test results of SetContextAlpha
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetContextAlphaTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->SetContextAlpha(1.0f, true);
    testNode->SetContextAlpha(0.5f, true);
    testNode->SetContextAlpha(0.5f, false);
    EXPECT_EQ(testNode->contextAlpha_, 0.5f);
}

/**
 * @tc.name: SetContextClipRegionTest
 * @tc.desc: test results of GetContextClipRegion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetContextClipRegionTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    Drawing::Rect rect(0, 0, 100, 100);
    testNode->SetContextClipRegion(rect, true);
    testNode->SetContextClipRegion(rect, false);
    EXPECT_EQ(testNode->contextClipRect_->left_, rect.left_);
    testNode->SetContextClipRegion(Drawing::Rect(1, 1, 1, 1), true);
    EXPECT_NE(testNode->contextClipRect_->left_, rect.left_);
}

/**
 * @tc.name: SetSkipLayerTest
 * @tc.desc: test results of SetSkipLayer
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetSkipLayerTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->SetSkipLayer(true);
    EXPECT_TRUE(node->isSkipLayer_);
    node->SetSkipLayer(false);
    EXPECT_FALSE(node->isSkipLayer_);
}

/**
 * @tc.name: SyncSecurityInfoToFirstLevelNodeTest
 * @tc.desc: test results of SyncSecurityInfoToFirstLevelNode
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SyncSecurityInfoToFirstLevelNodeTest, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->SyncSecurityInfoToFirstLevelNode();
    EXPECT_FALSE(node->isSkipLayer_);
}

/**
 * @tc.name: SyncSkipInfoToFirstLevelNode
 * @tc.desc: test results of SyncSkipInfoToFirstLevelNode
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SyncSkipInfoToFirstLevelNode, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->SyncSkipInfoToFirstLevelNode();
    EXPECT_FALSE(node->isSkipLayer_);
}

/**
 * @tc.name: NotifyTreeStateChange
 * @tc.desc: test results of NotifyTreeStateChange
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, NotifyTreeStateChange, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    node->NotifyTreeStateChange();
    bool callbackCalled = false;
    node->RegisterTreeStateChangeCallback(
        [&callbackCalled](const RSSurfaceRenderNode& node) { callbackCalled = true; });
    node->NotifyTreeStateChange();
    EXPECT_TRUE(callbackCalled);
}

/**
 * @tc.name: UpdateSurfaceDefaultSize
 * @tc.desc: test results of UpdateSurfaceDefaultSize
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateSurfaceDefaultSize, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(1, context, true);
    node->UpdateSurfaceDefaultSize(1920.0f, 1080.0f);
    node->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    node->UpdateSurfaceDefaultSize(1920.0f, 1080.0f);
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_, nullptr);
}

/**
 * @tc.name: NeedClearBufferCache
 * @tc.desc: test results of NeedClearBufferCache
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, NeedClearBufferCache, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->InitRenderParams();
    testNode->addedToPendingSyncList_ = true;
    testNode->NeedClearBufferCache();
    EXPECT_FALSE(testNode->isSkipLayer_);
}

/**
 * @tc.name: RegisterBufferAvailableListenerTest001
 * @tc.desc: test results of RegisterBufferAvailableListener
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, RegisterBufferAvailableListenerTest001, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    sptr<RSIBufferAvailableCallback> callback;
    bool isFromRenderThread = false;
    testNode->RegisterBufferAvailableListener(callback, isFromRenderThread);
    EXPECT_FALSE(testNode->isSkipLayer_);
}

/**
 * @tc.name: SetNotifyRTBufferAvailable
 * @tc.desc: test results of SetNotifyRTBufferAvailable
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetNotifyRTBufferAvailable, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->SetNotifyRTBufferAvailable(true);
    ASSERT_TRUE(testNode->isNotifyRTBufferAvailable_);
}

/**
 * @tc.name: ConnectToNodeInRenderServiceTest
 * @tc.desc: test results of ConnectToNodeInRenderService
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ConnectToNodeInRenderServiceTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->ConnectToNodeInRenderService();
    EXPECT_FALSE(testNode->isSkipLayer_);
}

/**
 * @tc.name: NotifyRTBufferAvailable
 * @tc.desc: test results of NotifyRTBufferAvailable
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, NotifyRTBufferAvailable, TestSize.Level1)
{
    auto testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->NotifyRTBufferAvailable(false);
    ASSERT_FALSE(testNode->isNotifyRTBufferAvailablePre_);
    testNode->NotifyRTBufferAvailable(true);
    testNode->isRefresh_ = true;
    testNode->NotifyRTBufferAvailable(true);
    ASSERT_FALSE(testNode->isNotifyRTBufferAvailable_);
}

/**
 * @tc.name: NotifyRTBufferAvailable
 * @tc.desc: test results of NotifyRTBufferAvailable
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, NotifyUIBufferAvailable, TestSize.Level1)
{
    auto testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->NotifyUIBufferAvailable();
    testNode->isNotifyUIBufferAvailable_ = false;
    testNode->NotifyUIBufferAvailable();
    ASSERT_TRUE(testNode->isNotifyUIBufferAvailable_);
}

/**
 * @tc.name: UpdateDirtyIfFrameBufferConsumed
 * @tc.desc: test results of UpdateDirtyIfFrameBufferConsumed
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateDirtyIfFrameBufferConsumed, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    testNode->GetRSSurfaceHandler()->isCurrentFrameBufferConsumed_ = true;
    bool resultOne = testNode->UpdateDirtyIfFrameBufferConsumed();
    EXPECT_TRUE(resultOne);

    testNode->GetRSSurfaceHandler()->isCurrentFrameBufferConsumed_ = false;
    bool resultTwo = testNode->UpdateDirtyIfFrameBufferConsumed();
    EXPECT_FALSE(resultTwo);
}

/**
 * @tc.name: IsSurfaceInStartingWindowStage
 * @tc.desc: test results of IsSurfaceInStartingWindowStage
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsSurfaceInStartingWindowStage, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    auto parentSurfaceNode = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    EXPECT_FALSE(testNode->IsSurfaceInStartingWindowStage());

    testNode->SetParent(parentSurfaceNode);
    testNode->isNotifyUIBufferAvailable_ = false;
    testNode->SetSurfaceNodeType(RSSurfaceNodeType::LEASH_WINDOW_NODE);
    bool resultOne = testNode->IsSurfaceInStartingWindowStage();
    EXPECT_FALSE(resultOne);

    parentSurfaceNode->SetSurfaceNodeType(RSSurfaceNodeType::SURFACE_TEXTURE_NODE);
    bool resultTwo = testNode->IsSurfaceInStartingWindowStage();
    EXPECT_FALSE(resultTwo);
}

/**
 * @tc.name: IsParentLeashWindowInScale
 * @tc.desc: test results of IsParentLeashWindowInScale
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsParentLeashWindowInScale, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    std::shared_ptr<RSSurfaceRenderNode> parentSurfaceNode = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    testNode->SetParent(parentSurfaceNode);

    bool resultOne = testNode->IsParentLeashWindowInScale();
    EXPECT_FALSE(resultOne);

    parentSurfaceNode->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    parentSurfaceNode->isScale_ = true;
    bool resultTwo = testNode->IsParentLeashWindowInScale();
    EXPECT_TRUE(resultTwo);
}

/**
 * @tc.name: GetSurfaceOcclusionRect
 * @tc.desc: test results of GetSurfaceOcclusionRect
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetSurfaceOcclusionRect, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    bool isUniRender = true;
    Occlusion::Rect expectedRect1 = testNode->GetOldDirtyInSurface();
    Occlusion::Rect resultOne = testNode->GetSurfaceOcclusionRect(isUniRender);
    EXPECT_EQ(expectedRect1, resultOne);

    isUniRender = false;
    Occlusion::Rect expectedRect2 = testNode->GetDstRect();
    Occlusion::Rect resultTwo = testNode->GetSurfaceOcclusionRect(isUniRender);
    EXPECT_EQ(expectedRect2, resultTwo);
}

/**
 * @tc.name: QueryIfAllHwcChildrenForceDisabledByFilter
 * @tc.desc: test results of QueryIfAllHwcChildrenForceDisabledByFilter
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, QueryIfAllHwcChildrenForceDisabledByFilter, TestSize.Level1)
{
    auto testNode = std::make_shared<RSSurfaceRenderNode>(id, context);
    EXPECT_TRUE(testNode->QueryIfAllHwcChildrenForceDisabledByFilter());

    auto childNode1 = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    auto childNode2 = std::make_shared<RSSurfaceRenderNode>(id + 2, context);
    testNode->AddChildHardwareEnabledNode(childNode1);
    testNode->AddChildHardwareEnabledNode(childNode2);
    childNode1->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    EXPECT_TRUE(testNode->QueryIfAllHwcChildrenForceDisabledByFilter());
}

/**
 * @tc.name: AccumulateOcclusionRegion
 * @tc.desc: test results of AccumulateOcclusionRegion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, AccumulateOcclusionRegion, TestSize.Level1)
{
    auto testNode = std::make_shared<RSSurfaceRenderNode>(id, context);

    Occlusion::Region accumulatedRegion;
    Occlusion::Region curRegion;
    bool hasFilterCacheOcclusion = false;
    bool isUniRender = true;
    bool filterCacheOcclusionEnabled = true;

    testNode->isNotifyUIBufferAvailable_ = false;
    testNode->SetSurfaceNodeType(RSSurfaceNodeType::LEASH_WINDOW_NODE);
    testNode->isNotifyUIBufferAvailable_ = false;
    testNode->AccumulateOcclusionRegion(
        accumulatedRegion, curRegion, hasFilterCacheOcclusion, isUniRender, filterCacheOcclusionEnabled);
    EXPECT_TRUE(accumulatedRegion.IsEmpty());

    auto parentSurfaceNode = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    testNode->SetParent(parentSurfaceNode);
    testNode->isOcclusionInSpecificScenes_ = true;
    testNode->AccumulateOcclusionRegion(
        accumulatedRegion, curRegion, hasFilterCacheOcclusion, isUniRender, filterCacheOcclusionEnabled);
    EXPECT_FALSE(hasFilterCacheOcclusion);
}

/**
 * @tc.name: GetVisibleLevelForWMS
 * @tc.desc: test results of GetVisibleLevelForWMS
 * @tc.type: FUNC
 * @tc.require: issueIA61E9
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetVisibleLevelForWMS, TestSize.Level1)
{
    RSSurfaceRenderNode node(id);

    EXPECT_EQ(node.GetVisibleLevelForWMS(RSVisibleLevel::RS_INVISIBLE), WINDOW_LAYER_INFO_TYPE::INVISIBLE);

    EXPECT_EQ(node.GetVisibleLevelForWMS(RSVisibleLevel::RS_ALL_VISIBLE), WINDOW_LAYER_INFO_TYPE::ALL_VISIBLE);

    EXPECT_EQ(
        node.GetVisibleLevelForWMS(RSVisibleLevel::RS_SEMI_NONDEFAULT_VISIBLE), WINDOW_LAYER_INFO_TYPE::SEMI_VISIBLE);

    EXPECT_EQ(
        node.GetVisibleLevelForWMS(RSVisibleLevel::RS_SEMI_DEFAULT_VISIBLE), WINDOW_LAYER_INFO_TYPE::SEMI_VISIBLE);

    EXPECT_EQ(
        node.GetVisibleLevelForWMS(RSVisibleLevel::RS_UNKNOW_VISIBLE_LEVEL), WINDOW_LAYER_INFO_TYPE::SEMI_VISIBLE);
}

/**
 * @tc.name: SetVisibleRegionRecursive
 * @tc.desc: test results of SetVisibleRegionRecursive
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetVisibleRegionRecursive, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    Occlusion::Rect rect(1, 1, 1, 1);
    Occlusion::Region region(rect);
    VisibleData visibleVec;
    std::map<NodeId, RSVisibleLevel> visMapForVsyncRate;
    bool needSetVisibleRegion = true;
    RSVisibleLevel visibleLevel = RSVisibleLevel::RS_ALL_VISIBLE;
    bool isSystemAnimatedScenes = false;

    node->nodeType_ = RSSurfaceNodeType::SELF_DRAWING_NODE;
    node->SetVisibleRegionRecursive(
        region, visibleVec, visMapForVsyncRate, needSetVisibleRegion, visibleLevel, isSystemAnimatedScenes);
    node->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;

    node->SetVisibleRegionRecursive(
        region, visibleVec, visMapForVsyncRate, needSetVisibleRegion, visibleLevel, isSystemAnimatedScenes);

    needSetVisibleRegion = false;
    node->SetVisibleRegionRecursive(
        region, visibleVec, visMapForVsyncRate, needSetVisibleRegion, visibleLevel, isSystemAnimatedScenes);
    ASSERT_TRUE(node->visibleRegionForCallBack_.IsEmpty());
}

/**
 * @tc.name: CalcFilterCacheValidForOcclusion
 * @tc.desc: test results of CalcFilterCacheValidForOcclusion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, CalcFilterCacheValidForOcclusionTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->isFilterCacheFullyCovered_ = true;
    node->dirtyManager_ = std::make_shared<RSDirtyRegionManager>();
    node->CalcFilterCacheValidForOcclusion();
    EXPECT_TRUE(node->isFilterCacheStatusChanged_);

    node->isFilterCacheFullyCovered_ = false;
    node->isFilterCacheValidForOcclusion_ = false;
    node->CalcFilterCacheValidForOcclusion();
    EXPECT_FALSE(node->isFilterCacheStatusChanged_);
}

/**
 * @tc.name: CalcFilterCacheValidForOcclusion
 * @tc.desc: test results of CalcFilterCacheValidForOcclusion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateFilterNodesTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    std::shared_ptr<RSRenderNode> renderNode;
    node->UpdateFilterNodes(renderNode);

    renderNode = std::make_shared<RSRenderNode>(id + 1);
    node->UpdateFilterNodes(renderNode);
    EXPECT_EQ(node->filterNodes_.size(), 1);
}

/**
 * @tc.name: CalcFilterCacheValidForOcclusion
 * @tc.desc: test results of CalcFilterCacheValidForOcclusion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, CheckValidFilterCacheFullyCoverTargetTest, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    RSRenderNode filterNode(id + 1);
    RectI targetRect;
    node->CheckValidFilterCacheFullyCoverTarget(filterNode, targetRect);
    EXPECT_FALSE(node->isFilterCacheStatusChanged_);
}

/**
 * @tc.name: UpdateSurfaceCacheContentStaticFlag
 * @tc.desc: test results of UpdateSurfaceCacheContentStaticFlag
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateSurfaceCacheContentStaticFlag, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    node->InitRenderParams();
    node->addedToPendingSyncList_ = true;
    node->UpdateSurfaceCacheContentStaticFlag();

    node->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    node->UpdateSurfaceCacheContentStaticFlag();
    EXPECT_EQ(node->nodeType_, RSSurfaceNodeType::LEASH_WINDOW_NODE);
}

/**
 * @tc.name: UpdateSurfaceSubTreeDirtyFlag
 * @tc.desc: test results of UpdateSurfaceSubTreeDirtyFlag
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateSurfaceSubTreeDirtyFlag, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    node->stagingRenderParams_ = std::make_unique<RSSurfaceRenderParams>(id + 1);
    node->addedToPendingSyncList_ = true;
    node->UpdateSurfaceSubTreeDirtyFlag();
    ASSERT_NE(node->stagingRenderParams_, nullptr);
}

/**
 * @tc.name: UpdateDrawingCacheNodes
 * @tc.desc: test results of UpdateDrawingCacheNodes
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateDrawingCacheNodes, TestSize.Level1)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    auto renderNode = std::make_shared<RSRenderNode>(id + 1);
    node->UpdateDrawingCacheNodes(renderNode);
    node->UpdateDrawingCacheNodes(nullptr);
    EXPECT_EQ(node->drawingCacheNodes_.size(), 1);
}

/**
 * @tc.name: ResetDrawingCacheStatusIfNodeStatic
 * @tc.desc: test results of ResetDrawingCacheStatusIfNodeStatic
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetDrawingCacheStatusIfNodeStatic, TestSize.Level1)
{
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    std::unordered_map<NodeId, std::unordered_set<NodeId>> allRects;
    renderNode->ResetDrawingCacheStatusIfNodeStatic(allRects);
    EXPECT_EQ(renderNode->drawingCacheNodes_.size(), 0);
}

/**
 * @tc.name: UpdateFilterCacheStatusWithVisible
 * @tc.desc: test results of UpdateFilterCacheStatusWithVisible
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateFilterCacheStatusWithVisible, TestSize.Level1)
{
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    bool visible = true;
    renderNode->UpdateFilterCacheStatusWithVisible(visible);
    renderNode->UpdateFilterCacheStatusWithVisible(visible);
    ASSERT_TRUE(renderNode->prevVisible_);
}

/**
 * @tc.name: UpdateFilterCacheStatusIfNodeStatic
 * @tc.desc: test results of UpdateFilterCacheStatusIfNodeStatic
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateFilterCacheStatusIfNodeStatic, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->UpdateFilterCacheStatusIfNodeStatic(RectI(0, 0, 100, 100), true);

    std::shared_ptr<RSRenderNode> mockNode = std::make_shared<RSEffectRenderNode>(id);
    node->filterNodes_.emplace_back(mockNode);
    node->UpdateFilterCacheStatusIfNodeStatic(RectI(0, 0, 100, 100), false);
    ASSERT_NE(node->filterNodes_.size(), 0);
}

/**
 * @tc.name: ResetOpaqueRegion
 * @tc.desc: test results of ResetOpaqueRegion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetOpaqueRegion, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id);
    RectI absRect { 0, 0, 100, 100 };
    ScreenRotation screenRotation = ScreenRotation::ROTATION_0;
    bool isFocusWindow = true;
    Occlusion::Region res= testNode->ResetOpaqueRegion(absRect, screenRotation, isFocusWindow);
    EXPECT_NE(res.rects_.size(), 0);
    isFocusWindow = false;
    res =testNode->ResetOpaqueRegion(absRect, screenRotation, isFocusWindow);
    EXPECT_NE(res.rects_.size(), 0);
}

/**
 * @tc.name: SetUnfocusedWindowOpaqueRegion
 * @tc.desc: test results of SetUnfocusedWindowOpaqueRegion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetUnfocusedWindowOpaqueRegion, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> surfaceNode = std::make_shared<RSSurfaceRenderNode>(id);
    RectI absRect { 0, 0, 100, 100 };
    ScreenRotation rotationCases[] = { ScreenRotation::ROTATION_0, ScreenRotation::ROTATION_90,
        ScreenRotation::ROTATION_180, ScreenRotation::ROTATION_270, ScreenRotation::INVALID_SCREEN_ROTATION };
    for (ScreenRotation rotation : rotationCases) {
        Occlusion::Region opaqueRegion = surfaceNode->SetUnfocusedWindowOpaqueRegion(absRect, rotation);
        EXPECT_NE(opaqueRegion.rects_.size(), 0);
    }
}

/**
 * @tc.name: SetFocusedWindowOpaqueRegion
 * @tc.desc: test results of SetFocusedWindowOpaqueRegion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetFocusedWindowOpaqueRegion, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    RectI absRect { 0, 0, 100, 100 };
    ScreenRotation rotationCases[] = { ScreenRotation::ROTATION_0, ScreenRotation::ROTATION_90,
    ScreenRotation::ROTATION_180, ScreenRotation::ROTATION_270, ScreenRotation::INVALID_SCREEN_ROTATION };
    for (ScreenRotation rotation : rotationCases) {
        Occlusion::Region opaqueRegion = renderNode->SetFocusedWindowOpaqueRegion(absRect, rotation);
        EXPECT_NE(opaqueRegion.rects_.size(), 0);
    }
}

/**
 * @tc.name: ResetSurfaceContainerRegion
 * @tc.desc: test results of ResetSurfaceContainerRegion
 * @tc.type: FUNC
 * @tc.require: issueI9JAFQ
 */
HWTEST_F(RSSurfaceRenderNodeTest, ResetSurfaceContainerRegion, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    RectI screeninfo { 0, 0, 100, 100 };
    RectI absRect { 0, 0, 50, 50 };
    ScreenRotation rotationCases[] = { ScreenRotation::ROTATION_0, ScreenRotation::ROTATION_90,
    ScreenRotation::ROTATION_180, ScreenRotation::ROTATION_270, ScreenRotation::INVALID_SCREEN_ROTATION };
    renderNode->ResetSurfaceContainerRegion(screeninfo, absRect, rotationCases[0]);
    renderNode->containerConfig_.hasContainerWindow_ = true;
    for (ScreenRotation rotation : rotationCases) {
        renderNode->ResetSurfaceContainerRegion(screeninfo, absRect, rotation);
        EXPECT_FALSE(renderNode->containerRegion_.IsEmpty());
    }
}

/**
 * @tc.name: OnSync
 * @tc.desc: test results of OnSync
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, OnSync, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> surfaceNode = std::make_shared<RSSurfaceRenderNode>(id);
    surfaceNode->InitRenderParams();
    surfaceNode->OnSync();
    ASSERT_NE(surfaceNode->stagingRenderParams_, nullptr);
}

/**
 * @tc.name: CheckIfOcclusionReusable
 * @tc.desc: test results of CheckIfOcclusionReusable
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, CheckIfOcclusionReusable, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> surfaceNode = std::make_shared<RSSurfaceRenderNode>(id);
    std::queue<NodeId> surfaceNodesIds;
    ASSERT_TRUE(surfaceNode->CheckIfOcclusionReusable(surfaceNodesIds));
    surfaceNodesIds.push(1);
    bool result = surfaceNode->CheckIfOcclusionReusable(surfaceNodesIds);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: CheckParticipateInOcclusion
 * @tc.desc: test results of CheckParticipateInOcclusion
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, CheckParticipateInOcclusion, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    EXPECT_FALSE(node->CheckParticipateInOcclusion());
}

/**
 * @tc.name: CheckAndUpdateOpaqueRegion
 * @tc.desc: test results of CheckAndUpdateOpaqueRegion
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, CheckAndUpdateOpaqueRegion, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    RectI screeninfo { 0, 0, 100, 100 };
    ScreenRotation screenRotation = ScreenRotation::ROTATION_0;
    node->CheckAndUpdateOpaqueRegion(screeninfo, screenRotation, true);
    EXPECT_FALSE(node->IsOpaqueRegionChanged());
}

/**
 * @tc.name: UpdateChildrenFilterRects
 * @tc.desc: test results of UpdateChildrenFilterRects
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateChildrenFilterRects, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> testNode = std::make_shared<RSSurfaceRenderNode>(id);
    std::shared_ptr<RSRenderNode> filterNode = std::make_shared<RSRenderNode>(id + 1);
    RectI rect { 0, 0, 20, 20 };
    bool cacheValid = true;
    testNode->ResetChildrenFilterRects();
    testNode->UpdateChildrenFilterRects(filterNode, rect, cacheValid);
    testNode->UpdateChildrenFilterRects(filterNode, RectI(), cacheValid);
    const std::vector<RectI>& filterRects = testNode->GetChildrenNeedFilterRects();
    ASSERT_EQ(filterRects.size(), 1);
}

/**
 * @tc.name: UpdateChildrenFilterRects
 * @tc.desc: test results of UpdateChildrenFilterRects
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateAbilityNodeIds, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->UpdateAbilityNodeIds(1, true);
    EXPECT_TRUE(node->GetAbilityNodeIds().count(1) == 1);
    std::unordered_set<NodeId> nodeIds;
    node->AddAbilityComponentNodeIds(nodeIds);
    node->ResetAbilityNodeIds();
    node->UpdateAbilityNodeIds(1, false);
    EXPECT_TRUE(node->GetAbilityNodeIds().empty());
}

/**
 * @tc.name: UpdateChildHardwareEnabledNode
 * @tc.desc: test results of UpdateChildHardwareEnabledNode
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateChildHardwareEnabledNode, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->UpdateChildHardwareEnabledNode(1, false);
    node->UpdateChildHardwareEnabledNode(1, true);
    ASSERT_TRUE(node->GetNeedCollectHwcNode());
}

/**
 * @tc.name: SetHwcChildrenDisabledStateByUifirst
 * @tc.desc: test results of SetHwcChildrenDisabledStateByUifirst
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetHwcChildrenDisabledStateByUifirst, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->SetHwcChildrenDisabledStateByUifirst();
    ASSERT_TRUE(node->childHardwareEnabledNodes_.size() == 0);
}

/**
 * @tc.name: OnApplyModifiers
 * @tc.desc: test results of OnApplyModifiers
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, OnApplyModifiers, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->OnApplyModifiers();
    auto& properties = node->GetMutableRenderProperties();
    ASSERT_EQ(properties.GetAlpha(), properties.GetAlpha() * node->contextAlpha_);
}

/**
 * @tc.name: LeashWindowRelatedAppWindowOccluded
 * @tc.desc: test results of LeashWindowRelatedAppWindowOccluded
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, LeashWindowRelatedAppWindowOccluded, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> appNode;
    ASSERT_FALSE(node->LeashWindowRelatedAppWindowOccluded(appNode));
}

/**
 * @tc.name: GetLeashWindowNestedSurfaces
 * @tc.desc: test results of GetLeashWindowNestedSurfaces
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetLeashWindowNestedSurfaces, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_TRUE(node->GetLeashWindowNestedSurfaces().size() == 0);
}

/**
 * @tc.name: IsUIFirstSelfDrawCheck
 * @tc.desc: test results of IsUIFirstSelfDrawCheck
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsUIFirstSelfDrawCheck, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_TRUE(node->IsUIFirstSelfDrawCheck());
}

/**
 * @tc.name: IsCurFrameStatic
 * @tc.desc: test results of IsCurFrameStatic
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    DeviceType deviceType = DeviceType::PHONE;
    bool res = node->IsCurFrameStatic(deviceType);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: IsVisibleDirtyEmpty
 * @tc.desc: test results of IsVisibleDirtyEmpty
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsVisibleDirtyEmpty, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    DeviceType deviceType = DeviceType::PHONE;
    bool res = node->IsVisibleDirtyEmpty(deviceType);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: UpdateCacheSurfaceDirtyManager
 * @tc.desc: test results of UpdateCacheSurfaceDirtyManager
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateCacheSurfaceDirtyManager, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    int bufferAge = 1;
    node->UpdateCacheSurfaceDirtyManager(bufferAge);
    ASSERT_NE(node->cacheSurfaceDirtyManager_, nullptr);
}

/**
 * @tc.name: SetIsOnTheTree
 * @tc.desc: test results of SetIsOnTheTree
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetIsOnTheTree, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    bool flag = true;
    NodeId instanceRootNodeId = 1;
    NodeId firstLevelNodeId = 1;
    NodeId cacheNodeId = 1;
    node->SetIsOnTheTree(flag, instanceRootNodeId, firstLevelNodeId, cacheNodeId);
    ASSERT_EQ(node->GetId(), 0);
}

/**
 * @tc.name: HasOnlyOneRootNode
 * @tc.desc: test results of HasOnlyOneRootNode
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, HasOnlyOneRootNode, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    bool res = node->HasOnlyOneRootNode();
    ASSERT_FALSE(res);
}

/**
 * @tc.name: GetNodeIsSingleFrameComposer
 * @tc.desc: test results of GetNodeIsSingleFrameComposer
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetNodeIsSingleFrameComposer, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    bool res = node->GetNodeIsSingleFrameComposer();
    ASSERT_FALSE(res);
}

/**
 * @tc.name: QuerySubAssignable
 * @tc.desc: test results of QuerySubAssignable
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, QuerySubAssignable, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    bool isRotation = true;
    bool res = node->QuerySubAssignable(isRotation);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: GetGravityTranslate
 * @tc.desc: test results of GetGravityTranslate
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetGravityTranslate, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    float imgWidth = 1.0f;
    float imgHeight = 1.0f;
    node->GetGravityTranslate(imgWidth, imgHeight);
    ASSERT_FALSE(node->IsLeashWindow());
}

/**
 * @tc.name: SetOcclusionVisible
 * @tc.desc: test results of SetOcclusionVisible
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetOcclusionVisible, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    bool visible = true;
    node->SetOcclusionVisible(visible);
    node->InitRenderParams();
    node->addedToPendingSyncList_ = true;
    node->SetOcclusionVisible(visible);
    ASSERT_TRUE(node->isOcclusionVisible_);
}

/**
 * @tc.name: UpdatePartialRenderParams
 * @tc.desc: test results of UpdatePartialRenderParams
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdatePartialRenderParams, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->UpdatePartialRenderParams();
    node->UpdateRenderParams();
    node->UpdateAncestorDisplayNodeInRenderParams();
    node->SetUifirstChildrenDirtyRectParam(RectI());
    node->SetUifirstNodeEnableParam(MultiThreadCacheType::NONE);
    node->SetIsParentUifirstNodeEnableParam(true);
    ASSERT_EQ(node->stagingRenderParams_.get(), nullptr);
}

/**
 * @tc.name: InitRenderParams
 * @tc.desc: test results of InitRenderParams
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, InitRenderParams, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->InitRenderParams();
    ASSERT_NE(node->stagingRenderParams_.get(), nullptr);
}

/**
 * @tc.name: GetHasTransparentSurface
 * @tc.desc: test results of GetHasTransparentSurface
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetHasTransparentSurface, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->SetHasSharedTransitionNode(true);
    ASSERT_TRUE(node->GetHasSharedTransitionNode());
    ASSERT_FALSE(node->GetHasTransparentSurface());
}

/**
 * @tc.name: GetCacheSurfaceProcessedStatus
 * @tc.desc: test results of GetCacheSurfaceProcessedStatus
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetCacheSurfaceProcessedStatus, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    CacheProcessStatus cacheProcessStatus = CacheProcessStatus::DOING;
    node->SetCacheSurfaceProcessedStatus(cacheProcessStatus);
    ASSERT_EQ(node->GetCacheSurfaceProcessedStatus(), cacheProcessStatus);
}

/**
 * @tc.name: IsUIFirstCacheReusable
 * @tc.desc: test results of IsUIFirstCacheReusable
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsUIFirstCacheReusable, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    DeviceType deviceType = DeviceType::PHONE;
    node->GetContextClipRegion();
    ASSERT_FALSE(node->IsHistoryOccludedDirtyRegionNeedSubmit());
    node->ClearHistoryUnSubmittedDirtyInfo();
    ASSERT_FALSE(node->hasUnSubmittedOccludedDirtyRegion_);
    node->UpdateHistoryUnsubmittedDirtyInfo();
    ASSERT_TRUE(node->hasUnSubmittedOccludedDirtyRegion_);
    ASSERT_FALSE(node->IsUIFirstCacheReusable(deviceType));
}

/**
 * @tc.name: GetLocalZOrder
 * @tc.desc: test results of GetLocalZOrder
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetLocalZOrder, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    float localZOrder = 1.0f;
    node->SetLocalZOrder(localZOrder);
    ASSERT_EQ(node->GetLocalZOrder(), localZOrder);
}

/**
 * @tc.name: GetChildHardwareEnabledNodes
 * @tc.desc: test results of GetChildHardwareEnabledNodes
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetChildHardwareEnabledNodes, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    std::weak_ptr<RSSurfaceRenderNode> childNode = std::make_shared<RSSurfaceRenderNode>(id + 1);
    node->AddChildHardwareEnabledNode(childNode);
    node->ResetChildHardwareEnabledNodes();
    ASSERT_EQ(node->GetChildHardwareEnabledNodes().size(), 0);
}

/**
 * @tc.name: UpdateSurfaceCacheContentStatic
 * @tc.desc: test results of UpdateSurfaceCacheContentStatic
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, UpdateSurfaceCacheContentStatic001, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->UpdateSurfaceCacheContentStatic();
    ASSERT_EQ(node->dirtyContentNodeNum_, 0);
}

/**
 * @tc.name: GetChildrenNeedFilterRectsCacheValid
 * @tc.desc: test results of GetChildrenNeedFilterRectsCacheValid
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetChildrenNeedFilterRectsCacheValid, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_EQ(node->GetChildrenFilterNodes().size(), 0);
    ASSERT_EQ(node->GetChildrenNeedFilterRectsCacheValid().size(), 0);
}

/**
 * @tc.name: CheckOpaqueRegionBaseInfo
 * @tc.desc: test results of CheckOpaqueRegionBaseInfo
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, CheckOpaqueRegionBaseInfo, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    RectI screeninfo;
    RectI absRect;
    ScreenRotation screenRotation = ScreenRotation::ROTATION_0;
    bool isFocusWindow = true;
    Vector4<int> cornerRadius;
    ASSERT_FALSE(node->CheckOpaqueRegionBaseInfo(screeninfo, absRect, screenRotation, isFocusWindow, cornerRadius));
    bool hasContainer = true;
    float density = 1.0f;
    node->containerConfig_.Update(hasContainer, density);
    node->InitRenderParams();
    node->addedToPendingSyncList_ = true;
    node->isHardwareForcedDisabled_ = true;
    node->UpdateHardwareDisabledState(true);
    ASSERT_FALSE(node->opaqueRegionBaseInfo_.hasContainerWindow_);
    node->UpdateOccludedByFilterCache(false);
    ASSERT_FALSE(node->IsOccludedByFilterCache());
    ASSERT_TRUE(node->IsSCBNode());
    ASSERT_FALSE(node->CheckIfOcclusionChanged());
}

/**
 * @tc.name: NeedSetCallbackForRenderThreadRefresh
 * @tc.desc: test results of NeedSetCallbackForRenderThreadRefresh
 * @tc.type: FUNC
 * @tc.require: issueI9L0VL
 */
HWTEST_F(RSSurfaceRenderNodeTest, NeedSetCallbackForRenderThreadRefresh, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(id);
    node->SetStartAnimationFinished();
    ASSERT_TRUE(node->IsStartAnimationFinished());

    node->SetCallbackForRenderThreadRefresh(true);
    ASSERT_FALSE(node->NeedSetCallbackForRenderThreadRefresh());
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

/**
 * @tc.name: IsCurFrameStatic001
 * @tc.desc: Test IsCurFrameStatic when DeviceType is PC.
 * @tc.type: FUNC
 * @tc.require: issueI9P0BR
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic001, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    bool result = node->IsCurFrameStatic(DeviceType::PC);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: IsCurFrameStatic002
 * @tc.desc: Test IsCurFrameStatic when DeviceType is PHONE.
 * @tc.type: FUNC
 * @tc.require: issueI9P0BR
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic002, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    bool result = node->IsCurFrameStatic(DeviceType::PHONE);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: IsCurFrameStatic003
 * @tc.desc: Test IsCurFrameStatic when node is leashwiNode
 * @tc.type: FUNC
 * @tc.require: issueI9P0BR
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic003, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);
    node->surfaceCacheContentStatic_ = true;
    node->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    bool result = node->IsCurFrameStatic(DeviceType::PC);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: IsCurFrameStatic004
 * @tc.desc: Test IsCurFrameStatic when node is selfDrawingNode
 * @tc.type: FUNC
 * @tc.require: issueI9P0BR
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic004, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);
    node->surfaceCacheContentStatic_ = true;
    node->nodeType_ = RSSurfaceNodeType::SELF_DRAWING_NODE;
    bool result = node->IsCurFrameStatic(DeviceType::PC);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: IsCurFrameStatic005
 * @tc.desc: Test IsCurFrameStatic when childNode is contentStatic
 * @tc.type: FUNC
 * @tc.require: issueI9P0BR
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic005, TestSize.Level2)
{
    auto leash = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(leash, nullptr);
    leash->surfaceCacheContentStatic_ = true;
    leash->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    auto app = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    ASSERT_NE(app, nullptr);
    app->surfaceCacheContentStatic_ = true;
    app->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;

    leash->AddChild(app);
    leash->GenerateFullChildrenList();
    leash->lastFrameChildrenCnt_ = 1;
    bool result = leash->IsCurFrameStatic(DeviceType::PC);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: IsCurFrameStatic006
 * @tc.desc: Test IsCurFrameStatic when lastFrameChildrenCnt_ is 0
 * @tc.type: FUNC
 * @tc.require: issueI9P0BR
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic006, TestSize.Level2)
{
    auto leash = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(leash, nullptr);
    leash->surfaceCacheContentStatic_ = true;
    leash->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    auto app = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    ASSERT_NE(app, nullptr);
    app->surfaceCacheContentStatic_ = true;
    app->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;

    leash->AddChild(app);
    leash->GenerateFullChildrenList();
    bool result = leash->IsCurFrameStatic(DeviceType::PC);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: IsCurFrameStatic007
 * @tc.desc: Test IsCurFrameStatic when lastFrameChildrenCnt_ is 0
 * @tc.type: FUNC
 * @tc.require: issueI9P0BR
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic007, TestSize.Level2)
{
    auto leash = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(leash, nullptr);
    leash->surfaceCacheContentStatic_ = true;
    leash->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    auto app = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    ASSERT_NE(app, nullptr);
    app->surfaceCacheContentStatic_ = false;
    app->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;

    leash->AddChild(app);
    leash->GenerateFullChildrenList();
    bool result = leash->IsCurFrameStatic(DeviceType::PC);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: IsCurFrameStatic008
 * @tc.desc: Test IsCurFrameStatic when childNode is not contentStatic
 * @tc.type: FUNC
 * @tc.require: issueI9P0BR
 */
HWTEST_F(RSSurfaceRenderNodeTest, IsCurFrameStatic008, TestSize.Level2)
{
    auto leash = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(leash, nullptr);
    leash->surfaceCacheContentStatic_ = true;
    leash->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    auto app = std::make_shared<RSSurfaceRenderNode>(id + 1, context);
    ASSERT_NE(app, nullptr);
    app->surfaceCacheContentStatic_ = false;
    app->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;

    leash->AddChild(app);
    leash->GenerateFullChildrenList();
    leash->lastFrameChildrenCnt_ = 1;
    bool result = leash->IsCurFrameStatic(DeviceType::PC);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: SetDoDirectComposition001
 * @tc.desc: Test SetDoDirectComposition
 * @tc.type: FUNC
 * @tc.require: issueI9Q8E9
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetDoDirectComposition001, TestSize.Level2)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(id, context);
    ASSERT_NE(node, nullptr);

    node->SetDoDirectComposition(false);
    ASSERT_EQ(node->GetDoDirectComposition(), false);

    node->SetDoDirectComposition(true);
    ASSERT_EQ(node->GetDoDirectComposition(), true);
}

/**
 * @tc.name: SetSkipDraw001
 * @tc.desc: Test function SetSkipDraw
 * @tc.type: FUNC
 * @tc.require: issueI9U6LX
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetSkipDraw001, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    ASSERT_NE(node, nullptr);

    node->SetSkipDraw(true);
    ASSERT_TRUE(node->GetSkipDraw());

    node->SetSkipDraw(false);
    ASSERT_FALSE(node->GetSkipDraw());
}

/**
 * @tc.name: SetSkipDraw001
 * @tc.desc: Test function SetSkipDraw
 * @tc.type: FUNC
 * @tc.require: issueI9U6LX
 */
HWTEST_F(RSSurfaceRenderNodeTest, GetSkipDraw001, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    ASSERT_NE(rsContext, nullptr);
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    ASSERT_NE(node, nullptr);

    ASSERT_FALSE(node->GetSkipDraw());
}

/**
 * @tc.name: SetRootIdOfCaptureWindow
 * @tc.desc: test results of SetRootIdOfCaptureWindow
 * @tc.type:FUNC
 * @tc.require:issueI981R9
 */
HWTEST_F(RSSurfaceRenderNodeTest, SetRootIdOfCaptureWindow, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    auto rootId = id + 1; // 1 : generate a rootId for CaptureWindow
    node->SetRootIdOfCaptureWindow(rootId);
    ASSERT_EQ(node->GetRootIdOfCaptureWindow(), rootId);
    node->InitRenderParams();
    node->SetRootIdOfCaptureWindow(rootId);
    ASSERT_EQ(node->GetStagingRenderParams()->GetRootIdOfCaptureWindow(), rootId);
}

/**
 * @tc.name: RotateCorner001
 * @tc.desc: test results of RotateCorner
 * @tc.type:FUNC
 * @tc.require:issueIAIAQ0
 */
HWTEST_F(RSSurfaceRenderNodeTest, RotateCorner001, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    constexpr int firstCornerRadius{1};
    constexpr int secondCornerRadius{2};
    constexpr int thirdCornerRadius{3};
    constexpr int fourthCornerRadius{4};

    Vector4<int> cornerRadius1{firstCornerRadius, secondCornerRadius, thirdCornerRadius, fourthCornerRadius};
    node->RotateCorner(RS_ROTATION_0, cornerRadius1);
    EXPECT_TRUE(cornerRadius1 == Vector4<int>(
        firstCornerRadius, secondCornerRadius, thirdCornerRadius, fourthCornerRadius));
    
    Vector4<int> cornerRadius2{firstCornerRadius, secondCornerRadius, thirdCornerRadius, fourthCornerRadius};
    node->RotateCorner(RS_ROTATION_90, cornerRadius2);
    EXPECT_TRUE(cornerRadius2 == Vector4<int>(
        fourthCornerRadius, firstCornerRadius, secondCornerRadius, thirdCornerRadius));
    
    Vector4<int> cornerRadius3{firstCornerRadius, secondCornerRadius, thirdCornerRadius, fourthCornerRadius};
    node->RotateCorner(RS_ROTATION_180, cornerRadius3);
    EXPECT_TRUE(cornerRadius3 == Vector4<int>(
        thirdCornerRadius, fourthCornerRadius, firstCornerRadius, secondCornerRadius));
    
    Vector4<int> cornerRadius4{firstCornerRadius, secondCornerRadius, thirdCornerRadius, fourthCornerRadius};
    node->RotateCorner(RS_ROTATION_270, cornerRadius4);
    EXPECT_TRUE(cornerRadius4 == Vector4<int>(
        secondCornerRadius, thirdCornerRadius, fourthCornerRadius, firstCornerRadius));
}
} // namespace Rosen
} // namespace OHOS