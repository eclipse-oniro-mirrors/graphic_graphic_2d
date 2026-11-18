/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "animation/rs_render_property_animation.h"
#include "params/rs_logical_display_render_params.h"
#include "pipeline/rs_canvas_render_node.h"
#include "pipeline/rs_context.h"
#include "pipeline/rs_logical_display_render_node.h"
#include "pipeline/rs_root_render_node.h"
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_draw_cmd.h"
#include "render_thread/rs_render_thread_visitor.h"
#include "visitor/rs_node_visitor.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class RSRenderPropertyAnimationMock : public RSRenderPropertyAnimation {
public:
    RSRenderPropertyAnimationMock(
        AnimationId id, const PropertyId& propertyId,
        const std::shared_ptr<RSRenderPropertyBase>& originValue)
        : RSRenderPropertyAnimation(id, propertyId, originValue)
    {}
    void RebuildPropertyValue(float fraction) override {}
};

class RSRenderNodeDrawableAdapterMock : public DrawableV2::RSRenderNodeDrawableAdapter {
public:
    explicit RSRenderNodeDrawableAdapterMock(std::shared_ptr<const RSRenderNode> node)
        : RSRenderNodeDrawableAdapter(std::move(node))
    {}
    void Draw(Drawing::Canvas&) override {}
};

class RSLogicalDisplayRenderNodeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    // Builds record fixture nodes with the drawable, tree flag and display stamp the snapshot walk reads,
    // registering each node in the context map; stampedDisplayId stamps a deliberately stale display.
    static std::shared_ptr<RSLogicalDisplayRenderNode> CreateRecordDisplay(
        const std::shared_ptr<RSContext>& rsContext, NodeId id);
    static std::shared_ptr<RSSurfaceRenderNode> CreateRecordSurface(const std::shared_ptr<RSContext>& rsContext,
        const std::shared_ptr<RSRenderNode>& parent, NodeId id, RSSurfaceNodeType type, bool onTree,
        bool shouldPaint = true, bool withDrawable = true, NodeId stampedDisplayId = INVALID_NODEID);

    static inline NodeId id;
    static inline std::weak_ptr<RSContext> context = {};
    static inline Drawing::Canvas canvas;
};

void RSLogicalDisplayRenderNodeTest::SetUpTestCase() {}
void RSLogicalDisplayRenderNodeTest::TearDownTestCase() {}
void RSLogicalDisplayRenderNodeTest::SetUp() {}
void RSLogicalDisplayRenderNodeTest::TearDown() {}

std::shared_ptr<RSLogicalDisplayRenderNode> RSLogicalDisplayRenderNodeTest::CreateRecordDisplay(
    const std::shared_ptr<RSContext>& rsContext, NodeId id)
{
    RSDisplayNodeConfig config;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(id, config, rsContext);
    display->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(display);
    rsContext->GetMutableNodeMap().renderNodeMap_[ExtractPid(display->GetId())][display->GetId()] = display;
    return display;
}

std::shared_ptr<RSSurfaceRenderNode> RSLogicalDisplayRenderNodeTest::CreateRecordSurface(
    const std::shared_ptr<RSContext>& rsContext, const std::shared_ptr<RSRenderNode>& parent, NodeId id,
    RSSurfaceNodeType type, bool onTree, bool shouldPaint, bool withDrawable, NodeId stampedDisplayId)
{
    RSSurfaceRenderNodeConfig config { .id = id, .nodeType = type };
    auto node = std::make_shared<RSSurfaceRenderNode>(config, rsContext);
    if (withDrawable) {
        node->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(node);
    }
    node->isOnTheTree_ = onTree;
    node->logicalDisplayNodeId_ = stampedDisplayId == INVALID_NODEID ? parent->GetId() : stampedDisplayId;
    node->shouldPaint_ = shouldPaint;
    parent->AddChild(node);
    rsContext->GetMutableNodeMap().renderNodeMap_[ExtractPid(node->GetId())][node->GetId()] = node;
    return node;
}

/**
 * @tc.name: QuickPrepareTest
 * @tc.desc: test results of QuickPrepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, QuickPrepareTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    std::shared_ptr<RSNodeVisitor> visitor;
    EXPECT_EQ(visitor, nullptr);
    renderNode->QuickPrepare(visitor);

    visitor = std::make_shared<RSRenderThreadVisitor>();
    renderNode->QuickPrepare(visitor);
}

/**
 * @tc.name: PrepareTest
 * @tc.desc: test results of Prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, PrepareTest, TestSize.Level0)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    std::shared_ptr<RSNodeVisitor> visitor;
    EXPECT_EQ(visitor, nullptr);
    renderNode->Prepare(visitor);

    visitor = std::make_shared<RSRenderThreadVisitor>();
    renderNode->Prepare(visitor);
}

/**
 * @tc.name: ProcessTest
 * @tc.desc: test results of Process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, ProcessTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    std::shared_ptr<RSNodeVisitor> visitor;
    EXPECT_EQ(visitor, nullptr);
    renderNode->Process(visitor);
    
    visitor = std::make_shared<RSRenderThreadVisitor>();
    renderNode->Process(visitor);
}

/**
 * @tc.name: UpdateRenderParamsTest
 * @tc.desc: test results of UpdateRenderParams
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, UpdateRenderParamsTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_NE(renderNode, nullptr);
    renderNode->stagingRenderParams_ = nullptr;
    renderNode->UpdateRenderParams();

    std::shared_ptr<RSLogicalDisplayRenderNode> tempNode;
    renderNode->mirrorSource_ = tempNode;
    renderNode->UpdateRenderParams();

    constexpr NodeId newNodeId = 2;
    auto rsDisplayRenderNode = std::make_shared<RSLogicalDisplayRenderNode>(newNodeId, config);
    renderNode->mirrorSource_ = rsDisplayRenderNode;
}

/**
 * @tc.name: SetWindowContainerTest
 * @tc.desc: test results of SetWindowContainer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, SetWindowContainerTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->SetWindowContainer(nullptr);
    EXPECT_EQ(renderNode->windowContainer_, nullptr);

    NodeId rootId = 1;
    auto rootNode = std::make_shared<RSBaseRenderNode>(rootId);
    renderNode->SetWindowContainer(rootNode);
    EXPECT_NE(renderNode->windowContainer_, nullptr);

    NodeId newRootId = 2;
    auto newRootNode = std::make_shared<RSBaseRenderNode>(newRootId);
    renderNode->SetWindowContainer(newRootNode);
    EXPECT_NE(renderNode->windowContainer_, nullptr);

    renderNode->SetWindowContainer(nullptr);
}

/**
 * @tc.name: IsOnlyHDRAnimationTest
 * @tc.desc: test results of IsOnlyHDRAnimation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, IsOnlyHDRAnimationTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_EQ(displayNode->GetModifiersNG(ModifierNG::RSModifierType::HDR_BRIGHTNESS).empty(), true);
    EXPECT_EQ(displayNode->IsOnlyHDRAnimation(), false);

    std::shared_ptr<Drawing::DrawCmdList> drawCmdList = nullptr;
    auto property = std::make_shared<RSRenderProperty<Drawing::DrawCmdListPtr>>();
    property->GetRef() = drawCmdList;
    property->id_ = 1;
    ModifierId id = 1;
    std::shared_ptr<ModifierNG::RSRenderModifier> modifier = nullptr;
    RSRootRenderNode::ModifierNGContainer modifiers { modifier };
    EXPECT_EQ(displayNode->IsOnlyHDRAnimation(), false);

    auto modifier2 = ModifierNG::RSRenderModifier::MakeRenderModifier(
        ModifierNG::RSModifierType::HDR_BRIGHTNESS, property, id, ModifierNG::RSPropertyType::HDR_BRIGHTNESS_FACTOR);
    modifiers.emplace_back(modifier2);
    displayNode->modifiersNG_.emplace(ModifierNG::RSModifierType::HDR_BRIGHTNESS, modifiers);
    auto animationProperty = std::make_shared<RSRenderAnimatableProperty<float>>(0.0f);
    auto renderPropertyAnimation = std::make_shared<RSRenderPropertyAnimationMock>(0, 1, animationProperty);
    displayNode->animationManager_ = std::make_shared<RSAnimationManager>();
    displayNode->animationManager_->animations_[0] = renderPropertyAnimation;
    displayNode->IsOnlyHDRAnimation();

    auto modifier3 = ModifierNG::RSRenderModifier::MakeRenderModifier(
        ModifierNG::RSModifierType::HDR_BRIGHTNESS, property, id, ModifierNG::RSPropertyType::HDR_BRIGHTNESS);
    modifiers.emplace_back(modifier3);
    renderPropertyAnimation->propertyId_ = 2;
    std::shared_ptr<RSRenderAnimation> animation2;
    displayNode->animationManager_->animations_[1] = animation2;
    displayNode->IsOnlyHDRAnimation();
}

/**
 * @tc.name: GetWindowContainerTest
 * @tc.desc: test results of GetWindowContainer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, GetWindowContainerTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_EQ(renderNode->GetWindowContainer(), nullptr);
}

/**
 * @tc.name: GetRotationTest
 * @tc.desc: test results of GetRotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, GetRotationTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->renderProperties_.boundsGeo_ = nullptr;
    EXPECT_EQ(renderNode->GetRotation(), ScreenRotation::ROTATION_0);
    renderNode->renderProperties_.boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    EXPECT_EQ(renderNode->GetRotation(), ScreenRotation::ROTATION_0);
}

/**
 * @tc.name: IsRotationChangedTest
 * @tc.desc: test results of IsRotationChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, IsRotationChangedTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->renderProperties_.boundsGeo_ = nullptr;
    EXPECT_FALSE(renderNode->IsRotationChanged());
    renderNode->renderProperties_.boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    EXPECT_FALSE(renderNode->IsRotationChanged());
}

/**
 * @tc.name: UpdateRotationTest
 * @tc.desc: test results of UpdateRotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, UpdateRotationTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_NE(renderNode, nullptr);
    renderNode->stagingRenderParams_ = nullptr;
    renderNode->UpdateRotation();
    renderNode->stagingRenderParams_ = std::make_unique<RSRenderParams>(nodeId);
    renderNode->UpdateRotation();
    renderNode->renderProperties_.boundsGeo_ = nullptr;
    renderNode->UpdateRotation();
    renderNode->renderProperties_.boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    renderNode->UpdateRotation();
}

/**
 * @tc.name: IsLastRotationChangedTest
 * @tc.desc: test results of IsLastRotationChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, IsLastRotationChangedTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_FALSE(renderNode->IsLastRotationChanged());
}

/**
 * @tc.name: GetPreRotationStatusTest
 * @tc.desc: test results of GetPreRotationStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, GetPreRotationStatusTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_FALSE(renderNode->GetPreRotationStatus());
}

/**
 * @tc.name: GetCurRotationStatusTest
 * @tc.desc: test results of GetCurRotationStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, GetCurRotationStatusTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_FALSE(renderNode->GetCurRotationStatus());
}

/**
 * @tc.name: UpdateOffscreenRenderParamsTest
 * @tc.desc: test results of UpdateOffscreenRenderParams
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, UpdateOffscreenRenderParamsTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->UpdateOffscreenRenderParams(false);
    EXPECT_NE(renderNode, nullptr);
}

/**
 * @tc.name: SetMirrorSourceTest
 * @tc.desc: test results of SetMirrorSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, SetMirrorSourceTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    std::weak_ptr<RSContext> context = {};

    constexpr NodeId newNodeId = 2;
    auto rsDisplayRenderNode = std::make_shared<RSLogicalDisplayRenderNode>(newNodeId, config);
    renderNode->SetDisplayMode(DisplayMode::MIRROR);
    renderNode->SetMirrorSource(nullptr);
    renderNode->SetMirrorSource(rsDisplayRenderNode);

    renderNode->SetDisplayMode(DisplayMode::EXPAND);
    renderNode->SetMirrorSource(nullptr);
    renderNode->SetMirrorSource(rsDisplayRenderNode);
    EXPECT_NE(renderNode->mirrorSource_.lock(), nullptr);
}

/**
 * @tc.name: SetDisplayModeTest
 * @tc.desc: test results of SetDisplayMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, SetDisplayModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->SetDisplayMode(DisplayMode::MIRROR);
    EXPECT_EQ(renderNode->GetDisplayMode(), DisplayMode::MIRROR);
}

/**
 * @tc.name: GetDisplayModeTest
 * @tc.desc: test results of GetDisplayMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, GetDisplayModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_EQ(renderNode->GetDisplayMode(), DisplayMode::INVALID);
}

/**
 * @tc.name: SetVirtualScreenMuteStatusTest
 * @tc.desc: test results of SetVirtualScreenMuteStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, SetVirtualScreenMuteStatusTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->SetVirtualScreenMuteStatus(true);
    EXPECT_TRUE(renderNode->virtualScreenMuteStatus_);
}

/**
 * @tc.name: GetVirtualScreenMuteStatusTest
 * @tc.desc: test results of GetVirtualScreenMuteStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, GetVirtualScreenMuteStatusTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_FALSE(renderNode->GetVirtualScreenMuteStatus());
}

/**
 * @tc.name: UpdateRenderParamsSyncsMuteWithoutMirrorSourceTest
 * @tc.desc: virtual screen mute status reaches the staging params even without a mirror source
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, UpdateRenderParamsSyncsMuteWithoutMirrorSourceTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->InitRenderParams();
    ASSERT_NE(renderNode->stagingRenderParams_, nullptr);
    ASSERT_TRUE(renderNode->GetMirrorSource().expired());
    auto params = static_cast<RSLogicalDisplayRenderParams*>(renderNode->stagingRenderParams_.get());
    ASSERT_NE(params, nullptr);
    EXPECT_FALSE(params->GetVirtualScreenMuteStatus());

    renderNode->SetVirtualScreenMuteStatus(true);
    renderNode->UpdateRenderParams();
    EXPECT_TRUE(params->GetVirtualScreenMuteStatus());

    renderNode->SetVirtualScreenMuteStatus(false);
    renderNode->UpdateRenderParams();
    EXPECT_FALSE(params->GetVirtualScreenMuteStatus());
}

/**
 * @tc.name: GetSpecialLayerMgrTest
 * @tc.desc: test results of GetSpecialLayerMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, GetSpecialLayerMgrTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_NE(renderNode, nullptr);
    renderNode->GetSpecialLayerMgr();
}

/**
 * @tc.name: AddSecurityLayerTest
 * @tc.desc: test results of AddSecurityLayer and GetSecurityLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, AddSecurityLayerTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    constexpr NodeId newNodeId = 2;
    renderNode->AddSecurityLayer(newNodeId);
    EXPECT_FALSE(renderNode->GetSecurityLayerList().empty());
}

/**
 * @tc.name: AddSecurityVisibleLayerTest
 * @tc.desc: test results of AddSecurityVisibleLayer and GetSecurityVisibleLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, AddSecurityVisibleLayerTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    constexpr NodeId newNodeId = 2;
    renderNode->AddSecurityVisibleLayer(newNodeId);
    EXPECT_FALSE(renderNode->GetSecurityVisibleLayerList().empty());
}

/**
 * @tc.name: SetSecurityExemptionTest
 * @tc.desc: test results of SetSecurityExemption and GetSecurityExemption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, SetSecurityExemption, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->SetSecurityExemption(true);
    EXPECT_TRUE(renderNode->GetSecurityExemption());
}

/**
 * @tc.name: ResetMirrorSourceKeepsSecurityExemption
 * @tc.desc: Verify mirror-source reset alone does not alter security exemption state
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, ResetMirrorSourceKeepsSecurityExemption, TestSize.Level1)
{
    constexpr NodeId nodeId = 2;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->SetSecurityExemption(true);
    renderNode->ResetMirrorSource();
    EXPECT_TRUE(renderNode->GetSecurityExemption());
}

/**
 * @tc.name: WindowRecordSnapshotUpdatesSecurityExemption
 * @tc.desc: Verify record computes exemption from its output screen and source display lists
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordSnapshotUpdatesSecurityExemption, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr ScreenId screenId = 500;
    constexpr NodeId screenNodeId = 50;
    constexpr NodeId sourceDisplayId = 51;
    constexpr NodeId recordDisplayId = 52;
    constexpr NodeId mainId = 53;
    constexpr NodeId securityLayerId = 54;
    constexpr NodeId otherLayerId = 55;
    auto screen = std::make_shared<RSScreenRenderNode>(screenNodeId, screenId, rsContext);
    screen->screenProperty_.Set<ScreenPropertyType::IS_VIRTUAL>(true);
    screen->screenProperty_.Set<ScreenPropertyType::SECURITY_EXEMPTION_LIST>(
        std::vector<NodeId>{ securityLayerId });
    RSDisplayNodeConfig displayConfig;
    displayConfig.screenId = screenId;
    auto sourceDisplay = std::make_shared<RSLogicalDisplayRenderNode>(sourceDisplayId, displayConfig, rsContext);
    sourceDisplay->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(sourceDisplay);
    sourceDisplay->AddSecurityLayer(securityLayerId);
    auto recordDisplay = std::make_shared<RSLogicalDisplayRenderNode>(recordDisplayId, displayConfig, rsContext);
    screen->AddChild(recordDisplay);

    RSSurfaceRenderNodeConfig mainConfig { .id = mainId, .nodeType = RSSurfaceNodeType::APP_WINDOW_NODE };
    auto mainNode = std::make_shared<RSSurfaceRenderNode>(mainConfig, rsContext);
    mainNode->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(mainNode);
    mainNode->isOnTheTree_ = true;
    sourceDisplay->AddChild(mainNode);
    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.renderNodeMap_[ExtractPid(sourceDisplayId)][sourceDisplayId] = sourceDisplay;
    nodeMap.renderNodeMap_[ExtractPid(mainId)][mainId] = mainNode;

    recordDisplay->SetWindowRecordConfig({ .surfaceNodeIds = { mainId } });
    RSLogicalDisplayRenderParams params(recordDisplayId);
    recordDisplay->ResolveWindowRecordSnapshot(params);
    EXPECT_TRUE(recordDisplay->GetSecurityExemption());
    EXPECT_TRUE(params.GetSecurityExemption());

    screen->screenProperty_.Set<ScreenPropertyType::SECURITY_EXEMPTION_LIST>(
        std::vector<NodeId>{ otherLayerId });
    RSLogicalDisplayRenderParams notExemptParams(recordDisplayId);
    recordDisplay->ResolveWindowRecordSnapshot(notExemptParams);
    EXPECT_FALSE(recordDisplay->GetSecurityExemption());
    EXPECT_FALSE(notExemptParams.GetSecurityExemption());
}

/**
 * @tc.name: SetHasSecLayerInVisibleRectTest
 * @tc.desc: test results of SetHasSecLayerInVisibleRect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, SetHasSecLayerInVisibleRectTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->SetHasSecLayerInVisibleRect(true);
    EXPECT_TRUE(renderNode->hasSecLayerInVisibleRect_);
}

/**
 * @tc.name: GetDisplayModeDefaultTest
 * @tc.desc: test results of GetDisplayMode default value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, GetDisplayModeDefaultTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_EQ(renderNode->GetDisplayMode(), DisplayMode::INVALID);
}

/**
 * @tc.name: ClearModifiersByPidTest
 * @tc.desc: test results of ClearModifiersByPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, ClearModifiersByPidTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    EXPECT_NE(renderNode, nullptr);
    int32_t pid = getpid();
    renderNode->ClearModifiersByPid(pid);
}

/**
 * @tc.name: UpdateDimensionsTest
 * @tc.desc: test results of UpdateDimensions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, UpdateDimensionsTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    renderNode->InitRenderParams();
    auto& geo = renderNode->GetRenderProperties().GetBoundsGeometry();
    geo->SetRotation(90);
    renderNode->UpdateRotation();
    renderNode->UpdateFixedSize();

    renderNode->UpdateRotation();
    renderNode->UpdateFixedSize();

    geo->SetRotation(270);
    renderNode->UpdateRotation();
    renderNode->UpdateRotation();
    renderNode->UpdateFixedSize();
    // Composite type is now managed by RSScreenRenderNode, not RSLogicalDisplayRenderNode
    // Test display mode instead
    EXPECT_EQ(renderNode->GetDisplayMode(), DisplayMode::INVALID);
}

/**
 * @tc.name: IsOnlyHDRAnimationWithNullManager001
 * @tc.desc: Verify IsOnlyHDRAnimation returns false with null animationManager and HDR modifiers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, IsOnlyHDRAnimationWithNullManager001, TestSize.Level1)
{
    NodeId nodeId = 0;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);

    // Add HDR modifiers but NO animationManager (don't add any animation)
    std::shared_ptr<Drawing::DrawCmdList> drawCmdList = nullptr;
    auto property = std::make_shared<RSRenderProperty<Drawing::DrawCmdListPtr>>();
    property->GetRef() = drawCmdList;
    property->id_ = 1;
    ModifierId id = 1;

    auto modifier = ModifierNG::RSRenderModifier::MakeRenderModifier(
        ModifierNG::RSModifierType::HDR_BRIGHTNESS, property, id, ModifierNG::RSPropertyType::HDR_BRIGHTNESS_FACTOR);
    RSRootRenderNode::ModifierNGContainer modifiers { modifier };
    displayNode->modifiersNG_.emplace(ModifierNG::RSModifierType::HDR_BRIGHTNESS, modifiers);

    // animationManager_ is null since no animations were added
    EXPECT_EQ(displayNode->GetAnimationManager(), nullptr);
    EXPECT_FALSE(displayNode->IsOnlyHDRAnimation());
}

/**
 * @tc.name: IsInBlendModeGroupNonlinearTest
 * @tc.desc: Verify IsInBlendModeGroup with NonlinearBlendModes group
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, IsInBlendModeGroupNonlinearTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    // Nonlinear modes should return true
    EXPECT_TRUE(displayNode->IsInBlendModeGroup(
        static_cast<int>(RSColorBlendMode::SCREEN), RSLogicalDisplayRenderNode::NonlinearBlendModes));

    // Non-nonlinear modes should return false
    EXPECT_FALSE(displayNode->IsInBlendModeGroup(
        static_cast<int>(RSColorBlendMode::SRC), RSLogicalDisplayRenderNode::NonlinearBlendModes));

    // Boundary: negative and large values
    EXPECT_FALSE(displayNode->IsInBlendModeGroup(-1, RSLogicalDisplayRenderNode::NonlinearBlendModes));
}

/**
 * @tc.name: IsInBlendModeGroupMultipleGroupsTest
 * @tc.desc: Verify IsInBlendModeGroup across Child, Empty, Parent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, IsInBlendModeGroupMultipleGroupsTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_TRUE(displayNode->IsInBlendModeGroup(static_cast<int>(RSColorBlendMode::SRC_OVER),
        RSLogicalDisplayRenderNode::ChildBlendModes));
    EXPECT_FALSE(displayNode->IsInBlendModeGroup(static_cast<int>(RSColorBlendMode::NONE),
        RSLogicalDisplayRenderNode::EmptyBlendModes));
    EXPECT_TRUE(displayNode->IsInBlendModeGroup(static_cast<int>(RSColorBlendMode::SRC_IN),
        RSLogicalDisplayRenderNode::ParentBlendModes));
}

/**
 * @tc.name: HasNonlinearBlendModeTest
 * @tc.desc: Verify HasNonlinearBlendMode with all linear and nonlinear modes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, HasNonlinearBlendModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    // Nonlinear modes
    EXPECT_TRUE(displayNode->HasNonlinearBlendMode(static_cast<int>(RSColorBlendMode::SCREEN)));

    // Linear modes
    EXPECT_FALSE(displayNode->HasNonlinearBlendMode(static_cast<int>(RSColorBlendMode::SRC)));

    // Boundary
    EXPECT_FALSE(displayNode->HasNonlinearBlendMode(100));
}

/**
 * @tc.name: HasChildBlendModeTest
 * @tc.desc: Verify HasChildBlendMode for all ChildBlendModes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, HasChildBlendModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_TRUE(displayNode->HasChildBlendMode(static_cast<int>(RSColorBlendMode::SRC_OVER)));
    EXPECT_FALSE(displayNode->HasChildBlendMode(static_cast<int>(RSColorBlendMode::PLUS)));
}

/**
 * @tc.name: HasEmptyBlendModeTest
 * @tc.desc: Verify HasEmptyBlendMode for all EmptyBlendModes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, HasEmptyBlendModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_TRUE(displayNode->HasEmptyBlendMode(static_cast<int>(RSColorBlendMode::XOR)));
    EXPECT_FALSE(displayNode->HasEmptyBlendMode(static_cast<int>(RSColorBlendMode::DST)));
    EXPECT_FALSE(displayNode->HasEmptyBlendMode(0));
}

/**
 * @tc.name: HasParentBlendModeTest
 * @tc.desc: Verify HasParentBlendMode for all ParentBlendModes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, HasParentBlendModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_TRUE(displayNode->HasParentBlendMode(static_cast<int>(RSColorBlendMode::SRC)));
    EXPECT_FALSE(displayNode->HasParentBlendMode(static_cast<int>(RSColorBlendMode::SRC_OVER)));
}

/**
 * @tc.name: IncreaseBlendModeNodeTest
 * @tc.desc: Verify IncreaseBlendModeNode increments counter correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, IncreaseBlendModeNodeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_FALSE(displayNode->HasDstAlphaBlendModeNode());

    displayNode->IncreaseBlendModeNode(nodeId);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());

    displayNode->IncreaseBlendModeNode(nodeId);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());

    // Different node id
    NodeId nodeId2 = nodeId + 1;
    displayNode->IncreaseBlendModeNode(nodeId2);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());

    // Multiple increments for same node
    displayNode->IncreaseBlendModeNode(nodeId);
    displayNode->IncreaseBlendModeNode(nodeId);
    displayNode->IncreaseBlendModeNode(nodeId);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());
}

/**
 * @tc.name: RemoveBlendModeNodeTest
 * @tc.desc: Verify RemoveBlendModeNode removes node from map correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, RemoveBlendModeNodeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    // Decrease non-existing node should not crash
    displayNode->RemoveBlendModeNode(nodeId);
    EXPECT_FALSE(displayNode->HasDstAlphaBlendModeNode());

    // Increase then decrease
    displayNode->IncreaseBlendModeNode(nodeId);
    displayNode->IncreaseBlendModeNode(nodeId);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());

    displayNode->RemoveBlendModeNode(nodeId);
    // After decrease, node is removed entirely
    EXPECT_FALSE(displayNode->HasDstAlphaBlendModeNode());

    // Multiple node ids
    NodeId nodeId2 = nodeId + 1;
    NodeId nodeId3 = nodeId + 2;
    displayNode->IncreaseBlendModeNode(nodeId);
    displayNode->IncreaseBlendModeNode(nodeId2);
    displayNode->IncreaseBlendModeNode(nodeId3);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());

    displayNode->RemoveBlendModeNode(nodeId2);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());

    displayNode->RemoveBlendModeNode(nodeId);
    displayNode->RemoveBlendModeNode(nodeId3);
    EXPECT_FALSE(displayNode->HasDstAlphaBlendModeNode());
}

/**
 * @tc.name: HasDstAlphaBlendModeNodeTest
 * @tc.desc: Verify HasDstAlphaBlendModeNode returns correct presence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, HasDstAlphaBlendModeNodeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    // Initially 0
    EXPECT_FALSE(displayNode->HasDstAlphaBlendModeNode());

    // Single node multiple increments
    displayNode->IncreaseBlendModeNode(nodeId);
    displayNode->IncreaseBlendModeNode(nodeId);
    displayNode->IncreaseBlendModeNode(nodeId);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());

    // Multiple nodes
    NodeId nodeId2 = nodeId + 1;
    displayNode->IncreaseBlendModeNode(nodeId2);
    displayNode->IncreaseBlendModeNode(nodeId2);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());

    // Remove one node
    displayNode->RemoveBlendModeNode(nodeId);
    EXPECT_TRUE(displayNode->HasDstAlphaBlendModeNode());
}

/**
 * @tc.name: CheckAncestorChildBlendModeBlendZeroEmptyCurrentTest
 * @tc.desc: Verify CheckAncestorChildBlendMode when blendMode==0 and current is Empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, CheckAncestorChildBlendModeBlendZeroEmptyCurrentTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::SRC), false, false));

    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::DST_ATOP), false, false));

    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::XOR), false, false));
}

/**
 * @tc.name: CheckAncestorChildBlendModeBlendZeroNonEmptyParentTest
 * @tc.desc: Verify CheckAncestorChildBlendMode when blendMode==0, current not Empty, but IsParentBlendMode=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, CheckAncestorChildBlendModeBlendZeroNonEmptyParentTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    // blendMode=0, current=SRC_IN (not Empty), IsParentBlendMode=true
    // -> isParent=true, then check HasChildBlendMode(0)
    // 0 is NONE which is not in ChildBlendModes => false
    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::SRC_IN), false, true));

    // blendMode=0, current=DST_OUT (not Empty), IsParentBlendMode=true
    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::DST_OUT), false, true));
}

/**
 * @tc.name: CheckAncestorChildBlendModeNonZeroParentBlendModeTest
 * @tc.desc: Verify CheckAncestorChildBlendMode for non-zero blendMode with ParentBlendMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, CheckAncestorChildBlendModeNonZeroParentBlendModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::DST_OVER),
        static_cast<int>(RSColorBlendMode::SRC), false, false));

    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::SRC_OUT),
        static_cast<int>(RSColorBlendMode::SRC_IN), false, false));

    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::SRC),
        static_cast<int>(RSColorBlendMode::DST_OUT), false, false));
}

/**
 * @tc.name: CheckAncestorChildBlendModeNonParentBlendModeTest
 * @tc.desc: Verify CheckAncestorChildBlendMode returns false when current is not ParentBlendMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, CheckAncestorChildBlendModeNonParentBlendModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::SRC_OVER),
        static_cast<int>(RSColorBlendMode::DST), false, false));

    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::DST_OVER),
        static_cast<int>(RSColorBlendMode::SRC_OVER), false, false));

    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::DST_OVER),
        static_cast<int>(RSColorBlendMode::CLEAR), false, false));

    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::SRC_OVER),
        static_cast<int>(RSColorBlendMode::PLUS), false, false));
}

/**
 * @tc.name: CheckAncestorChildBlendModeNonChildBlendModeTest
 * @tc.desc: Verify CheckAncestorChildBlendMode when ParentBlendMode but not Child
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, CheckAncestorChildBlendModeNonChildBlendModeTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::DST),
        static_cast<int>(RSColorBlendMode::SRC), false, false));

    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::CLEAR),
        static_cast<int>(RSColorBlendMode::SRC_IN), false, false));

    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::PLUS),
        static_cast<int>(RSColorBlendMode::XOR), false, false));
}

/**
 * @tc.name: CheckAncestorChildBlendModeOverrideFlagsTest
 * @tc.desc: Verify CheckAncestorChildBlendMode with IsEmptyBlendMode and IsParentBlendMode flags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, CheckAncestorChildBlendModeOverrideFlagsTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    // blendMode=0, current=DST (not Empty), IsEmptyBlendMode=true => should return true
    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::DST), true, false));

    // blendMode=0, current=None (not Empty), IsEmptyBlendMode=true => should return true
    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::NONE), true, false));

    // blendMode=SRC (is Child), current=DST (not Parent), IsParentBlendMode=true => should return true
    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::SRC),
        static_cast<int>(RSColorBlendMode::DST), false, true));

    // blendMode=DST_OVER (is Child), current=CLEAR (not Parent), IsParentBlendMode=true => should return true
    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::DST_OVER),
        static_cast<int>(RSColorBlendMode::CLEAR), false, true));

    // blendMode=SRC (is Child), IsParentBlendMode=false, current=DST_IN (is Parent) => should return true
    EXPECT_TRUE(displayNode->CheckAncestorChildBlendMode(
        static_cast<int>(RSColorBlendMode::SRC),
        static_cast<int>(RSColorBlendMode::DST_IN), false, false));
}

/**
 * @tc.name: CheckAncestorChildBlendModeBoundaryTest
 * @tc.desc: Verify CheckAncestorChildBlendMode with boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, CheckAncestorChildBlendModeBoundaryTest, TestSize.Level1)
{
    constexpr NodeId nodeId = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(nodeId, config);
    ASSERT_NE(displayNode, nullptr);

    // blendMode=0, current not Empty, not Parent, with empty flag false
    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::SRC_OVER), false, false));

    // blendMode=0, current=DARKEN (not Empty), not Parent
    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        0, static_cast<int>(RSColorBlendMode::DARKEN), false, false));

    // Non-zero blendMode not in ChildBlendModes
    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        -1, static_cast<int>(RSColorBlendMode::SRC), false, false));

    EXPECT_FALSE(displayNode->CheckAncestorChildBlendMode(
        100, static_cast<int>(RSColorBlendMode::SRC_IN), false, false));
}

/**
 * @tc.name: WindowRecordSnapshotKeepsMixedWhiteListIdsTest
 * @tc.desc: Verify the white list keeps persistent and node ids while only main windows drive bbox and source
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordSnapshotKeepsMixedWhiteListIdsTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr NodeId displayId = 20;
    constexpr NodeId otherDisplayId = 21;
    constexpr NodeId mainId = 10;
    constexpr NodeId childId = 11;
    constexpr LeashPersistentId mainLeashId = 1001;
    constexpr LeashPersistentId childLeashId = 1002;
    auto display = CreateRecordDisplay(rsContext, displayId);
    auto otherDisplay = CreateRecordDisplay(rsContext, otherDisplayId);

    auto mainNode = CreateRecordSurface(rsContext, display, mainId, RSSurfaceNodeType::APP_WINDOW_NODE, true);
    mainNode->SetLeashPersistentId(mainLeashId);
    auto childNode = CreateRecordSurface(rsContext, otherDisplay, childId, RSSurfaceNodeType::LEASH_WINDOW_NODE, true);
    EXPECT_EQ(childNode->GetLeashPersistentId(), INVALID_LEASH_PERSISTENTID);

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { childId, childLeashId, mainLeashId, mainId };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayId);
    display->ResolveWindowRecordSnapshot(params);

    const std::unordered_set<NodeId> expectedWhiteListIds = { childId, childLeashId, mainLeashId, mainId };
    EXPECT_EQ(display->BuildEffectiveRecordWhiteListIds(), expectedWhiteListIds);
    EXPECT_EQ(params.GetRecordWhiteListIds(), expectedWhiteListIds);
    ASSERT_EQ(params.GetRecordSurfaceDrawables().size(), 1u);
    auto bboxDrawable = params.GetRecordSurfaceDrawables()[0].lock();
    ASSERT_NE(bboxDrawable, nullptr);
    EXPECT_EQ(bboxDrawable->GetId(), mainId);
    auto sourceDisplay = params.GetRecordSourceDisplayDrawable().lock();
    ASSERT_NE(sourceDisplay, nullptr);
    EXPECT_EQ(sourceDisplay->GetId(), displayId);
    EXPECT_TRUE(params.HasPaintableRecordSurface());
}

/**
 * @tc.name: WindowRecordPaintableSurfaceSnapshotTest
 * @tc.desc: Verify record surface paintability includes on-tree state and ancestor visibility
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordPaintableSurfaceSnapshotTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr NodeId displayId = 40;
    constexpr NodeId mainId = 41;
    constexpr NodeId childId = 42;
    auto display = CreateRecordDisplay(rsContext, displayId);
    auto mainNode = CreateRecordSurface(
        rsContext, display, mainId, RSSurfaceNodeType::APP_WINDOW_NODE, true, false);
    auto childNode = CreateRecordSurface(rsContext, mainNode, childId, RSSurfaceNodeType::LEASH_WINDOW_NODE,
        true, false, false, displayId);

    RSWindowRecordConfig recordConfig;
    // The child precedes its anchor in config order.
    recordConfig.surfaceNodeIds = { childId, mainId };
    display->SetWindowRecordConfig(recordConfig);

    RSLogicalDisplayRenderParams nonePaintableParams(displayId);
    display->ResolveWindowRecordSnapshot(nonePaintableParams);
    EXPECT_FALSE(nonePaintableParams.HasPaintableRecordSurface());

    childNode->shouldPaint_ = true;
    mainNode->shouldPaint_ = true;
    RSLogicalDisplayRenderParams childPaintableParams(displayId);
    display->ResolveWindowRecordSnapshot(childPaintableParams);
    EXPECT_TRUE(childPaintableParams.HasPaintableRecordSurface());

    mainNode->shouldPaint_ = false;
    RSLogicalDisplayRenderParams parentUnpaintableParams(displayId);
    display->ResolveWindowRecordSnapshot(parentUnpaintableParams);
    EXPECT_FALSE(parentUnpaintableParams.HasPaintableRecordSurface());
}

/**
 * @tc.name: WindowRecordSnapshotWithoutMainWindowDisablesCaptureTest
 * @tc.desc: Verify mixed whitelist ids do not activate capture without a resolvable main window
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordSnapshotWithoutMainWindowDisablesCaptureTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr NodeId displayId = 30;
    constexpr NodeId childId = 31;
    constexpr LeashPersistentId childLeashId = 1003;
    RSDisplayNodeConfig displayConfig;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, displayConfig, rsContext);
    RSSurfaceRenderNodeConfig childConfig { .id = childId, .nodeType = RSSurfaceNodeType::LEASH_WINDOW_NODE };
    auto childNode = std::make_shared<RSSurfaceRenderNode>(childConfig, rsContext);
    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.renderNodeMap_[ExtractPid(childId)][childId] = childNode;

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { childId, childLeashId };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayId);
    display->ResolveWindowRecordSnapshot(params);

    EXPECT_TRUE(display->BuildEffectiveRecordWhiteListIds().empty());
    EXPECT_TRUE(params.GetRecordWhiteListIds().empty());
    EXPECT_TRUE(params.GetRecordSurfaceDrawables().empty());
    EXPECT_TRUE(params.GetRecordSourceDisplayDrawable().expired());
    EXPECT_FALSE(params.HasPaintableRecordSurface());
}

/**
 * @tc.name: WindowRecordCreatedInactiveThenSetterActivatesTest
 * @tc.desc: Verify a display is created without a record session and the setter activates it on a virtual screen
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordCreatedInactiveThenSetterActivatesTest, TestSize.Level1)
{
    constexpr ScreenId screenId = 6100;
    constexpr NodeId screenNodeId = 6101;
    constexpr NodeId displayId = 1100;
    auto rsContext = std::make_shared<RSContext>();
    auto screen = std::make_shared<RSScreenRenderNode>(screenNodeId, screenId, rsContext);
    screen->screenProperty_.Set<ScreenPropertyType::IS_VIRTUAL>(true);

    RSDisplayNodeConfig config;
    config.screenId = screenId;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, config, rsContext);
    screen->AddChild(display);
    ASSERT_TRUE(display->IsOnVirtualScreen());
    ASSERT_FALSE(display->IsWindowRecordActive());
    EXPECT_TRUE(display->GetWindowRecordConfig().surfaceNodeIds.empty());

    RSWindowRecordConfig recordConfig;
    recordConfig.renderFit = WindowRecordFit::ASPECT_FIT;
    recordConfig.surfaceNodeIds = { 1101, 1102 };
    display->SetWindowRecordConfig(recordConfig);
    EXPECT_TRUE(display->IsWindowRecordActive());
    EXPECT_EQ(display->GetWindowRecordConfig(), recordConfig);
    EXPECT_EQ(display->GetWindowRecordConfig().surfaceNodeIds.size(), 2u);
}

/**
 * @tc.name: WindowRecordVirtualPhysicalAndParentlessDetectionTest
 * @tc.desc: Verify IsOnVirtualScreen for virtual, physical, parentless, and invalid-screen-id displays
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordVirtualPhysicalAndParentlessDetectionTest, TestSize.Level1)
{
    constexpr ScreenId virtualScreenId = 6200;
    constexpr ScreenId physicalScreenId = 6201;
    auto rsContext = std::make_shared<RSContext>();
    auto virtualScreen = std::make_shared<RSScreenRenderNode>(6202, virtualScreenId, rsContext);
    virtualScreen->screenProperty_.Set<ScreenPropertyType::IS_VIRTUAL>(true);
    auto physicalScreen = std::make_shared<RSScreenRenderNode>(6203, physicalScreenId, rsContext);
    physicalScreen->screenProperty_.Set<ScreenPropertyType::IS_VIRTUAL>(false);

    RSDisplayNodeConfig virtualConfig;
    virtualConfig.screenId = virtualScreenId;
    auto virtualDisplay = std::make_shared<RSLogicalDisplayRenderNode>(6210, virtualConfig, rsContext);
    virtualScreen->AddChild(virtualDisplay);
    EXPECT_TRUE(virtualDisplay->IsOnVirtualScreen());

    RSDisplayNodeConfig physicalConfig;
    physicalConfig.screenId = physicalScreenId;
    auto physicalDisplay = std::make_shared<RSLogicalDisplayRenderNode>(6211, physicalConfig, rsContext);
    physicalScreen->AddChild(physicalDisplay);
    EXPECT_FALSE(physicalDisplay->IsOnVirtualScreen());

    RSDisplayNodeConfig parentlessConfig;
    parentlessConfig.screenId = virtualScreenId;
    auto parentlessDisplay = std::make_shared<RSLogicalDisplayRenderNode>(6212, parentlessConfig, rsContext);
    EXPECT_FALSE(parentlessDisplay->IsOnVirtualScreen());

    RSDisplayNodeConfig invalidConfig;
    invalidConfig.screenId = INVALID_SCREEN_ID;
    auto invalidDisplay = std::make_shared<RSLogicalDisplayRenderNode>(6213, invalidConfig, rsContext);
    virtualScreen->AddChild(invalidDisplay);
    EXPECT_FALSE(invalidDisplay->IsOnVirtualScreen());
}

/**
 * @tc.name: WindowRecordRejectsOverLimitConfigTest
 * @tc.desc: Verify 64 ids are accepted while 65 ids are rejected and the previous config is kept
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordRejectsOverLimitConfigTest, TestSize.Level1)
{
    constexpr NodeId displayId = 6300;
    RSDisplayNodeConfig config;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, config);
    RSWindowRecordConfig accepted;
    for (size_t index = 0; index < MAX_WINDOW_RECORD_SURFACE_NUM; ++index) {
        accepted.surfaceNodeIds.push_back(6301 + index);
    }
    display->SetWindowRecordConfig(accepted);
    EXPECT_EQ(display->GetWindowRecordConfig().surfaceNodeIds.size(), MAX_WINDOW_RECORD_SURFACE_NUM);

    RSWindowRecordConfig rejected = accepted;
    rejected.surfaceNodeIds.push_back(6400);
    display->SetWindowRecordConfig(rejected);
    EXPECT_EQ(display->GetWindowRecordConfig(), accepted);
    EXPECT_EQ(display->GetWindowRecordConfig().surfaceNodeIds.size(), MAX_WINDOW_RECORD_SURFACE_NUM);
}

/**
 * @tc.name: WindowRecordEmptyAndZeroWhitelistTest
 * @tc.desc: Verify empty config and zero ids do not produce white list entries while a main window does
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordEmptyAndZeroWhitelistTest, TestSize.Level1)
{
    constexpr NodeId displayId = 6500;
    constexpr NodeId mainId = 6501;
    auto rsContext = std::make_shared<RSContext>();
    RSDisplayNodeConfig config;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, config, rsContext);
    display->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(display);
    RSSurfaceRenderNodeConfig mainConfig { .id = mainId, .nodeType = RSSurfaceNodeType::APP_WINDOW_NODE };
    auto mainNode = std::make_shared<RSSurfaceRenderNode>(mainConfig, rsContext);
    mainNode->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(mainNode);
    mainNode->isOnTheTree_ = true;
    mainNode->logicalDisplayNodeId_ = displayId;
    display->AddChild(mainNode);
    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.renderNodeMap_[ExtractPid(displayId)][displayId] = display;
    nodeMap.renderNodeMap_[ExtractPid(mainId)][mainId] = mainNode;

    RSWindowRecordConfig emptyConfig;
    display->SetWindowRecordConfig(emptyConfig);
    RSLogicalDisplayRenderParams emptyParams(displayId);
    display->ResolveWindowRecordSnapshot(emptyParams);
    EXPECT_TRUE(display->BuildEffectiveRecordWhiteListIds().empty());
    EXPECT_TRUE(emptyParams.GetRecordWhiteListIds().empty());
    EXPECT_FALSE(emptyParams.NeedSync());

    RSWindowRecordConfig zeroConfig;
    zeroConfig.surfaceNodeIds = { INVALID_NODEID, INVALID_NODEID };
    display->SetWindowRecordConfig(zeroConfig);
    RSLogicalDisplayRenderParams zeroParams(displayId);
    display->ResolveWindowRecordSnapshot(zeroParams);
    EXPECT_TRUE(display->BuildEffectiveRecordWhiteListIds().empty());
    EXPECT_TRUE(zeroParams.GetRecordWhiteListIds().empty());
    EXPECT_TRUE(zeroParams.GetRecordSurfaceDrawables().empty());
    EXPECT_TRUE(zeroParams.NeedSync());

    RSWindowRecordConfig mixedConfig;
    mixedConfig.surfaceNodeIds = { INVALID_NODEID, mainId };
    display->SetWindowRecordConfig(mixedConfig);
    RSLogicalDisplayRenderParams mixedParams(displayId);
    display->ResolveWindowRecordSnapshot(mixedParams);
    const std::unordered_set<NodeId> expectedWhiteListIds = { mainId };
    EXPECT_EQ(display->BuildEffectiveRecordWhiteListIds(), expectedWhiteListIds);
    EXPECT_EQ(mixedParams.GetRecordWhiteListIds(), expectedWhiteListIds);
    EXPECT_EQ(mixedParams.GetRecordWhiteListIds().count(INVALID_NODEID), 0u);
    ASSERT_EQ(mixedParams.GetRecordSurfaceDrawables().size(), 1u);
}

/**
 * @tc.name: WindowRecordExpiredContextTest
 * @tc.desc: Verify record resolution degrades to an empty snapshot when the node has no context
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordExpiredContextTest, TestSize.Level1)
{
    constexpr NodeId displayId = 6600;
    RSDisplayNodeConfig config;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, config);
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 6601 };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayId);
    display->ResolveWindowRecordSnapshot(params);

    EXPECT_TRUE(display->BuildEffectiveRecordWhiteListIds().empty());
    EXPECT_TRUE(params.GetRecordWhiteListIds().empty());
    EXPECT_TRUE(params.GetRecordSurfaceDrawables().empty());
    EXPECT_TRUE(params.GetRecordSourceDisplayDrawable().expired());
    EXPECT_FALSE(params.NeedSync());
}

/**
 * @tc.name: WindowRecordMissingNodeAndDrawableTest
 * @tc.desc: Verify missing nodes, non-main windows, and main windows without drawables are skipped
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordMissingNodeAndDrawableTest, TestSize.Level1)
{
    constexpr NodeId displayId = 6700;
    constexpr NodeId mainId = 6701;
    constexpr NodeId childId = 6702;
    constexpr NodeId missingId = 6703;
    auto rsContext = std::make_shared<RSContext>();
    RSDisplayNodeConfig config;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, config, rsContext);
    RSSurfaceRenderNodeConfig mainConfig { .id = mainId, .nodeType = RSSurfaceNodeType::APP_WINDOW_NODE };
    auto mainNode = std::make_shared<RSSurfaceRenderNode>(mainConfig, rsContext);
    RSSurfaceRenderNodeConfig childConfig { .id = childId, .nodeType = RSSurfaceNodeType::LEASH_WINDOW_NODE };
    auto childNode = std::make_shared<RSSurfaceRenderNode>(childConfig, rsContext);
    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.renderNodeMap_[ExtractPid(mainId)][mainId] = mainNode;
    nodeMap.renderNodeMap_[ExtractPid(childId)][childId] = childNode;

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { mainId, childId, missingId };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayId);
    display->ResolveWindowRecordSnapshot(params);

    const std::unordered_set<NodeId> expectedWhiteListIds = { mainId, childId, missingId };
    EXPECT_EQ(params.GetRecordWhiteListIds(), expectedWhiteListIds);
    EXPECT_TRUE(params.GetRecordSurfaceDrawables().empty());
    EXPECT_TRUE(params.GetRecordSourceDisplayDrawable().expired());
    EXPECT_TRUE(params.NeedSync());
}

/**
 * @tc.name: WindowRecordOffTreeSourceDisplayTest
 * @tc.desc: Verify the source display drawable is resolved only for on-tree record surfaces
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordOffTreeSourceDisplayTest, TestSize.Level1)
{
    constexpr NodeId displayId = 6800;
    constexpr NodeId mainId = 6801;
    auto rsContext = std::make_shared<RSContext>();
    RSDisplayNodeConfig config;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, config, rsContext);
    display->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(display);
    RSSurfaceRenderNodeConfig mainConfig { .id = mainId, .nodeType = RSSurfaceNodeType::APP_WINDOW_NODE };
    auto mainNode = std::make_shared<RSSurfaceRenderNode>(mainConfig, rsContext);
    mainNode->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(mainNode);
    mainNode->logicalDisplayNodeId_ = displayId;
    mainNode->isOnTheTree_ = false;
    display->AddChild(mainNode);
    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.renderNodeMap_[ExtractPid(displayId)][displayId] = display;
    nodeMap.renderNodeMap_[ExtractPid(mainId)][mainId] = mainNode;

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { mainId };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams offTreeParams(displayId);
    display->ResolveWindowRecordSnapshot(offTreeParams);
    EXPECT_TRUE(offTreeParams.GetRecordSurfaceDrawables().empty());
    EXPECT_TRUE(offTreeParams.GetRecordSourceDisplayDrawable().expired());
    EXPECT_FALSE(offTreeParams.HasPaintableRecordSurface());

    mainNode->isOnTheTree_ = true;
    RSLogicalDisplayRenderParams onTreeParams(displayId);
    display->ResolveWindowRecordSnapshot(onTreeParams);
    auto sourceDisplay = onTreeParams.GetRecordSourceDisplayDrawable().lock();
    ASSERT_NE(sourceDisplay, nullptr);
    EXPECT_EQ(sourceDisplay->GetId(), displayId);
    EXPECT_TRUE(onTreeParams.HasPaintableRecordSurface());
    EXPECT_EQ(onTreeParams.GetRecordSurfaceDrawables().size(), 1u);
}

/**
 * @tc.name: WindowRecordNonAnchorDisplaySurfaceCannotPassTest
 * @tc.desc: Verify visible surfaces on the non-anchor display contribute neither paintability nor bbox
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordNonAnchorDisplaySurfaceCannotPassTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr NodeId displayId = 7000;
    constexpr NodeId otherDisplayId = 7001;
    constexpr NodeId anchorMainId = 7002;
    constexpr NodeId otherMainId = 7003;
    constexpr NodeId otherChildId = 7004;
    auto display = CreateRecordDisplay(rsContext, displayId);
    auto otherDisplay = CreateRecordDisplay(rsContext, otherDisplayId);

    // The first config entry is the anchor even though it is hidden; it stays on-tree and resolvable.
    CreateRecordSurface(rsContext, display, anchorMainId, RSSurfaceNodeType::APP_WINDOW_NODE, true, false);
    auto otherMain = CreateRecordSurface(
        rsContext, otherDisplay, otherMainId, RSSurfaceNodeType::APP_WINDOW_NODE, true);
    CreateRecordSurface(rsContext, otherMain, otherChildId, RSSurfaceNodeType::LEASH_WINDOW_NODE, true,
        true, true, otherDisplayId);

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { anchorMainId, otherMainId, otherChildId };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayId);
    display->ResolveWindowRecordSnapshot(params);

    auto sourceDisplay = params.GetRecordSourceDisplayDrawable().lock();
    ASSERT_NE(sourceDisplay, nullptr);
    EXPECT_EQ(sourceDisplay->GetId(), displayId);
    EXPECT_FALSE(params.HasPaintableRecordSurface());
    EXPECT_TRUE(params.GetRecordSurfaceDrawables().empty());
    // The whitelist still carries every configured id; only the snapshot scope is anchor-limited.
    EXPECT_EQ(params.GetRecordWhiteListIds().size(), 3u);
}

/**
 * @tc.name: WindowRecordOffTreeMainExcludedFromGeometryTest
 * @tc.desc: Verify an off-tree main window contributes no bbox while the on-tree anchor still does
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordOffTreeMainExcludedFromGeometryTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr NodeId displayId = 7100;
    constexpr NodeId offTreeMainId = 7101;
    constexpr NodeId onTreeMainId = 7102;
    RSDisplayNodeConfig displayConfig;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, displayConfig, rsContext);
    display->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(display);

    RSSurfaceRenderNodeConfig offTreeConfig { .id = offTreeMainId, .nodeType = RSSurfaceNodeType::APP_WINDOW_NODE };
    auto offTreeMain = std::make_shared<RSSurfaceRenderNode>(offTreeConfig, rsContext);
    offTreeMain->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(offTreeMain);
    offTreeMain->isOnTheTree_ = false;
    offTreeMain->logicalDisplayNodeId_ = displayId;
    display->AddChild(offTreeMain);
    RSSurfaceRenderNodeConfig onTreeConfig { .id = onTreeMainId, .nodeType = RSSurfaceNodeType::APP_WINDOW_NODE };
    auto onTreeMain = std::make_shared<RSSurfaceRenderNode>(onTreeConfig, rsContext);
    onTreeMain->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(onTreeMain);
    onTreeMain->isOnTheTree_ = true;
    onTreeMain->logicalDisplayNodeId_ = displayId;
    display->AddChild(onTreeMain);

    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.renderNodeMap_[ExtractPid(displayId)][displayId] = display;
    nodeMap.renderNodeMap_[ExtractPid(offTreeMainId)][offTreeMainId] = offTreeMain;
    nodeMap.renderNodeMap_[ExtractPid(onTreeMainId)][onTreeMainId] = onTreeMain;

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { offTreeMainId, onTreeMainId };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayId);
    display->ResolveWindowRecordSnapshot(params);

    auto sourceDisplay = params.GetRecordSourceDisplayDrawable().lock();
    ASSERT_NE(sourceDisplay, nullptr);
    EXPECT_EQ(sourceDisplay->GetId(), displayId);
    EXPECT_TRUE(params.HasPaintableRecordSurface());
    ASSERT_EQ(params.GetRecordSurfaceDrawables().size(), 1u);
    auto bboxDrawable = params.GetRecordSurfaceDrawables()[0].lock();
    ASSERT_NE(bboxDrawable, nullptr);
    EXPECT_EQ(bboxDrawable->GetId(), onTreeMainId);
}

/**
 * @tc.name: WindowRecordPaintableChildWithoutMainDrawableTest
 * @tc.desc: Verify a drawable-less main cannot anchor, so its paintable child opens neither gate
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordPaintableChildWithoutMainDrawableTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr NodeId displayId = 7200;
    constexpr NodeId mainId = 7201;
    constexpr NodeId childId = 7202;
    RSDisplayNodeConfig displayConfig;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, displayConfig, rsContext);
    display->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(display);

    // On-tree and visible but drawable-less, so it cannot anchor and its child must not stand in.
    RSSurfaceRenderNodeConfig mainConfig { .id = mainId, .nodeType = RSSurfaceNodeType::APP_WINDOW_NODE };
    auto mainNode = std::make_shared<RSSurfaceRenderNode>(mainConfig, rsContext);
    mainNode->isOnTheTree_ = true;
    mainNode->logicalDisplayNodeId_ = displayId;
    display->AddChild(mainNode);
    RSSurfaceRenderNodeConfig childConfig { .id = childId, .nodeType = RSSurfaceNodeType::LEASH_WINDOW_NODE };
    auto childNode = std::make_shared<RSSurfaceRenderNode>(childConfig, rsContext);
    childNode->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(childNode);
    childNode->isOnTheTree_ = true;
    childNode->logicalDisplayNodeId_ = displayId;
    mainNode->AddChild(childNode);

    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.renderNodeMap_[ExtractPid(displayId)][displayId] = display;
    nodeMap.renderNodeMap_[ExtractPid(mainId)][mainId] = mainNode;
    nodeMap.renderNodeMap_[ExtractPid(childId)][childId] = childNode;

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { mainId, childId };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayId);
    display->ResolveWindowRecordSnapshot(params);

    EXPECT_TRUE(params.GetRecordSourceDisplayDrawable().expired());
    EXPECT_FALSE(params.HasPaintableRecordSurface());
    EXPECT_TRUE(params.GetRecordSurfaceDrawables().empty());
}

/**
 * @tc.name: WindowRecordAnchorRequiresMainDrawableTest
 * @tc.desc: Verify a drawable-less main cannot anchor, so a later main on another display owns the snapshot
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordAnchorRequiresMainDrawableTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr NodeId displayAId = 7300;
    constexpr NodeId displayBId = 7301;
    constexpr NodeId noDrawableMainId = 7302;
    constexpr NodeId drawableMainId = 7303;
    constexpr NodeId childId = 7304;
    auto displayA = CreateRecordDisplay(rsContext, displayAId);
    auto displayB = CreateRecordDisplay(rsContext, displayBId);

    // The first candidate has no drawable, so the next paintable main with one anchors instead.
    CreateRecordSurface(rsContext, displayA, noDrawableMainId, RSSurfaceNodeType::APP_WINDOW_NODE, true,
        true, false);
    auto drawableMain = CreateRecordSurface(
        rsContext, displayB, drawableMainId, RSSurfaceNodeType::APP_WINDOW_NODE, true);
    CreateRecordSurface(rsContext, drawableMain, childId, RSSurfaceNodeType::LEASH_WINDOW_NODE, true,
        true, true, displayBId);

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { noDrawableMainId, drawableMainId, childId };
    displayB->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayBId);
    displayB->ResolveWindowRecordSnapshot(params);

    auto sourceDisplay = params.GetRecordSourceDisplayDrawable().lock();
    ASSERT_NE(sourceDisplay, nullptr);
    EXPECT_EQ(sourceDisplay->GetId(), displayBId);
    EXPECT_TRUE(params.HasPaintableRecordSurface());
    ASSERT_EQ(params.GetRecordSurfaceDrawables().size(), 1u);
    auto bboxDrawable = params.GetRecordSurfaceDrawables()[0].lock();
    ASSERT_NE(bboxDrawable, nullptr);
    EXPECT_EQ(bboxDrawable->GetId(), drawableMainId);
    EXPECT_EQ(params.GetRecordWhiteListIds().size(), 3u);
}

/**
 * @tc.name: WindowRecordStaleStampedDisplayFollowsRealParentTest
 * @tc.desc: Verify the live parent chain, not a stale stamped logical display id, scopes anchor and geometry
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordStaleStampedDisplayFollowsRealParentTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    constexpr NodeId realDisplayId = 7400;
    constexpr NodeId staleDisplayId = 7401;
    constexpr NodeId staleStampedMainId = 7402;
    constexpr NodeId staleDisplayMainId = 7403;
    auto realDisplay = CreateRecordDisplay(rsContext, realDisplayId);
    auto staleDisplay = CreateRecordDisplay(rsContext, staleDisplayId);

    // Deliberate stale stamp: the parent chain, not the stamp, must scope anchor and bbox.
    CreateRecordSurface(rsContext, realDisplay, staleStampedMainId, RSSurfaceNodeType::APP_WINDOW_NODE, true,
        true, true, staleDisplayId);
    CreateRecordSurface(rsContext, staleDisplay, staleDisplayMainId, RSSurfaceNodeType::APP_WINDOW_NODE, true);

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { staleStampedMainId, staleDisplayMainId };
    realDisplay->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(realDisplayId);
    realDisplay->ResolveWindowRecordSnapshot(params);

    auto sourceDisplay = params.GetRecordSourceDisplayDrawable().lock();
    ASSERT_NE(sourceDisplay, nullptr);
    EXPECT_EQ(sourceDisplay->GetId(), realDisplayId);
    EXPECT_TRUE(params.HasPaintableRecordSurface());
    ASSERT_EQ(params.GetRecordSurfaceDrawables().size(), 1u);
    auto bboxDrawable = params.GetRecordSurfaceDrawables()[0].lock();
    ASSERT_NE(bboxDrawable, nullptr);
    EXPECT_EQ(bboxDrawable->GetId(), staleStampedMainId);
}

/**
 * @tc.name: WindowRecordSessionClearingTest
 * @tc.desc: Verify ClearWindowRecordSession drops the config and empties the next snapshot
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderNodeTest, WindowRecordSessionClearingTest, TestSize.Level1)
{
    constexpr NodeId displayId = 6900;
    constexpr NodeId mainId = 6901;
    auto rsContext = std::make_shared<RSContext>();
    RSDisplayNodeConfig config;
    auto display = std::make_shared<RSLogicalDisplayRenderNode>(displayId, config, rsContext);
    display->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(display);
    RSSurfaceRenderNodeConfig mainConfig { .id = mainId, .nodeType = RSSurfaceNodeType::APP_WINDOW_NODE };
    auto mainNode = std::make_shared<RSSurfaceRenderNode>(mainConfig, rsContext);
    mainNode->renderDrawable_ = std::make_shared<RSRenderNodeDrawableAdapterMock>(mainNode);
    mainNode->isOnTheTree_ = true;
    mainNode->logicalDisplayNodeId_ = displayId;
    display->AddChild(mainNode);
    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.renderNodeMap_[ExtractPid(displayId)][displayId] = display;
    nodeMap.renderNodeMap_[ExtractPid(mainId)][mainId] = mainNode;

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { mainId };
    display->SetWindowRecordConfig(recordConfig);
    RSLogicalDisplayRenderParams params(displayId);
    display->ResolveWindowRecordSnapshot(params);
    ASSERT_EQ(params.GetRecordSurfaceDrawables().size(), 1u);

    display->ClearWindowRecordSession();
    EXPECT_FALSE(display->IsWindowRecordActive());
    EXPECT_TRUE(display->GetWindowRecordConfig().surfaceNodeIds.empty());
    params.SetNeedSync(false);
    display->ResolveWindowRecordSnapshot(params);
    EXPECT_TRUE(params.GetRecordWhiteListIds().empty());
    EXPECT_TRUE(params.GetRecordSurfaceDrawables().empty());
    EXPECT_TRUE(params.GetRecordSourceDisplayDrawable().expired());
    EXPECT_FALSE(params.NeedSync());
}

} // namespace OHOS::Rosen
