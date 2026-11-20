/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "command/rs_ui_director_command.h"
#include "common/rs_common_def.h"
#include "include/command/rs_display_node_command.h"
#include "params/rs_screen_render_params.h"
#include "pipeline/rs_logical_display_render_node.h"
#include "pipeline/rs_screen_render_node.h"
#include "screen_manager/rs_screen_property.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSDisplayNodeCommandTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSDisplayNodeCommandTest::SetUpTestCase() {}
void RSDisplayNodeCommandTest::TearDownTestCase() {}
void RSDisplayNodeCommandTest::SetUp() {}
void RSDisplayNodeCommandTest::TearDown() {}

namespace {
constexpr NodeId TEST_SCREEN_NODE_ID = 100;

void RegisterScreenNode(RSContext& context, NodeId nodeId, ScreenId screenId, bool isVirtual)
{
    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(nodeId, screenId, context.weak_from_this());
    RSScreenProperty property;
    auto virtualProperty = sptr<ScreenProperty<bool>>::MakeSptr(isVirtual);
    property.Set(ScreenPropertyType::IS_VIRTUAL, virtualProperty);
    screenRenderNode->SetScreenProperty(property);
    context.GetMutableNodeMap().RegisterRenderNode(screenRenderNode);
}

constexpr NodeId TEST_MIRROR_SOURCE_ID = 2;

// Creates the DMS mirror source first, then the MIRROR output bound to it, for tests that need a
// live configured source. Record start itself requires only a virtual MIRROR output.
void CreateMirrorDisplay(RSContext& context, NodeId displayId, NodeId sourceId, ScreenId screenId)
{
    RSDisplayNodeConfig sourceConfig;
    sourceConfig.screenId = screenId;
    DisplayNodeCommandHelper::Create(context, sourceId, sourceConfig);
    RSDisplayNodeConfig mirrorConfig;
    mirrorConfig.screenId = screenId;
    mirrorConfig.displayMode = DisplayMode::MIRROR;
    mirrorConfig.mirrorNodeId = sourceId;
    DisplayNodeCommandHelper::Create(context, displayId, mirrorConfig);
}

struct ActiveRecordFixture {
    std::shared_ptr<RSLogicalDisplayRenderNode> display;
    std::shared_ptr<RSScreenRenderNode> outputScreen;
    std::shared_ptr<RSScreenRenderNode> sourceScreen;
    RSScreenRenderParams* sourceParams = nullptr;
};

// Builds the virtual screens, the DMS mirror pair, an active record config and the output-screen
// relation derived from it. Callers assert the returned pointers before using the fixture.
ActiveRecordFixture CreateActiveRecordFixture(RSContext& context, NodeId displayId, ScreenId outputScreenId,
    ScreenId sourceScreenId)
{
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID, outputScreenId, true);
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID + 1, sourceScreenId, true);
    CreateMirrorDisplay(context, displayId, TEST_MIRROR_SOURCE_ID, outputScreenId);

    ActiveRecordFixture fixture;
    fixture.display = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayId);
    fixture.outputScreen = context.GetNodeMap().GetRenderNode<RSScreenRenderNode>(TEST_SCREEN_NODE_ID);
    fixture.sourceScreen = context.GetNodeMap().GetRenderNode<RSScreenRenderNode>(TEST_SCREEN_NODE_ID + 1);
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10, 11 };
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayId, recordConfig);
    // SetMirrorSource() publishes the counted relation through SetHasMirrorScreen(), which writes the
    // source staging params, so those params must exist before the relation is bound.
    if (fixture.sourceScreen != nullptr) {
        if (fixture.sourceScreen->stagingRenderParams_ == nullptr) {
            fixture.sourceScreen->stagingRenderParams_ =
                std::make_unique<RSScreenRenderParams>(fixture.sourceScreen->GetId());
        }
        fixture.sourceParams = static_cast<RSScreenRenderParams*>(fixture.sourceScreen->stagingRenderParams_.get());
    }
    if (fixture.outputScreen != nullptr && fixture.sourceScreen != nullptr) {
        fixture.outputScreen->SetIsMirrorScreen(true);
        fixture.outputScreen->SetMirrorSource(fixture.sourceScreen);
    }
    return fixture;
}
} // namespace

/**
 * @tc.name: TestRSBaseNodeCommand001
 * @tc.desc: SetScreenId test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, TestRSDisplayNodeCommand001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(-1);
    uint64_t screenId = static_cast<uint64_t>(0);
    DisplayNodeCommandHelper::SetScreenId(context, id, screenId);
    EXPECT_EQ(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);

    NodeId id2 = static_cast<NodeId>(1);
    RSDisplayNodeConfig config { 0, DisplayMode::EXPAND, 0 };
    DisplayNodeCommandHelper::Create(context, id2, config);
    DisplayNodeCommandHelper::SetScreenId(context, id2, screenId);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id2), nullptr);
}

/**
 * @tc.name: TestRSDisplayNodeCommand003
 * @tc.desc: SetSecurityDisplay test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, TestRSDisplayNodeCommand003, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    bool isSecurityDisplay = false;
    DisplayNodeCommandHelper::SetSecurityDisplay(context, id, isSecurityDisplay);

    RSDisplayNodeConfig config { 0, DisplayMode::EXPAND, 0 };
    DisplayNodeCommandHelper::Create(context, id, config);
    DisplayNodeCommandHelper::SetSecurityDisplay(context, id, isSecurityDisplay);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);
}

/**
 * @tc.name: SetDisplayModeTest001
 * @tc.desc: Test SetDisplayMode
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeTest001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig config { 0, DisplayMode::MIRROR, 0 };
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);
    EXPECT_EQ(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);
}

/**
 * @tc.name: SetDisplayModeTest002
 * @tc.desc: SetScreenId test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeTest002, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig config { 0, DisplayMode::EXPAND, 0 };
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);
    EXPECT_EQ(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);

    DisplayNodeCommandHelper::Create(context, id, config);
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);

    config.displayMode = DisplayMode::MIRROR;
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);

    NodeId mirrorNodeId = static_cast<NodeId>(2);
    config.mirrorNodeId = mirrorNodeId;
    DisplayNodeCommandHelper::Create(context, mirrorNodeId, config);
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);
}

/**
 * @tc.name: SetDisplayModeTest003
 * @tc.desc: Test SetDisplayMode with positionZ, screenRenderNode exists (if branch true)
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeTest003, TestSize.Level1)
{
    RSContext context;
    NodeId screenNodeId = static_cast<NodeId>(100);
    NodeId displayNodeId = static_cast<NodeId>(1);

    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(screenNodeId, 1, context.weak_from_this());
    context.GetMutableNodeMap().RegisterRenderNode(screenRenderNode);

    RSDisplayNodeConfig config;
    config.screenId = 1;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    DisplayNodeCommandHelper::AddDisplayNodeToTree(context, displayNodeId);
    DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, config);

    config.positionZ = 128;
    DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, config);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId), nullptr);
}

/**
 * @tc.name: SetDisplayModeTest004
 * @tc.desc: Test SetDisplayMode with positionZ, screenRenderNode null (if branch false)
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeTest004, TestSize.Level1)
{
    RSContext context;
    NodeId displayNodeId = static_cast<NodeId>(1);

    RSDisplayNodeConfig config;
    config.positionZ = 128;

    DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, config);
    EXPECT_EQ(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId), nullptr);
}

/**
 * @tc.name: SetDisplayModeTest005
 * @tc.desc: Test SetDisplayMode with NAN positionZ (should be rejected)
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeTest005, TestSize.Level1)
{
    RSContext context;
    NodeId screenNodeId = static_cast<NodeId>(100);
    NodeId displayNodeId = static_cast<NodeId>(1);

    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(screenNodeId, 1, context.weak_from_this());
    context.GetMutableNodeMap().RegisterRenderNode(screenRenderNode);

    RSDisplayNodeConfig config;
    config.screenId = 1;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    DisplayNodeCommandHelper::AddDisplayNodeToTree(context, displayNodeId);

    float originalZ = screenRenderNode->GetRenderProperties().GetPositionZ();
    config.positionZ = NAN;
    DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, config);
    // positionZ should NOT be applied when NAN
    EXPECT_EQ(screenRenderNode->GetRenderProperties().GetPositionZ(), originalZ);
}

/**
 * @tc.name: SetDisplayModeTest006
 * @tc.desc: Test SetDisplayMode with Inf positionZ (should be rejected)
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeTest006, TestSize.Level1)
{
    RSContext context;
    NodeId screenNodeId = static_cast<NodeId>(100);
    NodeId displayNodeId = static_cast<NodeId>(1);

    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(screenNodeId, 1, context.weak_from_this());
    context.GetMutableNodeMap().RegisterRenderNode(screenRenderNode);

    RSDisplayNodeConfig config;
    config.screenId = 1;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    DisplayNodeCommandHelper::AddDisplayNodeToTree(context, displayNodeId);

    float originalZ = screenRenderNode->GetRenderProperties().GetPositionZ();
    config.positionZ = INFINITY;
    DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, config);
    // positionZ should NOT be applied when Inf
    EXPECT_EQ(screenRenderNode->GetRenderProperties().GetPositionZ(), originalZ);
}

/**
 * @tc.name: Create001
 * @tc.desc: test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, Create001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig config { 0, DisplayMode::EXPAND, 0 };
    DisplayNodeCommandHelper::Create(context, id, config);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);

    NodeId id2 = static_cast<NodeId>(2);
    config.displayMode = DisplayMode::MIRROR;
    DisplayNodeCommandHelper::Create(context, id2, config);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id2), nullptr);

    NodeId id3 = static_cast<NodeId>(3);
    config.mirrorNodeId = id2;
    DisplayNodeCommandHelper::Create(context, id3, config);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id3), nullptr);
}

/**
 * @tc.name: AddDisplayNodeToTree001
 * @tc.desc: test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, AddDisplayNodeToTree001, TestSize.Level1)
{
    RSContext context;
    auto renderNodeChildren = context.GetGlobalRootRenderNode()->children_;

    NodeId id = static_cast<NodeId>(1);
    DisplayNodeCommandHelper::AddDisplayNodeToTree(context, id);
    ASSERT_EQ(renderNodeChildren.size(), 0);

    NodeId id2 = static_cast<NodeId>(2);
    DisplayNodeCommandHelper::AddDisplayNodeToTree(context, id2);
    ASSERT_EQ(renderNodeChildren.size(), 0);
}

/**
 * @tc.name: RemoveDisplayNodeFromTree001
 * @tc.desc: test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, RemoveDisplayNodeFromTree001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    DisplayNodeCommandHelper::RemoveDisplayNodeFromTree(context, id);
    EXPECT_NE(context.GetGlobalRootRenderNode(), nullptr);

    NodeId id2 = static_cast<NodeId>(2);
    DisplayNodeCommandHelper::RemoveDisplayNodeFromTree(context, id2);
    EXPECT_NE(context.GetGlobalRootRenderNode(), nullptr);
}

/**
 * @tc.name: SetBootAnimation001
 * @tc.desc: test.
 * @tc.type: FUNC
 * @tc.require:SR000HSUII
 */
HWTEST_F(RSDisplayNodeCommandTest, SetBootAnimation001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig config { 0, DisplayMode::MIRROR, 0 };
    DisplayNodeCommandHelper::Create(context, id, config);
    DisplayNodeCommandHelper::SetBootAnimation(context, id, true);

    DisplayNodeCommandHelper::SetBootAnimation(context, 5, true);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);
}

/**
 * @tc.name: SetScreenRotation001
 * @tc.desc: SetScreenId test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetScreenRotation001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    DisplayNodeCommandHelper::SetScreenRotation(context, id, ScreenRotation::ROTATION_0);

    RSDisplayNodeConfig config { 0, DisplayMode::EXPAND, 0 };
    DisplayNodeCommandHelper::Create(context, id, config);
    DisplayNodeCommandHelper::SetScreenRotation(context, id, ScreenRotation::ROTATION_0);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);
}

/**
 * @tc.name: SetDisplayMode001
 * @tc.desc: SetScreenId test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayMode001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig config { 0, DisplayMode::EXPAND, 0 };
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);
    EXPECT_EQ(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);

    DisplayNodeCommandHelper::Create(context, id, config);
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);

    config.displayMode = DisplayMode::MIRROR;
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);

    NodeId mirrorNodeId = static_cast<NodeId>(2);
    config.mirrorNodeId = mirrorNodeId;
    DisplayNodeCommandHelper::Create(context, mirrorNodeId, config);
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);
}

/**
 * @tc.name: ClearModifiersByPidTest001
 * @tc.desc: SetScreenId test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, ClearModifiersByPidTest001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    int32_t pid = getpid();
    DisplayNodeCommandHelper::ClearModifiersByPid(context, id, pid);
    EXPECT_EQ(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);
}

/**
 * @tc.name: ClearModifiersByPidTest002
 * @tc.desc: SetScreenId test.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, ClearModifiersByPidTest002, TestSize.Level1)
{
    RSContext context;
    int32_t pid = getpid();
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig config;
    std::shared_ptr<RSLogicalDisplayRenderNode> renderNode = std::make_shared<RSLogicalDisplayRenderNode>(id, config);
    context.GetMutableNodeMap().RegisterRenderNode(renderNode);
    DisplayNodeCommandHelper::ClearModifiersByPid(context, id, pid);
    EXPECT_FALSE(!context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id));
}

/**
 * @tc.name: SetVirtualScreenMuteStatus001
 * @tc.desc: SetVirtualScreenMuteStatus test.
 * @tc.type: FUNC
 * @tc.require: issueIA61E9
 */
HWTEST_F(RSDisplayNodeCommandTest, SetVirtualScreenMuteStatus001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig config { 0, DisplayMode::MIRROR, 0 };
    DisplayNodeCommandHelper::Create(context, id, config);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);

    bool virtualScreenMuteStatus = false;
    DisplayNodeCommandHelper::SetVirtualScreenMuteStatus(context, 5, virtualScreenMuteStatus);
}

/**
 * @tc.name: CreateInvalidRotation001
 * @tc.desc: Create rejects out-of-range mirrorSourceRotation.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, CreateInvalidRotation001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig config;
    config.mirrorSourceRotation = static_cast<uint32_t>(ScreenRotation::INVALID_SCREEN_ROTATION) + 1;
    DisplayNodeCommandHelper::Create(context, id, config);
    EXPECT_EQ(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);
}

/**
 * @tc.name: SetDisplayModeInvalidRotation001
 * @tc.desc: SetDisplayMode rejects out-of-range mirrorSourceRotation without crash.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeInvalidRotation001, TestSize.Level1)
{
    RSContext context;
    NodeId id = static_cast<NodeId>(1);
    RSDisplayNodeConfig validConfig { 0, DisplayMode::MIRROR, 0 };
    DisplayNodeCommandHelper::Create(context, id, validConfig);
    ASSERT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);

    RSDisplayNodeConfig badConfig { 0, DisplayMode::MIRROR, 0 };
    badConfig.mirrorSourceRotation = static_cast<uint32_t>(ScreenRotation::INVALID_SCREEN_ROTATION) + 1;
    DisplayNodeCommandHelper::SetDisplayMode(context, id, badConfig);
    EXPECT_NE(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id), nullptr);
}

/**
 * @tc.name: SetWindowRecordConfigRejectsTest001
 * @tc.desc: SetWindowRecordConfig rejects a missing node, a physical screen and a non-MIRROR virtual output
 *           before mutating any display state
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSDisplayNodeCommandTest, SetWindowRecordConfigRejectsTest001, TestSize.Level1)
{
    constexpr ScreenId screenId = 1;
    constexpr NodeId displayNodeId = 1;
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10, 11 };

    // Missing node id: an existing virtual display stays untouched.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        RSDisplayNodeConfig config;
        config.screenId = screenId;
        DisplayNodeCommandHelper::Create(context, displayNodeId, config);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        ASSERT_TRUE(displayNode->IsOnVirtualScreen());
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId + 1, recordConfig);
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
    }

    // Physical screen: the virtual-screen gate rejects the start.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, false);
        RSDisplayNodeConfig config;
        config.screenId = screenId;
        DisplayNodeCommandHelper::Create(context, displayNodeId, config);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        ASSERT_FALSE(displayNode->IsOnVirtualScreen());
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
    }

    // Virtual but non-MIRROR: the mode gate rejects the start without changing the mode.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        RSDisplayNodeConfig config;
        config.screenId = screenId;
        config.displayMode = DisplayMode::EXPAND;
        DisplayNodeCommandHelper::Create(context, displayNodeId, config);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        ASSERT_TRUE(displayNode->IsOnVirtualScreen());
        ASSERT_FALSE(displayNode->IsMirrorDisplay());
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
        EXPECT_EQ(displayNode->GetDisplayMode(), DisplayMode::EXPAND);
    }
}

/**
 * @tc.name: WindowRecordSessionEndedByDisplayLifecycleTest001
 * @tc.desc: SetScreenId and RemoveDisplayNodeFromTree end an active record session before reparenting or
 * detaching, releasing both record-owned relations exactly once
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSDisplayNodeCommandTest, WindowRecordSessionEndedByDisplayLifecycleTest001, TestSize.Level1)
{
    constexpr NodeId displayNodeId = 1;

    // SetScreenId to another screen: end, release the output relation, reparent, stay paused MIRROR.
    {
        RSContext context;
        constexpr ScreenId firstScreenId = 1;
        constexpr ScreenId secondScreenId = 2;
        constexpr ScreenId sourceScreenId = 3;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID + 2, secondScreenId, true);
        auto secondScreen = context.GetNodeMap().GetRenderNode<RSScreenRenderNode>(TEST_SCREEN_NODE_ID + 2);
        ASSERT_NE(secondScreen, nullptr);
        auto fixture = CreateActiveRecordFixture(context, displayNodeId, firstScreenId, sourceScreenId);
        ASSERT_NE(fixture.display, nullptr);
        ASSERT_NE(fixture.outputScreen, nullptr);
        ASSERT_NE(fixture.sourceParams, nullptr);
        ASSERT_TRUE(fixture.display->IsWindowRecordActive());
        ASSERT_FALSE(fixture.display->GetMirrorSource().expired());
        ASSERT_EQ(fixture.sourceParams->mirrorDstCount_, 1u);

        DisplayNodeCommandHelper::SetScreenId(context, displayNodeId, secondScreenId);
        EXPECT_EQ(fixture.display->GetScreenId(), secondScreenId);
        EXPECT_FALSE(fixture.display->IsWindowRecordActive());
        EXPECT_TRUE(fixture.display->GetWindowRecordConfig().surfaceNodeIds.empty());
        EXPECT_TRUE(fixture.display->GetMirrorSource().expired());
        EXPECT_EQ(fixture.display->GetParent().lock(), secondScreen);
        // Four states: the display stays MIRROR with no source, the unified paused output.
        EXPECT_TRUE(fixture.display->IsMirrorDisplay());
        EXPECT_TRUE(fixture.outputScreen->GetMirrorSource().expired());
        EXPECT_EQ(fixture.sourceParams->mirrorDstCount_, 0u);
        EXPECT_FALSE(fixture.sourceParams->HasMirrorScreen());
    }

    // RemoveDisplayNodeFromTree with two outputs sharing the source: only this output's relation drops.
    {
        RSContext context;
        constexpr ScreenId outputScreenId = 1;
        constexpr ScreenId otherOutputScreenId = 2;
        constexpr ScreenId sourceScreenId = 3;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID + 2, otherOutputScreenId, true);
        auto otherOutputScreen = context.GetNodeMap().GetRenderNode<RSScreenRenderNode>(TEST_SCREEN_NODE_ID + 2);
        ASSERT_NE(otherOutputScreen, nullptr);
        auto fixture = CreateActiveRecordFixture(context, displayNodeId, outputScreenId, sourceScreenId);
        ASSERT_NE(fixture.display, nullptr);
        ASSERT_NE(fixture.outputScreen, nullptr);
        ASSERT_NE(fixture.sourceScreen, nullptr);
        ASSERT_NE(fixture.sourceParams, nullptr);
        ASSERT_TRUE(fixture.display->IsWindowRecordActive());
        ASSERT_FALSE(fixture.display->GetMirrorSource().expired());
        otherOutputScreen->SetIsMirrorScreen(true);
        otherOutputScreen->SetMirrorSource(fixture.sourceScreen);
        ASSERT_EQ(fixture.sourceParams->mirrorDstCount_, 2u);

        DisplayNodeCommandHelper::RemoveDisplayNodeFromTree(context, displayNodeId);
        EXPECT_FALSE(fixture.display->IsWindowRecordActive());
        EXPECT_TRUE(fixture.display->GetWindowRecordConfig().surfaceNodeIds.empty());
        EXPECT_TRUE(fixture.display->GetMirrorSource().expired());
        EXPECT_TRUE(fixture.display->GetParent().expired());
        // Both record-owned layers are empty, not carried over to the detached display or its output.
        EXPECT_TRUE(fixture.outputScreen->GetMirrorSource().expired());
        EXPECT_FALSE(fixture.outputScreen->IsMirrorScreen());
        // The other output keeps the shared relation and the source still reports one destination.
        EXPECT_EQ(otherOutputScreen->GetMirrorSource().lock(), fixture.sourceScreen);
        EXPECT_TRUE(otherOutputScreen->IsMirrorScreen());
        EXPECT_EQ(fixture.sourceParams->mirrorDstCount_, 1u);
        EXPECT_TRUE(fixture.sourceParams->HasMirrorScreen());
    }
}

/**
 * @tc.name: SetWindowRecordConfigStateMachineTest001
 * @tc.desc: A bounded start is accepted on a virtual MIRROR output, clear/restart works from the paused
 *           empty+no-source state, and oversized or inactive-empty configs keep the mirror source
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSDisplayNodeCommandTest, SetWindowRecordConfigStateMachineTest001, TestSize.Level1)
{
    constexpr ScreenId screenId = 1;
    constexpr NodeId displayNodeId = 1;
    constexpr NodeId pausedNodeId = 3;
    constexpr NodeId mirrorSourceId = TEST_MIRROR_SOURCE_ID;

    // Start accepted on a virtual MIRROR output with a live DMS source.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        CreateMirrorDisplay(context, displayNodeId, mirrorSourceId, screenId);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        ASSERT_TRUE(displayNode->IsOnVirtualScreen());
        EXPECT_EQ(displayNode->GetDisplayMode(), DisplayMode::MIRROR);
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());

        RSWindowRecordConfig recordConfig;
        recordConfig.renderFit = WindowRecordFit::ASPECT_FIT;
        recordConfig.surfaceNodeIds = { 10, 11 };
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
        EXPECT_TRUE(displayNode->IsWindowRecordActive());
        EXPECT_EQ(displayNode->GetWindowRecordConfig(), recordConfig);
    }

    // A paused empty+no-source MIRROR output can start, clear and restart without DMS.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        RSDisplayNodeConfig pausedConfig;
        pausedConfig.screenId = screenId;
        pausedConfig.displayMode = DisplayMode::MIRROR;
        pausedConfig.mirrorNodeId = 999;
        DisplayNodeCommandHelper::Create(context, pausedNodeId, pausedConfig);
        auto pausedNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(pausedNodeId);
        ASSERT_NE(pausedNode, nullptr);
        ASSERT_TRUE(pausedNode->IsMirrorDisplay());
        ASSERT_TRUE(pausedNode->GetMirrorSource().expired());
        ASSERT_FALSE(pausedNode->IsWindowRecordActive());

        RSWindowRecordConfig pausedRecordConfig;
        pausedRecordConfig.surfaceNodeIds = { 10 };
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, pausedNodeId, pausedRecordConfig);
        EXPECT_TRUE(pausedNode->IsWindowRecordActive());
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, pausedNodeId, RSWindowRecordConfig{});
        EXPECT_FALSE(pausedNode->IsWindowRecordActive());
        EXPECT_TRUE(pausedNode->GetMirrorSource().expired());
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, pausedNodeId, pausedRecordConfig);
        EXPECT_TRUE(pausedNode->IsWindowRecordActive());
    }

    // An oversized config keeps the previous (empty) config and the mirror on an inactive output.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        CreateMirrorDisplay(context, displayNodeId, mirrorSourceId, screenId);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        ASSERT_TRUE(displayNode->IsOnVirtualScreen());
        ASSERT_FALSE(displayNode->GetMirrorSource().expired());

        RSWindowRecordConfig oversizedConfig;
        oversizedConfig.surfaceNodeIds.assign(MAX_WINDOW_RECORD_SURFACE_NUM + 1, 10);
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, oversizedConfig);
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
        EXPECT_EQ(displayNode->GetDisplayMode(), DisplayMode::MIRROR);
        auto mirrorSource = displayNode->GetMirrorSource().lock();
        ASSERT_NE(mirrorSource, nullptr);
        EXPECT_EQ(mirrorSource->GetId(), mirrorSourceId);

        // An already stored record config is kept as well.
        RSWindowRecordConfig recordConfig;
        recordConfig.surfaceNodeIds = { 10 };
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
        ASSERT_TRUE(displayNode->IsWindowRecordActive());
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, oversizedConfig);
        EXPECT_EQ(displayNode->GetWindowRecordConfig(), recordConfig);
        EXPECT_NE(displayNode->GetMirrorSource().lock(), nullptr);
    }

    // An empty config on an inactive mirror is a no-op and keeps the source.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        CreateMirrorDisplay(context, displayNodeId, mirrorSourceId, screenId);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        ASSERT_TRUE(displayNode->IsOnVirtualScreen());
        ASSERT_FALSE(displayNode->GetMirrorSource().expired());
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, RSWindowRecordConfig{});
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
        EXPECT_EQ(displayNode->GetDisplayMode(), DisplayMode::MIRROR);
        auto mirrorSource = displayNode->GetMirrorSource().lock();
        ASSERT_NE(mirrorSource, nullptr);
        EXPECT_EQ(mirrorSource->GetId(), mirrorSourceId);
    }
}

/**
 * @tc.name: SetDisplayModeEndsRecordTest001
 * @tc.desc: SetDisplayMode ends an active record session before applying EXPAND or a MIRROR with an unknown
 *           source, while an inactive output keeps its existing mirror source
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeEndsRecordTest001, TestSize.Level1)
{
    constexpr ScreenId screenId = 1;
    constexpr NodeId displayNodeId = 1;

    // Active record + EXPAND: the session ends before the mode is applied.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        CreateMirrorDisplay(context, displayNodeId, TEST_MIRROR_SOURCE_ID, screenId);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        ASSERT_TRUE(displayNode->IsOnVirtualScreen());
        RSWindowRecordConfig recordConfig;
        recordConfig.surfaceNodeIds = { 10, 11, 12 };
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
        ASSERT_TRUE(displayNode->IsWindowRecordActive());
        ASSERT_FALSE(displayNode->GetMirrorSource().expired());

        RSDisplayNodeConfig expandConfig;
        expandConfig.screenId = screenId;
        expandConfig.displayMode = DisplayMode::EXPAND;
        DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, expandConfig);
        EXPECT_EQ(displayNode->GetDisplayMode(), DisplayMode::EXPAND);
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
        EXPECT_TRUE(displayNode->GetMirrorSource().expired());
    }

    // Active record + MIRROR with an unknown source: the session ends and stays paused MIRROR.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        CreateMirrorDisplay(context, displayNodeId, TEST_MIRROR_SOURCE_ID, screenId);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        RSWindowRecordConfig recordConfig;
        recordConfig.surfaceNodeIds = { 10 };
        DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
        ASSERT_TRUE(displayNode->IsWindowRecordActive());
        ASSERT_FALSE(displayNode->GetMirrorSource().expired());

        RSDisplayNodeConfig invalidConfig;
        invalidConfig.screenId = screenId;
        invalidConfig.displayMode = DisplayMode::MIRROR;
        invalidConfig.mirrorNodeId = 999;
        DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, invalidConfig);
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
        EXPECT_TRUE(displayNode->GetMirrorSource().expired());
        EXPECT_TRUE(displayNode->IsMirrorDisplay());
    }

    // Inactive output + MIRROR with an unknown source: no end, existing source retained.
    {
        RSContext context;
        RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);
        CreateMirrorDisplay(context, displayNodeId, TEST_MIRROR_SOURCE_ID, screenId);
        auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
        ASSERT_NE(displayNode, nullptr);
        ASSERT_FALSE(displayNode->IsWindowRecordActive());
        ASSERT_FALSE(displayNode->GetMirrorSource().expired());

        RSDisplayNodeConfig invalidConfig;
        invalidConfig.screenId = screenId;
        invalidConfig.displayMode = DisplayMode::MIRROR;
        invalidConfig.mirrorNodeId = 999;
        DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, invalidConfig);
        EXPECT_TRUE(displayNode->IsMirrorDisplay());
        EXPECT_FALSE(displayNode->IsWindowRecordActive());
        ASSERT_FALSE(displayNode->GetMirrorSource().expired());
        EXPECT_EQ(displayNode->GetMirrorSource().lock()->GetId(), TEST_MIRROR_SOURCE_ID);
    }
}

/**
 * @tc.name: SetDisplayModeMirrorRestoresAfterRecordSession001
 * @tc.desc: A mirror A -> record B -> clear (paused empty+no-source) -> explicit DMS C flow ends record and
 *           selects C
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeMirrorRestoresAfterRecordSession001, TestSize.Level1)
{
    RSContext context;
    constexpr ScreenId screenId = 1;
    constexpr ScreenId sourceScreenId = 2;
    constexpr NodeId displayNodeId = 1;
    auto fixture = CreateActiveRecordFixture(context, displayNodeId, screenId, sourceScreenId);
    ASSERT_NE(fixture.display, nullptr);
    ASSERT_TRUE(fixture.display->IsWindowRecordActive());
    // Start keeps the configured source until publication selects the record anchor.
    ASSERT_FALSE(fixture.display->GetMirrorSource().expired());

    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, RSWindowRecordConfig{});
    EXPECT_FALSE(fixture.display->IsWindowRecordActive());
    // Implicit clear is empty+no-source: the output stays MIRROR but is paused.
    EXPECT_TRUE(fixture.display->IsMirrorDisplay());
    EXPECT_TRUE(fixture.display->GetMirrorSource().expired());

    constexpr NodeId newSourceId = 3;
    RSDisplayNodeConfig newSourceConfig;
    newSourceConfig.screenId = screenId;
    DisplayNodeCommandHelper::Create(context, newSourceId, newSourceConfig);
    RSDisplayNodeConfig dmsConfig;
    dmsConfig.screenId = screenId;
    dmsConfig.displayMode = DisplayMode::MIRROR;
    dmsConfig.mirrorNodeId = newSourceId;
    DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, dmsConfig);
    EXPECT_FALSE(fixture.display->IsWindowRecordActive());
    ASSERT_FALSE(fixture.display->GetMirrorSource().expired());
    EXPECT_EQ(fixture.display->GetMirrorSource().lock()->GetId(), newSourceId);
}

/**
 * @tc.name: CreateSceneBoardBranchTest001
 * @tc.desc: Create with a marked token covers the SceneBoard branch.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, CreateSceneBoardBranchTest001, TestSize.Level1)
{
    constexpr pid_t pid = 816;
    constexpr uint64_t token = 817;
    constexpr NodeId directorNodeId = MakeNodeId(pid, 0);
    constexpr NodeId nodeId = MakeNodeId(pid, 1);
    RSContext context;
    RSUIDirectorCommandHelper::GoCreate(context, directorNodeId, token);
    RSUIDirectorCommandHelper::MarkSceneBoard(context, directorNodeId, token);
    RSDisplayNodeConfig config = {};
    DisplayNodeCommandHelper::Create(context, nodeId, config, token);
    auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(nodeId);
    ASSERT_NE(node, nullptr);
    EXPECT_TRUE(node->IsSceneBoard());
    EXPECT_EQ(node->GetUIContextToken(), token);
}

} // namespace OHOS::Rosen
