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

#include <vector>

#include "gtest/gtest.h"
#include "common/rs_common_def.h"
#include "include/command/rs_display_node_command.h"
#include "common/rs_common_def.h"
#include "command/rs_ui_director_command.h"
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
/**
 * @tc.name: SetWindowRecordConfigMissingNode001
 * @tc.desc: SetWindowRecordConfig is a no-op for a missing display node.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetWindowRecordConfigMissingNode001, TestSize.Level1)
{
    RSContext context;
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10, 11 };
    NodeId missingId = static_cast<NodeId>(5);
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, missingId, recordConfig);
    EXPECT_EQ(context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(missingId), nullptr);
}

/**
 * @tc.name: SetScreenIdClearsWindowRecordSession001
 * @tc.desc: Moving a display to another screen clears its previous record session.
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSDisplayNodeCommandTest, SetScreenIdClearsWindowRecordSession001, TestSize.Level1)
{
    RSContext context;
    constexpr ScreenId firstScreenId = 1;
    constexpr ScreenId secondScreenId = 2;
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID, firstScreenId, true);
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID + 1, secondScreenId, true);

    constexpr NodeId displayNodeId = 1;
    RSDisplayNodeConfig config;
    config.screenId = firstScreenId;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
    ASSERT_NE(displayNode, nullptr);
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10, 11 };
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
    ASSERT_TRUE(displayNode->IsWindowRecordActive());

    DisplayNodeCommandHelper::SetScreenId(context, displayNodeId, secondScreenId);
    EXPECT_EQ(displayNode->GetScreenId(), secondScreenId);
    EXPECT_FALSE(displayNode->IsWindowRecordActive());
    EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
}

/**
 * @tc.name: SetWindowRecordConfigPhysicalScreen001
 * @tc.desc: SetWindowRecordConfig is rejected when the display node is not on a virtual screen.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetWindowRecordConfigPhysicalScreen001, TestSize.Level1)
{
    RSContext context;
    ScreenId screenId = 1;
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, false);

    NodeId displayNodeId = static_cast<NodeId>(1);
    RSDisplayNodeConfig config;
    config.screenId = screenId;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
    ASSERT_NE(displayNode, nullptr);
    ASSERT_FALSE(displayNode->IsOnVirtualScreen());

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10, 11 };
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
    EXPECT_FALSE(displayNode->IsWindowRecordActive());
    EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
}

/**
 * @tc.name: SetWindowRecordConfigVirtualScreen001
 * @tc.desc: SetWindowRecordConfig stores a bounded config on a virtual screen.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetWindowRecordConfigVirtualScreen001, TestSize.Level1)
{
    RSContext context;
    ScreenId screenId = 1;
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);

    NodeId displayNodeId = static_cast<NodeId>(1);
    RSDisplayNodeConfig config;
    config.screenId = screenId;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
    ASSERT_NE(displayNode, nullptr);
    ASSERT_TRUE(displayNode->IsOnVirtualScreen());
    EXPECT_FALSE(displayNode->IsWindowRecordActive());
    EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());

    RSWindowRecordConfig recordConfig;
    recordConfig.renderFit = WindowRecordFit::ASPECT_FIT;
    recordConfig.surfaceNodeIds = { 10, 11 };
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
    EXPECT_TRUE(displayNode->IsWindowRecordActive());
    EXPECT_EQ(displayNode->GetWindowRecordConfig(), recordConfig);
}

/**
 * @tc.name: SetWindowRecordConfigTooManyIds001
 * @tc.desc: SetWindowRecordConfig keeps the previous config when the id count exceeds the cap.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetWindowRecordConfigTooManyIds001, TestSize.Level1)
{
    RSContext context;
    ScreenId screenId = 1;
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);

    NodeId displayNodeId = static_cast<NodeId>(1);
    RSDisplayNodeConfig config;
    config.screenId = screenId;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
    ASSERT_NE(displayNode, nullptr);
    ASSERT_TRUE(displayNode->IsOnVirtualScreen());

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10 };
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
    ASSERT_TRUE(displayNode->IsWindowRecordActive());

    RSWindowRecordConfig oversizedConfig;
    oversizedConfig.surfaceNodeIds.assign(MAX_WINDOW_RECORD_SURFACE_NUM + 1, 10);
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, oversizedConfig);
    EXPECT_EQ(displayNode->GetWindowRecordConfig(), recordConfig);
}

/**
 * @tc.name: SetWindowRecordConfigMirrorSourceReset001
 * @tc.desc: A record config resets the mirror source of the display node.
 * @tc.type: FUNC
 */
HWTEST_F(RSDisplayNodeCommandTest, SetWindowRecordConfigMirrorSourceReset001, TestSize.Level1)
{
    RSContext context;
    ScreenId screenId = 1;
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);

    NodeId mirrorSourceId = static_cast<NodeId>(2);
    NodeId displayNodeId = static_cast<NodeId>(1);
    RSDisplayNodeConfig config;
    config.screenId = screenId;
    DisplayNodeCommandHelper::Create(context, mirrorSourceId, config);
    config.displayMode = DisplayMode::MIRROR;
    config.mirrorNodeId = mirrorSourceId;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
    ASSERT_NE(displayNode, nullptr);
    ASSERT_FALSE(displayNode->GetMirrorSource().expired());

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10 };
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
    EXPECT_TRUE(displayNode->GetMirrorSource().expired());
}

/**
 * @tc.name: SetDisplayModeClearsRecordSession001
 * @tc.desc: SetDisplayMode ends an active record session before applying a non-mirror mode.
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeClearsRecordSession001, TestSize.Level1)
{
    RSContext context;
    ScreenId screenId = 1;
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);

    NodeId displayNodeId = static_cast<NodeId>(1);
    RSDisplayNodeConfig config;
    config.screenId = screenId;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
    ASSERT_NE(displayNode, nullptr);
    ASSERT_TRUE(displayNode->IsOnVirtualScreen());

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10, 11, 12 };
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
    ASSERT_TRUE(displayNode->IsWindowRecordActive());

    RSDisplayNodeConfig expandConfig;
    expandConfig.screenId = screenId;
    expandConfig.displayMode = DisplayMode::EXPAND;
    DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, expandConfig);
    EXPECT_EQ(displayNode->GetDisplayMode(), DisplayMode::EXPAND);
    EXPECT_FALSE(displayNode->IsWindowRecordActive());
    EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
    EXPECT_TRUE(displayNode->GetMirrorSource().expired());
}

/**
 * @tc.name: SetDisplayModeMirrorRestoresAfterRecordSession001
 * @tc.desc: SetDisplayMode clears the record session and restores the requested mirror source.
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSDisplayNodeCommandTest, SetDisplayModeMirrorRestoresAfterRecordSession001, TestSize.Level1)
{
    RSContext context;
    ScreenId screenId = 1;
    RegisterScreenNode(context, TEST_SCREEN_NODE_ID, screenId, true);

    NodeId mirrorSourceId = static_cast<NodeId>(2);
    NodeId displayNodeId = static_cast<NodeId>(1);
    RSDisplayNodeConfig config;
    config.screenId = screenId;
    DisplayNodeCommandHelper::Create(context, mirrorSourceId, config);
    config.displayMode = DisplayMode::MIRROR;
    config.mirrorNodeId = mirrorSourceId;
    DisplayNodeCommandHelper::Create(context, displayNodeId, config);
    auto displayNode = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId);
    ASSERT_NE(displayNode, nullptr);
    ASSERT_FALSE(displayNode->GetMirrorSource().expired());

    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { 10 };
    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
    ASSERT_TRUE(displayNode->IsWindowRecordActive());
    ASSERT_TRUE(displayNode->GetMirrorSource().expired());

    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, RSWindowRecordConfig{});
    EXPECT_FALSE(displayNode->IsWindowRecordActive());
    EXPECT_TRUE(displayNode->GetMirrorSource().expired());

    DisplayNodeCommandHelper::SetWindowRecordConfig(context, displayNodeId, recordConfig);
    ASSERT_TRUE(displayNode->IsWindowRecordActive());
    ASSERT_TRUE(displayNode->GetMirrorSource().expired());

    DisplayNodeCommandHelper::SetDisplayMode(context, displayNodeId, config);
    EXPECT_FALSE(displayNode->IsWindowRecordActive());
    EXPECT_TRUE(displayNode->GetWindowRecordConfig().surfaceNodeIds.empty());
    EXPECT_EQ(displayNode->GetDisplayMode(), DisplayMode::MIRROR);
    auto mirrorSource = displayNode->GetMirrorSource().lock();
    ASSERT_NE(mirrorSource, nullptr);
    EXPECT_EQ(mirrorSource->GetId(), mirrorSourceId);
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
