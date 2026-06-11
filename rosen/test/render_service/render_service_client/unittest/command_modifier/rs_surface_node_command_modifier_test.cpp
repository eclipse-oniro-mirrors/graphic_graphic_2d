/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "gtest/hwext/gtest-tag.h"

#include "command_modifier/rs_surface_node_command_modifier.h"
#include "ui/rs_surface_node.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

class RSSurfaceNodeCommandModifierTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSSurfaceNodeCommandModifierTest::SetUpTestCase() {}
void RSSurfaceNodeCommandModifierTest::TearDownTestCase() {}
void RSSurfaceNodeCommandModifierTest::SetUp() {}
void RSSurfaceNodeCommandModifierTest::TearDown() {}

static std::weak_ptr<RSNode> MakeExpiredNode()
{
    std::weak_ptr<RSNode> weak;
    { auto n = RSSurfaceNode::Create(); weak = n; }
    return weak;
}

/**
 * @tc.name: LeashPersistentIdTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, LeashPersistentIdTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    LeashPersistentIdCmdParam param{100};
    auto mod = std::make_shared<LeashPersistentIdCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::LEASH_PERSISTENT_ID);
    EXPECT_EQ(mod->GetParam().leashPersistentId_, 100);

    LeashPersistentIdCmdParam param2{200};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().leashPersistentId_, 200);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("leashPersistentId"), std::string::npos);
}

/**
 * @tc.name: LeashPersistentIdTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, LeashPersistentIdTest002, TestSize.Level1)
{
    LeashPersistentIdCmdParam param{0};
    auto mod = std::make_shared<LeashPersistentIdCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: SecurityLayerTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SecurityLayerTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    SecurityLayerCmdParam param{true};
    auto mod = std::make_shared<SecurityLayerCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::IS_SECURITY_LAYER);
    EXPECT_TRUE(mod->GetParam().isSecurityLayer_);

    SecurityLayerCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isSecurityLayer_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isSecurityLayer"), std::string::npos);
}

/**
 * @tc.name: SecurityLayerTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SecurityLayerTest002, TestSize.Level1)
{
    SecurityLayerCmdParam param{true};
    auto mod = std::make_shared<SecurityLayerCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: SkipLayerTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SkipLayerTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    SkipLayerCmdParam param{true};
    auto mod = std::make_shared<SkipLayerCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::IS_SKIP_LAYER);
    EXPECT_TRUE(mod->GetParam().isSkipLayer_);

    SkipLayerCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isSkipLayer_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isSkipLayer"), std::string::npos);
}

/**
 * @tc.name: SkipLayerTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SkipLayerTest002, TestSize.Level1)
{
    SkipLayerCmdParam param{true};
    auto mod = std::make_shared<SkipLayerCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: SnapshotSkipLayerTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SnapshotSkipLayerTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    SnapshotSkipLayerCmdParam param{true};
    auto mod = std::make_shared<SnapshotSkipLayerCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::IS_SNAPSHOT_SKIP_LAYER);
    EXPECT_TRUE(mod->GetParam().isSnapshotSkipLayer_);

    SnapshotSkipLayerCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isSnapshotSkipLayer_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isSnapshotSkipLayer"), std::string::npos);
}

/**
 * @tc.name: SnapshotSkipLayerTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SnapshotSkipLayerTest002, TestSize.Level1)
{
    SnapshotSkipLayerCmdParam param{true};
    auto mod = std::make_shared<SnapshotSkipLayerCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: HasFingerprintTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HasFingerprintTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    HasFingerprintCmdParam param{true};
    auto mod = std::make_shared<HasFingerprintCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::HAS_FINGER_PRINT);
    EXPECT_TRUE(mod->GetParam().hasFingerprint_);

    HasFingerprintCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().hasFingerprint_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("hasFingerprint"), std::string::npos);
}

/**
 * @tc.name: HasFingerprintTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HasFingerprintTest002, TestSize.Level1)
{
    HasFingerprintCmdParam param{true};
    auto mod = std::make_shared<HasFingerprintCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: ColorSpaceTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ColorSpaceTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    ColorSpaceCmdParam param{GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB};
    auto mod = std::make_shared<ColorSpaceCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::COLOR_SPACE);
    EXPECT_EQ(mod->GetParam().colorSpace_, GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB);

    ColorSpaceCmdParam param2{GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DISPLAY_P3};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().colorSpace_, GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DISPLAY_P3);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("colorSpace"), std::string::npos);
}

/**
 * @tc.name: ColorSpaceTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ColorSpaceTest002, TestSize.Level1)
{
    ColorSpaceCmdParam param{GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB};
    auto mod = std::make_shared<ColorSpaceCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: AbilityBGAlphaTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, AbilityBGAlphaTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    constexpr uint8_t alphaVal = 128;
    AbilityBGAlphaCmdParam param{alphaVal};
    auto mod = std::make_shared<AbilityBGAlphaCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::ABILITY_BG_ALPHA);
    EXPECT_EQ(mod->GetParam().abilityBGAlpha_, alphaVal);

    constexpr uint8_t alphaVal2 = 255;
    AbilityBGAlphaCmdParam param2{alphaVal2};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().abilityBGAlpha_, alphaVal2);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("abilityBGAlpha"), std::string::npos);
}

/**
 * @tc.name: AbilityBGAlphaTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, AbilityBGAlphaTest002, TestSize.Level1)
{
    AbilityBGAlphaCmdParam param{0};
    auto mod = std::make_shared<AbilityBGAlphaCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: NotifyUIBufferAvailableTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, NotifyUIBufferAvailableTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    NotifyUIBufferAvailableCmdParam param{true};
    auto mod = std::make_shared<NotifyUIBufferAvailableCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::NOTIFY_UI_BUFFER_AVL);
    EXPECT_TRUE(mod->GetParam().notifyUIBufferAvailable_);

    NotifyUIBufferAvailableCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().notifyUIBufferAvailable_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("notifyUIBufferAvailable"), std::string::npos);
}

/**
 * @tc.name: NotifyUIBufferAvailableTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, NotifyUIBufferAvailableTest002, TestSize.Level1)
{
    NotifyUIBufferAvailableCmdParam param{true};
    auto mod = std::make_shared<NotifyUIBufferAvailableCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: ContainerWindowTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ContainerWindowTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    RRect rrect{RectF(0, 0, 100, 100), 10.f, CornerSize::CornerSize{5, 5, 5, 5}};
    ContainerWindowCmdParam param{true, rrect};
    auto mod = std::make_shared<ContainerWindowCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::SET_CONTAINER_WINDOW);
    EXPECT_TRUE(mod->GetParam().hasContainerWindow_);

    ContainerWindowCmdParam param2{false, rrect};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().hasContainerWindow_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("hasContainerWindow"), std::string::npos);
}

/**
 * @tc.name: ContainerWindowTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ContainerWindowTest002, TestSize.Level1)
{
    RRect rrect;
    ContainerWindowCmdParam param{true, rrect};
    auto mod = std::make_shared<ContainerWindowCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: FreezeCmdTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, FreezeCmdTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    FreezeCmdParam param{true, false};
    auto mod = std::make_shared<FreezeCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::SF_IS_FREEZE);
    EXPECT_TRUE(mod->GetParam().isFreeze_);
    EXPECT_FALSE(mod->GetParam().isMarkedByUI_);

    FreezeCmdParam param2{false, true};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isFreeze_);
    EXPECT_TRUE(mod->GetParam().isMarkedByUI_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isFreeze"), std::string::npos);
}

/**
 * @tc.name: FreezeCmdTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, FreezeCmdTest002, TestSize.Level1)
{
    FreezeCmdParam param{true, true};
    auto mod = std::make_shared<FreezeCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: HardwareEnableHintTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HardwareEnableHintTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    HardwareEnableHintCmdParam param{true};
    auto mod = std::make_shared<HardwareEnableHintCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::HARDWARE_ENABLE_HINT);
    EXPECT_TRUE(mod->GetParam().isHardwareEnabled_);

    HardwareEnableHintCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isHardwareEnabled_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isHardwareEnabled"), std::string::npos);
}

/**
 * @tc.name: HardwareEnableHintTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HardwareEnableHintTest002, TestSize.Level1)
{
    HardwareEnableHintCmdParam param{true};
    auto mod = std::make_shared<HardwareEnableHintCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: HardwareEnabledTest001
 * @tc.desc: Test all methods including UpdateToRenderWithResult
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HardwareEnabledTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    HardwareEnabledCmdParam param{true, SelfDrawingNodeType::OVERLAY_NODE, false};
    auto mod = std::make_shared<HardwareEnabledCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::HARDWARE_ENABLED);
    EXPECT_TRUE(mod->GetParam().isHardwareEnabled_);
    EXPECT_EQ(mod->GetParam().isSelfDrawingNodeType_, SelfDrawingNodeType::OVERLAY_NODE);
    EXPECT_FALSE(mod->GetParam().isDynamicHardwareEnable_);

    HardwareEnabledCmdParam param2{false, SelfDrawingNodeType::DEFAULT, true};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isHardwareEnabled_);
    EXPECT_EQ(mod->GetParam().isSelfDrawingNodeType_, SelfDrawingNodeType::DEFAULT);
    EXPECT_TRUE(mod->GetParam().isDynamicHardwareEnable_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isHardwareEnabled"), std::string::npos);
}

/**
 * @tc.name: HardwareEnabledTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HardwareEnabledTest002, TestSize.Level1)
{
    HardwareEnabledCmdParam param{true, SelfDrawingNodeType::DEFAULT, false};
    auto mod = std::make_shared<HardwareEnabledCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: HardwareEnabledTest003
 * @tc.desc: Test UpdateToRenderWithResult with null node returns false
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HardwareEnabledTest003, TestSize.Level1)
{
    HardwareEnabledCmdParam param{true, SelfDrawingNodeType::DEFAULT, false};
    auto mod = std::make_shared<HardwareEnabledCmdModifier>(MakeExpiredNode(), param);
    auto result = mod->UpdateToRenderWithResult();
    bool val = std::get<bool>(result);
    EXPECT_FALSE(val);
}

/**
 * @tc.name: BootAnimationTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, BootAnimationTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    BootAnimationCmdParam param{true};
    auto mod = std::make_shared<BootAnimationCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::SF_IS_BOOT_ANIMATION);
    EXPECT_TRUE(mod->GetParam().isBootAnimation_);

    BootAnimationCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isBootAnimation_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isBootAnimation"), std::string::npos);
}

/**
 * @tc.name: BootAnimationTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, BootAnimationTest002, TestSize.Level1)
{
    BootAnimationCmdParam param{true};
    auto mod = std::make_shared<BootAnimationCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: GlobalPositionEnabledTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, GlobalPositionEnabledTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    GlobalPositionEnabledCmdParam param{true};
    auto mod = std::make_shared<GlobalPositionEnabledCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::IS_GLOBAL_POSITION_ENABLED);
    EXPECT_TRUE(mod->GetParam().isGlobalPositionEnabled_);

    GlobalPositionEnabledCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isGlobalPositionEnabled_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isGlobalPositionEnabled"), std::string::npos);
}

/**
 * @tc.name: GlobalPositionEnabledTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, GlobalPositionEnabledTest002, TestSize.Level1)
{
    GlobalPositionEnabledCmdParam param{true};
    auto mod = std::make_shared<GlobalPositionEnabledCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: ClonedNodeInfoTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ClonedNodeInfoTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    ClonedNodeInfoCmdParam param{100, true, false};
    auto mod = std::make_shared<ClonedNodeInfoCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::CLONED_NODE_INFO);
    EXPECT_EQ(mod->GetParam().clonedNodeId_, 100);
    EXPECT_TRUE(mod->GetParam().clonedNeedOffscreen_);
    EXPECT_FALSE(mod->GetParam().clonedIsRelated_);

    ClonedNodeInfoCmdParam param2{200, false, true};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().clonedNodeId_, 200);
    EXPECT_FALSE(mod->GetParam().clonedNeedOffscreen_);
    EXPECT_TRUE(mod->GetParam().clonedIsRelated_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("clonedNodeId"), std::string::npos);
}

/**
 * @tc.name: ClonedNodeInfoTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ClonedNodeInfoTest002, TestSize.Level1)
{
    ClonedNodeInfoCmdParam param{0, false, false};
    auto mod = std::make_shared<ClonedNodeInfoCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: ForceUIFirstTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ForceUIFirstTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    ForceUIFirstCmdParam param{true};
    auto mod = std::make_shared<ForceUIFirstCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::FORCE_UI_FIRST);
    EXPECT_TRUE(mod->GetParam().forceUIFirst_);

    ForceUIFirstCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().forceUIFirst_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("forceUIFirst"), std::string::npos);
}

/**
 * @tc.name: ForceUIFirstTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ForceUIFirstTest002, TestSize.Level1)
{
    ForceUIFirstCmdParam param{true};
    auto mod = std::make_shared<ForceUIFirstCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: AncoFlagsTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, AncoFlagsTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    constexpr uint32_t flagsVal = 3;
    AncoFlagsCmdParam param{flagsVal};
    auto mod = std::make_shared<AncoFlagsCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::ANCO_FLAGS);
    EXPECT_EQ(mod->GetParam().ancoFlags_, flagsVal);

    constexpr uint32_t flagsVal2 = 7;
    AncoFlagsCmdParam param2{flagsVal2};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().ancoFlags_, flagsVal2);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("ancoFlags"), std::string::npos);
}

/**
 * @tc.name: AncoFlagsTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, AncoFlagsTest002, TestSize.Level1)
{
    AncoFlagsCmdParam param{0};
    auto mod = std::make_shared<AncoFlagsCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: SkipDrawTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SkipDrawTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    SkipDrawCmdParam param{true};
    auto mod = std::make_shared<SkipDrawCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::IS_SKIP_DRAW);
    EXPECT_TRUE(mod->GetParam().skipDraw_);

    SkipDrawCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().skipDraw_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("skipDraw"), std::string::npos);
}

/**
 * @tc.name: SkipDrawTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SkipDrawTest002, TestSize.Level1)
{
    SkipDrawCmdParam param{true};
    auto mod = std::make_shared<SkipDrawCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: WatermarkEnabledTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, WatermarkEnabledTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    WatermarkEnabledCmdParam param{"testMark", true};
    auto mod = std::make_shared<WatermarkEnabledCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::WATER_MARK_ENABLED);
    EXPECT_EQ(mod->GetParam().watermarkName_, "testMark");
    EXPECT_TRUE(mod->GetParam().watermarkEnabled_);

    WatermarkEnabledCmdParam param2{"otherMark", false};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().watermarkName_, "otherMark");
    EXPECT_FALSE(mod->GetParam().watermarkEnabled_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("watermarkName"), std::string::npos);
}

/**
 * @tc.name: WatermarkEnabledTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, WatermarkEnabledTest002, TestSize.Level1)
{
    WatermarkEnabledCmdParam param{"", true};
    auto mod = std::make_shared<WatermarkEnabledCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: AbilityStateTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, AbilityStateTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    AbilityStateCmdParam param{RSSurfaceNodeAbilityState::FOREGROUND};
    auto mod = std::make_shared<AbilityStateCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::ABILITY_STATE);
    EXPECT_EQ(mod->GetParam().abilityState_, RSSurfaceNodeAbilityState::FOREGROUND);

    AbilityStateCmdParam param2{RSSurfaceNodeAbilityState::BACKGROUND};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().abilityState_, RSSurfaceNodeAbilityState::BACKGROUND);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("abilityState"), std::string::npos);
}

/**
 * @tc.name: AbilityStateTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, AbilityStateTest002, TestSize.Level1)
{
    AbilityStateCmdParam param{RSSurfaceNodeAbilityState::FOREGROUND};
    auto mod = std::make_shared<AbilityStateCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: HidePrivacyContentTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HidePrivacyContentTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    HidePrivacyContentCmdParam param{true};
    auto mod = std::make_shared<HidePrivacyContentCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::SET_HIDE_PRIVACY_CONTENT);
    EXPECT_TRUE(mod->GetParam().hidePrivacyContent_);

    HidePrivacyContentCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().hidePrivacyContent_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("hidePrivacyContent"), std::string::npos);
}

/**
 * @tc.name: HidePrivacyContentTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HidePrivacyContentTest002, TestSize.Level1)
{
    HidePrivacyContentCmdParam param{true};
    auto mod = std::make_shared<HidePrivacyContentCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: HidePrivacyContentTest003
 * @tc.desc: Test UpdateToRenderWithResult with null node returns UNKNOWN_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, HidePrivacyContentTest003, TestSize.Level1)
{
    HidePrivacyContentCmdParam param{true};
    auto mod = std::make_shared<HidePrivacyContentCmdModifier>(MakeExpiredNode(), param);
    auto result = mod->UpdateToRenderWithResult();
    auto* errCode = std::get_if<RSInterfaceErrorCode>(&result);
    ASSERT_TRUE(errCode);
    EXPECT_EQ(*errCode, RSInterfaceErrorCode::UNKNOWN_ERROR);
}

/**
 * @tc.name: ApiCompatibleVersionTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ApiCompatibleVersionTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    constexpr uint32_t versionVal = 10;
    ApiCompatibleVersionCmdParam param{versionVal};
    auto mod = std::make_shared<ApiCompatibleVersionCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::API_COMPAT_VERSION);
    EXPECT_EQ(mod->GetParam().apiCompatibleVersion_, versionVal);

    constexpr uint32_t versionVal2 = 20;
    ApiCompatibleVersionCmdParam param2{versionVal2};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().apiCompatibleVersion_, versionVal2);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("apiCompatibleVersion"), std::string::npos);
}

/**
 * @tc.name: ApiCompatibleVersionTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ApiCompatibleVersionTest002, TestSize.Level1)
{
    ApiCompatibleVersionCmdParam param{0};
    auto mod = std::make_shared<ApiCompatibleVersionCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: VirtualDisplayIdTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, VirtualDisplayIdTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    constexpr uint32_t displayId = 5;
    VirtualDisplayIdCmdParam param{displayId};
    auto mod = std::make_shared<VirtualDisplayIdCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::VIRTUAL_DISPLAY_ID);
    EXPECT_EQ(mod->GetParam().virtualDisplayId_, displayId);

    constexpr uint32_t displayId2 = 10;
    VirtualDisplayIdCmdParam param2{displayId2};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().virtualDisplayId_, displayId2);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("virtualDisplayId"), std::string::npos);
}

/**
 * @tc.name: VirtualDisplayIdTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, VirtualDisplayIdTest002, TestSize.Level1)
{
    VirtualDisplayIdCmdParam param{0};
    auto mod = std::make_shared<VirtualDisplayIdCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: AttachToWindowContainerTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, AttachToWindowContainerTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    constexpr ScreenId screenId = 42;
    AttachToWindowContainerCmdParam param{screenId};
    auto mod = std::make_shared<AttachToWindowContainerCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::ATTACH_TO_WINDOW_CONTAINER);
    EXPECT_EQ(mod->GetParam().attachToWindowContainer_, screenId);

    constexpr ScreenId screenId2 = 99;
    AttachToWindowContainerCmdParam param2{screenId2};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().attachToWindowContainer_, screenId2);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("attachToWindowContainer"), std::string::npos);
}

/**
 * @tc.name: AttachToWindowContainerTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, AttachToWindowContainerTest002, TestSize.Level1)
{
    AttachToWindowContainerCmdParam param{0};
    auto mod = std::make_shared<AttachToWindowContainerCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: RegionToBeMagnifiedTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, RegionToBeMagnifiedTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    Vector4<int> region{1, 2, 3, 4};
    RegionToBeMagnifiedCmdParam param{region};
    auto mod = std::make_shared<RegionToBeMagnifiedCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::REGION_TO_BE_MAGNIFIED);
    EXPECT_EQ(mod->GetParam().regionToBeMagnified_.x_, 1);
    EXPECT_EQ(mod->GetParam().regionToBeMagnified_.y_, 2);
    EXPECT_EQ(mod->GetParam().regionToBeMagnified_.z_, 3);
    EXPECT_EQ(mod->GetParam().regionToBeMagnified_.w_, 4);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("regionToBeMagnified"), std::string::npos);
}

/**
 * @tc.name: RegionToBeMagnifiedTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, RegionToBeMagnifiedTest002, TestSize.Level1)
{
    Vector4<int> region{0, 0, 0, 0};
    RegionToBeMagnifiedCmdParam param{region};
    auto mod = std::make_shared<RegionToBeMagnifiedCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: DetachFromWindowContainerTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, DetachFromWindowContainerTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    constexpr ScreenId screenId = 42;
    DetachFromWindowContainerCmdParam param{screenId};
    auto mod = std::make_shared<DetachFromWindowContainerCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::DETACH_TO_WINDOW_CONTAINER);
    EXPECT_EQ(mod->GetParam().detachFromWindowContainer_, screenId);

    constexpr ScreenId screenId2 = 99;
    DetachFromWindowContainerCmdParam param2{screenId2};
    mod->SetParam(param2);
    EXPECT_EQ(mod->GetParam().detachFromWindowContainer_, screenId2);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("detachFromWindowContainer"), std::string::npos);
}

/**
 * @tc.name: DetachFromWindowContainerTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, DetachFromWindowContainerTest002, TestSize.Level1)
{
    DetachFromWindowContainerCmdParam param{0};
    auto mod = std::make_shared<DetachFromWindowContainerCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: CompositeLayerTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, CompositeLayerTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    CompositeLayerCmdParam param{true, 0};
    auto mod = std::make_shared<CompositeLayerCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::UPDATE_COMPOSITE_LAYER);
    EXPECT_TRUE(mod->GetParam().isCompositeLayer_);
    EXPECT_EQ(mod->GetParam().isMarkedByUI_, 0);

    CompositeLayerCmdParam param2{false, 1};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isCompositeLayer_);
    EXPECT_EQ(mod->GetParam().isMarkedByUI_, 1);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isCompositeLayer"), std::string::npos);
}

/**
 * @tc.name: CompositeLayerTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, CompositeLayerTest002, TestSize.Level1)
{
    CompositeLayerCmdParam param{true, 0};
    auto mod = std::make_shared<CompositeLayerCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: CompositeLayerTest003
 * @tc.desc: Test UpdateToRenderWithResult with null node returns false
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, CompositeLayerTest003, TestSize.Level1)
{
    CompositeLayerCmdParam param{true, 0};
    auto mod = std::make_shared<CompositeLayerCmdModifier>(MakeExpiredNode(), param);
    auto result = mod->UpdateToRenderWithResult();
    bool val = std::get<bool>(result);
    EXPECT_FALSE(val);
}

/**
 * @tc.name: CompositeLayerTest004
 * @tc.desc: Test UpdateToRenderWithResult with valid node returns true
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, CompositeLayerTest004, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    CompositeLayerCmdParam param{true, 0};
    auto mod = std::make_shared<CompositeLayerCmdModifier>(node, param);
    auto result = mod->UpdateToRenderWithResult();
    bool val = std::get<bool>(result);
    EXPECT_TRUE(val);
}

/**
 * @tc.name: StaticCachedTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, StaticCachedTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    StaticCachedCmdParam param{true};
    auto mod = std::make_shared<StaticCachedCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::SET_STATIC_CACHED);
    EXPECT_TRUE(mod->GetParam().isStaticCached_);

    StaticCachedCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isStaticCached_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isStaticCached"), std::string::npos);
}

/**
 * @tc.name: StaticCachedTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, StaticCachedTest002, TestSize.Level1)
{
    StaticCachedCmdParam param{true};
    auto mod = std::make_shared<StaticCachedCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: FrameGravityNewVersionEnabledTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, FrameGravityNewVersionEnabledTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    FrameGravityNewVersionEnabledCmdParam param{true};
    auto mod = std::make_shared<FrameGravityNewVersionEnabledCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::IS_FRAME_GRAVITY_NEW_VER_ENABLED);
    EXPECT_TRUE(mod->GetParam().isFrameGravityNewVersionEnabled_);

    FrameGravityNewVersionEnabledCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isFrameGravityNewVersionEnabled_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isFrameGravityNewVersionEnabled"), std::string::npos);
}

/**
 * @tc.name: FrameGravityNewVersionEnabledTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, FrameGravityNewVersionEnabledTest002, TestSize.Level1)
{
    FrameGravityNewVersionEnabledCmdParam param{true};
    auto mod = std::make_shared<FrameGravityNewVersionEnabledCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: SurfaceBufferOpaqueTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SurfaceBufferOpaqueTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    SurfaceBufferOpaqueCmdParam param{true};
    auto mod = std::make_shared<SurfaceBufferOpaqueCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::IS_SURFACE_BUFFER_OPAQUE);
    EXPECT_TRUE(mod->GetParam().isSurfaceBufferOpaque_);

    SurfaceBufferOpaqueCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isSurfaceBufferOpaque_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isSurfaceBufferOpaque"), std::string::npos);
}

/**
 * @tc.name: SurfaceBufferOpaqueTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SurfaceBufferOpaqueTest002, TestSize.Level1)
{
    SurfaceBufferOpaqueCmdParam param{true};
    auto mod = std::make_shared<SurfaceBufferOpaqueCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: ContainerWindowTransparentTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ContainerWindowTransparentTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    ContainerWindowTransparentCmdParam param{true};
    auto mod = std::make_shared<ContainerWindowTransparentCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::IS_CONTAINER_WINDOW_TRANSPARENT);
    EXPECT_TRUE(mod->GetParam().isContainerWindowTransparent_);

    ContainerWindowTransparentCmdParam param2{false};
    mod->SetParam(param2);
    EXPECT_FALSE(mod->GetParam().isContainerWindowTransparent_);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("isContainerWindowTransparent"), std::string::npos);
}

/**
 * @tc.name: ContainerWindowTransparentTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, ContainerWindowTransparentTest002, TestSize.Level1)
{
    ContainerWindowTransparentCmdParam param{true};
    auto mod = std::make_shared<ContainerWindowTransparentCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: BufferAvailableCallbackTest001
 * @tc.desc: Test GetType, SetParam always updates, DumpParam with valid callback
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, BufferAvailableCallbackTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    bool called = false;
    BufferAvailableCallbackCmdParam param{[&called]() { called = true; }};
    auto mod = std::make_shared<BufferAvailableCallbackCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::SET_BUFFER_AVAILABLE);
    ASSERT_TRUE(mod->GetParam().callback);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("[valid]"), std::string::npos);

    mod->GetParam().callback();
    EXPECT_TRUE(called);
}

/**
 * @tc.name: BufferAvailableCallbackTest002
 * @tc.desc: Test DumpParam with null callback
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, BufferAvailableCallbackTest002, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    BufferAvailableCallbackCmdParam param{nullptr};
    auto mod = std::make_shared<BufferAvailableCallbackCmdModifier>(node, param);
    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("null"), std::string::npos);
}

/**
 * @tc.name: BufferAvailableCallbackTest003
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, BufferAvailableCallbackTest003, TestSize.Level1)
{
    BufferAvailableCallbackCmdParam param{[]() {}};
    auto mod = std::make_shared<BufferAvailableCallbackCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: BufferAvailableCallbackTest004
 * @tc.desc: Test UpdateToRenderWithResult with null node returns false
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, BufferAvailableCallbackTest004, TestSize.Level1)
{
    BufferAvailableCallbackCmdParam param{nullptr};
    auto mod = std::make_shared<BufferAvailableCallbackCmdModifier>(MakeExpiredNode(), param);
    auto result = mod->UpdateToRenderWithResult();
    bool val = std::get<bool>(result);
    EXPECT_FALSE(val);
}

/**
 * @tc.name: BufferAvailableCallbackTest005
 * @tc.desc: Test SetParam always assigns
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, BufferAvailableCallbackTest005, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    bool flag = false;
    BufferAvailableCallbackCmdParam param{[&flag]() { flag = true; }};
    auto mod = std::make_shared<BufferAvailableCallbackCmdModifier>(node, param);

    BufferAvailableCallbackCmdParam param2{nullptr};
    bool ret = mod->SetParam(param2);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(mod->GetParam().callback);
}

/**
 * @tc.name: SurfaceDefaultSizeTest001
 * @tc.desc: Test all methods
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SurfaceDefaultSizeTest001, TestSize.Level1)
{
    auto node = RSSurfaceNode::Create();
    SurfaceDefaultSizeCmdParam param{100.0f, 200.0f};
    auto mod = std::make_shared<SurfaceDefaultSizeCmdModifier>(node, param);
    EXPECT_EQ(mod->GetType(), RSCmdModifierType::UPDATE_SURFACE_DEFAULT_SIZE);
    EXPECT_FLOAT_EQ(mod->GetParam().width_, 100.0f);
    EXPECT_FLOAT_EQ(mod->GetParam().height_, 200.0f);

    SurfaceDefaultSizeCmdParam param2{300.0f, 400.0f};
    mod->SetParam(param2);
    EXPECT_FLOAT_EQ(mod->GetParam().width_, 300.0f);
    EXPECT_FLOAT_EQ(mod->GetParam().height_, 400.0f);

    std::string out;
    mod->DumpParam(out);
    EXPECT_NE(out.find("width"), std::string::npos);
    EXPECT_NE(out.find("height"), std::string::npos);
}

/**
 * @tc.name: SurfaceDefaultSizeTest002
 * @tc.desc: Test UpdateToRender with null node
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, SurfaceDefaultSizeTest002, TestSize.Level1)
{
    SurfaceDefaultSizeCmdParam param{0.0f, 0.0f};
    auto mod = std::make_shared<SurfaceDefaultSizeCmdModifier>(MakeExpiredNode(), param);
    mod->UpdateToRender();
}

/**
 * @tc.name: RSBufferAvailableCallbackWrapperTest001
 * @tc.desc: Test callback wrapper with valid callback
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, RSBufferAvailableCallbackWrapperTest001, TestSize.Level1)
{
    bool called = false;
    auto wrapper = new RSBufferAvailableCallbackWrapper([&called]() { called = true; });
    wrapper->OnBufferAvailable();
    EXPECT_TRUE(called);
    ASSERT_TRUE(wrapper->GetCallback());
    wrapper->DecRef();
}

/**
 * @tc.name: RSBufferAvailableCallbackWrapperTest002
 * @tc.desc: Test callback wrapper with null callback
 * @tc.type: FUNC
 */
HWTEST_F(RSSurfaceNodeCommandModifierTest, RSBufferAvailableCallbackWrapperTest002, TestSize.Level1)
{
    auto wrapper = new RSBufferAvailableCallbackWrapper(nullptr);
    wrapper->OnBufferAvailable();
    ASSERT_FALSE(wrapper->GetCallback());
    wrapper->DecRef();
}

} // namespace Rosen
} // namespace OHOS
