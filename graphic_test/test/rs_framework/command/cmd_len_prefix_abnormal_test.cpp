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
 
#include <parameters.h>
 
#include "rs_graphic_test.h"
#include "rs_graphic_test_img.h"
 
#include "command/rs_command.h"
#include "command/rs_node_command.h"
#include "modifier_ng/custom/rs_content_style_modifier.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_node.h"
 
using namespace testing;
using namespace testing::ext;
 
namespace OHOS::Rosen {
namespace {
// Same rationale as rs_transaction_data_prefix_test.cpp: the sender-side prefix switch is read
// once per process (reboot-gated by design), so lock it to "on" during static initialization,
// before the first transaction of this demo process. Receiver behaviour is driven by the
// version header on the wire, not by the local switch, so only this process is affected.
[[maybe_unused]] static const bool g_prefixSwitchOn =
    (system::SetParameter("persist.sys.graphic.commandLenPrefix.enabled", "1"), true);
 
constexpr uint16_t BOGUS_COMMAND_TYPE = 0xFFFF; // not registered in RSCommandFactory
constexpr uint16_t BOGUS_COMMAND_SUBTYPE = 0xFFFF;
constexpr int OVERSIZED_OP_COUNT = 60000; // ~2.4MB body, exceeds the 1800KB parcel split threshold
constexpr int REPEATED_UPDATE_COUNT = 20;
 
// Abnormal command A: marshalling always fails. With the length-prefix path on, the sender
// drops this single record (RewindWrite to recordPos) and keeps the rest of the transaction;
// without it the whole RSTransactionData::Marshalling would fail and nothing would be sent.
class MarshalFailPrefixCommand : public RSCommand {
public:
    explicit MarshalFailPrefixCommand(NodeId nodeId) : nodeId_(nodeId) {}
    ~MarshalFailPrefixCommand() override = default;
    bool Marshalling(Parcel&) const override
    {
        return false;
    }
    void Process(RSContext&) override {}
    bool UseLengthPrefix() const override
    {
        return true;
    }
    NodeId GetNodeId() const override
    {
        return nodeId_;
    }
 
private:
    NodeId nodeId_;
};
 
// Abnormal command B: a well-formed wire body whose type/subType pair is not registered in
// RSCommandFactory. The receiver cannot resolve an unmarshal function for it and must skip
// the record via its commandLen prefix instead of aborting the whole parcel.
class UnregisteredPrefixCommand : public RSCommand {
public:
    explicit UnregisteredPrefixCommand(NodeId nodeId) : nodeId_(nodeId) {}
    ~UnregisteredPrefixCommand() override = default;
    bool Marshalling(Parcel& parcel) const override
    {
        // mirrors RSCommandTemplate::Marshalling: type + subType + payload
        return parcel.WriteUint16(BOGUS_COMMAND_TYPE) && parcel.WriteUint16(BOGUS_COMMAND_SUBTYPE) &&
               parcel.WriteUint64(payload_);
    }
    void Process(RSContext&) override {}
    bool UseLengthPrefix() const override
    {
        return true;
    }
    NodeId GetNodeId() const override
    {
        return nodeId_;
    }
 
private:
    NodeId nodeId_;
    uint64_t payload_ = 0x1234567887654321;
};

// Abnormal command C: marshalling always fails, WITHOUT the length-prefix path. The sender
// cannot rewind to a record boundary, so the whole RSTransactionData::Marshalling fails and
// nothing is sent — used to contrast with MarshalFailPrefixCommand.
class MarshalFailNonPrefixCommand : public RSCommand {
public:
    explicit MarshalFailNonPrefixCommand(NodeId nodeId) : nodeId_(nodeId) {}
    ~MarshalFailNonPrefixCommand() override = default;
    bool Marshalling(Parcel&) const override
    {
        return false;
    }
    void Process(RSContext&) override {}
    bool UseLengthPrefix() const override
    {
        return false;
    }
    NodeId GetNodeId() const override
    {
        return nodeId_;
    }

private:
    NodeId nodeId_;
};


 
// Content modifier whose recording is delivered as RSUpdatePropertyDrawCmdListNG.
class NativeRectModifier : public ModifierNG::RSContentStyleModifier {
public:
    ~NativeRectModifier() override = default;
    void Draw(ModifierNG::RSDrawingContext& context) const override
    {
        if (!context.canvas) {
            return;
        }
        Drawing::Brush brush;
        brush.SetColor(Drawing::Color::COLOR_BLUE);
        context.canvas->AttachBrush(brush);
        context.canvas->DrawRect(Drawing::Rect(0, 0, context.width, context.height));
        context.canvas->DetachBrush();
    }
};
 
void FillRect(std::shared_ptr<Drawing::Canvas> canvas, const Drawing::Rect& rect, Drawing::Color color)
{
    Drawing::Brush brush;
    brush.SetColor(color);
    canvas->AttachBrush(brush);
    canvas->DrawRect(rect);
    canvas->DetachBrush();
}
} // namespace
 
class CmdLenPrefixAbnormalTest : public RSGraphicTest {
public:
    // called before each tests
    void BeforeEach() override
    {
        SetScreenSize(SCREEN_WIDTH, SCREEN_HEIGHT);
    }
 
    void SetNode(std::shared_ptr<RSNode>& node, const Vector4f& bounds)
    {
        node->SetBounds(bounds);
        int transXY = 20;
        int transZ = 0;
        node->SetTranslate(transXY, transXY, transZ);
        Vector4<BorderStyle> style = Vector4<BorderStyle>(BorderStyle::SOLID);
        node->SetBorderStyle(style);
        Vector4f borderWidth = { 5, 5, 5, 5 };
        node->SetBorderWidth(borderWidth);
        node->SetBorderColor(Vector4<Color>(Color(0, 255, 0)));
    }
 
    // convenience: create a canvas node, lay it out and attach it to the root
    std::shared_ptr<RSCanvasNode> CreateLayoutNode(const Vector4f& bounds)
    {
        auto rsUiContext = RSGraphicTestDirector::Instance().GetRSUIContext();
        auto canvasNode = RSCanvasNode::Create(false, false, rsUiContext);
        auto node = std::static_pointer_cast<RSNode>(canvasNode);
        SetNode(node, bounds);
        GetRootNode()->AddChild(canvasNode);
        RegisterNode(canvasNode);
        return canvasNode;
    }
 
private:
    static constexpr int SCREEN_WIDTH = 1200;
    static constexpr int SCREEN_HEIGHT = 2000;
};
 
/*
 * @tc.name: LenPrefix_MarshalFailDropped_Test
 * @tc.desc: A prefixed command whose marshalling fails is dropped by the sender; the other
 *           commands of the same transaction (RSCanvasNodeUpdateRecording) still reach the
 *           service and render. Expected screenshot: cyan rect on the top node, bottom node
 *           shows border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_MarshalFailDropped_Test)
{
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 450 });
    testNode1->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE, [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 450), Drawing::Color::COLOR_CYAN);
    });
 
    // the failing record must be dropped alone; without the drop the whole transaction would
    // be lost and testNode1 would not render either
    auto testNode2 = CreateLayoutNode({ 0, 550, 1000, 450 });
    std::unique_ptr<RSCommand> failCmd = std::make_unique<MarshalFailPrefixCommand>(testNode2->GetId());
    testNode2->AddCommand(failCmd, testNode2->IsRenderServiceNode());
 
    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}

/*
 * @tc.name: LenPrefix_UnregisteredTypeSkipped_Test
 * @tc.desc: A prefixed command with an unregistered type/subType pair is skipped by the
 *           receiver via its commandLen prefix; the parcel is not aborted and the remaining
 *           commands (RSCanvasNodeUpdateRecording) still apply. Expected screenshot: yellow
 *           rect on the top node, bottom node shows border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_UnregisteredTypeSkipped_Test)
{
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 450 });
    testNode1->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE, [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 450), Drawing::Color::COLOR_YELLOW);
    });
 
    auto testNode2 = CreateLayoutNode({ 0, 550, 1000, 450 });
    std::unique_ptr<RSCommand> bogusCmd = std::make_unique<UnregisteredPrefixCommand>(testNode2->GetId());
    testNode2->AddCommand(bogusCmd, testNode2->IsRenderServiceNode());
 
    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}

/*
 * @tc.name: LenPrefix_UnregisteredTypeSkipped_Test2
 * @tc.desc: A prefixed command whose marshalling fails is dropped by the sender, and a
 *           prefixed command with an unregistered type/subType pair is skipped by the
 *           receiver; the remaining command (RSCanvasNodeUpdateRecording) still applies.
 *           Expected screenshot: top node shows border only, red rect on the middle node,
 *           bottom node shows border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_UnregisteredTypeSkipped_Test2)
{
    // top: failing record dropped alone by sender
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 300 });
    std::unique_ptr<RSCommand> failCmd = std::make_unique<MarshalFailPrefixCommand>(testNode1->GetId());
    testNode1->AddCommand(failCmd, testNode1->IsRenderServiceNode());

    // middle: normal red rect renders
    auto testNode2 = CreateLayoutNode({ 0, 350, 1000, 300 });
    testNode2->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE, [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 300), Drawing::Color::COLOR_RED);
    });

    // bottom: unregistered type skipped by receiver
    auto testNode3 = CreateLayoutNode({ 0, 700, 1000, 300 });
    std::unique_ptr<RSCommand> bogusCmd = std::make_unique<UnregisteredPrefixCommand>(testNode3->GetId());
    testNode3->AddCommand(bogusCmd, testNode3->IsRenderServiceNode());

    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}

/*
 * @tc.name: LenPrefix_EmptyRecordingDropped_Test
 * @tc.desc: DrawOnNode with a draw function that records nothing produces no command at all
 *           (empty recording dropped on the sender); no crash, sibling node unaffected.
 *           Expected screenshot: red rect on the bottom node, top node shows border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_EmptyRecordingDropped_Test)
{
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 450 });
    testNode1->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE,
        [](std::shared_ptr<Drawing::Canvas> canvas) {});
 
    auto testNode2 = CreateLayoutNode({ 0, 550, 1000, 450 });
    testNode2->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE, [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 450), Drawing::Color::COLOR_RED);
    });
 
    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}
 
/*
 * @tc.name: LenPrefix_LegacyNullDrawCmdList_Test
 * @tc.desc: Injects a legacy RSUpdatePropertyDrawCmdList carrying a null DrawCmdList. The
 *           null body marshalls as the -1 sentinel and the service-side helper ignores it;
 *           the transaction survives and the sibling recording renders. Expected
 *           screenshot: cyan rect on the bottom node, top node shows border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_LegacyNullDrawCmdList_Test)
{
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 450 });
    std::unique_ptr<RSCommand> legacyCmd = std::make_unique<RSUpdatePropertyDrawCmdList>(
        testNode1->GetId(), nullptr, 0, PropertyUpdateType::UPDATE_TYPE_FORCE_OVERWRITE);
    testNode1->AddCommand(legacyCmd, testNode1->IsRenderServiceNode());
 
    auto testNode2 = CreateLayoutNode({ 0, 550, 1000, 450 });
    testNode2->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE,
        [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 450), Drawing::Color::COLOR_CYAN);
    });
 
    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}
 
/*
 * @tc.name: LenPrefix_OversizedRecordingSplit_Test
 * @tc.desc: One recording with 60000 identical rect ops (~2.4MB) exceeds the 1800KB parcel
 *           split threshold; each split parcel carries its own version header and the
 *           commandLen of every prefixed record must stay correct across the split. Expected
 *           screenshot: yellow rect on the top node (overdraw collapses to one rect), red
 *           rect on the bottom node.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_OversizedRecordingSplit_Test)
{
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 900 });
    testNode1->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE,
        [](std::shared_ptr<Drawing::Canvas> canvas) {
        Drawing::Brush brush;
        brush.SetColor(Drawing::Color::COLOR_YELLOW);
        canvas->AttachBrush(brush);
        for (int i = 0; i < OVERSIZED_OP_COUNT; i++) {
            canvas->DrawRect(Drawing::Rect(0, 0, 1000, 450));
        }
        canvas->DetachBrush();
    });
 
    auto testNode2 = CreateLayoutNode({ 0, 1000, 1000, 450 });
    testNode2->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE,
        [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 450), Drawing::Color::COLOR_RED);
    });
 
    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}
 
/*
 * @tc.name: LenPrefix_MixedAbnormalOneTransaction_Test
 * @tc.desc: One flushed transaction mixing all three prefixed commands with three kinds of
 *           abnormal records: a healthy RSCanvasNodeUpdateRecording (green rect), a healthy
 *           RSUpdatePropertyDrawCmdListNG via a native content modifier (blue rect), and a
 *           node carrying a legacy null-cmdList record, an unregistered-type record and a
 *           marshal-failing record. Expected screenshot: green and blue rects render, the
 *           third node shows border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_MixedAbnormalOneTransaction_Test)
{
    // healthy RSCanvasNodeUpdateRecording
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 300 });
    testNode1->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE,
        [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 300), Drawing::Color::COLOR_GREEN);
    });
 
    // healthy RSUpdatePropertyDrawCmdListNG through the modifier_ng pipeline
    auto testNode2 = CreateLayoutNode({ 0, 400, 1000, 300 });
    testNode2->AddModifier(std::make_shared<NativeRectModifier>());
 
    // three abnormal records in the same transaction
    auto testNode3 = CreateLayoutNode({ 0, 800, 1000, 300 });
    std::unique_ptr<RSCommand> legacyCmd = std::make_unique<RSUpdatePropertyDrawCmdList>(
        testNode3->GetId(), nullptr, 0, PropertyUpdateType::UPDATE_TYPE_FORCE_OVERWRITE);
    testNode3->AddCommand(legacyCmd, testNode3->IsRenderServiceNode());
    std::unique_ptr<RSCommand> bogusCmd = std::make_unique<UnregisteredPrefixCommand>(testNode3->GetId());
    testNode3->AddCommand(bogusCmd, testNode3->IsRenderServiceNode());
    std::unique_ptr<RSCommand> failCmd = std::make_unique<MarshalFailPrefixCommand>(testNode3->GetId());
    testNode3->AddCommand(failCmd, testNode3->IsRenderServiceNode());
 
    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}
 
/*
 * @tc.name: LenPrefix_RepeatedRecordingUpdate_Test
 * @tc.desc: Repeated DrawOnNode updates append many prefixed records; a wrong commandLen
 *           backfill would corrupt the stream and break the later records. Expected
 *           screenshot: the final update wins, one cyan rect.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_RepeatedRecordingUpdate_Test)
{
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 900 });
    for (int i = 0; i < REPEATED_UPDATE_COUNT; i++) {
        Drawing::Color color = (i % 2 == 0) ? Drawing::Color::COLOR_RED : Drawing::Color::COLOR_YELLOW;
        testNode1->DrawOnNode(
            ModifierNG::RSModifierType::CONTENT_STYLE, [color](std::shared_ptr<Drawing::Canvas> canvas) {
                FillRect(canvas, Drawing::Rect(0, 0, 1000, 900), color);
            });
    }
    testNode1->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE,
        [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 900), Drawing::Color::COLOR_CYAN);
    });
 
    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}

/*
 * @tc.name: MarshalFail_No_PrefixCommand_All_Dropped_Test
 * @tc.desc: A prefixed command whose marshalling fails is dropped by the sender, a normal
 *           command still renders, and a non-prefixed command whose marshalling fails aborts
 *           the remaining transaction. Expected screenshot: top node shows border only,
 *           cyan rect on the middle node, bottom node shows border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, MarshalFail_No_PrefixCommand_All_Dropped_Test)
{
    // top: prefix marshal fail, dropped alone by sender
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 300 });
    std::unique_ptr<RSCommand> failPrefixCmd = std::make_unique<MarshalFailPrefixCommand>(testNode1->GetId());
    testNode1->AddCommand(failPrefixCmd, testNode1->IsRenderServiceNode());

    // middle: normal cyan rect renders
    auto testNode2 = CreateLayoutNode({ 0, 350, 1000, 300 });
    testNode2->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE, [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 300), Drawing::Color::COLOR_CYAN);
    });

    // bottom: non-prefix marshal fail, aborts the whole transaction at sender
    auto testNode3 = CreateLayoutNode({ 0, 700, 1000, 300 });
    std::unique_ptr<RSCommand> failNonPrefixCmd = std::make_unique<MarshalFailNonPrefixCommand>(testNode3->GetId());
    testNode3->AddCommand(failNonPrefixCmd, testNode3->IsRenderServiceNode());

    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}

/*
 * @tc.name: LenPrefix_MarshalFailNonPrefixCommandType_Test
 * @tc.desc: A non-prefixed command whose marshalling fails aborts the whole transaction at
 *           the sender; no command reaches the service. Expected screenshot: all three nodes
 *           show border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_MarshalFailNonPrefixCommandType_Test)
{
    // top: non-prefix failing record (no len guard, may abort the parcel)
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 300 });
    std::unique_ptr<RSCommand> failCmd = std::make_unique<MarshalFailNonPrefixCommand>(testNode1->GetId());
    testNode1->AddCommand(failCmd, testNode1->IsRenderServiceNode());

    // middle: normal red rect renders
    auto testNode2 = CreateLayoutNode({ 0, 350, 1000, 300 });
    testNode2->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE, [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 300), Drawing::Color::COLOR_RED);
    });

    // bottom: unregistered type skipped by receiver
    auto testNode3 = CreateLayoutNode({ 0, 700, 1000, 300 });
    std::unique_ptr<RSCommand> bogusCmd = std::make_unique<UnregisteredPrefixCommand>(testNode3->GetId());
    testNode3->AddCommand(bogusCmd, testNode3->IsRenderServiceNode());

    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}

/*
 * @tc.name: LenPrefix_AllPrefixFailedTypeSkipped_Test
 * @tc.desc: All prefixed commands in the transaction fail to marshal and are dropped by the
 *           sender; no command reaches the service. Expected screenshot: all three nodes
 *           show border only.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_AllPrefixFailedTypeSkipped_Test)
{
    // top: failing record dropped alone by sender
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 300 });
    std::unique_ptr<RSCommand> failCmd1 = std::make_unique<MarshalFailPrefixCommand>(testNode1->GetId());
    testNode1->AddCommand(failCmd1, testNode1->IsRenderServiceNode());

    // middle: failing record dropped alone by sender
    auto testNode2 = CreateLayoutNode({ 0, 350, 1000, 300 });
    std::unique_ptr<RSCommand> failCmd2 = std::make_unique<MarshalFailPrefixCommand>(testNode2->GetId());
    testNode2->AddCommand(failCmd2, testNode2->IsRenderServiceNode());

    // bottom: failing record dropped alone by sender
    auto testNode3 = CreateLayoutNode({ 0, 700, 1000, 300 });
    std::unique_ptr<RSCommand> failCmd3 = std::make_unique<MarshalFailPrefixCommand>(testNode3->GetId());
    testNode3->AddCommand(failCmd3, testNode3->IsRenderServiceNode());

    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}


/*
 * @tc.name: LenPrefix_NormalPrefixCommand_Test
 * @tc.desc: Normal prefixed commands in the same transaction both reach the service and
 *           render. Expected screenshot: black rect on the top node, red rect on the bottom
 *           node.
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
GRAPHIC_TEST(CmdLenPrefixAbnormalTest, CONTENT_DISPLAY_TEST, LenPrefix_NormalPrefixCommand_Test)
{
    // top: normal black rect renders
    auto testNode1 = CreateLayoutNode({ 0, 0, 1000, 450 });
    testNode1->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE, [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 450), Drawing::Color::COLOR_BLACK);
    });

    // bottom: normal red rect renders
    auto testNode2 = CreateLayoutNode({ 0, 550, 1000, 450 });
    testNode2->DrawOnNode(ModifierNG::RSModifierType::CONTENT_STYLE, [](std::shared_ptr<Drawing::Canvas> canvas) {
        FillRect(canvas, Drawing::Rect(0, 0, 1000, 450), Drawing::Color::COLOR_RED);
    });

    RSGraphicTestDirector::Instance().rsUiDirector_->SendMessages();
}


} // namespace OHOS::Rosen