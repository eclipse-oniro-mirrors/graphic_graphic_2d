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

#include <gtest/gtest.h>
#include <parameters.h>

#include "command/rs_base_node_command.h"
#include "command/rs_canvas_node_command.h"
#include "command/rs_command.h"
#include "command/rs_command_factory.h"
#include "command/rs_node_command.h"
#include "recording/draw_cmd_list.h"
#include "recording/recording_canvas.h"
#include "transaction/rs_transaction_data.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

namespace {
// The commandLen prefix switch is read once per process (reboot-gated by design), so it cannot
// be toggled at test runtime. This binary locks the switch to "on" during static initialization
// (before main, hence before the first lazy read) and every test below runs with the prefix path
// enabled. The default-off behaviour is covered by rs_transaction_data_test.cpp.
[[maybe_unused]] static const bool g_prefixSwitchOn =
    (system::SetParameter("persist.sys.graphic.commandLenPrefix.enabled", "1"), true);

// test-only command that always fails to marshal and opts into the prefix path, to exercise
// the drop-on-failure behaviour of RSTransactionData::Marshalling
class RSMarshalFailPrefixCommand : public RSCommand {
public:
    RSMarshalFailPrefixCommand() = default;
    ~RSMarshalFailPrefixCommand() = default;
    bool Marshalling(Parcel&) const override
    {
        return false;
    }
    void Process(RSContext&) override {}
    bool UseLengthPrefix() const override
    {
        return true;
    }
};

// writes the fixed trailer fields that follow the command list
void WriteTrailer(Parcel& parcel)
{
    parcel.WriteBool(false); // needSync_
    parcel.WriteBool(false); // needCloseSync_
    parcel.WriteInt32(0);    // syncTransactionCount_
    parcel.WriteUint64(0);   // token_
    parcel.WriteUint64(0);   // timestamp_
    parcel.WriteInt32(0);    // pid_
    parcel.WriteUint64(0);   // index_
    parcel.WriteUint64(0);   // syncId_
    parcel.WriteInt32(0);    // parentPid_
    parcel.WriteBool(false); // dvsyncTimeUpdate_
    parcel.WriteUint64(0);   // dvsyncTime_
    parcel.WriteUint8(0);    // scene_
#ifndef ROSEN_CROSS_PLATFORM
    parcel.WriteInt32(-1); // tid_
#endif
}

// writes one prefixed record with an unregistered type/subType pair
void WriteBogusPrefixedCommand(Parcel& parcel, NodeId nodeId)
{
    parcel.WriteUint64(nodeId); // nodeId
    parcel.WriteUint8(1);       // followType
    parcel.WriteUint8(1);       // hasCommand
    parcel.WriteBool(true);     // wire flag: commandLen prefix follows
    parcel.WriteUint32(4);      // commandLen: commandType(2) + commandSubType(2)
    parcel.WriteUint16(0xFFFF); // commandType (unregistered)
    parcel.WriteUint16(0xFFFF); // commandSubType (unregistered)
}

// builds a recording with real content. A default-constructed empty DrawCmdList (size == 0)
// never reaches the wire in production (real recordings are either null or contain ops) and its
// marshalling is not byte-symmetric with the unmarshalling, so the round-trip tests must use a
// real recording like every production sender does.
std::shared_ptr<Drawing::DrawCmdList> MakeRecording()
{
    auto canvas = std::make_shared<Drawing::RecordingCanvas>(10, 10);
    canvas->DrawPoint(Drawing::Point(5, 5));
    return canvas->GetDrawCmdList();
}
} // namespace

class RSTransactionDataPrefixTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: PrefixCommandRoundTrip001
 * @tc.desc: Prefix command (canvas recording) round-trips through flag + commandLen format
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
HWTEST_F(RSTransactionDataPrefixTest, PrefixCommandRoundTrip001, TestSize.Level1)
{
    RSTransactionData src;
    NodeId nodeId = 100;
    auto drawing = MakeRecording();
    std::unique_ptr<RSCommand> cmd =
        std::make_unique<RSCanvasNodeUpdateRecording>(nodeId, drawing, 0);
    src.AddCommand(cmd, nodeId, FollowType::FOLLOW_TO_PARENT);
    Parcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    RSTransactionData dst;
    ASSERT_TRUE(dst.UnmarshallingCommand(parcel));
    EXPECT_EQ(dst.GetCommandCount(), 1u);
    EXPECT_EQ(dst.GetSkippedCommandCount(), 0u);
}

/**
 * @tc.name: NonPrefixCommandKeepsOriginPath001
 * @tc.desc: With the switch on, non-prefix commands keep the origin format and round-trip
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
HWTEST_F(RSTransactionDataPrefixTest, NonPrefixCommandKeepsOriginPath001, TestSize.Level1)
{
    RSTransactionData src;
    NodeId nodeId = 100;
    std::unique_ptr<RSCommand> cmd = std::make_unique<RSBaseNodeDestroy>(nodeId);
    src.AddCommand(cmd, nodeId, FollowType::FOLLOW_TO_PARENT);
    Parcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    RSTransactionData dst;
    ASSERT_TRUE(dst.UnmarshallingCommand(parcel));
    EXPECT_EQ(dst.GetCommandCount(), 1u);
    EXPECT_EQ(dst.GetSkippedCommandCount(), 0u);
}

/**
 * @tc.name: MixedCommandsRoundTrip001
 * @tc.desc: Prefix and non-prefix commands in one transaction round-trip correctly
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
HWTEST_F(RSTransactionDataPrefixTest, MixedCommandsRoundTrip001, TestSize.Level1)
{
    RSTransactionData src;
    NodeId nodeId1 = 100;
    NodeId nodeId2 = 200;
    auto drawing = MakeRecording();
    std::unique_ptr<RSCommand> cmd1 =
        std::make_unique<RSCanvasNodeUpdateRecording>(nodeId1, drawing, 0);
    std::unique_ptr<RSCommand> cmd2 = std::make_unique<RSBaseNodeDestroy>(nodeId2);
    src.AddCommand(cmd1, nodeId1, FollowType::FOLLOW_TO_PARENT);
    src.AddCommand(cmd2, nodeId2, FollowType::FOLLOW_TO_PARENT);
    Parcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    RSTransactionData dst;
    ASSERT_TRUE(dst.UnmarshallingCommand(parcel));
    EXPECT_EQ(dst.GetCommandCount(), 2u);
    EXPECT_EQ(dst.GetSkippedCommandCount(), 0u);
}

/**
 * @tc.name: SkipUnregisteredCommand001
 * @tc.desc: Unregistered prefixed command is skipped; remaining commands are processed
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
HWTEST_F(RSTransactionDataPrefixTest, SkipUnregisteredCommand001, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteInt32(1);    // command count
    parcel.WriteBool(false); // isUniRender
    WriteBogusPrefixedCommand(parcel, 1);
    WriteTrailer(parcel);
    RSTransactionData dst;
    ASSERT_TRUE(dst.UnmarshallingCommand(parcel));
    EXPECT_EQ(dst.GetCommandCount(), 0u);
    EXPECT_EQ(dst.GetSkippedCommandCount(), 1u);
}

/**
 * @tc.name: AllSkippedReturnsNullptr001
 * @tc.desc: Unmarshalling returns nullptr when all commands were skipped
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
HWTEST_F(RSTransactionDataPrefixTest, AllSkippedReturnsNullptr001, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteInt32(1);    // command count
    parcel.WriteBool(false); // isUniRender
    WriteBogusPrefixedCommand(parcel, 1);
    WriteTrailer(parcel);
    EXPECT_EQ(RSTransactionData::Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: SkipIsolation001
 * @tc.desc: A failed command body does not corrupt the next command (RewindRead isolation)
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
HWTEST_F(RSTransactionDataPrefixTest, SkipIsolation001, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteInt32(2);    // command count
    parcel.WriteBool(false); // isUniRender
    WriteBogusPrefixedCommand(parcel, 1);
    WriteBogusPrefixedCommand(parcel, 2);
    WriteTrailer(parcel);
    RSTransactionData dst;
    ASSERT_TRUE(dst.UnmarshallingCommand(parcel));
    EXPECT_EQ(dst.GetCommandCount(), 0u);
    EXPECT_EQ(dst.GetSkippedCommandCount(), 2u);
}

/**
 * @tc.name: CommandLenBounds001
 * @tc.desc: Invalid commandLen values (zero, too small, out of range) abort the whole parcel
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
HWTEST_F(RSTransactionDataPrefixTest, CommandLenBounds001, TestSize.Level1)
{
    for (uint32_t invalidLen : { 0u, 2u, 0xFFFFFFFFu }) {
        Parcel parcel;
        parcel.WriteInt32(1);    // command count
        parcel.WriteBool(false); // isUniRender
        parcel.WriteUint64(1);   // nodeId
        parcel.WriteUint8(1);    // followType
        parcel.WriteUint8(1);    // hasCommand
        parcel.WriteBool(true);  // wire flag: commandLen prefix follows
        parcel.WriteUint32(invalidLen);
        RSTransactionData dst;
        EXPECT_FALSE(dst.UnmarshallingCommand(parcel));
    }
}

/**
 * @tc.name: MarshalFailDrop001
 * @tc.desc: Prefix command that fails to marshal is dropped; the parcel stays consistent
 * @tc.type: FUNC
 * @tc.require: issue#26143
 */
HWTEST_F(RSTransactionDataPrefixTest, MarshalFailDrop001, TestSize.Level1)
{
    RSTransactionData src;
    NodeId nodeId1 = 100;
    NodeId nodeId2 = 200;
    auto drawing = MakeRecording();
    std::unique_ptr<RSCommand> failCmd = std::make_unique<RSMarshalFailPrefixCommand>();
    std::unique_ptr<RSCommand> goodCmd =
        std::make_unique<RSCanvasNodeUpdateRecording>(nodeId2, drawing, 0);
    src.AddCommand(failCmd, nodeId1, FollowType::FOLLOW_TO_PARENT);
    src.AddCommand(goodCmd, nodeId2, FollowType::FOLLOW_TO_PARENT);
    Parcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    RSTransactionData dst;
    ASSERT_TRUE(dst.UnmarshallingCommand(parcel));
    EXPECT_EQ(dst.GetCommandCount(), 1u);
    EXPECT_EQ(dst.GetSkippedCommandCount(), 0u);
}

} // namespace Rosen
} // namespace OHOS
