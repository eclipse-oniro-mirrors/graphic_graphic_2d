/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "transaction/rs_transaction_data.h"
#include "command/rs_command.h"
#include "command/rs_command_factory.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

class RSTransactionDataTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSTransactionDataTest::SetUpTestCase() {}
void RSTransactionDataTest::TearDownTestCase() {}
void RSTransactionDataTest::SetUp() {}
void RSTransactionDataTest::TearDown() {}

/**
 * @tc.name: ProcessTest
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSTransactionDataTest, ProcessTest, TestSize.Level1)
{
    RSContext context;
    RSTransactionData rsTransactionData;
    rsTransactionData.Process(context);
    ASSERT_TRUE(rsTransactionData.IsEmpty());

}

/**
 * @tc.name: ClearTest
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSTransactionDataTest, ClearTest, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    rsTransactionData.Clear();
    ASSERT_TRUE(rsTransactionData.IsEmpty());
}

/**
 * @tc.name: Unmarshalling
 * @tc.desc: Test Unmarshalling
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, Unmarshalling, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    ASSERT_EQ(rsTransactionData.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: UnmarshallingCommand001
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand001, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    rsTransactionData.Marshalling(parcel);
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), true);
}

/**
 * @tc.name: UnmarshallingCommand002
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand002, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand003
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand003, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(57); // for test commandSize > readableSize
    rsTransactionData.Marshalling(parcel);
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand004
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand004, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand005
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand005, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    parcel.WriteBool(false); // for test isUniRender
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand006
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand006, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    parcel.WriteBool(false); // for test isUniRender
    parcel.WriteUint64(1); // for test nodeId
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand007
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand007, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    parcel.WriteBool(false); // for test isUniRender
    parcel.WriteUint64(1); // for test nodeId
    parcel.WriteUint8(1); // for test followType
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand008
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand008, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    parcel.WriteBool(false); // for test isUniRender
    parcel.WriteUint64(1); // for test nodeId
    parcel.WriteUint8(1); // for test followType
    parcel.WriteUint8(1); // for test hasCommand
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand009
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand009, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    parcel.WriteBool(false); // for test isUniRender
    parcel.WriteUint64(1); // for test nodeId
    parcel.WriteUint8(1); // for test followType
    parcel.WriteUint8(1); // for test hasCommand
    parcel.WriteUint16(0); // for test commandType
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand010
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand010, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    parcel.WriteBool(false); // for test isUniRender
    parcel.WriteUint64(1); // for test nodeId
    parcel.WriteUint8(1); // for test followType
    parcel.WriteUint8(1); // for test hasCommand
    parcel.WriteUint16(100); // for test commandType
    parcel.WriteUint16(100); // for test commandSubType
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand011
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand011, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    parcel.WriteBool(false); // for test isUniRender
    parcel.WriteUint64(1); // for test nodeId
    parcel.WriteUint8(1); // for test followType
    parcel.WriteUint8(1); // for test hasCommand
    parcel.WriteUint16(0); // for test commandType
    parcel.WriteUint16(0); // for test commandSubType
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), false);
}

/**
 * @tc.name: UnmarshallingCommand012
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, UnmarshallingCommand012, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(rsTransactionData.payload_.size())); // for test commandSize
    parcel.WriteBool(false); // for test isUniRender
    parcel.WriteUint64(1); // for test nodeId
    parcel.WriteUint8(1); // for test followType
    parcel.WriteUint8(1); // for test hasCommand
    parcel.WriteUint16(0); // for test commandType
    parcel.WriteUint16(0); // for test commandSubType
    parcel.WriteBool(true); // for test needSync_
    parcel.WriteBool(true); // for test needCloseSync_
    parcel.WriteInt32(100); // for test syncTransactionCount_
    parcel.WriteUint64(100); // for test timestamp_
    parcel.WriteInt32(1); // for test pid
    parcel.WriteUint64(1); // for test index_
    parcel.WriteUint64(1); // for test syncId_
    parcel.WriteInt32(1); // for test hostPid_
    ASSERT_EQ(rsTransactionData.UnmarshallingCommand(parcel), true);
}

/**
 * @tc.name: Marshalling
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, Marshalling, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    ASSERT_EQ(rsTransactionData.Marshalling(parcel), true);
}

/**
 * @tc.name: AlarmRsNodeLog
 * @tc.desc: Test UnmarshallingCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, AlarmRsNodeLog, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    rsTransactionData.AlarmRsNodeLog();
    EXPECT_NE(rsTransactionData.pid_, -1);
}

/**
 * @tc.name: AddCommand
 * @tc.desc: Test AddCommand
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, AddCommand, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    std::unique_ptr<RSCommand> command;
    rsTransactionData.AddCommand(command, 1, FollowType::FOLLOW_TO_PARENT);
    EXPECT_NE(rsTransactionData.pid_, -1);
}

/**
 * @tc.name: ProcessBySingleFrameComposer
 * @tc.desc: Test ProcessBySingleFrameComposer
 * @tc.type:FUNC
 * @tc.require: issueI9QIQO
 */
HWTEST_F(RSTransactionDataTest, ProcessBySingleFrameComposer, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    Parcel parcel;
    std::unique_ptr<RSCommand> command;
    rsTransactionData.AddCommand(command, 1, FollowType::FOLLOW_TO_PARENT);
    RSContext context;
    rsTransactionData.ProcessBySingleFrameComposer(context);
    EXPECT_NE(rsTransactionData.pid_, -1);
}

/**
 * @tc.name: IsCallingPidValid
 * @tc.desc: Test IsCallingPidValid
 * @tc.type: FUNC
 * @tc.require: issueIAI1VN
 */
HWTEST_F(RSTransactionDataTest, IsCallingPidValid, TestSize.Level1)
{
    RSTransactionData rsTransactionData;
    RSRenderNodeMap rsRenderNodeMap;
    pid_t callingPid = -1;
    pid_t conflictCommandPid = 0;
    std::string commandMapDesc = "";

    bool isCallingPidValid =
        rsTransactionData.IsCallingPidValid(callingPid, rsRenderNodeMap, conflictCommandPid, commandMapDesc);
    EXPECT_TRUE(isCallingPidValid);
}
} // namespace Rosen
} // namespace OHOS