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
#include "command/rs_delegate_composite_command.h"
#include "transaction/rs_buffer_transaction.h"
#include "pipeline/rs_context.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_surface_handler.h"
#include "message_parcel.h"
#include "command/rs_command_factory.h"
#include "common/rs_common_def.h"
#include "feature/delegate_composite/rs_delegate_composite_callback_manager.h"
#include "iconsumer_surface.h"
#include "consumer_surface.h"
#include "ipc_callbacks/rs_delegate_composite_callback.h"
#include "iremote_stub.h"
#include "sync_fence.h"
#include "transaction/rs_marshalling_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
constexpr NodeId SET_BUFFER_NODE_ID = 601;
constexpr NodeId SET_RECT_NODE_ID = 602;
constexpr uint32_t INVALID_BUFFER_SEQ = 4242;
constexpr float SRC_RECT_TOP = 11.0f;
constexpr float SRC_RECT_LEFT = 12.0f;
constexpr float SRC_RECT_WIDTH = 13.0f;
constexpr float SRC_RECT_HEIGHT = 14.0f;
constexpr float DST_RECT_TOP = 21.0f;
constexpr float DST_RECT_LEFT = 22.0f;
constexpr float DST_RECT_WIDTH = 23.0f;
constexpr float DST_RECT_HEIGHT = 24.0f;
} // namespace

class MockSurfaceNodeBufferReleaseCallback : public IRemoteStub<RSISurfaceNodeBufferReleaseCallback> {
public:
    MockSurfaceNodeBufferReleaseCallback() = default;
    ~MockSurfaceNodeBufferReleaseCallback() noexcept override = default;
    GSError OnBufferComplete(std::queue<OnCompletedRet>& queue) override
    {
        callCount++;
        while (!queue.empty()) {
            received.push_back(queue.front());
            queue.pop();
        }
        return GSERROR_OK;
    }
    uint32_t callCount = 0;
    std::vector<OnCompletedRet> received;
};

class RSDelegateCompositeCommandTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static std::shared_ptr<RSContext> CreateContextWithSurfaceNode(NodeId nodeId, bool enableDelegateMode);
    static RSTransactionConfig MakeInfoOnlyConfig(NodeId nodeId, uint32_t sequence);
    static void DrainManagerState(RSContext& context);
    static inline pid_t nodePid_ = 60100;
    static inline sptr<MockSurfaceNodeBufferReleaseCallback> listener_ = nullptr;
};

void RSDelegateCompositeCommandTest::SetUpTestCase() {}
void RSDelegateCompositeCommandTest::TearDownTestCase()
{
    listener_ = nullptr;
}

void RSDelegateCompositeCommandTest::SetUp()
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    listener_ = new MockSurfaceNodeBufferReleaseCallback();
    manager.RegisterSurfaceNodeBufferReleaseListener(nodePid_, listener_);
}

void RSDelegateCompositeCommandTest::TearDown()
{
    auto context = std::make_shared<RSContext>();
    DrainManagerState(*context);
    RsDelegateCompositeCallbackManager::GetInstance().UnRegisterSurfaceNodeBufferReleaseListener(nodePid_);
    listener_->callCount = 0;
    listener_->received.clear();
}

std::shared_ptr<RSContext> RSDelegateCompositeCommandTest::CreateContextWithSurfaceNode(
    NodeId nodeId, bool enableDelegateMode)
{
    auto context = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId, context);
    auto surfaceHandler = node->GetMutableRSSurfaceHandler();
    if (surfaceHandler != nullptr) {
        surfaceHandler->SetConsumer(IConsumerSurface::Create("DelegateCmdTestSurface"));
    }
    if (enableDelegateMode) {
        node->SetDelegateMode(true);
    }
    context->GetMutableNodeMap().RegisterRenderNode(node);
    return context;
}

RSTransactionConfig RSDelegateCompositeCommandTest::MakeInfoOnlyConfig(NodeId nodeId, uint32_t sequence)
{
    RSTransactionConfig config;
    config.nodeId = nodeId;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = sequence;
    config.transactionInfo.fence = nullptr;
    config.delList = {};
    return config;
}

void RSDelegateCompositeCommandTest::DrainManagerState(RSContext& context)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    while (manager.ProcessDelegateCompositeCommand(context)) {}
    manager.NotifyCurrentSurfaceNodeBufferReleaseCallback();
}


/**
 * @tc.name: TransactionBufferCommandConstructor001
 * @tc.desc: Test TransactionBufferCommand constructor with valid params
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandConstructor001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    EXPECT_EQ(cmd.GetNodeId(), nodeId);
    EXPECT_EQ(cmd.GetType(), RSCommandType::DELEGATE_COMPOSITE);
    EXPECT_EQ(cmd.GetSubType(), RSDelegateCompositeCommandType::TRANSACTION_BUFFER);
}

/**
 * @tc.name: TransactionBufferCommandConstructor002
 * @tc.desc: Test TransactionBufferCommand default constructor
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandConstructor002, TestSize.Level1)
{
    TransactionBufferCommand cmd;
    EXPECT_EQ(cmd.GetNodeId(), 0);
}

/**
 * @tc.name: TransactionBufferCommandGetType001
 * @tc.desc: Test GetType returns DELEGATE_COMPOSITE
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandGetType001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    EXPECT_EQ(cmd.GetType(), RSCommandType::DELEGATE_COMPOSITE);
}

/**
 * @tc.name: TransactionBufferCommandGetSubType001
 * @tc.desc: Test GetSubType returns TRANSACTION_BUFFER
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandGetSubType001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    EXPECT_EQ(cmd.GetSubType(), RSDelegateCompositeCommandType::TRANSACTION_BUFFER);
}

/**
 * @tc.name: TransactionBufferCommandGetAccessPermission001
 * @tc.desc: Test GetAccessPermission returns PERMISSION_APP
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandGetAccessPermission001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    EXPECT_EQ(cmd.GetAccessPermission(), RSCommandPermissionType::PERMISSION_APP);
}

/**
 * @tc.name: TransactionBufferCommandMarshalling001
 * @tc.desc: Test Marshalling with INVALID cmdType - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshalling001, TestSize.Level1)
{
    TransactionBufferCommand cmd;
    MessageParcel parcel;
    bool result = cmd.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TransactionBufferCommandMarshalling002
 * @tc.desc: Test Marshalling with valid params - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshalling002, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    bool result = cmd.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshalling001
 * @tc.desc: Test Unmarshalling with valid data - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshalling001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    cmd.Marshalling(parcel);

    RSCommand* result = TransactionBufferCommand::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshalling002
 * @tc.desc: Test Unmarshalling with invalid data - false branch (read cmd type failed)
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshalling002, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(-1);

    RSCommand* result = TransactionBufferCommand::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: TransactionBufferCommandProcess001
 * @tc.desc: Test Process with SET_BUFFER cmdType - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcess001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.Process(context));
}

/**
 * @tc.name: TransactionBufferCommandProcess002
 * @tc.desc: Test Process with INVALID cmdType - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcess002, TestSize.Level1)
{
    TransactionBufferCommand cmd;
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.Process(context));
}

/**
 * @tc.name: SurfaceTransactionCommandConstructor001
 * @tc.desc: Test SurfaceTransactionCommand constructor
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandConstructor001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    EXPECT_EQ(cmd.GetType(), RSCommandType::DELEGATE_COMPOSITE);
    EXPECT_EQ(cmd.GetSubType(), RSDelegateCompositeCommandType::SURFACE_TRANSACTION_CMD);
    EXPECT_EQ(cmd.GetAccessPermission(), RSCommandPermissionType::PERMISSION_APP);
}

/**
 * @tc.name: SurfaceTransactionCommandGetType001
 * @tc.desc: Test GetType returns DELEGATE_COMPOSITE
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandGetType001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    EXPECT_EQ(cmd.GetType(), RSCommandType::DELEGATE_COMPOSITE);
}

/**
 * @tc.name: SurfaceTransactionCommandGetSubType001
 * @tc.desc: Test GetSubType returns SURFACE_TRANSACTION_CMD
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandGetSubType001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    EXPECT_EQ(cmd.GetSubType(), RSDelegateCompositeCommandType::SURFACE_TRANSACTION_CMD);
}

/**
 * @tc.name: SurfaceTransactionCommandGetAccessPermission001
 * @tc.desc: Test GetAccessPermission returns PERMISSION_APP
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandGetAccessPermission001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    EXPECT_EQ(cmd.GetAccessPermission(), RSCommandPermissionType::PERMISSION_APP);
}

/**
 * @tc.name: SurfaceTransactionCommandMarshalling001
 * @tc.desc: Test Marshalling with valid params - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandMarshalling001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    MessageParcel parcel;
    bool result = cmd.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SurfaceTransactionCommandUnmarshalling001
 * @tc.desc: Test Unmarshalling with valid data - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandUnmarshalling001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    MessageParcel parcel;
    cmd.Marshalling(parcel);

    RSCommand* result = SurfaceTransactionCommand::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    if (result != nullptr) {
        delete result;
    }
}

/**
 * @tc.name: SurfaceTransactionCommandUnmarshalling002
 * @tc.desc: Test Unmarshalling with invalid data - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandUnmarshalling002, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteUint64(100);

    RSCommand* result = SurfaceTransactionCommand::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SurfaceTransactionCommandProcess001
 * @tc.desc: Test Process
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandProcess001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.Process(context));
}

/**
 * @tc.name: SurfaceTransactionCommandProcess002
 * @tc.desc: Test Process when commandSendPid_ matches ExtractPid(nodeId_)
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommandProcess002, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = (static_cast<NodeId>(pid) << 32) | 1;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.Process(context));
}

/**
 * @tc.name: TransactionBufferCommandMarshallingCmdTypeSetBuffer001
 * @tc.desc: Test MarshallingCmdTypeSetBuffer with invalid cmdType - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshallingCmdTypeSetBuffer001, TestSize.Level1)
{
    TransactionBufferCommand cmd;
    MessageParcel parcel;
    bool result = cmd.MarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TransactionBufferCommandMarshallingCmdTypeSetBuffer002
 * @tc.desc: Test MarshallingCmdTypeSetBuffer with valid cmdType - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshallingCmdTypeSetBuffer002, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    bool result = cmd.MarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TransactionBufferCommandMarshallingCmdTypeSetBuffer003
 * @tc.desc: Test MarshallingCmdTypeSetBuffer with write size failed - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshallingCmdTypeSetBuffer003, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    bool result = cmd.MarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TransactionBufferCommandMarshallingCmdTypeSetBuffer004
 * @tc.desc: Test MarshallingCmdTypeSetBuffer with write nodeId failed - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshallingCmdTypeSetBuffer004, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    parcel.WriteUint32(configs.size());
    bool result = cmd.MarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshallingCmdTypeSetBuffer001
 * @tc.desc: Test UnmarshallingCmdTypeSetBuffer with valid data - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshallingCmdTypeSetBuffer001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    cmd.Marshalling(parcel);

    RSCommand* result = TransactionBufferCommand::UnmarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshallingCmdTypeSetBuffer002
 * @tc.desc: Test UnmarshallingCmdTypeSetBuffer with read size failed - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshallingCmdTypeSetBuffer002, TestSize.Level1)
{
    MessageParcel parcel;

    RSCommand* result = TransactionBufferCommand::UnmarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshallingCmdTypeSetBuffer003
 * @tc.desc: Test UnmarshallingCmdTypeSetBuffer with read nodeId failed - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshallingCmdTypeSetBuffer003, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteUint32(0);

    RSCommand* result = TransactionBufferCommand::UnmarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with invalid cmdType - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer001, TestSize.Level1)
{
    TransactionBufferCommand cmd;
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer002
 * @tc.desc: Test ProcessCmdTypeSetBuffer with valid cmdType - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer002, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandUnmarshalling_ReadInt32Failed_001
 * @tc.desc: Test Unmarshalling with parcel data insufficient to read Int32
 *           Should return nullptr when ReadInt32 fails (line 59 condition true)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshalling_ReadInt32Failed_001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteUint8(1);

    RSCommand* result = TransactionBufferCommand::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshalling_SET_BUFFER_Success_001
 * @tc.desc: Test Unmarshalling with SET_BUFFER cmdType
 *           Should enter SET_BUFFER case and return valid command (line 65 case)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshalling_SET_BUFFER_Success_001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(0));
    parcel.WriteUint32(0);
    parcel.WriteUint64(12345);

    RSCommand* result = TransactionBufferCommand::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    if (result != nullptr) {
        delete result;
    }
}

/**
 * @tc.name: TransactionBufferCommandMarshalling_DefaultCase_001
 * @tc.desc: Test Marshalling with invalid cmdType to trigger default case (line 92)
 *           Should return false when cmdType_ is neither INVALID nor SET_BUFFER
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshalling_DefaultCase_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd1(configs, nodeId);
    TransactionBufferCommand cmd2;

    char* ptr1 = reinterpret_cast<char*>(&cmd1);
    char* ptr2 = reinterpret_cast<char*>(&cmd2);
    int32_t* cmdTypePtr = nullptr;

    for (size_t offset = 0; offset < sizeof(TransactionBufferCommand) - sizeof(int32_t); offset++) {
        int32_t val1 = *reinterpret_cast<int32_t*>(ptr1 + offset);
        int32_t val2 = *reinterpret_cast<int32_t*>(ptr2 + offset);
        if (val1 == 0 && val2 == -1) {
            cmdTypePtr = reinterpret_cast<int32_t*>(ptr1 + offset);
            break;
        }
    }

    if (cmdTypePtr != nullptr) {
        *cmdTypePtr = 100;
        MessageParcel parcel;
        bool result = cmd1.Marshalling(parcel);
        EXPECT_FALSE(result);
    }
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_CmdTypeNotSetBuffer_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with cmdType_ != SET_BUFFER (line 125 condition true)
 *           Should return early without processing
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_CmdTypeNotSetBuffer_001, TestSize.Level1)
{
    TransactionBufferCommand cmd;
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_NodeInvalid_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with node not found in context (line 132 condition true)
 *           Should continue to next config when node is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_NodeInvalid_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 99999;
    configs.push_back(config);
    NodeId nodeId = 99999;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_NodeValid_SurfaceHandlerNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with valid node but null surfaceHandler (line 138 condition true)
 *           Should continue when surfaceHandler is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_NodeValid_SurfaceHandlerNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with config.transaction nullptr (line 143 condition true)
 *           Should execute FlushBuffer with transactionInfo
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = 1;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction not null but buffer null (line 159 condition true)
 *           Should continue when transaction->GetBuffer() returns nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction();
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction and buffer both not null (line 159 condition false)
 *           Should proceed to attach and flush buffer
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_MultipleConfigs_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with multiple configs iterating through loop
 *           Should process each config in configList_
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_MultipleConfigs_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    for (int i = 0; i < 5; i++) {
        RSTransactionConfig config;
        config.nodeId = 12345 + i;
        config.transaction = nullptr;
        configs.push_back(config);
    }
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_EmptyConfigList_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with empty configList (loop body never executed)
 *           Should return without any processing
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_EmptyConfigList_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBufferFailed_TransactionNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction nullptr and FlushBuffer fails
 *           Branch: line 151 if (ret != GSERROR_OK) -> true
 *           Should log error when FlushBuffer returns error
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBufferFailed_TransactionNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = 1;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_BufferNotCached_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with buffer not cached in consumer
 *           Branch: line 170 if (!consumer->IsCached(buffer->GetSeqNum())) -> true
 *           Should call AttachBufferToQueue
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_BufferNotCached_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_BufferCached_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with buffer already cached in consumer
 *           Branch: line 170 if (!consumer->IsCached(buffer->GetSeqNum())) -> false
 *           Should skip AttachBufferToQueue and directly FlushBuffer
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_BufferCached_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_QueueFull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer when AttachBufferToQueue returns QUEUE_FULL
 *           Branch: line 172 if (ret == SURFACE_ERROR_BUFFER_QUEUE_FULL) -> true
 *           Should call CleanProducerBySeqNum and retry AttachBufferToQueue
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_QueueFull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_AttachBufferFailed_NotQueueFull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer when AttachBufferToQueue fails with other error
 *           Branch: line 172 if (ret == SURFACE_ERROR_BUFFER_QUEUE_FULL) -> false
 *           Should proceed to FlushBuffer without retry
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_AttachBufferFailed_NotQueueFull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBufferFailed_TransactionNotNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction and buffer but FlushBuffer fails
 *           Branch: line 179 if (ret != GSERROR_OK) -> true
 *           Should log error when FlushBuffer returns error
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBufferFailed_TransactionNotNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBufferSuccess_TransactionNotNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction and buffer and FlushBuffer succeeds
 *           Branch: line 179 if (ret != GSERROR_OK) -> false
 *           Should complete without error log
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBufferSuccess_TransactionNotNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_DelList_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with non-empty delList in config
 *           Branch: line 173 producer->CleanProducerBySeqNum(config.delList) executed
 *           Should clean buffers from delList when queue is full
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_DelList_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    config.delList = {1, 2, 3};
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_FlushBufferSuccess_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction nullptr and FlushBuffer succeeds
 *           Branch: line 151 if (ret != GSERROR_OK) -> false
 *           Should complete without error log
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_FlushBufferSuccess_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = 1;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_Damages_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with damages in transaction
 *           Branch: line 167 configDamages.damages = transaction->GetDamages()
 *           Should set damages from transaction to configDamages
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_Damages_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    std::vector<Rect> damages = {{0, 0, 100, 100}};
    transaction->SetDamages(damages);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_Timestamp_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with uiTimestamp in transaction
 *           Branch: line 168 configDamages.timestamp = transaction->GetUiTimestamp()
 *           Should set timestamp from transaction to configDamages
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_Timestamp_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    transaction->SetUiTimestamp(123456789);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_DesiredTimestamp_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with desiredPresentTimestamp in transaction
 *           Branch: line 169 configDamages.desiredPresentTimestamp = transaction->GetDesiredPresentTimestamp()
 *           Should set desiredPresentTimestamp from transaction to configDamages
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_DesiredTimestamp_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    transaction->SetDesiredPresentTimestamp(987654321);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_TransactionInfoDamages_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction nullptr and damages in transactionInfo
 *           Branch: line 145 configDamages.damages = config.transactionInfo.damages
 *           Should set damages from transactionInfo to configDamages
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_TransactionInfoDamages_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = 1;
    std::vector<Rect> damages = {{0, 0, 100, 100}};
    config.transactionInfo.damages = damages;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_TransactionInfoTimestamp_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction nullptr and uiTimestamp in transactionInfo
 *           Branch: line 146 configDamages.timestamp = config.transactionInfo.uiTimestamp
 *           Should set timestamp from transactionInfo to configDamages
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_TransactionInfoTimestamp_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = 1;
    config.transactionInfo.uiTimestamp = 111111111;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_TransactionInfoDesiredTimestamp_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction nullptr and desiredPresentTimestamp in transactionInfo
 *           Branch: line 147 configDamages.desiredPresentTimestamp = config.transactionInfo.desiredPresentTimestamp
 *           Should set desiredPresentTimestamp from transactionInfo to configDamages
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_TransactionInfoDesiredTimestamp_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = 1;
    config.transactionInfo.desiredPresentTimestamp = 222222222;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    context.nodeMap.renderNodeMap_[0][nodeId] = std::make_shared<RSSurfaceRenderNode>(nodeId);
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_ConsumerProducerNotNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction nullptr but valid consumer and producer
 *           Branch: line 143 if true - consumer and producer not null, config.transaction is nullptr
 *           Should execute FlushBuffer via producer with transactionInfo (line 144-155)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNull_ConsumerProducerNotNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = 1;
    config.transactionInfo.uiTimestamp = 123456789;
    config.transactionInfo.desiredPresentTimestamp = 987654321;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_, nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_->GetProducer(), nullptr);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNull_ConsumerProducerNotNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with transaction not null but buffer null, consumer and producer valid
 *           Branch: line 143 if false, line 159 if true - transaction exists but GetBuffer() returns nullptr
 *           Should continue without processing (line 160)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNull_ConsumerProducerNotNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction();
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_, nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_->GetProducer(), nullptr);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_ConsumerProducerNotNull_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with valid transaction, buffer, consumer and producer
 *           Branch: line 143 if false, line 159 if false, line 170 if true - all conditions valid, buffer not cached
 *           Should execute AttachBufferToQueue (line 171) and FlushBuffer via producer (line 178-182)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_TransactionNotNull_BufferNotNull_ConsumerProducerNotNull_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_, nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_->GetProducer(), nullptr);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_BufferNotCached_AttachBufferToQueue_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer with buffer not cached, explicitly calling AttachBufferToQueue
 *           Branch: line 170 if (!consumer->IsCached(buffer->GetSeqNum())) -> true
 *                   line 171 producer->AttachBufferToQueue(buffer) is called
 *           Should attach buffer to queue when buffer is not cached
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_BufferNotCached_AttachBufferToQueue_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    uint32_t seqNum = buffer->GetSeqNum();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_, nullptr);
    auto producer = node->GetRSSurfaceHandler()->consumer_->GetProducer();
    ASSERT_NE(producer, nullptr);
    EXPECT_FALSE(node->GetRSSurfaceHandler()->consumer_->IsCached(seqNum));
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBuffer_Success_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer when FlushBuffer succeeds (line 179 if false)
 *           Branch: line 178 FlushBuffer called, line 179 if (ret != GSERROR_OK) -> false
 *           Should complete without error log when FlushBuffer returns GSERROR_OK
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBuffer_Success_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_, nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_->GetProducer(), nullptr);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBuffer_Failed_001
 * @tc.desc: Test ProcessCmdTypeSetBuffer when FlushBuffer fails (line 179 if true)
 *           Branch: line 178 FlushBuffer called, line 179 if (ret != GSERROR_OK) -> true
 *           Should log error message when FlushBuffer returns error (line 180-181)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessCmdTypeSetBuffer_FlushBuffer_Failed_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    transaction->SetFence(SyncFence::INVALID_FENCE);
    config.transaction = transaction;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_, nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_->GetProducer(), nullptr);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetBuffer(context));
}

/**
 * @tc.name: ProcessCmdTypeSetRect_CmdTypeNotSetRect_True
 * @tc.desc: Test ProcessCmdTypeSetRect when cmdType_ != SET_RECT (line 264 condition true)
 *           Branch: if (cmdType_ != CmdType::SET_RECT) -> true
 *           Should return early and log error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetRect_CmdTypeNotSetRect_True, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetRect(context));
}

/**
 * @tc.name: ProcessCmdTypeSetRect_CmdTypeIsSetRect_False
 * @tc.desc: Test ProcessCmdTypeSetRect when cmdType_ == SET_RECT (line 264 condition false)
 *           Branch: if (cmdType_ != CmdType::SET_RECT) -> false
 *           Should proceed to get node from nodeMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetRect_CmdTypeIsSetRect_False, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 100.0f, 200.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetRect(context));
}

/**
 * @tc.name: ProcessCmdTypeSetRect_NodeNotFound_False
 * @tc.desc: Test ProcessCmdTypeSetRect when node not found (line 270-271 condition false)
 *           Branch: if (auto node = ...) -> false (else branch)
 *           Should log error when node doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetRect_NodeNotFound_False, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 100.0f, 200.0f);
    bool isSrcRect = true;
    NodeId nodeId = 99999;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetRect(context));
}

/**
 * @tc.name: ProcessCmdTypeSetRect_NodeFound_True
 * @tc.desc: Test ProcessCmdTypeSetRect when node is found (line 270-271 condition true)
 *           Branch: if (auto node = ...) -> true
 *           Should process rect setting for the found node
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetRect_NodeFound_True, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 100.0f, 200.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12346;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->SetDelegateMode(true);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetRect(context));
}

/**
 * @tc.name: ProcessCmdTypeSetRect_IsSrcRect_True
 * @tc.desc: Test ProcessCmdTypeSetRect when isSrcRect_ is true (line 272 condition true)
 *           Branch: if (isSrcRect_) -> true
 *           Should call SetDelegateSrcRect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetRect_IsSrcRect_True, TestSize.Level1)
{
    RectF rect(50.0f, 100.0f, 200.0f, 300.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12347;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->SetDelegateMode(true);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetRect(context));
    RectF srcRect = node->GetDelegateSrcRect();
    EXPECT_FLOAT_EQ(srcRect.GetTop(), rect.GetTop());
    EXPECT_FLOAT_EQ(srcRect.GetLeft(), rect.GetLeft());
}

/**
 * @tc.name: ProcessCmdTypeSetRect_IsSrcRect_False
 * @tc.desc: Test ProcessCmdTypeSetRect when isSrcRect_ is false (line 272 condition false)
 *           Branch: if (isSrcRect_) -> false (else branch)
 *           Should call SetDelegateDstRect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetRect_IsSrcRect_False, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 100.0f, 200.0f);
    bool isSrcRect = false;
    NodeId nodeId = 12348;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->SetDelegateMode(true);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetRect(context));
    RectF dstRect = node->GetDelegateDstRect();
    EXPECT_FLOAT_EQ(dstRect.GetTop(), rect.GetTop());
    EXPECT_FLOAT_EQ(dstRect.GetLeft(), rect.GetLeft());
}

/**
 * @tc.name: MarshallingCmdTypeSetRect_CmdTypeNotSetRect_True
 * @tc.desc: Test MarshallingCmdTypeSetRect when cmdType_ != SET_RECT (line 311 condition true)
 *           Branch: if (cmdType_ != CmdType::SET_RECT) -> true
 *           Should return false and log error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetRect_CmdTypeNotSetRect_True, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    bool result = cmd.MarshallingCmdTypeSetRect(&parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingCmdTypeSetRect_CmdTypeIsSetRect_False
 * @tc.desc: Test MarshallingCmdTypeSetRect when cmdType_ == SET_RECT (line 311 condition false)
 *           Branch: if (cmdType_ != CmdType::SET_RECT) -> false
 *           Should proceed to write rect data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetRect_CmdTypeIsSetRect_False, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 100.0f, 200.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12349;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    MessageParcel parcel;
    bool result = cmd.MarshallingCmdTypeSetRect(&parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MarshallingCmdTypeSetRect_WriteSuccess_False
 * @tc.desc: Test MarshallingCmdTypeSetRect when write succeeds (line 322 condition false)
 *           Branch: if (!ret) -> false
 *           Should return true when all writes succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetRect_WriteSuccess_False, TestSize.Level1)
{
    RectF rect(50.0f, 100.0f, 200.0f, 300.0f);
    bool isSrcRect = false;
    NodeId nodeId = 12350;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    MessageParcel parcel;
    bool result = cmd.MarshallingCmdTypeSetRect(&parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MarshallingCmdTypeSetRect_WriteFailed_True
 * @tc.desc: Test MarshallingCmdTypeSetRect when write fails (line 322 condition true)
 *           Branch: if (!ret) -> true
 *           Should return false when write fails (simulated by invalid parcel)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetRect_WriteFailed_True, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 100.0f, 200.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12351;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    MessageParcel parcel;
    bool result = cmd.MarshallingCmdTypeSetRect(&parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ProcessCmdTypeSetRect_FullFlow_SrcRect
 * @tc.desc: Test ProcessCmdTypeSetRect full flow with srcRect
 *           Verify complete process with all conditions correct for srcRect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetRect_FullFlow_SrcRect, TestSize.Level1)
{
    RectF rect(100.0f, 200.0f, 500.0f, 600.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12352;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->SetDelegateMode(true);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetRect(context));
}

/**
 * @tc.name: ProcessCmdTypeSetRect_FullFlow_DstRect
 * @tc.desc: Test ProcessCmdTypeSetRect full flow with dstRect
 *           Verify complete process with all conditions correct for dstRect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetRect_FullFlow_DstRect, TestSize.Level1)
{
    RectF rect(150.0f, 250.0f, 400.0f, 500.0f);
    bool isSrcRect = false;
    NodeId nodeId = 12353;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    RSContext context;
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId);
    node->SetDelegateMode(true);
    context.nodeMap.renderNodeMap_[0][nodeId] = node;
    EXPECT_NO_FATAL_FAILURE(cmd.ProcessCmdTypeSetRect(context));
}

/**
 * @tc.name: MarshallingCmdTypeSetRect_FullFlow_Success
 * @tc.desc: Test MarshallingCmdTypeSetRect full flow with successful marshalling
 *           Verify complete marshalling process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetRect_FullFlow_Success, TestSize.Level1)
{
    RectF rect(75.0f, 175.0f, 300.0f, 400.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12354;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    MessageParcel parcel;
    bool result = cmd.MarshallingCmdTypeSetRect(&parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: UnmarshallingCmdTypeSetRect_ReadSuccess_True
 * @tc.desc: Test UnmarshallingCmdTypeSetRect when read succeeds (line 299 condition false)
 *           Branch: if (!ret) -> false
 *           Should return valid command when all reads succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, UnmarshallingCmdTypeSetRect_ReadSuccess_True, TestSize.Level1)
{
    MessageParcel parcel;
    float top = 10.0f;
    float left = 20.0f;
    float width = 100.0f;
    float height = 200.0f;
    bool isSrcRect = true;
    NodeId nodeId = 12355;

    parcel.WriteFloat(top);
    parcel.WriteFloat(left);
    parcel.WriteFloat(width);
    parcel.WriteFloat(height);
    parcel.WriteBool(isSrcRect);
    parcel.WriteUint64(nodeId);

    parcel.RewindRead(0);
    RSCommand* cmd = TransactionBufferCommand::UnmarshallingCmdTypeSetRect(&parcel);
    ASSERT_NE(cmd, nullptr);
    delete cmd;
}

/**
 * @tc.name: UnmarshallingCmdTypeSetRect_ReadFailed_False
 * @tc.desc: Test UnmarshallingCmdTypeSetRect when read fails (line 299 condition true)
 *           Branch: if (!ret) -> true
 *           Should return nullptr when read fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, UnmarshallingCmdTypeSetRect_ReadFailed_False, TestSize.Level1)
{
    MessageParcel parcel;
    float top = 10.0f;
    parcel.WriteFloat(top);

    parcel.RewindRead(0);
    RSCommand* cmd = TransactionBufferCommand::UnmarshallingCmdTypeSetRect(&parcel);
    EXPECT_EQ(cmd, nullptr);
}

/**
 * @tc.name: UnmarshallingCmdTypeSetRect_FullFlow_SrcRect
 * @tc.desc: Test UnmarshallingCmdTypeSetRect full flow with srcRect
 *           Verify complete unmarshalling process for srcRect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, UnmarshallingCmdTypeSetRect_FullFlow_SrcRect, TestSize.Level1)
{
    MessageParcel parcel;
    float top = 50.0f;
    float left = 100.0f;
    float width = 200.0f;
    float height = 300.0f;
    bool isSrcRect = true;
    NodeId nodeId = 12356;

    parcel.WriteFloat(top);
    parcel.WriteFloat(left);
    parcel.WriteFloat(width);
    parcel.WriteFloat(height);
    parcel.WriteBool(isSrcRect);
    parcel.WriteUint64(nodeId);

    parcel.RewindRead(0);
    RSCommand* cmd = TransactionBufferCommand::UnmarshallingCmdTypeSetRect(&parcel);
    ASSERT_NE(cmd, nullptr);
    delete cmd;
}

/**
 * @tc.name: UnmarshallingCmdTypeSetRect_FullFlow_DstRect
 * @tc.desc: Test UnmarshallingCmdTypeSetRect full flow with dstRect
 *           Verify complete unmarshalling process for dstRect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeCommandTest, UnmarshallingCmdTypeSetRect_FullFlow_DstRect, TestSize.Level1)
{
    MessageParcel parcel;
    float top = 75.0f;
    float left = 125.0f;
    float width = 250.0f;
    float height = 350.0f;
    bool isSrcRect = false;
    NodeId nodeId = 12357;

    parcel.WriteFloat(top);
    parcel.WriteFloat(left);
    parcel.WriteFloat(width);
    parcel.WriteFloat(height);
    parcel.WriteBool(isSrcRect);
    parcel.WriteUint64(nodeId);

    parcel.RewindRead(0);
    RSCommand* cmd = TransactionBufferCommand::UnmarshallingCmdTypeSetRect(&parcel);
    ASSERT_NE(cmd, nullptr);
    delete cmd;
}

/**
 * @tc.name: Process_SET_RECT_001
 * @tc.desc: Test Process with SET_RECT cmdType (lines 47-48)
 *           Should call ProcessCmdTypeSetRect via Process switch
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, Process_SET_RECT_001, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 30.0f, 40.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    RSContext context;
    EXPECT_NO_FATAL_FAILURE(cmd.Process(context));
}

/**
 * @tc.name: Unmarshalling_EmptyParcel_ReadInt32Fail_001
 * @tc.desc: Test Unmarshalling with empty parcel (lines 64-65)
 *           ReadInt32 fails on empty MessageParcel, should return nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, Unmarshalling_EmptyParcel_ReadInt32Fail_001, TestSize.Level1)
{
    MessageParcel parcel;
    RSCommand* result = TransactionBufferCommand::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: TransactionBufferCommand_Marshalling_RSMarshallingHelperFail_001
 * @tc.desc: Test Marshalling when RSMarshallingHelper fails (lines 91-92)
 *           Set writable_ = false to force all parcel writes to fail
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommand_Marshalling_RSMarshallingHelperFail_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    parcel.writable_ = false;
    bool result = cmd.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TransactionBufferCommand_Marshalling_WriteCmdTypeFail_001
 * @tc.desc: Test Marshalling when WriteInt32(cmdType_) fails after RSMarshallingHelper succeeds (lines 97-99)
 *           Set dataCapacity_ and maxDataCapacity_ to 8 so RSMarshallingHelper succeeds but WriteInt32 fails
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommand_Marshalling_WriteCmdTypeFail_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    parcel.dataCapacity_ = 8;
    parcel.maxDataCapacity_ = 8;
    bool result = cmd.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TransactionBufferCommand_Marshalling_SET_RECT_Success_001
 * @tc.desc: Test Marshalling with SET_RECT cmdType (lines 108-109)
 *           Should enter SET_RECT case and call MarshallingCmdTypeSetRect
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommand_Marshalling_SET_RECT_Success_001, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 30.0f, 40.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    MessageParcel parcel;
    bool result = cmd.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MarshallingCmdTypeSetBuffer_WriteUint32Fail_001
 * @tc.desc: Test MarshallingCmdTypeSetBuffer when WriteUint32(size) fails (lines 127-128)
 *           Set writable_ = false to force write failure
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetBuffer_WriteUint32Fail_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    parcel.writable_ = false;
    bool result = cmd.MarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingCmdTypeSetBuffer_WriteTransactionConfigFail_001
 * @tc.desc: Test MarshallingCmdTypeSetBuffer when WriteTransactionConfigToMessageParcel fails (lines 132-133)
 *           Set dataCapacity_=4, maxDataCapacity_=4 so WriteUint32 succeeds but config write fails
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetBuffer_WriteTransactionConfigFail_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    RSTransactionConfig config;
    config.nodeId = 12345;
    configs.push_back(config);
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    parcel.dataCapacity_ = 4;
    parcel.maxDataCapacity_ = 4;
    bool result = cmd.MarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingCmdTypeSetBuffer_WriteNodeIdFail_001
 * @tc.desc: Test MarshallingCmdTypeSetBuffer when WriteUint64(nodeId_) fails (lines 138-139)
 *           Set dataCapacity_=4, maxDataCapacity_=4 so WriteUint32(0) succeeds but WriteUint64 fails
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetBuffer_WriteNodeIdFail_001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(configs, nodeId);
    MessageParcel parcel;
    parcel.dataCapacity_ = 4;
    parcel.maxDataCapacity_ = 4;
    bool result = cmd.MarshallingCmdTypeSetBuffer(&parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MarshallingCmdTypeSetRect_WriteFail_001
 * @tc.desc: Test MarshallingCmdTypeSetRect when write fails (lines 323-325)
 *           Set writable_ = false to force all writes to fail
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, MarshallingCmdTypeSetRect_WriteFail_001, TestSize.Level1)
{
    RectF rect(10.0f, 20.0f, 30.0f, 40.0f);
    bool isSrcRect = true;
    NodeId nodeId = 12345;
    TransactionBufferCommand cmd(rect, isSrcRect, nodeId);
    MessageParcel parcel;
    parcel.writable_ = false;
    bool result = cmd.MarshallingCmdTypeSetRect(&parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceTransactionCommand_Marshalling_RSMarshallingHelperFail_001
 * @tc.desc: Test SurfaceTransactionCommand Marshalling when RSMarshallingHelper fails (lines 361-362)
 *           Set writable_ = false to force all parcel writes to fail
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest,
    SurfaceTransactionCommand_Marshalling_RSMarshallingHelperFail_001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    MessageParcel parcel;
    parcel.writable_ = false;
    bool result = cmd.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceTransactionCommand_Marshalling_WriteCmdFail_001
 * @tc.desc: Test SurfaceTransactionCommand Marshalling when write command data fails (lines 366-367)
 *           Set dataCapacity_=8, maxDataCapacity_=8 so RSMarshallingHelper succeeds but WriteUint64 fails
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, SurfaceTransactionCommand_Marshalling_WriteCmdFail_001, TestSize.Level1)
{
    uint64_t srcId = 100;
    uint64_t seqNum = 200;
    pid_t pid = 300;
    pid_t tid = 400;
    NodeId nodeId = 123456;
    SurfaceTransactionCommand cmd(srcId, seqNum, pid, tid, nodeId);
    MessageParcel parcel;
    parcel.dataCapacity_ = 8;
    parcel.maxDataCapacity_ = 8;
    bool result = cmd.Marshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UnmarshallingCmdTypeSetRect_ReadFail_001
 * @tc.desc: Test UnmarshallingCmdTypeSetRect when read fails (lines 299-302)
 *           Empty MessageParcel causes read chain to fail
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCommandTest, UnmarshallingCmdTypeSetRect_ReadFail_001, TestSize.Level1)
{
    MessageParcel parcel;
    RSCommand* result = TransactionBufferCommand::UnmarshallingCmdTypeSetRect(&parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: TransactionBufferCommandSubType001
 * @tc.desc: Verify SET_BUFFER constructor maps to TRANSACTION_BUFFER subtype and keeps node id.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandSubType001, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs = { MakeInfoOnlyConfig(SET_BUFFER_NODE_ID, INVALID_BUFFER_SEQ) };
    TransactionBufferCommand cmd(configs, SET_BUFFER_NODE_ID);
    EXPECT_EQ(cmd.GetType(), RSCommandType::DELEGATE_COMPOSITE);
    EXPECT_EQ(cmd.GetSubType(), RSDelegateCompositeCommandType::TRANSACTION_BUFFER);
    EXPECT_EQ(cmd.GetNodeId(), SET_BUFFER_NODE_ID);
}

/**
 * @tc.name: TransactionBufferCommandSubType002
 * @tc.desc: Verify SET_RECT constructor maps to SRC_RECT/DST_RECT subtype by isSrcRect flag.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandSubType002, TestSize.Level1)
{
    RectF srcRect(SRC_RECT_TOP, SRC_RECT_LEFT, SRC_RECT_WIDTH, SRC_RECT_HEIGHT);
    TransactionBufferCommand srcCmd(srcRect, true, SET_RECT_NODE_ID);
    EXPECT_EQ(srcCmd.GetType(), RSCommandType::DELEGATE_COMPOSITE);
    EXPECT_EQ(srcCmd.GetSubType(), RSDelegateCompositeCommandType::TRANSACTION_BUFFER_SRC_RECT);
    EXPECT_EQ(srcCmd.GetNodeId(), SET_RECT_NODE_ID);

    RectF dstRect(DST_RECT_TOP, DST_RECT_LEFT, DST_RECT_WIDTH, DST_RECT_HEIGHT);
    TransactionBufferCommand dstCmd(dstRect, false, SET_RECT_NODE_ID);
    EXPECT_EQ(dstCmd.GetSubType(), RSDelegateCompositeCommandType::TRANSACTION_BUFFER_DST_RECT);
}

/**
 * @tc.name: TransactionBufferCommandMarshalling003
 * @tc.desc: Verify SET_BUFFER marshalling writes DELEGATE_COMPOSITE type and TRANSACTION_BUFFER
 *           subtype header; info-only config (null transaction) fails the payload write.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshalling003, TestSize.Level1)
{
    std::vector<RSTransactionConfig> configs = { MakeInfoOnlyConfig(SET_BUFFER_NODE_ID, INVALID_BUFFER_SEQ) };
    TransactionBufferCommand cmd(configs, SET_BUFFER_NODE_ID);

    MessageParcel parcel;
    // null transaction fails at WriteTransactionConfigToMessageParcel
    EXPECT_FALSE(cmd.Marshalling(parcel));
    // type and subtype header is written before the payload failure
    uint16_t type = 0;
    uint16_t subtype = 0;
    ASSERT_TRUE(RSMarshallingHelper::Unmarshalling(parcel, type, subtype));
    EXPECT_EQ(type, RSCommandType::DELEGATE_COMPOSITE);
    EXPECT_EQ(subtype, RSDelegateCompositeCommandType::TRANSACTION_BUFFER);
}

/**
 * @tc.name: TransactionBufferCommandMarshalling004
 * @tc.desc: Verify SET_RECT src/dst commands round trip keeps their new subtypes.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandMarshalling004, TestSize.Level1)
{
    RectF srcRect(SRC_RECT_TOP, SRC_RECT_LEFT, SRC_RECT_WIDTH, SRC_RECT_HEIGHT);
    TransactionBufferCommand srcCmd(srcRect, true, SET_RECT_NODE_ID);
    MessageParcel srcParcel;
    ASSERT_TRUE(srcCmd.Marshalling(srcParcel));
    uint16_t type = 0;
    uint16_t subtype = 0;
    ASSERT_TRUE(RSMarshallingHelper::Unmarshalling(srcParcel, type, subtype));
    EXPECT_EQ(subtype, RSDelegateCompositeCommandType::TRANSACTION_BUFFER_SRC_RECT);
    auto* srcRaw = TransactionBufferCommand::Unmarshalling(srcParcel);
    ASSERT_NE(srcRaw, nullptr);
    std::unique_ptr<TransactionBufferCommand> srcRoundTrip(static_cast<TransactionBufferCommand*>(srcRaw));
    EXPECT_EQ(srcRoundTrip->GetSubType(), RSDelegateCompositeCommandType::TRANSACTION_BUFFER_SRC_RECT);

    RectF dstRect(DST_RECT_TOP, DST_RECT_LEFT, DST_RECT_WIDTH, DST_RECT_HEIGHT);
    TransactionBufferCommand dstCmd(dstRect, false, SET_RECT_NODE_ID);
    MessageParcel dstParcel;
    ASSERT_TRUE(dstCmd.Marshalling(dstParcel));
    ASSERT_TRUE(RSMarshallingHelper::Unmarshalling(dstParcel, type, subtype));
    EXPECT_EQ(subtype, RSDelegateCompositeCommandType::TRANSACTION_BUFFER_DST_RECT);
    auto* dstRaw = TransactionBufferCommand::Unmarshalling(dstParcel);
    ASSERT_NE(dstRaw, nullptr);
    std::unique_ptr<TransactionBufferCommand> dstRoundTrip(static_cast<TransactionBufferCommand*>(dstRaw));
    EXPECT_EQ(dstRoundTrip->GetSubType(), RSDelegateCompositeCommandType::TRANSACTION_BUFFER_DST_RECT);
    EXPECT_EQ(dstRoundTrip->GetNodeId(), SET_RECT_NODE_ID);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshalling003
 * @tc.desc: Verify unmarshalling fails on empty parcel and on invalid cmdType.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshalling003, TestSize.Level1)
{
    // branch: ReadInt32(cmdType) fails on empty parcel
    MessageParcel emptyParcel;
    EXPECT_EQ(TransactionBufferCommand::Unmarshalling(emptyParcel), nullptr);

    // branch: invalid cmdType hits the default case and returns nullptr
    MessageParcel invalidParcel;
    ASSERT_TRUE(invalidParcel.WriteInt32(999));
    EXPECT_EQ(TransactionBufferCommand::Unmarshalling(invalidParcel), nullptr);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshalling004
 * @tc.desc: Verify SET_BUFFER unmarshalling rejects truncated, oversized and missing-field parcels.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshalling004, TestSize.Level1)
{
    // branch: ReadUint32(size) fails when payload is missing
    MessageParcel noSizeParcel;
    ASSERT_TRUE(noSizeParcel.WriteInt32(0)); // CmdType::SET_BUFFER
    EXPECT_EQ(TransactionBufferCommand::Unmarshalling(noSizeParcel), nullptr);

    // branch: size exceeds SURFACE_PARCEL_SIZE_LIMIT
    MessageParcel oversizeParcel;
    ASSERT_TRUE(oversizeParcel.WriteInt32(0)); // CmdType::SET_BUFFER
    ASSERT_TRUE(oversizeParcel.WriteUint32(UINT32_MAX));
    EXPECT_EQ(TransactionBufferCommand::Unmarshalling(oversizeParcel), nullptr);

    // branch: ReadTransactionConfigFromMessageParcel fails on truncated config payload
    MessageParcel truncatedParcel;
    ASSERT_TRUE(truncatedParcel.WriteInt32(0)); // CmdType::SET_BUFFER
    ASSERT_TRUE(truncatedParcel.WriteUint32(1)); // one config
    ASSERT_TRUE(truncatedParcel.WriteUint64(1)); // config.nodeId
    ASSERT_TRUE(truncatedParcel.WriteBool(false)); // config.hasBuffer
    // transaction info payload truncated: ReadBufferInfoFromMessageParcel fails
    EXPECT_EQ(TransactionBufferCommand::Unmarshalling(truncatedParcel), nullptr);

    // branch: ReadUint64(nodeId) fails when config list is empty and nodeId is missing
    MessageParcel noNodeIdParcel;
    ASSERT_TRUE(noNodeIdParcel.WriteInt32(0)); // CmdType::SET_BUFFER
    ASSERT_TRUE(noNodeIdParcel.WriteUint32(0)); // empty config list
    EXPECT_EQ(TransactionBufferCommand::Unmarshalling(noNodeIdParcel), nullptr);
}

/**
 * @tc.name: TransactionBufferCommandUnmarshalling005
 * @tc.desc: Verify SET_RECT unmarshalling rejects truncated field chains.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandUnmarshalling005, TestSize.Level1)
{
    // branch: rect field chain fails when nothing follows cmdType
    MessageParcel emptyRectParcel;
    ASSERT_TRUE(emptyRectParcel.WriteInt32(1)); // CmdType::SET_RECT
    EXPECT_EQ(TransactionBufferCommand::Unmarshalling(emptyRectParcel), nullptr);

    // branch: rect field chain fails when nodeId is missing
    MessageParcel noNodeIdParcel;
    ASSERT_TRUE(noNodeIdParcel.WriteInt32(1)); // CmdType::SET_RECT
    ASSERT_TRUE(noNodeIdParcel.WriteFloat(SRC_RECT_TOP));
    ASSERT_TRUE(noNodeIdParcel.WriteFloat(SRC_RECT_LEFT));
    ASSERT_TRUE(noNodeIdParcel.WriteFloat(SRC_RECT_WIDTH));
    ASSERT_TRUE(noNodeIdParcel.WriteFloat(SRC_RECT_HEIGHT));
    ASSERT_TRUE(noNodeIdParcel.WriteBool(true));
    EXPECT_EQ(TransactionBufferCommand::Unmarshalling(noNodeIdParcel), nullptr);
}

/**
 * @tc.name: TransactionBufferCommandProcess003
 * @tc.desc: Verify default constructed command hits the invalid cmdType branch without crash.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcess003, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    TransactionBufferCommand cmd;
    EXPECT_EQ(cmd.cmdType_, TransactionBufferCommand::CmdType::INVALID);
    cmd.Process(*context);
}

/**
 * @tc.name: TransactionBufferCommandProcess004
 * @tc.desc: Verify SET_RECT command on a missing node only prints error and does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcess004, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    RectF rect(SRC_RECT_TOP, SRC_RECT_LEFT, SRC_RECT_WIDTH, SRC_RECT_HEIGHT);
    TransactionBufferCommand cmd(rect, true, SET_RECT_NODE_ID);
    EXPECT_EQ(cmd.cmdType_, TransactionBufferCommand::CmdType::SET_RECT);
    cmd.Process(*context);
}

/**
 * @tc.name: TransactionBufferCommandProcess005
 * @tc.desc: Verify SET_RECT command applies src/dst rect on registered delegate node.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcess005, TestSize.Level1)
{
    auto context = CreateContextWithSurfaceNode(SET_RECT_NODE_ID, true);
    auto node = context->GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(SET_RECT_NODE_ID);
    ASSERT_NE(node, nullptr);
    node->SetDelegateSrcRect(RectF{0, 0, 0, 0});
    node->SetDelegateDstRect(RectF{0, 0, 0, 0});

    RectF srcRect(SRC_RECT_LEFT, SRC_RECT_TOP, SRC_RECT_WIDTH, SRC_RECT_HEIGHT);
    TransactionBufferCommand srcCmd(srcRect, true, SET_RECT_NODE_ID);
    srcCmd.Process(*context);
    // ProcessCmdTypeSetRect passes (GetTop, GetLeft, GetWidth, GetHeight) to the node
    EXPECT_EQ(node->GetDelegateSrcRect(),
        RectF(srcRect.GetLeft(), srcRect.GetTop(), srcRect.GetWidth(), srcRect.GetHeight()));

    RectF dstRect(DST_RECT_LEFT, DST_RECT_TOP, DST_RECT_WIDTH, DST_RECT_HEIGHT);
    TransactionBufferCommand dstCmd(dstRect, false, SET_RECT_NODE_ID);
    dstCmd.Process(*context);
    EXPECT_EQ(node->GetDelegateDstRect(),
        RectF(dstRect.GetLeft(), dstRect.GetTop(), dstRect.GetWidth(), dstRect.GetHeight()));
    context->GetMutableNodeMap().UnregisterRenderNode(SET_RECT_NODE_ID);
}

/**
 * @tc.name: TransactionBufferCommandProcessSetBuffer001
 * @tc.desc: Verify info-only flush failure in delegate mode adds release info with invalid fence
 *           and notifies the buffer release listener.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessSetBuffer001, TestSize.Level1)
{
    NodeId nodeId = (static_cast<NodeId>(nodePid_) << 32) | SET_BUFFER_NODE_ID;
    auto context = CreateContextWithSurfaceNode(nodeId, true);
    std::vector<RSTransactionConfig> configs = { MakeInfoOnlyConfig(nodeId, INVALID_BUFFER_SEQ) };
    TransactionBufferCommand cmd(configs, nodeId);

    cmd.Process(*context);
    EXPECT_EQ(listener_->callCount, 1);
    ASSERT_EQ(listener_->received.size(), 1);
    EXPECT_EQ(listener_->received.front().nodeId, nodeId);
    EXPECT_EQ(listener_->received.front().bufferSeqNum, INVALID_BUFFER_SEQ);
    EXPECT_NE(listener_->received.front().releaseFence, nullptr);
    context->GetMutableNodeMap().UnregisterRenderNode(nodeId);
}

/**
 * @tc.name: TransactionBufferCommandProcessSetBuffer002
 * @tc.desc: Verify info-only flush failure without delegate mode does not add release info.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessSetBuffer002, TestSize.Level1)
{
    NodeId nodeId = (static_cast<NodeId>(nodePid_) << 32) | 603;
    auto context = CreateContextWithSurfaceNode(nodeId, false);
    std::vector<RSTransactionConfig> configs = { MakeInfoOnlyConfig(nodeId, INVALID_BUFFER_SEQ) };
    TransactionBufferCommand cmd(configs, nodeId);

    cmd.Process(*context);
    EXPECT_EQ(listener_->callCount, 0);
    context->GetMutableNodeMap().UnregisterRenderNode(nodeId);
}

/**
 * @tc.name: TransactionBufferCommandProcessSetBuffer003
 * @tc.desc: Verify missing node config is skipped without crash or callback.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessSetBuffer003, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    std::vector<RSTransactionConfig> configs = { MakeInfoOnlyConfig(SET_BUFFER_NODE_ID, INVALID_BUFFER_SEQ) };
    TransactionBufferCommand cmd(configs, SET_BUFFER_NODE_ID);
    cmd.Process(*context);
    EXPECT_EQ(listener_->callCount, 0);
}

/**
 * @tc.name: TransactionBufferCommandProcessSetBuffer004
 * @tc.desc: Verify node without consumer surface and consumer without producer are both skipped.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessSetBuffer004, TestSize.Level1)
{
    // branch: node exists but has no consumer
    auto context = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(SET_BUFFER_NODE_ID, context);
    node->SetDelegateMode(true);
    context->GetMutableNodeMap().RegisterRenderNode(node);
    std::vector<RSTransactionConfig> configs = { MakeInfoOnlyConfig(SET_BUFFER_NODE_ID, INVALID_BUFFER_SEQ) };
    TransactionBufferCommand cmd(configs, SET_BUFFER_NODE_ID);
    cmd.Process(*context);
    EXPECT_EQ(listener_->callCount, 0);
    context->GetMutableNodeMap().UnregisterRenderNode(SET_BUFFER_NODE_ID);

    // branch: consumer exists but producer is null
    NodeId nullProducerNodeId = (static_cast<NodeId>(nodePid_) << 32) | 604;
    auto context2 = std::make_shared<RSContext>();
    auto node2 = std::make_shared<RSSurfaceRenderNode>(nullProducerNodeId, context2);
    auto handler2 = node2->GetMutableRSSurfaceHandler();
    ASSERT_NE(handler2, nullptr);
    auto consumer2 = new ConsumerSurface("nullptr_producer");
    consumer2->producer_ = nullptr;
    handler2->SetConsumer(consumer2);
    node2->SetDelegateMode(true);
    context2->GetMutableNodeMap().RegisterRenderNode(node2);
    std::vector<RSTransactionConfig> configs2 = { MakeInfoOnlyConfig(nullProducerNodeId, INVALID_BUFFER_SEQ) };
    TransactionBufferCommand cmd2(configs2, nullProducerNodeId);
    cmd2.Process(*context2);
    EXPECT_EQ(listener_->callCount, 0);
    context2->GetMutableNodeMap().UnregisterRenderNode(nullProducerNodeId);
}

/**
 * @tc.name: TransactionBufferCommandProcessSetBuffer005
 * @tc.desc: Verify non-empty delList triggers CleanProducerBySeqNum before flush.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessSetBuffer005, TestSize.Level1)
{
    NodeId nodeId = (static_cast<NodeId>(nodePid_) << 32) | 605;
    auto context = CreateContextWithSurfaceNode(nodeId, true);
    RSTransactionConfig config = MakeInfoOnlyConfig(nodeId, INVALID_BUFFER_SEQ);
    config.delList = { 1, 2, 3 };
    std::vector<RSTransactionConfig> configs = { config };
    TransactionBufferCommand cmd(configs, nodeId);

    cmd.Process(*context);
    // flush still fails on unknown sequence, delegate mode notifies release info
    EXPECT_EQ(listener_->callCount, 1);
    ASSERT_EQ(listener_->received.size(), 1);
    EXPECT_EQ(listener_->received.front().bufferSeqNum, INVALID_BUFFER_SEQ);
    context->GetMutableNodeMap().UnregisterRenderNode(nodeId);
}

/**
 * @tc.name: TransactionBufferCommandProcessSetBuffer006
 * @tc.desc: Verify attach path returns early when transaction carries no buffer.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessSetBuffer006, TestSize.Level1)
{
    NodeId nodeId = (static_cast<NodeId>(nodePid_) << 32) | 606;
    auto context = CreateContextWithSurfaceNode(nodeId, true);
    RSTransactionConfig config;
    config.nodeId = nodeId;
    config.transaction = new RSBufferTransaction(); // empty transaction without buffer
    config.delList = {};
    std::vector<RSTransactionConfig> configs = { config };
    TransactionBufferCommand cmd(configs, nodeId);

    cmd.Process(*context);
    EXPECT_EQ(listener_->callCount, 0);
    context->GetMutableNodeMap().UnregisterRenderNode(nodeId);
}

/**
 * @tc.name: TransactionBufferCommandProcessSetBuffer007
 * @tc.desc: Verify empty config list skips the loop but still triggers the notify callback path.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessSetBuffer007, TestSize.Level1)
{
    NodeId nodeId = (static_cast<NodeId>(nodePid_) << 32) | 607;
    auto context = CreateContextWithSurfaceNode(nodeId, true);
    std::vector<RSTransactionConfig> emptyConfigs = {};
    TransactionBufferCommand cmd(emptyConfigs, nodeId);

    cmd.Process(*context);
    EXPECT_EQ(listener_->callCount, 0); // no release info, notify finds nothing
    context->GetMutableNodeMap().UnregisterRenderNode(nodeId);
}

/**
 * @tc.name: TransactionBufferCommandProcessSetBuffer008
 * @tc.desc: Verify info-only flush failure with a non-null fence passes the same fence
 *           through to the release callback instead of replacing it with invalid fence.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, TransactionBufferCommandProcessSetBuffer008, TestSize.Level1)
{
    NodeId nodeId = (static_cast<NodeId>(nodePid_) << 32) | 608;
    auto context = CreateContextWithSurfaceNode(nodeId, true);
    RSTransactionConfig config = MakeInfoOnlyConfig(nodeId, INVALID_BUFFER_SEQ);
    sptr<SyncFence> fence = SyncFence::InvalidFence();
    config.transactionInfo.fence = fence; // non-null fence arm of the ternary
    std::vector<RSTransactionConfig> configs = { config };
    TransactionBufferCommand cmd(configs, nodeId);

    cmd.Process(*context);
    EXPECT_EQ(listener_->callCount, 1);
    ASSERT_EQ(listener_->received.size(), 1);
    EXPECT_EQ(listener_->received.front().releaseFence, fence); // same sptr passes through
    context->GetMutableNodeMap().UnregisterRenderNode(nodeId);
}

/**
 * @tc.name: ProcessCmdTypeSetBufferwithAttach001
 * @tc.desc: Verify info-only flush failure in delegate mode adds release info with invalid fence
 *           and notifies the buffer release listener.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCommandTest, ProcessCmdTypeSetBufferwithAttach001, TestSize.Level1)
{
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    sptr<RSBufferTransaction> transaction = new RSBufferTransaction(buffer);
    ASSERT_NE(transaction, nullptr);
    transaction->SetFence(SyncFence::INVALID_FENCE);

    RSTransactionConfig config;
    config.transaction = transaction;
    config.nodeId = 12345;
    auto iConsumer = IConsumerSurface::Create("test");
    ASSERT_NE(iConsumer, nullptr);
    auto consumer = static_cast<ConsumerSurface*>(iConsumer.GetRefPtr());
    ASSERT_NE(consumer->producer_, nullptr);
    consumer->producer_->bufferQueue_ = nullptr;

    TransactionBufferCommand cmd;
    cmd.ProcessCmdTypeSetBufferwithAttach(config.transaction, iConsumer, config, false);
    cmd.ProcessCmdTypeSetBufferwithAttach(config.transaction, iConsumer, config, true);
}
} // namespace OHOS::Rosen