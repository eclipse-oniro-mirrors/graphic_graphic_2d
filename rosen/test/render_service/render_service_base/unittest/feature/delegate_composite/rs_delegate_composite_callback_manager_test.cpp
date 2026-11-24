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

#include "command/rs_node_command.h"
#include "command/rs_surface_node_command.h"
#include "command/rs_delegate_composite_command.h"
#include "common/rs_common_def.h"
#include "feature/delegate_composite/rs_delegate_composite_callback_manager.h"
#include "iconsumer_surface.h"
#include "ipc_callbacks/rs_delegate_composite_callback.h"
#include "modifier_ng/rs_modifier_ng_type.h"
#include "iremote_stub.h"
#include "pipeline/rs_context.h"
#include "pipeline/rs_effect_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "surface_buffer_impl.h"
#include "sync_fence.h"
#include "transaction/rs_transaction_data.h"
#include "transaction/transaction.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
#ifndef ROSEN_CROSS_PLATFORM
namespace {
constexpr uint32_t CLEAN_BUFFER_SEQ = 901;
constexpr uint32_t KEEP_BUFFER_SEQ = 902;
constexpr uint32_t RELEASE_BUFFER_SEQ = 903;
constexpr uint32_t PREPARE_BUFFER_SEQ = 904;
constexpr uint64_t SRC_ID_BASE = 900000;
constexpr uint64_t SEQ_NUM_BASE = 910000;
constexpr uint64_t TX_INDEX_FIRST = 1;
constexpr uint64_t TX_INDEX_SECOND = 2;
constexpr NodeId UPDATE_HW_NODE_ID_BASE = 78000;
const char DELEGATE_CHILD_NAME[] = "delegate_child";
} // namespace

class MockNodeBufferReleaseCallback : public IRemoteStub<RSISurfaceNodeBufferReleaseCallback> {
public:
    MockNodeBufferReleaseCallback() = default;
    ~MockNodeBufferReleaseCallback() noexcept override = default;
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

class RSDelegateCompositeCallbackManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void TearDown() override;

    static std::unique_ptr<RSTransactionData> MakeTransactionData(
        pid_t sendingPid, pid_t sendingTid, uint64_t index);
    static std::unique_ptr<RSCommand> MakeBufferCmd(NodeId nodeId, uint32_t sequence);
    static std::unique_ptr<RSCommand> MakeRectCmd(NodeId nodeId, bool isSrcRect);
    static std::shared_ptr<RSSurfaceRenderNode> RegisterDelegateSurfaceNode(
        const std::shared_ptr<RSContext>& context, NodeId nodeId);
    static std::shared_ptr<RSSurfaceRenderNode> MakeNamedSurfaceNode(
        const std::shared_ptr<RSContext>& context, NodeId nodeId, const std::string& name);
    static std::shared_ptr<RSSurfaceRenderNode> MakeDelegateModeNode(
        const std::shared_ptr<RSContext>& context, NodeId nodeId, const std::string& name);
    static void PrepareCommands(pid_t pid, pid_t tid, uint64_t index,
        std::vector<std::unique_ptr<RSCommand>> cmds);
    static void DrainCmdQueues(RSContext& context);
};

void RSDelegateCompositeCallbackManagerTest::SetUpTestCase() {}

void RSDelegateCompositeCallbackManagerTest::TearDownTestCase() {}

void RSDelegateCompositeCallbackManagerTest::TearDown()
{
    // Drain leftover commands and release infos so the singleton stays clean for other tests.
    auto context = std::make_shared<RSContext>();
    DrainCmdQueues(*context);
    RsDelegateCompositeCallbackManager::GetInstance().NotifyCurrentSurfaceNodeBufferReleaseCallback();
    // reset direct-composition flags and hardware composer collection state for other tests
    bool hasCommandProcess = false;
    bool doDirectCompositionSupport = false;
    RsDelegateCompositeCallbackManager::GetInstance().QueryAndResetCommandProcessFlag(
        hasCommandProcess, doDirectCompositionSupport);
    auto resetContext = std::make_shared<RSContext>();
    RsDelegateCompositeCallbackManager::GetInstance().ProcessDelegateCompositeCommand(*resetContext);
}

std::unique_ptr<RSTransactionData> RSDelegateCompositeCallbackManagerTest::MakeTransactionData(
    pid_t sendingPid, pid_t sendingTid, uint64_t index)
{
    auto data = std::make_unique<RSTransactionData>();
    data->SetSendingPid(sendingPid);
    data->SetSendingTid(sendingTid);
    data->SetIndex(index);
    return data;
}

std::unique_ptr<RSCommand> RSDelegateCompositeCallbackManagerTest::MakeBufferCmd(
    NodeId nodeId, uint32_t sequence)
{
    RSTransactionConfig config;
    config.nodeId = nodeId;
    config.transaction = nullptr;
    config.transactionInfo.bufferInfo.sequence = sequence;
    config.transactionInfo.fence = nullptr;
    config.delList = {};
    std::vector<RSTransactionConfig> configs = { config };
    return std::make_unique<TransactionBufferCommand>(configs, nodeId);
}

std::unique_ptr<RSCommand> RSDelegateCompositeCallbackManagerTest::MakeRectCmd(
    NodeId nodeId, bool isSrcRect)
{
    RectF rect(5.0f, 6.0f, 7.0f, 8.0f);
    return std::make_unique<TransactionBufferCommand>(rect, isSrcRect, nodeId);
}

std::shared_ptr<RSSurfaceRenderNode> RSDelegateCompositeCallbackManagerTest::RegisterDelegateSurfaceNode(
    const std::shared_ptr<RSContext>& context, NodeId nodeId)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId, context);
    auto handler = node->GetMutableRSSurfaceHandler();
    if (handler != nullptr) {
        handler->SetConsumer(IConsumerSurface::Create("DelegateManagerTestSurface"));
    }
    node->SetDelegateMode(true);
    context->GetMutableNodeMap().RegisterRenderNode(node);
    return node;
}

std::shared_ptr<RSSurfaceRenderNode> RSDelegateCompositeCallbackManagerTest::MakeNamedSurfaceNode(
    const std::shared_ptr<RSContext>& context, NodeId nodeId, const std::string& name)
{
    RSSurfaceRenderNodeConfig config;
    config.id = nodeId;
    config.name = name;
    return std::make_shared<RSSurfaceRenderNode>(config, context);
}

std::shared_ptr<RSSurfaceRenderNode> RSDelegateCompositeCallbackManagerTest::MakeDelegateModeNode(
    const std::shared_ptr<RSContext>& context, NodeId nodeId, const std::string& name)
{
    auto node = MakeNamedSurfaceNode(context, nodeId, name);
    node->SetDelegateMode(true);
    return node;
}

void RSDelegateCompositeCallbackManagerTest::PrepareCommands(pid_t pid, pid_t tid, uint64_t index,
    std::vector<std::unique_ptr<RSCommand>> cmds)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.AddSurfaceTransactionCmdInfo(SRC_ID_BASE + static_cast<uint64_t>(pid),
        SEQ_NUM_BASE + index, pid, tid);
    auto data = MakeTransactionData(pid, tid, index);
    auto& payload = data->GetPayload();
    for (auto& cmd : cmds) {
        payload.emplace_back(cmd->GetNodeId(), FollowType::NONE, std::move(cmd));
    }
    manager.PrepareDelegateCompositeCommand(data);
}

void RSDelegateCompositeCallbackManagerTest::DrainCmdQueues(RSContext& context)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    while (manager.ProcessDelegateCompositeCommand(context)) {}
}

/**
 * @tc.name: CleanDelegateCompositeCommand001
 * @tc.desc: Verify clean returns true when the pid has no pending command map.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CleanDelegateCompositeCommand001, TestSize.Level1)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_TRUE(manager.CleanDelegateCompositeCommand(0, 0, 654321));
}

/**
 * @tc.name: CleanDelegateCompositeCommand002
 * @tc.desc: Verify clean removes only TRANSACTION_BUFFER commands of the target node across
 *           all index queues; rect subtypes and other nodes are kept.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CleanDelegateCompositeCommand002, TestSize.Level1)
{
    constexpr pid_t sendingPid = 71001;
    constexpr pid_t sendingTid = 71002;
    constexpr pid_t nodePid = 71003;
    NodeId targetNode = (static_cast<NodeId>(nodePid) << 32) | 1;
    NodeId otherNode = (static_cast<NodeId>(nodePid) << 32) | 2;

    auto context = std::make_shared<RSContext>();
    auto targetSurfaceNode = RegisterDelegateSurfaceNode(context, targetNode);
    auto otherSurfaceNode = RegisterDelegateSurfaceNode(context, otherNode);
    auto rectNode = RegisterDelegateSurfaceNode(context, (static_cast<NodeId>(nodePid) << 32) | 3);
    ASSERT_NE(targetSurfaceNode, nullptr);
    ASSERT_NE(otherSurfaceNode, nullptr);
    ASSERT_NE(rectNode, nullptr);

    sptr<MockNodeBufferReleaseCallback> listener = new MockNodeBufferReleaseCallback();
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.RegisterSurfaceNodeBufferReleaseListener(nodePid, listener);

    // index 1 queue: mixed commands
    std::vector<std::unique_ptr<RSCommand>> firstQueue;
    firstQueue.push_back(MakeRectCmd((static_cast<NodeId>(nodePid) << 32) | 3, true)); // rect kept
    firstQueue.push_back(MakeBufferCmd(targetNode, CLEAN_BUFFER_SEQ)); // buffer cleaned
    firstQueue.push_back(MakeBufferCmd(otherNode, KEEP_BUFFER_SEQ)); // other node kept
    firstQueue.push_back(MakeRectCmd((static_cast<NodeId>(nodePid) << 32) | 3, false)); // dst rect kept
    firstQueue.push_back(MakeBufferCmd(targetNode, CLEAN_BUFFER_SEQ)); // buffer cleaned
    PrepareCommands(sendingPid, sendingTid, TX_INDEX_FIRST, std::move(firstQueue));

    // index 2 queue: buffer cmd of target node + rect cmd of target node
    std::vector<std::unique_ptr<RSCommand>> secondQueue;
    secondQueue.push_back(MakeBufferCmd(targetNode, CLEAN_BUFFER_SEQ)); // cleaned in second queue too
    secondQueue.push_back(MakeRectCmd((static_cast<NodeId>(nodePid) << 32) | 3, true)); // kept
    PrepareCommands(sendingPid, sendingTid, TX_INDEX_SECOND, std::move(secondQueue));

    ASSERT_TRUE(manager.CleanDelegateCompositeCommand(0, targetNode, sendingPid));

    DrainCmdQueues(*context);

    RectF delegateSrcRect = RectF(5.0f, 6.0f, 7.0f, 8.0f);
    RectF delegateDstRect = RectF(5.1f, 6.1f, 7.1f, 8.1f);
    rectNode->SetDelegateSrcRect(delegateSrcRect);
    rectNode->SetDelegateDstRect(delegateDstRect);
    // rect commands survived and were processed
    EXPECT_EQ(rectNode->GetDelegateSrcRect(), delegateSrcRect);
    EXPECT_EQ(rectNode->GetDelegateDstRect(), delegateDstRect);
    // only the buffer command of the other node was flushed, target node's were cleaned
    ASSERT_EQ(listener->callCount, 1);
    ASSERT_EQ(listener->received.size(), 1);
    EXPECT_EQ(listener->received.front().nodeId, otherNode);
    EXPECT_EQ(listener->received.front().bufferSeqNum, KEEP_BUFFER_SEQ);
    EXPECT_NE(listener->received.front().releaseFence, nullptr);

    context->GetMutableNodeMap().UnregisterRenderNode(targetNode);
    context->GetMutableNodeMap().UnregisterRenderNode(otherNode);
    context->GetMutableNodeMap().UnregisterRenderNode((static_cast<NodeId>(nodePid) << 32) | 3);
    manager.UnRegisterSurfaceNodeBufferReleaseListener(nodePid);
    manager.RemoveAllListenerbyPid(sendingPid);
}

/**
 * @tc.name: CleanDelegateCompositeCommand003
 * @tc.desc: Verify clean on a pid with only empty index queues returns true and is a no-op.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CleanDelegateCompositeCommand003, TestSize.Level1)
{
    constexpr pid_t sendingPid = 72001;
    constexpr pid_t sendingTid = 72002;
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    // prepare a transaction without any command, produces an empty index queue
    manager.AddSurfaceTransactionCmdInfo(SRC_ID_BASE + sendingPid, SEQ_NUM_BASE, sendingPid, sendingTid);
    auto data = MakeTransactionData(sendingPid, sendingTid, TX_INDEX_FIRST);
    manager.PrepareDelegateCompositeCommand(data);

    EXPECT_TRUE(manager.CleanDelegateCompositeCommand(0, 123, sendingPid));

    auto context = std::make_shared<RSContext>();
    EXPECT_FALSE(manager.ProcessDelegateCompositeCommand(*context));
    manager.RemoveAllListenerbyPid(sendingPid);
}

/**
 * @tc.name: PrepareDelegateCompositeCommand001
 * @tc.desc: Verify prepare with null data or unregistered identity keeps the manager empty.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, PrepareDelegateCompositeCommand001, TestSize.Level1)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    std::unique_ptr<RSTransactionData> nullData = nullptr;
    manager.PrepareDelegateCompositeCommand(nullData); // null data branch

    // identity not registered: sending pid/tid mismatch branch
    constexpr pid_t unknownPid = 73001;
    auto data = MakeTransactionData(unknownPid, 73002, TX_INDEX_FIRST);
    data->GetPayload().emplace_back(0, FollowType::NONE, MakeRectCmd(1, true));
    manager.PrepareDelegateCompositeCommand(data);
    EXPECT_FALSE(data->GetPayload().empty()); // commands are not moved out

    auto context = std::make_shared<RSContext>();
    EXPECT_FALSE(manager.ProcessDelegateCompositeCommand(*context));
}

/**
 * @tc.name: AddBufferReleaseInfo001
 * @tc.desc: Verify null release fence is converted to invalid fence and the listener
 *           receives the entry after notify.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, AddBufferReleaseInfo001, TestSize.Level1)
{
    constexpr pid_t clientPid = 74001;
    constexpr NodeId nodeId = 74002;
    constexpr uint64_t surfaceId = 74003;
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    sptr<MockNodeBufferReleaseCallback> listener = new MockNodeBufferReleaseCallback();
    manager.RegisterSurfaceNodeBufferReleaseListener(clientPid, listener);

    manager.AddBufferReleaseInfo(nodeId, surfaceId, RELEASE_BUFFER_SEQ, nullptr, clientPid);
    manager.NotifyCurrentSurfaceNodeBufferReleaseCallback();

    ASSERT_EQ(listener->callCount, 1);
    ASSERT_EQ(listener->received.size(), 1);
    EXPECT_EQ(listener->received.front().nodeId, nodeId);
    EXPECT_EQ(listener->received.front().queueId, surfaceId);
    EXPECT_EQ(listener->received.front().bufferSeqNum, RELEASE_BUFFER_SEQ);
    EXPECT_NE(listener->received.front().releaseFence, nullptr); // SyncFence::InvalidFence
    manager.UnRegisterSurfaceNodeBufferReleaseListener(clientPid);
}

/**
 * @tc.name: AddBufferReleaseInfo002
 * @tc.desc: Verify buffer/fence/surface overload rejects invalid inputs and surfaces
 *           without delegate user data; valid input notifies with buffer sequence.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, AddBufferReleaseInfo002, TestSize.Level1)
{
    constexpr pid_t clientPid = 75001;
    constexpr NodeId nodeId = 75002;
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    sptr<MockNodeBufferReleaseCallback> listener = new MockNodeBufferReleaseCallback();
    manager.RegisterSurfaceNodeBufferReleaseListener(clientPid, listener);

    sptr<SurfaceBuffer> buffer = new SurfaceBufferImpl(RELEASE_BUFFER_SEQ);
    sptr<SyncFence> fence = SyncFence::InvalidFence();
    sptr<IConsumerSurface> surface = IConsumerSurface::Create("AddReleaseInfoSurface");

    // invalid input branches: null buffer / null fence / null surface / surface without user data
    manager.AddBufferReleaseInfo(nullptr, fence, surface);
    manager.AddBufferReleaseInfo(buffer, nullptr, surface);
    manager.AddBufferReleaseInfo(buffer, fence, nullptr);
    manager.AddBufferReleaseInfo(buffer, fence, surface); // GetInfo fails: no user data
    manager.NotifyCurrentSurfaceNodeBufferReleaseCallback();
    EXPECT_EQ(listener->callCount, 0);

    // valid input after SetInfo
    ASSERT_TRUE(manager.SetInfo(surface, nodeId, clientPid));
    manager.AddBufferReleaseInfo(buffer, fence, surface);
    manager.NotifyCurrentSurfaceNodeBufferReleaseCallback();
    ASSERT_EQ(listener->callCount, 1);
    ASSERT_EQ(listener->received.size(), 1);
    EXPECT_EQ(listener->received.front().nodeId, nodeId);
    EXPECT_EQ(listener->received.front().bufferSeqNum, RELEASE_BUFFER_SEQ);
    manager.UnRegisterSurfaceNodeBufferReleaseListener(clientPid);
}

/**
 * @tc.name: PrepareBufferReleaseInfo001
 * @tc.desc: Verify prepare stores pending release info, rejects duplicate or null buffer,
 *           and process consumes it once with invalid fence for null input.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, PrepareBufferReleaseInfo001, TestSize.Level1)
{
    constexpr pid_t clientPid = 76001;
    constexpr NodeId nodeId = 76002;
    constexpr uint64_t surfaceId = 76003;
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    sptr<MockNodeBufferReleaseCallback> listener = new MockNodeBufferReleaseCallback();
    manager.RegisterSurfaceNodeBufferReleaseListener(clientPid, listener);

    sptr<SurfaceBuffer> buffer = new SurfaceBufferImpl(PREPARE_BUFFER_SEQ);
    uint64_t bufferId = buffer->GetBufferId();

    EXPECT_FALSE(manager.PrepareBufferReleaseInfo(nodeId, surfaceId, nullptr, nullptr, clientPid));
    EXPECT_TRUE(manager.PrepareBufferReleaseInfo(nodeId, surfaceId, buffer, nullptr, clientPid));
    EXPECT_FALSE(manager.PrepareBufferReleaseInfo(nodeId, surfaceId, buffer, nullptr, clientPid));

    EXPECT_TRUE(manager.ProcessBufferReleaseInfo(bufferId));
    EXPECT_FALSE(manager.ProcessBufferReleaseInfo(bufferId)); // already consumed
    manager.NotifyCurrentSurfaceNodeBufferReleaseCallback();

    ASSERT_EQ(listener->callCount, 1);
    ASSERT_EQ(listener->received.size(), 1);
    EXPECT_EQ(listener->received.front().bufferSeqNum, PREPARE_BUFFER_SEQ);
    EXPECT_NE(listener->received.front().releaseFence, nullptr);
    manager.UnRegisterSurfaceNodeBufferReleaseListener(clientPid);
}

/**
 * @tc.name: PrepareBufferReleaseInfo002
 * @tc.desc: Verify a non-null release fence passes through to the callback unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, PrepareBufferReleaseInfo002, TestSize.Level1)
{
    constexpr pid_t clientPid = 77001;
    constexpr NodeId nodeId = 77002;
    constexpr uint64_t surfaceId = 77003;
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    sptr<MockNodeBufferReleaseCallback> listener = new MockNodeBufferReleaseCallback();
    manager.RegisterSurfaceNodeBufferReleaseListener(clientPid, listener);

    sptr<SurfaceBuffer> buffer = new SurfaceBufferImpl(RELEASE_BUFFER_SEQ);
    sptr<SyncFence> fence = SyncFence::InvalidFence();
    uint64_t bufferId = buffer->GetBufferId();

    ASSERT_TRUE(manager.PrepareBufferReleaseInfo(nodeId, surfaceId, buffer, fence, clientPid));
    ASSERT_TRUE(manager.ProcessBufferReleaseInfo(bufferId));
    manager.NotifyCurrentSurfaceNodeBufferReleaseCallback();

    ASSERT_EQ(listener->callCount, 1);
    ASSERT_EQ(listener->received.size(), 1);
    EXPECT_EQ(listener->received.front().releaseFence, fence); // same sptr passes through
    manager.UnRegisterSurfaceNodeBufferReleaseListener(clientPid);
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState001
 * @tc.desc: Verify null surface node input is a safe no-op without crash.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState001, TestSize.Level1)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    std::shared_ptr<RSSurfaceRenderNode> nullNode = nullptr;
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(nullNode);
    SUCCEED();
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState002
 * @tc.desc: Verify a node named delegate_child without delegate mode returns early and
 *           keeps hardware enabled even when a disabled delegate sibling exists.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState002, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto container = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 1, "delegate_container");
    auto disabledSibling = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 2, "web_view");
    disabledSibling->SetHardwareForcedDisabledState(true);
    auto hwcNode = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 3, DELEGATE_CHILD_NAME);
    container->AddChild(disabledSibling);
    container->AddChild(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_FALSE(hwcNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState003
 * @tc.desc: Verify a delegate mode node not named delegate_child returns early and
 *           keeps hardware enabled even when a disabled delegate sibling exists.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState003, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto container = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 11, "delegate_container");
    auto disabledSibling = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 12, "web_view");
    disabledSibling->SetHardwareForcedDisabledState(true);
    auto hwcNode = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 13, "other_child");
    container->AddChild(disabledSibling);
    container->AddChild(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_FALSE(hwcNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState004
 * @tc.desc: Verify an already hardware forced disabled delegate_child returns early
 *           and stays disabled without touching siblings.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState004, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto container = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 21, "delegate_container");
    auto hwcNode = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 22, DELEGATE_CHILD_NAME);
    hwcNode->SetHardwareForcedDisabledState(true);
    container->AddChild(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_TRUE(hwcNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState005
 * @tc.desc: Verify a delegate_child without parent returns early and keeps hardware enabled.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState005, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto hwcNode = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 31, DELEGATE_CHILD_NAME);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_FALSE(hwcNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState006
 * @tc.desc: Verify siblings that do not satisfy delegate mode / not delegate child /
 *           disabled conditions never disable the delegate_child node.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState006, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto container = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 41, "delegate_container");
    auto effectChild = std::make_shared<RSEffectRenderNode>(UPDATE_HW_NODE_ID_BASE + 42, context);
    auto disabledNoDelegateMode = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 43, "web_view");
    disabledNoDelegateMode->SetHardwareForcedDisabledState(true);
    auto delegateModeNotDisabled = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 44, "web_view");
    auto delegateChildDisabled = MakeDelegateModeNode(
        context, UPDATE_HW_NODE_ID_BASE + 45, DELEGATE_CHILD_NAME);
    delegateChildDisabled->SetHardwareForcedDisabledState(true);
    auto hwcNode = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 46, DELEGATE_CHILD_NAME);
    container->AddChild(effectChild);
    container->AddChild(disabledNoDelegateMode);
    container->AddChild(delegateModeNotDisabled);
    container->AddChild(delegateChildDisabled);
    container->AddChild(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_FALSE(hwcNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState007
 * @tc.desc: Verify a sibling with delegate mode, not delegate child and hardware forced
 *           disabled disables the delegate_child node.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState007, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto container = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 51, "delegate_container");
    auto disabledSibling = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 52, "web_view");
    disabledSibling->SetHardwareForcedDisabledState(true);
    auto hwcNode = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 53, DELEGATE_CHILD_NAME);
    container->AddChild(disabledSibling);
    container->AddChild(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_TRUE(hwcNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState008
 * @tc.desc: Verify the sibling loop skips non-matching children and still disables the
 *           delegate_child node when a matching disabled delegate sibling exists.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState008, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto container = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 61, "delegate_container");
    auto effectChild = std::make_shared<RSEffectRenderNode>(UPDATE_HW_NODE_ID_BASE + 62, context);
    auto disabledNoDelegateMode = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 63, "web_view");
    disabledNoDelegateMode->SetHardwareForcedDisabledState(true);
    auto delegateModeNotDisabled = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 64, "web_view");
    auto disabledSibling = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 65, "web_view");
    disabledSibling->SetHardwareForcedDisabledState(true);
    auto hwcNode = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 66, DELEGATE_CHILD_NAME);
    container->AddChild(effectChild);
    container->AddChild(disabledNoDelegateMode);
    container->AddChild(delegateModeNotDisabled);
    container->AddChild(disabledSibling);
    container->AddChild(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_TRUE(hwcNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState009
 * @tc.desc: Verify an expired child in the parent list is skipped by the loop and a
 *           matching disabled sibling after it still disables the delegate_child node.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState009, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto container = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 71, "delegate_container");
    {
        // destroyed while still referenced by the parent children list, leaves an expired weak_ptr
        auto expiredChild = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 72, "web_view");
        expiredChild->SetHardwareForcedDisabledState(true);
        container->AddChild(expiredChild);
    }
    auto disabledSibling = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 73, "web_view");
    disabledSibling->SetHardwareForcedDisabledState(true);
    auto hwcNode = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 74, DELEGATE_CHILD_NAME);
    container->AddChild(disabledSibling);
    container->AddChild(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_TRUE(hwcNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: UpdateHardWareForcedDisabledState010
 * @tc.desc: Verify an expired child alone never disables the delegate_child node.
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, UpdateHardWareForcedDisabledState010, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto container = MakeNamedSurfaceNode(context, UPDATE_HW_NODE_ID_BASE + 81, "delegate_container");
    {
        // destroyed while still referenced by the parent children list, leaves an expired weak_ptr
        auto expiredChild = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 82, "web_view");
        expiredChild->SetHardwareForcedDisabledState(true);
        container->AddChild(expiredChild);
    }
    auto hwcNode = MakeDelegateModeNode(context, UPDATE_HW_NODE_ID_BASE + 83, DELEGATE_CHILD_NAME);
    container->AddChild(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.UpdateHardWareForcedDisabledStateForDelegateMode(hwcNode);
    EXPECT_FALSE(hwcNode->IsHardwareForcedDisabled());
}
static std::shared_ptr<RSSurfaceRenderNode> MakeNodeWithDirtyTypes(const std::shared_ptr<RSContext>& context,
    NodeId nodeId, const std::vector<ModifierNG::RSModifierType>& dirtyTypes)
{
    auto node = std::make_shared<RSSurfaceRenderNode>(nodeId, context);
    for (auto type : dirtyTypes) {
        node->AddDirtyType(type);
    }
    return node;
}

static void ExpectQueryFlags(bool expectHasCommand, bool expectSupport)
{
    bool hasCommandProcess = false;
    bool doDirectCompositionSupport = false;
    RsDelegateCompositeCallbackManager::GetInstance().QueryAndResetCommandProcessFlag(
        hasCommandProcess, doDirectCompositionSupport);
    EXPECT_EQ(hasCommandProcess, expectHasCommand);
    EXPECT_EQ(doDirectCompositionSupport, expectSupport);
}

static void ExpectHwcOptionalState(bool expectHasValue, bool expectValue)
{
    auto value = RsDelegateCompositeCallbackManager::GetInstance().GetDoDirectCompositionSupportByHwcEnable();
    ASSERT_EQ(value.has_value(), expectHasValue);
    if (expectHasValue) {
        EXPECT_EQ(value.value(), expectValue);
    }
}

/**
 * @tc.name: IsDoDirectCompositionSupportByCmd001
 * @tc.desc: any delegate composite subType supports direct composition
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, IsDoDirectCompositionSupportByCmd001, TestSize.Level1)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_TRUE(manager.IsDoDirectCompositionSupportByCmd(RSCommandType::DELEGATE_COMPOSITE,
        RSDelegateCompositeCommandType::TRANSACTION_BUFFER, nullptr));
    EXPECT_TRUE(manager.IsDoDirectCompositionSupportByCmd(RSCommandType::DELEGATE_COMPOSITE,
        RSDelegateCompositeCommandType::TRANSACTION_BUFFER_SRC_RECT, nullptr));
    EXPECT_TRUE(manager.IsDoDirectCompositionSupportByCmd(RSCommandType::DELEGATE_COMPOSITE,
        RSDelegateCompositeCommandType::TRANSACTION_BUFFER_DST_RECT, nullptr));
}

/**
 * @tc.name: IsDoDirectCompositionSupportByCmd002
 * @tc.desc: surface node command supports direct composition only for surface size update
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, IsDoDirectCompositionSupportByCmd002, TestSize.Level1)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_TRUE(manager.IsDoDirectCompositionSupportByCmd(RSCommandType::SURFACE_NODE,
        RSSurfaceNodeCommandType::SURFACE_NODE_UPDATE_SURFACE_SIZE, nullptr));
    EXPECT_FALSE(manager.IsDoDirectCompositionSupportByCmd(RSCommandType::SURFACE_NODE,
        RSSurfaceNodeCommandType::SURFACE_NODE_SET_SNAPSHOT_SKIP_LAYER, nullptr));
}

/**
 * @tc.name: IsDoDirectCompositionSupportByCmd003
 * @tc.desc: rs node commands need the modifier subTypes and a valid node
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, IsDoDirectCompositionSupportByCmd003, TestSize.Level1)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_FALSE(manager.IsDoDirectCompositionSupportByCmd(RSCommandType::RS_NODE, 0x0b02, nullptr));
    EXPECT_FALSE(manager.IsDoDirectCompositionSupportByCmd(
        RSCommandType::RS_NODE, RSNodeCommandType::ADD_MODIFIER_NG, nullptr));
}

/**
 * @tc.name: IsDoDirectCompositionSupportByCmd004
 * @tc.desc: modifier rs node commands follow the node dirty types
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, IsDoDirectCompositionSupportByCmd004, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto boundsNode = MakeNodeWithDirtyTypes(context, 910001, { ModifierNG::RSModifierType::BOUNDS });
    auto transformNode = MakeNodeWithDirtyTypes(context, 910002, { ModifierNG::RSModifierType::TRANSFORM });
    auto bothNode = MakeNodeWithDirtyTypes(context, 910003,
        { ModifierNG::RSModifierType::BOUNDS, ModifierNG::RSModifierType::TRANSFORM });
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_TRUE(manager.IsDoDirectCompositionSupportByCmd(
        RSCommandType::RS_NODE, RSNodeCommandType::ADD_MODIFIER_NG, boundsNode));
    EXPECT_TRUE(manager.IsDoDirectCompositionSupportByCmd(
        RSCommandType::RS_NODE, RSNodeCommandType::REMOVE_MODIFIER_NG, transformNode));
    EXPECT_TRUE(manager.IsDoDirectCompositionSupportByCmd(
        RSCommandType::RS_NODE, RSNodeCommandType::UPDATE_MODIFIER_VECTOR4F, bothNode));
}

/**
 * @tc.name: IsDoDirectCompositionSupportByCmd005
 * @tc.desc: non delegate composite command types never support direct composition
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, IsDoDirectCompositionSupportByCmd005, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto boundsNode = MakeNodeWithDirtyTypes(context, 910011, { ModifierNG::RSModifierType::BOUNDS });
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_FALSE(manager.IsDoDirectCompositionSupportByCmd(
        RSCommandType::ANIMATION, RSNodeCommandType::ADD_MODIFIER_NG, boundsNode));
}

/**
 * @tc.name: CheckRSNodeCommandSubType001
 * @tc.desc: non modifier rs node subTypes never support direct composition
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CheckRSNodeCommandSubType001, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto node = MakeNodeWithDirtyTypes(context, 910021, { ModifierNG::RSModifierType::BOUNDS });
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_FALSE(manager.CheckRSNodeCommandSubType(0x0b02, node));
    EXPECT_FALSE(manager.CheckRSNodeCommandSubType(0x0001, node));
}

/**
 * @tc.name: CheckRSNodeCommandSubType002
 * @tc.desc: null node and empty dirty types do not support direct composition
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CheckRSNodeCommandSubType002, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto emptyNode = MakeNodeWithDirtyTypes(context, 910022, {});
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_FALSE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::ADD_MODIFIER_NG, nullptr));
    EXPECT_FALSE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::ADD_MODIFIER_NG, emptyNode));
}

/**
 * @tc.name: CheckRSNodeCommandSubType003
 * @tc.desc: a single bounds or transform dirty type supports direct composition
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CheckRSNodeCommandSubType003, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto boundsNode = MakeNodeWithDirtyTypes(context, 910023, { ModifierNG::RSModifierType::BOUNDS });
    auto transformNode = MakeNodeWithDirtyTypes(context, 910024, { ModifierNG::RSModifierType::TRANSFORM });
    auto alphaNode = MakeNodeWithDirtyTypes(context, 910025, { ModifierNG::RSModifierType::ALPHA });
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_TRUE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::ADD_MODIFIER_NG, boundsNode));
    EXPECT_TRUE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::ADD_MODIFIER_NG, transformNode));
    EXPECT_FALSE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::ADD_MODIFIER_NG, alphaNode));
}

/**
 * @tc.name: CheckRSNodeCommandSubType004
 * @tc.desc: exactly bounds plus transform supports direct composition, other pairs do not
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CheckRSNodeCommandSubType004, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto bothNode = MakeNodeWithDirtyTypes(context, 910026,
        { ModifierNG::RSModifierType::BOUNDS, ModifierNG::RSModifierType::TRANSFORM });
    auto boundsAlphaNode = MakeNodeWithDirtyTypes(context, 910027,
        { ModifierNG::RSModifierType::BOUNDS, ModifierNG::RSModifierType::ALPHA });
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_TRUE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::ADD_MODIFIER_NG, bothNode));
    EXPECT_FALSE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::ADD_MODIFIER_NG, boundsAlphaNode));
}

/**
 * @tc.name: CheckRSNodeCommandSubType005
 * @tc.desc: three or more dirty types never support direct composition
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CheckRSNodeCommandSubType005, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto tripleNode = MakeNodeWithDirtyTypes(context, 910028,
        { ModifierNG::RSModifierType::BOUNDS, ModifierNG::RSModifierType::TRANSFORM,
          ModifierNG::RSModifierType::ALPHA });
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_FALSE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::ADD_MODIFIER_NG, tripleNode));
}

/**
 * @tc.name: CheckRSNodeCommandSubType006
 * @tc.desc: remove and update modifier vector4f subTypes share the same dirty type rule
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CheckRSNodeCommandSubType006, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto boundsNode = MakeNodeWithDirtyTypes(context, 910029, { ModifierNG::RSModifierType::BOUNDS });
    auto transformNode = MakeNodeWithDirtyTypes(context, 910030, { ModifierNG::RSModifierType::TRANSFORM });
    auto boundsAlphaNode = MakeNodeWithDirtyTypes(context, 910031,
        { ModifierNG::RSModifierType::BOUNDS, ModifierNG::RSModifierType::ALPHA });
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    EXPECT_TRUE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::REMOVE_MODIFIER_NG, boundsNode));
    EXPECT_TRUE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::UPDATE_MODIFIER_VECTOR4F, transformNode));
    EXPECT_FALSE(manager.CheckRSNodeCommandSubType(RSNodeCommandType::UPDATE_MODIFIER_VECTOR4F, boundsAlphaNode));
}
/**
 * @tc.name: GetRSCommandInfo001
 * @tc.desc: transaction buffer command keeps setBufferCmdOnly and fills command info
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, GetRSCommandInfo001, TestSize.Level1)
{
    constexpr NodeId infoNodeId = 920001;
    std::unique_ptr<RSCommand> cmd = MakeBufferCmd(infoNodeId, CLEAN_BUFFER_SEQ);
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    uint16_t cmdType = UINT16_MAX;
    uint16_t cmdSubType = UINT16_MAX;
    NodeId nodeId = 0;
    bool isSetBufferCmdOnly = true;
    manager.GetRSCommandInfo(cmd, cmdType, cmdSubType, nodeId, isSetBufferCmdOnly);
    EXPECT_EQ(cmdType, RSCommandType::DELEGATE_COMPOSITE);
    EXPECT_EQ(cmdSubType, RSDelegateCompositeCommandType::TRANSACTION_BUFFER);
    EXPECT_EQ(nodeId, infoNodeId);
    EXPECT_TRUE(isSetBufferCmdOnly);
    ExpectQueryFlags(true, false);
}

/**
 * @tc.name: GetRSCommandInfo002
 * @tc.desc: surface transaction command keeps setBufferCmdOnly
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, GetRSCommandInfo002, TestSize.Level1)
{
    constexpr NodeId infoNodeId = 920002;
    std::unique_ptr<RSCommand> cmd = std::make_unique<SurfaceTransactionCommand>(1, 2, 3, 4, infoNodeId);
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    uint16_t cmdType = UINT16_MAX;
    uint16_t cmdSubType = UINT16_MAX;
    NodeId nodeId = 0;
    bool isSetBufferCmdOnly = true;
    manager.GetRSCommandInfo(cmd, cmdType, cmdSubType, nodeId, isSetBufferCmdOnly);
    EXPECT_EQ(cmdType, RSCommandType::DELEGATE_COMPOSITE);
    EXPECT_EQ(cmdSubType, RSDelegateCompositeCommandType::SURFACE_TRANSACTION_CMD);
    EXPECT_EQ(nodeId, infoNodeId);
    EXPECT_TRUE(isSetBufferCmdOnly);
    ExpectQueryFlags(true, false);
}

/**
 * @tc.name: GetRSCommandInfo003
 * @tc.desc: set rect subType clears setBufferCmdOnly
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, GetRSCommandInfo003, TestSize.Level1)
{
    constexpr NodeId infoNodeId = 920003;
    std::unique_ptr<RSCommand> cmd = MakeRectCmd(infoNodeId, true);
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    uint16_t cmdType = UINT16_MAX;
    uint16_t cmdSubType = UINT16_MAX;
    NodeId nodeId = 0;
    bool isSetBufferCmdOnly = true;
    manager.GetRSCommandInfo(cmd, cmdType, cmdSubType, nodeId, isSetBufferCmdOnly);
    EXPECT_EQ(cmdSubType, RSDelegateCompositeCommandType::TRANSACTION_BUFFER_SRC_RECT);
    EXPECT_FALSE(isSetBufferCmdOnly);
    ExpectQueryFlags(true, false);
}

/**
 * @tc.name: GetRSCommandInfo004
 * @tc.desc: surface node command clears setBufferCmdOnly
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, GetRSCommandInfo004, TestSize.Level1)
{
    constexpr NodeId infoNodeId = 920004;
    std::unique_ptr<RSCommand> cmd = std::make_unique<RSSurfaceNodeUpdateSurfaceDefaultSize>(infoNodeId, 1.0f, 1.0f);
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    uint16_t cmdType = UINT16_MAX;
    uint16_t cmdSubType = UINT16_MAX;
    NodeId nodeId = 0;
    bool isSetBufferCmdOnly = true;
    manager.GetRSCommandInfo(cmd, cmdType, cmdSubType, nodeId, isSetBufferCmdOnly);
    EXPECT_EQ(cmdType, RSCommandType::SURFACE_NODE);
    EXPECT_EQ(cmdSubType, RSSurfaceNodeCommandType::SURFACE_NODE_UPDATE_SURFACE_SIZE);
    EXPECT_FALSE(isSetBufferCmdOnly);
    ExpectQueryFlags(true, false);
}

/**
 * @tc.name: GetRSCommandInfo005
 * @tc.desc: setBufferCmdOnly stays false once cleared
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, GetRSCommandInfo005, TestSize.Level1)
{
    constexpr NodeId infoNodeId = 920005;
    std::unique_ptr<RSCommand> cmd = MakeBufferCmd(infoNodeId, CLEAN_BUFFER_SEQ);
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    uint16_t cmdType = UINT16_MAX;
    uint16_t cmdSubType = UINT16_MAX;
    NodeId nodeId = 0;
    bool isSetBufferCmdOnly = false;
    manager.GetRSCommandInfo(cmd, cmdType, cmdSubType, nodeId, isSetBufferCmdOnly);
    EXPECT_FALSE(isSetBufferCmdOnly);
    ExpectQueryFlags(true, false);
}

/**
 * @tc.name: QueryAndResetCommandProcessFlag001
 * @tc.desc: clean manager reports no command and stays clean after reset
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, QueryAndResetCommandProcessFlag001, TestSize.Level1)
{
    ExpectQueryFlags(false, false);
    ExpectQueryFlags(false, false);
}

/**
 * @tc.name: QueryAndResetCommandProcessFlag002
 * @tc.desc: flags are reset after one query
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, QueryAndResetCommandProcessFlag002, TestSize.Level1)
{
    constexpr NodeId infoNodeId = 920006;
    std::unique_ptr<RSCommand> cmd = MakeBufferCmd(infoNodeId, CLEAN_BUFFER_SEQ);
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    uint16_t cmdType = UINT16_MAX;
    uint16_t cmdSubType = UINT16_MAX;
    NodeId nodeId = 0;
    bool isSetBufferCmdOnly = true;
    manager.GetRSCommandInfo(cmd, cmdType, cmdSubType, nodeId, isSetBufferCmdOnly);
    ExpectQueryFlags(true, false);
    ExpectQueryFlags(false, false);
    EXPECT_EQ(cmd->GetNodeId(), nodeId);
    EXPECT_EQ(cmd->GetType(), cmdType);
    EXPECT_EQ(cmd->GetSubType(), cmdSubType);
}

/**
 * @tc.name: CollectHwcNodesInfo001
 * @tc.desc: collection disabled or null screen leaves the optional unset
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo001, TestSize.Level1)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(false);
    EXPECT_EQ(manager.needCollectHwcNodesInfoFlag_, false);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(nullptr);
    ExpectHwcOptionalState(false, false);
}

/**
 * @tc.name: CollectHwcNodesInfo002
 * @tc.desc: null screen node with the flag on leaves the optional unset
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo002, TestSize.Level1)
{
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    EXPECT_EQ(manager.needCollectHwcNodesInfoFlag_, true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(nullptr);
    ExpectHwcOptionalState(false, false);
    manager.SetCollectHwcNodesInfoFlag(false);
    EXPECT_EQ(manager.needCollectHwcNodesInfoFlag_, false);
}

/**
 * @tc.name: CollectHwcNodesInfo003
 * @tc.desc: screen without hardware composer children leaves the optional unset
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo003, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(930001, 9301, context);
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    EXPECT_EQ(manager.needCollectHwcNodesInfoFlag_, true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(screenNode);
    ExpectHwcOptionalState(false, false);
    manager.SetCollectHwcNodesInfoFlag(false);
    EXPECT_EQ(manager.needCollectHwcNodesInfoFlag_, false);
}

/**
 * @tc.name: CollectHwcNodesInfo004
 * @tc.desc: all skipped hardware composer nodes leave the optional unset
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo004, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(930002, 9302, context);
    {
        // expired weak handle in the hardware composer list
        auto expired = MakeNamedSurfaceNode(context, 930003, "expired");
        expired->isOnTheTree_ = true;
        screenNode->childHwcNodes_.emplace_back(expired);
    }
    auto offTreeNode = MakeNamedSurfaceNode(context, 930004, "off_tree");
    offTreeNode->isOnTheTree_ = false;
    screenNode->childHwcNodes_.emplace_back(offTreeNode);
    auto noBufferNode = MakeNamedSurfaceNode(context, 930005, "no_buffer");
    noBufferNode->isOnTheTree_ = true;
    screenNode->childHwcNodes_.emplace_back(noBufferNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    EXPECT_EQ(manager.needCollectHwcNodesInfoFlag_, true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(screenNode);
    ExpectHwcOptionalState(false, false);
    manager.SetCollectHwcNodesInfoFlag(false);
    EXPECT_EQ(manager.needCollectHwcNodesInfoFlag_, false);
}

/**
 * @tc.name: CollectHwcNodesInfo005
 * @tc.desc: buffered enabled hardware composer node makes the support optional true
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo005, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(930006, 9306, context);
    auto hwcNode = MakeNamedSurfaceNode(context, 930007, "enabled");
    hwcNode->isOnTheTree_ = true;
    auto handler = hwcNode->GetMutableRSSurfaceHandler();
    ASSERT_NE(handler, nullptr);
    handler->SetBuffer(new SurfaceBufferImpl(0), SyncFence::INVALID_FENCE, Rect { 0, 0, 0, 0 }, 0, nullptr);
    screenNode->childHwcNodes_.emplace_back(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(screenNode);
    ExpectHwcOptionalState(true, true);
    manager.SetCollectHwcNodesInfoFlag(false);
}

/**
 * @tc.name: CollectHwcNodesInfo006
 * @tc.desc: consumed buffer on a forced disabled node blocks direct composition
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo006, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(930008, 9308, context);
    auto hwcNode = MakeNamedSurfaceNode(context, 930009, "consumed");
    hwcNode->isOnTheTree_ = true;
    hwcNode->SetHardwareForcedDisabledState(true);
    auto handler = hwcNode->GetMutableRSSurfaceHandler();
    ASSERT_NE(handler, nullptr);
    handler->SetBuffer(new SurfaceBufferImpl(0), SyncFence::INVALID_FENCE, Rect { 0, 0, 0, 0 }, 0, nullptr);
    handler->SetCurrentFrameBufferConsumed();
    screenNode->childHwcNodes_.emplace_back(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(screenNode);
    ExpectHwcOptionalState(true, false);
    manager.SetCollectHwcNodesInfoFlag(false);
}

/**
 * @tc.name: CollectHwcNodesInfo007
 * @tc.desc: last frame hardware composer enabled with forced disabled node blocks direct composition
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo007, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(930010, 9310, context);
    auto hwcNode = MakeNamedSurfaceNode(context, 930011, "last_frame");
    hwcNode->isOnTheTree_ = true;
    hwcNode->SetHardwareForcedDisabledState(true);
    auto handler = hwcNode->GetMutableRSSurfaceHandler();
    ASSERT_NE(handler, nullptr);
    handler->SetBuffer(new SurfaceBufferImpl(0), SyncFence::INVALID_FENCE, Rect { 0, 0, 0, 0 }, 0, nullptr);
    hwcNode->SetIsLastFrameHwcEnabled(true);
    screenNode->childHwcNodes_.emplace_back(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(screenNode);
    ExpectHwcOptionalState(true, false);
    manager.SetCollectHwcNodesInfoFlag(false);
}

/**
 * @tc.name: CollectHwcNodesInfo008
 * @tc.desc: forced disabled node without consumed buffer or last frame hardware composer keeps support
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo008, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(930012, 9312, context);
    auto hwcNode = MakeNamedSurfaceNode(context, 930013, "disabled_unconsumed");
    hwcNode->isOnTheTree_ = true;
    hwcNode->SetHardwareForcedDisabledState(true);
    auto handler = hwcNode->GetMutableRSSurfaceHandler();
    ASSERT_NE(handler, nullptr);
    handler->SetBuffer(new SurfaceBufferImpl(0), SyncFence::INVALID_FENCE, Rect { 0, 0, 0, 0 }, 0, nullptr);
    screenNode->childHwcNodes_.emplace_back(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(screenNode);
    ExpectHwcOptionalState(true, true);
    manager.SetCollectHwcNodesInfoFlag(false);
}

/**
 * @tc.name: CollectHwcNodesInfo009
 * @tc.desc: a cached false value short circuits the next collection
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo009, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(930014, 9314, context);
    auto hwcNode = MakeNamedSurfaceNode(context, 930015, "blocked");
    hwcNode->isOnTheTree_ = true;
    hwcNode->SetHardwareForcedDisabledState(true);
    auto handler = hwcNode->GetMutableRSSurfaceHandler();
    ASSERT_NE(handler, nullptr);
    handler->SetBuffer(new SurfaceBufferImpl(0), SyncFence::INVALID_FENCE, Rect { 0, 0, 0, 0 }, 0, nullptr);
    handler->SetCurrentFrameBufferConsumed();
    screenNode->childHwcNodes_.emplace_back(hwcNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(screenNode);
    ExpectHwcOptionalState(true, false);
    // cached false short circuits: the healthy node on a new screen cannot revive the flag
    auto healthyNode = MakeNamedSurfaceNode(context, 930016, "healthy");
    healthyNode->isOnTheTree_ = true;
    auto healthyHandler = healthyNode->GetMutableRSSurfaceHandler();
    ASSERT_NE(healthyHandler, nullptr);
    healthyHandler->SetBuffer(new SurfaceBufferImpl(0), SyncFence::INVALID_FENCE, Rect { 0, 0, 0, 0 }, 0, nullptr);
    auto healthyScreen = std::make_shared<RSScreenRenderNode>(930017, 9317, context);
    healthyScreen->childHwcNodes_.emplace_back(healthyNode);
    manager.SetCollectHwcNodesInfoFlag(true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(healthyScreen);
    ExpectHwcOptionalState(true, false);
    manager.SetCollectHwcNodesInfoFlag(false);
}

/**
 * @tc.name: CollectHwcNodesInfo010
 * @tc.desc: a cached true value still re-evaluates and can flip to false
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, CollectHwcNodesInfo010, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    auto goodScreen = std::make_shared<RSScreenRenderNode>(930018, 9318, context);
    auto goodNode = MakeNamedSurfaceNode(context, 930019, "good");
    goodNode->isOnTheTree_ = true;
    auto goodHandler = goodNode->GetMutableRSSurfaceHandler();
    ASSERT_NE(goodHandler, nullptr);
    goodHandler->SetBuffer(new SurfaceBufferImpl(0), SyncFence::INVALID_FENCE, Rect { 0, 0, 0, 0 }, 0, nullptr);
    goodScreen->childHwcNodes_.emplace_back(goodNode);

    auto badScreen = std::make_shared<RSScreenRenderNode>(930020, 9320, context);
    auto badNode = MakeNamedSurfaceNode(context, 930021, "bad");
    badNode->isOnTheTree_ = true;
    badNode->SetHardwareForcedDisabledState(true);
    auto badHandler = badNode->GetMutableRSSurfaceHandler();
    ASSERT_NE(badHandler, nullptr);
    badHandler->SetBuffer(new SurfaceBufferImpl(0), SyncFence::INVALID_FENCE, Rect { 0, 0, 0, 0 }, 0, nullptr);
    badHandler->SetCurrentFrameBufferConsumed();
    badScreen->childHwcNodes_.emplace_back(badNode);

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.SetCollectHwcNodesInfoFlag(true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(goodScreen);
    ExpectHwcOptionalState(true, true);
    // cached true does not short circuit: re-evaluation flips the value to false
    manager.SetCollectHwcNodesInfoFlag(true);
    manager.CollectHwcNodesHardwareForcedDisabledInfo(badScreen);
    ExpectHwcOptionalState(true, false);
    manager.SetCollectHwcNodesInfoFlag(false);
}
/**
 * @tc.name: ProcessEachCommandQueue001
 * @tc.desc: empty queue keeps the flags untouched
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, ProcessEachCommandQueue001, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    std::queue<std::unique_ptr<RSCommand>> queue;
    bool isSetBufferCmdOnly = true;
    bool doDirectCompositionSupportByCmd = true;
    RsDelegateCompositeCallbackManager::GetInstance().ProcessEachCommandQueue(
        queue, *context, isSetBufferCmdOnly, doDirectCompositionSupportByCmd);
    EXPECT_TRUE(isSetBufferCmdOnly);
    EXPECT_TRUE(doDirectCompositionSupportByCmd);
    ExpectQueryFlags(false, false);
}

/**
 * @tc.name: ProcessEachCommandQueue002
 * @tc.desc: null commands are skipped without touching the flags
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, ProcessEachCommandQueue002, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    std::queue<std::unique_ptr<RSCommand>> queue;
    queue.push(nullptr);
    bool isSetBufferCmdOnly = true;
    bool doDirectCompositionSupportByCmd = true;
    RsDelegateCompositeCallbackManager::GetInstance().ProcessEachCommandQueue(
        queue, *context, isSetBufferCmdOnly, doDirectCompositionSupportByCmd);
    EXPECT_TRUE(isSetBufferCmdOnly);
    EXPECT_TRUE(doDirectCompositionSupportByCmd);
    ExpectQueryFlags(false, false);
}

/**
 * @tc.name: ProcessEachCommandQueue003
 * @tc.desc: commands with invalid calling pid are skipped
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, ProcessEachCommandQueue003, TestSize.Level1)
{
    constexpr NodeId queueNodeId = 940001;
    auto context = std::make_shared<RSContext>();
    std::queue<std::unique_ptr<RSCommand>> queue;
    auto cmd = MakeBufferCmd(queueNodeId, CLEAN_BUFFER_SEQ);
    cmd->SetCallingPidValid(false);
    queue.push(std::move(cmd));
    bool isSetBufferCmdOnly = true;
    bool doDirectCompositionSupportByCmd = true;
    RsDelegateCompositeCallbackManager::GetInstance().ProcessEachCommandQueue(
        queue, *context, isSetBufferCmdOnly, doDirectCompositionSupportByCmd);
    EXPECT_TRUE(queue.empty());
    EXPECT_TRUE(isSetBufferCmdOnly);
    EXPECT_TRUE(doDirectCompositionSupportByCmd);
    ExpectQueryFlags(false, false);
}

/**
 * @tc.name: ProcessEachCommandQueue004
 * @tc.desc: buffer only queue keeps setBufferCmdOnly true
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, ProcessEachCommandQueue004, TestSize.Level1)
{
    constexpr NodeId queueNodeId = 940002;
    auto context = std::make_shared<RSContext>();
    std::queue<std::unique_ptr<RSCommand>> queue;
    queue.push(MakeBufferCmd(queueNodeId, CLEAN_BUFFER_SEQ));
    queue.push(std::make_unique<SurfaceTransactionCommand>(1, 2, 3, 4, queueNodeId));
    bool isSetBufferCmdOnly = true;
    bool doDirectCompositionSupportByCmd = true;
    RsDelegateCompositeCallbackManager::GetInstance().ProcessEachCommandQueue(
        queue, *context, isSetBufferCmdOnly, doDirectCompositionSupportByCmd);
    EXPECT_TRUE(queue.empty());
    EXPECT_TRUE(isSetBufferCmdOnly);
    EXPECT_TRUE(doDirectCompositionSupportByCmd);
    ExpectQueryFlags(true, false);
}

/**
 * @tc.name: ProcessEachCommandQueue005
 * @tc.desc: surface size update clears setBufferCmdOnly while keeping cmd support
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, ProcessEachCommandQueue005, TestSize.Level1)
{
    constexpr NodeId queueNodeId = 940003;
    auto context = std::make_shared<RSContext>();
    std::queue<std::unique_ptr<RSCommand>> queue;
    queue.push(MakeBufferCmd(queueNodeId, CLEAN_BUFFER_SEQ));
    queue.push(std::make_unique<RSSurfaceNodeUpdateSurfaceDefaultSize>(queueNodeId, 1.0f, 1.0f));
    bool isSetBufferCmdOnly = true;
    bool doDirectCompositionSupportByCmd = true;
    RsDelegateCompositeCallbackManager::GetInstance().ProcessEachCommandQueue(
        queue, *context, isSetBufferCmdOnly, doDirectCompositionSupportByCmd);
    EXPECT_TRUE(queue.empty());
    EXPECT_FALSE(isSetBufferCmdOnly);
    EXPECT_TRUE(doDirectCompositionSupportByCmd);
    ExpectQueryFlags(true, false);
}

/**
 * @tc.name: ProcessEachCommandQueue006
 * @tc.desc: an unsupported surface node command flips the accumulated support to false
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, ProcessEachCommandQueue006, TestSize.Level1)
{
    constexpr NodeId queueNodeId = 940004;
    auto context = std::make_shared<RSContext>();
    std::queue<std::unique_ptr<RSCommand>> queue;
    queue.push(MakeBufferCmd(queueNodeId, CLEAN_BUFFER_SEQ));
    queue.push(std::make_unique<RSSurfaceNodeSetSnapshotSkipLayer>(queueNodeId, false));
    bool isSetBufferCmdOnly = true;
    bool doDirectCompositionSupportByCmd = true;
    RsDelegateCompositeCallbackManager::GetInstance().ProcessEachCommandQueue(
        queue, *context, isSetBufferCmdOnly, doDirectCompositionSupportByCmd);
    EXPECT_TRUE(queue.empty());
    EXPECT_FALSE(isSetBufferCmdOnly);
    EXPECT_FALSE(doDirectCompositionSupportByCmd);
    ExpectQueryFlags(true, false);
}

/**
 * @tc.name: ProcessDelegateCompositeCommandInner001
 * @tc.desc: empty command map keeps setBufferCmdOnly true and marks cmd support
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, ProcessDelegateCompositeCommandInner001, TestSize.Level1)
{
    auto context = std::make_shared<RSContext>();
    std::unordered_map<pid_t, RsDelegateCompositeCallbackManager::singlePidCmdMap> emptyMap;
    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.ProcessDelegateCompositeCommandInner(*context, emptyMap);
    EXPECT_TRUE(context->GetOnlyDelegateModeSetBufferCmdFlag());
    bool hasCommandProcess = false;
    bool doDirectCompositionSupport = false;
    manager.QueryAndResetCommandProcessFlag(hasCommandProcess, doDirectCompositionSupport);
    EXPECT_FALSE(hasCommandProcess);
    EXPECT_TRUE(doDirectCompositionSupport);
}

/**
 * @tc.name: ProcessDelegateCompositeCommandInner002
 * @tc.desc: mixed queue sets both the context flag and the accumulated support result
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackManagerTest, ProcessDelegateCompositeCommandInner002, TestSize.Level1)
{
    constexpr NodeId innerNodeId = 940101;
    auto context = std::make_shared<RSContext>();
    std::unordered_map<pid_t, RsDelegateCompositeCallbackManager::singlePidCmdMap> cmdMap;
    RsDelegateCompositeCallbackManager::singlePidCmdMap &inner = cmdMap[95001];
    inner[1].push(MakeBufferCmd(innerNodeId, CLEAN_BUFFER_SEQ));
    inner[1].push(std::make_unique<RSSurfaceNodeSetSnapshotSkipLayer>(innerNodeId, false));

    auto& manager = RsDelegateCompositeCallbackManager::GetInstance();
    manager.ProcessDelegateCompositeCommandInner(*context, cmdMap);
    EXPECT_FALSE(context->GetOnlyDelegateModeSetBufferCmdFlag());
    bool hasCommandProcess = false;
    bool doDirectCompositionSupport = false;
    manager.QueryAndResetCommandProcessFlag(hasCommandProcess, doDirectCompositionSupport);
    EXPECT_TRUE(hasCommandProcess);
    EXPECT_FALSE(doDirectCompositionSupport);
}
#endif // ROSEN_CROSS_PLATFORM
} // namespace Rosen
} // namespace OHOS
