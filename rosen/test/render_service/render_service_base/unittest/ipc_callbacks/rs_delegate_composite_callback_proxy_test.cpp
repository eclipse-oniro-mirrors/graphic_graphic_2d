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
#include "ipc_callbacks/rs_delegate_composite_callback.h"
#include "ipc_callbacks/rs_delegate_composite_callback_proxy.h"
#include "ipc_callbacks/rs_delegate_composite_callback_stub.h"
#include "mock_iremote_object.h"
#include "message_parcel.h"
#include "sync_fence.h"
#include "ipc_callbacks/rs_transaction_callback.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class RSDelegateCompositeCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static inline sptr<MockIRemoteObject> remoteObj_ = nullptr;
    static inline sptr<RSWebProxyComposerCallbackProxy> webProxy_ = nullptr;
    static inline sptr<SurfaceNodeBufferReleaseCallbackProxy> bufferProxy_ = nullptr;
};

void RSDelegateCompositeCallbackProxyTest::SetUpTestCase()
{
    remoteObj_ = new MockIRemoteObject();
    webProxy_ = new RSWebProxyComposerCallbackProxy(remoteObj_);
    bufferProxy_ = new SurfaceNodeBufferReleaseCallbackProxy(remoteObj_);
}

void RSDelegateCompositeCallbackProxyTest::TearDownTestCase() {}
void RSDelegateCompositeCallbackProxyTest::SetUp() {}
void RSDelegateCompositeCallbackProxyTest::TearDown() {}

/**
 * @tc.name: RSWebProxyComposerCallbackProxyConstructor001
 * @tc.desc: Test RSWebProxyComposerCallbackProxy constructor
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, RSWebProxyComposerCallbackProxyConstructor001, TestSize.Level1)
{
    sptr<IRemoteObject> remote = new MockIRemoteObject();
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(remote);
    EXPECT_NE(proxy, nullptr);
}

/**
 * @tc.name: OnComplete001
 * @tc.desc: Test OnComplete with valid params - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete001, TestSize.Level1)
{
    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);
    seqNums.push(2);
    seqNums.push(3);

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete002
 * @tc.desc: Test OnComplete with empty seqNums
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete002, TestSize.Level1)
{
    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete003
 * @tc.desc: Test OnComplete with large seqNums queue
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete003, TestSize.Level1)
{
    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    for (int i = 0; i < 100; i++) {
        seqNums.push(i);
    }

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseCallbackProxyConstructor001
 * @tc.desc: Test SurfaceNodeBufferReleaseCallbackProxy constructor
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, SurfaceNodeBufferReleaseCallbackProxyConstructor001, TestSize.Level1)
{
    sptr<IRemoteObject> remote = new MockIRemoteObject();
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(remote);
    EXPECT_NE(proxy, nullptr);
}

/**
 * @tc.name: OnBufferComplete001
 * @tc.desc: Test OnBufferComplete with valid params - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete002
 * @tc.desc: Test OnBufferComplete with empty queue
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete002, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete003
 * @tc.desc: Test OnBufferComplete with multiple items in queue - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete003, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    for (int i = 0; i < 5; i++) {
        OnCompletedRet ret;
        ret.nodeId = 12345 + i;
        ret.clientPid = 1000 + i;
        ret.queueId = 67890 + i;
        ret.bufferSeqNum = 100 + i;
        ret.releaseFence = SyncFence::INVALID_FENCE;
        ret.isActiveGame = (i % 2 == 0);
        queue.push(ret);
    }

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete004
 * @tc.desc: Test OnBufferComplete with isActiveGame true - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete004, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = true;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete005
 * @tc.desc: Test OnBufferComplete with isActiveGame false - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete005, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteInterfaceToken_True_001
 * @tc.desc: Test OnComplete condition !arguments.WriteInterfaceToken returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteInterfaceToken_True_001, TestSize.Level1)
{
    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteParams_True_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint64(timestamp) || !arguments.WriteUint64(srcId) || !arguments.WriteUint32(size) returns false (all success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteParams_True_001, TestSize.Level1)
{
    uint64_t timestamp = UINT64_MAX;
    uint64_t srcId = UINT64_MAX;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_SeqNumsEmpty_True_001
 * @tc.desc: Test OnComplete condition !seqNums.empty() returns true (queue has items)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_SeqNumsEmpty_True_001, TestSize.Level1)
{
    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);
    seqNums.push(2);
    seqNums.push(3);

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_SeqNumsEmpty_False_001
 * @tc.desc: Test OnComplete condition !seqNums.empty() returns false (queue is empty)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_SeqNumsEmpty_False_001, TestSize.Level1)
{
    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteSeqNum_True_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint64(seqNums.front()) returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteSeqNum_True_001, TestSize.Level1)
{
    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(UINT64_MAX);

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_SendRequest_Success_001
 * @tc.desc: Test OnComplete condition ret != ERR_NONE returns false (SendRequest succeeds)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_SendRequest_Success_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_SendRequest_Fail_001
 * @tc.desc: Test OnComplete condition ret != ERR_NONE returns true (SendRequest fails)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_SendRequest_Fail_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_INVALID_DATA;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_BINDER);
}

/**
 * @tc.name: OnBufferComplete_WriteInterfaceToken_True_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteInterfaceToken returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteInterfaceToken_True_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteSize_True_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint32(size) returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteSize_True_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    for (int i = 0; i < 100; i++) {
        OnCompletedRet ret;
        ret.nodeId = 12345 + i;
        ret.clientPid = 1000;
        ret.queueId = 67890;
        ret.bufferSeqNum = 100;
        ret.releaseFence = SyncFence::INVALID_FENCE;
        ret.isActiveGame = false;
        queue.push(ret);
    }

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_QueueEmpty_True_001
 * @tc.desc: Test OnBufferComplete condition !queue.empty() returns true (queue has items)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_QueueEmpty_True_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_QueueEmpty_False_001
 * @tc.desc: Test OnBufferComplete condition !queue.empty() returns false (queue is empty)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_QueueEmpty_False_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteNodeId_True_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint64(ret.nodeId) returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteNodeId_True_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = UINT64_MAX;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteQueueId_True_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint64(ret.queueId) returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteQueueId_True_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = UINT64_MAX;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteBufferSeqNum_True_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint32(ret.bufferSeqNum) returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteBufferSeqNum_True_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = UINT32_MAX;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteReleaseFence_True_001
 * @tc.desc: Test OnBufferComplete condition !ret.releaseFence->WriteToMessageParcel(data) returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteReleaseFence_True_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteIsActiveGame_True_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteBool(ret.isActiveGame) returns false (success, isActiveGame=true)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteIsActiveGame_True_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = true;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteIsActiveGame_False_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteBool(ret.isActiveGame) returns false (success, isActiveGame=false)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteIsActiveGame_False_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_SendRequest_Success_001
 * @tc.desc: Test OnBufferComplete condition err != NO_ERROR returns false (SendRequest succeeds)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_SendRequest_Success_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_SendRequest_Fail_001
 * @tc.desc: Test OnBufferComplete condition err != NO_ERROR returns true (SendRequest fails)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_SendRequest_Fail_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_INVALID_DATA;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_BINDER);
}

/**
 * @tc.name: OnBufferComplete_MultipleQueueItems_001
 * @tc.desc: Test OnBufferComplete with multiple items - each item processed in while loop
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_MultipleQueueItems_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    for (int i = 0; i < 10; i++) {
        OnCompletedRet ret;
        ret.nodeId = 12345 + i;
        ret.clientPid = 1000 + i;
        ret.queueId = 67890 + i;
        ret.bufferSeqNum = 100 + i;
        ret.releaseFence = SyncFence::INVALID_FENCE;
        ret.isActiveGame = (i % 2 == 0);
        queue.push(ret);
    }

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_ZeroTimestamp_001
 * @tc.desc: Test OnComplete with zero timestamp
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_ZeroTimestamp_001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_ZeroSrcId_001
 * @tc.desc: Test OnComplete with zero srcId
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_ZeroSrcId_001, TestSize.Level1)
{
    uint64_t timestamp = 123456789;
    uint64_t srcId = 0;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webProxy_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_ZeroNodeId_001
 * @tc.desc: Test OnBufferComplete with zero nodeId
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_ZeroNodeId_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 0;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_ZeroClientPid_001
 * @tc.desc: Test OnBufferComplete with zero clientPid
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_ZeroClientPid_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 0;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_ZeroQueueId_001
 * @tc.desc: Test OnBufferComplete with zero queueId
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_ZeroQueueId_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 0;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_ZeroBufferSeqNum_001
 * @tc.desc: Test OnBufferComplete with zero bufferSeqNum
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_ZeroBufferSeqNum_001, TestSize.Level1)
{
    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 0;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = bufferProxy_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_SendRequest_True_001
 * @tc.desc: Test OnComplete condition ret != ERR_NONE returns true (SendRequest fails with various error codes)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_SendRequest_True_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_DEAD_OBJECT;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_BINDER);
}

/**
 * @tc.name: OnComplete_SendRequest_False_001
 * @tc.desc: Test OnComplete condition ret != ERR_NONE returns false (SendRequest succeeds with ERR_NONE)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_SendRequest_False_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteTimestamp_True_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint64(timestamp) returns false (success with max timestamp)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteTimestamp_True_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = UINT64_MAX;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteTimestamp_Zero_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint64(timestamp) returns false (success with zero timestamp)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteTimestamp_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 0;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteSrcId_True_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint64(srcId) returns false (success with max srcId)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteSrcId_True_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = UINT64_MAX;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteSrcId_Zero_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint64(srcId) returns false (success with zero srcId)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteSrcId_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 0;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteSize_True_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint32(size) returns false (success with size=1)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteSize_True_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteSize_Zero_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint32(size) returns false (success with size=0)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteSize_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteSize_Large_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint32(size) returns false (success with large size)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteSize_Large_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    for (int i = 0; i < 1000; i++) {
        seqNums.push(i);
    }

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteSeqNums_Multiple_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint64(seqNums.front()) returns false for multiple seqNums
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteSeqNums_Multiple_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);
    seqNums.push(UINT64_MAX);
    seqNums.push(0);
    seqNums.push(999999);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WriteSeqNum_Zero_001
 * @tc.desc: Test OnComplete condition !arguments.WriteUint64(seqNums.front()) returns false with zero seqNum
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WriteSeqNum_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(0);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WhileLoop_True_001
 * @tc.desc: Test OnComplete while loop condition !seqNums.empty() returns true (queue has items)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WhileLoop_True_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);
    seqNums.push(2);
    seqNums.push(3);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_WhileLoop_False_001
 * @tc.desc: Test OnComplete while loop condition !seqNums.empty() returns false (queue is empty)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_WhileLoop_False_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_AllParams_Max_001
 * @tc.desc: Test OnComplete with all params at max values
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_AllParams_Max_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = UINT64_MAX;
    uint64_t srcId = UINT64_MAX;
    std::queue<uint64_t> seqNums;
    seqNums.push(UINT64_MAX);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_AllParams_Zero_001
 * @tc.desc: Test OnComplete with all params at zero values
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_AllParams_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_NONE;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 0;
    uint64_t srcId = 0;
    std::queue<uint64_t> seqNums;
    seqNums.push(0);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_SendRequest_EINVAL_001
 * @tc.desc: Test OnComplete condition ret != ERR_NONE returns true (SendRequest fails with EINVAL)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_SendRequest_EINVAL_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = EINVAL;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_BINDER);
}

/**
 * @tc.name: OnComplete_SendRequest_TIMEDOUT_001
 * @tc.desc: Test OnComplete condition ret != ERR_NONE returns true (SendRequest fails with TIMEDOUT)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnComplete_SendRequest_TIMEDOUT_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ETIMEDOUT;
    sptr<RSWebProxyComposerCallbackProxy> proxy = new RSWebProxyComposerCallbackProxy(mockRemote);

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = proxy->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_BINDER);
}

/**
 * @tc.name: OnBufferComplete_SendRequest_True_001
 * @tc.desc: Test OnBufferComplete condition err != NO_ERROR returns true (SendRequest fails with ERR_DEAD_OBJECT)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_SendRequest_True_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ERR_DEAD_OBJECT;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_BINDER);
}

/**
 * @tc.name: OnBufferComplete_SendRequest_False_001
 * @tc.desc: Test OnBufferComplete condition err != NO_ERROR returns false (SendRequest succeeds with NO_ERROR)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_SendRequest_False_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_SendRequest_EINVAL_001
 * @tc.desc: Test OnBufferComplete condition err != NO_ERROR returns true (SendRequest fails with EINVAL)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_SendRequest_EINVAL_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = EINVAL;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_BINDER);
}

/**
 * @tc.name: OnBufferComplete_SendRequest_TIMEDOUT_001
 * @tc.desc: Test OnBufferComplete condition err != NO_ERROR returns true (SendRequest fails with ETIMEDOUT)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_SendRequest_TIMEDOUT_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = ETIMEDOUT;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_BINDER);
}

/**
 * @tc.name: OnBufferComplete_WriteNodeId_Max_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint64(ret.nodeId) returns false (success with max nodeId)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteNodeId_Max_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = UINT64_MAX;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteNodeId_Zero_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint64(ret.nodeId) returns false (success with zero nodeId)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteNodeId_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 0;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteQueueId_Max_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint64(ret.queueId) returns false (success with max queueId)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteQueueId_Max_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = UINT64_MAX;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteQueueId_Zero_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint64(ret.queueId) returns false (success with zero queueId)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteQueueId_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 0;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteBufferSeqNum_Max_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint32(ret.bufferSeqNum) returns false (success with max bufferSeqNum)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteBufferSeqNum_Max_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = UINT32_MAX;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteBufferSeqNum_Zero_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint32(ret.bufferSeqNum) returns false (success with zero bufferSeqNum)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteBufferSeqNum_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 0;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteClientPid_Max_001
 * @tc.desc: Test OnBufferComplete with max clientPid value
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteClientPid_Max_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = UINT32_MAX;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteClientPid_Zero_001
 * @tc.desc: Test OnBufferComplete with zero clientPid value
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteClientPid_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 0;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteSize_One_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint32(size) returns false (success with size=1)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteSize_One_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteSize_Zero_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint32(size) returns false (success with size=0, empty queue)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteSize_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteSize_Large_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteUint32(size) returns false (success with large size=500)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteSize_Large_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    for (int i = 0; i < 500; i++) {
        OnCompletedRet ret;
        ret.nodeId = 12345 + i;
        ret.clientPid = 1000 + i;
        ret.queueId = 67890 + i;
        ret.bufferSeqNum = 100 + i;
        ret.releaseFence = SyncFence::INVALID_FENCE;
        ret.isActiveGame = (i % 2 == 0);
        queue.push(ret);
    }

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WhileLoop_True_001
 * @tc.desc: Test OnBufferComplete while loop condition !queue.empty() returns true (queue has items)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WhileLoop_True_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret1;
    ret1.nodeId = 12345;
    ret1.clientPid = 1000;
    ret1.queueId = 67890;
    ret1.bufferSeqNum = 100;
    ret1.releaseFence = SyncFence::INVALID_FENCE;
    ret1.isActiveGame = false;
    queue.push(ret1);

    OnCompletedRet ret2;
    ret2.nodeId = 12346;
    ret2.clientPid = 1001;
    ret2.queueId = 67891;
    ret2.bufferSeqNum = 101;
    ret2.releaseFence = SyncFence::INVALID_FENCE;
    ret2.isActiveGame = true;
    queue.push(ret2);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WhileLoop_False_001
 * @tc.desc: Test OnBufferComplete while loop condition !queue.empty() returns false (queue is empty)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WhileLoop_False_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_AllFields_Max_001
 * @tc.desc: Test OnBufferComplete with all fields at max values
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_AllFields_Max_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = UINT64_MAX;
    ret.clientPid = UINT32_MAX;
    ret.queueId = UINT64_MAX;
    ret.bufferSeqNum = UINT32_MAX;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = true;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_AllFields_Zero_001
 * @tc.desc: Test OnBufferComplete with all fields at zero values
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_AllFields_Zero_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 0;
    ret.clientPid = 0;
    ret.queueId = 0;
    ret.bufferSeqNum = 0;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteIsActiveGame_True_002
 * @tc.desc: Test OnBufferComplete condition !data.WriteBool(ret.isActiveGame) returns false (isActiveGame=true)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteIsActiveGame_True_002, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = true;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteIsActiveGame_False_002
 * @tc.desc: Test OnBufferComplete condition !data.WriteBool(ret.isActiveGame) returns false (isActiveGame=false)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteIsActiveGame_False_002, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_MultipleItemsMixed_001
 * @tc.desc: Test OnBufferComplete with multiple items having mixed field values
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_MultipleItemsMixed_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;

    OnCompletedRet ret1;
    ret1.nodeId = UINT64_MAX;
    ret1.clientPid = 0;
    ret1.queueId = UINT64_MAX;
    ret1.bufferSeqNum = 0;
    ret1.releaseFence = SyncFence::INVALID_FENCE;
    ret1.isActiveGame = true;
    queue.push(ret1);

    OnCompletedRet ret2;
    ret2.nodeId = 0;
    ret2.clientPid = UINT32_MAX;
    ret2.queueId = 0;
    ret2.bufferSeqNum = UINT32_MAX;
    ret2.releaseFence = SyncFence::INVALID_FENCE;
    ret2.isActiveGame = false;
    queue.push(ret2);

    OnCompletedRet ret3;
    ret3.nodeId = 12345;
    ret3.clientPid = 1000;
    ret3.queueId = 67890;
    ret3.bufferSeqNum = 100;
    ret3.releaseFence = SyncFence::INVALID_FENCE;
    ret3.isActiveGame = true;
    queue.push(ret3);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_WriteInterfaceToken_False_001
 * @tc.desc: Test OnBufferComplete condition !data.WriteInterfaceToken returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_WriteInterfaceToken_False_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnBufferComplete_ReleaseFenceWrite_False_001
 * @tc.desc: Test OnBufferComplete condition !ret.releaseFence->WriteToMessageParcel returns false (success)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackProxyTest, OnBufferComplete_ReleaseFenceWrite_False_001, TestSize.Level1)
{
    sptr<MockIRemoteObject> mockRemote = new MockIRemoteObject();
    mockRemote->sendRequestResult_ = NO_ERROR;
    sptr<SurfaceNodeBufferReleaseCallbackProxy> proxy = new SurfaceNodeBufferReleaseCallbackProxy(mockRemote);

    std::queue<OnCompletedRet> queue;
    OnCompletedRet ret;
    ret.nodeId = 12345;
    ret.clientPid = 1000;
    ret.queueId = 67890;
    ret.bufferSeqNum = 100;
    ret.releaseFence = SyncFence::INVALID_FENCE;
    ret.isActiveGame = false;
    queue.push(ret);

    GSError result = proxy->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

} // namespace OHOS::Rosen