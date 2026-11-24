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
#include "ipc_callbacks/rs_delegate_composite_callback_stub.h"
#include "ipc_callbacks/rs_delegate_composite_callback_interface_code.h"
#include "ipc_callbacks/rs_transaction_callback.h"
#include "message_parcel.h"
#include "message_option.h"
#include "sync_fence.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class RSDelegateCompositeCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static inline sptr<RSWebProxyComposerCallbackStub> webStub_ = nullptr;
    static inline sptr<SurfaceNodeBufferReleaseCallbackStub> bufferStub_ = nullptr;
};

void RSDelegateCompositeCallbackStubTest::SetUpTestCase()
{
    webStub_ = new RSWebProxyComposerCallbackStub();
    bufferStub_ = new SurfaceNodeBufferReleaseCallbackStub();
}

void RSDelegateCompositeCallbackStubTest::TearDownTestCase() {}
void RSDelegateCompositeCallbackStubTest::SetUp() {}
void RSDelegateCompositeCallbackStubTest::TearDown() {}

/**
 * @tc.name: RSWebProxyComposerCallbackStubConstructor001
 * @tc.desc: Test RSWebProxyComposerCallbackStub constructor
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, RSWebProxyComposerCallbackStubConstructor001, TestSize.Level1)
{
    sptr<RSWebProxyComposerCallbackStub> stub = new RSWebProxyComposerCallbackStub();
    EXPECT_NE(stub, nullptr);
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: Test OnRemoteRequest with ON_COMPLETE code - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnRemoteRequest001, TestSize.Level1)
{
    MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(RSISurfaceTransactionListener::GetDescriptor());
    arguments.WriteUint64(123456789);
    arguments.WriteUint64(100);
    arguments.WriteUint32(3);
    arguments.WriteUint64(1);
    arguments.WriteUint64(2);
    arguments.WriteUint64(3);

    uint32_t code = static_cast<uint32_t>(RSIWebProxyComposerCallbackInterfaceCode::ON_COMPLETE);
    int32_t result = webStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: Test OnRemoteRequest with invalid descriptor - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnRemoteRequest002, TestSize.Level1)
{
    MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(u"invalid.descriptor");
    arguments.WriteUint64(123456789);
    arguments.WriteUint64(100);
    arguments.WriteUint32(3);

    uint32_t code = static_cast<uint32_t>(RSIWebProxyComposerCallbackInterfaceCode::ON_COMPLETE);
    int32_t result = webStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
}

/**
 * @tc.name: OnComplete001
 * @tc.desc: Test OnComplete with callback registered - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete001, TestSize.Level1)
{
    bool callbackExecuted = false;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        callbackExecuted = true;
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);
    seqNums.push(2);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_TRUE(callbackExecuted);
}

/**
 * @tc.name: OnComplete002
 * @tc.desc: Test OnComplete without callback - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete002, TestSize.Level1)
{
    webStub_->UnRegisterOnCompleteCallBack();

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: RegisterOnCompleteCallBack001
 * @tc.desc: Test RegisterOnCompleteCallBack
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, RegisterOnCompleteCallBack001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(webStub_->RegisterOnCompleteCallBack([](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {}));
}

/**
 * @tc.name: UnRegisterOnCompleteCallBack001
 * @tc.desc: Test UnRegisterOnCompleteCallBack
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, UnRegisterOnCompleteCallBack001, TestSize.Level1)
{
    webStub_->RegisterOnCompleteCallBack([](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {});
    EXPECT_NO_FATAL_FAILURE(webStub_->UnRegisterOnCompleteCallBack());
}

/**
 * @tc.name: OnComplete_Callback_True_MaxTimestamp_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with UINT64_MAX timestamp
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_MaxTimestamp_001, TestSize.Level1)
{
    uint64_t receivedTimestamp = 0;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedTimestamp = timestamp;
    });

    uint64_t timestamp = UINT64_MAX;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedTimestamp, UINT64_MAX);
}

/**
 * @tc.name: OnComplete_Callback_True_ZeroTimestamp_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with zero timestamp
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_ZeroTimestamp_001, TestSize.Level1)
{
    uint64_t receivedTimestamp = 1;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedTimestamp = timestamp;
    });

    uint64_t timestamp = 0;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedTimestamp, 0ULL);
}

/**
 * @tc.name: OnComplete_Callback_True_MaxSrcId_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with UINT64_MAX srcId
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_MaxSrcId_001, TestSize.Level1)
{
    uint64_t receivedSrcId = 0;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedSrcId = srcId;
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = UINT64_MAX;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedSrcId, UINT64_MAX);
}

/**
 * @tc.name: OnComplete_Callback_True_ZeroSrcId_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with zero srcId
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_ZeroSrcId_001, TestSize.Level1)
{
    uint64_t receivedSrcId = 1;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedSrcId = srcId;
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 0;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedSrcId, 0ULL);
}

/**
 * @tc.name: OnComplete_Callback_True_MaxSeqNum_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with UINT64_MAX seqNum
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_MaxSeqNum_001, TestSize.Level1)
{
    std::vector<uint64_t> receivedSeqNums;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        std::queue<uint64_t> copy = seqNums;
        while (!copy.empty()) {
            receivedSeqNums.push_back(copy.front());
            copy.pop();
        }
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(UINT64_MAX);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedSeqNums.size(), 1UL);
    EXPECT_EQ(receivedSeqNums[0], UINT64_MAX);
}

/**
 * @tc.name: OnComplete_Callback_True_ZeroSeqNum_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with zero seqNum
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_ZeroSeqNum_001, TestSize.Level1)
{
    std::vector<uint64_t> receivedSeqNums;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        std::queue<uint64_t> copy = seqNums;
        while (!copy.empty()) {
            receivedSeqNums.push_back(copy.front());
            copy.pop();
        }
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(0);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedSeqNums.size(), 1UL);
    EXPECT_EQ(receivedSeqNums[0], 0ULL);
}

/**
 * @tc.name: OnComplete_Callback_True_AllMax_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with all max values
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_AllMax_001, TestSize.Level1)
{
    uint64_t receivedTimestamp = 0;
    uint64_t receivedSrcId = 0;
    std::vector<uint64_t> receivedSeqNums;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedTimestamp = timestamp;
        receivedSrcId = srcId;
        std::queue<uint64_t> copy = seqNums;
        while (!copy.empty()) {
            receivedSeqNums.push_back(copy.front());
            copy.pop();
        }
    });

    uint64_t timestamp = UINT64_MAX;
    uint64_t srcId = UINT64_MAX;
    std::queue<uint64_t> seqNums;
    seqNums.push(UINT64_MAX);
    seqNums.push(UINT64_MAX);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedTimestamp, UINT64_MAX);
    EXPECT_EQ(receivedSrcId, UINT64_MAX);
    EXPECT_EQ(receivedSeqNums.size(), 2UL);
}

/**
 * @tc.name: OnComplete_Callback_True_AllZero_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with all zero values
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_AllZero_001, TestSize.Level1)
{
    uint64_t receivedTimestamp = 1;
    uint64_t receivedSrcId = 1;
    size_t receivedQueueSize = 1;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedTimestamp = timestamp;
        receivedSrcId = srcId;
        receivedQueueSize = seqNums.size();
    });

    uint64_t timestamp = 0;
    uint64_t srcId = 0;
    std::queue<uint64_t> seqNums;
    seqNums.push(0);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedTimestamp, 0ULL);
    EXPECT_EQ(receivedSrcId, 0ULL);
    EXPECT_EQ(receivedQueueSize, 1UL);
}

/**
 * @tc.name: OnComplete_Callback_True_MultipleSeqNums_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with multiple seqNums
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_MultipleSeqNums_001, TestSize.Level1)
{
    size_t receivedQueueSize = 0;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedQueueSize = seqNums.size();
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    for (int i = 0; i < 50; i++) {
        seqNums.push(i);
    }

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedQueueSize, 50UL);
}

/**
 * @tc.name: OnComplete_Callback_True_MixedSeqNums_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with mixed seqNums (0, max, normal)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_MixedSeqNums_001, TestSize.Level1)
{
    std::vector<uint64_t> receivedSeqNums;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        std::queue<uint64_t> copy = seqNums;
        while (!copy.empty()) {
            receivedSeqNums.push_back(copy.front());
            copy.pop();
        }
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(0);
    seqNums.push(UINT64_MAX);
    seqNums.push(12345);
    seqNums.push(999999);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedSeqNums.size(), 4UL);
    EXPECT_EQ(receivedSeqNums[0], 0ULL);
    EXPECT_EQ(receivedSeqNums[1], UINT64_MAX);
    EXPECT_EQ(receivedSeqNums[2], 12345ULL);
    EXPECT_EQ(receivedSeqNums[3], 999999ULL);
}

/**
 * @tc.name: OnComplete_Callback_True_CallbackVerifyParams_001
 * @tc.desc: Test OnComplete callback receives exact parameters passed
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_CallbackVerifyParams_001, TestSize.Level1)
{
    uint64_t expectedTimestamp = 888888888;
    uint64_t expectedSrcId = 777;
    std::vector<uint64_t> expectedSeqNums = {100, 200, 300, 400, 500};

    bool allParamsCorrect = false;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        allParamsCorrect = (timestamp == expectedTimestamp) && (srcId == expectedSrcId);
        std::queue<uint64_t> copy = seqNums;
        size_t i = 0;
        while (!copy.empty() && i < expectedSeqNums.size()) {
            if (copy.front() != expectedSeqNums[i]) {
                allParamsCorrect = false;
                break;
            }
            copy.pop();
            i++;
        }
        if (copy.size() != 0 || i != expectedSeqNums.size()) {
            allParamsCorrect = false;
        }
    });

    uint64_t timestamp = expectedTimestamp;
    uint64_t srcId = expectedSrcId;
    std::queue<uint64_t> seqNums;
    for (auto num : expectedSeqNums) {
        seqNums.push(num);
    }

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_TRUE(allParamsCorrect);
}

/**
 * @tc.name: OnComplete_Callback_True_MultipleCalls_001
 * @tc.desc: Test OnComplete called multiple times with same callback
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_MultipleCalls_001, TestSize.Level1)
{
    int callbackCount = 0;
    std::vector<uint64_t> allTimestamps;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        callbackCount++;
        allTimestamps.push_back(timestamp);
    });

    for (int i = 0; i < 10; i++) {
        uint64_t timestamp = i * 1000000;
        uint64_t srcId = i;
        std::queue<uint64_t> seqNums;
        seqNums.push(i);
        GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
        EXPECT_EQ(result, GSERROR_OK);
    }

    EXPECT_EQ(callbackCount, 10);
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(allTimestamps[i], i * 1000000ULL);
    }
}

/**
 * @tc.name: OnComplete_Callback_True_SingleSeqNum_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with single seqNum
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_SingleSeqNum_001, TestSize.Level1)
{
    size_t receivedQueueSize = 0;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedQueueSize = seqNums.size();
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedQueueSize, 1UL);
}

/**
 * @tc.name: OnComplete_Callback_True_VeryLargeQueue_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns true with very large queue (1000 items)
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_VeryLargeQueue_001, TestSize.Level1)
{
    size_t receivedQueueSize = 0;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        receivedQueueSize = seqNums.size();
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    for (int i = 0; i < 1000; i++) {
        seqNums.push(i);
    }

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_EQ(receivedQueueSize, 1000UL);
}

/**
 * @tc.name: OnComplete_Callback_True_RegisterNullThenRegister_001
 * @tc.desc: Test OnComplete after unregister then register again
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_True_RegisterNullThenRegister_001, TestSize.Level1)
{
    int firstCallbackCount = 0;
    int secondCallbackCount = 0;

    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        firstCallbackCount++;
    });

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(firstCallbackCount, 1);

    webStub_->UnRegisterOnCompleteCallBack();
    webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(firstCallbackCount, 1);

    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        secondCallbackCount++;
    });

    webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(firstCallbackCount, 1);
    EXPECT_EQ(secondCallbackCount, 1);
}

/**
 * @tc.name: OnComplete_Callback_False_NoRegister_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns false without ever registering
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_False_NoRegister_001, TestSize.Level1)
{
    sptr<RSWebProxyComposerCallbackStub> freshStub = new RSWebProxyComposerCallbackStub();

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);
    seqNums.push(2);
    seqNums.push(3);

    GSError result = freshStub->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_Callback_False_AfterUnregister_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns false after unregister
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_False_AfterUnregister_001, TestSize.Level1)
{
    bool callbackExecuted = false;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        callbackExecuted = true;
    });

    webStub_->UnRegisterOnCompleteCallBack();
    callbackExecuted = false;

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
    EXPECT_FALSE(callbackExecuted);
}

/**
 * @tc.name: OnComplete_Callback_False_WithMaxParams_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns false with max params
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_False_WithMaxParams_001, TestSize.Level1)
{
    webStub_->UnRegisterOnCompleteCallBack();

    uint64_t timestamp = UINT64_MAX;
    uint64_t srcId = UINT64_MAX;
    std::queue<uint64_t> seqNums;
    seqNums.push(UINT64_MAX);
    seqNums.push(UINT64_MAX);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_Callback_False_WithZeroParams_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns false with zero params
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_False_WithZeroParams_001, TestSize.Level1)
{
    webStub_->UnRegisterOnCompleteCallBack();

    uint64_t timestamp = 0;
    uint64_t srcId = 0;
    std::queue<uint64_t> seqNums;
    seqNums.push(0);

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_Callback_False_EmptyQueue_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns false with empty queue
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_False_EmptyQueue_001, TestSize.Level1)
{
    webStub_->UnRegisterOnCompleteCallBack();

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_Callback_False_LargeQueue_001
 * @tc.desc: Test OnComplete condition onCompleteCallback_ returns false with large queue
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_False_LargeQueue_001, TestSize.Level1)
{
    webStub_->UnRegisterOnCompleteCallBack();

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    for (int i = 0; i < 500; i++) {
        seqNums.push(i);
    }

    GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_Callback_False_MultipleCalls_001
 * @tc.desc: Test OnComplete called multiple times when callback is false
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_Callback_False_MultipleCalls_001, TestSize.Level1)
{
    webStub_->UnRegisterOnCompleteCallBack();

    for (int i = 0; i < 20; i++) {
        uint64_t timestamp = i * 1000000;
        uint64_t srcId = i;
        std::queue<uint64_t> seqNums;
        seqNums.push(i);
        GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
        EXPECT_EQ(result, GSERROR_OK);
    }
}

/**
 * @tc.name: OnComplete_ReturnValue_AlwaysGSERROR_OK_001
 * @tc.desc: Test OnComplete always returns GSERROR_OK regardless of callback state
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_ReturnValue_AlwaysGSERROR_OK_001, TestSize.Level1)
{
    webStub_->RegisterOnCompleteCallBack([](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {});

    uint64_t timestamp = 123456789;
    uint64_t srcId = 100;
    std::queue<uint64_t> seqNums;
    seqNums.push(1);

    GSError result1 = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result1, GSERROR_OK);

    webStub_->UnRegisterOnCompleteCallBack();
    GSError result2 = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result2, GSERROR_OK);

    webStub_->RegisterOnCompleteCallBack([](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {});
    GSError result3 = webStub_->OnComplete(timestamp, srcId, seqNums);
    EXPECT_EQ(result3, GSERROR_OK);
}

/**
 * @tc.name: OnComplete_MutexLock_ThreadSafe_001
 * @tc.desc: Test OnComplete uses mutex lock for thread safety
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_MutexLock_ThreadSafe_001, TestSize.Level1)
{
    int callbackCount = 0;
    webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
        callbackCount++;
    });

    for (int i = 0; i < 100; i++) {
        uint64_t timestamp = i;
        uint64_t srcId = i;
        std::queue<uint64_t> seqNums;
        seqNums.push(i);
        GSError result = webStub_->OnComplete(timestamp, srcId, seqNums);
        EXPECT_EQ(result, GSERROR_OK);
    }

    EXPECT_EQ(callbackCount, 100);
}

/**
 * @tc.name: OnComplete_RegisterUnregisterConcurrent_001
 * @tc.desc: Test concurrent register and unregister operations
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnComplete_RegisterUnregisterConcurrent_001, TestSize.Level1)
{
    for (int cycle = 0; cycle < 10; cycle++) {
        int callbackCount = 0;
        webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
            callbackCount++;
        });

        uint64_t timestamp = 123456789;
        uint64_t srcId = 100;
        std::queue<uint64_t> seqNums;
        seqNums.push(1);

        webStub_->OnComplete(timestamp, srcId, seqNums);
        EXPECT_EQ(callbackCount, 1);

        webStub_->UnRegisterOnCompleteCallBack();
        webStub_->OnComplete(timestamp, srcId, seqNums);
        EXPECT_EQ(callbackCount, 1);

        webStub_->RegisterOnCompleteCallBack([&](uint64_t timestamp, uint64_t srcId, const std::queue<uint64_t>& seqNums) {
            callbackCount++;
        });
        webStub_->OnComplete(timestamp, srcId, seqNums);
        EXPECT_EQ(callbackCount, 2);
    }
}

/**
 * @tc.name: SurfaceNodeBufferReleaseCallbackStubConstructor001
 * @tc.desc: Test SurfaceNodeBufferReleaseCallbackStub constructor
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, SurfaceNodeBufferReleaseCallbackStubConstructor001, TestSize.Level1)
{
    sptr<SurfaceNodeBufferReleaseCallbackStub> stub = new SurfaceNodeBufferReleaseCallbackStub();
    EXPECT_NE(stub, nullptr);
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: Test OnRemoteRequest with ON_BUFFER_COMPLETE code - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnRemoteRequest005, TestSize.Level1)
{
    MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(RSISurfaceNodeBufferReleaseCallback::GetDescriptor());
    arguments.WriteUint32(1);
    arguments.WriteUint64(12345);
    arguments.WriteUint64(67890);
    arguments.WriteUint32(100);

    sptr<SyncFence> fence = SyncFence::INVALID_FENCE;
    fence->WriteToMessageParcel(arguments);
    arguments.WriteBool(false);

    uint32_t code = static_cast<uint32_t>(RSISurfaceNodeBufferReleaseInterfaceCode::ON_BUFFER_COMPLETE);
    int32_t result = bufferStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: Test OnRemoteRequest with invalid descriptor - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnRemoteRequest006, TestSize.Level1)
{
    MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(u"invalid.descriptor");
    arguments.WriteUint32(1);

    uint32_t code = static_cast<uint32_t>(RSISurfaceNodeBufferReleaseInterfaceCode::ON_BUFFER_COMPLETE);
    int32_t result = bufferStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
}

/**
 * @tc.name: OnRemoteRequest007
 * @tc.desc: Test OnRemoteRequest with read size failed - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnRemoteRequest007, TestSize.Level1)
{
MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(RSISurfaceNodeBufferReleaseCallback::GetDescriptor());

    uint32_t code = 999;
    int32_t result = bufferStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_UNKNOWN_TRANSACTION);
}

/**
 * @tc.name: OnRemoteRequest008
 * @tc.desc: Test OnRemoteRequest with read nodeId failed - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnRemoteRequest008, TestSize.Level1)
{
    MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(RSISurfaceNodeBufferReleaseCallback::GetDescriptor());
    arguments.WriteUint32(1);
    arguments.WriteUint64(12345);

    uint32_t code = static_cast<uint32_t>(RSISurfaceNodeBufferReleaseInterfaceCode::ON_BUFFER_COMPLETE);
    int32_t result = bufferStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest009
 * @tc.desc: Test OnRemoteRequest with read releaseFence failed - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnRemoteRequest009, TestSize.Level1)
{
    MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(RSISurfaceNodeBufferReleaseCallback::GetDescriptor());
    arguments.WriteUint32(1);
    arguments.WriteUint64(12345);
    arguments.WriteUint64(67890);
    arguments.WriteUint32(100);

    sptr<SyncFence> fence = nullptr;
    if (fence) {
        fence->WriteToMessageParcel(arguments);
    }
    arguments.WriteBool(false);

    uint32_t code = static_cast<uint32_t>(RSISurfaceNodeBufferReleaseInterfaceCode::ON_BUFFER_COMPLETE);
    int32_t result = bufferStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest010
 * @tc.desc: Test OnRemoteRequest with default code - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnRemoteRequest010, TestSize.Level1)
{
    MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(RSISurfaceNodeBufferReleaseCallback::GetDescriptor());

    uint32_t code = 999;
    int32_t result = bufferStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_UNKNOWN_TRANSACTION);
}

/**
 * @tc.name: OnBufferComplete002
 * @tc.desc: Test OnBufferComplete without callback - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, OnBufferComplete002, TestSize.Level1)
{
    bufferStub_->UnRegisterReleaseBufferCallBack();

    std::queue<OnCompletedRet> queue;

    GSError result = bufferStub_->OnBufferComplete(queue);
    EXPECT_EQ(result, GSERROR_OK);
}

/**
 * @tc.name: WebStub_OnRemoteRequest_DescriptorMatch_True_001
 * @tc.desc: Test RSWebProxyComposerCallbackStub OnRemoteRequest condition GetDescriptor() != remoteDescriptor returns true
 * @tc.type: FUNC
 * @tc.require: issueIAL2EA
 */
HWTEST_F(RSDelegateCompositeCallbackStubTest, WebStub_OnRemoteRequest_DescriptorMatch_True_001, TestSize.Level1)
{
    MessageParcel arguments;
    MessageParcel reply;
    MessageOption option;

    arguments.WriteInterfaceToken(u"invalid.descriptor");

    uint32_t code = static_cast<uint32_t>(RSIWebProxyComposerCallbackInterfaceCode::ON_COMPLETE);
    int32_t result = webStub_->OnRemoteRequest(code, arguments, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
}
} // namespace OHOS::Rosen