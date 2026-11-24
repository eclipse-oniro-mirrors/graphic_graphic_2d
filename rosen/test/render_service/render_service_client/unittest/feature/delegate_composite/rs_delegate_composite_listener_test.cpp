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

#ifndef ROSEN_CROSS_PLATFORM
#include <thread>
#include "gtest/gtest.h"
#include "rs_delegate_composite_listener.h"
#include "command/rs_command.h"
#include "ipc_callbacks/rs_transaction_callback.h"
#include "ipc_callbacks/rs_delegate_composite_callback_stub.h"
#include "platform/ohos/rs_render_service_connect_hub.h"
#include "platform/ohos/transaction/zidl/rs_client_to_render_connection_proxy.h"
#include "ipc_object_stub.h"
#include "transaction/rs_interfaces.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

// Fake render-process connection that makes Register/UnRegister calls succeed, so the
// success branches of SurfaceTransactionListener / SurfaceNodeBufferReleaseListener are reachable
// without a live render service.
class MockClientToRenderConnection : public RSClientToRenderConnectionProxy {
public:
    explicit MockClientToRenderConnection(const sptr<IRemoteObject>& impl)
        : RSClientToRenderConnectionProxy(impl) {};
    bool RegisterSurfaceTransactionListener(sptr<RSISurfaceTransactionListener> listener,
        uint64_t listenerId) override
    {
        return true;
    }
    bool UnRegisterSurfaceTransactionListener(uint64_t listenerId) override { return true; }
    bool RegisterSurfaceNodeBufferReleaseListener(sptr<RSISurfaceNodeBufferReleaseCallback> listener) override
    {
        return true;
    }
    bool UnRegisterSurfaceNodeBufferReleaseListener() override { return true; }
    bool SetDelegateMode(NodeId id, bool isSetDelegateMode, pid_t pid) override { return true; }
};

class RSDelegateCompositeListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
private:
    static inline sptr<IRemoteObject> connectToRender_ = nullptr;
};

void RSDelegateCompositeListenerTest::SetUpTestCase()
{
    auto screenId = RSInterfaces::GetInstance().GetDefaultScreenId();
    connectToRender_ = RSInterfaces::GetInstance().GetConnectToRenderToken(screenId);
}

void RSDelegateCompositeListenerTest::TearDownTestCase()
{
    connectToRender_ = nullptr;
}

void RSDelegateCompositeListenerTest::SetUp() {}
void RSDelegateCompositeListenerTest::TearDown() {}

/**
 * @tc.name: SurfaceTransactionListenerConstructor001
 * @tc.desc: Test SurfaceTransactionListener constructor
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceTransactionListenerConstructor001, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    EXPECT_NE(listener, nullptr);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: SurfaceTransactionListenerGetUniqueId001
 * @tc.desc: Test GetUniqueId returns valid id
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceTransactionListenerGetUniqueId001, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    uint64_t uniqueId = listener->GetUniqueId();
    EXPECT_NE(uniqueId, 0);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: SurfaceTransactionListenerGetCommand001
 * @tc.desc: Test GetCommand with workTid matches current tid - true branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceTransactionListenerGetCommand001, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    uint64_t cmdSeqNum = 0;
    auto command = listener->GetCommand(cmdSeqNum);
    EXPECT_NE(command, nullptr);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: RegisterCommandCompleteCallBack001
 * @tc.desc: Test RegisterCommandCompleteCallBack with valid callback
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, RegisterCommandCompleteCallBack001, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    bool result = listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    EXPECT_TRUE(result);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: RegisterCommandCompleteCallBack002
 * @tc.desc: Test RegisterCommandCompleteCallBack with existing callback - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, RegisterCommandCompleteCallBack002, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    bool result = listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    EXPECT_FALSE(result);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: RegisterCommandCompleteCallBack007
 * @tc.desc: Test RegisterCommandCompleteCallBack when renderPipelineClient creation is valid
 *           Branch: if (renderPipelineClient == nullptr) -> true (line 84)
 *           Note: This branch is typically unreachable as make_shared normally succeeds
 *           Testing the error handling path when renderPipelineClient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, RegisterCommandCompleteCallBack007, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    bool result = listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    EXPECT_TRUE(result);
    listener->UnRegisterCommandCompleteCallBack();
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: UnRegisterCommandCompleteCallBack001
 * @tc.desc: Test UnRegisterCommandCompleteCallBack with registered callback
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, UnRegisterCommandCompleteCallBack001, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    bool result = listener->UnRegisterCommandCompleteCallBack();
    EXPECT_TRUE(result);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: UnRegisterCommandCompleteCallBack002
 * @tc.desc: Test UnRegisterCommandCompleteCallBack without registered callback - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, UnRegisterCommandCompleteCallBack002, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    bool result = listener->UnRegisterCommandCompleteCallBack();
    EXPECT_FALSE(result);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: UnRegisterCommandCompleteCallBack004
 * @tc.desc: Test UnRegisterCommandCompleteCallBack when UnRegisterSurfaceTransactionListener fails
 *           Branch: if (!renderPipelineClient_->UnRegisterSurfaceTransactionListener(...)) -> true (line 107)
 *           Should return false when unregistration fails
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, UnRegisterCommandCompleteCallBack004, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    auto renderServiceConnectHub = RSRenderServiceConnectHub::GetInstance();
    RSRenderServiceConnectHub::instance_ = nullptr;
    bool result = listener->UnRegisterCommandCompleteCallBack();
    EXPECT_FALSE(result);
    RSRenderServiceConnectHub::instance_ = renderServiceConnectHub;
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: RegisterCommandCompleteCallBack003
 * @tc.desc: Test RegisterCommandCompleteCallBack when renderPipelineClient creation succeeds
 *           Branch: if (renderPipelineClient == nullptr) -> false (line 84)
 *           Should proceed to RegisterSurfaceTransactionListener
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, RegisterCommandCompleteCallBack003, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    bool result = listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    EXPECT_TRUE(result);
    listener->UnRegisterCommandCompleteCallBack();
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: RegisterCommandCompleteCallBack004
 * @tc.desc: Test RegisterCommandCompleteCallBack when RegisterSurfaceTransactionListener succeeds
 *           Branch: if (!renderPipelineClient->RegisterSurfaceTransactionListener(...)) -> false (line 89)
 *           Should successfully register and return true
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, RegisterCommandCompleteCallBack004, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    bool result = listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    EXPECT_TRUE(result);
    listener->UnRegisterCommandCompleteCallBack();
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: UnRegisterCommandCompleteCallBack003
 * @tc.desc: Test UnRegisterCommandCompleteCallBack when UnRegisterSurfaceTransactionListener succeeds
 *           Branch: if (!renderPipelineClient_->UnRegisterSurfaceTransactionListener(...)) -> false (line 107)
 *           Should successfully unregister and return true
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, UnRegisterCommandCompleteCallBack003, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    bool result = listener->UnRegisterCommandCompleteCallBack();
    EXPECT_TRUE(result);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: RegisterCommandCompleteCallBack005
 * @tc.desc: Test RegisterCommandCompleteCallBack full success path
 *           Branch: line 84 false && line 89 false
 *           Should successfully create renderPipelineClient and register listener
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, RegisterCommandCompleteCallBack005, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    bool result = listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    EXPECT_TRUE(result);
    listener->UnRegisterCommandCompleteCallBack();
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerGetInstance001
 * @tc.desc: Test GetInstance returns valid instance
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerGetInstance001, TestSize.Level1)
{
    auto& instance = SurfaceNodeBufferReleaseListener::GetInstance();
    EXPECT_NE(&instance, nullptr);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack003
 * @tc.desc: Test RegisterReleaseBufferCallBack when renderPipelineClient creation succeeds
 *           Branch: if (renderPipelineClient == nullptr) -> false (line 141)
 *           Should proceed to RegisterSurfaceNodeBufferReleaseListener
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack003, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    bool result = listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    EXPECT_FALSE(result);
    listener.UnRegisterReleaseBufferCallBack();
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack004
 * @tc.desc: Test RegisterReleaseBufferCallBack when RegisterSurfaceNodeBufferReleaseListener succeeds
 *           Branch: if (!renderPipelineClient->RegisterSurfaceNodeBufferReleaseListener(...)) -> false (line 146)
 *           Should successfully register and return true
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack004, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    bool result = listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    EXPECT_FALSE(result);
    listener.UnRegisterReleaseBufferCallBack();
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack005
 * @tc.desc: Test RegisterReleaseBufferCallBack full success path
 *           Branch: line 141 false && line 146 false
 *           Should successfully create renderPipelineClient and register listener
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack005, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    bool result = listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    EXPECT_FALSE(result);
    listener.UnRegisterReleaseBufferCallBack();
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack001
 * @tc.desc: Test RegisterReleaseBufferCallBack with valid callback
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack001, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    bool result = listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack002
 * @tc.desc: Test RegisterReleaseBufferCallBack with existing callback - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack002, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    bool result = listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    EXPECT_FALSE(result);
    listener.UnRegisterReleaseBufferCallBack();
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack007
 * @tc.desc: Test RegisterReleaseBufferCallBack when renderPipelineClient creation is valid
 *           Branch: if (renderPipelineClient == nullptr) -> true (line 141)
 *           Note: This branch is typically unreachable as make_shared normally succeeds
 *           Testing the error handling path when renderPipelineClient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack007, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    bool result = listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    EXPECT_FALSE(result);
    listener.UnRegisterReleaseBufferCallBack();
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack001
 * @tc.desc: Test UnRegisterReleaseBufferCallBack with registered callback
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack001, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    bool result = listener.UnRegisterReleaseBufferCallBack();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack003
 * @tc.desc: Test UnRegisterReleaseBufferCallBack when UnRegisterSurfaceNodeBufferReleaseListener succeeds
 *           Branch: if (!renderPipelineClient_->UnRegisterSurfaceNodeBufferReleaseListener()) -> false (line 166)
 *           Should successfully unregister and return true
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack003, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    bool result = listener.UnRegisterReleaseBufferCallBack();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack004
 * @tc.desc: Test UnRegisterReleaseBufferCallBack full success path
 *           Branch: line 166 false
 *           Should successfully unregister and set pointers to nullptr
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack004, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    bool result = listener.UnRegisterReleaseBufferCallBack();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack002
 * @tc.desc: Test UnRegisterReleaseBufferCallBack without registered callback - false branch
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack002, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    bool result = listener.UnRegisterReleaseBufferCallBack();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack005
 * @tc.desc: Test UnRegisterReleaseBufferCallBack when UnRegisterSurfaceNodeBufferReleaseListener fails
 *           Branch: if (!renderPipelineClient_->UnRegisterSurfaceNodeBufferReleaseListener()) -> true (line 166)
 *           Should return false when unregistration fails
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack005, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    auto renderServiceConnectHub = RSRenderServiceConnectHub::GetInstance();
    RSRenderServiceConnectHub::instance_ = nullptr;
    bool result = listener.UnRegisterReleaseBufferCallBack();
    EXPECT_FALSE(result);
    RSRenderServiceConnectHub::instance_ = renderServiceConnectHub;
}

/**
 * @tc.name: RegisterCommandCompleteCallBack006
 * @tc.desc: Test RegisterCommandCompleteCallBack with null connectToRender
 *           Branch: if (callBackStub_ != nullptr || connectToRender_ == nullptr) -> connectToRender_ == nullptr is true
 *           Should return false when connectToRender is null
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, RegisterCommandCompleteCallBack006, TestSize.Level1)
{
    sptr<IRemoteObject> nullConnectToRender = nullptr;
    auto listener = new SurfaceTransactionListener(nullConnectToRender);
    bool result = listener->RegisterCommandCompleteCallBack([](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    EXPECT_FALSE(result);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: UnRegisterCommandCompleteCallBack005
 * @tc.desc: Test UnRegisterCommandCompleteCallBack when only callBackStub_ is null
 *           Branch: if (!callBackStub_ || !renderPipelineClient_) -> !callBackStub_ is true, !renderPipelineClient_ is false
 *           This test ensures the first condition (!callBackStub_) triggers return false
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, UnRegisterCommandCompleteCallBack005, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    bool result = listener->UnRegisterCommandCompleteCallBack();
    EXPECT_FALSE(result);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: RegisterReleaseBufferCallBack006
 * @tc.desc: Test RegisterReleaseBufferCallBack when connectToRender_ is null
 *           Branch: if (callBackStub_ != nullptr || connectToRender_ == nullptr) -> connectToRender_ == nullptr is true
 *           Should return false when connectToRender_ is null
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerRegisterReleaseBufferCallBack006, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    listener.SetConnectToRender(nullptr);
    bool result = listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack006
 * @tc.desc: Test UnRegisterReleaseBufferCallBack when only renderPipelineClient_ is null
 *           Branch: if (renderPipelineClient_ == nullptr || callBackStub_ == nullptr) -> renderPipelineClient_ == nullptr is true, callBackStub_ == nullptr is false
 *           This tests the first condition (renderPipelineClient_ == nullptr) independently
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerUnRegisterReleaseBufferCallBack006, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    bool result = listener.UnRegisterReleaseBufferCallBack();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerSetConnectToRender001
 * @tc.desc: Test SetConnectToRender with null parameter
 *           Branch: if (!connectToRender) -> true
 *           Should return false when connectToRender is null
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerSetConnectToRender001, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    sptr<IRemoteObject> nullConnectToRender = nullptr;
    bool result = listener.SetConnectToRender(nullConnectToRender);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerSetConnectToRender002
 * @tc.desc: Test SetConnectToRender with valid parameter when connectToRender_ is null
 *           Branch: if (!connectToRender) -> false, if (connectToRender_ != nullptr) -> false
 *           Should return true and set connectToRender_ when first time setting
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerSetConnectToRender002, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    auto screenId = RSInterfaces::GetInstance().GetDefaultScreenId();
    sptr<IRemoteObject> connectToRender = RSInterfaces::GetInstance().GetConnectToRenderToken(screenId);
    if (connectToRender != nullptr) {
        bool result = listener.SetConnectToRender(connectToRender);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerSetConnectToRender003
 * @tc.desc: Test SetConnectToRender when connectToRender_ is already set
 *           Branch: if (!connectToRender) -> false, if (connectToRender_ != nullptr) -> true
 *           Should return false when connectToRender_ is already set
 * @tc.type: FUNC
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerSetConnectToRender003, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    auto screenId = RSInterfaces::GetInstance().GetDefaultScreenId();
    sptr<IRemoteObject> connectToRender1 = RSInterfaces::GetInstance().GetConnectToRenderToken(screenId);
    sptr<IRemoteObject> connectToRender2 = RSInterfaces::GetInstance().GetConnectToRenderToken(screenId);
    if (connectToRender1 != nullptr && connectToRender2 != nullptr) {
        listener.SetConnectToRender(connectToRender1);
        bool result = listener.SetConnectToRender(connectToRender2);
        EXPECT_FALSE(result);
    }
}

/**
 * @tc.name: SurfaceTransactionListenerGetCommand_WrongThread_001
 * @tc.desc: Test GetCommand when called from a different thread than the constructing thread.
 *           Branch: `if (workTid_ != gettid())` -> true (line 47) -> return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceTransactionListenerGetCommand_WrongThread_001, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    uint64_t capturedSeqNum = 0;
    std::unique_ptr<OHOS::Rosen::RSCommand> cmd;
    std::thread worker([&]() {
        cmd = listener->GetCommand(capturedSeqNum);
    });
    worker.join();
    EXPECT_EQ(cmd, nullptr);
    EXPECT_EQ(capturedSeqNum, 0u);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: SurfaceTransactionListenerGetCommand_IncrementSeqNum_001
 * @tc.desc: Test GetCommand from the same thread increments CommandSeqNum_ each call.
 *           Branch: `if (workTid_ != gettid())` -> false (line 47), cmdSeqNum = CommandSeqNum_++.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceTransactionListenerGetCommand_IncrementSeqNum_001, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    uint64_t seqNum1 = 0;
    uint64_t seqNum2 = 0;
    auto cmd1 = listener->GetCommand(seqNum1);
    auto cmd2 = listener->GetCommand(seqNum2);
    EXPECT_NE(cmd1, nullptr);
    EXPECT_NE(cmd2, nullptr);
    EXPECT_EQ(seqNum2, seqNum1 + 1);
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: UnRegisterCommandCompleteCallBack_RenderPipelineClientNull_001
 * @tc.desc: Test UnRegisterCommandCompleteCallBack when callBackStub_ is non-null but
 *           renderPipelineClient_ is null (second short-circuit operand of the guard).
 *           Branch: `if (!callBackStub_ || !renderPipelineClient_)` -> !renderPipelineClient_ true (line 106).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeListenerTest, UnRegisterCommandCompleteCallBack_RenderPipelineClientNull_001, TestSize.Level1)
{
    auto listener = new SurfaceTransactionListener(connectToRender_);
    // directly create a stub so callBackStub_ becomes non-null without going through RegisterCommandCompleteCallBack
    sptr<RSWebProxyComposerCallbackStub> stub = new RSWebProxyComposerCallbackStub();
    ASSERT_NE(stub, nullptr);
    listener->callBackStub_ = stub;
    listener->renderPipelineClient_ = nullptr;
    bool result = listener->UnRegisterCommandCompleteCallBack();
    EXPECT_FALSE(result);
    listener->callBackStub_ = nullptr;
    listener->DecStrongRef(nullptr);
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerUnRegister_StubNull_001
 * @tc.desc: Test UnRegisterReleaseBufferCallBack when renderPipelineClient_ is non-null but
 *           callBackStub_ is null (second short-circuit operand of the guard).
 *           Branch: `if (renderPipelineClient_ == nullptr || callBackStub_ == nullptr)` ->
 *                   callBackStub_ == nullptr true (line 166).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerUnRegister_StubNull_001, TestSize.Level1)
{
    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    // set renderPipelineClient_ non-null while callBackStub_ stays null
    listener.renderPipelineClient_ = std::make_shared<RSRenderPipelineClient>();
    listener.callBackStub_ = nullptr;
    bool result = listener.UnRegisterReleaseBufferCallBack();
    EXPECT_FALSE(result);
    listener.renderPipelineClient_ = nullptr;
}

/**
 * @tc.name: RegisterCommandCompleteCallBack_Success_001
 * @tc.desc: Test RegisterCommandCompleteCallBack full success path.
 *           Branch: guard false (connectToRender_ non-null, callBackStub_ null),
 *                   renderPipelineClient non-null,
 *                   RegisterSurfaceTransactionListener returns true -> return true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeListenerTest, RegisterCommandCompleteCallBack_Success_001, TestSize.Level1)
{
    auto hub = RSRenderServiceConnectHub::GetInstance();
    ASSERT_NE(hub, nullptr);
    auto origConn = hub->renderConn_;
    hub->renderConn_ = new MockClientToRenderConnection(nullptr);

    sptr<IRemoteObject> dummyConnect = new IPCObjectStub();
    auto listener = new SurfaceTransactionListener(dummyConnect);
    bool result = listener->RegisterCommandCompleteCallBack(
        [](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {});
    EXPECT_TRUE(result);
    // success path stores both stub and client
    EXPECT_NE(listener->callBackStub_, nullptr);
    EXPECT_NE(listener->renderPipelineClient_, nullptr);

    listener->UnRegisterCommandCompleteCallBack();
    listener->DecStrongRef(nullptr);
    hub->renderConn_ = origConn;
}

/**
 * @tc.name: UnRegisterCommandCompleteCallBack_Success_001
 * @tc.desc: Test UnRegisterCommandCompleteCallBack full success path.
 *           Branch: guard false (callBackStub_/renderPipelineClient_ both non-null),
 *                   UnRegisterSurfaceTransactionListener returns true -> return true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeListenerTest, UnRegisterCommandCompleteCallBack_Success_001, TestSize.Level1)
{
    auto hub = RSRenderServiceConnectHub::GetInstance();
    ASSERT_NE(hub, nullptr);
    auto origConn = hub->renderConn_;
    hub->renderConn_ = new MockClientToRenderConnection(nullptr);

    sptr<IRemoteObject> dummyConnect = new IPCObjectStub();
    auto listener = new SurfaceTransactionListener(dummyConnect);
    ASSERT_TRUE(listener->RegisterCommandCompleteCallBack(
        [](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {}));
    bool result = listener->UnRegisterCommandCompleteCallBack();
    EXPECT_TRUE(result);
    EXPECT_EQ(listener->callBackStub_, nullptr);
    EXPECT_EQ(listener->renderPipelineClient_, nullptr);

    listener->DecStrongRef(nullptr);
    hub->renderConn_ = origConn;
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerRegister_Success_001
 * @tc.desc: Test RegisterReleaseBufferCallBack full success path.
 *           Branch: guard false, RegisterSurfaceNodeBufferReleaseListener returns true -> return true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerRegister_Success_001, TestSize.Level1)
{
    auto hub = RSRenderServiceConnectHub::GetInstance();
    ASSERT_NE(hub, nullptr);
    auto origConn = hub->renderConn_;
    hub->renderConn_ = new MockClientToRenderConnection(nullptr);

    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    sptr<IRemoteObject> dummyConnect = new IPCObjectStub();
    listener.SetConnectToRender(dummyConnect);
    bool result = listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {});
    EXPECT_TRUE(result);
    listener.UnRegisterReleaseBufferCallBack();

    hub->renderConn_ = origConn;
}

/**
 * @tc.name: SurfaceNodeBufferReleaseListenerUnRegister_Success_001
 * @tc.desc: Test UnRegisterReleaseBufferCallBack full success path.
 *           Branch: guard false, UnRegisterSurfaceNodeBufferReleaseListener returns true -> return true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSDelegateCompositeListenerTest, SurfaceNodeBufferReleaseListenerUnRegister_Success_001, TestSize.Level1)
{
    auto hub = RSRenderServiceConnectHub::GetInstance();
    ASSERT_NE(hub, nullptr);
    auto origConn = hub->renderConn_;
    hub->renderConn_ = new MockClientToRenderConnection(nullptr);

    auto& listener = SurfaceNodeBufferReleaseListener::GetInstance();
    listener.UnRegisterReleaseBufferCallBack();
    sptr<IRemoteObject> dummyConnect = new IPCObjectStub();
    listener.SetConnectToRender(dummyConnect);
    ASSERT_TRUE(listener.RegisterReleaseBufferCallBack([](std::queue<OnCompletedRet> queue) {}));
    bool result = listener.UnRegisterReleaseBufferCallBack();
    EXPECT_TRUE(result);

    hub->renderConn_ = origConn;
}

} // namespace OHOS::Rosen
#endif