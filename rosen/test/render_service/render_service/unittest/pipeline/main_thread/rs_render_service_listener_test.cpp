/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <memory>
#include "gtest/gtest.h"
#include "limit_number.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/main_thread/rs_render_service_listener.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_test_util.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSRenderServiceListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderServiceListenerTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}
void RSRenderServiceListenerTest::TearDownTestCase() {}
void RSRenderServiceListenerTest::SetUp() {}
void RSRenderServiceListenerTest::TearDown() {}

/**
 * @tc.name: CreateAndDestroy001
 * @tc.desc: Create listener with RSSurfaceRenderNode.
 * @tc.type: FUNC
 * @tc.require:issueI590LM
 */
HWTEST_F(RSRenderServiceListenerTest, CreateAndDestroy001, TestSize.Level1)
{
    NodeId id = 5;
    RSSurfaceRenderNodeConfig config;
    config.id = id;
    config.name = std::to_string(id);
    auto rsSurfaceRenderNode = std::make_shared<RSSurfaceRenderNode>(config);
    auto surfaceHandler(rsSurfaceRenderNode->GetRSSurfaceHandler());
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(rsSurfaceRenderNode, surfaceHandler, nullptr);
    ASSERT_NE(rsListener, nullptr);
}

/**
 * @tc.name: OnTunnelHandleChange001
 * @tc.desc: Test OnTunnelHandleChange of invalid and valid listener.
 * @tc.type: FUNC
 * @tc.require: issueI5X0TR
 */
HWTEST_F(RSRenderServiceListenerTest, OnTunnelHandleChange001, TestSize.Level1)
{
    // nullptr test and early return
    NodeId id = 5;
    RSSurfaceRenderNodeConfig config;
    config.id = id;
    config.name = std::to_string(id);
    auto rsSurfaceRenderNode = std::make_shared<RSSurfaceRenderNode>(config);
    auto surfaceHandler(rsSurfaceRenderNode->GetRSSurfaceHandler());
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(rsSurfaceRenderNode, surfaceHandler, nullptr);
    rsListener->OnTunnelHandleChange();

    std::shared_ptr<RSSurfaceRenderNode> node = RSTestUtil::CreateSurfaceNode();
    rsListener = std::make_shared<RSRenderServiceListener>(node, surfaceHandler, nullptr);
    rsListener->OnTunnelHandleChange();
    ASSERT_EQ(node->GetTunnelHandleChange(), true);
}

/**
 * @tc.name: OnCleanCache001
 * @tc.desc: Test OnCleanCache of invalid and valid listener.
 * @tc.type: FUNC
 * @tc.require: issueI5X0TR
 */
HWTEST_F(RSRenderServiceListenerTest, OnCleanCache001, TestSize.Level1)
{
    // nullptr test and early return
    NodeId id = 5;
    RSSurfaceRenderNodeConfig config;
    config.id = id;
    config.name = std::to_string(id);
    auto rsSurfaceRenderNode = std::make_shared<RSSurfaceRenderNode>(config);
    auto surfaceHandler(rsSurfaceRenderNode->GetRSSurfaceHandler());

    auto clientComposer = std::make_shared<RSComposerClientManager>();
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(rsSurfaceRenderNode, surfaceHandler, clientComposer);
    uint32_t bufSeqNum = 0;
    rsListener->OnCleanCache(&bufSeqNum);

    std::shared_ptr<RSSurfaceRenderNode> node = RSTestUtil::CreateSurfaceNode();
    rsListener = std::make_shared<RSRenderServiceListener>(node, surfaceHandler, clientComposer);
    rsListener->OnCleanCache(&bufSeqNum);
    ASSERT_EQ(node->GetRSSurfaceHandler()->GetAvailableBufferCount(), 0);
    ASSERT_TRUE(bufSeqNum >= 0);
}

/**
 * @tc.name: OnBufferAvailable001
 * @tc.desc: Test OnBufferAvailable of invalid and valid listener.
 * @tc.type: FUNC
 * @tc.require: issueI590LM
 */
HWTEST_F(RSRenderServiceListenerTest, OnBufferAvailable001, TestSize.Level1)
{
    RSMainThread::Instance()->composerClientManager_ = std::make_shared<RSComposerClientManager>();
    // nullptr test and early return
    std::shared_ptr<RSSurfaceRenderNode> rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    auto surfaceHandler(rsSurfaceRenderNode->GetRSSurfaceHandler());
    std::shared_ptr<RSRenderServiceListener> rsListener = std::make_shared<RSRenderServiceListener>(
        rsSurfaceRenderNode, surfaceHandler, std::make_shared<RSComposerClientManager>());
    rsListener->OnBufferAvailable();

    rsListener = std::make_shared<RSRenderServiceListener>(
        rsSurfaceRenderNode, surfaceHandler, std::make_shared<RSComposerClientManager>());
    rsSurfaceRenderNode->SetIsNotifyUIBufferAvailable(false);
    rsListener->OnBufferAvailable();
    ASSERT_EQ(rsSurfaceRenderNode->IsNotifyUIBufferAvailable(), true);

    rsSurfaceRenderNode->SetIsNotifyUIBufferAvailable(true);
    rsListener->OnBufferAvailable();
    ASSERT_EQ(rsSurfaceRenderNode->IsNotifyUIBufferAvailable(), true);
}

/**
 * @tc.name: OnForceRefresh001
 * @tc.desc: Test OnForceRefresh001 of invalid and valid listener.
 * @tc.type: FUNC
 * @tc.require: #IC3LEU
 */
HWTEST_F(RSRenderServiceListenerTest, OnForceRefresh001, TestSize.Level1)
{
    // nullptr test and early return
    std::shared_ptr<RSSurfaceRenderNode> rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    auto surfaceHandler(rsSurfaceRenderNode->GetRSSurfaceHandler());
    std::shared_ptr<RSRenderServiceListener> rsListener = std::make_shared<RSRenderServiceListener>(
        rsSurfaceRenderNode, surfaceHandler, std::make_shared<RSComposerClientManager>());
    rsListener->OnBufferAvailable();

    rsListener = std::make_shared<RSRenderServiceListener>(
        rsSurfaceRenderNode, surfaceHandler, std::make_shared<RSComposerClientManager>());
    rsSurfaceRenderNode->SetAncoFlags(static_cast<uint32_t>(AncoFlags::FORCE_REFRESH));
    rsListener->OnBufferAvailable();
    ASSERT_EQ(rsSurfaceRenderNode->GetAncoFlags(), 0);
}

/**
 * @tc.name: SetBufferInfoAndRequest001
 * @tc.desc: Test SetBufferInfoAndRequest
 * @tc.type: FUNC
 * @tc.require: issue20841
 */
HWTEST_F(RSRenderServiceListenerTest, SetBufferInfoAndRequest001, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    auto surfaceHandler(rsSurfaceRenderNode->GetRSSurfaceHandler());
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(rsSurfaceRenderNode, surfaceHandler, nullptr);
    std::shared_ptr<RSSurfaceRenderNode> node = RSTestUtil::CreateSurfaceNode();
    NodeId id = 0;
    std::shared_ptr<RSSurfaceHandler> handler = std::make_shared<RSSurfaceHandler>(id);
    rsListener->SetBufferInfoAndRequest(handler, handler->GetConsumer(), true);
    ASSERT_EQ(rsSurfaceRenderNode->GetAncoFlags(), 0);
    rsListener->SetBufferInfoAndRequest(handler, handler->GetConsumer(), false);
    ASSERT_EQ(rsSurfaceRenderNode->GetAncoFlags(), 0);
}

/**
 * @tc.name: OnDropBuffer001
 * @tc.desc: Test OnDropBuffer when node is nullptr, should early return without crash.
 * @tc.type: FUNC
 * @tc.require: issue23825
 */
HWTEST_F(RSRenderServiceListenerTest, OnDropBuffer001, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    auto surfaceHandler(rsSurfaceRenderNode->GetRSSurfaceHandler());
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(rsSurfaceRenderNode, surfaceHandler, nullptr);
    rsListener->OnDropBuffer();
    ASSERT_NE(rsListener, nullptr);
}

/**
 * @tc.name: OnDropBuffer002
 * @tc.desc: Test OnDropBuffer when node is valid, should set BufferDropped to true.
 * @tc.type: FUNC
 * @tc.require: issue23825
 */
HWTEST_F(RSRenderServiceListenerTest, OnDropBuffer002, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    auto surfaceHandler(rsSurfaceRenderNode->GetRSSurfaceHandler());
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(rsSurfaceRenderNode, surfaceHandler, nullptr);
    ASSERT_NE(rsSurfaceRenderNode->GetRSSurfaceHandler(), nullptr);
    rsSurfaceRenderNode->GetRSSurfaceHandler()->SetBufferDropped(false);
    ASSERT_FALSE(rsSurfaceRenderNode->GetRSSurfaceHandler()->GetBufferDropped());
    rsListener->OnDropBuffer();
    ASSERT_TRUE(rsSurfaceRenderNode->GetRSSurfaceHandler()->GetBufferDropped());
}

/**
 * @tc.name: OnTunnelLayerInfoChanged001
 * @tc.desc: Test OnTunnelLayerInfoChanged with null node, should early return without crash.
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderServiceListenerTest, OnTunnelLayerInfoChanged001, TestSize.Level1)
{
    std::weak_ptr<RSSurfaceRenderNode> wp;
    std::weak_ptr<RSSurfaceHandler> sh;
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(wp, sh, nullptr);
    TunnelLayerState state;
    state.tunnelLayerId = 1001;
    state.property = TUNNEL_PROP_BUFFER_ADDR;
    rsListener->OnTunnelLayerInfoChanged(state);
    ASSERT_NE(rsListener, nullptr);
}

/**
 * @tc.name: OnTunnelLayerInfoChanged002
 * @tc.desc: Test OnTunnelLayerInfoChanged stores layer info in RSTunnelRuntimeStore and requests VSync.
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderServiceListenerTest, OnTunnelLayerInfoChanged002, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(node, nullptr);
    auto surfaceHandler = node->GetRSSurfaceHandler();
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(node, surfaceHandler, nullptr);

    constexpr uint64_t testTunnelLayerId = 2001;
    constexpr uint32_t testProperty = TUNNEL_PROP_BUFFER_ADDR | TUNNEL_PROP_DEVICE_COMMIT;
    TunnelLayerState state;
    state.tunnelLayerId = testTunnelLayerId;
    state.property = static_cast<TunnelLayerProperty>(testProperty);

    rsListener->OnTunnelLayerInfoChanged(state);

    uint64_t storedTunnelLayerId = 0;
    uint32_t storedProperty = TUNNEL_PROP_INVALID;
    RSTunnelRuntimeStore::GetLayerInfoOrDefault(node->GetId(), storedTunnelLayerId, storedProperty);
    EXPECT_EQ(storedTunnelLayerId, testTunnelLayerId);
    EXPECT_EQ(storedProperty, testProperty);

    RSTunnelRuntimeStore::Erase(node->GetId());
}

/**
 * @tc.name: OnTunnelLayerInfoChanged003
 * @tc.desc: Test OnTunnelLayerInfoChanged with zero tunnelLayerId resets stored info.
 * @tc.type: FUNC
 */
HWTEST_F(RSRenderServiceListenerTest, OnTunnelLayerInfoChanged003, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> node = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(node, nullptr);
    auto surfaceHandler = node->GetRSSurfaceHandler();
    std::shared_ptr<RSRenderServiceListener> rsListener =
        std::make_shared<RSRenderServiceListener>(node, surfaceHandler, nullptr);

    constexpr uint64_t initialTunnelLayerId = 3001;
    constexpr uint32_t initialProperty = TUNNEL_PROP_BUFFER_ADDR;
    RSTunnelRuntimeStore::SetLayerInfo(node->GetId(), initialTunnelLayerId, initialProperty);

    TunnelLayerState state;
    state.tunnelLayerId = 0;
    state.property = TUNNEL_PROP_INVALID;
    rsListener->OnTunnelLayerInfoChanged(state);

    uint64_t storedTunnelLayerId = 0;
    uint32_t storedProperty = TUNNEL_PROP_INVALID;
    RSTunnelRuntimeStore::GetLayerInfoOrDefault(node->GetId(), storedTunnelLayerId, storedProperty);
    EXPECT_EQ(storedTunnelLayerId, 0u);
    EXPECT_EQ(storedProperty, TUNNEL_PROP_INVALID);

    RSTunnelRuntimeStore::Erase(node->GetId());
}
} // namespace OHOS::Rosen
