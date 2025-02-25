/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "feature/anco_manager/rs_anco_manager.h"
#include "feature/mock/mock_anco_manager.h"
#include "gtest/gtest.h"
#include "parameters.h"
#include "params/rs_surface_render_params.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSAncoManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSAncoManagerTest::SetUpTestCase() {}
void RSAncoManagerTest::TearDownTestCase() {}
void RSAncoManagerTest::SetUp() {}
void RSAncoManagerTest::TearDown() {}

/**
 * @tc.name: AncoOptimizeDisplayNode
 * @tc.desc: test AncoOptimizeDisplayNode
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, IsAncoOptimize, TestSize.Level2)
{
    auto ancoManager = RSAncoManager::Instance();
    ASSERT_NE(ancoManager, nullptr);

    RSSurfaceRenderNode::SetAncoForceDoDirect(false);
    ASSERT_EQ(ancoManager->IsAncoOptimize(ScreenRotation::ROTATION_0), false);
}

/**
 * @tc.name: AncoOptimizeDisplayNode
 * @tc.desc: test AncoOptimizeDisplayNode
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, AncoOptimizeDisplayNode_01, TestSize.Level2)
{
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes;
    std::shared_ptr<RSSurfaceHandler> surfaceHandler = nullptr;
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();

    sptr<SyncFence> fence = SyncFence::InvalidFence();

    std::unique_ptr<Mock::MockRSAncoManager> mock = std::make_unique<Mock::MockRSAncoManager>();
    EXPECT_CALL(*mock, IsAncoOptimize(_)).WillRepeatedly(testing::Return(true));

    ASSERT_EQ(mock->AncoOptimizeDisplayNode(surfaceHandler, hardwareEnabledNodes,
        ScreenRotation::ROTATION_90, 0, 0), false);
}

/**
 * @tc.name: AncoOptimizeDisplayNode
 * @tc.desc: test AncoOptimizeDisplayNode
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, AncoOptimizeDisplayNode_02, TestSize.Level2)
{
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes;
    std::shared_ptr<RSSurfaceHandler> surfaceHandler = std::make_shared<RSSurfaceHandler>(0);
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();

    sptr<SyncFence> fence = SyncFence::InvalidFence();
    Rect damage = {10, 10, 100, 100};
    int64_t timestamp = 0;
    surfaceHandler->SetBuffer(surfaceBuffer, fence, damage, timestamp);

    std::unique_ptr<Mock::MockRSAncoManager> mock = std::make_unique<Mock::MockRSAncoManager>();
    EXPECT_CALL(*mock, IsAncoOptimize(_)).WillRepeatedly(testing::Return(true));
    ASSERT_NE(surfaceHandler->GetBuffer(), nullptr);

    ASSERT_EQ(mock->AncoOptimizeDisplayNode(surfaceHandler, hardwareEnabledNodes,
        ScreenRotation::ROTATION_90, 0, 0), false);
}

/**
 * @tc.name: AncoOptimizeDisplayNode
 * @tc.desc: test AncoOptimizeDisplayNode
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, AncoOptimizeDisplayNode_03, TestSize.Level2)
{
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes;
    std::shared_ptr<RSSurfaceHandler> surfaceHandler = std::make_shared<RSSurfaceHandler>(0);
    ASSERT_NE(surfaceHandler, nullptr);
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();

    sptr<SyncFence> fence = SyncFence::InvalidFence();
    
    std::unique_ptr<Mock::MockRSAncoManager> mock = std::make_unique<Mock::MockRSAncoManager>();
    EXPECT_CALL(*mock, IsAncoOptimize(_)).WillRepeatedly(testing::Return(true));
    ASSERT_EQ(surfaceHandler->GetBuffer(), nullptr);

    ASSERT_EQ(mock->AncoOptimizeDisplayNode(surfaceHandler, hardwareEnabledNodes,
        ScreenRotation::ROTATION_90, 1260, 2720), false);
}

/**
 * @tc.name: AncoOptimizeDisplayNode
 * @tc.desc: test AncoOptimizeDisplayNode
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, AncoOptimizeDisplayNode_04, TestSize.Level2)
{
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes;
    std::shared_ptr<RSSurfaceHandler> surfaceHandler = std::make_shared<RSSurfaceHandler>(0);
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();

    sptr<SyncFence> fence = SyncFence::InvalidFence();
    Rect damage = {10, 10, 100, 100};
    int64_t timestamp = 0;
    surfaceHandler->SetBuffer(surfaceBuffer, fence, damage, timestamp);
    
    std::unique_ptr<Mock::MockRSAncoManager> mock = std::make_unique<Mock::MockRSAncoManager>();
    EXPECT_CALL(*mock, IsAncoOptimize(_)).WillRepeatedly(testing::Return(true));
    ASSERT_NE(surfaceHandler->GetBuffer(), nullptr);

    NodeId id = 1;
    RSSurfaceNodeType type = RSSurfaceNodeType::DEFAULT;
    RSSurfaceRenderNodeConfig config = { .id = id, .nodeType = type };
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config);
    surfaceNode1->SetAncoFlags(0);
    EXPECT_EQ(surfaceNode1->GetAncoFlags(), 0);

    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config);
    EXPECT_NE(surfaceNode2, nullptr);
    surfaceNode2->SetAncoFlags(static_cast<uint32_t>(AncoFlags::IS_ANCO_NODE));
    surfaceNode2->SetGlobalAlpha(0.0f);
    surfaceNode2->GetRSSurfaceHandler()->SetBuffer(surfaceBuffer, fence, damage, timestamp);
    EXPECT_EQ(surfaceNode2->GetAncoFlags(), 1);

    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(config);
    surfaceNode3->SetAncoFlags(static_cast<uint32_t>(AncoFlags::IS_ANCO_NODE));
    surfaceNode3->SetGlobalAlpha(1.8f);
    surfaceNode3->GetRSSurfaceHandler()->SetBuffer(surfaceBuffer, fence, damage, timestamp);
    surfaceNode3->InitRenderParams();
    EXPECT_EQ(surfaceNode3->GetAncoFlags(), 1);

    hardwareEnabledNodes.push_back(surfaceNode1);
    hardwareEnabledNodes.push_back(surfaceNode2);
    hardwareEnabledNodes.push_back(surfaceNode3);

    ASSERT_EQ(mock->AncoOptimizeDisplayNode(surfaceHandler, hardwareEnabledNodes,
              ScreenRotation::ROTATION_90, 1260, 2720), true);
}

/**
 * @tc.name: AncoOptimizeDisplayNode
 * @tc.desc: test AncoOptimizeDisplayNode
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, AncoOptimizeDisplayNode_05, TestSize.Level2)
{
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes;
    std::shared_ptr<RSSurfaceHandler> surfaceHandler = std::make_shared<RSSurfaceHandler>(0);
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();

    sptr<SyncFence> fence = SyncFence::InvalidFence();
    Rect damage = {10, 10, 100, 100};
    int64_t timestamp = 0;
    surfaceHandler->SetBuffer(surfaceBuffer, fence, damage, timestamp);

    std::unique_ptr<Mock::MockRSAncoManager> mock = std::make_unique<Mock::MockRSAncoManager>();
    EXPECT_CALL(*mock, IsAncoOptimize(_)).WillRepeatedly(testing::Return(true));
    ASSERT_NE(surfaceHandler->GetBuffer(), nullptr);

    NodeId id = 1;
    RSSurfaceNodeType type = RSSurfaceNodeType::DEFAULT;
    RSSurfaceRenderNodeConfig config = { .id = id, .nodeType = type };
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config);
    surfaceNode1->SetAncoFlags(0);
    EXPECT_EQ(surfaceNode1->GetAncoFlags(), 0);

    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config);
    EXPECT_NE(surfaceNode2, nullptr);
    surfaceNode2->SetAncoFlags(static_cast<uint32_t>(AncoFlags::IS_ANCO_NODE));
    surfaceNode2->SetGlobalAlpha(0.0f);
    surfaceNode2->GetRSSurfaceHandler()->SetBuffer(surfaceBuffer, fence, damage, timestamp);
    EXPECT_EQ(surfaceNode2->GetAncoFlags(), 1);

    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(config);
    surfaceNode3->SetAncoFlags(static_cast<uint32_t>(AncoFlags::IS_ANCO_NODE));
    surfaceNode3->SetGlobalAlpha(1.8f);
    surfaceNode3->GetRSSurfaceHandler()->SetBuffer(surfaceBuffer, fence, damage, timestamp);
    EXPECT_EQ(surfaceNode3->GetAncoFlags(), 1);

    hardwareEnabledNodes.push_back(surfaceNode1);
    hardwareEnabledNodes.push_back(surfaceNode2);
    hardwareEnabledNodes.push_back(surfaceNode3);

    ASSERT_EQ(mock->AncoOptimizeDisplayNode(surfaceHandler, hardwareEnabledNodes,
              ScreenRotation::ROTATION_90, 1260, 2720), true);
}

/**
 * @tc.name: AncoOptimizeDisplayNode
 * @tc.desc: test AncoOptimizeDisplayNode
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, AncoOptimizeDisplayNode_06, TestSize.Level2)
{
    auto ancoManager = RSAncoManager::Instance();
    ASSERT_NE(ancoManager, nullptr);
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes;
    std::shared_ptr<RSSurfaceHandler> surfaceHandler = nullptr;
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();

    sptr<SyncFence> fence = SyncFence::InvalidFence();
    ASSERT_EQ(ancoManager->AncoOptimizeDisplayNode(surfaceHandler, hardwareEnabledNodes,
        ScreenRotation::ROTATION_90, 0, 0), false);
}

/**
 * @tc.name: SetAncoHebcStatus
 * @tc.desc: test SetAncoHebcStatus
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, SetAncoHebcStatus, TestSize.Level2)
{
    auto hebc = system::GetParameter("persist.sys.graphic.anco.disableHebc", "0");
    system::SetParameter("persist.sys.graphic.anco.disableHebc", "1");
    auto ancoManager = RSAncoManager::Instance();
    ASSERT_NE(ancoManager, nullptr);
    ancoManager->SetAncoHebcStatus(AncoHebcStatus::INITIAL);
    ASSERT_EQ(ancoManager->GetAncoHebcStatus(), AncoHebcStatus::INITIAL);
    system::SetParameter("persist.sys.graphic.anco.disableHebc", hebc);
}

/**
 * @tc.name: GetAncoHebcStatus
 * @tc.desc: test GetAncoHebcStatus
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, GetAncoHebcStatus, TestSize.Level2)
{
    auto ancoManager = RSAncoManager::Instance();
    ASSERT_NE(ancoManager, nullptr);
    ancoManager->SetAncoHebcStatus(AncoHebcStatus::INITIAL);
    ASSERT_EQ(ancoManager->GetAncoHebcStatus(), AncoHebcStatus::INITIAL);
}

/**
 * @tc.name: AncoOptimizeCheck
 * @tc.desc: test AncoOptimizeCheck
 * @tc.type: FUNC
 * @tc.require: issueIARZ3Q
 */
HWTEST_F(RSAncoManagerTest, AncoOptimizeCheck, TestSize.Level2)
{
    auto ancoManager = RSAncoManager::Instance();
    ASSERT_NE(ancoManager, nullptr);
    ASSERT_EQ(ancoManager->AncoOptimizeCheck(true, 3, 2), true);
    ASSERT_EQ(ancoManager->AncoOptimizeCheck(true, 4, 2), false);
    ASSERT_EQ(ancoManager->AncoOptimizeCheck(false, 3, 2), false);
    ASSERT_EQ(ancoManager->AncoOptimizeCheck(false, 4, 2), true);
}
} // namespace OHOS::Rosen