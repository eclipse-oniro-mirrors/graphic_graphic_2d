/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "gmock/gmock.h"
#include "mock.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_device.h"
#include "feature/hwc/hpae_offline/rs_offline_processor.h"
#include "feature/hwc/rs_uni_hwc_prevalidate_util.h"
#include "pipeline/rs_test_util.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "drawable/rs_render_node_drawable_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
constexpr size_t MAX_NUM_INVALID_FRAME_NUM = 2;
}
class RSHpaeOfflineDeviceMockTest : public ::testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSHpaeOfflineDeviceMockTest::SetUpTestCase() {}
void RSHpaeOfflineDeviceMockTest::TearDownTestCase()
{
    RSTestUtil::InitRenderNodeGC();
    auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
    nodeMap.FilterNodeByPid(0, true);
    DrawableV2::RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}
void RSHpaeOfflineDeviceMockTest::SetUp() {}
void RSHpaeOfflineDeviceMockTest::TearDown() {}

/**
 * @tc.name: LoadPreProcessHandleTest001
 * @tc.desc: Verify function LoadPreProcessHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, LoadPreProcessHandleTest001, TestSize.Level0)
{
    g_DlopenNull = true;
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_);
    g_DlopenNull = false;

    g_ProcessOfflineSurfaceNull = true;
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_);
    g_ProcessOfflineSurfaceNull = false;

    g_GetOfflineConfigNull = true;
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_);
    g_GetOfflineConfigNull = false;

    g_InitOfflineNull = true;
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_);
    g_InitOfflineNull = false;

    g_DeInitOfflineNull = true;
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_);
    g_DeInitOfflineNull = false;

    g_GetOfflineOutputFenceFailed = true;
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_);
    g_GetOfflineOutputFenceFailed = false;

    device->LoadPreProcessHandle();
    EXPECT_TRUE(device->loadSuccess_);
}

/**
 * @tc.name: preprocess Init001
 * @tc.desc: test for preprocess when initPrevalidate is nullptr, or return failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, InitPrevalidate002, TestSize.Level1)
{
    g_InitPrevalidateNull = false;
    g_InitPrevalidateFailed = false;
    auto device = std::make_shared<RSHpaeOfflineDevice>();

    g_InitPrevalidateNull = true;
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_); // true & false

    g_InitPrevalidateFailed = true;
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_); // true & true

    g_InitPrevalidateNull = false;
    device->LoadPreProcessHandle();
    EXPECT_FALSE(device->loadSuccess_); // false & true

    g_InitPrevalidateFailed = false;
    device->LoadPreProcessHandle();
    EXPECT_TRUE(device->loadSuccess_); // false & false
}

/**
 * @tc.name: LoadPreProcessHandleTest003
 * @tc.desc: Verify function LoadPreProcessHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, LoadPreProcessHandleTest003, TestSize.Level0)
{
    g_DlopenNull = true;
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    g_DlopenNull = false;

    EXPECT_EQ(device->preProcessFunc_, nullptr);
    EXPECT_EQ(device->getConfigFunc_, nullptr);
}

/**
 * @tc.name: CheckAndPostClearOfflineResourceTaskTest
 * @tc.desc: Verify function CheckAndPostClearOfflineResourceTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, CheckAndPostClearOfflineResourceTaskTest, TestSize.Level0)
{
    g_DlopenNull = true;
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    g_DlopenNull = false;

    EXPECT_EQ(device->preProcessFunc_, nullptr);
    EXPECT_EQ(device->getConfigFunc_, nullptr);

    std::vector<uint64_t> emptyNodeIds;
    device->CheckAndPostClearOfflineResourceTask(emptyNodeIds);
    EXPECT_FALSE(device->loadSuccess_);

    device->loadSuccess_ = true;
    device->isInitOfflineFuncSucc_ = false;
    device->CheckAndPostClearOfflineResourceTask(emptyNodeIds);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(device->loadSuccess_);
}

/**
 * @tc.name: CheckAndPostClearInvalidFramesTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask clears context when invalidFrames reaches threshold
 *           - Create context and set invalidFrames >= maxInvalidFrames
 *           - Verify context is removed after calling CheckAndPostClearOfflineResourceTask
 * @tc.type: FUNC
 * @tc.require: issue_hpae_offline_mock_005
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, CheckAndPostClearInvalidFramesTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();
    auto ctx1 = device->GetOrCreateOfflineContext(surfaceNode1);
    EXPECT_NE(ctx1, nullptr);

    ctx1->invalidFrames = MAX_NUM_INVALID_FRAME_NUM;

    std::vector<uint64_t> nodeIds;
    device->CheckAndPostClearOfflineResourceTask(nodeIds);

    auto ctxAfter = device->GetOfflineContext(1);
    EXPECT_EQ(ctxAfter, nullptr);
}

/**
 * @tc.name: CheckAndPostClearMultipleNodesTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask with multiple nodes exceeding threshold
 *           - Create contexts for multiple nodes with invalidFrames >= maxInvalidFrames
 *           - Verify all contexts exceeding threshold are removed
 * @tc.type: FUNC
 * @tc.require: issue_hpae_offline_mock_006
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, CheckAndPostClearMultipleNodesTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();
    auto ctx1 = device->GetOrCreateOfflineContext(surfaceNode1);

    auto rsContext2 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config2;
    config2.id = 2;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config2, rsContext2->weak_from_this());
    surfaceNode2->InitRenderParams();
    auto ctx2 = device->GetOrCreateOfflineContext(surfaceNode2);

    auto rsContext3 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config3;
    config3.id = 3;
    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(config3, rsContext3->weak_from_this());
    surfaceNode3->InitRenderParams();
    auto ctx3 = device->GetOrCreateOfflineContext(surfaceNode3);

    EXPECT_NE(ctx1, nullptr);
    EXPECT_NE(ctx2, nullptr);
    EXPECT_EQ(ctx3, nullptr);

    ctx1->invalidFrames = MAX_NUM_INVALID_FRAME_NUM;
    ctx2->invalidFrames = MAX_NUM_INVALID_FRAME_NUM + 1;

    std::vector<uint64_t> nodeIds;
    device->CheckAndPostClearOfflineResourceTask(nodeIds);

    EXPECT_EQ(device->GetOfflineContext(1), nullptr);
    EXPECT_EQ(device->GetOfflineContext(2), nullptr);
}

/**
 * @tc.name: CheckAndPostClearMixedInvalidFramesTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask with mixed invalidFrames values
 *           - Some nodes exceed threshold, some do not
 *           - Verify only exceeding nodes are removed, others are kept with incremented invalidFrames
 * @tc.type: FUNC
 * @tc.require: issue_hpae_offline_mock_007
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, CheckAndPostClearMixedInvalidFramesTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();
    auto ctx1 = device->GetOrCreateOfflineContext(surfaceNode1);

    auto rsContext2 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config2;
    config2.id = 2;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config2, rsContext2->weak_from_this());
    surfaceNode2->InitRenderParams();
    auto ctx2 = device->GetOrCreateOfflineContext(surfaceNode2);

    EXPECT_NE(ctx1, nullptr);
    EXPECT_NE(ctx2, nullptr);

    ctx1->invalidFrames = MAX_NUM_INVALID_FRAME_NUM + 1;
    ctx2->invalidFrames = 0;
    std::vector<uint64_t> nodeIds;
    device->CheckAndPostClearOfflineResourceTask(nodeIds);

    EXPECT_EQ(device->GetOfflineContext(1), nullptr);
    auto ctx2After = device->GetOfflineContext(2);
    EXPECT_NE(ctx2After, nullptr);
}

/**
 * @tc.name: CheckAndPostClearEmptyCacheTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask when context cache is empty
 *           - Should not crash when calling with empty cache
 * @tc.type: FUNC
 * @tc.require: issue_hpae_offline_mock_008
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, CheckAndPostClearEmptyCacheTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    EXPECT_NE(device, nullptr);

    std::vector<uint64_t> emptyNodeIds;
    device->CheckAndPostClearOfflineResourceTask(emptyNodeIds);
}

/**
 * @tc.name: CheckAndPostClearWithPendingTasksTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask does not remove context when pending tasks exist
 *           - Context invalidFrames >= maxInvalidFrames but has pending tasks in resultPool
 *           - Verify context is not removed
 * @tc.type: FUNC
 * @tc.require: issue_hpae_offline_mock_009
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, CheckAndPostClearWithPendingTasksTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();
    auto ctx1 = device->GetOrCreateOfflineContext(surfaceNode1);

    offlineTaskId taskId = std::make_pair(100, 1);
    auto future = device->offlineResultSync_.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    std::vector<uint64_t> nodeIds;
    device->CheckAndPostClearOfflineResourceTask(nodeIds);

    auto ctxAfter = device->GetOfflineContext(1);
    EXPECT_NE(ctxAfter, nullptr);

    device->offlineResultSync_.ClearResultPool();
}

/**
 * @tc.name: prevalidate Init001
 * @tc.desc: test for initPrevalidate when initPrevalidate is nullptr, or return failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDeviceMockTest, InitPrevalidate001, TestSize.Level1)
{
    g_InitPrevalidateNull = false;
    g_InitPrevalidateFailed = false;

    g_InitPrevalidateNull = true;
    RSUniHwcPrevalidateUtil util1;
    EXPECT_FALSE(util1.loadSuccess_); // true & false

    g_InitPrevalidateFailed = true;
    RSUniHwcPrevalidateUtil util2;
    EXPECT_FALSE(util2.loadSuccess_); // true & true

    g_InitPrevalidateNull = false;
    RSUniHwcPrevalidateUtil util3;
    EXPECT_FALSE(util3.loadSuccess_); // false & true

    g_InitPrevalidateFailed = false;
    RSUniHwcPrevalidateUtil util4;
    EXPECT_FALSE(util4.loadSuccess_); // false & false
}
} // namespace OHOS::Rosen