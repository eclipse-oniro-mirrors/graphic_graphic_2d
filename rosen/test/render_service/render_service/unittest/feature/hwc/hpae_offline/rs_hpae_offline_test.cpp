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
#include <memory>
#include <chrono>

#include "feature/hwc/hpae_offline/rs_offline_processor.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_device.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_buffer.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_thread.h"
#include "feature/hwc/hpae_offline/rs_offline_device.h"
#include "feature/hwc/hpae_offline/rs_offline_util.h"
#include "feature/hwc/hpae_offline/rs_offline_result.h"
#include "feature/hwc/rs_uni_hwc_prevalidate_util.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_system_properties.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Rosen;

namespace {
constexpr NodeId TEST_NODE_ID = 12345;
constexpr uint64_t TEST_VSYNC_ID = 100;
constexpr uint64_t TEST_TIMEOUT_MS = 100;
}


// ==================== RSHpaeOfflineProcessSyncerTest Tests ====================

class RSHpaeOfflineProcessSyncerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSHpaeOfflineProcessSyncerTest::SetUpTestCase() {}
void RSHpaeOfflineProcessSyncerTest::TearDownTestCase() {}
void RSHpaeOfflineProcessSyncerTest::SetUp() {}
void RSHpaeOfflineProcessSyncerTest::TearDown() {}


/**
 * @tc.name: RegisterPostedTaskTest001
 * @tc.desc: Test RegisterPostedTask with valid taskId
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_029
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, RegisterPostedTaskTest001, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    auto future = syncer.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    auto size = syncer.GetResultPoolSize();
    EXPECT_EQ(size, 1);
}

/**
 * @tc.name: RegisterPostedTaskTest002
 * @tc.desc: Test RegisterPostedTask with duplicate taskId
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_029
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, RegisterPostedTaskTest002, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    auto future1 = syncer.RegisterPostedTask(taskId);
    EXPECT_NE(future1, nullptr);

    // Duplicate registration should return nullptr
    auto future2 = syncer.RegisterPostedTask(taskId);
    EXPECT_EQ(future2, nullptr);
}

/**
 * @tc.name: SetDirectResultTest001
 * @tc.desc: Test SetDirectResult with valid taskId
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_030
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, SetDirectResultTest001, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    ProcessOfflineResult result;
    result.taskSuccess = true;

    syncer.SetDirectResult(taskId, result);

    auto size = syncer.GetResultPoolSize();
    EXPECT_EQ(size, 1);
}

/**
 * @tc.name: WaitForTaskAndGetResultWithDirectResultTest001
 * @tc.desc: Test WaitForTaskAndGetResult with direct result set
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_031
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, WaitForTaskAndGetResultWithDirectResultTest001, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    ProcessOfflineResult setResult;
    setResult.taskSuccess = true;
    setResult.isGPUOffline = true;

    syncer.SetDirectResult(taskId, setResult);

    ProcessOfflineResult getResult;
    bool waitSuccess = syncer.WaitForTaskAndGetResult(taskId,
        std::chrono::milliseconds(TEST_TIMEOUT_MS), getResult);

    EXPECT_TRUE(waitSuccess);
    EXPECT_TRUE(getResult.taskSuccess);
    EXPECT_TRUE(getResult.isGPUOffline);
}

/**
 * @tc.name: MarkTaskDoneAndSetResultTest001
 * @tc.desc: Test MarkTaskDoneAndSetResult with valid future
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_032
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, MarkTaskDoneAndSetResultTest001, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    auto future = syncer.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    ProcessOfflineResult result;
    result.taskSuccess = true;

    syncer.MarkTaskDoneAndSetResult(future, result);

    EXPECT_TRUE(future->done);
    EXPECT_TRUE(future->result.taskSuccess);
}

/**
 * @tc.name: SyncerWaitForTaskAndGetResultTimeoutTest001
 * @tc.desc: Test WaitForTaskAndGetResult with short timeout where task is not done
 *           - Tests the wait_for timeout path where future->done is still false
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_026
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, WaitForTaskAndGetResultTimeoutTest001, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Register a task but don't mark it as done
    auto future = syncer.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    ProcessOfflineResult result;
    // Very short timeout, task is not done, should timeout
    bool waitResult = syncer.WaitForTaskAndGetResult(
        taskId, std::chrono::milliseconds(1), result);

    EXPECT_FALSE(waitResult);
}

/**
 * @tc.name: SyncerWaitForTaskAndGetResultMaxTimeoutTest001
 * @tc.desc: Test WaitForTaskAndGetResult with chrono::milliseconds::max() timeout
 *           - Tests the cv.wait(lock, ...) path (infinite wait) when task is marked done
 *           before the wait starts
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_026
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, WaitForTaskAndGetResultMaxTimeoutTest001, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Register a task
    auto future = syncer.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    // Mark task as done before waiting
    ProcessOfflineResult setResult;
    setResult.taskSuccess = true;
    syncer.MarkTaskDoneAndSetResult(future, setResult);

    ProcessOfflineResult result;
    // Use max timeout - since task is already done, wait should return immediately
    bool waitResult = syncer.WaitForTaskAndGetResult(
        taskId, std::chrono::milliseconds::max(), result);

    EXPECT_TRUE(waitResult);
    EXPECT_TRUE(result.taskSuccess);
}

/**
 * @tc.name: SyncerGetResultPoolSizeByNodeBothPoolsTest001
 * @tc.desc: Test GetResultPoolSizeByNode with entries in both resultPool_ and directResultCache_
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_027
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, GetResultPoolSizeByNodeBothPoolsTest001, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;

    // Add entry to resultPool_
    offlineTaskId taskId1 = std::make_pair(100, TEST_NODE_ID);
    auto future1 = syncer.RegisterPostedTask(taskId1);
    EXPECT_NE(future1, nullptr);

    // Add another entry to resultPool_ for same node
    offlineTaskId taskId2 = std::make_pair(200, TEST_NODE_ID);
    auto future2 = syncer.RegisterPostedTask(taskId2);
    EXPECT_NE(future2, nullptr);

    // Add entry to directResultCache_ for same node
    offlineTaskId taskId3 = std::make_pair(300, TEST_NODE_ID);
    ProcessOfflineResult directResult;
    directResult.taskSuccess = true;
    syncer.SetDirectResult(taskId3, directResult);

    // GetResultPoolSizeByNode should count entries from both pools
    auto size = syncer.GetResultPoolSizeByNode(TEST_NODE_ID);
    EXPECT_EQ(size, 3);
}

/**
 * @tc.name: SyncerGetResultPoolSizeByNodeDifferentNodesTest001
 * @tc.desc: Test GetResultPoolSizeByNode with entries for different node IDs
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_027
 */
HWTEST_F(RSHpaeOfflineProcessSyncerTest, GetResultPoolSizeByNodeDifferentNodesTest001, TestSize.Level1)
{
    RSHpaeOfflineProcessSyncer syncer;

    // Add entry for node 1
    offlineTaskId taskId1 = std::make_pair(100, 1);
    auto future1 = syncer.RegisterPostedTask(taskId1);
    EXPECT_NE(future1, nullptr);

    // Add entry for node 2
    offlineTaskId taskId2 = std::make_pair(200, 2);
    auto future2 = syncer.RegisterPostedTask(taskId2);
    EXPECT_NE(future2, nullptr);

    // GetResultPoolSizeByNode for node 1 should return 1
    EXPECT_EQ(syncer.GetResultPoolSizeByNode(1), 1);

    // GetResultPoolSizeByNode for node 2 should return 1
    EXPECT_EQ(syncer.GetResultPoolSizeByNode(2), 1);

    // GetResultPoolSizeByNode for node 3 should return 0
    EXPECT_EQ(syncer.GetResultPoolSizeByNode(3), 0);
}
// ==================== OfflineDeviceTypeTest Tests ====================

class OfflineDeviceTypeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void OfflineDeviceTypeTest::SetUpTestCase() {}
void OfflineDeviceTypeTest::TearDownTestCase() {}
void OfflineDeviceTypeTest::SetUp() {}
void OfflineDeviceTypeTest::TearDown() {}


/**
 * @tc.name: EnumValuesTest001
 * @tc.desc: Test OfflineDeviceType enum values
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_022
 */
HWTEST_F(OfflineDeviceTypeTest, EnumValuesTest001, TestSize.Level1)
{
    EXPECT_EQ(static_cast<int>(OfflineDeviceType::INVALID), 0);
    EXPECT_EQ(static_cast<int>(OfflineDeviceType::HPAE_OFFLINE_DEVICE), 3);
    EXPECT_EQ(static_cast<int>(OfflineDeviceType::GPU_OFFLINE_DEVICE), 7);
}

// ==================== ProcessOfflineResultTest Tests ====================

class ProcessOfflineResultTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ProcessOfflineResultTest::SetUpTestCase() {}
void ProcessOfflineResultTest::TearDownTestCase() {}
void ProcessOfflineResultTest::SetUp() {}
void ProcessOfflineResultTest::TearDown() {}

/**
 * @tc.name: DefaultValuesTest001
 * @tc.desc: Test ProcessOfflineResult default values
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_023
 */
HWTEST_F(ProcessOfflineResultTest, DefaultValuesTest001, TestSize.Level1)
{
    ProcessOfflineResult result;

    EXPECT_EQ(result.consumer, nullptr);
    EXPECT_EQ(result.preBuffer, nullptr);
    EXPECT_EQ(result.buffer, nullptr);
    EXPECT_EQ(result.acquireFence, nullptr);
    EXPECT_EQ(result.bufferOwnerCount, nullptr);
    EXPECT_EQ(result.transformType, GraphicTransformType::GRAPHIC_ROTATE_NONE);
    EXPECT_FALSE(result.taskSuccess);
    EXPECT_FALSE(result.isGPUOffline);
    EXPECT_EQ(result.linearMatrix.size(), 9u);
}

// ==================== ProcessOfflineFutureTest Tests ====================

class ProcessOfflineFutureTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void ProcessOfflineFutureTest::SetUpTestCase() {}
void ProcessOfflineFutureTest::TearDownTestCase() {}
void ProcessOfflineFutureTest::SetUp() {}
void ProcessOfflineFutureTest::TearDown() {}

/**
 * @tc.name: DefaultValuesTest001
 * @tc.desc: Test ProcessOfflineFuture default values
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_033
 */
HWTEST_F(ProcessOfflineFutureTest, DefaultValuesTest001, TestSize.Level1)
{
    ProcessOfflineFuture future;

    EXPECT_FALSE(future.done);
    EXPECT_FALSE(future.timeout);
}

