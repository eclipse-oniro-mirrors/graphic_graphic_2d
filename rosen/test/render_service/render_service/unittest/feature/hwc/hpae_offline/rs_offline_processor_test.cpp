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
#include "feature/hwc/hpae_offline/rs_hpae_offline_device.h"
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


// ==================== RSOfflineProcessorTest Tests ====================

class RSOfflineProcessorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSOfflineProcessorTest::SetUpTestCase() {}
void RSOfflineProcessorTest::TearDownTestCase() {}
void RSOfflineProcessorTest::SetUp() {}
void RSOfflineProcessorTest::TearDown() {}


/**
 * @tc.name: GetOfflineProcessorSingletonTest001
 * @tc.desc: Test RSOfflineProcessor singleton pattern
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_001
 */
HWTEST_F(RSOfflineProcessorTest, GetOfflineProcessorSingletonTest001, TestSize.Level1)
{
    auto& processor1 = RSOfflineProcessor::GetOfflineProcessor();
    auto& processor2 = RSOfflineProcessor::GetOfflineProcessor();
    EXPECT_EQ(&processor1, &processor2);
}

/**
 * @tc.name: GetOfflineDeviceTypeTest001
 * @tc.desc: Test GetOfflineDeviceType with valid taskId
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_002
 */
HWTEST_F(RSOfflineProcessorTest, GetOfflineDeviceTypeTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // DeviceType not registered, should return INVALID
    OfflineDeviceType type = processor.GetOfflineDeviceType(taskId);
    EXPECT_EQ(type, OfflineDeviceType::INVALID);
}

/**
 * @tc.name: GetOfflineDeviceTypeTest002
 * @tc.desc: Test GetOfflineDeviceType after registering device type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_002
 */
HWTEST_F(RSOfflineProcessorTest, GetOfflineDeviceTypeTest002, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    auto& deviceTypeMap = processor.deviceTypeMap_;
    auto& mutex = processor.deviceTypeMapMutex_;

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Manually register device type
    {
        std::lock_guard<std::mutex> lock(mutex);
        deviceTypeMap[TEST_NODE_ID] = OfflineDeviceType::GPU_OFFLINE_DEVICE;
    }

    OfflineDeviceType type = processor.GetOfflineDeviceType(taskId);
    EXPECT_EQ(type, OfflineDeviceType::GPU_OFFLINE_DEVICE);

    // Clean up
    {
        std::lock_guard<std::mutex> lock(mutex);
        deviceTypeMap.erase(TEST_NODE_ID);
    }
}

/**
 * @tc.name: CreateDeviceTest001
 * @tc.desc: Test CreateDevice with HPAE_OFFLINE_DEVICE type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_003
 */
HWTEST_F(RSOfflineProcessorTest, CreateDeviceTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    auto device = processor.GetOrCreateOfflineDevice(OfflineDeviceType::HPAE_OFFLINE_DEVICE, true);

    EXPECT_NE(device, nullptr);
    EXPECT_EQ(device->GetDeviceType(), OfflineDeviceType::HPAE_OFFLINE_DEVICE);
}

/**
 * @tc.name: CreateDeviceTest002
 * @tc.desc: Test CreateDevice with GPU_OFFLINE_DEVICE type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_003
 */
HWTEST_F(RSOfflineProcessorTest, CreateDeviceTest002, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    auto device = processor.GetOrCreateOfflineDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE, true);

    EXPECT_NE(device, nullptr);
    EXPECT_EQ(device->GetDeviceType(), OfflineDeviceType::GPU_OFFLINE_DEVICE);
}

/**
 * @tc.name: CreateDeviceTest003
 * @tc.desc: Test CreateDevice with INVALID type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_003
 */
HWTEST_F(RSOfflineProcessorTest, CreateDeviceTest003, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    auto device = processor.GetOrCreateOfflineDevice(OfflineDeviceType::INVALID, true);

    EXPECT_EQ(device, nullptr);
}

/**
 * @tc.name: IsRSOfflineProcessorReadyTest001
 * @tc.desc: Test IsRSOfflineProcessorReady with invalid device type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_004
 */
HWTEST_F(RSOfflineProcessorTest, IsRSOfflineProcessorReadyTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    bool result = processor.IsRSOfflineProcessorReady(surfaceNode, OfflineDeviceType::INVALID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsRSOfflineProcessorReadyTest002
 * @tc.desc: Test IsRSOfflineProcessorReady with invalid device type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_004
 */
HWTEST_F(RSOfflineProcessorTest, IsRSOfflineProcessorReadyTest002, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    auto& deviceTypeMap = processor.deviceTypeMap_;
    auto& mutex = processor.deviceTypeMapMutex_;
    auto& deviceTypeInsertOrder = processor.deviceTypeInsertOrder_;
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = 101;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    std::shared_ptr<RSOfflineDevice> device =
        processor.GetOrCreateOfflineDevice(OfflineDeviceType::HPAE_OFFLINE_DEVICE, true);
    std::shared_ptr<RSHpaeOfflineDevice> offlineDevice = std::static_pointer_cast<RSHpaeOfflineDevice>(device);
    offlineDevice->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            return 0;
        });
    offlineDevice->preProcessHandle_ = nullptr;
    offlineDevice->preProcessFunc_ = nullptr;
    offlineDevice->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return 0; });
    offlineDevice->deInitOfflineFunc_ = static_cast<OHOS::Rosen::DeInitOfflineResourceFunc>([]() {});
    offlineDevice->getFenceFunc_ =
        static_cast<OHOS::Rosen::GetFenceFunc>([](int32_t &outputFence) {
            outputFence = -1;
            return 0;
        });
    std::shared_ptr<RSHpaeOfflineContext> context = offlineDevice->GetOrCreateOfflineContext(surfaceNode);
    context->timeout = false;
    context->contextType = OfflineContextType::SCALE;
    context->preAllocBufferSucc = true;
    bool result = processor.IsRSOfflineProcessorReady(surfaceNode, OfflineDeviceType::HPAE_OFFLINE_DEVICE);
    deviceTypeMap.erase(101);
    deviceTypeInsertOrder.pop_front();
    {
        std::lock_guard<std::mutex> lock(mutex);
        for (uint64_t i = 0; i < 8; ++i) {
            deviceTypeMap[i] = OfflineDeviceType::HPAE_OFFLINE_DEVICE;
            deviceTypeInsertOrder.push_back(i);
        }
    }
    result = processor.IsRSOfflineProcessorReady(surfaceNode, OfflineDeviceType::HPAE_OFFLINE_DEVICE);
    EXPECT_TRUE(result);

    result = processor.IsRSOfflineProcessorReady(surfaceNode, OfflineDeviceType::HPAE_OFFLINE_DEVICE);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: PostProcessOfflineTaskTest001
 * @tc.desc: Test PostProcessOfflineTask without device ready
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_006
 */
HWTEST_F(RSOfflineProcessorTest, PostProcessOfflineTaskTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    // Register device type for this node
    auto& deviceTypeMap = processor.deviceTypeMap_;
    auto& mutex = processor.deviceTypeMapMutex_;
    {
        std::lock_guard<std::mutex> lock(mutex);
        deviceTypeMap[TEST_NODE_ID] = OfflineDeviceType::INVALID;
    }
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    bool result = processor.PostProcessOfflineTask(surfaceNode, taskId);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: WaitForProcessOfflineResultTest001
 * @tc.desc: Test WaitForProcessOfflineResult with invalid device type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_007
 */
HWTEST_F(RSOfflineProcessorTest, WaitForProcessOfflineResultTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    ProcessOfflineResult result;

    bool waitResult = processor.WaitForProcessOfflineResult(
        taskId, std::chrono::milliseconds(TEST_TIMEOUT_MS), result);
    EXPECT_FALSE(waitResult);
}
// ==================== RSOfflineProcessorPrivateTest Tests ====================

class RSOfflineProcessorPrivateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSOfflineProcessorPrivateTest::SetUpTestCase() {}
void RSOfflineProcessorPrivateTest::TearDownTestCase() {}
void RSOfflineProcessorPrivateTest::SetUp() {}
void RSOfflineProcessorPrivateTest::TearDown() {}


/**
 * @tc.name: CreateDeviceTest001
 * @tc.desc: Test CreateDevice private method - HPAE
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_processor_001
 */
HWTEST_F(RSOfflineProcessorPrivateTest, CreateDeviceTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    auto device = processor.CreateDevice(OfflineDeviceType::HPAE_OFFLINE_DEVICE);
    EXPECT_NE(device, nullptr);
    EXPECT_EQ(device->GetDeviceType(), OfflineDeviceType::HPAE_OFFLINE_DEVICE);
}

/**
 * @tc.name: CreateDeviceTest002
 * @tc.desc: Test CreateDevice private method - GPU
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_processor_001
 */
HWTEST_F(RSOfflineProcessorPrivateTest, CreateDeviceTest002, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    auto device = processor.CreateDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE);
    EXPECT_NE(device, nullptr);
    EXPECT_EQ(device->GetDeviceType(), OfflineDeviceType::GPU_OFFLINE_DEVICE);
}

/**
 * @tc.name: CreateDeviceTest003
 * @tc.desc: Test CreateDevice private method - INVALID returns nullptr
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_processor_001
 */
HWTEST_F(RSOfflineProcessorPrivateTest, CreateDeviceTest003, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    auto device = processor.CreateDevice(OfflineDeviceType::INVALID);
    EXPECT_EQ(device, nullptr);
}

/**
 * @tc.name: CreateDeviceTest004
 * @tc.desc: Test CreateDevice private method - Unknown type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_processor_001
 */
HWTEST_F(RSOfflineProcessorPrivateTest, CreateDeviceTest004, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    auto device = processor.CreateDevice(static_cast<OfflineDeviceType>(999));
    EXPECT_EQ(device, nullptr);
}

/**
 * @tc.name: GetOrCreateOfflineDeviceTest001
 * @tc.desc: Test GetOrCreateOfflineDevice - create new device
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_processor_002
 */
HWTEST_F(RSOfflineProcessorPrivateTest, GetOrCreateOfflineDeviceTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    auto device = processor.GetOrCreateOfflineDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE, true);
    EXPECT_NE(device, nullptr);
}

/**
 * @tc.name: GetOrCreateOfflineDeviceTest002
 * @tc.desc: Test GetOrCreateOfflineDevice - don't create, return nullptr
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_processor_002
 */
HWTEST_F(RSOfflineProcessorPrivateTest, GetOrCreateOfflineDeviceTest002, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    // Use a device type that hasn't been created
    auto device = processor.GetOrCreateOfflineDevice(static_cast<OfflineDeviceType>(50), false);
    EXPECT_EQ(device, nullptr);
}

/**
 * @tc.name: GetOrCreateOfflineDeviceTest003
 * @tc.desc: Test GetOrCreateOfflineDevice - INVALID returns nullptr
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_processor_002
 */
HWTEST_F(RSOfflineProcessorPrivateTest, GetOrCreateOfflineDeviceTest003, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    auto device = processor.GetOrCreateOfflineDevice(OfflineDeviceType::INVALID, true);
    EXPECT_EQ(device, nullptr);
}

/**
 * @tc.name: DeleteOfflineDeviceFromTypeTest001
 * @tc.desc: Test DeleteOfflineDeviceFromType removes device from pool
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_processor_003
 */
HWTEST_F(RSOfflineProcessorPrivateTest, DeleteOfflineDeviceFromTypeTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    // Create device first
    auto device = processor.GetOrCreateOfflineDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE, true);
    EXPECT_NE(device, nullptr);

    // Delete it
    processor.DeleteOfflineDeviceFromType(OfflineDeviceType::GPU_OFFLINE_DEVICE);

    // Get without creating should return nullptr
    auto deviceAgain = processor.GetOrCreateOfflineDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE, false);
    EXPECT_EQ(deviceAgain, nullptr);
}

/**
 * @tc.name: ProcessorPostProcessOfflineTaskNodeSuccessTest001
 * @tc.desc: Test PostProcessOfflineTask(node) success path with registered device type
 *           and existing device
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_023
 */
HWTEST_F(RSOfflineProcessorPrivateTest, PostProcessOfflineTaskNodeSuccessTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    // Register device type for this node
    auto& deviceTypeMap = processor.deviceTypeMap_;
    auto& mutex = processor.deviceTypeMapMutex_;

    {
        std::lock_guard<std::mutex> lock(mutex);
        deviceTypeMap[TEST_NODE_ID] = OfflineDeviceType::GPU_OFFLINE_DEVICE;
    }

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Device exists but device->IsRSOfflineProcessorReady hasn't been called
    // PostProcessOfflineTask will find device and call device->PostProcessOfflineTask
    bool result = processor.PostProcessOfflineTask(surfaceNode, taskId);
    // Device PostProcessOfflineTask depends on context existence and timeout status
    // No context exists for this node, so should return false
    EXPECT_FALSE(result);

    // Clean up
    {
        std::lock_guard<std::mutex> lock(mutex);
        deviceTypeMap.erase(TEST_NODE_ID);
    }
}

/**
 * @tc.name: ProcessorWaitForProcessOfflineResultSuccessTest001
 * @tc.desc: Test WaitForProcessOfflineResult with registered task and GPU device
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_024
 */
HWTEST_F(RSOfflineProcessorPrivateTest, WaitForProcessOfflineResultSuccessTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    // Register device type for the node
    auto& deviceTypeMap = processor.deviceTypeMap_;
    auto& mutex = processor.deviceTypeMapMutex_;

    {
        std::lock_guard<std::mutex> lock(mutex);
        deviceTypeMap[TEST_NODE_ID] = OfflineDeviceType::GPU_OFFLINE_DEVICE;
    }

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    ProcessOfflineResult result;

    // Device exists, will call device->WaitForProcessOfflineResult
    bool waitResult = processor.WaitForProcessOfflineResult(
        taskId, std::chrono::milliseconds(TEST_TIMEOUT_MS), result);
    // No task registered in device's syncer, should return false
    EXPECT_FALSE(waitResult);

    // Clean up
    {
        std::lock_guard<std::mutex> lock(mutex);
        deviceTypeMap.erase(TEST_NODE_ID);
    }
}

/**
 * @tc.name: ProcessorCheckAndPostClearDeviceExistsTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask when device exists and CanDeleteDevice=true
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_025
 */
HWTEST_F(RSOfflineProcessorPrivateTest, CheckAndPostClearDeviceExistsTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    // Create GPU device (which has empty cache, CanDeleteDevice=true)
    processor.GetOrCreateOfflineDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE, true);

    // CheckAndPostClearOfflineResourceTask with GPU type
    // Device cache is empty, CanDeleteDevice returns true, device should be deleted
    processor.CheckAndPostClearOfflineResourceTask(OfflineDeviceType::GPU_OFFLINE_DEVICE);

    // After CanDeleteDevice=true, device should be removed from pool
    auto device = processor.GetOrCreateOfflineDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE, false);
    EXPECT_EQ(device, nullptr);
}

/**
 * @tc.name: ProcessorCheckAndPostClearDeviceNotDeletableTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask when device exists but CanDeleteDevice=false
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_025
 */
HWTEST_F(RSOfflineProcessorPrivateTest, CheckAndPostClearDeviceNotDeletableTest001, TestSize.Level1)
{
    auto& processor = RSOfflineProcessor::GetOfflineProcessor();

    // Create GPU device
    auto device = processor.GetOrCreateOfflineDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE, true);
    EXPECT_NE(device, nullptr);

    // Manually cast to RSGPUOfflineDevice and add a context to make cache non-empty
    auto gpuDevice = std::static_pointer_cast<RSGPUOfflineDevice>(device);
    EXPECT_NE(gpuDevice, nullptr);

    // Create a context to make CanDeleteDevice return false
    gpuDevice->GetOrCreateOfflineContext(TEST_NODE_ID);

    // CheckAndPostClearOfflineResourceTask - device exists, CanDeleteDevice=false
    processor.CheckAndPostClearOfflineResourceTask(OfflineDeviceType::GPU_OFFLINE_DEVICE);

    // Device should still be in pool since CanDeleteDevice=false
    auto deviceAgain = processor.GetOrCreateOfflineDevice(OfflineDeviceType::GPU_OFFLINE_DEVICE, false);
    EXPECT_NE(deviceAgain, nullptr);
}

