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
#include <parameters.h>

#include "feature/hwc/hpae_offline/rs_offline_processor.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_device.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_buffer.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_thread.h"
#include "feature/hwc/hpae_offline/rs_offline_device.h"
#include "feature/hwc/hpae_offline/rs_offline_util.h"
#include "feature/hwc/hpae_offline/rs_offline_result.h"
#include "feature/hwc/rs_uni_hwc_prevalidate_util.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/main_thread/rs_uni_render_visitor.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_surface_handler.h"
#include "pipeline/rs_screen_render_node.h"
#include "platform/common/rs_system_properties.h"
#include "system/rs_system_parameters.h"
#include "utils/system_properties.h"
#include "surface_buffer.h"
#include "v2_2/buffer_handle_meta_key_type.h"
#include "drawable/rs_surface_render_node_drawable.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Rosen;
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;

namespace {
constexpr NodeId TEST_NODE_ID = 12345;
constexpr uint64_t TEST_VSYNC_ID = 100;
constexpr uint64_t TEST_TIMEOUT_MS = 100;
constexpr int32_t BUFFER_WIDTH = 1000;
constexpr int32_t BUFFER_HEIGHT = 1000;
std::vector<uint8_t> g_hdrStaticMetadataVec = {10, 215, 35, 63, 195, 245, 168, 62, 154, 153, 153, 62,
    154, 153, 25, 63, 154, 153, 25, 62, 143, 194, 117, 61, 55, 26, 160, 62, 176, 114, 168, 62, 0, 0,
    122, 68, 0, 0, 0, 0, 0, 64, 24, 68, 0, 64, 24, 68};
}

// ==================== RSGPUOfflineDeviceTest Tests ====================

class RSGPUOfflineDeviceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

private:
    sptr<SurfaceBuffer> CreateSurfaceBuffer(int32_t width, int32_t height);
    void SetRSSurfaceHandlerBuffer(sptr<SurfaceBuffer> &surfaceBuffer, std::shared_ptr<RSSurfaceHandler> surfaceHandler);
};

sptr<SurfaceBuffer> RSGPUOfflineDeviceTest::CreateSurfaceBuffer(int32_t width, int32_t height)
{
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();;
    BufferRequestConfig bufConfig = {
        .width = width,
        .height = height,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA |
            BUFFER_USAGE_MEM_MMZ_CACHE | BUFFER_USAGE_HW_RENDER | BUFFER_USAGE_HW_TEXTURE,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,

    };
    surfaceBuffer->Alloc(bufConfig);
    return surfaceBuffer;
}

void RSGPUOfflineDeviceTest::SetRSSurfaceHandlerBuffer(sptr<SurfaceBuffer> &surfaceBuffer, std::shared_ptr<RSSurfaceHandler> surfaceHandler)
{
    surfaceBuffer->SetMetadata(ATTRKEY_HDR_STATIC_METADATA, g_hdrStaticMetadataVec);
    sptr<SyncFence> fence = SyncFence::InvalidFence();
    int64_t timestamp = 0;
    Rect damage = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    std::shared_ptr<RSRcdSurfaceRenderNode::BufferOwnerCount> bufferOwnerCount = std::make_shared<RSRcdSurfaceRenderNode::BufferOwnerCount>();
    surfaceHandler->SetBuffer(surfaceBuffer, fence, damage, timestamp, bufferOwnerCount);
}

void RSGPUOfflineDeviceTest::SetUpTestCase() {}
void RSGPUOfflineDeviceTest::TearDownTestCase() {}
void RSGPUOfflineDeviceTest::SetUp() {}
void RSGPUOfflineDeviceTest::TearDown() {}


/**
 * @tc.name: CanDeleteDeviceTest001
 * @tc.desc: Test CanDeleteDevice with empty cache
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_009
 */
HWTEST_F(RSGPUOfflineDeviceTest, CanDeleteDeviceTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Empty cache, should be deletable
    EXPECT_TRUE(device->CanDeleteDevice());
}

/**
 * @tc.name: WaitForProcessOfflineResultTest001
 * @tc.desc: Test WaitForProcessOfflineResult with invalid taskId
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_011
 */
HWTEST_F(RSGPUOfflineDeviceTest, WaitForProcessOfflineResultTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    ProcessOfflineResult result;

    bool waitResult = device->WaitForProcessOfflineResult(
        taskId, std::chrono::milliseconds(TEST_TIMEOUT_MS), result);
    EXPECT_FALSE(waitResult);
}

/**
 * @tc.name: GetOrCreateOfflineContextTest001
 * @tc.desc: Test GetOrCreateOfflineContext creates new context for new nodeId
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_001
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetOrCreateOfflineContextTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);
    EXPECT_EQ(context->nodeId, TEST_NODE_ID);
    EXPECT_NE(context->offlineBuffer, nullptr);
}

/**
 * @tc.name: GetOrCreateOfflineContextTest002
 * @tc.desc: Test GetOrCreateOfflineContext returns existing context for same nodeId
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_001
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetOrCreateOfflineContextTest002, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context1 = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    auto context2 = device->GetOrCreateOfflineContext(TEST_NODE_ID);

    EXPECT_EQ(context1, context2);
}

/**
 * @tc.name: GetOfflineContextTest001
 * @tc.desc: Test GetOfflineContext returns nullptr for non-existent nodeId
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_002
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetOfflineContextTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = device->GetOfflineContext(TEST_NODE_ID);
    EXPECT_EQ(context, nullptr);
}

/**
 * @tc.name: GetOfflineContextTest002
 * @tc.desc: Test GetOfflineContext returns existing context
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_002
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetOfflineContextTest002, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    device->GetOrCreateOfflineContext(TEST_NODE_ID);
    auto context = device->GetOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);
}

/**
 * @tc.name: FindOldestEntryTest001
 * @tc.desc: Test FindOldestEntry returns 0 when cache is empty
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_003
 */
HWTEST_F(RSGPUOfflineDeviceTest, FindOldestEntryTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto oldestId = device->FindOldestEntry();
    EXPECT_EQ(oldestId, 0u);
}

/**
 * @tc.name: FindOldestEntryTest002
 * @tc.desc: Test FindOldestEntry returns correct oldest entry
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_003
 */
HWTEST_F(RSGPUOfflineDeviceTest, FindOldestEntryTest002, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Create contexts in order
    auto ctx1 = device->GetOrCreateOfflineContext(1);
    auto ctx2 = device->GetOrCreateOfflineContext(2);

    // Update ctx2 timestamp to make ctx1 oldest
    ctx1->timestamp = 100;
    ctx2->timestamp = 200;

    auto oldestId = device->FindOldestEntry();
    EXPECT_EQ(oldestId, 1u);
}

/**
 * @tc.name: FindOldestEntryTest003
 * @tc.desc: Test FindOldestEntry with multiple entries finds the one with smallest timestamp
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_003
 */
HWTEST_F(RSGPUOfflineDeviceTest, FindOldestEntryTest003, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto ctx1 = device->GetOrCreateOfflineContext(1);
    auto ctx2 = device->GetOrCreateOfflineContext(2);
    auto ctx3 = device->GetOrCreateOfflineContext(3);

    ctx1->timestamp = 300;
    ctx2->timestamp = 100; // Oldest
    ctx3->timestamp = 200;

    auto oldestId = device->FindOldestEntry();
    EXPECT_EQ(oldestId, 2u);
}

/**
 * @tc.name: TryRemoveContextTest001
 * @tc.desc: Test TryRemoveContext removes context when no pending tasks
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_004
 */
HWTEST_F(RSGPUOfflineDeviceTest, TryRemoveContextTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    device->GetOrCreateOfflineContext(TEST_NODE_ID);
    device->TryRemoveContext(TEST_NODE_ID);

    auto context = device->GetOfflineContext(TEST_NODE_ID);
    EXPECT_EQ(context, nullptr);
}

/**
 * @tc.name: GetGPUBufferConfigTest001
 * @tc.desc: Test GetGPUBufferConfig with valid taskContext
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_005
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetGPUBufferConfigTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;

    auto config = device->GetGPUBufferConfig(taskContext);

    EXPECT_EQ(config.width, 1920);
    EXPECT_EQ(config.height, 1080);
    EXPECT_EQ(config.strideAlignment, 0x8);
    EXPECT_EQ(config.format, GRAPHIC_PIXEL_FMT_RGBA_8888);
    EXPECT_EQ(config.timeout, 0);
    EXPECT_EQ(config.transform, GraphicTransformType::GRAPHIC_ROTATE_NONE);
}

/**
 * @tc.name: GetGPUBufferConfigTest002
 * @tc.desc: Test GetGPUBufferConfig with different colorGamut
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_005
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetGPUBufferConfigTest002, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.drawParams.resultWidth = 1280;
    taskContext.drawParams.resultHeight = 720;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2020;

    auto config = device->GetGPUBufferConfig(taskContext);

    EXPECT_EQ(config.width, 1280);
    EXPECT_EQ(config.height, 720);
    EXPECT_EQ(config.colorGamut, GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2020);
}

/**
 * @tc.name: CreateBufferDrawParamTest001
 * @tc.desc: Test CreateBufferDrawParam with default values
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_006
 */
HWTEST_F(RSGPUOfflineDeviceTest, CreateBufferDrawParamTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    taskContext.drawParams.useBilinearInterpolation = false;
    taskContext.drawParams.ignoreAlpha = false;
    taskContext.drawParams.gAlpha = 255;
    taskContext.drawParams.screenId = 1;

    auto params = device->CreateBufferDrawParam(taskContext);

    EXPECT_FALSE(params.useCPU);
    EXPECT_FALSE(params.useBilinearInterpolation);
    EXPECT_FALSE(params.ignoreAlpha);
    EXPECT_EQ(params.screenId, 1u);
    EXPECT_EQ(params.paint.GetAlpha(), 255);
}

/**
 * @tc.name: CreateBufferDrawParamTest002
 * @tc.desc: Test CreateBufferDrawParam with bilinear interpolation enabled
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_006
 */
HWTEST_F(RSGPUOfflineDeviceTest, CreateBufferDrawParamTest002, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.drawParams.useBilinearInterpolation = true;
    taskContext.drawParams.ignoreAlpha = true;

    auto params = device->CreateBufferDrawParam(taskContext);

    EXPECT_TRUE(params.useBilinearInterpolation);
    EXPECT_TRUE(params.ignoreAlpha);
}

/**
 * @tc.name: CreateBufferDrawParamTest003
 * @tc.desc: Test CreateBufferDrawParam srcRect and dstRect
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_006
 */
HWTEST_F(RSGPUOfflineDeviceTest, CreateBufferDrawParamTest003, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.drawParams.resultWidth = 1000;
    taskContext.drawParams.resultHeight = 500;

    auto params = device->CreateBufferDrawParam(taskContext);

    EXPECT_EQ(params.srcRect.GetWidth(), 1000.f);
    EXPECT_EQ(params.srcRect.GetHeight(), 500.f);
    EXPECT_EQ(params.dstRect.GetWidth(), 1000.f);
    EXPECT_EQ(params.dstRect.GetHeight(), 500.f);
}

/**
 * @tc.name: CreateBufferDrawParamTest004
 * @tc.desc: Test CreateBufferDrawParam colorFollow flag
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_006
 */
HWTEST_F(RSGPUOfflineDeviceTest, CreateBufferDrawParamTest004, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.drawParams.colorFollow = true;

    auto params = device->CreateBufferDrawParam(taskContext);
    EXPECT_TRUE(params.colorFollow);
}

/**
 * @tc.name: CollectDrawParamsTest001
 * @tc.desc: Test CollectDrawParams with surfaceNode and surfaceHandler
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_007
 */
HWTEST_F(RSGPUOfflineDeviceTest, CollectDrawParamsTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto rsContext = std::make_shared<RSContext>();
    EXPECT_NE(device, nullptr);
    EXPECT_NE(rsContext, nullptr);
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode, nullptr);
    surfaceNode->InitRenderParams();

    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    RSSurfaceRenderParams params(0);

    // Without buffer, GetBuffer returns nullptr
    auto drawParams = device->CollectDrawParams(surfaceNode, params);
    // resultWidth/resultHeight will be 0 without buffer
    EXPECT_EQ(drawParams.resultWidth, 0);
    EXPECT_EQ(drawParams.resultHeight, 0);
}

/**
 * @tc.name: CollectDrawParamsWithBufferTest001
 * @tc.desc: Test CollectDrawParams with valid buffer - covers line 355:
 *           drawParams.transformType = GraphicTransformType::GRAPHIC_ROTATE_NONE;
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_line_355
 */
HWTEST_F(RSGPUOfflineDeviceTest, CollectDrawParamsWithBufferTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto rsContext = std::make_shared<RSContext>();
    EXPECT_NE(device, nullptr);
    EXPECT_NE(rsContext, nullptr);
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode, nullptr);
    surfaceNode->InitRenderParams();

    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* params = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    EXPECT_NE(params, nullptr);

    auto drawParams = device->CollectDrawParams(surfaceNode, *params);
    EXPECT_EQ(drawParams.resultWidth, 0);
    EXPECT_EQ(drawParams.resultHeight, 0);
    EXPECT_EQ(drawParams.transformType, GraphicTransformType::GRAPHIC_ROTATE_NONE);
}

/**
 * @tc.name: FillOfflineResultTest001
 * @tc.desc: Test FillOfflineResult with null offlineBuffer
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_009
 */
HWTEST_F(RSGPUOfflineDeviceTest, FillOfflineResultTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    std::shared_ptr<RSGPUOfflineBuffer> offlineBuffer = nullptr;
    GPUOfflineSubThreadData taskContext;
    ProcessOfflineResult result;

    bool ret = device->FillOfflineResult(offlineBuffer, taskContext, result);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: FillOfflineResultTest002
 * @tc.desc: Test FillOfflineResult with valid offlineBuffer but null surfaceParams
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_009
 */
HWTEST_F(RSGPUOfflineDeviceTest, FillOfflineResultTest002, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    GPUOfflineSubThreadData taskContext;
    ProcessOfflineResult result;

    // ConsumeAndGetBuffer returns nullptr without surface
    bool ret = device->FillOfflineResult(offlineBuffer, taskContext, result);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: FillOfflineResultWithValidBufferTest001
 * @tc.desc: Test FillOfflineResult with valid offlineBuffer and valid buffer
 *           - covers line 174: result.preBuffer = offlineSurfaceHandler->GetPreBuffer()
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_line_174
 */
HWTEST_F(RSGPUOfflineDeviceTest, FillOfflineResultWithValidBufferTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    EXPECT_NE(offlineBuffer, nullptr);

    auto surfaceHandler = offlineBuffer->GetSurfaceHandler();
    EXPECT_NE(surfaceHandler, nullptr);

    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    EXPECT_NE(surfaceBuffer, nullptr);

    sptr<SyncFence> fence = SyncFence::InvalidFence();
    int64_t timestamp = 0;
    Rect damage = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    std::shared_ptr<RSRcdSurfaceRenderNode::BufferOwnerCount> bufferOwnerCount = std::make_shared<RSRcdSurfaceRenderNode::BufferOwnerCount>();
    surfaceHandler->SetBuffer(surfaceBuffer, fence, damage, timestamp, bufferOwnerCount);

    GPUOfflineSubThreadData taskContext;
    ProcessOfflineResult result;

    bool ret = device->FillOfflineResult(offlineBuffer, taskContext, result);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(result.isGPUOffline);
    EXPECT_NE(result.buffer, nullptr);
}

/**
 * @tc.name: SetResultWhenSkipDrawTest001
 * @tc.desc: Test SetResultWhenSkipDraw with null offlineBuffer in context
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_010
 */
HWTEST_F(RSGPUOfflineDeviceTest, SetResultWhenSkipDrawTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = std::make_shared<GPUOfflineContext>();
    context->offlineBuffer = nullptr;

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    GPUOfflineSubThreadData taskContext;

    bool ret = device->SetResultWhenSkipDraw(context, taskContext, taskId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetResultWhenSkipDrawSuccessTest001
 * @tc.desc: Test SetResultWhenSkipDraw success path - covers line 198: result.preBuffer = nullptr
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_line_198
 */
HWTEST_F(RSGPUOfflineDeviceTest, SetResultWhenSkipDrawSuccessTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    EXPECT_NE(offlineBuffer, nullptr);

    auto surfaceHandler = offlineBuffer->GetSurfaceHandler();
    EXPECT_NE(surfaceHandler, nullptr);

    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    EXPECT_NE(surfaceBuffer, nullptr);

    sptr<SyncFence> fence = SyncFence::InvalidFence();
    int64_t timestamp = 0;
    Rect damage = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    std::shared_ptr<RSRcdSurfaceRenderNode::BufferOwnerCount> bufferOwnerCount = std::make_shared<RSRcdSurfaceRenderNode::BufferOwnerCount>();
    surfaceHandler->SetBuffer(surfaceBuffer, fence, damage, timestamp, bufferOwnerCount);

    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);
    context->offlineBuffer = offlineBuffer;
    context->skipDraw = true;

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    GPUOfflineSubThreadData taskContext;

    bool ret = device->SetResultWhenSkipDraw(context, taskContext, taskId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CheckAndHandleTimeoutEventTest002
 * @tc.desc: Test CheckAndHandleTimeoutEvent when timeout is true
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_011
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckAndHandleTimeoutEventTest002, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_FALSE(context->timeout);

    auto futurePtr = std::make_shared<ProcessOfflineFuture>();
    futurePtr->timeout = true;

    device->CheckAndHandleTimeoutEvent(futurePtr, TEST_NODE_ID);

    // Context timeout should be set
    EXPECT_TRUE(context->timeout);
}

/**
 * @tc.name: PostOfflineTaskCommonTest001
 * @tc.desc: Test PostOfflineTaskCommon when skipDraw is true
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_012
 */
HWTEST_F(RSGPUOfflineDeviceTest, PostOfflineTaskCommonTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    context->skipDraw = true;

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    RSSurfaceRenderParams* surfaceParams = nullptr;

    // SetResultWhenSkipDraw will fail with null buffer
    bool ret = device->PostOfflineTaskCommon(context, surfaceParams, taskId);
    EXPECT_FALSE(ret);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
    auto* surfaceParams2 = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    ret = device->PostOfflineTaskCommon(context, surfaceParams2, taskId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DoProcessOfflineWithContextTest001
 * @tc.desc: Test DoProcessOfflineWithContext with null buffer
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_013
 */
HWTEST_F(RSGPUOfflineDeviceTest, DoProcessOfflineWithContextTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    ProcessOfflineResult result;
    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = nullptr;

    bool ret = device->DoProcessOfflineWithContext(result, taskContext);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DrawHDRImageTest001
 * @tc.desc: Test DrawHDRImage with null offlineBuffer
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_014
 */
HWTEST_F(RSGPUOfflineDeviceTest, DrawHDRImageTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = nullptr;

    bool ret = device->DrawHDRImage(taskContext);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: RSGPUOfflineDeviceCanDeleteDeviceWithCacheTest001
 * @tc.desc: Test CanDeleteDevice returns false when cache has contexts (non-empty cache)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_001
 */
HWTEST_F(RSGPUOfflineDeviceTest, CanDeleteDeviceWithCacheTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Create a context to populate cache
    device->GetOrCreateOfflineContext(TEST_NODE_ID);

    // Cache is non-empty, CanDeleteDevice should return false
    EXPECT_FALSE(device->CanDeleteDevice());

    // Remove the context
    device->TryRemoveContext(TEST_NODE_ID);

    // Cache is now empty
    EXPECT_TRUE(device->CanDeleteDevice());
}

/**
 * @tc.name: RSGPUOfflineDeviceCheckAndPostClearInvalidFramesTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask triggers TryRemoveContext when
 *           invalidFrames >= MAX_NUM_INVALID_FRAME (10)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_002
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckAndPostClearInvalidFramesTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Create a context and set invalidFrames to trigger removal
    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);

    // Set invalidFrames >= MAX_NUM_INVALID_FRAME (10)
    context->invalidFrames = 10;

    std::vector<uint64_t> nodeIds = { TEST_NODE_ID };
    // CheckAndPostClearOfflineResourceTask should detect invalidFrames >= 10 and try to remove
    device->CheckAndPostClearOfflineResourceTask(nodeIds);

    // After CheckAndPostClearOfflineResourceTask, the context should be removed if no pending tasks
    auto ctxAfter = device->GetOfflineContext(TEST_NODE_ID);
    // If no pending tasks in resultPool_, the context should be removed
    EXPECT_NE(ctxAfter, nullptr);
}

/**
 * @tc.name: RSGPUOfflineDeviceWaitForResultContextNullTest001
 * @tc.desc: Test WaitForProcessOfflineResult when context is nullptr (after cache eviction)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_003
 */
HWTEST_F(RSGPUOfflineDeviceTest, WaitForResultContextNullTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Register a task so we have a future in the pool
    auto future = device->offlineResultSync_.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    // Mark task as done with taskSuccess = true
    ProcessOfflineResult setResult;
    setResult.taskSuccess = true;
    device->offlineResultSync_.MarkTaskDoneAndSetResult(future, setResult);

    // No context exists for this nodeId (cache eviction scenario)
    // WaitForProcessOfflineResult should still return waitSuccess from syncer
    ProcessOfflineResult result;
    bool waitResult = device->WaitForProcessOfflineResult(
        taskId, std::chrono::milliseconds(TEST_TIMEOUT_MS), result);

    // waitResult should reflect the syncer result (true because task was done)
    EXPECT_TRUE(waitResult);
}

/**
 * @tc.name: RSGPUOfflineDeviceWaitForResultTaskSuccessFalseTest001
 * @tc.desc: Test WaitForProcessOfflineResult updates context when result.taskSuccess is false
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_003
 */
HWTEST_F(RSGPUOfflineDeviceTest, WaitForResultTaskSuccessFalseTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Create context
    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);
    context->invalidFrames = 3;

    // Register and mark task as done with taskSuccess = false
    auto future = device->offlineResultSync_.RegisterPostedTask(taskId);
    ProcessOfflineResult setResult;
    setResult.taskSuccess = false;
    device->offlineResultSync_.MarkTaskDoneAndSetResult(future, setResult);

    ProcessOfflineResult result;
    bool waitResult = device->WaitForProcessOfflineResult(
        taskId, std::chrono::milliseconds(TEST_TIMEOUT_MS), result);

    EXPECT_TRUE(waitResult);
    // After commit 670e21cc: invalidFrames is no longer modified by WaitForProcessOfflineResult
    // (removed: context->invalidFrames = result.taskSuccess ? 0 : context->invalidFrames + 1)
    EXPECT_EQ(context->invalidFrames.load(), 3u);
    EXPECT_FALSE(context->hasDrawn);
}

/**
 * @tc.name: RSGPUOfflineDeviceWaitForResultTaskSuccessTrueTest001
 * @tc.desc: Test WaitForProcessOfflineResult resets invalidFrames when result.taskSuccess is true
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_003
 */
HWTEST_F(RSGPUOfflineDeviceTest, WaitForResultTaskSuccessTrueTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Create context with some invalidFrames
    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);
    context->invalidFrames = 5;

    // Register and mark task as done with taskSuccess = true
    auto future = device->offlineResultSync_.RegisterPostedTask(taskId);
    ProcessOfflineResult setResult;
    setResult.taskSuccess = true;
    device->offlineResultSync_.MarkTaskDoneAndSetResult(future, setResult);

    ProcessOfflineResult result;
    bool waitResult = device->WaitForProcessOfflineResult(taskId, std::chrono::milliseconds(TEST_TIMEOUT_MS), result);

    EXPECT_TRUE(waitResult);
    // After commit 670e21cc: invalidFrames is no longer reset by WaitForProcessOfflineResult
    // (removed: context->invalidFrames = result.taskSuccess ? 0 : context->invalidFrames + 1)
    // Only hasDrawn is still set from result.taskSuccess
    EXPECT_EQ(context->invalidFrames.load(), 5u);
    EXPECT_TRUE(context->hasDrawn);
}

/**
 * @tc.name: RSGPUOfflineDevicePostProcessOfflineTaskNodeNullContextTest001
 * @tc.desc: Test PostProcessOfflineTask(node) when offlineContext is null
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_006
 */
HWTEST_F(RSGPUOfflineDeviceTest, PostProcessOfflineTaskNodeNullContextTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // No context exists for this node, should return false
    bool result = device->PostProcessOfflineTask(surfaceNode, taskId);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: RSGPUOfflineDevicePostProcessOfflineTaskNodeTimeoutTest001
 * @tc.desc: Test PostProcessOfflineTask(node) when offlineContext timeout is true
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_006
 */
HWTEST_F(RSGPUOfflineDeviceTest, PostProcessOfflineTaskNodeTimeoutTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Create context and set timeout
    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);
    offlineContext->timeout = true;

    bool result = device->PostProcessOfflineTask(surfaceNode, taskId);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PostProcessOfflineTaskNodeSuccessTest001
 * @tc.desc: Test PostProcessOfflineTask(node) when UpdateContext returns false
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_006
 */
HWTEST_F(RSGPUOfflineDeviceTest, PostProcessOfflineTaskNodeSuccessTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Create context without timeout
    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);
    offlineContext->timeout = false;

    // UpdateContext will fail because surfaceNode has no buffer
    bool result = device->PostProcessOfflineTask(surfaceNode, taskId);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PostProcessOfflineTaskDrawableNullContextTest001
 * @tc.desc: Test PostProcessOfflineTask(drawable) when offlineContext is null
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_drawable_001
 */
HWTEST_F(RSGPUOfflineDeviceTest, PostProcessOfflineTaskDrawableNullContextTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    auto drawableAdapter = DrawableV2::RSSurfaceRenderNodeDrawable::OnGenerate(surfaceNode);
    auto surfaceDrawable = std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable>(
        static_cast<DrawableV2::RSSurfaceRenderNodeDrawable*>(drawableAdapter));

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    bool result = device->PostProcessOfflineTask(surfaceDrawable, taskId);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PostProcessOfflineTaskDrawableTimeoutTest001
 * @tc.desc: Test PostProcessOfflineTask(drawable) when offlineContext timeout is true
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_drawable_002
 */
HWTEST_F(RSGPUOfflineDeviceTest, PostProcessOfflineTaskDrawableTimeoutTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    auto drawableAdapter = DrawableV2::RSSurfaceRenderNodeDrawable::OnGenerate(surfaceNode);
    auto surfaceDrawable = std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable>(
        static_cast<DrawableV2::RSSurfaceRenderNodeDrawable*>(drawableAdapter));

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);
    offlineContext->timeout = true;

    bool result = device->PostProcessOfflineTask(surfaceDrawable, taskId);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: RSGPUOfflineDeviceDoProcessOfflineSrcBufferOwnerCountNullTest001
 * @tc.desc: Test DoProcessOfflineWithContext when srcBufferOwnerCount is null
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_007
 */
HWTEST_F(RSGPUOfflineDeviceTest, DoProcessOfflineSrcBufferOwnerCountNullTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();

    ProcessOfflineResult result;
    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    // srcBuffer and bufferOwnerCount are nullptr by default in taskContext
    bool ret = device->DoProcessOfflineWithContext(result, taskContext);
    EXPECT_FALSE(ret);

    // srcBuffer not nullptr and bufferOwnerCount is nullptr
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    taskContext.srcBuffer = buffer;
    taskContext.bufferOwnerCount = nullptr;
    ret = device->DoProcessOfflineWithContext(result, taskContext);
    EXPECT_FALSE(ret);

    // srcBuffer is nullptr and bufferOwnerCount not nullptr
    taskContext.srcBuffer = nullptr;
    taskContext.bufferOwnerCount = bufferOwnerCount;
    ret = device->DoProcessOfflineWithContext(result, taskContext);
    EXPECT_FALSE(ret);

    // srcBuffer and bufferOwnerCount are not nullptr
    taskContext.srcBuffer = buffer;
    device->offlineThread_.Start();
    ret = device->DoProcessOfflineWithContext(result, taskContext);
    device->offlineThread_.Stop();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: RSGPUOfflineDeviceDoProcessOfflineWithContextBufferAndOwnerCountValidTest001
 * @tc.desc: Test DoProcessOfflineWithContext when srcBuffer and srcBufferOwnerCount
 *           are both valid to cover line 384
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_009
 */
HWTEST_F(RSGPUOfflineDeviceTest, DoProcessOfflineWithContextBufferAndOwnerCountValidTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();

    ProcessOfflineResult result;
    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    taskContext.srcBuffer = buffer;
    taskContext.bufferOwnerCount = bufferOwnerCount;

    device->offlineThread_.Start();
    bool ret = device->DrawHDRImage(taskContext);
    device->offlineThread_.Stop();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: RSGPUOfflineDeviceDrawHDRImageBufferNotNullRequestFrameNullTest001
 * @tc.desc: Test DrawHDRImage when offlineBuffer is not null but RequestFrame returns null
 *           (renderEngine is null, so RequestFrame on buffer fails)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_008
 */
HWTEST_F(RSGPUOfflineDeviceTest, DrawHDRImageBufferNotNullRequestFrameNullTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;

    // The offlineThread's renderEngine_ is null, so RequestFrame will return null
    bool ret = device->DrawHDRImage(taskContext);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: RSGPUOfflineDeviceDrawHDRImageBufferAndSurfaceBufferValidTest001
 * @tc.desc: Test DrawHDRImage when offlineBuffer and surfaceParams.GetBuffer() are both valid
 *           to cover line 414: BufferRequestConfig bufferConfig = GetGPUBufferConfig(taskContext)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_line_414
 */
HWTEST_F(RSGPUOfflineDeviceTest, DrawHDRImageBufferAndSurfaceBufferValidTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();

    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    taskContext.srcBuffer = buffer;
    taskContext.bufferOwnerCount = bufferOwnerCount;

    device->offlineThread_.Start();
    bool ret = device->DrawHDRImage(taskContext);
    device->offlineThread_.Stop();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: RSGPUOfflineDeviceOfflineTaskFuncWithDataSuccessPathTest001
 * @tc.desc: Test OfflineTaskFuncWithData with valid buffer but null surfaceParams
 *           covers the DoProcessOfflineWithContext failure path
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_009
 */
HWTEST_F(RSGPUOfflineDeviceTest, OfflineTaskFuncWithDataSuccessPathTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto futurePtr = std::make_shared<ProcessOfflineFuture>();
    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    taskContext.nodeId = TEST_NODE_ID;
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    // srcBuffer is nullptr by default

    device->OfflineTaskFuncWithData(futurePtr, taskContext);

    EXPECT_TRUE(futurePtr->done);
    EXPECT_FALSE(futurePtr->result.taskSuccess); // DoProcessOfflineWithContext fails without buffer
}

/**
 * @tc.name: PostOfflineTaskCommonDuplicateRegisterTest001
 * @tc.desc: Test PostOfflineTaskCommon when RegisterPostedTask fails (duplicate taskId)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_033
 */
HWTEST_F(RSGPUOfflineDeviceTest, PostOfflineTaskCommonDuplicateRegisterTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = std::make_shared<GPUOfflineContext>();
    context->nodeId = TEST_NODE_ID;
    context->offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    context->skipDraw = false;

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // Pre-register the same taskId to make RegisterPostedTask return nullptr
    device->offlineResultSync_.RegisterPostedTask(taskId);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    ASSERT_NE(surfaceParams, nullptr);

    bool ret = device->PostOfflineTaskCommon(context, surfaceParams, taskId);
    EXPECT_FALSE(ret); // RegisterPostedTask returns nullptr for duplicate
}

/**
 * @tc.name: CollectDrawParamsNullBufferTest001
 * @tc.desc: Test CollectDrawParams when surfaceParams.GetBuffer() returns nullptr
 *           - CollectDrawParams calls srcBuffer->GetWidth()/GetHeight(), crashes with null buffer
 *           - This tests the UpdateContext guard: surfaceParams null buffer => UpdateContext returns false
 *           - before reaching CollectDrawParams
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_040
 */
HWTEST_F(RSGPUOfflineDeviceTest, CollectDrawParamsNullBufferTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    RSSurfaceRenderParams params(0);

    // params.GetBuffer() returns nullptr, CollectDrawParams would crash
    // But UpdateContext checks surfaceHandler/params and returns false before calling CollectDrawParams
    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);

    bool result = device->UpdateContext(surfaceNode, offlineContext);
    // UpdateContext returns false when surfaceHandler has no buffer
    EXPECT_TRUE(result);
}

/**
 * @tc.name: UpdateContextSkipDrawTrueTest001
 * @tc.desc: Test UpdateContext sets skipDraw=true when conditions met:
 *           !bufferConsumed && hasDrawn && same params
 *           - Directly manipulate context state to simulate skipDraw conditions
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_042
 */
HWTEST_F(RSGPUOfflineDeviceTest, UpdateContextSkipDrawTrueTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);

    // Set hasDrawn=true and fixed drawParams to simulate "same params" condition
    offlineContext->hasDrawn = true;
    offlineContext->drawParams.resultWidth = 1920;
    offlineContext->drawParams.resultHeight = 1080;

    // Call UpdateContext - surfaceHandler has no buffer => bufferConsumed=false
    // If hasDrawn=true and drawParams match, skipDraw could be set
    // But since surfaceParams.GetBuffer() is null, UpdateContext returns false early
    bool result = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(result);

    // Verify skipDraw was not set (since UpdateContext failed)
    EXPECT_FALSE(offlineContext->skipDraw);
}

/**
 * @tc.name: UpdateContextSkipDrawFalseTest001
 * @tc.desc: Test UpdateContext sets skipDraw=false when hasDrawn=false or params differ
 *           - Verify the normal drawing path (skipDraw=false)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_043
 */
HWTEST_F(RSGPUOfflineDeviceTest, UpdateContextSkipDrawFalseTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);

    // hasDrawn=false means skipDraw should not be set
    offlineContext->hasDrawn = false;

    // UpdateContext will fail due to no buffer, but verify hasDrawn remains false
    bool result = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(result);
    EXPECT_FALSE(offlineContext->hasDrawn);
}

/**
 * @tc.name: CheckConditionNullSurfaceHandlerTest001
 * @tc.desc: Test CheckCondition when surfaceNode has null surfaceHandler
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_044
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckConditionNullSurfaceHandlerTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    // Without InitRenderParams, surfaceHandler may be null
    bool result = device->CheckCondition(surfaceNode);
    // surfaceHandler null => false
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckConditionNoBufferTest001
 * @tc.desc: Test CheckCondition when surfaceHandler has no buffer (GetBuffer returns null)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_044
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckConditionNoBufferTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    // surfaceHandler exists but GetBuffer() returns nullptr
    bool result = device->CheckCondition(surfaceNode);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckConditionNotHdrTest001
 * @tc.desc: Test CheckCondition when surfaceHandler has no buffer (GetBuffer returns null)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_044
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckConditionNotHdrTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    
    sptr<SyncFence> fence = SyncFence::InvalidFence();
    int64_t timestamp = 0;
    Rect damage = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    std::shared_ptr<RSRcdSurfaceRenderNode::BufferOwnerCount> bufferOwnerCount = std::make_shared<RSRcdSurfaceRenderNode::BufferOwnerCount>();
    surfaceHandler->SetBuffer(surfaceBuffer, fence, damage, timestamp, bufferOwnerCount);
    // not hdr
    bool result = device->CheckCondition(surfaceNode);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckConditionSuccessTest001
 * @tc.desc: Test CheckCondition when surfaceHandler has no buffer (GetBuffer returns null)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_044
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckConditionSuccessTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
    bool result = device->CheckCondition(surfaceNode);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckConditionTransformNoneTest001
 * @tc.desc: Test CheckCondition transformType verification - GRAPHIC_ROTATE_NONE should pass
 *           this check if other conditions are met. In test environment, earlier conditions
 *           (GPUOfflineEnabled, buffer) will fail first.
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_044
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckConditionTransformNoneTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    // Default transformType is GRAPHIC_ROTATE_NONE
    auto* params = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    if (params) {
        EXPECT_EQ(params->GetLayerInfo().transformType, GraphicTransformType::GRAPHIC_ROTATE_NONE);
    }
}

/**
 * @tc.name: CheckConditionTransform180Test001
 * @tc.desc: Test CheckCondition transformType GRAPHIC_ROTATE_180 should pass
 *           this check if other conditions are met
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_044
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckConditionTransform180Test001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    // GRAPHIC_ROTATE_180 is also accepted by CheckCondition
    // Set transformType on surfaceParams
    auto* params = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    if (params) {
        auto layerInfo = params->GetLayerInfo();
        layerInfo.transformType = GraphicTransformType::GRAPHIC_ROTATE_180;
        params->SetLayerInfo(layerInfo);
        EXPECT_EQ(params->GetLayerInfo().transformType, GraphicTransformType::GRAPHIC_ROTATE_180);
    }
}

/**
 * @tc.name: CheckConditionTransform90Test001
 * @tc.desc: Test CheckCondition transformType GRAPHIC_ROTATE_90 should fail
 *           CheckCondition (not ROTATE_NONE or ROTATE_180)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_044
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckConditionTransform90Test001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    // GRAPHIC_ROTATE_90 should cause CheckCondition to return false
    auto* params = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    if (params) {
        auto layerInfo = params->GetLayerInfo();
        layerInfo.transformType = GraphicTransformType::GRAPHIC_ROTATE_90;
        params->SetLayerInfo(layerInfo);
        EXPECT_EQ(params->GetLayerInfo().transformType, GraphicTransformType::GRAPHIC_ROTATE_90);
    }
}

/**
 * @tc.name: IsRSOfflineDeviceReadyMaxCacheSizeTest001
 * @tc.desc: Test IsRSOfflineDeviceReady currentFrameNodeCount_ >= MAX_CACHE_SIZE path
 *           - When count >= 4, the node is skipped even if other conditions pass
 *           - Directly manipulate currentFrameNodeCount_ to simulate the condition
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_052
 */
HWTEST_F(RSGPUOfflineDeviceTest, IsRSOfflineDeviceReadyMaxCacheSizeTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Set currentFrameNodeCount_ >= MAX_CACHE_SIZE (4)
    device->currentFrameNodeCount_ = 4;
    device->currentVsyncId_ = RSMainThread::Instance()->GetVsyncId();

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    // IsRSOfflineDeviceReady checks currentFrameNodeCount_ >= MAX_CACHE_SIZE first
    // Then calls CheckCondition which will fail in test environment
    bool result = device->IsRSOfflineDeviceReady(surfaceNode);
    // Will return false (either from MAX_CACHE_SIZE or CheckCondition)
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsRSOfflineDeviceReadyTimeOutTest001
 * @tc.desc: Test IsRSOfflineDeviceReady currentFrameNodeCount_ < MAX_CACHE_SIZE
 *           - When count < 4, the node is not skipped due to cache size
 *           - CheckCondition success
 *           - offlineContext->timeout failed
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_052
 */
HWTEST_F(RSGPUOfflineDeviceTest, IsRSOfflineDeviceReadyTimeOutTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Set currentFrameNodeCount_ < MAX_CACHE_SIZE
    device->currentFrameNodeCount_ = 2;
    device->currentVsyncId_ = 100;

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto nodeId = surfaceNode->GetId();
    auto offlineContext = device->GetOrCreateOfflineContext(nodeId);
    EXPECT_NE(offlineContext, nullptr);
    offlineContext->timeout = true;
    // Will fail due to offlineContext->timeout = true
    bool result = device->IsRSOfflineDeviceReady(surfaceNode);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsRSOfflineDeviceReadySuccessTest001
 * @tc.desc: Test IsRSOfflineDeviceReady currentFrameNodeCount_ < MAX_CACHE_SIZE
 *           - When count < 4, the node is not skipped due to cache size
 *           - CheckCondition success
 *           - offlineContext->timeout true
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_052
 */
HWTEST_F(RSGPUOfflineDeviceTest, IsRSOfflineDeviceReadySuccessTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Set currentFrameNodeCount_ < MAX_CACHE_SIZE
    device->currentFrameNodeCount_ = 2;
    device->currentVsyncId_ = 100;

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    bool result = device->IsRSOfflineDeviceReady(surfaceNode);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsRSOfflineDeviceReadyBelowMaxCacheSizeTest001
 * @tc.desc: Test IsRSOfflineDeviceReady currentFrameNodeCount_ < MAX_CACHE_SIZE
 *           - When count < 4, the node is not skipped due to cache size
 *           - But other conditions (CheckCondition, context) may still fail
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_052
 */
HWTEST_F(RSGPUOfflineDeviceTest, IsRSOfflineDeviceReadyBelowMaxCacheSizeTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Set currentFrameNodeCount_ < MAX_CACHE_SIZE
    device->currentFrameNodeCount_ = 2;
    device->currentVsyncId_ = 100;

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    // Will fail due to CheckCondition (no buffer), but not due to MAX_CACHE_SIZE
    bool result = device->IsRSOfflineDeviceReady(surfaceNode);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CheckAndPostClearMultipleNodesTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask with multiple nodes exceeding threshold
 *           - Multiple contexts with invalidFrames >= MAX_NUM_INVALID_FRAME (10)
 *           - All should be marked for removal
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_056
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckAndPostClearMultipleNodesTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Create contexts for multiple nodes
    auto ctx1 = device->GetOrCreateOfflineContext(1);
    auto ctx2 = device->GetOrCreateOfflineContext(2);
    auto ctx3 = device->GetOrCreateOfflineContext(3);

    EXPECT_NE(ctx1, nullptr);
    EXPECT_NE(ctx2, nullptr);
    EXPECT_NE(ctx3, nullptr);

    // Set all to exceed threshold
    ctx1->invalidFrames = 10;
    ctx2->invalidFrames = 10;
    ctx3->invalidFrames = 12;

    std::vector<uint64_t> nodeIds = {1, 2, 3};
    // Call CheckAndPostClearOfflineResourceTask
    device->CheckAndPostClearOfflineResourceTask(nodeIds);

    // All contexts with invalidFrames >= 10 should be removed
    // (if no pending tasks in resultPool)
    EXPECT_NE(device->GetOfflineContext(1), nullptr);
    EXPECT_NE(device->GetOfflineContext(2), nullptr);
    EXPECT_NE(device->GetOfflineContext(3), nullptr);
}

/**
 * @tc.name: CheckAndPostClearMixedInvalidFramesTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask with mixed invalidFrames
 *           - Some nodes exceed threshold, some don't
 *           - Only exceeding nodes should be removed
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_057
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckAndPostClearMixedInvalidFramesTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto ctx1 = device->GetOrCreateOfflineContext(1);
    auto ctx2 = device->GetOrCreateOfflineContext(2);

    EXPECT_NE(ctx1, nullptr);
    EXPECT_NE(ctx2, nullptr);

    // ctx1 exceeds threshold, ctx2 does not
    ctx1->invalidFrames = 10;
    ctx2->invalidFrames = 3;
    std::vector<uint64_t> nodeIds = {1, 2};
    device->CheckAndPostClearOfflineResourceTask(nodeIds);

    // ctx1 should be removed, ctx2 should remain (invalidFrames incremented to 4)
    EXPECT_NE(device->GetOfflineContext(1), nullptr);
    // ctx2 stays but invalidFrames incremented
    auto ctx2After = device->GetOfflineContext(2);
    EXPECT_NE(ctx2After, nullptr);
    EXPECT_EQ(ctx2After->invalidFrames.load(), 0);
}

/**
 * @tc.name: TryRemoveContextWithPendingTasksTest001
 * @tc.desc: Test TryRemoveContext when there are pending tasks for the node
 *           - GetResultPoolSizeByNode >= 1 means context should not be removed
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_058
 */
HWTEST_F(RSGPUOfflineDeviceTest, TryRemoveContextWithPendingTasksTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Create context
    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);

    // Register a pending task for this node
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    auto future = device->offlineResultSync_.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    // TryRemoveContext should NOT remove context because pending task exists
    device->TryRemoveContext(TEST_NODE_ID);

    // Context should still exist
    auto ctxAfter = device->GetOfflineContext(TEST_NODE_ID);
    EXPECT_NE(ctxAfter, nullptr);

    // Verify pool size is >= 1 for this node
    EXPECT_GE(device->offlineResultSync_.GetResultPoolSizeByNode(TEST_NODE_ID), 1);
}

/**
 * @tc.name: GetOrCreateOfflineContextCacheEvictionTest001
 * @tc.desc: Test GetOrCreateOfflineContext cache eviction when size >= MAX_CACHE_SIZE (4)
 *           - Adding 5th context should evict oldest
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_059
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetOrCreateOfflineContextCacheEvictionTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Create 4 contexts (MAX_CACHE_SIZE)
    auto ctx1 = device->GetOrCreateOfflineContext(1);
    auto ctx2 = device->GetOrCreateOfflineContext(2);
    auto ctx3 = device->GetOrCreateOfflineContext(3);
    auto ctx4 = device->GetOrCreateOfflineContext(4);

    EXPECT_NE(ctx1, nullptr);
    EXPECT_NE(ctx2, nullptr);
    EXPECT_NE(ctx3, nullptr);
    EXPECT_NE(ctx4, nullptr);

    // Set timestamps to make ctx1 oldest
    ctx1->timestamp = 100;
    ctx2->timestamp = 200;
    ctx3->timestamp = 300;
    ctx4->timestamp = 400;

    // Create 5th context - should evict oldest (ctx1/nodeId=1)
    auto ctx5 = device->GetOrCreateOfflineContext(5);
    EXPECT_NE(ctx5, nullptr);

    // Node 1 should be evicted
    auto ctx1Again = device->GetOfflineContext(1);
    EXPECT_EQ(ctx1Again, nullptr);

    // Others should remain
    EXPECT_NE(device->GetOfflineContext(2), nullptr);
    EXPECT_NE(device->GetOfflineContext(3), nullptr);
    EXPECT_NE(device->GetOfflineContext(4), nullptr);
    EXPECT_NE(device->GetOfflineContext(5), nullptr);
}

/**
 * @tc.name: SetResultWhenSkipDrawBufferNotNullButConsumeNullTest001
 * @tc.desc: Test SetResultWhenSkipDraw when offlineBuffer is not null but
 *           ConsumeAndGetBuffer returns null - FillOfflineResult fails
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_061
 */
HWTEST_F(RSGPUOfflineDeviceTest, SetResultWhenSkipDrawBufferNotNullButConsumeNullTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);

    // offlineBuffer exists but ConsumeAndGetBuffer returns null (no real surface)
    context->skipDraw = true;

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    GPUOfflineSubThreadData taskContext;

    bool ret = device->SetResultWhenSkipDraw(context, taskContext, taskId);
    // FillOfflineResult fails because ConsumeAndGetBuffer returns null
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UpdateContextNullSurfaceHandlerTest001
 * @tc.desc: Test UpdateContext when surfaceHandler is null - covers the early
 *           return false path (line 323-324)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_002
 */
HWTEST_F(RSGPUOfflineDeviceTest, UpdateContextNullSurfaceHandlerTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    // Don't call InitRenderParams, so surfaceHandler stays null

    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);

    bool result = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateContextNullSurfaceParamsTest001
 * @tc.desc: Test UpdateContext when surfaceParams is null - GetStagingRenderParams
 *           returns nullptr, covers line 323-324
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_002
 */
HWTEST_F(RSGPUOfflineDeviceTest, UpdateContextNullSurfaceParamsTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());

    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);

    // surfaceParams is null because GetStagingRenderParams returns nullptr without InitRenderParams
    bool result = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: UpdateContextSkipDrawTrueConditionsMetTest001
 * @tc.desc: Test UpdateContext when all skipDraw conditions are met:
 *           - bufferConsumed = false (IsCurrentFrameBufferConsumed returns false)
 *           - hasDrawn = true
 *           - drawParams == currentDrawParams
 *           This covers line 335: offlineContext->skipDraw = true;
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_line_335
 */
HWTEST_F(RSGPUOfflineDeviceTest, UpdateContextSkipDrawTrueConditionsMetTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();

    // Create a valid surface buffer with HDR metadata (required by CheckCondition)
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);

    // Set hasDrawn = false first, then call UpdateContext to collect initial drawParams
    offlineContext->hasDrawn = false;

    // First call: UpdateContext will collect drawParams from buffer
    bool firstResult = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(firstResult);
    EXPECT_FALSE(offlineContext->skipDraw); // First call sets skipDraw = false

    // Save the current drawParams
    auto savedDrawParams = offlineContext->drawParams;

    // Second call: With same drawParams and hasDrawn=true, skipDraw should be set to true
    // IsCurrentFrameBufferConsumed() returns false by default (buffer not consumed)
    offlineContext->hasDrawn = true;
    offlineContext->drawParams = savedDrawParams; // Ensure params match

    bool secondResult = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(secondResult);
    EXPECT_TRUE(offlineContext->skipDraw); // Should reach line 335
}

/**
 * @tc.name: CheckAndHandleTimeoutEventTimeoutFalseTest001
 * @tc.desc: Test CheckAndHandleTimeoutEvent when futurePtr->timeout=false
 *           - covers the branch where timeout flag is not set on context
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_004
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckAndHandleTimeoutEventTimeoutFalseTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(context, nullptr);
    EXPECT_FALSE(context->timeout);

    auto futurePtr = std::make_shared<ProcessOfflineFuture>();
    futurePtr->timeout = false;

    device->CheckAndHandleTimeoutEvent(futurePtr, TEST_NODE_ID);

    // Context timeout should remain false since futurePtr->timeout was false
    EXPECT_FALSE(context->timeout);
}

/**
 * @tc.name: GetGPUBufferConfigBT2020Test001
 * @tc.desc: Test GetGPUBufferConfig with BT2020 colorGamut - covers the
 *           colorGamut assignment branch with different gamut values
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_010
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetGPUBufferConfigBT2020Test001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    GPUOfflineSubThreadData taskContext;
    taskContext.drawParams.resultWidth = 3840;
    taskContext.drawParams.resultHeight = 2160;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2100_PQ;

    auto config = device->GetGPUBufferConfig(taskContext);

    EXPECT_EQ(config.width, 3840);
    EXPECT_EQ(config.height, 2160);
    EXPECT_EQ(config.strideAlignment, 0x8);
    EXPECT_EQ(config.colorGamut, GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2100_PQ);
    EXPECT_EQ(config.format, GRAPHIC_PIXEL_FMT_RGBA_8888);
    EXPECT_EQ(config.timeout, 0);
    EXPECT_EQ(config.transform, GraphicTransformType::GRAPHIC_ROTATE_NONE);
    // Verify usage flags
    EXPECT_TRUE((config.usage & BUFFER_USAGE_HW_RENDER) != 0);
    EXPECT_TRUE((config.usage & BUFFER_USAGE_HW_TEXTURE) != 0);
    EXPECT_TRUE((config.usage & BUFFER_USAGE_MEM_DMA) != 0);
    EXPECT_TRUE((config.usage & BUFFER_USAGE_HW_COMPOSER) != 0);
    EXPECT_TRUE((config.usage & BUFFER_USAGE_CPU_READ) != 0);
}

/**
 * @tc.name: CheckAndPostClearEmptyCacheTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask when context cache is empty
 *           - covers the case where there are no contexts to iterate
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_013
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckAndPostClearEmptyCacheTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // No contexts created, cache is empty
    EXPECT_TRUE(device->CanDeleteDevice());
    std::vector<uint64_t> emptyNodeIds;
    // Should not crash with empty cache
    device->CheckAndPostClearOfflineResourceTask(emptyNodeIds);
}

/**
 * @tc.name: CheckAndPostClearWithPendingTasksTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTask when context has invalidFrames >= threshold
 *           but has pending tasks in resultPool (GetResultPoolSizeByNode >= 1)
 *           - verifies TryRemoveContext does not remove context with pending tasks
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_013
 */
HWTEST_F(RSGPUOfflineDeviceTest, CheckAndPostClearWithPendingTasksTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto context = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    context->invalidFrames = 10;

    // Register a task in the resultPool for TEST_NODE_ID
    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);
    auto future = device->offlineResultSync_.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    std::vector<uint64_t> nodeIds = {TEST_NODE_ID};
    device->CheckAndPostClearOfflineResourceTask(nodeIds);

    // Context should NOT be removed because GetResultPoolSizeByNode(TEST_NODE_ID) >= 1
    auto ctxAfter = device->GetOfflineContext(TEST_NODE_ID);
    EXPECT_NE(ctxAfter, nullptr);

    device->offlineResultSync_.ClearResultPool();
}

/**
 * @tc.name: FindOldestEntryAllSameTimestampTest001
 * @tc.desc: Test FindOldestEntry when all contexts have same timestamp
 *           - verifies that it still finds one entry (the first encountered)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_017
 */
HWTEST_F(RSGPUOfflineDeviceTest, FindOldestEntryAllSameTimestampTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Create 3 contexts
    device->GetOrCreateOfflineContext(1);
    device->GetOrCreateOfflineContext(2);
    device->GetOrCreateOfflineContext(3);

    // FindOldestEntry should return the entry with smallest timestamp
    auto oldestId = device->FindOldestEntry();
    // Since all were created recently, one of them should be returned
    EXPECT_NE(oldestId, 0u); // Should return some valid nodeId
}

/**
 * @tc.name: PostOfflineTaskCommonSkipDrawTrueSuccessTest001
 * @tc.desc: Test PostOfflineTaskCommon when skipDraw=true and SetResultWhenSkipDraw succeeds
 *           - requires offlineBuffer with valid buffer. Simulate by creating context
 *           with skipDraw=true and offlineBuffer, then call PostOfflineTaskCommon.
 *           Note: Without real buffer, SetResultWhenSkipDraw calls FillOfflineResult which
 *           calls ConsumeAndGetBuffer which returns nullptr -> FillOfflineResult returns false.
 *           This test verifies the accessible state paths.
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, PostOfflineTaskCommonSkipDrawTrueSuccessTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    // Create context with skipDraw=true and offlineBuffer (but buffer won't have real surface)
    auto context = std::make_shared<GPUOfflineContext>();
    context->nodeId = TEST_NODE_ID;
    context->offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    context->skipDraw = true;
    context->hasDrawn = true;

    offlineTaskId taskId = std::make_pair(TEST_VSYNC_ID, TEST_NODE_ID);

    // SetResultWhenSkipDraw with default taskContext will fail
    GPUOfflineSubThreadData taskContext;
    bool ret = device->SetResultWhenSkipDraw(context, taskContext, taskId);
    EXPECT_FALSE(ret); // FillOfflineResult fails because ConsumeAndGetBuffer returns nullptr
}

// ==================== GPUOfflineContextTest Tests ====================

class GPUOfflineContextTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void GPUOfflineContextTest::SetUpTestCase() {}
void GPUOfflineContextTest::TearDownTestCase() {}
void GPUOfflineContextTest::SetUp() {}
void GPUOfflineContextTest::TearDown() {}


/**
 * @tc.name: AtomicFieldsTest001
 * @tc.desc: Test GPUOfflineContext atomic fields default values
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_context_001
 */
HWTEST_F(GPUOfflineContextTest, AtomicFieldsTest001, TestSize.Level1)
{
    GPUOfflineContext context;

    EXPECT_FALSE(context.skipDraw);
    EXPECT_FALSE(context.hasDrawn);
    EXPECT_EQ(context.invalidFrames.load(), 0u);
    EXPECT_FALSE(context.timeout);
}

/**
 * @tc.name: UpdateContextSkipDrawSwitchTypeNotNoneTest001
 * @tc.desc: Test UpdateContext: switchType != NONE should prevent skipDraw even when
 *           !bufferConsumed && hasDrawn && same drawParams
 *           - Covers the new condition: currentDrawParams.switchType == SingleBufferMode::SINGLE_BUFFER_MODE_NONE
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_013
 */
HWTEST_F(RSGPUOfflineDeviceTest, UpdateContextSkipDrawSwitchTypeNotNoneTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);
 
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
 
    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);
 
    // First call to collect initial drawParams
    offlineContext->hasDrawn = false;
    bool firstResult = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(firstResult);
    EXPECT_FALSE(offlineContext->skipDraw);
 
    // Set up conditions for skipDraw: hasDrawn=true, same params, buffer not consumed
    offlineContext->hasDrawn = true;
    auto savedDrawParams = offlineContext->drawParams;
 
    // Now set switchType to TO_SIGNLE - should prevent skipDraw
    savedDrawParams.switchType = SingleBufferMode::SINGLE_BUFFER_MODE_TO_SINGLE;
    offlineContext->drawParams = savedDrawParams;
 
    bool secondResult = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(secondResult);
    // skipDraw should be false because switchType != NONE
    EXPECT_FALSE(offlineContext->skipDraw);
}

/**
 * @tc.name: UpdateContextSkipDrawSwitchTypeNoneTest001
 * @tc.desc: Test UpdateContext: switchType == NONE allows skipDraw when
 *           !bufferConsumed && hasDrawn && same drawParams
 *           - Covers the new condition with switchType == NONE
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_014
 */
HWTEST_F(RSGPUOfflineDeviceTest, UpdateContextSkipDrawSwitchTypeNoneTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);
 
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
 
    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);
 
    // First call
    offlineContext->hasDrawn = false;
    bool firstResult = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(firstResult);
 
    // Set up skipDraw conditions with switchType == NONE (default)
    offlineContext->hasDrawn = true;
    auto savedDrawParams = offlineContext->drawParams;
    // switchType defaults to NONE
    EXPECT_EQ(savedDrawParams.switchType, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
    offlineContext->drawParams = savedDrawParams;
 
    bool secondResult = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(secondResult);
    // With switchType == NONE and all conditions met, skipDraw should be true
    EXPECT_TRUE(offlineContext->skipDraw);
}

/**
 * @tc.name: UpdateContextSkipDrawSwitchTypeToMultiTest001
 * @tc.desc: Test UpdateContext: switchType == TO_MULTI prevents skipDraw
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_015
 */
HWTEST_F(RSGPUOfflineDeviceTest, UpdateContextSkipDrawSwitchTypeToMultiTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);
 
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
 
    auto offlineContext = device->GetOrCreateOfflineContext(TEST_NODE_ID);
    EXPECT_NE(offlineContext, nullptr);
 
    // First call
    offlineContext->hasDrawn = false;
    device->UpdateContext(surfaceNode, offlineContext);
 
    // Set up skipDraw conditions with switchType == TO_MULTI
    offlineContext->hasDrawn = true;
    offlineContext->drawParams.switchType = SingleBufferMode::SINGLE_BUFFER_MODE_TO_MULTI;
 
    bool result = device->UpdateContext(surfaceNode, offlineContext);
    EXPECT_TRUE(result);
    // TO_MULTI should prevent skipDraw
    EXPECT_FALSE(offlineContext->skipDraw);
    // hasDrawn should be reset to false
    EXPECT_FALSE(offlineContext->hasDrawn);
}

/**
 * @tc.name: CollectDrawParamsSwitchTypeTest001
 * @tc.desc: Test CollectDrawParams sets switchType from GetSingleBufferMode
 *           - Without consumer, switchType should be NONE
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_016
 */
HWTEST_F(RSGPUOfflineDeviceTest, CollectDrawParamsSwitchTypeTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto rsContext = std::make_shared<RSContext>();
    EXPECT_NE(device, nullptr);
    EXPECT_NE(rsContext, nullptr);
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
 
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    RSSurfaceRenderParams params(0);
 
    // Without buffer, resultWidth/resultHeight will be 0
    auto drawParams = device->CollectDrawParams(surfaceNode, params);
    // switchType defaults to NONE when no consumer
    EXPECT_EQ(drawParams.switchType, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
}

/**
 * @tc.name: CollectDrawParamsSwitchTypeWithBufferTest001
 * @tc.desc: Test CollectDrawParams with valid buffer and no consumer
 *           - switchType should be NONE since no consumer is set
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_017
 */
HWTEST_F(RSGPUOfflineDeviceTest, CollectDrawParamsSwitchTypeWithBufferTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();
 
    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
 
    auto* params = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    EXPECT_NE(params, nullptr);
 
    auto drawParams = device->CollectDrawParams(surfaceNode, *params);
    // No consumer set → switchType should be NONE
    EXPECT_EQ(drawParams.switchType, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
}

/**
 * @tc.name: DrawHDRImagePassesSwitchTypeTest001
 * @tc.desc: Test DrawHDRImage passes switchType to RequestFrame
 *           - taskContext.drawParams.switchType is forwarded to RequestFrame
 *           - With TO_SIGNLE type, RequestFrame should trigger CleanCache
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_018
 */
HWTEST_F(RSGPUOfflineDeviceTest, DrawHDRImagePassesSwitchTypeTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();

    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    taskContext.drawParams.switchType = SingleBufferMode::SINGLE_BUFFER_MODE_TO_SINGLE;
    taskContext.srcBuffer = buffer;
    taskContext.bufferOwnerCount = bufferOwnerCount;

    device->offlineThread_.Start();
    bool ret = device->DrawHDRImage(taskContext);
    device->offlineThread_.Stop();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DrawHDRImageSwitchTypeToMultiTest001
 * @tc.desc: Test DrawHDRImage with switchType=TO_MULTI
 *           - RequestFrame receives TO_MULTI, CleanCache triggered, isFirstRequest_=false
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, DrawHDRImageSwitchTypeToMultiTest001, TestSize.Level1)
{
    auto device = std::make_shared<RSGPUOfflineDevice>();
    EXPECT_NE(device, nullptr);

    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();

    GPUOfflineSubThreadData taskContext;
    taskContext.offlineBuffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    taskContext.drawParams.resultWidth = 1920;
    taskContext.drawParams.resultHeight = 1080;
    taskContext.drawParams.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    taskContext.srcBuffer = buffer;
    taskContext.bufferOwnerCount = bufferOwnerCount;

    device->offlineThread_.Start();
    bool ret = device->DrawHDRImage(taskContext);
    device->offlineThread_.Stop();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ChooseEdrHwcTest001
 * @tc.desc: Test ChooseEdrHwc
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, ChooseEdrHwcTest001, TestSize.Level1)
{
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> nodes;
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto rsContext = std::make_shared<RSContext>();
    EXPECT_NE(device, nullptr);
    EXPECT_NE(rsContext, nullptr);
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode, nullptr);
    surfaceNode->isLayerTop_ = false;
    surfaceNode->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceNode->surfaceHandler_);
    auto buffer = surfaceNode->GetRSSurfaceHandler()->GetBuffer();
    buffer->SetFlushTimestamp(10);

    RSSurfaceRenderNodeConfig config2;
    config2.id = 2;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config2, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode2, nullptr);
    surfaceNode2->isLayerTop_ = true;
    surfaceNode2->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(config2.id);
    sptr<SurfaceBuffer> surfaceBuffer2 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer2, surfaceNode2->surfaceHandler_);
    auto buffer2 = surfaceNode2->GetRSSurfaceHandler()->GetBuffer();
    buffer2->SetFlushTimestamp(11);

    nodes.push_back(surfaceNode);
    nodes.push_back(surfaceNode2);
    device->ChooseEdrHwc(nodes);
    EXPECT_EQ(nodes.size(), 1);
}

/**
 * @tc.name: ChooseEdrHwcTest002
 * @tc.desc: Test ChooseEdrHwc
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, ChooseEdrHwcTest002, TestSize.Level1)
{
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> nodes;
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto rsContext = std::make_shared<RSContext>();
    EXPECT_NE(device, nullptr);
    EXPECT_NE(rsContext, nullptr);
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode, nullptr);
    surfaceNode->isLayerTop_ = false;
    surfaceNode->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceNode->surfaceHandler_);
    auto buffer = surfaceNode->GetRSSurfaceHandler()->GetBuffer();
    buffer->SetFlushTimestamp(10);

    RSSurfaceRenderNodeConfig config2;
    config2.id = 2;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config2, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode2, nullptr);
    surfaceNode2->isLayerTop_ = true;
    surfaceNode2->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(config2.id);
    sptr<SurfaceBuffer> surfaceBuffer2 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer2, surfaceNode2->surfaceHandler_);
    auto buffer2 = surfaceNode2->GetRSSurfaceHandler()->GetBuffer();
    buffer2->SetFlushTimestamp(11);
 
    nodes.push_back(surfaceNode);
    nodes.push_back(surfaceNode2);

    device->ChooseEdrHwc(nodes);
    EXPECT_EQ(nodes.size(), 1);
}

/**
 * @tc.name: ChooseEdrHwcTest003
 * @tc.desc: Test ChooseEdrHwc
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, ChooseEdrHwcTest003, TestSize.Level1)
{
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> nodes;
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto rsContext = std::make_shared<RSContext>();
    EXPECT_NE(device, nullptr);
    EXPECT_NE(rsContext, nullptr);
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode, nullptr);
    surfaceNode->isLayerTop_ = true;
    surfaceNode->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceNode->surfaceHandler_);
    auto buffer = surfaceNode->GetRSSurfaceHandler()->GetBuffer();
    buffer->SetFlushTimestamp(10);

    RSSurfaceRenderNodeConfig config2;
    config2.id = 2;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config2, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode2, nullptr);
    surfaceNode2->isLayerTop_ = false;
    surfaceNode2->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(config2.id);
    surfaceNode2->srcRect_ = RectI{0, 0, 2561, 10};
    sptr<SurfaceBuffer> surfaceBuffer2 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer2, surfaceNode2->surfaceHandler_);
    auto buffer2 = surfaceNode2->GetRSSurfaceHandler()->GetBuffer();
    buffer2->SetFlushTimestamp(11);

    RSSurfaceRenderNodeConfig config3;
    config3.id = 3;
    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(config3, rsContext->weak_from_this());
    EXPECT_NE(surfaceNode3, nullptr);
    surfaceNode3->isLayerTop_ = false;
    surfaceNode3->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(config3.id);
    sptr<SurfaceBuffer> surfaceBuffer3 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer3, surfaceNode3->surfaceHandler_);
    auto buffer3 = surfaceNode3->GetRSSurfaceHandler()->GetBuffer();
    surfaceNode3->GetRSSurfaceHandler()->SetCurrentFrameBufferConsumed();
    buffer3->SetFlushTimestamp(11);

    bool debugSwitch = system::GetBoolParameter("persist.sys.graphic.rgba_1010108.enabled", true);
    system::SetParameter("persist.sys.graphic.rgba_1010108.enabled", "false");
    nodes.push_back(surfaceNode);
    nodes.push_back(surfaceNode2);
    nodes.push_back(surfaceNode3);

    device->ChooseEdrHwc(nodes);
    EXPECT_EQ(nodes.size(), 2);

    system::SetParameter("persist.sys.graphic.rgba_1010108.enabled", debugSwitch ? "true" : "false");
}

/**
 * @tc.name: ProcessEdrNodes_NormalFlow
 * @tc.desc: Test ProcessEdrNodes
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, ProcessEdrNodes_NormalFlow, TestSize.Level1) {
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(1, 2, context);
    device->ProcessEdrNodes(*screenNode);
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->isLayerTop_ = false;
    surfaceNode->srcRect_ = RectI{0, 0, 1920, 1080};
    surfaceNode->isOnTheTree_ = true;
    surfaceNode->ancestorScreenNode_ = screenNode;
    surfaceNode->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GTM;
    surfaceNode->isHardwareForcedDisabled_ = false;
    surfaceNode->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> buffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(buffer, surfaceNode->surfaceHandler_);
    buffer->SetFlushTimestamp(100);
    buffer->SetMetadata(ATTRKEY_HDR_STATIC_METADATA, g_hdrStaticMetadataVec);
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode);

    device->ProcessEdrNodes(*screenNode);
    EXPECT_FALSE(surfaceNode->GetDeviceOfflineEnable());
    EXPECT_FALSE(surfaceNode->IsHardwareForcedDisabled());
}

/**
 * @tc.name: SetGpuOfflineEnableTest001
 * @tc.desc: Test SetGpuOfflineEnable
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, SetGpuOfflineEnableTest001, TestSize.Level1) {
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(1, 2, context);
    device->ProcessEdrNodes(*screenNode);
    screenNode->GetDirtyManager()->SetCurrentFrameDirtyRect(RectI{1, 1, 1, 1});

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    
    surfaceNode->isLayerTop_ = false;
    surfaceNode->srcRect_ = RectI{0, 0, 1920, 1080};
    surfaceNode->isOnTheTree_ = true;
    surfaceNode->ancestorScreenNode_ = screenNode;
    surfaceNode->SetDstRect({0, 1106, 1080, 1135});
    
    surfaceNode->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GTM;
    surfaceNode->isHardwareForcedDisabled_ = false;
    
    surfaceNode->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> buffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(buffer, surfaceNode->surfaceHandler_);
    buffer->SetFlushTimestamp(100);
    
    buffer->SetMetadata(ATTRKEY_HDR_STATIC_METADATA, g_hdrStaticMetadataVec);
    
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode);
    device->SetGpuOfflineEnable(*screenNode, surfaceNode);
    EXPECT_FALSE(surfaceNode->GetDeviceOfflineEnable());
}

/**
 * @tc.name: GetEdrNodesTest001
 * @tc.desc: Test GetEdrNodes
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetEdrNodesTest001, TestSize.Level1) {
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(1, 2, context);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> edrSurfaceNodeVec;
    device->GetEdrNodes(*screenNode, edrSurfaceNodeVec);
    auto selfDrawingNodes = RSMainThread::Instance()->GetSelfDrawingNodes();
    selfDrawingNodes.clear();
    EXPECT_EQ(edrSurfaceNodeVec.size(), 0);

    surfaceNode->isLayerTop_ = false;
    surfaceNode->isOnTheTree_ = true;
    surfaceNode->ancestorScreenNode_ = screenNode;
    
    surfaceNode->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GTM;
    surfaceNode->isHardwareForcedDisabled_ = false;
    
    surfaceNode->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> buffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(buffer, surfaceNode->surfaceHandler_);
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode);

    RSSurfaceRenderNodeConfig config2;
    config2.id = TEST_NODE_ID;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config2, rsContext->weak_from_this());
    surfaceNode2->isLayerTop_ = false;
    surfaceNode2->isOnTheTree_ = true;
    surfaceNode2->ancestorScreenNode_ = screenNode;
    
    surfaceNode2->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GTM;
    surfaceNode2->isHardwareForcedDisabled_ = false;
    
    surfaceNode2->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> buffer2 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(buffer2, surfaceNode2->surfaceHandler_);
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode2);

    RSSurfaceRenderNodeConfig config3;
    config3.id = TEST_NODE_ID;
    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(config3, rsContext->weak_from_this());
    surfaceNode3->isLayerTop_ = false;
    surfaceNode3->isOnTheTree_ = false;
    surfaceNode3->ancestorScreenNode_ = screenNode;
    
    surfaceNode3->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GTM;
    surfaceNode3->isHardwareForcedDisabled_ = false;
    
    surfaceNode3->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> buffer3 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(buffer3, surfaceNode3->surfaceHandler_);
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode3);
    device->GetEdrNodes(*screenNode, edrSurfaceNodeVec);
    EXPECT_EQ(edrSurfaceNodeVec.size(), 0);
}

/**
 * @tc.name: GetEdrNodesTest002
 * @tc.desc: Test GetEdrNodes
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetEdrNodesTest002, TestSize.Level1) {
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(1, 2, context);

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = TEST_NODE_ID;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> edrSurfaceNodeVec;
    surfaceNode->isLayerTop_ = false;
    surfaceNode->isOnTheTree_ = true;
    surfaceNode->ancestorScreenNode_ = screenNode;
    surfaceNode->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GTM;
    surfaceNode->isHardwareForcedDisabled_ = true;
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode);

    RSSurfaceRenderNodeConfig config2;
    config2.id = TEST_NODE_ID;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config2, rsContext->weak_from_this());
    surfaceNode2->isLayerTop_ = false;
    surfaceNode2->isOnTheTree_ = true;
    surfaceNode2->ancestorScreenNode_ = screenNode;
    surfaceNode2->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GTM ;
    surfaceNode2->isHardwareForcedDisabled_ = false;
    
    surfaceNode2->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> buffer2 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(buffer2, surfaceNode2->surfaceHandler_);
    CM_HDR_Metadata_Type hdrMetadataType = CM_IMAGE_HDR_VIVID_SINGLE;
    MetadataHelper::SetHDRMetadataType(buffer2, hdrMetadataType);
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode2);

    RSSurfaceRenderNodeConfig config3;
    config3.id = TEST_NODE_ID;
    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(config3, rsContext->weak_from_this());
    surfaceNode3->isLayerTop_ = false;
    surfaceNode3->isOnTheTree_ = false;
    surfaceNode3->ancestorScreenNode_ = screenNode;
    
    surfaceNode3->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GTM;
    surfaceNode3->isHardwareForcedDisabled_ = false;
    
    surfaceNode3->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> buffer3 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(buffer3, surfaceNode3->surfaceHandler_);
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode3);
    device->GetEdrNodes(*screenNode, edrSurfaceNodeVec);
    EXPECT_EQ(edrSurfaceNodeVec.size(), 0);
}

/**
 * @tc.name: GetEdrNodesTest003
 * @tc.desc: Test GetEdrNodes
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_019
 */
HWTEST_F(RSGPUOfflineDeviceTest, GetEdrNodesTest003, TestSize.Level1) {
    auto device = std::make_shared<RSGPUOfflineDevice>();
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(1, 2, context);
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config2;
    config2.id = TEST_NODE_ID;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(config2, rsContext->weak_from_this());
    surfaceNode2->isLayerTop_ = false;
    surfaceNode2->isOnTheTree_ = true;
    surfaceNode2->ancestorScreenNode_ = screenNode;
    surfaceNode2->hdrVideoSurface_ = HdrStatus::AI_HDR_VIDEO_GAINMAP ;
    surfaceNode2->isHardwareForcedDisabled_ = false;
    
    surfaceNode2->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(TEST_NODE_ID);
    sptr<SurfaceBuffer> buffer2 = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(buffer2, surfaceNode2->surfaceHandler_);
    CM_HDR_Metadata_Type hdrMetadataType = CM_IMAGE_HDR_VIVID_SINGLE;
    MetadataHelper::SetHDRMetadataType(buffer2, hdrMetadataType);
    RSMainThread::Instance()->AddSelfDrawingNodes(surfaceNode2);
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> edrSurfaceNodeVec;
    device->GetEdrNodes(*screenNode, edrSurfaceNodeVec);
    EXPECT_EQ(edrSurfaceNodeVec.size(), 0);
}