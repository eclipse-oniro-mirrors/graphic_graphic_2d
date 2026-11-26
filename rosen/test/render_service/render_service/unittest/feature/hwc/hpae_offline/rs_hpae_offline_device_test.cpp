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
#include "event_handler.h"

#include <vector>
#include <cmath>
#include <future>
#include <parameters.h>

#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_screen_render_params.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_device.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_process_syncer.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_thread_manager.h"
#include "feature/hwc/hpae_offline/rs_offline_processor.h"
#include "feature/round_corner_display/rs_rcd_surface_render_node.h"
#include "pipeline/rs_surface_handler.h"
#ifdef HETERO_HDR_ENABLE
#include "rs_hetero_hdr_manager.h"
#endif

using namespace testing;
using namespace testing::ext;
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;

namespace OHOS::Rosen {

namespace {
constexpr size_t MAX_NUM_INVALID_FRAME_NUM = 2;
constexpr int32_t BUFFER_WIDTH = 1000;
constexpr int32_t BUFFER_HEIGHT = 1000;
std::vector<uint8_t> g_hdrStaticMetadataVec = {10, 215, 35, 63, 195, 245, 168, 62, 154, 153, 153, 62,
    154, 153, 25, 63, 154, 153, 25, 62, 143, 194, 117, 61, 55, 26, 160, 62, 176, 114, 168, 62, 0, 0,
    122, 68, 0, 0, 0, 0, 0, 64, 24, 68, 0, 64, 24, 68};
}

class RSHpaeOfflineDeviceTest : public ::testing::Test {
public:
    void SetUp() override
    {
        processor_ = std::make_unique<RSHpaeOfflineDevice>();
    }

    void TearDown() override
    {
        processor_ = nullptr;
    }

    void LoadNullPreProcessHandle()
    {
        processor_->preProcessHandle_ = nullptr;
        processor_->preProcessFunc_ = nullptr;
        processor_->getConfigFunc_ = nullptr;
        processor_->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return 0; });
        processor_->deInitOfflineFunc_ = static_cast<OHOS::Rosen::DeInitOfflineResourceFunc>([]() {});
        processor_->getFenceFunc_ =
        static_cast<OHOS::Rosen::GetFenceFunc>([](int32_t &outputFence) {
            outputFence = -1;
            return 0;
        });
    }

    sptr<SurfaceBuffer> CreateSurfaceBuffer(int32_t width, int32_t height)
    {
        sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
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

    void SetRSSurfaceHandlerBuffer(sptr<SurfaceBuffer> &surfaceBuffer, std::shared_ptr<RSSurfaceHandler> surfaceHandler)
    {
        surfaceBuffer->SetMetadata(ATTRKEY_HDR_STATIC_METADATA, g_hdrStaticMetadataVec);
        sptr<SyncFence> fence = SyncFence::InvalidFence();
        int64_t timestamp = 0;
        Rect damage = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
        std::shared_ptr<RSRcdSurfaceRenderNode::BufferOwnerCount> bufferOwnerCount =
            std::make_shared<RSRcdSurfaceRenderNode::BufferOwnerCount>();
        surfaceHandler->SetBuffer(surfaceBuffer, fence, damage, timestamp, bufferOwnerCount);
    }

    std::unique_ptr<RSHpaeOfflineDevice> processor_;
};

/**
 * @tc.name: GetOutputConfig
 * @tc.desc: Verify function GetOutputConfig
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, GetOutputConfig001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    auto ret = processor_->GetOutputConfig(context, renderNode);
    EXPECT_FALSE(ret);
    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            return 0;
        });
    ret = processor_->GetOutputConfig(context, renderNode);
    EXPECT_TRUE(ret);
    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 0;
            outputInfo.bufferConfig.height = 0;
            return 0;
        });
    ret = processor_->GetOutputConfig(context, renderNode);
    EXPECT_FALSE(ret);
    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 0;
            return 0;
        });
    ret = processor_->GetOutputConfig(context, renderNode);
    EXPECT_FALSE(ret);
    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 0;
            outputInfo.bufferConfig.height = 128;
            return 0;
        });
    ret = processor_->GetOutputConfig(context, renderNode);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsRSOfflineDeviceReady
 * @tc.desc: Verify function IsRSOfflineDeviceReady
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, IsRSOfflineDeviceReady001, TestSize.Level0)
{
    LoadNullPreProcessHandle();

    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    renderNode->InitRenderParams();

    // offlineProcessorEnabled false
    OHOS::system::SetParameter("rosen.hpaeoffline.enabled", "0");
    auto ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_FALSE(ret);
    OHOS::system::SetParameter("rosen.hpaeoffline.enabled", "1");

    // surfaceNode is null
    std::shared_ptr<RSSurfaceRenderNode> nullNode = nullptr;
    ret = processor_->IsRSOfflineDeviceReady(nullNode);
    EXPECT_FALSE(ret);

    // loadSuccess_ false
    processor_->loadSuccess_ = false;
    ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_FALSE(ret);
    processor_->loadSuccess_ = true;

    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    // timeout
    context->timeout = true;
    ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_FALSE(ret);
    context->timeout = false;

    processor_->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return 0; });
    processor_->preProcessHandle_ = reinterpret_cast<void*>(0xFF);
    context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(context, nullptr);
    ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_FALSE(ret);

    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            return 0;
        });
    ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_FALSE(ret);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_TRUE(ret);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    context->preAllocBufferSucc = true;
    ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: IsRSOfflineDeviceReady002
 * @tc.desc: Verify IsRSOfflineDeviceReady with context pool full (returns nullptr)
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, IsRSOfflineDeviceReady002, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    processor_->loadSuccess_ = true;
    processor_->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return 0; });

    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    processor_->hpaeOfflineContextPool_.clear();
    constexpr size_t MAX_CACHE_SIZE = 2;
    for (size_t i = 0; i < MAX_CACHE_SIZE; i++) {
        NodeId tempId = i + 100;
        auto tempNode = std::make_shared<RSSurfaceRenderNode>(tempId);
        auto context = processor_->GetOrCreateOfflineContext(tempNode);
        ASSERT_NE(context, nullptr);
    }
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_EQ(context, nullptr);
    auto ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsRSOfflineDeviceReady003
 * @tc.desc: Verify IsRSOfflineDeviceReady with updateContext failed.
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, IsRSOfflineDeviceReady003, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    processor_->loadSuccess_ = true;

    // UpdateContext
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(1);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    context->contextType = OfflineContextType::AI2020;
    context->timeout = false;
    auto surfaceHandler = renderNode->GetRSSurfaceHandler();
    surfaceHandler = nullptr;
    auto ret = processor_->IsRSOfflineDeviceReady(renderNode);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CheckAndPostPreAllocBuffersTask001
 * @tc.desc: Verify function CheckAndPostPreAllocBuffersTask with valid context
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, CheckAndPostPreAllocBuffersTask001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            outputInfo.bufferConfig.format = 12;
            outputInfo.bufferConfig.usage = 1800;
            outputInfo.bufferConfig.timeout = 100;
            return 0;
        });

    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(context, nullptr);

    context->preAllocBufferSucc = true;
    processor_->CheckAndPostPreAllocBuffersTask(context);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(context->preAllocBufferSucc);

    context->preAllocBufferSucc = false;
    processor_->CheckAndPostPreAllocBuffersTask(context);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(context->preAllocBufferSucc);

    offlineTaskId taskId = { 100, 123 };
    auto future = processor_->offlineResultSync_.RegisterPostedTask(taskId);
    processor_->CheckAndPostPreAllocBuffersTask(context);
    EXPECT_FALSE(context->preAllocBufferSucc);
}

/**
 * @tc.name: InitHpaeOfflineResource001
 * @tc.desc: Verify InitHpaeOfflineResource posts task to initialize
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, InitHpaeOfflineResource001, TestSize.Level0)
{
    LoadNullPreProcessHandle();

    processor_->initOfflineFunc_ = nullptr;
    processor_->InitHpaeOfflineResource();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_FALSE(processor_->isInitOfflineFuncSucc_);

    processor_->isInitOfflineFuncSucc_ = false;
    processor_->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return -1; });
    processor_->InitHpaeOfflineResource();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_FALSE(processor_->isInitOfflineFuncSucc_);

    processor_->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return 0; });
    processor_->InitHpaeOfflineResource();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(processor_->isInitOfflineFuncSucc_);
}

/**
 * @tc.name: InitHpaeOfflineResource002
 * @tc.desc: Verify InitHpaeOfflineResource posts task to initialize
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, InitHpaeOfflineResource002, TestSize.Level0)
{
    LoadNullPreProcessHandle();

    processor_->isInitOfflineFuncSucc_ = false;
    processor_->InitHpaeOfflineResource();
    processor_->isInitOfflineFuncSucc_ = true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(processor_->isInitOfflineFuncSucc_);
}

/**
 * @tc.name: GetOfflineProcessInput001
 * @tc.desc: Verify GetOfflineProcessInput when RequestSurfaceBuffer returns nullptr
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, GetOfflineProcessInput001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            outputInfo.bufferConfig.format = 12;
            outputInfo.bufferConfig.usage = 1800;
            outputInfo.bufferConfig.timeout = 100;
            outputInfo.bufferConfig.colorGamut = 4;
            outputInfo.outRect = {.x = 10, .y = 20, .w = 100, .h = 200};
            return 0;
        });

    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    processor_->GetOutputConfig(context, surfaceNode1);

    context->contextType = OfflineContextType::AI2020;
    HpaeOfflineSubThreadData taskData;
    taskData.contextType = context->contextType;
    taskData.offlineRect = context->offlineRect;
    taskData.layerConfig = context->layerConfig;
    taskData.offlineLayer = context->offlineLayer;

    OfflineProcessInputInfo inputInfo;
    sptr<SurfaceBuffer> dstSurfaceBuffer = nullptr;
    int32_t releaseFence = -1;

    taskData.srcBuffer = surfaceParams->GetBuffer();
    taskData.bufferOwnerCount = surfaceParams->GetBufferOwnerCount();
    taskData.acquireFence = surfaceParams->GetAcquireFence();
    taskData.srcRect = surfaceParams->GetLayerInfo().srcRect;
    taskData.transformType = surfaceParams->GetLayerInfo().transformType;

    auto ret = processor_->GetOfflineProcessInput(inputInfo, dstSurfaceBuffer, releaseFence, taskData);
    EXPECT_TRUE(ret);

    // Replace buffer with an unallocated one so GetBufferHandle() returns nullptr
    sptr<SurfaceBuffer> nullHandleBuffer = SurfaceBuffer::Create();
    taskData.srcBuffer = nullHandleBuffer;
    ret = processor_->GetOfflineProcessInput(inputInfo, dstSurfaceBuffer, releaseFence, taskData);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetOfflineProcessInput002
 * @tc.desc: Verify GetOfflineProcessInput when RequestSurfaceBuffer returns nullptr
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, GetOfflineProcessInput002, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            outputInfo.bufferConfig.format = 12;
            outputInfo.bufferConfig.usage = 1800;
            outputInfo.bufferConfig.timeout = 100;
            outputInfo.bufferConfig.colorGamut = 4;
            outputInfo.outRect = {.x = 10, .y = 20, .w = 100, .h = 200};
            return 0;
        });

    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    processor_->GetOutputConfig(context, surfaceNode1);

    context->contextType = OfflineContextType::SCALE;
    HpaeOfflineSubThreadData taskData;
    taskData.contextType = context->contextType;
    taskData.offlineRect = context->offlineRect;
    taskData.layerConfig = context->layerConfig;
    taskData.offlineLayer = context->offlineLayer;

    OfflineProcessInputInfo inputInfo;
    sptr<SurfaceBuffer> dstSurfaceBuffer = nullptr;
    int32_t releaseFence = -1;

    taskData.srcBuffer = surfaceParams->GetBuffer();
    taskData.bufferOwnerCount = surfaceParams->GetBufferOwnerCount();
    taskData.acquireFence = surfaceParams->GetAcquireFence();
    taskData.srcRect = surfaceParams->GetLayerInfo().srcRect;
    taskData.transformType = surfaceParams->GetLayerInfo().transformType;

    auto ret = processor_->GetOfflineProcessInput(inputInfo, dstSurfaceBuffer, releaseFence, taskData);
    EXPECT_TRUE(ret);

    surfaceBuffer->SetCropMetadata({0, 0, 100, 100});
    ret = processor_->GetOfflineProcessInput(inputInfo, dstSurfaceBuffer, releaseFence, taskData);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DoProcessOffline001
 * @tc.desc: Test DoProcessOffline
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, DoProcessOffline001, TestSize.Level1)
{
    LoadNullPreProcessHandle();
    ProcessOfflineResult result;
    HpaeOfflineSubThreadData taskContext;
    // srcSurfaceBuffer null
    bool ret = processor_->DoProcessOffline(result, taskContext);
    EXPECT_FALSE(ret);

    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            outputInfo.bufferConfig.format = 12;
            outputInfo.bufferConfig.usage = 1800;
            outputInfo.bufferConfig.timeout = 100;
            outputInfo.bufferConfig.colorGamut = 4;
            outputInfo.outRect = {.x = 10, .y = 20, .w = 100, .h = 200};
            return 0;
        });

    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
    
    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    processor_->GetOutputConfig(context, surfaceNode1);

    
    context->contextType = OfflineContextType::AI2020;
    HpaeOfflineSubThreadData taskData;
    taskData.contextType = context->contextType;
    taskData.offlineRect = context->offlineRect;
    taskData.layerConfig = context->layerConfig;
    taskData.offlineLayer = context->offlineLayer;
    taskData.srcBuffer = surfaceParams->GetBuffer();
    taskData.bufferOwnerCount = nullptr;
    taskData.acquireFence = surfaceParams->GetAcquireFence();
    taskData.srcRect = surfaceParams->GetLayerInfo().srcRect;
    taskData.transformType = surfaceParams->GetLayerInfo().transformType;

    // preProcessFunc_ null
    ret = processor_->DoProcessOffline(result, taskData);
    EXPECT_FALSE(ret);

    taskData.bufferOwnerCount = surfaceParams->GetBufferOwnerCount();
    ret = processor_->DoProcessOffline(result, taskData);
    EXPECT_FALSE(ret);

    taskData.acquireFence = nullptr;
    ret = processor_->DoProcessOffline(result, taskData);
    EXPECT_FALSE(ret);

    // getFenceFunc_ null
    processor_->preProcessFunc_ =
        static_cast<OHOS::Rosen::ProcessOfflineFunc>([](const OfflineProcessInputInfo &) { return 0; });
    processor_->getFenceFunc_ = nullptr;
    ret = processor_->DoProcessOffline(result, taskData);
    EXPECT_TRUE(ret);

    processor_->getFenceFunc_ =
        static_cast<OHOS::Rosen::GetFenceFunc>([](int32_t &outputFence) {
            outputFence = -1;
            return 0;
        });
    ret = processor_->DoProcessOffline(result, taskData);
    EXPECT_TRUE(ret);

    // GetOfflineProcessInput false: layerConfig with zero size causes RequestSurfaceBuffer to return null
    taskData.layerConfig = {
        .width = 0,
        .height = 0,
        .strideAlignment = 0x08, // default stride is 8 Bytes.
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_HW_COMPOSER | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_CPU_READ,
        .timeout = 0,
    };
    ret = processor_->DoProcessOffline(result, taskData);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: PostProcessOfflineTask001
 * @tc.desc: Verify PostProcessOfflineTask
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, PostProcessOfflineTask001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = 12345;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);
    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    offlineTaskId taskId = std::make_pair(100, 12345);

    processor_->loadSuccess_ = false;
    bool ret = processor_->PostProcessOfflineTask(surfaceNode, taskId);
    EXPECT_FALSE(ret);

    processor_->loadSuccess_ = true;
    processor_->isInitOfflineFuncSucc_ = false;
    ret = processor_->PostProcessOfflineTask(surfaceNode, taskId);
    EXPECT_FALSE(ret);

    processor_->isInitOfflineFuncSucc_ = true;
    ret = processor_->PostProcessOfflineTask(surfaceNode, taskId);
    EXPECT_FALSE(ret);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode);
    context->timeout = true;
    ret = processor_->PostProcessOfflineTask(surfaceNode, taskId);
    EXPECT_FALSE(ret);

    context->timeout = false;
    ret = processor_->PostProcessOfflineTask(surfaceNode, taskId);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: PostProcessOfflineTask002
 * @tc.desc: Verify PostProcessOfflineTask
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, PostProcessOfflineTask002, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    offlineTaskId taskId = std::make_pair(100, 12345);
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(12345);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    context->contextType = OfflineContextType::AI2020;
    processor_->loadSuccess_ = true;
    processor_->isInitOfflineFuncSucc_ = true;
    context->timeout = false;
    auto surfaceHandler = renderNode->GetRSSurfaceHandler();
    surfaceHandler = nullptr;
    auto ret = processor_->PostProcessOfflineTask(renderNode, taskId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: PostProcessOfflineTask003
 * @tc.desc: Verify PostProcessOfflineTask
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, PostProcessOfflineTask003, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    auto rsContext = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config;
    config.id = 123456;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
    surfaceNode->InitRenderParams();

    auto surfaceHandler = surfaceNode->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto drawableAdapter = DrawableV2::RSSurfaceRenderNodeDrawable::OnGenerate(surfaceNode);
    auto surfaceDrawable = std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable>(
        static_cast<DrawableV2::RSSurfaceRenderNodeDrawable*>(drawableAdapter));
    offlineTaskId taskId = std::make_pair(101, 123456);

    processor_->loadSuccess_ = false;
    bool ret = processor_->PostProcessOfflineTask(surfaceDrawable, taskId);
    EXPECT_FALSE(ret);

    processor_->loadSuccess_ = true;
    processor_->isInitOfflineFuncSucc_ = false;
    ret = processor_->PostProcessOfflineTask(surfaceDrawable, taskId);
    EXPECT_FALSE(ret);

    processor_->isInitOfflineFuncSucc_ = true;
    ret = processor_->PostProcessOfflineTask(surfaceDrawable, taskId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetNodeArsrTag001
 * @tc.desc: Verify SetNodeArsrTag returns early when offlineNodeIds is empty
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, SetNodeArsrTag001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id1 = 101;
    auto node1 = std::make_shared<RSSurfaceRenderNode>(id1);
    node1->InitRenderParams();
    std::vector<uint64_t> nodeIds = { id1 };
    processor_->SetNodeArsrTag(nodeIds);
    EXPECT_TRUE(node1->GetArsrTag());
}

/**
 * @tc.name: SetNodeArsrTag002
 * @tc.desc: Verify SetNodeArsrTag sets ArsrTag to false for valid nodes
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, SetNodeArsrTag002, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
    nodeMap.renderNodeMap_.clear();

    NodeId id1 = 101;
    NodeId id2 = 102;
    auto node1 = std::make_shared<RSSurfaceRenderNode>(id1);
    auto node2 = std::make_shared<RSSurfaceRenderNode>(id2);
    node1->InitRenderParams();
    node2->InitRenderParams();
    nodeMap.RegisterRenderNode(node1);
    nodeMap.RegisterRenderNode(node2);

    std::vector<uint64_t> nodeIds = { id1, id2 };
    processor_->SetNodeArsrTag(nodeIds);
    EXPECT_FALSE(node1->GetArsrTag());
    EXPECT_FALSE(node2->GetArsrTag());
}

/**
 * @tc.name: CloseOfflineHandle001
 * @tc.desc: Verify CloseOfflineHandle sets loadSuccess_ to false
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, CloseOfflineHandle001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    processor_->loadSuccess_ = true;
    processor_->preProcessHandle_ = reinterpret_cast<void*>(0xFF);
    processor_->CloseOfflineHandle("TestSymbol", "ENOENT");
    EXPECT_EQ(processor_->preProcessHandle_, nullptr);
}

/**
 * @tc.name: GetOrCreateOfflineContextTest001
 * @tc.desc: Verify GetOrCreateOfflineContext creates new context for new node
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, GetOrCreateOfflineContextTest001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(context, nullptr);
    EXPECT_EQ(processor_->GetContextPoolSize(), 1);
    auto context2 = processor_->GetOrCreateOfflineContext(renderNode);
    EXPECT_EQ(context, context2);
    EXPECT_EQ(processor_->GetContextPoolSize(), 1);
}

/**
 * @tc.name: GetOrCreateOfflineContextTest002
 * @tc.desc: Verify GetOrCreateOfflineContext returns nullptr when pool is full
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, GetOrCreateOfflineContextTest002, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    constexpr size_t MAX_CACHE_SIZE = 2;
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> nodes;
    for (size_t i = 0; i < MAX_CACHE_SIZE; i++) {
        NodeId id = i + 100;
        auto node = std::make_shared<RSSurfaceRenderNode>(id);
        auto ctx = processor_->GetOrCreateOfflineContext(node);
        ASSERT_NE(ctx, nullptr);
        nodes.push_back(node);
    }
    EXPECT_EQ(processor_->GetContextPoolSize(), MAX_CACHE_SIZE);
    NodeId newId = 999;
    auto newNode = std::make_shared<RSSurfaceRenderNode>(newId);
    auto context = processor_->GetOrCreateOfflineContext(newNode);
    EXPECT_EQ(context, nullptr);
}

/**
 * @tc.name: GetOrCreateOfflineContextTest003
 * @tc.desc: Verify GetOrCreateOfflineContext creates new context for new node
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, GetOrCreateOfflineContextTest003, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);
    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    ASSERT_NE(context, nullptr);
    EXPECT_EQ(processor_->GetContextPoolSize(), 1);
}

/**
 * @tc.name: GetOfflineContext001
 * @tc.desc: Verify GetOfflineContext returns existing context
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, GetOfflineContext001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto createdContext = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(createdContext, nullptr);
    auto retrievedContext = processor_->GetOfflineContext(id);
    EXPECT_EQ(createdContext, retrievedContext);
    auto nonExistentContext = processor_->GetOfflineContext(999);
    EXPECT_EQ(nonExistentContext, nullptr);
}

/**
 * @tc.name: GetContextPoolSize001
 * @tc.desc: Verify GetContextPoolSize returns correct count
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, GetContextPoolSize001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    EXPECT_EQ(processor_->GetContextPoolSize(), 0);
    for (int i = 0; i < 3; i++) {
        NodeId id = i + 100;
        auto node = std::make_shared<RSSurfaceRenderNode>(id);
        (void)processor_->GetOrCreateOfflineContext(node);
    }
    EXPECT_EQ(processor_->GetContextPoolSize(), 2);
}

/**
 * @tc.name: UpdateContext001
 * @tc.desc: Verify UpdateContext returns true for SCALE context type
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, UpdateContext001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(context, nullptr);
    context->contextType = OfflineContextType::SCALE;
    auto ret = processor_->UpdateContext(renderNode, context);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: UpdateContext002
 * @tc.desc: Verify UpdateContext returns true for AI2020 context type
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, UpdateContext002, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    ASSERT_NE(context, nullptr);
    context->contextType = OfflineContextType::AI2020;
    context->hasDrawn = true;
    auto ret = processor_->UpdateContext(surfaceNode1, context);
    EXPECT_TRUE(ret);

    context->hasDrawn = false;
    ret = processor_->UpdateContext(surfaceNode1, context);
    EXPECT_TRUE(ret);

    surfaceNode1->surfaceHandler_ = nullptr;
    ret = processor_->UpdateContext(surfaceNode1, context);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UpdateContext003
 * @tc.desc: Verify UpdateContext sets skipDraw for AI2020 when buffer not consumed
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, UpdateContext003, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(context, nullptr);
    context->contextType = OfflineContextType::AI2020;
    context->hasDrawn = true;
    auto surfaceHandler = renderNode->GetRSSurfaceHandler();
    auto ret = processor_->UpdateContext(renderNode, context);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(context->skipDraw);
}

/**
 * @tc.name: FillOfflineResultTest001
 * @tc.desc: Verify FillOfflineResult fills ProcessOfflineResult correctly
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, FillOfflineResultTest001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    ProcessOfflineResult result;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(1);

    HpaeOfflineSubThreadData taskData;
    taskData.contextType = OfflineContextType::SCALE;
    taskData.offlineLayer = std::make_shared<RSHpaeOfflineLayer>("DeviceOfflineLayer_SCALE", INVALID_NODEID);
    taskData.layerConfig.width = 128;
    taskData.layerConfig.height = 128;
    taskData.offlineRect = {5, 10, 50, 100};
    auto offlineSurfaceHandler = taskData.offlineLayer->GetMutableRSSurfaceHandler();
    auto ret = processor_->FillOfflineResult(result, taskData, offlineSurfaceHandler);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: FillOfflineResultTest001
 * @tc.desc: Verify FillOfflineResult fills ProcessOfflineResult correctly
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, FillOfflineResultTest002, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    ASSERT_NE(context, nullptr);

    RSLayerInfo layerInfo;
    layerInfo.srcRect = {10, 20, 100, 200};
    surfaceParams->SetLayerInfo(layerInfo);

    context->layerConfig.width = 128;
    context->layerConfig.height = 128;
    context->offlineRect = {5, 10, 50, 100};
    context->contextType = OfflineContextType::AI2020;

    HpaeOfflineSubThreadData taskData;
    taskData.nodeId = context->nodeId;
    taskData.layerConfig = context->layerConfig;
    taskData.offlineRect = context->offlineRect;
    taskData.offlineLayer = context->offlineLayer;
    taskData.contextType = context->contextType;
    taskData.lastProcessSuccess = context->lastProcessSuccess;
    taskData.srcRect = surfaceParams->GetLayerInfo().srcRect;
    taskData.transformType = surfaceParams->GetLayerInfo().transformType;

    ProcessOfflineResult result;
    auto offlineSurfaceHandler = taskData.offlineLayer->GetMutableRSSurfaceHandler();
    auto ret = processor_->FillOfflineResult(result, taskData, offlineSurfaceHandler);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: FlushAndReleaseOfflineLayer001
 * @tc.desc: Verify FlushAndReleaseOfflineLayer releases buffer correctly
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, FlushAndReleaseOfflineLayer001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    processor_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId nodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            return 0;
        });

    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(context, nullptr);

    HpaeOfflineSubThreadData taskData;
    taskData.offlineLayer = context->offlineLayer;
    taskData.layerConfig = context->layerConfig;

    int32_t releaseFence = -1;
    sptr<SurfaceBuffer> dstSurfaceBuffer =
        taskData.offlineLayer->RequestSurfaceBuffer(taskData.layerConfig, releaseFence);
    ASSERT_EQ(dstSurfaceBuffer, nullptr);

    processor_->FlushAndReleaseOfflineLayer(dstSurfaceBuffer, taskData);
}

/**
 * @tc.name: CheckAndHandleTimeoutEvent001
 * @tc.desc: Verify CheckAndHandleTimeoutEvent sets context timeout
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, CheckAndHandleTimeoutEvent001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto future = std::make_shared<ProcessOfflineFuture>();
    future->timeout = true;
    std::shared_ptr<ProcessOfflineFuture> futurePtr = future;

    ASSERT_EQ(processor_->GetOfflineContext(id), nullptr);
    processor_->CheckAndHandleTimeoutEvent(futurePtr, id);

    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(context, nullptr);
    processor_->CheckAndHandleTimeoutEvent(futurePtr, id);
    EXPECT_TRUE(context->timeout);
}

/**
 * @tc.name: CheckAndHandleTimeoutEvent002
 * @tc.desc: Verify CheckAndHandleTimeoutEvent does nothing when not timeout
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, CheckAndHandleTimeoutEvent002, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id = 1;
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(id);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    ASSERT_NE(context, nullptr);
    context->timeout = false;

    auto future = std::make_shared<ProcessOfflineFuture>();
    future->timeout = false;
    std::shared_ptr<ProcessOfflineFuture> futurePtr = future;
    processor_->CheckAndHandleTimeoutEvent(futurePtr, id);
    EXPECT_FALSE(context->timeout);
}

/**
 * @tc.name: ClearOfflineContext001
 * @tc.desc: Verify ClearOfflineContext clears invalid frames contexts
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, ClearOfflineContext001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    NodeId id1 = 1;
    NodeId id2 = 2;
    auto node1 = std::make_shared<RSSurfaceRenderNode>(id1);
    auto node2 = std::make_shared<RSSurfaceRenderNode>(id2);
    auto context1 = processor_->GetOrCreateOfflineContext(node1);
    auto context2 = processor_->GetOrCreateOfflineContext(node2);
    EXPECT_EQ(processor_->GetContextPoolSize(), 2);

    context2->invalidFrames = MAX_NUM_INVALID_FRAME_NUM;
    std::vector<uint64_t> offlineNodeIds = {id1};
    processor_->ClearOfflineContext(offlineNodeIds);
    EXPECT_EQ(processor_->GetContextPoolSize(), 1);
}

/**
 * @tc.name: WaitForProcessOfflineResult001
 * @tc.desc: Verify WaitForProcessOfflineResult returns false when not loaded
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, WaitForProcessOfflineResult001, TestSize.Level0)
{
    LoadNullPreProcessHandle();
    auto device = std::make_shared<RSHpaeOfflineDevice>();
    device->loadSuccess_ = false;
    offlineTaskId taskId = { 100, 123 };
    ProcessOfflineResult result;
    auto ret = device->WaitForProcessOfflineResult(taskId, std::chrono::milliseconds(100), result);
    EXPECT_FALSE(ret);

    device->loadSuccess_ = true;
    // Register a task so we have a future in the pool
    auto future = device->offlineResultSync_.RegisterPostedTask(taskId);
    EXPECT_NE(future, nullptr);

    // Mark task as done with taskSuccess = true
    ProcessOfflineResult setResult;
    setResult.taskSuccess = true;
    device->offlineResultSync_.MarkTaskDoneAndSetResult(future, setResult);
    ret = device->WaitForProcessOfflineResult(taskId, std::chrono::milliseconds(100), result);
    EXPECT_TRUE(ret);

    auto node1 = std::make_shared<RSSurfaceRenderNode>(123);
    auto context1 = device->GetOrCreateOfflineContext(node1);
    ret = device->WaitForProcessOfflineResult(taskId, std::chrono::milliseconds(100), result);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: PostOfflineTaskCommonTest001
 * @tc.desc: Verify SPostOfflineTaskCommonTest is skipDraw.
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, PostOfflineTaskCommonTest001, TestSize.Level1)
{
    LoadNullPreProcessHandle();
    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    context->skipDraw = true;
    context->contextType = OfflineContextType::AI2020;

    offlineTaskId taskId = std::make_pair(100, 100);

    bool ret = processor_->PostOfflineTaskCommon(context, surfaceParams, taskId);
    EXPECT_FALSE(ret);

    surfaceParams = nullptr;
    ret = processor_->PostOfflineTaskCommon(context, surfaceParams, taskId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: PostOfflineTaskCommonTest002
 * @tc.desc: Verify PostOfflineTaskCommonTest is not skipDraw.
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, PostOfflineTaskCommonTest002, TestSize.Level1)
{
    LoadNullPreProcessHandle();
    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    offlineTaskId taskId = std::make_pair(100, 100);
    processor_->offlineResultSync_.RegisterPostedTask(taskId);

    bool ret = processor_->PostOfflineTaskCommon(context, surfaceParams, taskId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetResultWhenSkipDrawTest001
 * @tc.desc: Verify SetResultWhenSkipDraw.
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, SetResultWhenSkipDrawTest001, TestSize.Level1)
{
    LoadNullPreProcessHandle();
    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    offlineTaskId taskId = std::make_pair(100, 100);

    auto offlineSurfaceHandler = context->offlineLayer->GetMutableRSSurfaceHandler();
    SetRSSurfaceHandlerBuffer(surfaceBuffer, offlineSurfaceHandler);

    HpaeOfflineSubThreadData taskData;
    taskData.nodeId = context->nodeId;
    taskData.layerConfig = context->layerConfig;
    taskData.offlineRect = context->offlineRect;
    taskData.offlineLayer = context->offlineLayer;
    taskData.contextType = context->contextType;
    taskData.lastProcessSuccess = context->lastProcessSuccess;
    taskData.srcBuffer = surfaceParams->GetBuffer();
    taskData.bufferOwnerCount = surfaceParams->GetBufferOwnerCount();
    taskData.acquireFence = surfaceParams->GetAcquireFence();
    taskData.srcRect = surfaceParams->GetLayerInfo().srcRect;
    taskData.transformType = surfaceParams->GetLayerInfo().transformType;

    bool ret = processor_->SetResultWhenSkipDraw(context, taskData, taskId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: SetResultWhenSkipDrawTest002
 * @tc.desc: Test SetResultWhenSkipDraw with null offlineBuffer
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, SetResultWhenSkipDrawTest002, TestSize.Level1)
{
    LoadNullPreProcessHandle();
    offlineTaskId taskId = std::make_pair(100, 12345);
    auto renderNode = std::make_shared<RSSurfaceRenderNode>(12345);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    auto offlineSurfaceHandler = context->offlineLayer->GetMutableRSSurfaceHandler();
    offlineSurfaceHandler = nullptr;
    HpaeOfflineSubThreadData taskData;
    taskData.nodeId = context->nodeId;
    taskData.layerConfig = context->layerConfig;
    taskData.offlineRect = context->offlineRect;
    taskData.offlineLayer = context->offlineLayer;
    taskData.contextType = context->contextType;
    taskData.lastProcessSuccess = context->lastProcessSuccess;
    bool ret = processor_->SetResultWhenSkipDraw(context, taskData, taskId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: OfflineTaskFuncTest001
 * @tc.desc: Test OfflineTaskFuncTest with context
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, OfflineTaskFuncTest001, TestSize.Level1)
{
    LoadNullPreProcessHandle();
    auto rsContext1 = std::make_shared<RSContext>();
    RSSurfaceRenderNodeConfig config1;
    config1.id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(config1, rsContext1->weak_from_this());
    surfaceNode1->InitRenderParams();

    auto surfaceHandler = surfaceNode1->GetRSSurfaceHandler();
    sptr<SurfaceBuffer> surfaceBuffer = CreateSurfaceBuffer(BUFFER_WIDTH, BUFFER_HEIGHT);
    SetRSSurfaceHandlerBuffer(surfaceBuffer, surfaceHandler);

    auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetStagingRenderParams().get());
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 888u;
    Rect damageRect = {0, 0, BUFFER_WIDTH, BUFFER_HEIGHT};
    surfaceParams->SetBuffer(surfaceBuffer, bufferOwnerCount, damageRect);

    auto future = std::make_shared<ProcessOfflineFuture>();
    future->timeout = true;
    std::shared_ptr<ProcessOfflineFuture> futurePtr = future;

    auto context = processor_->GetOrCreateOfflineContext(surfaceNode1);
    context->lastProcessSuccess = false;

    HpaeOfflineSubThreadData taskData;
    taskData.nodeId = 1;
    taskData.offlineRect = {5, 10, 50, 100};
    taskData.offlineLayer = std::make_shared<RSHpaeOfflineLayer>("DeviceOfflineLayer_TEST", INVALID_NODEID);
    taskData.contextType = OfflineContextType::SCALE;
    taskData.lastProcessSuccess = context->lastProcessSuccess;
    taskData.srcBuffer = surfaceParams->GetBuffer();
    taskData.bufferOwnerCount = surfaceParams->GetBufferOwnerCount();
    taskData.acquireFence = surfaceParams->GetAcquireFence();
    taskData.srcRect = surfaceParams->GetLayerInfo().srcRect;
    taskData.transformType = surfaceParams->GetLayerInfo().transformType;

    processor_->OfflineTaskFunc(futurePtr, taskData);
    EXPECT_FALSE(context->lastProcessSuccess);
}

/**
 * @tc.name: CheckAndPostClearOfflineResourceTaskTest001
 * @tc.desc: Test CheckAndPostClearOfflineResourceTaskTest001
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, CheckAndPostClearOfflineResourceTaskTest001, TestSize.Level1)
{
    LoadNullPreProcessHandle();
    processor_->loadSuccess_ = true;
    processor_->isInitOfflineFuncSucc_ = true;

    std::vector<uint64_t> emptyNodeIds;
    processor_->hpaeOfflineContextPool_.clear();
    processor_->CheckAndPostClearOfflineResourceTask(emptyNodeIds);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(processor_->isInitOfflineFuncSucc_);

    processor_->isInitOfflineFuncSucc_ = true;
    std::vector<uint64_t> nodeIds = { 1 };
    processor_->CheckAndPostClearOfflineResourceTask(nodeIds);
    EXPECT_TRUE(processor_->isInitOfflineFuncSucc_);

    auto renderNode = std::make_shared<RSSurfaceRenderNode>(1);
    auto context = processor_->GetOrCreateOfflineContext(renderNode);
    processor_->CheckAndPostClearOfflineResourceTask(nodeIds);
    EXPECT_TRUE(processor_->isInitOfflineFuncSucc_);
}

/**
 * @tc.name: ISOfflineDeviceEnableTest001
 * @tc.desc: Test ISOfflineDeviceEnableTest001
 * @tc.type: FUNC
 * @tc.require: issuesIBT79X
 */
HWTEST_F(RSHpaeOfflineDeviceTest, ISOfflineDeviceEnableTest001, TestSize.Level1)
{
    LoadNullPreProcessHandle();
    auto context = std::make_shared<RSHpaeOfflineContext>(OfflineContextType::AI2020);
    auto ret = processor_->IsOfflineDeviceEnable(context);
    EXPECT_TRUE(ret);

#ifdef HETERO_HDR_ENABLE
    RSHeteroHDRManager::Instance().needClearBufferAndMHC_ = true;
    ret = processor_->IsOfflineDeviceEnable(context);
    EXPECT_FALSE(ret);
    RSHeteroHDRManager::Instance().needClearBufferAndMHC_ = false;
#endif
}

// ==================== RSHpaeOfflineContextTest Tests ====================

class RSHpaeOfflineContextTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSHpaeOfflineContextTest::SetUpTestCase() {}
void RSHpaeOfflineContextTest::TearDownTestCase() {}
void RSHpaeOfflineContextTest::SetUp() {}
void RSHpaeOfflineContextTest::TearDown() {}

/**
 * @tc.name: RSHpaeOfflineContextScaleConstructorTest001
 * @tc.desc: Test RSHpaeOfflineContext constructor with SCALE type
 * @tc.type: FUNC
 * @tc.require: issue_hpae_offline_ctx_001
 */
HWTEST_F(RSHpaeOfflineContextTest, RSHpaeOfflineContextScaleConstructorTest001, TestSize.Level1)
{
    auto context1 = std::make_shared<RSHpaeOfflineContext>(OfflineContextType::SCALE);
    EXPECT_NE(context1, nullptr);
    EXPECT_EQ(context1->contextType, OfflineContextType::SCALE);
    EXPECT_NE(context1->offlineLayer, nullptr);
    EXPECT_EQ(context1->maxInvalidFrames.load(), MAX_NUM_INVALID_FRAME_NUM);

    auto context_2 = std::make_shared<RSHpaeOfflineContext>(OfflineContextType::AI2020);
    EXPECT_NE(context_2, nullptr);
    EXPECT_EQ(context_2->contextType, OfflineContextType::AI2020);
    EXPECT_NE(context_2->offlineLayer, nullptr);
    EXPECT_EQ(context_2->maxInvalidFrames.load(), MAX_NUM_INVALID_FRAME_NUM);
    EXPECT_TRUE(context_2->preAllocBufferSucc);

    auto context_3 = std::make_shared<RSHpaeOfflineContext>(OfflineContextType::INVALID);
    EXPECT_NE(context_3, nullptr);
    EXPECT_EQ(context_3->contextType, OfflineContextType::INVALID);
}
} // namespace OHOS::Rosen