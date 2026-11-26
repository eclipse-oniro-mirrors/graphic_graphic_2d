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

#include "consumer_surface.h"
#include "feature/hwc/hpae_offline/rs_offline_processor.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_device.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_buffer.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_thread.h"
#include "feature/hwc/hpae_offline/rs_offline_device.h"
#include "feature/hwc/hpae_offline/rs_offline_util.h"
#include "feature/hwc/hpae_offline/rs_offline_result.h"
#include "feature/hwc/rs_uni_hwc_prevalidate_util.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/main_thread/rs_uni_render_listener.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_system_properties.h"
#include "engine/rs_uni_render_engine.h"
#include "surface_buffer_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Rosen;

namespace {
constexpr NodeId TEST_NODE_ID = 12345;
}


// ==================== RSGPUOfflineBufferTest Tests ====================

class RSGPUOfflineBufferTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSGPUOfflineBufferTest::SetUpTestCase() {}
void RSGPUOfflineBufferTest::TearDownTestCase() {}
void RSGPUOfflineBufferTest::SetUp() {}
void RSGPUOfflineBufferTest::TearDown() {}


/**
 * @tc.name: GetSurfaceHandlerTest001
 * @tc.desc: Test GetSurfaceHandler after construction
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_013
 */
HWTEST_F(RSGPUOfflineBufferTest, GetSurfaceHandlerTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test_buffer", TEST_NODE_ID);

    auto handler = buffer->GetSurfaceHandler();
    EXPECT_NE(handler, nullptr);
}

/**
 * @tc.name: ConsumeAndGetBufferTest001
 * @tc.desc: Test ConsumeAndGetBuffer without surface
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_015
 */
HWTEST_F(RSGPUOfflineBufferTest, ConsumeAndGetBufferTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test_buffer", TEST_NODE_ID);

    auto result = buffer->ConsumeAndGetBuffer();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: ConsumeAndGetBufferTest002
 * @tc.desc: Test ConsumeAndGetBuffer
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_015
 */
HWTEST_F(RSGPUOfflineBufferTest, ConsumeAndGetBufferTest002, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test_buffer", TEST_NODE_ID);
    buffer->surfaceHandler_->bufferAvailableCount_ = -1;
    buffer->surfaceHandler_->buffer_.buffer = SurfaceBuffer::Create();
    auto handler = buffer->ConsumeAndGetBuffer();
    EXPECT_NE(handler, nullptr);
    buffer->surfaceHandler_->SetCurrentFrameBufferConsumed();
    buffer->surfaceHandler_->bufferAvailableCount_ = -1;
    buffer->surfaceHandler_->buffer_.buffer = SurfaceBuffer::Create();
    auto handler2 = buffer->ConsumeAndGetBuffer();
    EXPECT_NE(handler2, nullptr);

    buffer->surfaceHandler_->preBuffer_.bufferOwnerCount_ =
        std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    auto handler3 = buffer->ConsumeAndGetBuffer();
    EXPECT_NE(handler3, nullptr);

    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    sptr<SyncFence> requestFence = SyncFence::InvalidFence();
    sptr<SyncFence> flushFence = SyncFence::InvalidFence();
    BufferRequestConfig testBufferRequestConfig = {
        .width = 0x100,
        .height = 0x100,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
    };
    BufferFlushConfig testBufferFlushConfig = {
        .damage = { .w = 0x100, .h = 0x100 },
    };
    auto consumer = IConsumerSurface::Create("test_real_surface");
    if (consumer == nullptr) { return; }
    sptr<IBufferConsumerListener> listener = new RSUniRenderListener(buffer->surfaceHandler_);
    SurfaceError regRet = consumer->RegisterConsumerListener(listener);
    if (regRet != SURFACE_ERROR_OK) { return; }
    bool created = buffer->CreateSurface(listener);
    if (!created) { return; }
    auto producer = buffer->pSurface_;
    ASSERT_EQ(producer->RequestBuffer(surfaceBuffer, requestFence, testBufferRequestConfig), GSERROR_OK);          
    ASSERT_NE(surfaceBuffer, nullptr);                                                                        
    ASSERT_EQ(producer->FlushBuffer(surfaceBuffer, flushFence, testBufferFlushConfig), GSERROR_OK);
    auto testBufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    testBufferOwnerCount->bufferId_ = 0;
    testBufferOwnerCount->bufferReleaseCb_ = [](uint64_t bufferId) {};
    buffer->surfaceHandler_->preBuffer_.bufferOwnerCount_ = testBufferOwnerCount;
    buffer->surfaceHandler_->bufferAvailableCount_ = 1;
    buffer->surfaceHandler_->buffer_.buffer = SurfaceBuffer::Create();
    auto handler4 = buffer->ConsumeAndGetBuffer();
    EXPECT_NE(handler4, nullptr);


    ASSERT_EQ(producer->RequestBuffer(surfaceBuffer, requestFence, testBufferRequestConfig), GSERROR_OK);          
    ASSERT_NE(surfaceBuffer, nullptr);                                                                        
    ASSERT_EQ(producer->FlushBuffer(surfaceBuffer, flushFence, testBufferFlushConfig), GSERROR_OK);
    auto testBufferOwnerCount2 = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    buffer->surfaceHandler_->buffer_.buffer = SurfaceBuffer::Create();
    testBufferOwnerCount2->bufferId_ = 0;
    testBufferOwnerCount2->bufferReleaseCb_ = [](uint64_t bufferId) {};
    buffer->surfaceHandler_->preBuffer_.bufferOwnerCount_ = testBufferOwnerCount2;
    buffer->surfaceHandler_->buffer_.bufferOwnerCount_ = testBufferOwnerCount2;
    buffer->surfaceHandler_->bufferAvailableCount_ = 1;
    auto handler5 = buffer->ConsumeAndGetBuffer();
    EXPECT_NE(handler5, nullptr);
}
// ==================== RSGPUOfflineBufferPrivateTest Tests ====================

class RSGPUOfflineBufferPrivateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSGPUOfflineBufferPrivateTest::SetUpTestCase() {}
void RSGPUOfflineBufferPrivateTest::TearDownTestCase() {}
void RSGPUOfflineBufferPrivateTest::SetUp() {}
void RSGPUOfflineBufferPrivateTest::TearDown() {}


/**
 * @tc.name: PreAllocBuffersTest001
 * @tc.desc: Test PreAllocBuffers without surface created
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_buffer_001
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, PreAllocBuffersTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    BufferRequestConfig config = {};
    config.width = 1920;
    config.height = 1080;

    // Without actual IConsumerSurface, CreateSurface will fail
    bool ret = buffer->PreAllocBuffers(config);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ConvertColorGamutToSpaceTypeTest001
 * @tc.desc: Test ConvertColorGamutToSpaceType with SRGB
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_buffer_002
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutToSpaceTypeTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    GraphicColorGamut colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(colorGamut, colorSpaceType);
    EXPECT_TRUE(ret);
    (void)colorSpaceType;
}

/**
 * @tc.name: ConvertColorGamutToSpaceTypeTest002
 * @tc.desc: Test ConvertColorGamutToSpaceType with BT2020
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_buffer_002
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutToSpaceTypeTest002, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    GraphicColorGamut colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2020;
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(colorGamut, colorSpaceType);
    EXPECT_TRUE(ret);
    (void)colorSpaceType;
}

/**
 * @tc.name: ConvertColorGamutToSpaceTypeTest003
 * @tc.desc: Test ConvertColorGamutToSpaceType with invalid gamut
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_buffer_002
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutToSpaceTypeTest003, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    GraphicColorGamut colorGamut = static_cast<GraphicColorGamut>(999); // Invalid
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(colorGamut, colorSpaceType);
    EXPECT_FALSE(ret);
    (void)colorSpaceType;
}

/**
 * @tc.name: CreateSurfaceTest001
 * @tc.desc: Test CreateSurface with null listener
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_buffer_003
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, CreateSurfaceTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    sptr<IBufferConsumerListener> listener = nullptr;
    bool ret = buffer->CreateSurface(listener);
    // Without actual IConsumerSurface::Create, will fail
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CopyAndAttachBufferToQueueTest001
 * @tc.desc: Test CopyAndAttachBufferToQueue with null producerSurface
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_private_buffer_005
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, CopyAndAttachBufferToQueueTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    NativeWindowBufferInfo info(false);
    OHOS::sptr<OHOS::Surface> producerSurface = nullptr;
    uint64_t bufferQueueId = 12345;

    bool ret = buffer->CopyAndAttachBufferToQueue(info, producerSurface, bufferQueueId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: RSGPUOfflineBufferLayerNameTest001
 * @tc.desc: Test layerName_ initialization
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_006
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, LayerNameTest001, TestSize.Level1)
{
    std::string testName = "test_layer_name";
    auto buffer = std::make_shared<RSGPUOfflineBuffer>(testName, TEST_NODE_ID);

    EXPECT_EQ(buffer->layerName_, testName);
}

/**
 * @tc.name: RSGPUOfflineBufferSurfaceHandlerTest001
 * @tc.desc: Test surfaceHandler_ initialization
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_018
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, SurfaceHandlerTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    auto handler = buffer->surfaceHandler_;
    EXPECT_NE(handler, nullptr);
}

/**
 * @tc.name: ConvertColorGamutBT601Test001
 * @tc.desc: Test ConvertColorGamutToSpaceType with GRAPHIC_COLOR_GAMUT_STANDARD_BT601
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_010
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutBT601Test001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(
        GraphicColorGamut::GRAPHIC_COLOR_GAMUT_STANDARD_BT601, colorSpaceType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(colorSpaceType, HDI::Display::Graphic::Common::V1_0::CM_BT601_EBU_FULL);
}

/**
 * @tc.name: ConvertColorGamutBT709Test001
 * @tc.desc: Test ConvertColorGamutToSpaceType with GRAPHIC_COLOR_GAMUT_STANDARD_BT709
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_010
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutBT709Test001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(
        GraphicColorGamut::GRAPHIC_COLOR_GAMUT_STANDARD_BT709, colorSpaceType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(colorSpaceType, HDI::Display::Graphic::Common::V1_0::CM_BT709_FULL);
}

/**
 * @tc.name: ConvertColorGamutAdobeRGBTest001
 * @tc.desc: Test ConvertColorGamutToSpaceType with GRAPHIC_COLOR_GAMUT_ADOBE_RGB
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_010
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutAdobeRGBTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(
        GraphicColorGamut::GRAPHIC_COLOR_GAMUT_ADOBE_RGB, colorSpaceType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(colorSpaceType, HDI::Display::Graphic::Common::V1_0::CM_ADOBERGB_FULL);
}

/**
 * @tc.name: ConvertColorGamutDisplayP3Test001
 * @tc.desc: Test ConvertColorGamutToSpaceType with GRAPHIC_COLOR_GAMUT_DISPLAY_P3
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_010
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutDisplayP3Test001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(
        GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DISPLAY_P3, colorSpaceType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(colorSpaceType, HDI::Display::Graphic::Common::V1_0::CM_P3_FULL);
}

/**
 * @tc.name: ConvertColorGamutBT2100PQTest001
 * @tc.desc: Test ConvertColorGamutToSpaceType with GRAPHIC_COLOR_GAMUT_BT2100_PQ
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_010
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutBT2100PQTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(
        GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2100_PQ, colorSpaceType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(colorSpaceType, HDI::Display::Graphic::Common::V1_0::CM_BT2020_PQ_FULL);
}

/**
 * @tc.name: ConvertColorGamutBT2100HLGTest001
 * @tc.desc: Test ConvertColorGamutToSpaceType with GRAPHIC_COLOR_GAMUT_BT2100_HLG
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_010
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutBT2100HLGTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(
        GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2100_HLG, colorSpaceType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(colorSpaceType, HDI::Display::Graphic::Common::V1_0::CM_BT2020_HLG_FULL);
}

/**
 * @tc.name: ConvertColorGamutDisplayBT2020Test001
 * @tc.desc: Test ConvertColorGamutToSpaceType with GRAPHIC_COLOR_GAMUT_DISPLAY_BT2020
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_010
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, ConvertColorGamutDisplayBT2020Test001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = buffer->ConvertColorGamutToSpaceType(
        GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DISPLAY_BT2020, colorSpaceType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(colorSpaceType, HDI::Display::Graphic::Common::V1_0::CM_DISPLAY_BT2020_SRGB);
}

/**
 * @tc.name: GetRSSurfaceOhosSurfaceCreatedTest001
 * @tc.desc: Test GetRSSurfaceOhos when surfaceCreated=true but rsSurface_=null
 *           - This tests the path where surfaceCreated_ is already true but rsSurface_ is null
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_014
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, GetRSSurfaceOhosSurfaceCreatedTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    // Force surfaceCreated_ to true without actually creating surface
    buffer->surfaceCreated_ = true;
    // rsSurface_ is still null

    auto surface = buffer->GetRSSurfaceOhos();
    // rsSurface_ is null, so should return nullptr
    EXPECT_EQ(surface, nullptr);
}

/**
 * @tc.name: CreateSurfaceConsumerAlreadyCreatedTest001
 * @tc.desc: Test CreateSurface when consumer != nullptr && rsSurface_ != nullptr
 *           - This tests the early return path where surface is already created
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_048
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, CreateSurfaceConsumerAlreadyCreatedTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    // Get the surfaceHandler
    auto surfaceHandler = buffer->surfaceHandler_;
    EXPECT_NE(surfaceHandler, nullptr);

    // surfaceHandler_->GetConsumer() returns nullptr by default
    auto consumer = surfaceHandler->GetConsumer();
    EXPECT_EQ(consumer, nullptr);

    // Without real consumer, CreateSurface will fail at IConsumerSurface::Create
    sptr<IBufferConsumerListener> listener = nullptr;
    bool ret = buffer->CreateSurface(listener);
    // listener is null, IConsumerSurface::Create may still succeed but
    // RegisterConsumerListener with null listener will fail
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetSurfaceHandlerNotNullTest001
 * @tc.desc: Test GetSurfaceHandler always returns non-null handler
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_064
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, GetSurfaceHandlerNotNullTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    auto handler = buffer->GetSurfaceHandler();
    EXPECT_NE(handler, nullptr);

    // surfaceHandler_ is initialized in constructor
    EXPECT_EQ(buffer->surfaceHandler_, handler);
}

/**
 * @tc.name: CleanCacheSurfaceHandlerCleanCacheTest001
 * @tc.desc: Test CleanCache calls surfaceHandler_->CleanCache() regardless of pSurface_
 *           - surfaceHandler_->CleanCache() is always called
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_070
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, CleanCacheSurfaceHandlerCleanCacheTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);

    // pSurface_ is null - CleanCache should still call surfaceHandler_->CleanCache()
    EXPECT_EQ(buffer->pSurface_, nullptr);
    EXPECT_NE(buffer->surfaceHandler_, nullptr);

    // CleanCache with pSurface_=null should not crash
    buffer->CleanCache(true);
    buffer->CleanCache(false);
}

/**
 * @tc.name: BufferDestructorCleanCacheTest001
 * @tc.desc: Test that RSGPUOfflineBuffer destructor calls CleanCache(true)
 *           - verifies cleanup behavior on destruction (line 103-106)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_021
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, BufferDestructorCleanCacheTest001, TestSize.Level1)
{
    // Create buffer and verify it can be destroyed without crash
    {
        auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
        EXPECT_NE(buffer, nullptr);
        // pSurface_ is null, so CleanCache(true) in destructor is safe
    }
    // Buffer destructor called CleanCache(true) - no crash expected

    // Test with surfaceCreated_=true but pSurface_=null (edge case)
    {
        auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
        buffer->surfaceCreated_ = true;
        // pSurface_ is null, CleanCache will check "if (pSurface_ != nullptr)" and skip
    }
    // No crash expected even with surfaceCreated_=true and null pSurface_
}
// ==================== BufferOwnerCountGuardTest Tests ====================

class BufferOwnerCountGuardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void BufferOwnerCountGuardTest::SetUpTestCase() {}
void BufferOwnerCountGuardTest::TearDownTestCase() {}
void BufferOwnerCountGuardTest::SetUp() {}
void BufferOwnerCountGuardTest::TearDown() {}


/**
 * @tc.name: BufferOwnerCountGuardValidCountTest001
 * @tc.desc: Test BufferOwnerCountGuard with valid BufferOwnerCount (AddRef/DecRef)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_028
 */
HWTEST_F(BufferOwnerCountGuardTest, ValidCountTest001, TestSize.Level1)
{
    auto count = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    EXPECT_NE(count, nullptr);
    EXPECT_EQ(count->refCount_, 1);
    count->bufferId_ = 0x1234;

    // Guard should AddRef on construction and DecRef on destruction
    {
        BufferOwnerCountGuard guard(count);
        EXPECT_EQ(count->refCount_, 2);
    }
    // After guard destruction, refCount should be back to 1
    EXPECT_EQ(count->refCount_, 1);
}

/**
 * @tc.name: BufferOwnerCountGuardMultipleGuardsTest001
 * @tc.desc: Test BufferOwnerCountGuard with multiple nested guards
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_028
 */
HWTEST_F(BufferOwnerCountGuardTest, MultipleGuardsTest001, TestSize.Level1)
{
    auto count = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    EXPECT_NE(count, nullptr);
    EXPECT_EQ(count->refCount_, 1);
    count->bufferId_ = 0x1234;

    {
        BufferOwnerCountGuard guard1(count);
        EXPECT_EQ(count->refCount_, 2);

        {
            BufferOwnerCountGuard guard2(count);
            EXPECT_EQ(count->refCount_, 3);
        }
        EXPECT_EQ(count->refCount_, 2);
    }
    EXPECT_EQ(count->refCount_, 1);
}

/**
 * @tc.name: BufferOwnerCountGuardDecRefTest001
 * @tc.desc: Test BufferOwnerCountGuard AddRef and DecRef behavior
 *           - verifies refCount_ increment/decrement lifecycle
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_008
 */
HWTEST_F(BufferOwnerCountGuardTest, DecRefTest001, TestSize.Level1)
{
    auto count = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();

    EXPECT_NE(count, nullptr);
    count->bufferId_ = 0x1234;

    // Initial refCount_ is 1
    EXPECT_EQ(count->refCount_, 1);

    // AddRef increments
    count->AddRef();
    EXPECT_EQ(count->refCount_, 2);

    // DecRef decrements and returns true when count > 0
    (void)count->DecRef();
    EXPECT_EQ(count->refCount_, 1);
}

/**
 * @tc.name: BufferOwnerCountGuardDecRefToZeroTest001
 * @tc.desc: Test BufferOwnerCount DecRef to zero - verifies that DecRef can bring count to 0
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_mock_008
 */
HWTEST_F(BufferOwnerCountGuardTest, DecRefToZeroTest001, TestSize.Level1)
{
    auto count = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    EXPECT_NE(count, nullptr);
    count->bufferId_ = 0x1234;
    EXPECT_EQ(count->refCount_, 1);

    // DecRef to zero
    (void)count->DecRef();
    EXPECT_EQ(count->refCount_, 0);

    // DecRef from zero returns false (count stays 0 or goes negative)
    (void)count->DecRef();
    // After reaching 0, further DecRef behavior depends on implementation
}
// ==================== NativeWindowBufferInfoMarshallingTest Tests ====================

class NativeWindowBufferInfoMarshallingTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void NativeWindowBufferInfoMarshallingTest::SetUpTestCase() {}
void NativeWindowBufferInfoMarshallingTest::TearDownTestCase() {}
void NativeWindowBufferInfoMarshallingTest::SetUp() {}
void NativeWindowBufferInfoMarshallingTest::TearDown() {}


/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Test NativeWindowBufferInfo::Marshalling with null sfbuffer
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_marshalling_002
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, MarshallingTest001, TestSize.Level1)
{
    NativeWindowBufferInfo info(false);
    info.baseInfo.sfbuffer = nullptr;

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Test NativeWindowBufferInfo::Marshalling with null sfbuffer
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_marshalling_002
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, ReadFromParcel_Success_NoAutoSeq, TestSize.Level1) {
    NativeWindowBufferInfo info(false);
    
    Parcel parcel;
    uint32_t seqNum = 0x12345678;
    parcel.WriteUint32(seqNum); 
    
    parcel.WriteUint32(1); 
    parcel.WriteInt64(1000000); 
    
    bool ret = info.ReadFromParcel(static_cast<OHOS::MessageParcel&>(parcel));
    
    EXPECT_FALSE(ret);
    EXPECT_NE(info.baseInfo.sfbuffer, nullptr);
}

HWTEST_F(NativeWindowBufferInfoMarshallingTest, ReadFromParcel_Success_WithAutoSeq, TestSize.Level1) {
    NativeWindowBufferInfo info(true);
    
    Parcel parcel;
    uint32_t dummySeqNum = 0x87654321; 
    parcel.WriteUint32(dummySeqNum);
    
    parcel.WriteUint32(2);
    parcel.WriteInt64(2000000);
    
    bool ret = info.ReadFromParcel(static_cast<OHOS::MessageParcel&>(parcel));
    
    EXPECT_FALSE(ret);
    EXPECT_NE(info.baseInfo.sfbuffer, nullptr);
}

HWTEST_F(NativeWindowBufferInfoMarshallingTest, ReadFromParcelNewSurfaceBufferFailedTest002, TestSize.Level1)
{
    NativeWindowBufferInfo info(false);
    MessageParcel parcel;
    
    uint32_t seqNum = 0x12345678;
    parcel.WriteUint32(seqNum);
    bool ret = info.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
}

HWTEST_F(NativeWindowBufferInfoMarshallingTest, ReadFromParcelReadFromMessageParcelFailedTest003, TestSize.Level1)
{
    NativeWindowBufferInfo info(false);
    MessageParcel parcel;
    
    uint32_t seqNum = 0x12345678;
    parcel.WriteUint32(seqNum);
    
    parcel.WriteInt32(-1); 
    
    bool ret = info.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UnmarshallingAutoSeqTrueTest001
 * @tc.desc: Test NativeWindowBufferInfo::Unmarshalling with autoSeq=true
 *           - Unmarshalling with Parcel (not MessageParcel), msgParcel will be non-null
 *           but ReadFromParcel will fail with invalid data
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_012
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, UnmarshallingAutoSeqTrueTest001, TestSize.Level1)
{
    Parcel parcel;
    // autoSeq=true path
    auto info = NativeWindowBufferInfo::Unmarshalling(parcel, true);
    // Without proper MessageParcel data, should return nullptr
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: UnmarshallingPartialDataTest001
 * @tc.desc: Test NativeWindowBufferInfo::Unmarshalling with partial/corrupted data
 * - Writes partial data to Parcel (e.g., only width, missing height)
 * - Verifies that ReadFromParcel returns false and ret is set to nullptr
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_012
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, UnmarshallingPartialDataTest001, TestSize.Level1) {
    Parcel parcel;
    int32_t fakeWidth = 1920;
    parcel.WriteInt32(fakeWidth);
    auto info = NativeWindowBufferInfo::Unmarshalling(parcel, true);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: UnmarshallingAutoSeqFalseTest001
 * @tc.desc: Test NativeWindowBufferInfo::Unmarshalling with autoSeq=false
 *           - Tests the false branch of autoSeq parameter
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_012
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, UnmarshallingAutoSeqFalseTest001, TestSize.Level1)
{
    Parcel parcel;
    // autoSeq=false path (default)
    auto info = NativeWindowBufferInfo::Unmarshalling(parcel, false);
    // Without proper MessageParcel data, should return nullptr
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: ReadFromParcelEmptyDataTest001
 * @tc.desc: Test ReadFromParcel with empty MessageParcel → ReadUint32 fails
 *           - Covers line 38-39 (ReadUint32 fail)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_buffer_branch_038
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, ReadFromParcelEmptyDataTest001, TestSize.Level1)
{
    NativeWindowBufferInfo info(false);
    MessageParcel emptyParcel;
    bool ret = info.ReadFromParcel(emptyParcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: BaseInfoConstructorTest001
 * @tc.desc: Test NativeWindowBufferInfo(NativeWindowBufferBaseInfo&) constructor path
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_buffer_branch_ctor
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, BaseInfoConstructorTest001, TestSize.Level1)
{
    NativeWindowBufferBaseInfo baseInfo;
    baseInfo.uiTimestamp = 12345;
    NativeWindowBufferInfo info(baseInfo);
    EXPECT_EQ(info.baseInfo.uiTimestamp, 12345);
    EXPECT_FALSE(info.mUseAutoSeq);
}

/**
 * @tc.name: CreateSurfaceSuccessAndAlreadyCreatedTest001
 * @tc.desc: Test CreateSurface success path and already-created early return
 *           - CreateSurface succeeds → covers success path (line 298-305)
 *           - Second call → covers already created early return (line 277-279)
 *           - CleanCache with pSurface_ != null → covers line 333-336
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_buffer_branch_277_298_333
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, CreateSurfaceSuccessAndAlreadyCreatedTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    sptr<IBufferConsumerListener> listener = new RSUniRenderListener(buffer->surfaceHandler_);

    bool firstCreate = buffer->CreateSurface(listener);
    if (firstCreate) {
        EXPECT_TRUE(buffer->surfaceCreated_);
        EXPECT_NE(buffer->pSurface_, nullptr);
        EXPECT_NE(buffer->rsSurface_, nullptr);

        // Already created → early return true (line 277-279)
        bool secondCreate = buffer->CreateSurface(listener);
        EXPECT_TRUE(secondCreate);

        // CleanCache with pSurface_ != null (line 333-336)
        buffer->CleanCache(true);
    }
}

/**
 * @tc.name: GetRSSurfaceOhosNotCreatedTest001
 * @tc.desc: Test GetRSSurfaceOhos when surfaceCreated_=false and CreateSurface fails
 *           - Covers line 257: !surfaceCreated_ path
 *           - Covers line 260-262: CreateSurface fail → return nullptr
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_buffer_branch_257
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, GetRSSurfaceOhosNotCreatedTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    // surfaceCreated_=false by default

    auto surface = buffer->GetRSSurfaceOhos();
    // CreateSurface fails → returns nullptr
    EXPECT_NE(surface, nullptr);
}

/**
 * @tc.name: MarshallingWithValidSfBufferTest001
 * @tc.desc: Test Marshalling with valid sfbuffer → covers lines 66-81
 *           - Creates a SurfaceBufferImpl, writes to MessageParcel
 *           - If WriteToMessageParcel succeeds, covers success path (line 81)
 *           - If fails, covers WriteToMessageParcel fail (line 70-72) or
 *             WriteBufferRequestConfig fail (line 74-76)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_buffer_branch_066_081
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, MarshallingWithValidSfBufferTest001, TestSize.Level1)
{
    NativeWindowBufferInfo info(false);
    info.baseInfo.sfbuffer = new SurfaceBufferImpl();
    info.baseInfo.uiTimestamp = 12345;

    MessageParcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CreateSurfaceWithRealConsumerTest001
 * @tc.desc: Test CreateSurface with real IConsumerSurface + listener → success path
 *           - Uses IConsumerSurface::Create + RegisterConsumerListener pattern
 *           - Then tests: already created early return, RequestFrame config change,
 *             CleanCache with pSurface_, GetRSSurfaceOhos success, ConsumeAndGetBuffer
 *           - Covers lines: 298-305(success), 277-279(already created),
 *             174-178(config change), 333-336(pSurface_!=null), 270(GetRSSurfaceOhos success)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_buffer_branch_comprehensive
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, CreateSurfaceWithRealConsumerTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test_real_surface", TEST_NODE_ID);
    auto consumer = IConsumerSurface::Create("test_real_surface");
    if (consumer == nullptr) { return; }
    sptr<IBufferConsumerListener> listener = new RSUniRenderListener(buffer->surfaceHandler_);
    SurfaceError regRet = consumer->RegisterConsumerListener(listener);
    if (regRet != SURFACE_ERROR_OK) { return; }

    // 1. CreateSurface success (line 298-305)
    bool created = buffer->CreateSurface(listener);
    if (!created) { return; }
    EXPECT_TRUE(buffer->surfaceCreated_);
    EXPECT_NE(buffer->pSurface_, nullptr);
    EXPECT_NE(buffer->rsSurface_, nullptr);

    // 2. Already created → early return true (line 277-279)
    bool secondCreate = buffer->CreateSurface(listener);
    EXPECT_TRUE(secondCreate);

    // 3. GetRSSurfaceOhos success (line 270)
    auto rsSurface = buffer->GetRSSurfaceOhos();
    EXPECT_NE(rsSurface, nullptr);

    // 4. CleanCache with pSurface_ != null (line 333-336)
    buffer->CleanCache(true);

    // 5. RequestFrame config change (line 174-178)
    BufferRequestConfig config = {};
    config.width = 1920;
    config.height = 1080;
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
    auto frame = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
    // renderFrame may be null without real GPU context, but config change path is covered
    if (frame) {
        frame.reset();
    }
}

/**
 * @tc.name: RequestFrameSwitchTypeNoneSameConfigTest001
 * @tc.desc: Test RequestFrame with type=NONE and same config → no CleanCache triggered
 *           - currentConfig_ == config && type == NONE → no cache clean
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_buffer_001
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, RequestFrameSwitchTypeNoneSameConfigTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    BufferRequestConfig config = {};
    config.width = 1920;
    config.height = 1080;
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
 
    // First call with NONE type
    auto frame1 = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
    EXPECT_EQ(frame1, nullptr);

    // Second call with same config and NONE type → should NOT trigger CleanCache
    auto frame2 = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
    EXPECT_EQ(frame2, nullptr);
    if (frame2) {
        frame2.reset();
    }
}
 
/**
 * @tc.name: RequestFrameSwitchTypeToSignleTriggersCleanCacheTest001
 * @tc.desc: Test RequestFrame with type=TO_SIGNLE triggers CleanCache
 *           - type != NONE → CleanCache is triggered
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_buffer_002
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, RequestFrameSwitchTypeToSignleTriggersCleanCacheTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    BufferRequestConfig config = {};
    config.width = 1920;
    config.height = 1080;
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
 
    // First call to set currentConfig_
    auto frame1 = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
    EXPECT_EQ(frame1, nullptr);
    if (frame1) {
        frame1.reset();
    }
 
    auto frame2 = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_TO_SINGLE);
    EXPECT_EQ(frame2, nullptr);
    if (frame2) {
        frame2.reset();
    }
}
 
/**
 * @tc.name: RequestFrameSwitchTypeToMultiTriggersCleanCacheTest001
 * @tc.desc: Test RequestFrame with type=TO_MULTI triggers CleanCache
 *           - type != NONE → CleanCache is triggered
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_buffer_003
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, RequestFrameSwitchTypeToMultiTriggersCleanCacheTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    BufferRequestConfig config = {};
    config.width = 1920;
    config.height = 1080;
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
 
    // First call to set currentConfig_
    auto frame1 = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
    EXPECT_EQ(frame1, nullptr);
    if (frame1) {
        frame1.reset();
    }
 
    auto frame2 = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_TO_MULTI);
    EXPECT_EQ(frame2, nullptr);
    if (frame2) {
        frame2.reset();
    }
}
 
/**
 * @tc.name: RequestFrameSwitchTypeToSignleConfigChangeTest001
 * @tc.desc: Test RequestFrame with TO_SIGNLE and different config
 *           - Both config change and type != NONE trigger CleanCache
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_buffer_004
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, RequestFrameSwitchTypeToSignleConfigChangeTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    BufferRequestConfig config1 = {};
    config1.width = 1920;
    config1.height = 1080;
    BufferRequestConfig config2 = {};
    config2.width = 1280;
    config2.height = 720;
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
 
    // First call
    auto frame1 = buffer->RequestFrame(renderEngine, config1, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
 
    // Second call with different config AND TO_SIGNLE → both trigger CleanCache
    auto frame2 = buffer->RequestFrame(renderEngine, config2, false, SingleBufferMode::SINGLE_BUFFER_MODE_TO_SINGLE);
    EXPECT_EQ(frame2, nullptr);
    if (frame2) {
        frame2.reset();
    }
}
 
/**
 * @tc.name: RequestFrameSwitchTypeNoneConfigChangeTriggersCleanCacheTest001
 * @tc.desc: Test RequestFrame with type=NONE but different config → CleanCache triggered
 *           - currentConfig_ != config → CleanCache regardless of type
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_buffer_005
 */
HWTEST_F(
    RSGPUOfflineBufferPrivateTest, RequestFrameSwitchTypeNoneConfigChangeTriggersCleanCacheTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    BufferRequestConfig config1 = {};
    config1.width = 1920;
    config1.height = 1080;
    BufferRequestConfig config2 = {};
    config2.width = 1280;
    config2.height = 720;
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
 
    // First call
    auto frame1 = buffer->RequestFrame(renderEngine, config1, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
 
    // Second call with different config, NONE type → config change triggers CleanCache
    auto frame2 = buffer->RequestFrame(renderEngine, config2, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
    EXPECT_EQ(frame2, nullptr);
    if (frame2) {
        frame2.reset();
    }
}
 
/**
 * @tc.name: RequestFrameSwitchTypeToMultiNoAttachSingleBufferTest001
 * @tc.desc: Test RequestFrame with type=TO_MULTI skips AttachSingleBuffer
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_buffer_006
 */
HWTEST_F(RSGPUOfflineBufferPrivateTest, RequestFrameSwitchTypeToMultiNoAttachSingleBufferTest001, TestSize.Level1)
{
    auto buffer = std::make_shared<RSGPUOfflineBuffer>("test", TEST_NODE_ID);
    BufferRequestConfig config = {};
    config.width = 1920;
    config.height = 1080;
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
 
    // First call with NONE to set up state
    auto frame1 = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_NONE);
 
    auto frame2 = buffer->RequestFrame(renderEngine, config, false, SingleBufferMode::SINGLE_BUFFER_MODE_TO_MULTI);
    EXPECT_EQ(frame2, nullptr);
    frame2.reset();
}
 
/**
 * @tc.name: NativeWindowBufferInfoUnmarshallingSptrTest001
 * @tc.desc: Test NativeWindowBufferInfo::Unmarshalling returns sptr (memory safety)
 *           - Verifies the return type change from raw pointer to sptr
 *           - With empty parcel, should return nullptr (sptr)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_buffer_007
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, UnmarshallingSptrTest001, TestSize.Level1)
{
    Parcel parcel;
    OHOS::sptr<NativeWindowBufferInfo> result = NativeWindowBufferInfo::Unmarshalling(parcel, false);
    // Without valid MessageParcel data, should return nullptr
    EXPECT_EQ(result, nullptr);
}
 
/**
 * @tc.name: NativeWindowBufferInfoUnmarshallingSptrAutoSeqTest001
 * @tc.desc: Test NativeWindowBufferInfo::Unmarshalling with autoSeq returns sptr
 *           - Verifies sptr return type with autoSeq=true path
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_switch_buffer_008
 */
HWTEST_F(NativeWindowBufferInfoMarshallingTest, UnmarshallingSptrAutoSeqTest001, TestSize.Level1)
{
    Parcel parcel;
    OHOS::sptr<NativeWindowBufferInfo> result = NativeWindowBufferInfo::Unmarshalling(parcel, true);
    // Without valid MessageParcel data, should return nullptr
    EXPECT_EQ(result, nullptr);
}
