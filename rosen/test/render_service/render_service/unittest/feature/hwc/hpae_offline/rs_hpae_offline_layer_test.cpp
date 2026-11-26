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
#include "foundation/graphic/graphic_2d/rosen/test/render_service/render_service/unittest/pipeline/rs_test_util.h"

#include "feature/hwc/hpae_offline/rs_hpae_offline_layer.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/main_thread/rs_main_thread.h"


using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSHpaeOfflineLayerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSHpaeOfflineLayerTest::SetUpTestCase()
{
}
void RSHpaeOfflineLayerTest::TearDownTestCase()
{
    auto& rtThread = RSUniRenderThread::Instance();
    if (rtThread.uniRenderEngine_) {
        auto* engine = rtThread.uniRenderEngine_.get();
        if (engine->renderContext_) {
            engine->renderContext_->drGPUContext_ = nullptr;
        }
        if (engine->protectedRenderContext_) {
            engine->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        engine->skContext_ = nullptr;
        engine->renderContext_ = nullptr;
        engine->protectedRenderContext_ = nullptr;
        engine->imageManager_ = nullptr;
        engine->gpuCacheManager_ = nullptr;
#ifdef USE_VIDEO_PROCESSING_ENGINE
        engine->colorSpaceConverterDisplay_ = nullptr;
#endif
    }
    rtThread.uniRenderEngine_ = nullptr;
    auto mainThread = RSMainThread::Instance();
    if (mainThread && mainThread->renderEngine_) {
        auto* engine = mainThread->renderEngine_.get();
        if (engine->renderContext_) {
            engine->renderContext_->drGPUContext_ = nullptr;
        }
        if (engine->protectedRenderContext_) {
            engine->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        engine->skContext_ = nullptr;
        engine->renderContext_ = nullptr;
        engine->protectedRenderContext_ = nullptr;
        engine->imageManager_ = nullptr;
        engine->gpuCacheManager_ = nullptr;
#ifdef USE_VIDEO_PROCESSING_ENGINE
        engine->colorSpaceConverterDisplay_ = nullptr;
#endif
    }
    if (mainThread) {
        mainThread->renderEngine_ = nullptr;
    }
}
void RSHpaeOfflineLayerTest::SetUp() {}
void RSHpaeOfflineLayerTest::TearDown() {}

/**
 * @tc.name: PreAllocBuffers
 * @tc.desc: PreAllocBuffers Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineLayerTest, PreAllocBuffersTest, TestSize.Level1)
{
    auto RSHpaeOfflineLayer1 = std::make_shared<RSHpaeOfflineLayer>("test", 100);
    ASSERT_NE(RSHpaeOfflineLayer1, nullptr);
    RSHpaeOfflineLayer1->surfaceCreated_ = true;
    sptr<IConsumerSurface> cSurface = IConsumerSurface::Create("DisplayNode");
    ASSERT_TRUE(cSurface != nullptr);
    sptr<IBufferProducer> bp = cSurface->GetProducer();
    RSHpaeOfflineLayer1->pSurface_ = Surface::CreateSurfaceAsProducer(bp);
    BufferRequestConfig requestConfig = {
        .width = 0x100,
        .height = 0x100,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
    };
    bool rsHpaeOfflineLayerResult = RSHpaeOfflineLayer1->PreAllocBuffers(requestConfig);
    ASSERT_NE(rsHpaeOfflineLayerResult, false);

    RSHpaeOfflineLayer1->bufferSize_ = 0;
    rsHpaeOfflineLayerResult = RSHpaeOfflineLayer1->PreAllocBuffers(requestConfig);
    ASSERT_EQ(rsHpaeOfflineLayerResult, false);

    RSHpaeOfflineLayer1->bufferSize_ = 5;
    RSHpaeOfflineLayer1->surfaceCreated_ = false;
    rsHpaeOfflineLayerResult = RSHpaeOfflineLayer1->PreAllocBuffers(requestConfig);
    ASSERT_NE(rsHpaeOfflineLayerResult, false);
}

/**
 * @tc.name: RequestSurfaceBuffer
 * @tc.desc: RequestSurfaceBuffer Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineLayerTest, RequestSurfaceBufferTest, TestSize.Level1)
{
    auto RSHpaeOfflineLayer1 = std::make_shared<RSHpaeOfflineLayer>("test", 100);
    ASSERT_NE(RSHpaeOfflineLayer1, nullptr);
    RSHpaeOfflineLayer1->surfaceCreated_ = true;
    sptr<IConsumerSurface> cSurface = IConsumerSurface::Create("DisplayNode");
    ASSERT_TRUE(cSurface != nullptr);
    sptr<IBufferProducer> bp = cSurface->GetProducer();
    RSHpaeOfflineLayer1->pSurface_ = Surface::CreateSurfaceAsProducer(bp);
    BufferRequestConfig requestConfig = {
        .width = 0x100,
        .height = 0x100,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
    };
    int32_t releaseFence = 0;
    sptr<SurfaceBuffer> RSHpaeOfflineLayerResult = RSHpaeOfflineLayer1->RequestSurfaceBuffer(requestConfig, releaseFence);
    ASSERT_EQ(RSHpaeOfflineLayerResult, nullptr);

    RSHpaeOfflineLayer1->surfaceCreated_ = false;
    RSHpaeOfflineLayerResult = RSHpaeOfflineLayer1->RequestSurfaceBuffer(requestConfig, releaseFence);
    ASSERT_NE(RSHpaeOfflineLayerResult, nullptr);

    requestConfig.colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DCI_P3;
    RSHpaeOfflineLayerResult = RSHpaeOfflineLayer1->RequestSurfaceBuffer(requestConfig, releaseFence);
    ASSERT_NE(RSHpaeOfflineLayerResult, nullptr);
}

/**
 * @tc.name: CreateSurfaceTest_001
 * @tc.desc: CreateSurface Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineLayerTest, CreateSurfaceTest001, TestSize.Level1)
{
    auto RSHpaeOfflineLayer1 = std::make_shared<RSHpaeOfflineLayer>("test", 100);
    ASSERT_NE(RSHpaeOfflineLayer1, nullptr);

    RSSurfaceRenderNodeConfig config;
    std::shared_ptr<RSSurfaceRenderNode> rsNode = std::make_shared<RSSurfaceRenderNode>(config);
    rsNode->InitRenderParams();
    std::weak_ptr<RSSurfaceRenderNode> surfaceRenderNode(rsNode);
    auto surfaceHandler(rsNode->GetRSSurfaceHandler());
    sptr<IBufferConsumerListener> listener =
        new RSRenderServiceListener(surfaceRenderNode, surfaceHandler, nullptr);

    sptr<IConsumerSurface> cSurface = IConsumerSurface::Create("DisplayNode");
    RSHpaeOfflineLayer1->surfaceHandler_->SetConsumer(cSurface);
    sptr<IBufferProducer> bp = cSurface->GetProducer();
    RSHpaeOfflineLayer1->pSurface_ = Surface::CreateSurfaceAsProducer(bp);
    bool resultRSHpaeOfflineLayerTest = RSHpaeOfflineLayer1->CreateSurface(listener);
    ASSERT_TRUE(resultRSHpaeOfflineLayerTest);

    RSHpaeOfflineLayer1->surfaceHandler_->SetConsumer(nullptr);

    resultRSHpaeOfflineLayerTest = RSHpaeOfflineLayer1->CreateSurface(listener);
    ASSERT_TRUE(resultRSHpaeOfflineLayerTest);

    RSHpaeOfflineLayer1->pSurface_ = nullptr;

    resultRSHpaeOfflineLayerTest = RSHpaeOfflineLayer1->CreateSurface(listener);
    ASSERT_TRUE(resultRSHpaeOfflineLayerTest);

    RSHpaeOfflineLayer1->surfaceHandler_->SetConsumer(cSurface);

    resultRSHpaeOfflineLayerTest = RSHpaeOfflineLayer1->CreateSurface(listener);
    ASSERT_TRUE(resultRSHpaeOfflineLayerTest);
}

/**
 * @tc.name: CleanCache001
 * @tc.desc: CleanCache Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineLayerTest, CleanCache001, TestSize.Level1)
{
    auto RSHpaeOfflineLayer1 = std::make_shared<RSHpaeOfflineLayer>("test", 100);
    sptr<IConsumerSurface> cSurface = IConsumerSurface::Create("DisplayNode");
    ASSERT_NE(RSHpaeOfflineLayer1, nullptr);

    RSHpaeOfflineLayer1->CleanCache(true);
    ASSERT_EQ(RSHpaeOfflineLayer1->pSurface_, nullptr);

    RSHpaeOfflineLayer1->surfaceHandler_->SetConsumer(cSurface);
    sptr<IBufferProducer> bp = cSurface->GetProducer();
    RSHpaeOfflineLayer1->pSurface_ = Surface::CreateSurfaceAsProducer(bp);
    RSHpaeOfflineLayer1->CleanCache(false);
    ASSERT_NE(RSHpaeOfflineLayer1->pSurface_, nullptr);
    RSHpaeOfflineLayer1->CleanCache(true);
    ASSERT_NE(RSHpaeOfflineLayer1->pSurface_, nullptr);
}

/**
 * @tc.name: ConvertColorGamutToSpaceTypeTest001
 * @tc.desc: Test ConvertColorGamutToSpaceType with SRGB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineLayerTest, ConvertColorGamutToSpaceTypeTest001, TestSize.Level1)
{
    auto RSHpaeOfflineLayer1 = std::make_shared<RSHpaeOfflineLayer>("test", 100);

    GraphicColorGamut colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = RSHpaeOfflineLayer1->ConvertColorGamutToSpaceType(colorGamut, colorSpaceType);
    EXPECT_TRUE(ret);
    (void)colorSpaceType;
}

/**
 * @tc.name: ConvertColorGamutToSpaceTypeTest002
 * @tc.desc: Test ConvertColorGamutToSpaceType with BT2020
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineLayerTest, ConvertColorGamutToSpaceTypeTest002, TestSize.Level1)
{
    auto RSHpaeOfflineLayer1 = std::make_shared<RSHpaeOfflineLayer>("test", 100);

    GraphicColorGamut colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2020;
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = RSHpaeOfflineLayer1->ConvertColorGamutToSpaceType(colorGamut, colorSpaceType);
    EXPECT_TRUE(ret);
    (void)colorSpaceType;
}

/**
 * @tc.name: ConvertColorGamutToSpaceTypeTest003
 * @tc.desc: Test ConvertColorGamutToSpaceType with invalid gamut
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineLayerTest, ConvertColorGamutToSpaceTypeTest003, TestSize.Level1)
{
    auto RSHpaeOfflineLayer1 = std::make_shared<RSHpaeOfflineLayer>("test", 100);

    GraphicColorGamut colorGamut = static_cast<GraphicColorGamut>(999); // Invalid
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType colorSpaceType;

    bool ret = RSHpaeOfflineLayer1->ConvertColorGamutToSpaceType(colorGamut, colorSpaceType);
    EXPECT_FALSE(ret);
    (void)colorSpaceType;
}
}
