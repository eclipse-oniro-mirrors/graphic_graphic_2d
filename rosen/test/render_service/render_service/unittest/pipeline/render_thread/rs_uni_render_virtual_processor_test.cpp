/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <parameters.h>

#include "ibuffer_consumer_listener.h"
#include "gtest/gtest.h"
#include "limit_number.h"
#include "drawable/rs_screen_render_node_drawable.h"
#include "drawable/rs_logical_display_render_node_drawable.h"
#include "params/rs_render_params.h"
#include "feature/hdr/rs_hdr_util.h"
#include "multiscreen_param.h"
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_logical_display_render_node.h"
#include "pipeline/render_thread/rs_render_engine.h"
#include "engine/rs_uni_render_engine.h"
#include "pipeline/render_thread/rs_uni_render_virtual_processor.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/main_thread/rs_uni_render_listener.h"
#include "pipeline/rs_processor_factory.h"
#ifdef USE_VIDEO_PROCESSING_ENGINE
#include "platform/ohos/backend/rs_surface_frame_ohos_vulkan.h"
#include "platform/ohos/backend/rs_surface_ohos_vulkan.h"
#endif
#include "common/rs_obj_abs_geometry.h"
#include "feature/round_corner_display/rs_rcd_surface_render_node.h"
#include "foundation/graphic/graphic_2d/rosen/test/render_service/render_service/unittest/pipeline/rs_test_util.h"
#include "params/rs_screen_render_params.h"
#include "platform/ohos/backend/rs_surface_frame_ohos_raster.h"
#include "platform/ohos/backend/rs_surface_ohos_gl.h"
#include "platform/ohos/backend/rs_surface_ohos_raster.h"
#include "surface_buffer_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
namespace {
constexpr uint32_t DEFAULT_CANVAS_WIDTH = 800;
constexpr uint32_t DEFAULT_CANVAS_HEIGHT = 600;
constexpr NodeId DEFAULT_ID = 0xFFFF;
#ifdef RS_ENABLE_VK
constexpr int32_t DEFAULT_BUFFER_AGE = 10;
#endif
const HDI::Display::Graphic::Common::V1_0::BufferHandleMetaRegion DEFAULT_META_REGION {0, 0, 100, 100};
constexpr int32_t TEST_FRAME_DIM = 100;
}
BufferRequestConfig requestConfig = {
    .width = 0x100,
    .height = 0x100,
    .strideAlignment = 0x8,
    .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
    .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
    .timeout = 0,
};

class BufferConsumerListener : public ::OHOS::IBufferConsumerListener {
public:
    void OnBufferAvailable() override
    {
    }
};

class RSUniRenderVirtualProcessorTest : public testing::Test {
public:
    std::shared_ptr<RSProcessor> processor_ = nullptr;
    std::shared_ptr<RSUniRenderVirtualProcessor> virtualProcessor_ = nullptr;
    std::shared_ptr<Drawing::Canvas> drawingCanvas_ = nullptr;
    std::shared_ptr<RSScreenRenderNode> rsScreenRenderNode_ = nullptr;
    RSScreenRenderNodeDrawable* screenDrawable_ = nullptr;
    RSLogicalDisplayRenderNodeDrawable* displayDrawable_ = nullptr;
    sptr<RSScreenManager> screenManager_ = sptr<RSScreenManager>::MakeSptr();

    RSDisplayNodeConfig config_;
    NodeId nodeId_ = 0;
    ScreenId screenNodeId_ = 1;
    std::shared_ptr<RSContext> context_ = std::make_shared<RSContext>();

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    class RSSurfaceOhosRasterTest : public RSSurfaceOhosRaster {
    public:
        explicit RSSurfaceOhosRasterTest(const sptr<Surface>& producer);
        ~RSSurfaceOhosRasterTest() = default;
        sptr<SurfaceBuffer> GetCurrentBuffer() override;
    };
};

void RSUniRenderVirtualProcessorTest::SetUpTestCase()
{
#ifdef RS_ENABLE_VK
    RsVulkanContext::SetRecyclable(false);
#endif
    // Create render engine in SetUpTestCase for all tests to use
    RSUniRenderThread::Instance().uniRenderEngine_ = std::make_shared<RSUniRenderEngine>();
}
void RSUniRenderVirtualProcessorTest::TearDownTestCase()
{
    // Clean up global singletons to prevent crash on test suite exit
    RSUniRenderThread::Instance().uniRenderEngine_ = nullptr;
    RSUniRenderThread::Instance().composerClientManager_ = nullptr;
}
void RSUniRenderVirtualProcessorTest::SetUp()
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    processor_ = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    ASSERT_NE(processor_, nullptr);
    virtualProcessor_ = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor_);
    ASSERT_NE(virtualProcessor_, nullptr);

    drawingCanvas_ = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    ASSERT_NE(drawingCanvas_, nullptr);
    virtualProcessor_->canvas_ = std::make_unique<RSPaintFilterCanvas>(drawingCanvas_.get());
    ASSERT_NE(virtualProcessor_->canvas_, nullptr);

    rsScreenRenderNode_ = std::make_shared<RSScreenRenderNode>(nodeId_, screenNodeId_, context_);
    ASSERT_NE(rsScreenRenderNode_, nullptr);
    screenDrawable_ =
        static_cast<RSScreenRenderNodeDrawable*>(RSScreenRenderNodeDrawable::OnGenerate(rsScreenRenderNode_));
    ASSERT_NE(screenDrawable_, nullptr);
    screenDrawable_->renderParams_ = std::make_unique<RSRenderParams>(nodeId_);
    ASSERT_NE(screenDrawable_->renderParams_, nullptr);
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    displayDrawable_ =
        std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(renderNode->GetRenderDrawable()).get();
    screenManager_->Init(nullptr);
    RSTestUtil::InitRenderNodeGC();
}
void RSUniRenderVirtualProcessorTest::TearDown()
{
    // Clean up surfaceFrames_ safely before destroying frames
    for (auto& sf : virtualProcessor_->surfaceFrames_) {
        if (sf.frame) {
            sf.frame->Reset();
        }
        sf.canvas = nullptr;
    }
    virtualProcessor_->surfaceFrames_.clear();
    // Clean up per-test resources to prevent crash
    virtualProcessor_ = nullptr;
    processor_ = nullptr;
    drawingCanvas_ = nullptr;
    rsScreenRenderNode_ = nullptr;
    screenDrawable_ = nullptr;
    displayDrawable_ = nullptr;
    RSUniRenderThread::Instance().composerClientManager_ = nullptr;
}
RSUniRenderVirtualProcessorTest::RSSurfaceOhosRasterTest::RSSurfaceOhosRasterTest(const sptr<Surface>& producer)
    : RSSurfaceOhosRaster(producer) {}

sptr<SurfaceBuffer> RSUniRenderVirtualProcessorTest::RSSurfaceOhosRasterTest::GetCurrentBuffer()
{
    return new SurfaceBufferImpl();
}

RSLogicalDisplayRenderNodeDrawable* GenerateLogicalscreenDrawableById(
    NodeId id, const std::weak_ptr<RSContext>& context)
{
    RSDisplayNodeConfig config;
    std::shared_ptr<RSLogicalDisplayRenderNode> renderNode =
        std::make_shared<RSLogicalDisplayRenderNode>(id, config, context);
    if (!renderNode) {
        return nullptr;
    }
    RSRenderNodeDrawableAdapter* displayAdapter = RSLogicalDisplayRenderNodeDrawable::OnGenerate(renderNode);
    if (!displayAdapter) {
        return nullptr;
    }
    return static_cast<RSLogicalDisplayRenderNodeDrawable*>(displayAdapter);
}

/**
 * @tc.name: CreateAndDestroy
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CreateAndDestroy, TestSize.Level2)
{
    // The best way to create RSUniRenderVirtualProcessor.
    auto type = CompositeType::UNI_RENDER_MIRROR_COMPOSITE;
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(type, 0);
    auto rsUniRenderVirtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(nullptr, rsUniRenderVirtualProcessor);
}

/**
 * @tc.name: ProcessSurface
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessSurface, TestSize.Level2)
{
    RSSurfaceRenderNodeConfig config;
    RSSurfaceRenderNode rsSurfaceRenderNode(config);
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    ASSERT_NE(processor, nullptr);
    processor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: ProcessScreenSurface
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurface, TestSize.Level2)
{
    NodeId id = 0;
    RSScreenRenderNode screenRenderNode(id, 1);
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    ASSERT_NE(nullptr, processor);
    processor->ProcessScreenSurface(screenRenderNode);
}

/**
 * @tc.name: MergeMirrorFenceToHardwareEnabledDrawablesTest001
 * @tc.desc: Test MergeMirrorFenceToHardwareEnabledDrawables, RSRenderThreadParams null or not
 * @tc.type: FUNC
 * @tc.require: issueICNZ6M
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, MergeMirrorFenceToHardwareEnabledDrawablesTest001, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(virtualProcessor, nullptr);
    virtualProcessor->MergeMirrorFenceToHardwareEnabledDrawables(SyncFence::InvalidFence());
    std::unique_ptr<RSRenderThreadParams> newUniParam = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(newUniParam));
    ASSERT_TRUE(virtualProcessor->surfaceFrames_.empty());
    virtualProcessor->MergeMirrorFenceToHardwareEnabledDrawables(SyncFence::InvalidFence());
}

#ifdef RS_ENABLE_VK
/**
 * @tc.name: MergeMirrorFenceToHardwareEnabledDrawablesTest002
 * @tc.desc: Test MergeMirrorFenceToHardwareEnabledDrawables, acquireFence null, not valid or valid
 * @tc.type: FUNC
 * @tc.require: issueICNZ6M
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, MergeMirrorFenceToHardwareEnabledDrawablesTest002, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(virtualProcessor, nullptr);

    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    std::shared_ptr<RSSurfaceOhosVulkan> rsSurface1 = std::make_shared<RSSurfaceOhosVulkan>(pSurface);
    auto tmpSurface = std::make_shared<Drawing::Surface>();
    auto surfaceFrame = std::make_unique<RSSurfaceFrameOhosVulkan>(tmpSurface, TEST_FRAME_DIM, TEST_FRAME_DIM,
        DEFAULT_BUFFER_AGE);
    SurfaceFrameConfig config;
    config.surface = pSurface;
    config.frame = std::make_unique<RSRenderFrame>(rsSurface1, std::move(surfaceFrame));
    ASSERT_NE(config.frame, nullptr);
    ASSERT_NE(config.frame->surfaceFrame_, nullptr);
    virtualProcessor->surfaceFrames_.push_back(std::move(config));

    // Test with invalid fence -> early return
    ASSERT_FALSE(virtualProcessor->surfaceFrames_[0].frame->acquireFence_->IsValid());
    virtualProcessor->MergeMirrorFenceToHardwareEnabledDrawables(SyncFence::InvalidFence());
    // Test with null fence -> early return
    virtualProcessor->MergeMirrorFenceToHardwareEnabledDrawables(nullptr);
    // Test with valid fence
    int fenceFd = open("/data/local/tmpfile", O_RDONLY | O_CREAT);
    sptr<SyncFence> validFence = sptr<SyncFence>(new SyncFence(::dup(fenceFd)));
    ASSERT_TRUE(validFence->IsValid());
    virtualProcessor->MergeMirrorFenceToHardwareEnabledDrawables(validFence);
    close(fenceFd);
}

/**
 * @tc.name: MergeMirrorFenceToHardwareEnabledDrawablesTest003
 * @tc.desc: Test MergeMirrorFenceToHardwareEnabledDrawables, hardware enabled drawables
 * @tc.type: FUNC
 * @tc.require: issueICNZ6M
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, MergeMirrorFenceToHardwareEnabledDrawablesTest003, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(virtualProcessor, nullptr);

    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    std::shared_ptr<RSSurfaceOhosVulkan> rsSurface1 = std::make_shared<RSSurfaceOhosVulkan>(pSurface);
    auto tmpSurface = std::make_shared<Drawing::Surface>();
    auto surfaceFrame = std::make_unique<RSSurfaceFrameOhosVulkan>(tmpSurface, TEST_FRAME_DIM, TEST_FRAME_DIM,
        DEFAULT_BUFFER_AGE);
    SurfaceFrameConfig config;
    config.surface = pSurface;
    config.frame = std::make_unique<RSRenderFrame>(rsSurface1, std::move(surfaceFrame));
    ASSERT_NE(config.frame, nullptr);
    ASSERT_NE(config.frame->surfaceFrame_, nullptr);
    int fenceFd = open("/data/local/tmpfile", O_RDONLY | O_CREAT);
    sptr<SyncFence> validFence = sptr<SyncFence>(new SyncFence(::dup(fenceFd)));
    ASSERT_TRUE(validFence->IsValid());
    virtualProcessor->surfaceFrames_.push_back(std::move(config));

    auto newUniParam = std::make_unique<RSRenderThreadParams>();
    NodeId displayNodeId = 1000;
    NodeId surfaceNodeId = 200;
    NodeId mirroredScreenId = 300;
    virtualProcessor->mirroredScreenNodeId_ = mirroredScreenId;
    auto surfaceNode0 = std::make_shared<RSSurfaceRenderNode>(surfaceNodeId);
    auto drawable0 = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(std::move(surfaceNode0));

    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(surfaceNodeId);
    auto drawable1 = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(std::move(surfaceNode1));
    drawable1->renderParams_ = std::make_unique<RSSurfaceRenderParams>(surfaceNodeId);

    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(surfaceNodeId);
    auto drawable2 = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(std::move(surfaceNode2));
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create().GetRefPtr();
    ASSERT_NE(buffer, nullptr);
    Rect damageRect;
    drawable2->renderParams_ = std::make_unique<RSSurfaceRenderParams>(surfaceNodeId);
    ASSERT_NE(drawable2->renderParams_, nullptr);
    drawable2->renderParams_->SetBuffer(buffer, damageRect);

    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(surfaceNodeId);
    auto drawable3 = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(std::move(surfaceNode3));
    drawable3->renderParams_ = std::make_unique<RSSurfaceRenderParams>(surfaceNodeId);
    ASSERT_NE(drawable3->renderParams_, nullptr);
    drawable3->renderParams_->SetBuffer(buffer, damageRect);
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable3->renderParams_.get());
    surfaceParams->GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
    newUniParam->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(0, 0, nullptr));
    newUniParam->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(mirroredScreenId, 0, nullptr));
    newUniParam->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(mirroredScreenId, displayNodeId, drawable0));
    newUniParam->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(mirroredScreenId, displayNodeId, drawable1));
    newUniParam->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(mirroredScreenId, displayNodeId, drawable2));
    newUniParam->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(mirroredScreenId, displayNodeId, drawable3));
    RSUniRenderThread::Instance().Sync(std::move(newUniParam));
    virtualProcessor->MergeMirrorFenceToHardwareEnabledDrawables(validFence);

    newUniParam = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(newUniParam));
    close(fenceFd);
}
#endif // RS_ENABLE_VK

/**
 * @tc.name: PostProcess
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, PostProcess, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    ASSERT_NE(processor, nullptr);
    processor->PostProcess();
}

#ifdef USE_VIDEO_PROCESSING_ENGINE
/**
 * @tc.name: InitForRenderThread003
 * @tc.desc: Test RSUniRenderVirtualProcessorTest.InitForRenderThread
 * @tc.type:FUNC
 * @tc.require: issueIB7AGV
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, InitForRenderThread003, TestSize.Level1)
{
    auto surface = Surface::CreateSurfaceAsConsumer("test_surface");
    ASSERT_NE(surface, nullptr);
    auto screenId = screenManager_->CreateVirtualScreen("virtual_screen", 10, 10, surface, 0UL, 0, {});
    screenManager_->SetVirtualScreenStatus(screenId, VirtualScreenStatus::VIRTUAL_SCREEN_PLAY);

    NodeId mainNodeId = 1;
    NodeId virtualNodeId = 2; // virtual node id
    auto mainNode = std::make_shared<RSScreenRenderNode>(mainNodeId, 0);
    mainNode->InitRenderParams();
    auto virtualNode = std::make_shared<RSScreenRenderNode>(virtualNodeId, screenId);
    virtualNode->isMirroredScreen_ = true;
    virtualNode->mirrorSource_ = mainNode;
    virtualNode->InitRenderParams();

    auto mainRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(mainNode->renderDrawable_.get());
    auto virtualRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(virtualNode->renderDrawable_.get());
    ASSERT_NE(mainRenderDrawable, nullptr);
    ASSERT_NE(virtualRenderDrawable, nullptr);
    auto mainRenderParams = static_cast<RSScreenRenderParams*>(mainRenderDrawable->GetRenderParams().get());
    auto virtualRenderParams = static_cast<RSScreenRenderParams*>(virtualRenderDrawable->GetRenderParams().get());
    ASSERT_NE(mainRenderParams, nullptr);
    ASSERT_NE(virtualRenderParams, nullptr);
    virtualRenderParams->mirrorSourceDrawable_ = mainNode->renderDrawable_;

    auto renderEngine = RSUniRenderThread::Instance().GetRenderEngine();
    ASSERT_NE(renderEngine, nullptr);

    mainRenderParams->newColorSpace_ = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2100_HLG;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(virtualProcessor, nullptr);
    virtualProcessor->virtualScreenId_ = screenId;
    auto screen = screenManager_->GetScreen(virtualProcessor->virtualScreenId_);
    ASSERT_NE(screen, nullptr);
    auto surfaceConfigs = screen->GetMultiSurfaceConfigs();
    ASSERT_FALSE(surfaceConfigs.empty());
    ASSERT_NE(surfaceConfigs[0].surface, nullptr);

    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    std::shared_ptr<RSSurfaceOhosVulkan> rsSurface1 = std::make_shared<RSSurfaceOhosVulkan>(pSurface);
    auto tmpSurface = std::make_shared<Drawing::Surface>();
    auto surfaceFrame = std::make_unique<RSSurfaceFrameOhosVulkan>(tmpSurface, TEST_FRAME_DIM, TEST_FRAME_DIM,
        DEFAULT_BUFFER_AGE);
    SurfaceFrameConfig sfc;
    sfc.surface = pSurface;
    sfc.frame = std::make_unique<RSRenderFrame>(rsSurface1, std::move(surfaceFrame));
    ASSERT_NE(sfc.frame, nullptr);
    ASSERT_NE(sfc.frame->surfaceFrame_, nullptr);
    virtualProcessor->surfaceFrames_.push_back(std::move(sfc));
    virtualProcessor->InitForRenderThread(*virtualRenderDrawable, renderEngine);

    virtualRenderParams->newColorSpace_ = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_BT2100_HLG;
    virtualRenderParams->SetHDRPresent(true);
    virtualProcessor->InitForRenderThread(*virtualRenderDrawable, renderEngine);

    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<IBufferConsumerListener> listener = new BufferConsumerListener();
    cSurface->RegisterConsumerListener(listener);
    sptr<OHOS::IBufferProducer> producer2 = cSurface->GetProducer();
    sptr<OHOS::Surface> pSurface2 = Surface::CreateSurfaceAsProducer(producer2);
    int32_t fence;
    sptr<OHOS::SurfaceBuffer> sBuffer = nullptr;

    pSurface2->RequestBuffer(sBuffer, fence, requestConfig);
    NativeWindowBuffer* nativeWindowBuffer = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&sBuffer);
    ASSERT_NE(nativeWindowBuffer, nullptr);
    rsSurface1->mSurfaceList.emplace_back(nativeWindowBuffer);
    virtualProcessor->InitForRenderThread(*virtualRenderDrawable, renderEngine);
    auto res = RSHdrUtil::SetMetadata(RSHDRUtilConst::HDR_CAST_OUT_COLORSPACE,
        virtualProcessor->surfaceFrames_[0].frame, true);
    EXPECT_EQ(GSERROR_OK, res);
}
#endif

/**
 * @tc.name: OriginScreenRotation
 * @tc.desc: OriginScreenRotation Test
 * @tc.type: FUNC
 * @tc.require: issueI992VW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, OriginScreenRotation, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(nullptr, virtualProcessor);
    auto drawingCanvas = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    ASSERT_NE(nullptr, drawingCanvas);
    virtualProcessor->canvas_ = std::make_unique<RSPaintFilterCanvas>(drawingCanvas.get());
    ASSERT_NE(nullptr, virtualProcessor->canvas_);
    virtualProcessor->OriginScreenRotation(ScreenRotation::ROTATION_0, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    virtualProcessor->OriginScreenRotation(ScreenRotation::ROTATION_90, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    virtualProcessor->OriginScreenRotation(ScreenRotation::ROTATION_180, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    virtualProcessor->OriginScreenRotation(ScreenRotation::ROTATION_270, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
}

/**
 * @tc.name: Fill
 * @tc.desc: Fill Test
 * @tc.type: FUNC
 * @tc.require: issueI992VW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, Fill, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(nullptr, virtualProcessor);
    auto drawingCanvas = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    ASSERT_NE(nullptr, drawingCanvas);
    auto canvas = std::make_shared<RSPaintFilterCanvas>(drawingCanvas.get());
    virtualProcessor->Fill(*canvas, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT,
        DEFAULT_CANVAS_WIDTH / 2, DEFAULT_CANVAS_HEIGHT / 2);
}

/**
 * @tc.name: UniScale
 * @tc.desc: UniScale Test
 * @tc.type: FUNC
 * @tc.require: issueI992VW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, UniScale, TestSize.Level2)
{
    auto surface = Surface::CreateSurfaceAsConsumer("test_surface");
    ASSERT_NE(surface, nullptr);
    auto screenId = screenManager_->CreateVirtualScreen("virtual_screen", 10, 10, surface, 0UL, 0, {});

    NodeId mainNodeId = 1;
    NodeId virtualNodeId = 2;
    auto mainNode = std::make_shared<RSScreenRenderNode>(mainNodeId, screenNodeId_, context_);
    mainNode->InitRenderParams();
    auto virtualNode = std::make_shared<RSScreenRenderNode>(virtualNodeId, screenNodeId_, context_);
    virtualNode->InitRenderParams();
    ASSERT_NE(mainNode->renderDrawable_, nullptr);
    ASSERT_NE(virtualNode->renderDrawable_, nullptr);
    ASSERT_NE(mainNode->renderDrawable_->renderParams_, nullptr);
    ASSERT_NE(virtualNode->renderDrawable_->renderParams_, nullptr);

    auto mainRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(mainNode->renderDrawable_.get());
    auto virtualRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(virtualNode->renderDrawable_.get());
    ASSERT_NE(mainRenderDrawable, nullptr);
    ASSERT_NE(virtualRenderDrawable, nullptr);
    auto mainRenderParams = static_cast<RSScreenRenderParams* >(mainRenderDrawable->GetRenderParams().get());
    auto virtualRenderParams = static_cast<RSScreenRenderParams* >(virtualRenderDrawable->GetRenderParams().get());
    ASSERT_NE(mainRenderParams, nullptr);
    ASSERT_NE(virtualRenderParams, nullptr);
    virtualRenderParams->mirrorSourceDrawable_ = mainNode->renderDrawable_;
    virtualRenderParams->screenInfo_.id = screenId;

    auto& uniRenderThread = RSUniRenderThread::Instance();
    auto renderEngine = uniRenderThread.GetRenderEngine();

    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(nullptr, virtualProcessor);
    virtualProcessor->InitForRenderThread(*virtualRenderDrawable, renderEngine);

    auto drawingCanvas = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    ASSERT_NE(nullptr, drawingCanvas);
    auto canvas = std::make_shared<RSPaintFilterCanvas>(drawingCanvas.get());
    virtualProcessor->UniScale(*canvas, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT,
        DEFAULT_CANVAS_WIDTH / 3, DEFAULT_CANVAS_HEIGHT / 2);
    virtualProcessor->UniScale(*canvas, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT,
        DEFAULT_CANVAS_WIDTH / 2, DEFAULT_CANVAS_HEIGHT / 3);
    virtualProcessor->UniScale(*canvas, 0, DEFAULT_CANVAS_HEIGHT,
        DEFAULT_CANVAS_WIDTH / 2, DEFAULT_CANVAS_HEIGHT / 3);
    virtualProcessor->UniScale(*canvas, DEFAULT_CANVAS_WIDTH, 0,
        DEFAULT_CANVAS_WIDTH / 2, DEFAULT_CANVAS_HEIGHT / 3);
    virtualProcessor->UniScale(*canvas, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT,
        0, DEFAULT_CANVAS_HEIGHT / 3);
    virtualProcessor->UniScale(*canvas, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT,
        DEFAULT_CANVAS_WIDTH / 2, 0);

    bool slrEnabled = MultiScreenParam::IsSlrScaleEnabled();
    auto param = system::GetParameter("rosen.SLRScale.enabled", "");
    system::SetParameter("rosen.SLRScale.enabled", "1");
    MultiScreenParam::SetSlrScaleEnabled(true);
    virtualProcessor->mirrorScaleX_ = 0.5;
    virtualProcessor->mirrorScaleY_ = 0.5;
    virtualProcessor->drawMirrorCopy_ = true;
    virtualProcessor->UniScale(*canvas, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT,
        DEFAULT_CANVAS_WIDTH / 3, DEFAULT_CANVAS_HEIGHT / 2);

    virtualProcessor->slrManager_ = std::make_shared<RSSLRScaleFunction>(200, 200,
        500, 500);
    virtualProcessor->UniScale(*canvas, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT,
        DEFAULT_CANVAS_WIDTH / 3, DEFAULT_CANVAS_HEIGHT / 2);

    system::SetParameter("rosen.SLRScale.enabled", "0");
    Rect rect = {0, 0, 100, 100};
    screenManager_->SetMirrorScreenVisibleRect(screenId, rect, false);
    virtualProcessor->drawMirrorCopy_ = false;
    virtualProcessor->UniScale(*canvas, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT,
        DEFAULT_CANVAS_WIDTH / 3, DEFAULT_CANVAS_HEIGHT / 2);

    MultiScreenParam::SetSlrScaleEnabled(slrEnabled);
    system::SetParameter("rosen.SLRScale.enabled", param);
    screenManager_->RemoveVirtualScreen(screenId);
}

/**
 * @tc.name: ProcessRcdSurfaceTest
 * @tc.desc: Verify function ProcessRcdSurface
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessRcdSurfaceTest, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[0];
    RCDSurfaceType type = RCDSurfaceType::INVALID;
    RSRcdSurfaceRenderNode node(nodeId, type);
    processor->ProcessRcdSurface(node);
    EXPECT_FALSE(processor->forceCPU_);
}

/**
 * @tc.name: ProcessScreenSurfaceTest
 * @tc.desc: Verify function ProcessScreenSurface
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurfaceTest, TestSize.Level2)
{
    NodeId id = 0;
    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(id, 1);
    ASSERT_NE(screenRenderNode, nullptr);
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    processor->ProcessScreenSurface(*screenRenderNode);
    Drawing::Canvas canvas;
    processor->canvas_ = std::make_unique<RSPaintFilterCanvas>(&canvas);
    auto screenDrawable =
        static_cast<RSScreenRenderNodeDrawable*>(RSScreenRenderNodeDrawable::OnGenerate(screenRenderNode));
    auto surfaceHandler = screenDrawable->GetRSSurfaceHandlerOnDraw();
    surfaceHandler->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    processor->ProcessScreenSurface(*screenRenderNode);
    EXPECT_FALSE(processor->forceCPU_);
}

/**
 * @tc.name: CanvasInit_001
 * @tc.desc: CanvasInit Test, screenDrawable isFirstTimeToProcessor
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasInit_001, TestSize.Level2)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(virtualProcessor_, nullptr);
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    displayDrawable_ =
        std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(renderNode->GetRenderDrawable()).get();
    ASSERT_NE(displayDrawable_, nullptr);
    displayDrawable_->isFirstTimeToProcessor_ = true;
    virtualProcessor_->CanvasInit(*displayDrawable_);
    ASSERT_FALSE(displayDrawable_->isFirstTimeToProcessor_);
}

/**
 * @tc.name: CanvasInit_002
 * @tc.desc: CanvasInit Test, screenDrawable_ is not FirstTimeToProcessor, canvasRotation of virtualProcessor_ is true
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasInit_002, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    displayDrawable_ =
        std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(renderNode->GetRenderDrawable()).get();
    displayDrawable_->isFirstTimeToProcessor_ = false;
    virtualProcessor_->canvasRotation_ = true;
    virtualProcessor_->CanvasInit(*displayDrawable_);
    ASSERT_EQ(virtualProcessor_->screenRotation_, displayDrawable_->originScreenRotation_);
}

/**
 * @tc.name: CanvasInit_003
 * @tc.desc: CanvasInit Test, autoBufferRotation conditions
 * @tc.type:FUNC
 * @tc.require:issueICGA54
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasInit_003, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    displayDrawable_ =
        std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(renderNode->GetRenderDrawable()).get();
    displayDrawable_->isFirstTimeToProcessor_ = false;
    virtualProcessor_->canvasRotation_ = false;
    virtualProcessor_->CanvasInit(*displayDrawable_);

    virtualProcessor_->autoBufferRotation_ = true;
    virtualProcessor_->CanvasInit(*displayDrawable_);
    ASSERT_EQ(virtualProcessor_->screenRotation_, displayDrawable_->originScreenRotation_);
}

/**
 * @tc.name: CanvasInit_004
 * @tc.desc: CanvasInit Test, mirrorSourceRotation_ != ScreenRotation::INVALID_SCREEN_ROTATION
 * @tc.type:FUNC
 * @tc.require:issueICGA54
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasInit_004, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    RSDisplayNodeConfig config;
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    displayDrawable_ =
        std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(renderNode->GetRenderDrawable()).get();
    virtualProcessor_->mirrorSourceRotation_ = ScreenRotation::ROTATION_0;
    virtualProcessor_->CanvasInit(*displayDrawable_);

    virtualProcessor_->mirrorSourceRotation_ = ScreenRotation::INVALID_SCREEN_ROTATION;
    virtualProcessor_->CanvasInit(*displayDrawable_);
    ASSERT_EQ(virtualProcessor_->mirrorSourceRotation_, ScreenRotation::INVALID_SCREEN_ROTATION);
}

/**
 * @tc.name: CheckIfBufferSizeNeedChangeTest
 * @tc.desc: CheckIfBufferSizeNeedChange Test
 * @tc.type:FUNC
 * @tc.require:issueICGA54
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CheckIfBufferSizeNeedChangeTest, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    EXPECT_TRUE(virtualProcessor_->CheckIfBufferSizeNeedChange(
        ScreenRotation::ROTATION_0, ScreenRotation::ROTATION_90));
    EXPECT_FALSE(virtualProcessor_->CheckIfBufferSizeNeedChange(
        ScreenRotation::ROTATION_0, ScreenRotation::ROTATION_0));
}

/**
 * @tc.name: GetBufferAge_001
 * @tc.desc: GetBufferAge Test, surfaceFrames_ with null surface/frame, expect 0
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, GetBufferAge_001, TestSize.Level2)
{
    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    ASSERT_NE(config.frame, nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));

    auto ret = virtualProcessor_->GetBufferAge();
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: SetDirtyInfo_001
 * @tc.desc: SetDirtyInfo Test, surfaceFrames_ is empty
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetDirtyInfo_001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_TRUE(virtualProcessor_->surfaceFrames_.empty());
    std::vector<RectI> damageRegion {};
    virtualProcessor_->SetDirtyInfo(damageRegion);
}

/**
 * @tc.name: SetDirtyInfo_002
 * @tc.desc: SetDirtyInfo Test, surfaceFrames_ with null surface/frame
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetDirtyInfo_002, TestSize.Level2)
{
    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    ASSERT_NE(config.frame, nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));
    std::vector<RectI> damageRegion {};
    ASSERT_EQ(virtualProcessor_->SetRoiRegionToCodec(damageRegion), GSERROR_OK);

    virtualProcessor_->SetDirtyInfo(damageRegion);
}

/**
 * @tc.name: SetRoiRegionToCodec_001
 * @tc.desc: test SetRoiRegionToCodec while surfaceFrames_ is empty
 * @tc.type:FUNC
 * @tc.require:issuesIBHR8N
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetRoiRegionToCodec001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_TRUE(virtualProcessor_->surfaceFrames_.empty());

    std::vector<RectI> damageRegion {};
    ASSERT_EQ(virtualProcessor_->SetRoiRegionToCodec(damageRegion), GSERROR_OK);
}

/**
 * @tc.name: ProcessScreenSurfaceForRenderThread_001
 * @tc.desc: ProcessScreenSurfaceForRenderThread Test, isExpand_ is true, return directly
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurfaceForRenderThread_001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    virtualProcessor_->ProcessScreenSurfaceForRenderThread(*screenDrawable_);
}

/**
 * @tc.name: ProcessScreenSurfaceForRenderThread_002
 * @tc.desc: ProcessScreenSurfaceForRenderThread Test, isExpand_ is false, canvas and Buffer are not null ,
 * renderEngine_  is not null, return
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurfaceForRenderThread_002, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_->canvas_, nullptr);
    auto surfaceHandler = screenDrawable_->GetRSSurfaceHandlerOnDraw();
    surfaceHandler->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    processor_->ProcessScreenSurface(*rsScreenRenderNode_);
    ASSERT_NE(screenDrawable_->GetRSSurfaceHandlerOnDraw()->GetBuffer(), nullptr);

    virtualProcessor_->renderEngine_ = RSUniRenderThread::Instance().GetRenderEngine();
    ASSERT_NE(virtualProcessor_->renderEngine_, nullptr);
    virtualProcessor_->ProcessScreenSurfaceForRenderThread(*screenDrawable_);
}

/**
 * @tc.name: ProcessScreenSurfaceForRenderThread_003
 * @tc.desc: ProcessScreenSurfaceForRenderThread Test, isExpand_ is false, canvas_ is null, buffer not null, return
 * directly
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurfaceForRenderThread_003, TestSize.Level2)
{
    virtualProcessor_->canvas_ = nullptr;
    auto surfaceHandler = screenDrawable_->GetRSSurfaceHandlerOnDraw();
    surfaceHandler->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    processor_->ProcessScreenSurface(*rsScreenRenderNode_);
    ASSERT_NE(screenDrawable_->GetRSSurfaceHandlerOnDraw()->GetBuffer(), nullptr);
    virtualProcessor_->ProcessScreenSurfaceForRenderThread(*screenDrawable_);
}

/**
 * @tc.name: ProcessScreenSurfaceForRenderThread_004
 * @tc.desc: ProcessScreenSurfaceForRenderThread Test, isExpand_ is false, canvas_ is null, buffer is null, return
 * directly
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurfaceForRenderThread_004, TestSize.Level2)
{
    virtualProcessor_->canvas_ = nullptr;
    auto surfaceHandler = screenDrawable_->GetRSSurfaceHandlerOnDraw();
    surfaceHandler->buffer_.buffer = nullptr;
    ASSERT_EQ(screenDrawable_->GetRSSurfaceHandlerOnDraw()->GetBuffer(), nullptr);
    virtualProcessor_->ProcessScreenSurfaceForRenderThread(*screenDrawable_);
}

/**
 * @tc.name: ProcessScreenSurfaceForRenderThread_005
 * @tc.desc: ProcessScreenSurfaceForRenderThread Test, isExpand_ is false, canvas_ is not null, buffer is null, return
 * directly
 * @tc.type:FUNC
 * @tc.require:issuesIAJ4FW
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurfaceForRenderThread_005, TestSize.Level2)
{
    ASSERT_NE(nullptr, virtualProcessor_->canvas_);
    auto surfaceHandler = screenDrawable_->GetRSSurfaceHandlerOnDraw();
    surfaceHandler->buffer_.buffer = nullptr;
    ASSERT_EQ(screenDrawable_->GetRSSurfaceHandlerOnDraw()->GetBuffer(), nullptr);
    virtualProcessor_->ProcessScreenSurfaceForRenderThread(*screenDrawable_);
}

/**
 * @tc.name: CanvasClipRegionForUniscaleMode
 * @tc.desc: Canvas do clipRegion, When performing uniscale on a virtual screen.
 * @tc.type:FUNC
 * @tc.require:issuesIAOEPL
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasClipRegionForUniscaleMode, TestSize.Level2)
{
    auto surface = Surface::CreateSurfaceAsConsumer("test_surface");
    ASSERT_NE(surface, nullptr);
    auto screenId = screenManager_->CreateVirtualScreen("virtual_screen", 10, 10, surface, 0UL, 0, {});

    NodeId mainNodeId = 1;
    NodeId virtualNodeId = 2;
    auto mainNode = std::make_shared<RSScreenRenderNode>(mainNodeId, screenNodeId_, context_);
    mainNode->InitRenderParams();
    auto virtualNode = std::make_shared<RSScreenRenderNode>(virtualNodeId, screenNodeId_, context_);
    virtualNode->InitRenderParams();
    ASSERT_NE(mainNode->renderDrawable_, nullptr);
    ASSERT_NE(virtualNode->renderDrawable_, nullptr);
    ASSERT_NE(mainNode->renderDrawable_->renderParams_, nullptr);
    ASSERT_NE(virtualNode->renderDrawable_->renderParams_, nullptr);

    auto mainRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(mainNode->renderDrawable_.get());
    auto virtualRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(virtualNode->renderDrawable_.get());
    ASSERT_NE(mainRenderDrawable, nullptr);
    ASSERT_NE(virtualRenderDrawable, nullptr);
    auto mainRenderParams = static_cast<RSScreenRenderParams* >(mainRenderDrawable->GetRenderParams().get());
    auto virtualRenderParams = static_cast<RSScreenRenderParams* >(virtualRenderDrawable->GetRenderParams().get());
    ASSERT_NE(mainRenderParams, nullptr);
    ASSERT_NE(virtualRenderParams, nullptr);
    virtualRenderParams->mirrorSourceDrawable_ = mainNode->renderDrawable_;
    virtualRenderParams->screenInfo_.id = screenId;

    auto& uniRenderThread = RSUniRenderThread::Instance();
    auto renderEngine = uniRenderThread.GetRenderEngine();
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(nullptr, virtualProcessor);
    virtualProcessor->InitForRenderThread(*virtualRenderDrawable, renderEngine);
    virtualProcessor_->CanvasClipRegionForUniscaleMode();

    virtualProcessor_->scaleMode_ = ScreenScaleMode::UNISCALE_MODE;
    virtualProcessor_->CanvasClipRegionForUniscaleMode();

    Rect rect = {0, 0, 100, 100};
    screenManager_->SetMirrorScreenVisibleRect(screenId, rect, false);
    virtualProcessor_->CanvasClipRegionForUniscaleMode();

    virtualProcessor_->drawMirrorCopy_ = false;
    ScreenInfo mainScreenInfo;
    mainScreenInfo.isSamplingOn = true;
    virtualProcessor_->CanvasClipRegionForUniscaleMode();

    auto param = system::GetParameter("rosen.SLRScale.enabled", "");
    system::SetParameter("rosen.SLRScale.enabled", "1");
    virtualProcessor_->CanvasClipRegionForUniscaleMode();
    system::SetParameter("rosen.SLRScale.enabled", "0");
    virtualProcessor_->CanvasClipRegionForUniscaleMode();

    screenManager_->RemoveVirtualScreen(screenId);
}

/**
 * @tc.name: ProcessCacheImage
 * @tc.desc: draw virtual screen by cache image.
 * @tc.type:FUNC
 * @tc.require:issuesIBIPST
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessCacheImage, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(nullptr, virtualProcessor);

    Drawing::Canvas canvas;
    RSPaintFilterCanvas paintCanvase(&canvas);
    std::shared_ptr<Drawing::Image> image = std::make_shared<Drawing::Image>();
    BufferDrawParam params;
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    params.buffer = surfaceNode->GetRSSurfaceHandler()->GetBuffer();
    Drawing::Rect srcRect(0.0f, 0.0f, 10, 20);
    Drawing::Rect dstRect(0.0f, 0.0f, 10, 20);
    Drawing::Brush paint;
    params.srcRect = srcRect;
    params.dstRect = dstRect;
    params.paint = paint;
    Drawing::SamplingOptions samplingOptions(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NEAREST);
    auto renderEngine = std::make_shared<RSRenderEngine>();
    ASSERT_NE(renderEngine, nullptr);
    renderEngine->DrawImageRect(paintCanvase, image, params, samplingOptions);
    ASSERT_NE(image, nullptr);

    virtualProcessor->ProcessCacheImage(*image);
}

/**
 * @tc.name: ScaleMirrorIfNeed
 * @tc.desc: test ScaleMirrorIfNeed.
 * @tc.type:FUNC
 * @tc.require:issues
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ScaleMirrorIfNeedTest, TestSize.Level2)
{
    auto surface = Surface::CreateSurfaceAsConsumer("test_surface");
    ASSERT_NE(surface, nullptr);
    auto screenId = screenManager_->CreateVirtualScreen("virtual_screen", 10, 10, surface, 0UL, 0, {});

    NodeId mainNodeId = 1;
    NodeId virtualNodeId = 2;
    auto mainNode = std::make_shared<RSScreenRenderNode>(mainNodeId, screenNodeId_, context_);
    mainNode->InitRenderParams();
    auto virtualNode = std::make_shared<RSScreenRenderNode>(virtualNodeId, screenNodeId_, context_);
    virtualNode->InitRenderParams();
    ASSERT_NE(mainNode->renderDrawable_, nullptr);
    ASSERT_NE(virtualNode->renderDrawable_, nullptr);
    ASSERT_NE(mainNode->renderDrawable_->renderParams_, nullptr);
    ASSERT_NE(virtualNode->renderDrawable_->renderParams_, nullptr);

    auto mainRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(mainNode->renderDrawable_.get());
    auto virtualRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(virtualNode->renderDrawable_.get());
    ASSERT_NE(mainRenderDrawable, nullptr);
    ASSERT_NE(virtualRenderDrawable, nullptr);
    auto mainRenderParams = static_cast<RSScreenRenderParams* >(mainRenderDrawable->GetRenderParams().get());
    auto virtualRenderParams = static_cast<RSScreenRenderParams* >(virtualRenderDrawable->GetRenderParams().get());
    ASSERT_NE(mainRenderParams, nullptr);
    ASSERT_NE(virtualRenderParams, nullptr);
    virtualRenderParams->mirrorSourceDrawable_ = mainNode->renderDrawable_;
    virtualRenderParams->screenInfo_.id = screenId;

    auto& uniRenderThread = RSUniRenderThread::Instance();
    auto renderEngine = uniRenderThread.GetRenderEngine();
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(virtualProcessor, nullptr);
    virtualProcessor->InitForRenderThread(*virtualRenderDrawable, renderEngine);

    auto drawingCanvas_ = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    auto canvas = std::make_unique<RSPaintFilterCanvas>(drawingCanvas_.get());

    virtualProcessor->ScaleMirrorIfNeed(ScreenRotation::ROTATION_90, *canvas);

    virtualProcessor->mirroredScreenWidth_ = 100;
    virtualProcessor->virtualScreenWidth_ = 100;
    virtualProcessor->ScaleMirrorIfNeed(ScreenRotation::ROTATION_90, *canvas);

    virtualProcessor->mirroredScreenHeight_ = 100;
    virtualProcessor->virtualScreenHeight_ = 100;
    virtualProcessor->ScaleMirrorIfNeed(ScreenRotation::ROTATION_90, *canvas);

    Rect rect = {0, 0, 100, 100};
    screenManager_->SetMirrorScreenVisibleRect(screenId, rect, false);
    virtualProcessor->ScaleMirrorIfNeed(ScreenRotation::ROTATION_90, *canvas);
    screenManager_->RemoveVirtualScreen(screenId);
}

/**
 * @tc.name: Fill scaling test
 * @tc.desc: test Fill scaling mode
 * @tc.type:FUNC
 * @tc.require:issues
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FillTest, TestSize.Level2)
{
    auto surface = Surface::CreateSurfaceAsConsumer("test_surface");
    ASSERT_NE(surface, nullptr);
    auto screenId = screenManager_->CreateVirtualScreen("virtual_screen", 10, 10, surface, 0UL, 0, {});

    NodeId mainNodeId = 1;
    NodeId virtualNodeId = 2;
    auto mainNode = std::make_shared<RSScreenRenderNode>(mainNodeId, screenNodeId_, context_);
    mainNode->InitRenderParams();
    auto virtualNode = std::make_shared<RSScreenRenderNode>(virtualNodeId, screenNodeId_, context_);
    virtualNode->InitRenderParams();
    ASSERT_NE(mainNode->renderDrawable_, nullptr);
    ASSERT_NE(virtualNode->renderDrawable_, nullptr);
    ASSERT_NE(mainNode->renderDrawable_->renderParams_, nullptr);
    ASSERT_NE(virtualNode->renderDrawable_->renderParams_, nullptr);

    auto mainRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(mainNode->renderDrawable_.get());
    auto virtualRenderDrawable = static_cast<RSScreenRenderNodeDrawable* >(virtualNode->renderDrawable_.get());
    ASSERT_NE(mainRenderDrawable, nullptr);
    ASSERT_NE(virtualRenderDrawable, nullptr);
    auto mainRenderParams = static_cast<RSScreenRenderParams* >(mainRenderDrawable->GetRenderParams().get());
    auto virtualRenderParams = static_cast<RSScreenRenderParams* >(virtualRenderDrawable->GetRenderParams().get());
    ASSERT_NE(mainRenderParams, nullptr);
    ASSERT_NE(virtualRenderParams, nullptr);
    virtualRenderParams->mirrorSourceDrawable_ = mainNode->renderDrawable_;
    virtualRenderParams->screenInfo_.id = screenId;

    auto& uniRenderThread = RSUniRenderThread::Instance();
    auto renderEngine = uniRenderThread.GetRenderEngine();
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(virtualProcessor, nullptr);
    virtualProcessor->InitForRenderThread(*virtualRenderDrawable, renderEngine);

    auto drawingCanvas_ = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    auto canvas = std::make_unique<RSPaintFilterCanvas>(drawingCanvas_.get());
    float mainWidth = 100;
    float mainHeight = 200;
    float mirrorWidth = 300;
    float mirrorHeight = 400;
    virtualProcessor->Fill(*canvas, mainWidth, mainHeight, mirrorWidth, mirrorHeight);

    Rect rect = {0, 0, 100, 100};
    screenManager_->SetMirrorScreenVisibleRect(screenId, rect, false);
    virtualProcessor->Fill(*canvas, mainWidth, mainHeight, mirrorWidth, mirrorHeight);

    virtualProcessor->drawMirrorCopy_ = true;
    virtualProcessor->Fill(*canvas, mainWidth, mainHeight, mirrorWidth, mirrorHeight);

    screenManager_->RemoveVirtualScreen(screenId);
}

/**
 * @tc.name: EnableSlrScale
 * @tc.desc: test enable slr scale switch.
 * @tc.type:FUNC
 * @tc.require:issuesIBJLYR
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, EnableSlrScale, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    virtualProcessor->EnableSlrScale();
    ASSERT_NE(nullptr, virtualProcessor);
}

/**
 * @tc.name: SetSpecialLayerType
 * @tc.desc: test draw virtual mirror screen by copy.
 * @tc.type:FUNC
 * @tc.require:issuesIBKZFK
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetSpecialLayerType, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_NE(nullptr, virtualProcessor);
    virtualProcessor->SetDrawVirtualMirrorCopy(true);
}

/**
 * @tc.name: SetColorSpaceForMetadata
 * @tc.desc: SetColorSpaceForMetadata test - test all error paths
 * @tc.type:FUNC
 * @tc.require:issuesIBKZFK
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetColorSpaceForMetadata, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    EXPECT_NE(nullptr, virtualProcessor);

    GraphicColorGamut validColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DISPLAY_P3;

    // Test 1: empty surfaceFrames_ -> GSERROR_OK (loop doesn't execute)
    ASSERT_TRUE(virtualProcessor->surfaceFrames_.empty());
    auto res = virtualProcessor->SetColorSpaceForMetadata(validColorGamut);
    EXPECT_EQ(GSERROR_OK, res);

    // Test 2: surfaceFrames_ with null frame -> GSERROR_INVALID_ARGUMENTS
    SurfaceFrameConfig nullFrameConfig;
    nullFrameConfig.frame = nullptr;
    virtualProcessor->surfaceFrames_.push_back(std::move(nullFrameConfig));
    res = virtualProcessor->SetColorSpaceForMetadata(validColorGamut);
    EXPECT_EQ(GSERROR_INVALID_ARGUMENTS, res);

    // Test 3: surface exists but buffer is nullptr -> GSERROR_NO_BUFFER
    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    std::shared_ptr<RSSurfaceOhos> rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    EXPECT_NE(nullptr, rsSurface);
    virtualProcessor->surfaceFrames_.clear();
    SurfaceFrameConfig surfaceConfig;
    surfaceConfig.frame = std::make_unique<RSRenderFrame>(rsSurface, nullptr);
    virtualProcessor->surfaceFrames_.push_back(std::move(surfaceConfig));
    res = virtualProcessor->SetColorSpaceForMetadata(validColorGamut);
    EXPECT_EQ(GSERROR_NO_BUFFER, res);

    // Note: Testing successful path requires a valid buffer with GetCurrentBuffer() support,
    // which is difficult to set up in unit tests. The above tests cover all null-check error paths.
}

/**
 * @tc.name: SetRoiRegionToCodec002
 * @tc.desc: SetRoiRegionToCodec002 test - test all error paths.
 * @tc.type:FUNC
 * @tc.require:issuesIBKZFK
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetRoiRegionToCodec002, TestSize.Level2)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    EXPECT_NE(nullptr, virtualProcessor);

    // Test 1: empty surfaceFrames_ -> GSERROR_OK (loop doesn't execute)
    ASSERT_TRUE(virtualProcessor->surfaceFrames_.empty());
    RectI rect(1, 2, 3, 4);
    std::vector<RectI> vRect = { rect };
    auto res = virtualProcessor->SetRoiRegionToCodec(vRect);
    EXPECT_EQ(GSERROR_OK, res);

    // Test 2: surfaceFrames_ with null frame -> GSERROR_INVALID_ARGUMENTS
    SurfaceFrameConfig nullFrameConfig;
    nullFrameConfig.frame = nullptr;
    virtualProcessor->surfaceFrames_.push_back(std::move(nullFrameConfig));
    res = virtualProcessor->SetRoiRegionToCodec(vRect);
    EXPECT_EQ(GSERROR_INVALID_ARGUMENTS, res);

    // Test 3: surface exists but buffer is nullptr -> GSERROR_NO_BUFFER
    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    std::shared_ptr<RSSurfaceOhos> rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    EXPECT_NE(nullptr, rsSurface);

    virtualProcessor->surfaceFrames_.clear();
    SurfaceFrameConfig surfaceConfig;
    surfaceConfig.frame = std::make_unique<RSRenderFrame>(rsSurface, nullptr);
    virtualProcessor->surfaceFrames_.push_back(std::move(surfaceConfig));
    res = virtualProcessor->SetRoiRegionToCodec(vRect);
    EXPECT_EQ(GSERROR_NO_BUFFER, res);

    // Test 4: Multiple rects in vector (tests the merge path when size > ROI_REGIONS_MAX_CNT)
    vRect.emplace_back(rect);
    vRect.emplace_back(rect);
    vRect.emplace_back(rect);
    vRect.emplace_back(rect);
    vRect.emplace_back(rect);
    res = virtualProcessor->SetRoiRegionToCodec(vRect);
    EXPECT_EQ(GSERROR_NO_BUFFER, res);

    // Note: Testing successful path requires a valid buffer with GetCurrentBuffer() support,
    // which is difficult to set up in unit tests. The above tests cover all null-check error paths
    // and the merge path for multiple rects.
}

/**
 * @tc.name: UpdateMirrorInfo001
 * @tc.desc: Test UpdateMirrorInfo
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, UpdateMirrorInfo001, TestSize.Level1)
{
    NodeId displayNodeId = 1;
    RSDisplayNodeConfig displayConfig;
    auto displayNode = std::make_shared<RSLogicalDisplayRenderNode>(displayNodeId, displayConfig);
    displayNode->InitRenderParams();
    ASSERT_NE(displayNode->renderDrawable_->renderParams_, nullptr);

    auto displayDrawable = static_cast<RSLogicalDisplayRenderNodeDrawable*>(displayNode->renderDrawable_.get());
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderProcessor>(processor);
    auto result1 = virtualProcessor->UpdateMirrorInfo(*displayDrawable);
    ASSERT_EQ(result1, true);

    displayDrawable->renderParams_ = nullptr;
    auto result2 = virtualProcessor->UpdateMirrorInfo(*displayDrawable);
    ASSERT_EQ(result2, false);
}

/**
 * @tc.name: UpdateMirrorInfo002
 * @tc.desc: test UpdateMirrorInfo
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, UpdateMirrorInfo002, TestSize.Level2)
{
    RSDisplayNodeConfig mainNodeConfig;
    auto mainDisplayNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, mainNodeConfig);
    mainDisplayNode->InitRenderParams();
    auto sourceDrawable = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(mainDisplayNode);

    RSDisplayNodeConfig config;
    config.isMirrored = true;
    config.mirrorNodeId = mainDisplayNode->GetId();
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    auto drawable = std::static_pointer_cast<DrawableV2::RSLogicalDisplayRenderNodeDrawable>(
        DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(renderNode));
    auto params = static_cast<RSLogicalDisplayRenderParams*>(drawable->renderParams_.get());
    params->mirrorSourceDrawable_ = sourceDrawable;

    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    auto result = virtualProcessor->UpdateMirrorInfo(*drawable);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: UpdateMirrorInfo003
 * @tc.desc: test UpdateMirrorInfo
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, UpdateMirrorInfo003, TestSize.Level2)
{
    RSDisplayNodeConfig mainNodeConfig;
    auto mainDisplayNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, mainNodeConfig);
    mainDisplayNode->InitRenderParams();
    auto sourceDrawable = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(mainDisplayNode);

    RSDisplayNodeConfig config;
    config.isMirrored = true;
    config.mirrorNodeId = mainDisplayNode->GetId();
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    auto drawable = std::static_pointer_cast<DrawableV2::RSLogicalDisplayRenderNodeDrawable>(
        DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(renderNode));
    auto params = static_cast<RSLogicalDisplayRenderParams*>(drawable->renderParams_.get());
    params->mirrorSourceDrawable_ = sourceDrawable;
    sourceDrawable->renderParams_ = nullptr;

    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    auto result = virtualProcessor->UpdateMirrorInfo(*drawable);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: UpdateMirrorInfo004
 * @tc.desc: test UpdateMirrorInfo
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, UpdateMirrorInfo004, TestSize.Level2)
{
    RSDisplayNodeConfig mainNodeConfig;
    auto mainDisplayNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, mainNodeConfig);
    mainDisplayNode->InitRenderParams();
    auto sourceDrawable = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(mainDisplayNode);
    auto mainScreenNode = std::make_shared<RSScreenRenderNode>(DEFAULT_ID - 1, 0);
    mainScreenNode->InitRenderParams();
    auto sourceScreenDrawable = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(mainScreenNode);
    ASSERT_NE(sourceDrawable->renderParams_, nullptr);
    auto displayParams = static_cast<RSLogicalDisplayRenderParams*>(sourceDrawable->renderParams_.get());
    displayParams->SetAncestorScreenDrawable(sourceScreenDrawable);

    RSDisplayNodeConfig config;
    config.isMirrored = true;
    config.mirrorNodeId = mainDisplayNode->GetId();
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    auto drawable = std::static_pointer_cast<DrawableV2::RSLogicalDisplayRenderNodeDrawable>(
        DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(renderNode));
    auto params = static_cast<RSLogicalDisplayRenderParams*>(drawable->renderParams_.get());
    params->mirrorSourceDrawable_ = sourceDrawable;
    sourceDrawable->renderParams_ = nullptr;

    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    auto result = virtualProcessor->UpdateMirrorInfo(*drawable);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: UpdateMirrorInfo005
 * @tc.desc: test UpdateMirrorInfo
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, UpdateMirrorInfo005, TestSize.Level2)
{
    RSDisplayNodeConfig mainNodeConfig;
    auto mainDisplayNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, mainNodeConfig);
    mainDisplayNode->InitRenderParams();
    auto sourceDrawable = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(mainDisplayNode);
    auto mainScreenNode = std::make_shared<RSScreenRenderNode>(DEFAULT_ID - 1, 0);
    mainScreenNode->InitRenderParams();
    auto sourceScreenDrawable = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(mainScreenNode);
    ASSERT_NE(sourceDrawable->renderParams_, nullptr);
    auto displayParams = static_cast<RSLogicalDisplayRenderParams*>(sourceDrawable->renderParams_.get());
    displayParams->SetAncestorScreenDrawable(sourceScreenDrawable);

    RSDisplayNodeConfig config;
    config.isMirrored = true;
    config.mirrorNodeId = mainDisplayNode->GetId();
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    auto drawable = std::static_pointer_cast<DrawableV2::RSLogicalDisplayRenderNodeDrawable>(
        DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(renderNode));
    auto params = static_cast<RSLogicalDisplayRenderParams*>(drawable->renderParams_.get());
    params->mirrorSourceDrawable_ = sourceDrawable;

    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    auto result = virtualProcessor->UpdateMirrorInfo(*drawable);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: UpdateMirrorInfo006
 * @tc.desc: test UpdateMirrorInfo
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, UpdateMirrorInfo006, TestSize.Level2)
{
    RSDisplayNodeConfig mainNodeConfig;
    auto mainDisplayNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, mainNodeConfig);
    mainDisplayNode->InitRenderParams();
    auto sourceDrawable = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(mainDisplayNode);
    auto mainScreenNode = std::make_shared<RSScreenRenderNode>(DEFAULT_ID - 1, 0);
    mainScreenNode->InitRenderParams();
    auto sourceScreenDrawable = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(mainScreenNode);
    ASSERT_NE(sourceDrawable->renderParams_, nullptr);
    auto displayParams = static_cast<RSLogicalDisplayRenderParams*>(sourceDrawable->renderParams_.get());
    displayParams->SetAncestorScreenDrawable(sourceScreenDrawable);

    RSDisplayNodeConfig config;
    config.isMirrored = true;
    config.mirrorNodeId = mainDisplayNode->GetId();
    auto renderNode = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID, config);
    renderNode->InitRenderParams();
    auto drawable = std::static_pointer_cast<DrawableV2::RSLogicalDisplayRenderNodeDrawable>(
        DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(renderNode));
    auto params = static_cast<RSLogicalDisplayRenderParams*>(drawable->renderParams_.get());
    params->mirrorSourceDrawable_ = sourceDrawable;
    auto mirroredScreenParams = static_cast<RSScreenRenderParams*>(sourceScreenDrawable->renderParams_.get());
    mirroredScreenParams->screenProperty_.Set<ScreenPropertyType::SAMPLING_OPTION>(
        std::make_tuple(true, 0.f, 0.f, 1.f));

    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    auto result = virtualProcessor->UpdateMirrorInfo(*drawable);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: ProcessScreenSurfaceForRenderThread001
 * @tc.desc: Test ProcessScreenSurfaceForRenderThread
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurfaceForRenderThread001, TestSize.Level1)
{
    NodeId screenNodeId = 100;
    auto context1 = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(screenNodeId, 0, context1->weak_from_this());
    screenNode->InitRenderParams();
    ASSERT_NE(screenNode->renderDrawable_, nullptr);
    ASSERT_NE(screenNode->renderDrawable_->renderParams_, nullptr);

    auto screenDrawable = static_cast<RSScreenRenderNodeDrawable*>(screenNode->renderDrawable_.get());
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderProcessor>(processor);
    screenDrawable->surfaceHandler_->buffer_.buffer = SurfaceBuffer::Create();
    ASSERT_NE(screenDrawable->GetRSSurfaceHandlerOnDraw()->GetBuffer(), nullptr);
    virtualProcessor_->ProcessScreenSurfaceForRenderThread(*screenDrawable);

    auto context2 = std::make_shared<RSContext>();
    auto newScreenNode = std::make_shared<RSScreenRenderNode>(1, 0, context2->weak_from_this());
    newScreenNode->InitRenderParams();
    auto newScreenDrawable = static_cast<RSScreenRenderNodeDrawable* >(newScreenNode->renderDrawable_.get());
    newScreenDrawable->renderParams_ = nullptr;
    virtualProcessor_->ProcessScreenSurfaceForRenderThread(*newScreenDrawable);
    ASSERT_NE(screenDrawable->GetRSSurfaceHandlerOnDraw()->GetBuffer(), nullptr);
}

/**
 * @tc.name: ProcessScreenSurfaceForRenderThread002
 * @tc.desc: Test ProcessScreenSurfaceForRenderThread
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, ProcessScreenSurfaceForRenderThread002, TestSize.Level1)
{
    NodeId screenNodeId = 1;
    ScreenId screenId = 2;
    auto context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(screenNodeId, screenId, context->weak_from_this());
    screenNode->InitRenderParams();
    ASSERT_NE(screenNode->renderDrawable_, nullptr);
    ASSERT_NE(screenNode->renderDrawable_->renderParams_, nullptr);

    auto screenDrawable = static_cast<RSScreenRenderNodeDrawable*>(screenNode->renderDrawable_.get());
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    std::shared_ptr<RSBaseRenderEngine> renderEngine = nullptr;
    virtualProcessor->visibleRect_ = Drawing::RectI(0, 0, 1044, 2088);

    auto context2 = std::make_shared<RSContext>();
    auto newScreenNode = std::make_shared<RSScreenRenderNode>(1, 0, context2->weak_from_this());
    virtualProcessor_->ProcessScreenSurfaceForRenderThread(*screenDrawable);
    ASSERT_EQ(screenDrawable->GetRSSurfaceHandlerOnDraw()->GetBuffer() == nullptr, true);
}

#ifdef RS_ENABLE_VK
/**
 * @tc.name: CancelCurrentFrame
 * @tc.desc: Test CancelCurrentFrame
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CancelCurrentFrame, TestSize.Level1)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    virtualProcessor->CancelCurrentFrame();
    ASSERT_TRUE(virtualProcessor->surfaceFrames_.empty());

    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosVulkan>(pSurface);
    ASSERT_NE(nullptr, rsSurface);
    SurfaceFrameConfig config;
    config.surface = pSurface;
    config.frame = std::make_unique<RSRenderFrame>(rsSurface, nullptr);
    config.frame->targetSurface_ = nullptr;
    virtualProcessor->surfaceFrames_.push_back(std::move(config));
    virtualProcessor->CancelCurrentFrame();
    ASSERT_EQ(virtualProcessor->surfaceFrames_.size(), 1u);
    ASSERT_NE(virtualProcessor->surfaceFrames_[0].frame, nullptr);
}
#endif // RS_ENABLE_VK

/**
* @tc.name: SetVirtualScreenSizeTest
* @tc.desc: test SetVirtualScreenSize
* @tc.type:FUNC
* @tc.require:
*/
HWTEST_F(RSUniRenderVirtualProcessorTest, SetVirtualScreenSizeTest, TestSize.Level1)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(CompositeType::UNI_RENDER_MIRROR_COMPOSITE, 0);
    auto virtualProcessor = std::static_pointer_cast<RSUniRenderVirtualProcessor>(processor);
    ASSERT_TRUE(virtualProcessor->surfaceFrames_.empty());

    auto screenNode = std::make_shared<RSScreenRenderNode>(10, 20);
    screenNode->InitRenderParams();
    ASSERT_NE(screenNode->renderDrawable_, nullptr);
    ASSERT_NE(screenNode->renderDrawable_->renderParams_, nullptr);
    auto screenDrawable = static_cast<RSScreenRenderNodeDrawable*>(screenNode->renderDrawable_.get());

    screenDrawable->renderParams_ = nullptr;
    virtualProcessor->SetVirtualScreenSize(*screenDrawable);
}

/**
 * @tc.name: GetFrameAcquireFence_RenderFrameNullTest001
 * @tc.desc: Test GetFrameAcquireFence when surfaceFrames_ is empty
 *           Should return SyncFence::InvalidFence()
 *           Should return SyncFence::InvalidFence()
 * @tc.type: FUNC
 * @tc.require: issue41
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, GetFrameAcquireFence_RenderFrameNullTest001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);

    // Empty surfaceFrames_ -> returns InvalidFence
    ASSERT_TRUE(virtualProcessor_->surfaceFrames_.empty());

    auto fence = virtualProcessor_->GetFrameAcquireFence();
    ASSERT_NE(fence, nullptr);
    EXPECT_FALSE(fence->IsValid());
    EXPECT_EQ(fence->Get(), -1);
}

/**
 * @tc.name: GetFrameAcquireFence_RenderFrameValidTest001
 * @tc.desc: Test GetFrameAcquireFence when surfaceFrames_ has valid frame
 *           Should return fence from surfaceFrames_ frame
 * @tc.type: FUNC
 * @tc.require: issue41
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, GetFrameAcquireFence_RenderFrameValidTest001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);

    auto consumer = IConsumerSurface::Create("test_acquire_fence");
    ASSERT_NE(consumer, nullptr);
    auto producer = consumer->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);

    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    ASSERT_NE(rsSurface, nullptr);

    auto mockFrame = std::make_unique<RSSurfaceFrameOhosRaster>(TEST_FRAME_DIM, TEST_FRAME_DIM);

    SurfaceFrameConfig config;
    config.surface = pSurface;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface),
        std::move(mockFrame));

    ASSERT_NE(config.frame, nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));

    auto fence = virtualProcessor_->GetFrameAcquireFence();
    ASSERT_NE(fence, nullptr);
}

// ==================== CanvasClipRegionForUniscaleMode ====================

/**
 * @tc.name: CanvasClipRegionForUniscaleMode_CanvasNullTest001
 * @tc.desc: Test CanvasClipRegionForUniscaleMode when canvas_ is nullptr
 *           The if (canvas_ == nullptr) branch at line 633 should be true
 * @tc.type: FUNC
 * @tc.require: issue41
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasClipRegionForUniscaleMode_CanvasNullTest001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);

    // Set canvas_ to nullptr
    virtualProcessor_->canvas_ = nullptr;

    Drawing::Matrix matrix;
    bool isSamplingOn = false;

    // Should return early when canvas_ is nullptr (no crash)
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CanvasClipRegionForUniscaleMode(matrix, isSamplingOn));
}

/**
 * @tc.name: CanvasClipRegionForUniscaleMode_NotUniscaleModeTest001
 * @tc.desc: Test CanvasClipRegionForUniscaleMode when scaleMode_ is not UNISCALE_MODE
 *           The if (scaleMode_ != UNISCALE_MODE) branch at line 637 should be true
 * @tc.type: FUNC
 * @tc.require: issue41
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasClipRegionForUniscaleMode_NotUniscaleModeTest001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);

    // Set scaleMode to FILL_MODE (not UNISCALE_MODE)
    virtualProcessor_->scaleMode_ = ScreenScaleMode::FILL_MODE;

    Drawing::Matrix matrix;
    bool isSamplingOn = false;

    // Should return early when scaleMode_ is not UNISCALE_MODE (no crash)
    // canvas_ is nullptr, but the function returns at line 637 before checking canvas
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CanvasClipRegionForUniscaleMode(matrix, isSamplingOn));
}

/**
 * @tc.name: CanvasClipRegionForUniscaleMode_EnableVisibleRectTest001
 * @tc.desc: Test CanvasClipRegionForUniscaleMode when enableVisibleRect_ is true and drawMirrorCopy_ is true
 *           The if (enableVisibleRect_) and if (drawMirrorCopy_) branches should be true
 * @tc.type: FUNC
 * @tc.require: issue41
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasClipRegionForUniscaleMode_EnableVisibleRectTest001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);

    // Set up canvas using proper shared_ptr with explicit cast to resolve constructor ambiguity
    Drawing::Canvas drawCanvas;
    auto canvas = std::make_shared<RSPaintFilterCanvas>(&drawCanvas);
    virtualProcessor_->canvas_ = canvas;

    // Set scaleMode to UNISCALE_MODE
    virtualProcessor_->scaleMode_ = ScreenScaleMode::UNISCALE_MODE;

    // Set enableVisibleRect_ to true
    virtualProcessor_->enableVisibleRect_ = true;

    // Set drawMirrorCopy_ to true
    virtualProcessor_->drawMirrorCopy_ = true;

    // Set visibleRect_
    virtualProcessor_->visibleRect_ = Drawing::RectI(0, 0, 100, 100);

    // Set mirrored screen size
    virtualProcessor_->mirroredScreenWidth_ = 200;
    virtualProcessor_->mirroredScreenHeight_ = 200;

    Drawing::Matrix matrix;
    bool isSamplingOn = false;

    // Should clip region with visibleRect when enableVisibleRect_ and drawMirrorCopy_ are true
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CanvasClipRegionForUniscaleMode(matrix, isSamplingOn));
}

/**
 * @tc.name: CanvasClipRegionForUniscaleMode_EnableVisibleRectNoMirrorCopyTest001
 * @tc.desc: Test CanvasClipRegionForUniscaleMode when enableVisibleRect_ is true and drawMirrorCopy_ is false
 *           The if (enableVisibleRect_) branch is true, if (drawMirrorCopy_) branch is false
 * @tc.type: FUNC
 * @tc.require: issue41
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasClipRegionForUniscaleMode_EnableVisibleRectNoMirrorCopyTest001,
    TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);

    // Set up canvas using proper shared_ptr with explicit canvas object
    Drawing::Canvas drawCanvas;
    auto canvas = std::make_shared<RSPaintFilterCanvas>(&drawCanvas);
    virtualProcessor_->canvas_ = canvas;

    // Set scaleMode to UNISCALE_MODE
    virtualProcessor_->scaleMode_ = ScreenScaleMode::UNISCALE_MODE;

    // Set enableVisibleRect_ to true
    virtualProcessor_->enableVisibleRect_ = true;

    // Set drawMirrorCopy_ to false
    virtualProcessor_->drawMirrorCopy_ = false;

    // Set visibleRect_
    virtualProcessor_->visibleRect_ = Drawing::RectI(10, 10, 80, 80);

    // Set mirrored screen size and translate
    virtualProcessor_->mirroredScreenWidth_ = 100;
    virtualProcessor_->mirroredScreenHeight_ = 100;
    virtualProcessor_->mirroredTranslateX_ = 0;
    virtualProcessor_->mirroredTranslateY_ = 0;

    Drawing::Matrix matrix;
    bool isSamplingOn = false;

    // Should clip region with visibleRect when enableVisibleRect_ is true and drawMirrorCopy_ is false
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CanvasClipRegionForUniscaleMode(matrix, isSamplingOn));
}

/**
 * @tc.name: CanvasClipRegionForUniscaleMode_EnableVisibleRectWithSamplingTest001
 * @tc.desc: Test CanvasClipRegionForUniscaleMode when isSamplingOn is true and SLRScale is disabled
 *           The if (isSamplingOn && !SLRScaleEnabled) branch at line 649 should be true
 * @tc.type: FUNC
 * @tc.require: issue41
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasClipRegionForUniscaleMode_EnableVisibleRectWithSamplingTest001,
    TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);

    // Set up canvas using proper shared_ptr with explicit canvas object
    Drawing::Canvas drawCanvas;
    auto canvas = std::make_shared<RSPaintFilterCanvas>(&drawCanvas);
    virtualProcessor_->canvas_ = canvas;

    // Set scaleMode to UNISCALE_MODE
    virtualProcessor_->scaleMode_ = ScreenScaleMode::UNISCALE_MODE;

    // Set enableVisibleRect_ to true
    virtualProcessor_->enableVisibleRect_ = true;

    // Set drawMirrorCopy_ to false
    virtualProcessor_->drawMirrorCopy_ = false;

    // Set visibleRect_
    virtualProcessor_->visibleRect_ = Drawing::RectI(10, 10, 80, 80);

    // Set mirrored screen size and translate
    virtualProcessor_->mirroredScreenWidth_ = 100;
    virtualProcessor_->mirroredScreenHeight_ = 100;
    virtualProcessor_->mirroredTranslateX_ = 0;
    virtualProcessor_->mirroredTranslateY_ = 0;

    Drawing::Matrix visibleClipRectMatrix;
    visibleClipRectMatrix.SetScaleTranslate(2.0f, 2.0f, 0, 0);

    // Set isSamplingOn to true
    bool isSamplingOn = true;

    // Get current SLRScale enabled state
    auto param = system::GetParameter("rosen.SLRScale.enabled", "");

    // Temporarily disable SLRScale
    system::SetParameter("rosen.SLRScale.enabled", "0");

    // Should use visibleClipRectMatrix when isSamplingOn is true and SLRScale is disabled
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CanvasClipRegionForUniscaleMode(visibleClipRectMatrix, isSamplingOn));

    // Restore original SLRScale state
    system::SetParameter("rosen.SLRScale.enabled", param);
}

/**
 * @tc.name: CanvasClipRegionForUniscaleMode_DisableVisibleRectTest001
 * @tc.desc: Test CanvasClipRegionForUniscaleMode when enableVisibleRect_ is false
 *           The if (enableVisibleRect_) branch should be false
 * @tc.type: FUNC
 * @tc.require: issue41
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CanvasClipRegionForUniscaleMode_DisableVisibleRectTest001, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);

    // Set up canvas using proper shared_ptr with explicit canvas object
    Drawing::Canvas drawCanvas;
    auto canvas = std::make_shared<RSPaintFilterCanvas>(&drawCanvas);
    virtualProcessor_->canvas_ = canvas;

    // Set scaleMode to UNISCALE_MODE
    virtualProcessor_->scaleMode_ = ScreenScaleMode::UNISCALE_MODE;

    // Set enableVisibleRect_ to false (default)
    virtualProcessor_->enableVisibleRect_ = false;

    // Set mirrored screen size and translate
    virtualProcessor_->mirroredScreenWidth_ = 100;
    virtualProcessor_->mirroredScreenHeight_ = 100;
    virtualProcessor_->mirroredTranslateX_ = 10;
    virtualProcessor_->mirroredTranslateY_ = 10;

    Drawing::Matrix matrix;
    bool isSamplingOn = false;

    // Should clip region with default rect when enableVisibleRect_ is false
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CanvasClipRegionForUniscaleMode(matrix, isSamplingOn));
}

/**
 * @tc.name: SetCropRectForMetadata001
 * @tc.desc: Test SetCropRectForMetadata with null renderFrame
 * @tc.type: FUNC
 * @tc.require: issue22999
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetCropRectForMetadata001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    
    // Test with null renderFrame - should return false
    ASSERT_FALSE(processor->SetCropRectForMetadata(DEFAULT_META_REGION));
}

/**
 * @tc.name: SetCropRectForMetadata002
 * @tc.desc: Test SetCropRectForMetadata with null surface
 * @tc.type: FUNC
 * @tc.require: issue22999
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetCropRectForMetadata002, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    
    // Set up surfaceFrames_ with null surface frame
    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    processor->surfaceFrames_.push_back(std::move(config));
    
    // Test with null surface - should return false
    ASSERT_FALSE(processor->SetCropRectForMetadata(DEFAULT_META_REGION));
}

/**
 * @tc.name: SetCropRectForMetadata003
 * @tc.desc: Test SetCropRectForMetadata with null buffer
 * @tc.type: FUNC
 * @tc.require: issue22999
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetCropRectForMetadata003, TestSize.Level2)
{
#ifdef RS_ENABLE_VK
    if (RSSystemProperties::GetGpuApiType() != GpuApiType::VULKAN &&
        RSSystemProperties::GetGpuApiType() != GpuApiType::DDGR) {
        return;
    }
    auto csurface = IConsumerSurface::Create();
    ASSERT_NE(csurface, nullptr);
    auto producer = csurface->GetProducer();
    ASSERT_NE(producer, nullptr);
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    
    // Set up surfaceFrames_ with surface but null buffer
    std::shared_ptr<RSSurfaceOhosVulkan> rsSurface = std::make_shared<RSSurfaceOhosVulkan>(pSurface);
    auto surfaceFrame = std::make_unique<RSSurfaceFrameOhosVulkan>(
        std::make_shared<Drawing::Surface>(), DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT, DEFAULT_BUFFER_AGE);
    SurfaceFrameConfig config;
    config.surface = pSurface;
    config.frame = std::make_unique<RSRenderFrame>(rsSurface, std::move(surfaceFrame));
    processor->surfaceFrames_.push_back(std::move(config));
    
    // Test with null buffer - should return false
    ASSERT_FALSE(processor->SetCropRectForMetadata(DEFAULT_META_REGION));
#endif
}

/**
 * @tc.name: SetCropRectForMetadata004
 * @tc.desc: Test SetCropRectForMetadata with valid condition
 * @tc.type: FUNC
 * @tc.require: issue22999
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetCropRectForMetadata004, TestSize.Level2)
{
#ifdef RS_ENABLE_VK
    if (RSSystemProperties::GetGpuApiType() != GpuApiType::VULKAN &&
        RSSystemProperties::GetGpuApiType() != GpuApiType::DDGR) {
        return;
    }
    auto csurface = IConsumerSurface::Create();
    ASSERT_NE(csurface, nullptr);
    auto producer = csurface->GetProducer();
    ASSERT_NE(producer, nullptr);
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    auto surfaceHandler = std::make_shared<RSSurfaceHandler>(0);
    sptr<IBufferConsumerListener> listener = new RSUniRenderListener(surfaceHandler);
    csurface->RegisterConsumerListener(listener);

    // Create native buffer
    sptr<SurfaceBuffer> buffer = nullptr;
    int32_t fence;
    pSurface->RequestBuffer(buffer, fence, requestConfig);
    NativeWindowBuffer* nativeWindowBuffer = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&buffer);
    
    // Set up surfaceFrames_ with surface which has buffer
    std::shared_ptr<RSSurfaceOhosVulkan> rsSurface = std::make_shared<RSSurfaceOhosVulkan>(pSurface);
    rsSurface->mSurfaceList.emplace_back(nativeWindowBuffer);
    auto surfaceFrame = std::make_unique<RSSurfaceFrameOhosVulkan>(
        std::make_shared<Drawing::Surface>(), DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT, DEFAULT_BUFFER_AGE);
    SurfaceFrameConfig config;
    config.surface = pSurface;
    config.frame = std::make_unique<RSRenderFrame>(rsSurface, std::move(surfaceFrame));
    processor->surfaceFrames_.push_back(std::move(config));
    
    // Test with valid buffer - should return true
    ASSERT_TRUE(processor->SetCropRectForMetadata(DEFAULT_META_REGION));
#endif
}

/*
 * @tc.name: IsMultiSurfaceExtendMode_001
 * @tc.desc: Test IsMultiSurfaceExtendMode default false
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, IsMultiSurfaceExtendMode_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    EXPECT_FALSE(processor->IsMultiSurfaceExtendMode());
}

/*
 * @tc.name: IsMultiSurfaceExtendMode_002
 * @tc.desc: Test IsMultiSurfaceExtendMode true when needsOffscreenRender_ set
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, IsMultiSurfaceExtendMode_002, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    processor->needsOffscreenRender_ = true;
    EXPECT_TRUE(processor->IsMultiSurfaceExtendMode());
}

/*
 * @tc.name: GetSurfaceFrames_001
 * @tc.desc: Test GetSurfaceFrames default empty
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, GetSurfaceFrames_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    const auto& frames = processor->GetSurfaceFrames();
    EXPECT_TRUE(frames.empty());
}

/*
 * @tc.name: GetSurfaceFrames_002
 * @tc.desc: Test GetSurfaceFrames returns populated surfaceFrames_
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, GetSurfaceFrames_002, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    SurfaceFrameConfig config;
    config.region = RectI(0, 0, 100, 100);
    processor->surfaceFrames_.push_back(std::move(config));
    const auto& frames = processor->GetSurfaceFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].region.left_, 0);
    EXPECT_EQ(frames[0].region.width_, 100);
}

/*
 * @tc.name: BlitRegionsToSurfaces_001
 * @tc.desc: Test BlitRegionsToSurfaces with empty surfaceFrames
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, BlitRegionsToSurfaces_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    auto image = std::make_shared<Drawing::Image>();
    processor->BlitRegionsToSurfaces(image);
    EXPECT_TRUE(processor->surfaceFrames_.empty());
}

/*
 * @tc.name: BlitRegionsToSurfaces_002
 * @tc.desc: Test BlitRegionsToSurfaces with null image
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, BlitRegionsToSurfaces_002, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    SurfaceFrameConfig config;
    config.region = RectI(0, 0, 100, 100);
    processor->surfaceFrames_.push_back(std::move(config));
    processor->BlitRegionsToSurfaces(nullptr);
}

/*
 * @tc.name: BlitRegionsToSurfaces_003
 * @tc.desc: Test BlitRegionsToSurfaces with single surface (<=1)
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, BlitRegionsToSurfaces_003, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    SurfaceFrameConfig config;
    config.region = RectI(0, 0, 100, 100);
    processor->surfaceFrames_.push_back(std::move(config));
    auto image = std::make_shared<Drawing::Image>();
    processor->BlitRegionsToSurfaces(image);
}

/*
 * @tc.name: MergeAcquireFences_001
 * @tc.desc: Test MergeAcquireFences with empty fence list
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, MergeAcquireFences_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    std::vector<sptr<SyncFence>> fences;
    auto mergedFence = processor->MergeAcquireFences(fences);
    EXPECT_FALSE(mergedFence->IsValid());
}

/*
 * @tc.name: MergeAcquireFences_002
 * @tc.desc: Test MergeAcquireFences with single valid fence
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, MergeAcquireFences_002, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    std::vector<sptr<SyncFence>> fences;
    fences.emplace_back(SyncFence::InvalidFence());
    auto mergedFence = processor->MergeAcquireFences(fences);
    EXPECT_FALSE(mergedFence->IsValid());
}

/*
 * @tc.name: CancelCurrentFrame_MultiSurface_001
 * @tc.desc: Test CancelCurrentFrame with multiple surfaceFrames
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CancelCurrentFrame_MultiSurface_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    SurfaceFrameConfig config1;
    config1.region = RectI(0, 0, 100, 100);
    SurfaceFrameConfig config2;
    config2.region = RectI(100, 0, 100, 100);
    processor->surfaceFrames_.push_back(std::move(config1));
    processor->surfaceFrames_.push_back(std::move(config2));
    ASSERT_EQ(processor->surfaceFrames_.size(), 2u);
    processor->CancelCurrentFrame();
}

/*
 * @tc.name: GetBufferAge_MultiSurface_001
 * @tc.desc: Test GetBufferAge with empty surfaceFrames returns 0
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, GetBufferAge_MultiSurface_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    EXPECT_EQ(processor->GetBufferAge(), 0);
}

/*
 * @tc.name: GetFrameAcquireFence_MultiSurface_001
 * @tc.desc: Test GetFrameAcquireFence with empty surfaceFrames
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, GetFrameAcquireFence_MultiSurface_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    auto fence = processor->GetFrameAcquireFence();
    EXPECT_FALSE(fence->IsValid());
}

/*
 * @tc.name: SetDirtyInfo_MultiSurface_001
 * @tc.desc: Test SetDirtyInfo with empty surfaceFrames
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, SetDirtyInfo_MultiSurface_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    std::vector<RectI> dirtyRegion = {RectI(0, 0, 100, 100)};
    processor->SetDirtyInfo(dirtyRegion);
}

/*
 * @tc.name: PostProcess_NullRenderEngine_001
 * @tc.desc: Test PostProcess with null renderEngine
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, PostProcess_NullRenderEngine_001, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    processor->renderEngine_ = nullptr;
    processor->PostProcess();
}

/*
 * @tc.name: BlitRegionsToSurfaces_EarlyReturn_NullImage
 * @tc.desc: Test BlitRegionsToSurfaces returns early when offscreenImage is null
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, BlitRegionsToSurfaces_EarlyReturn_NullImage, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    SurfaceFrameConfig config1;
    config1.region = RectI(0, 0, 100, 100);
    config1.canvas = nullptr;
    SurfaceFrameConfig config2;
    config2.region = RectI(100, 0, 100, 100);
    config2.canvas = nullptr;
    processor->surfaceFrames_ = {config1, config2};
    processor->BlitRegionsToSurfaces(nullptr);
}

/*
 * @tc.name: BlitRegionsToSurfaces_EarlyReturn_SingleSurface
 * @tc.desc: Test BlitRegionsToSurfaces returns early when only one surface frame
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, BlitRegionsToSurfaces_EarlyReturn_SingleSurface, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    SurfaceFrameConfig config;
    config.region = RectI(0, 0, 100, 100);
    config.canvas = nullptr;
    processor->surfaceFrames_ = {config};
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format{Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_OPAQUE};
    bitmap.Build(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT, format);
    auto image = std::make_shared<Drawing::Image>();
    image->BuildFromBitmap(bitmap);
    processor->BlitRegionsToSurfaces(image);
}

/*
 * @tc.name: MergeAcquireFences_EmptyVector
 * @tc.desc: Test MergeAcquireFences with empty fence vector returns invalid fence
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, MergeAcquireFences_EmptyVector, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    std::vector<sptr<SyncFence>> fences;
    auto result = processor->MergeAcquireFences(fences);
    EXPECT_FALSE(result->IsValid());
}

/*
 * @tc.name: MergeAcquireFences_NullAndInvalidFences
 * @tc.desc: Test MergeAcquireFences skips null and invalid fences
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, MergeAcquireFences_NullAndInvalidFences, TestSize.Level2)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);
    std::vector<sptr<SyncFence>> fences;
    fences.push_back(nullptr);
    fences.push_back(SyncFence::InvalidFence());
    fences.push_back(nullptr);
    auto result = processor->MergeAcquireFences(fences);
    EXPECT_FALSE(result->IsValid());
}

/*
 * @tc.name: RequestFramesForAllSurfaces_NullSurfaceSkipped
 * @tc.desc: Test RequestFramesForAllSurfaces skips null surface entries (continue branch)
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, RequestFramesForAllSurfaces_NullSurfaceSkipped, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(screenDrawable_, nullptr);
    screenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(nodeId_);
    auto* screenParams = static_cast<RSScreenRenderParams*>(screenDrawable_->GetRenderParams().get());
    ASSERT_NE(screenParams, nullptr);

    SurfaceRegionConfig nullConfig;
    nullConfig.surface = nullptr;
    nullConfig.region = RectI(0, 0, TEST_FRAME_DIM, TEST_FRAME_DIM);
    screenParams->screenProperty_.Set<ScreenPropertyType::MULTI_SURFACE_CONFIGS>({nullConfig});

    virtualProcessor_->surfaceFrames_.clear();
    virtualProcessor_->RequestFramesForAllSurfaces(*screenDrawable_);
    EXPECT_TRUE(virtualProcessor_->surfaceFrames_.empty());
}

/**
 * @tc.name: CopyToSecondarySurfaces_NullPrimaryCanvas
 * @tc.desc: Test CopyToSecondarySurfaces returns early when primary canvas is null
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CopyToSecondarySurfaces_NullPrimaryCanvas, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    constexpr size_t expectedSize = 2;
    SurfaceFrameConfig primary;
    primary.canvas = nullptr;
    primary.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    SurfaceFrameConfig secondary;
    secondary.canvas = nullptr;
    secondary.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(primary));
    virtualProcessor_->surfaceFrames_.push_back(std::move(secondary));
    ASSERT_EQ(virtualProcessor_->surfaceFrames_.size(), expectedSize);
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CopyToSecondarySurfaces());
}

/**
 * @tc.name: CopyToSecondarySurfaces_NullPrimarySurface
 * @tc.desc: Test CopyToSecondarySurfaces returns early when canvas GetSurface is null
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CopyToSecondarySurfaces_NullPrimarySurface, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    Drawing::Canvas drawCanvas;
    auto canvas = std::make_shared<RSPaintFilterCanvas>(&drawCanvas);
    SurfaceFrameConfig primary;
    primary.canvas = canvas;
    primary.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    SurfaceFrameConfig secondary;
    secondary.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(primary));
    virtualProcessor_->surfaceFrames_.push_back(std::move(secondary));
    ASSERT_NE(virtualProcessor_->surfaceFrames_[0].canvas, nullptr);
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CopyToSecondarySurfaces());
}

/**
 * @tc.name: CopyToSecondarySurfaces_NullSecondaryCanvas
 * @tc.desc: Test CopyToSecondarySurfaces skips secondary surfaces with null canvas
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, CopyToSecondarySurfaces_NullSecondaryCanvas, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    Drawing::Canvas drawCanvas;
    auto canvas = std::make_shared<RSPaintFilterCanvas>(&drawCanvas);
    SurfaceFrameConfig primary;
    primary.canvas = canvas;
    primary.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    SurfaceFrameConfig secondary;
    secondary.canvas = nullptr;
    secondary.frame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(primary));
    virtualProcessor_->surfaceFrames_.push_back(std::move(secondary));
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->CopyToSecondarySurfaces());
}

/**
 * @tc.name: FlushGpu_NullFrame
 * @tc.desc: Test FlushGpu with null frame in surfaceFrames
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushGpu_NullFrame, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    SurfaceFrameConfig config;
    config.frame = nullptr;
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushGpu());
}

/**
 * @tc.name: FlushGpu_ValidFrame
 * @tc.desc: Test FlushGpu with valid RSRenderFrame in surfaceFrames
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushGpu_ValidFrame, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    auto csurf = IConsumerSurface::Create();
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    ASSERT_NE(rsSurface, nullptr);
    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    ASSERT_NE(config.frame, nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushGpu());
}

/**
 * @tc.name: FlushGpu_MixedFrames
 * @tc.desc: Test FlushGpu with mix of null and valid frames
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushGpu_MixedFrames, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    SurfaceFrameConfig nullConfig;
    nullConfig.frame = nullptr;
    virtualProcessor_->surfaceFrames_.push_back(std::move(nullConfig));
    auto csurf = IConsumerSurface::Create();
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig validConfig;
    validConfig.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(validConfig));
    constexpr size_t expectedSize = 2;
    ASSERT_EQ(virtualProcessor_->surfaceFrames_.size(), expectedSize);
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushGpu());
}

/**
 * @tc.name: FlushBuffer_NullFrame
 * @tc.desc: Test FlushBuffer with null frame skips iteration
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushBuffer_NullFrame, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    SurfaceFrameConfig config;
    config.frame = nullptr;
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));
    std::vector<sptr<SyncFence>> fences;
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushBuffer(fences));
    EXPECT_TRUE(fences.empty());
}

/**
 * @tc.name: FlushBuffer_ValidFrame
 * @tc.desc: Test FlushBuffer with valid frame processes flush and fence
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushBuffer_ValidFrame, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    auto csurf = IConsumerSurface::Create();
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));
    std::vector<sptr<SyncFence>> fences;
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushBuffer(fences));
}

/**
 * @tc.name: FlushBuffer_MixedFrames
 * @tc.desc: Test FlushBuffer with mix of null and valid frames
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushBuffer_MixedFrames, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    SurfaceFrameConfig nullConfig;
    nullConfig.frame = nullptr;
    virtualProcessor_->surfaceFrames_.push_back(std::move(nullConfig));
    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig validConfig;
    validConfig.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(validConfig));
    std::vector<sptr<SyncFence>> fences;
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushBuffer(fences));
}

/**
 * @tc.name: FlushAllSurfaces_CopyMode
 * @tc.desc: Test FlushAllSurfaces with needsOffscreenRender_ false calls CopyToSecondarySurfaces
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushAllSurfaces_CopyMode, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    auto csurf = IConsumerSurface::Create();
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig config1;
    config1.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    SurfaceFrameConfig config2;
    config2.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config1));
    virtualProcessor_->surfaceFrames_.push_back(std::move(config2));
    virtualProcessor_->needsOffscreenRender_ = false;
    virtualProcessor_->isMirror_ = false;
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushAllSurfaces());
}

/**
 * @tc.name: FlushAllSurfaces_OffscreenMode
 * @tc.desc: Test FlushAllSurfaces with needsOffscreenRender_ true skips CopyToSecondarySurfaces
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushAllSurfaces_OffscreenMode, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    auto csurf = IConsumerSurface::Create();
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig config1;
    config1.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    SurfaceFrameConfig config2;
    config2.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config1));
    virtualProcessor_->surfaceFrames_.push_back(std::move(config2));
    virtualProcessor_->needsOffscreenRender_ = true;
    virtualProcessor_->isMirror_ = false;
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushAllSurfaces());
}

/**
 * @tc.name: FlushAllSurfaces_MirrorMode
 * @tc.desc: Test FlushAllSurfaces with isMirror_ true merges fences
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, FlushAllSurfaces_MirrorMode, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    auto csurf = IConsumerSurface::Create();
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig config1;
    config1.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    SurfaceFrameConfig config2;
    config2.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config1));
    virtualProcessor_->surfaceFrames_.push_back(std::move(config2));
    virtualProcessor_->needsOffscreenRender_ = false;
    virtualProcessor_->isMirror_ = true;
    auto newUniParam = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(newUniParam));
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->FlushAllSurfaces());
}

/**
 * @tc.name: PostProcess_SingleSurface
 * @tc.desc: Test PostProcess with single surface calls Flush on the frame
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, PostProcess_SingleSurface, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    virtualProcessor_->renderEngine_ = RSUniRenderThread::Instance().GetRenderEngine();
    ASSERT_NE(virtualProcessor_->renderEngine_, nullptr);
    auto csurf = IConsumerSurface::Create();
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));
    virtualProcessor_->isMirror_ = false;
    ASSERT_EQ(virtualProcessor_->surfaceFrames_.size(), 1u);
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->PostProcess());
}

/**
 * @tc.name: PostProcess_SingleSurfaceMirror
 * @tc.desc: Test PostProcess single surface with isMirror_ true merges fence
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, PostProcess_SingleSurfaceMirror, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    virtualProcessor_->renderEngine_ = RSUniRenderThread::Instance().GetRenderEngine();
    ASSERT_NE(virtualProcessor_->renderEngine_, nullptr);
    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config));
    virtualProcessor_->isMirror_ = true;
    auto newUniParam = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(newUniParam));
    ASSERT_EQ(virtualProcessor_->surfaceFrames_.size(), 1u);
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->PostProcess());
}

/**
 * @tc.name: PostProcess_MultiSurface
 * @tc.desc: Test PostProcess with multiple surfaces calls FlushAllSurfaces
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, PostProcess_MultiSurface, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    virtualProcessor_->renderEngine_ = RSUniRenderThread::Instance().GetRenderEngine();
    ASSERT_NE(virtualProcessor_->renderEngine_, nullptr);
    auto csurf = IConsumerSurface::Create();
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    SurfaceFrameConfig config1;
    config1.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    SurfaceFrameConfig config2;
    config2.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), nullptr);
    virtualProcessor_->surfaceFrames_.push_back(std::move(config1));
    virtualProcessor_->surfaceFrames_.push_back(std::move(config2));
    virtualProcessor_->isMirror_ = false;
    ASSERT_EQ(virtualProcessor_->surfaceFrames_.size(), 2u);
    EXPECT_NO_FATAL_FAILURE(virtualProcessor_->PostProcess());
}

/**
 * @tc.name: RequestFramesForAllSurfaces_NullParams
 * @tc.desc: Test RequestFramesForAllSurfaces returns early when screenParams is null
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, RequestFramesForAllSurfaces_NullParams, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(screenDrawable_, nullptr);
    screenDrawable_->renderParams_ = nullptr;
    virtualProcessor_->surfaceFrames_.clear();
    virtualProcessor_->RequestFramesForAllSurfaces(*screenDrawable_);
    EXPECT_TRUE(virtualProcessor_->surfaceFrames_.empty());
}

/**
 * @tc.name: RequestFramesForAllSurfaces_EmptyConfigs
 * @tc.desc: Test RequestFramesForAllSurfaces returns early when multi surface configs are empty
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, RequestFramesForAllSurfaces_EmptyConfigs, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(screenDrawable_, nullptr);
    screenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(nodeId_);
    auto* screenParams = static_cast<RSScreenRenderParams*>(screenDrawable_->GetRenderParams().get());
    ASSERT_NE(screenParams, nullptr);
    screenParams->screenProperty_.Set<ScreenPropertyType::MULTI_SURFACE_CONFIGS>({});
    virtualProcessor_->surfaceFrames_.clear();
    virtualProcessor_->RequestFramesForAllSurfaces(*screenDrawable_);
    EXPECT_TRUE(virtualProcessor_->surfaceFrames_.empty());
}

/**
 * @tc.name: RequestFramesForAllSurfaces_VirtualSurfaceChanged
 * @tc.desc: Test RequestFramesForAllSurfaces calls ClearVirtualSurfaces when IsVirtualSurfaceChanged
 * @tc.type: FUNC
 */
HWTEST_F(RSUniRenderVirtualProcessorTest, RequestFramesForAllSurfaces_VirtualSurfaceChanged, TestSize.Level2)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(screenDrawable_, nullptr);
    screenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(nodeId_);
    auto* screenParams = static_cast<RSScreenRenderParams*>(screenDrawable_->GetRenderParams().get());
    ASSERT_NE(screenParams, nullptr);
    SurfaceRegionConfig nullConfig;
    nullConfig.surface = nullptr;
    nullConfig.region = RectI(0, 0, TEST_FRAME_DIM, TEST_FRAME_DIM);
    screenParams->screenProperty_.Set<ScreenPropertyType::MULTI_SURFACE_CONFIGS>({nullConfig});
    screenParams->SetVirtualSurfaceChanged(true);
    ASSERT_TRUE(screenParams->IsVirtualSurfaceChanged());
    virtualProcessor_->surfaceFrames_.clear();
    virtualProcessor_->RequestFramesForAllSurfaces(*screenDrawable_);
    EXPECT_TRUE(virtualProcessor_->surfaceFrames_.empty());
}
} // namespace OHOS::Rosen
