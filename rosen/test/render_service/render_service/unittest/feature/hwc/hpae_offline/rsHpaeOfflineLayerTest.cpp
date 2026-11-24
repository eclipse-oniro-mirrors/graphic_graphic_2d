/*
 * Copyright (c) 2025 HUA[REPLACED] Device Co., Ltd.
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
#include "rs_surface_layer.h"
#include "rs_render_surface_layer.h"
#include "pipeline/rs_surface_handler.h"
#include "pipeline/render_thread/rs_uni_render_processor.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "engine/rs_uni_render_engine.h"
#include "params/rs_surface_render_params.h"
#include "composer/composer_service/external_depend/hpae_offline/rs_hpae_offline_layer_info.h"

#define PRIVATE PUBLIC
#include "hdi_output.h"
#undef PRIVATE

#include "composer/composer_service/layer_backend/mock_hdi_device.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class RSHpaeOfflineLayerTest : public ::testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override
    {
        clientLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
        serverLayer_ = std::make_shared<RSRenderSurfaceLayer>();
        if (renderProcessor_ == nullptr) {
            uint32_t screenId = 0;
            RSUniRenderThread::Instance().composerClientManager_ = std::make_shared<RSComposerClientManager>();
            renderProcessor_ = std::make_shared<RSUniRenderProcessor>(screenId);
            renderProcessor_->screenInfo_.id = screenId;
            NodeId nodeId = 1;
            RSScreenRenderNode node(nodeId, screenId);
            auto renderEngine = std::make_shared<RSUniRenderEngine>();
            auto composerClient = RSComposerClient::Create(nullptr, nullptr);
            renderProcessor_->composerClient_ = composerClient;
            renderProcessor_->Init(node, renderEngine);
        } else {
            renderProcessor_->layers_.clear();
        }
    }

    void TearDown() override
    {
        clientLayer_ = nullptr;
        serverLayer_ = nullptr;
        // DEBUG_TDD: debug for tdd - clear layers to prevent accessing destroyed buffers
        if (renderProcessor_ != nullptr) {
            renderProcessor_->layers_.clear();
            renderProcessor_->uniLayer_ = nullptr;
        }
    }

    static inline std::shared_ptr<HdiOutput> hdiOutput_;
    static inline Mock::HdiDeviceMock* hdiDeviceMock_;
    static inline std::vector<std::string> paramKey_;
    static inline std::shared_ptr<RSUniRenderProcessor> renderProcessor_;

    std::shared_ptr<RSSurfaceLayer> clientLayer_;
    std::shared_ptr<RSRenderSurfaceLayer> serverLayer_;
};

void RSHpaeOfflineLayerTest::SetUpTestCase()
{
    uint32_t screenId = 0;
    hdiOutput_ = HdiOutput::CreateHdiOutput(screenId);
    hdiDeviceMock_ = Mock::HdiDeviceMock::GetInstance();
    hdiOutput_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, GetSupportedLayerPerFrameParameterKey()).WillRepeatedly(testing::ReturnRef(paramKey_));

    // Init RSUniRenderProcessor
    RSUniRenderThread::Instance().composerClientManager_ = std::make_shared<RSComposerClientManager>();
    renderProcessor_ = std::make_shared<RSUniRenderProcessor>(screenId);
    renderProcessor_->screenInfo_.id = screenId;
    NodeId nodeId = 1;
    RSScreenRenderNode node(nodeId, screenId);
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
    auto composerClient = RSComposerClient::Create(nullptr, nullptr);
    renderProcessor_->composerClient_ = composerClient;
    renderProcessor_->Init(node, renderEngine);
}

void RSHpaeOfflineLayerTest::TearDownTestCase()
{
    // Cleanup renderProcessor and its renderEngine to prevent crash
    if (renderProcessor_ != nullptr) {
        renderProcessor_->layers_.clear();
        renderProcessor_->uniLayer_ = nullptr;
        auto& engine = renderProcessor_->renderEngine_;
        if (engine) {
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
    }
    renderProcessor_ = nullptr;

    // Cleanup RSUniRenderThread singleton's uniRenderEngine to prevent
    // ~RSUniRenderThread crash at process exit (DecStrongRef on null)
    auto& rtThread = RSUniRenderThread::Instance();
    if (rtThread.uniRenderEngine_) {
        auto* uniEngine = rtThread.uniRenderEngine_.get();
        if (uniEngine->renderContext_) {
            uniEngine->renderContext_->drGPUContext_ = nullptr;
        }
        if (uniEngine->protectedRenderContext_) {
            uniEngine->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        uniEngine->skContext_ = nullptr;
        uniEngine->renderContext_ = nullptr;
        uniEngine->protectedRenderContext_ = nullptr;
        uniEngine->imageManager_ = nullptr;
        uniEngine->gpuCacheManager_ = nullptr;
#ifdef USE_VIDEO_PROCESSING_ENGINE
        uniEngine->colorSpaceConverterDisplay_ = nullptr;
#endif
    }
    rtThread.uniRenderEngine_ = nullptr;

    // Cleanup HdiOutput
    hdiOutput_->layersId_.clear();
    hdiOutput_->fences_.clear();
    hdiOutput_->layerIdMap_.clear();
    hdiOutput_->layersTobeRelease_.clear();
    hdiOutput_->device_ = nullptr;
    hdiOutput_ = nullptr;
}

HWTEST_F(RSHpaeOfflineLayerTest, OriginalBufferAllBranches, TestSize.Level1)
{
    sptr<SurfaceBuffer> buffer1 = OHOS::SurfaceBuffer::Create();
    sptr<SurfaceBuffer> buffer2 = OHOS::SurfaceBuffer::Create();
    sptr<SyncFence> fence1 = nullptr;
    sptr<SyncFence> fence2 = nullptr;
    GraphicIRect rect1 = { 0, 0, 100, 100 };
    GraphicIRect rect2 = { 0, 0, 200, 200 };

    // Test SetHpaeOriginalInfo with buffer1
    HpaeOriginalInfo info1;
    info1.originalBuffer = buffer1;
    info1.originalAcquireFence = fence1;
    info1.originalPreBuffer = buffer1;
    info1.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    info1.originalCropRect = rect1;
    clientLayer_->SetHpaeOriginalInfo(info1);
    auto& hpaeInfo1 = clientLayer_->GetHpaeOriginalInfo();
    EXPECT_EQ(hpaeInfo1.originalBuffer, buffer1);
    EXPECT_EQ(hpaeInfo1.originalPreBuffer, buffer1);
    EXPECT_EQ(hpaeInfo1.originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_90);
    EXPECT_EQ(hpaeInfo1.originalCropRect.w, 100);

    // Test SetHpaeOriginalInfo with buffer2 (different buffer)
    HpaeOriginalInfo info2;
    info2.originalBuffer = buffer2;
    info2.originalAcquireFence = fence2;
    info2.originalPreBuffer = buffer2;
    info2.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_180;
    info2.originalCropRect = rect2;
    clientLayer_->SetHpaeOriginalInfo(info2);
    auto& hpaeInfo2 = clientLayer_->GetHpaeOriginalInfo();
    EXPECT_EQ(hpaeInfo2.originalBuffer, buffer2);
    EXPECT_EQ(hpaeInfo2.originalPreBuffer, buffer2);
    EXPECT_EQ(hpaeInfo2.originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_180);
    EXPECT_EQ(hpaeInfo2.originalCropRect.w, 200);

    // Test SetHpaeOriginalInfo with nullptr
    HpaeOriginalInfo infoNull;
    infoNull.originalBuffer = nullptr;
    infoNull.originalAcquireFence = nullptr;
    infoNull.originalPreBuffer = nullptr;
    infoNull.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_BUTT;
    infoNull.originalCropRect = { 0, 0, 0, 0 };
    clientLayer_->SetHpaeOriginalInfo(infoNull);
    auto& hpaeInfoNull = clientLayer_->GetHpaeOriginalInfo();
    EXPECT_EQ(hpaeInfoNull.originalBuffer, nullptr);
    EXPECT_EQ(hpaeInfoNull.originalAcquireFence, nullptr);
    EXPECT_EQ(hpaeInfoNull.originalPreBuffer, nullptr);
    EXPECT_EQ(hpaeInfoNull.originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_BUTT);
    EXPECT_EQ(hpaeInfoNull.originalCropRect.w, 0);

    // BufferOwnerCount branches
    clientLayer_->SetOriginalBufferOwnerCount(nullptr);
    EXPECT_EQ(clientLayer_->GetOriginalBufferOwnerCount(), nullptr);
    auto boc1 = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    boc1->bufferId_ = 1u;
    std::atomic<int> released{0};
    boc1->bufferReleaseCb_ = [&released](uint64_t seq) { (void)seq; released.fetch_add(1); };
    clientLayer_->SetOriginalBufferOwnerCount(boc1);
    auto cur1 = clientLayer_->GetOriginalBufferOwnerCount();
    ASSERT_NE(cur1, nullptr);
    EXPECT_GE(cur1->refCount_.load(), 2);
    auto refBefore = cur1->refCount_.load();
    clientLayer_->SetOriginalBufferOwnerCount(boc1);
    EXPECT_EQ(cur1->refCount_.load(), refBefore);

    // UseDeviceOffline branches
    EXPECT_EQ(clientLayer_->GetUseDeviceOffline(), false);
    clientLayer_->SetUseDeviceOffline(true);
    EXPECT_EQ(clientLayer_->GetUseDeviceOffline(), true);
    clientLayer_->SetUseDeviceOffline(true);
    EXPECT_EQ(clientLayer_->GetUseDeviceOffline(), true);
    clientLayer_->SetUseDeviceOffline(false);
    EXPECT_EQ(clientLayer_->GetUseDeviceOffline(), false);

    // RSRenderSurfaceLayer clear buffer
    HpaeOriginalInfo serverInfo;
    serverInfo.originalBuffer = buffer1;
    serverInfo.originalAcquireFence = fence1;
    serverInfo.originalPreBuffer = buffer1;
    serverInfo.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    serverInfo.originalCropRect = rect1;
    serverLayer_->SetHpaeOriginalInfo(serverInfo);
    serverLayer_->SetUseDeviceOffline(true);
    EXPECT_EQ(serverLayer_->GetUseDeviceOffline(), true);
    serverLayer_->SetUseDeviceOffline(false);
    auto& serverHpaeInfo = serverLayer_->GetHpaeOriginalInfo();
    EXPECT_EQ(serverHpaeInfo.originalBuffer, nullptr);
    EXPECT_EQ(serverHpaeInfo.originalPreBuffer, nullptr);
}

HWTEST_F(RSHpaeOfflineLayerTest, PostProcessAllBranches, TestSize.Level1)
{
    ASSERT_NE(renderProcessor_, nullptr);

    // Create uniLayer with valid bufferOwnerCount
    auto layer0 = std::make_shared<RSSurfaceLayer>(0, nullptr);
    sptr<SurfaceBuffer> buffer0 = SurfaceBuffer::Create();
    layer0->SetBuffer(buffer0);
    auto uniBufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    uniBufferOwnerCount->bufferId_ = 100u;
    layer0->SetBufferOwnerCount(uniBufferOwnerCount, true);
    renderProcessor_->uniLayer_ = layer0;

    // layer1: useDeviceOffline = false
    auto layer1 = std::make_shared<RSSurfaceLayer>(1, nullptr);
    sptr<SurfaceBuffer> buffer1 = SurfaceBuffer::Create();
    layer1->SetBuffer(buffer1);
    layer1->SetUseDeviceOffline(false);
    auto bufferOwnerCount1 = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount1->bufferId_ = 1u;
    layer1->SetBufferOwnerCount(bufferOwnerCount1, true);
    renderProcessor_->layers_.push_back(layer1);

    // layer2: useDeviceOffline = true, originalBuffer = nullptr
    auto layer2 = std::make_shared<RSSurfaceLayer>(2, nullptr);
    sptr<SurfaceBuffer> buffer2 = SurfaceBuffer::Create();
    layer2->SetBuffer(buffer2);
    layer2->SetUseDeviceOffline(true);
    auto bufferOwnerCount2 = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount2->bufferId_ = 2u;
    layer2->SetBufferOwnerCount(bufferOwnerCount2, true);
    renderProcessor_->layers_.push_back(layer2);

    // layer3: useDeviceOffline = true, originalBuffer valid, originalBufferOwnerCount = nullptr
    auto layer3 = std::make_shared<RSSurfaceLayer>(3, nullptr);
    sptr<SurfaceBuffer> buffer3 = SurfaceBuffer::Create();
    layer3->SetBuffer(buffer3);
    layer3->SetUseDeviceOffline(true);
    HpaeOriginalInfo info3;
    sptr<SurfaceBuffer> origBuffer3 = SurfaceBuffer::Create();
    info3.originalBuffer = origBuffer3;
    layer3->SetHpaeOriginalInfo(info3);
    auto bufferOwnerCount3 = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount3->bufferId_ = 3u;
    layer3->SetBufferOwnerCount(bufferOwnerCount3, true);
    renderProcessor_->layers_.push_back(layer3);

    // layer4: both originalBuffer and originalBufferOwnerCount valid
    auto layer4 = std::make_shared<RSSurfaceLayer>(4, nullptr);
    sptr<SurfaceBuffer> buffer4 = SurfaceBuffer::Create();
    layer4->SetBuffer(buffer4);
    layer4->SetUseDeviceOffline(true);
    HpaeOriginalInfo info4;
    sptr<SurfaceBuffer> origBuffer4 = SurfaceBuffer::Create();
    info4.originalBuffer = origBuffer4;
    layer4->SetHpaeOriginalInfo(info4);
    auto bufferOwnerCount4 = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount4->bufferId_ = 4u;
    layer4->SetBufferOwnerCount(bufferOwnerCount4, true);
    auto originalBufferOwnerCount4 = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    originalBufferOwnerCount4->bufferId_ = 44u;
    layer4->SetOriginalBufferOwnerCount(originalBufferOwnerCount4);
    renderProcessor_->layers_.push_back(layer4);

    // layer5: bufferOwnerCount = nullptr
    auto layer5 = std::make_shared<RSSurfaceLayer>(5, nullptr);
    sptr<SurfaceBuffer> buffer5 = SurfaceBuffer::Create();
    layer5->SetBuffer(buffer5);
    layer5->SetUseDeviceOffline(true);
    HpaeOriginalInfo info5;
    sptr<SurfaceBuffer> origBuffer5 = SurfaceBuffer::Create();
    info5.originalBuffer = origBuffer5;
    layer5->SetHpaeOriginalInfo(info5);
    renderProcessor_->layers_.push_back(layer5);

    renderProcessor_->PostProcess();
    EXPECT_EQ(renderProcessor_->layers_.size(), 5u);
}

HWTEST_F(RSHpaeOfflineLayerTest, ReleaseLayerOriginalBuffer, TestSize.Level1)
{
    auto hdiOutput = RSHpaeOfflineLayerTest::hdiOutput_;
    hdiOutput->layersId_.clear();
    hdiOutput->fences_.clear();
    hdiOutput->layerIdMap_.clear();
    hdiOutput->layersTobeRelease_.clear();

    // Layer 1: useDeviceOffline = true
    std::shared_ptr<HdiLayer> hdiLayer1 = HdiLayer::CreateHdiLayer(1);
    std::shared_ptr<RSLayer> rsLayer1 = std::make_shared<RSSurfaceLayer>(1, nullptr);
    rsLayer1->SetUseDeviceOffline(true);
    sptr<SurfaceBuffer> preBuffer1 = OHOS::SurfaceBuffer::Create();
    rsLayer1->SetPreBuffer(preBuffer1);
    sptr<SurfaceBuffer> origPreBuffer1 = OHOS::SurfaceBuffer::Create();
    HpaeOriginalInfo info1;
    info1.originalPreBuffer = origPreBuffer1;
    rsLayer1->SetHpaeOriginalInfo(info1);
    hdiLayer1->UpdateRSLayer(rsLayer1);
    hdiOutput->layerIdMap_[1] = hdiLayer1;

    // Layer 2: useDeviceOffline = false
    std::shared_ptr<HdiLayer> hdiLayer2 = HdiLayer::CreateHdiLayer(2);
    std::shared_ptr<RSLayer> rsLayer2 = std::make_shared<RSSurfaceLayer>(2, nullptr);
    rsLayer2->SetUseDeviceOffline(false);
    sptr<SurfaceBuffer> preBuffer2 = OHOS::SurfaceBuffer::Create();
    rsLayer2->SetPreBuffer(preBuffer2);
    hdiLayer2->UpdateRSLayer(rsLayer2);
    hdiOutput->layerIdMap_[2] = hdiLayer2;

    ReleaseLayerBuffersInfo releaseLayerInfo;
    releaseLayerInfo.screenId = hdiOutput->GetScreenId();
    hdiOutput->ReleaseLayers(releaseLayerInfo);

    size_t layer1Count = 0;
    size_t layer2Count = 0;
    for (const auto& [layerId, buffer, fence] : releaseLayerInfo.releaseBufferFenceVec) {
        if (layerId == 1) {
            layer1Count++;
        } else if (layerId == 2) {
            layer2Count++;
        }
    }
    EXPECT_EQ(layer1Count, 2u);
    EXPECT_EQ(layer2Count, 1u);
}


/**
 * @tc.name: RSRenderSurfaceLayer_HpaeOffline_AllBranches
 * @tc.desc: RSRenderSurfaceLayer SetUseDeviceOffline and SetHpaeOriginalInfo
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, RSRenderSurfaceLayer_HpaeOffline_AllBranches, TestSize.Level1)
{
    auto layer = std::make_shared<RSRenderSurfaceLayer>();
    // SetUseDeviceOffline branches
    layer->SetUseDeviceOffline(true);  // false->true
    layer->SetUseDeviceOffline(true);  // true->true
    layer->SetUseDeviceOffline(false); // true->false (clear)
    layer->SetUseDeviceOffline(false); // false->false
    EXPECT_EQ(layer->GetUseDeviceOffline(), false);

    // SetHpaeOriginalInfo with all fields
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    sptr<SyncFence> fence = SyncFence::InvalidFence();
    HpaeOriginalInfo info;
    info.originalBuffer = buffer;
    info.originalAcquireFence = fence;
    info.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    layer->SetHpaeOriginalInfo(info);
    auto& hpaeInfo = layer->GetHpaeOriginalInfo();
    EXPECT_EQ(hpaeInfo.originalBuffer, buffer);
    EXPECT_EQ(hpaeInfo.originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_90);

    // SetHpaeOriginalInfo with nullptr
    HpaeOriginalInfo nullInfo;
    nullInfo.originalBuffer = nullptr;
    nullInfo.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_BUTT;
    layer->SetHpaeOriginalInfo(nullInfo);
    auto& nullHpaeInfo = layer->GetHpaeOriginalInfo();
    EXPECT_EQ(nullHpaeInfo.originalBuffer, nullptr);
    EXPECT_EQ(nullHpaeInfo.originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_BUTT);
}

/**
 * @tc.name: RSSurfaceLayer_HpaeOriginalInfo_AllBranches
 * @tc.desc: RSSurfaceLayer SetHpaeOriginalInfo same/different value and Get default
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, RSSurfaceLayer_HpaeOriginalInfo_AllBranches, TestSize.Level1)
{
    auto layer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    // Branch 1: Get default values
    auto& getInfo0 = layer->GetHpaeOriginalInfo();
    EXPECT_EQ(getInfo0.originalBuffer, nullptr);
    EXPECT_EQ(getInfo0.originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_BUTT);

    // Branch 2: Set different value
    HpaeOriginalInfo info1;
    info1.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    layer->SetHpaeOriginalInfo(info1);
    auto& getInfo1 = layer->GetHpaeOriginalInfo();
    EXPECT_EQ(getInfo1.originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_90);

    // Branch 3: Set same value (return early)
    layer->SetHpaeOriginalInfo(info1);
    auto& getInfo2 = layer->GetHpaeOriginalInfo();
    EXPECT_EQ(getInfo2.originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_90);
}

/**
 * @tc.name: SetDeviceOfflineOriginalInfo_Branch_Coverage
 * @tc.desc: Test SetDeviceOfflineOriginalInfo function branch coverage
 *           Covers: params.GetBufferOwnerCount() != nullptr branch at line 150-152
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, SetDeviceOfflineOriginalInfo_Branch_Coverage, TestSize.Level1)
{
    auto layer = std::make_shared<RSSurfaceLayer>(0, nullptr);

    // Branch: bufferOwnerCount != nullptr (line 150-152)
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 999u;
    layer->SetOriginalBufferOwnerCount(bufferOwnerCount);

    auto getBufferOwnerCount = layer->GetOriginalBufferOwnerCount();
    ASSERT_NE(getBufferOwnerCount, nullptr);
    EXPECT_EQ(getBufferOwnerCount->bufferId_, 999u);

    // SetHpaeOriginalInfo with valid buffer
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    HpaeOriginalInfo info;
    info.originalBuffer = buffer;
    layer->SetHpaeOriginalInfo(info);

    auto& hpaeInfo = layer->GetHpaeOriginalInfo();
    EXPECT_EQ(hpaeInfo.originalBuffer, buffer);

    // Branch: params.GetBufferOwnerCount() != nullptr (line 150-152)
    // Test RSSurfaceRenderParams with bufferOwnerCount set
    RSSurfaceRenderParams params(1);
    auto paramBufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    paramBufferOwnerCount->bufferId_ = 888u;
    sptr<SurfaceBuffer> paramBuffer = SurfaceBuffer::Create();
    Rect damageRect = {0, 0, 100, 100};
    params.SetBuffer(paramBuffer, paramBufferOwnerCount, damageRect);

    auto getParamBufferOwnerCount = params.GetBufferOwnerCount();
    ASSERT_NE(getParamBufferOwnerCount, nullptr);
    EXPECT_EQ(getParamBufferOwnerCount->bufferId_, 888u);
}

#ifndef ROSEN_CROSS_PLATFORM
/**
 * @tc.name: GetLayerInfo_BufferOwnerCount
 * @tc.desc: Test GetLayerInfo with bufferOwnerCount to cover SetDeviceOfflineOriginalInfo branch
 *           Covers: if (params.GetBufferOwnerCount()) at line 150-152
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, GetLayerInfo_BufferOwnerCount, TestSize.Level1)
{
    // Create params with bufferOwnerCount set
    RSSurfaceRenderParams param(100);  // Use unique id to avoid conflict
    auto bufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    bufferOwnerCount->bufferId_ = 777u;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    Rect damageRect = {0, 0, 100, 100};
    param.SetBuffer(buffer, bufferOwnerCount, damageRect);

    // Verify bufferOwnerCount is set
    auto getBufferOwnerCount = param.GetBufferOwnerCount();
    ASSERT_NE(getBufferOwnerCount, nullptr);
    EXPECT_EQ(getBufferOwnerCount->bufferId_, 777u);

    // Create all nullptr parameters with actual objects
    sptr<SurfaceBuffer> preBuffer = SurfaceBuffer::Create();
    sptr<IConsumerSurface> consumer = IConsumerSurface::Create("GetLayerInfo_Test");
    sptr<SyncFence> acquireFence = SyncFence::INVALID_FENCE;

    // Call GetLayerInfo with offlineResult to trigger SetDeviceOfflineOriginalInfo
    auto offlineResult = std::make_shared<ProcessOfflineResult>();
    offlineResult->consumer = consumer;
    offlineResult->buffer = buffer;

    auto layer = renderProcessor_->GetLayerInfo(param, buffer, preBuffer, consumer, acquireFence, offlineResult);
    ASSERT_NE(layer, nullptr);
}
#endif

/**
 * @tc.name: RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_DecRef
 * @tc.desc: Test RSSurfaceRenderParams::OnSync with preBufferOwnerCount to cover DecRef branch
 *           Covers: preBufferOwnerCount_ != nullptr && bufferSynced_ == false && preBufferOwnerCount_->DecRef()
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_DecRef, TestSize.Level1)
{
    // Create source params with preBufferOwnerCount
    RSSurfaceRenderParams sourceParams(1);
    sptr<SurfaceBuffer> preBuffer = SurfaceBuffer::Create();
    auto preBufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    preBufferOwnerCount->bufferId_ = 100u;
    // Set refCount to 1 so DecRef returns true
    preBufferOwnerCount->refCount_.store(1);
    sourceParams.SetPreBuffer(preBuffer, preBufferOwnerCount);
    sourceParams.SetBufferSynced(false);
    sourceParams.SetDirtyType(RSRenderParamsDirtyType::BUFFER_INFO_DIRTY);

    // Create target params
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSSurfaceRenderParams>(1);

    // Call OnSync - should trigger DecRef branch
    sourceParams.OnSync(target);

    // Verify preBufferOwnerCount was cleared (DecRef returned true and cleared the buffer)
    auto targetSurfaceParams = static_cast<RSSurfaceRenderParams*>(target.get());
    EXPECT_EQ(targetSurfaceParams->GetPreBuffer(), nullptr);
    EXPECT_EQ(targetSurfaceParams->GetPreBufferOwnerCount(), nullptr);
}

/**
 * @tc.name: RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_NotDecRef
 * @tc.desc: Test RSSurfaceRenderParams::OnSync when DecRef returns false
 *           Covers: preBufferOwnerCount_ != nullptr && bufferSynced_ == false && preBufferOwnerCount_->DecRef() returns false
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_NotDecRef, TestSize.Level1)
{
    // Create source params with preBufferOwnerCount but DecRef returns false (refCount > 1)
    RSSurfaceRenderParams sourceParams(1);
    sptr<SurfaceBuffer> preBuffer = SurfaceBuffer::Create();
    auto preBufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    preBufferOwnerCount->bufferId_ = 100u;
    // Set refCount to 2 so DecRef returns false (won't clear buffer)
    preBufferOwnerCount->refCount_.store(2);
    // Set non-null callback so DecRef returns false when refCount > 1
    preBufferOwnerCount->bufferReleaseCb_ = [](uint64_t) {};
    sourceParams.SetPreBuffer(preBuffer, preBufferOwnerCount);
    sourceParams.SetBufferSynced(false);
    sourceParams.SetDirtyType(RSRenderParamsDirtyType::BUFFER_INFO_DIRTY);

    // Create target params
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSSurfaceRenderParams>(1);

    // Call OnSync - DecRef returns false, should NOT clear preBuffer
    sourceParams.OnSync(target);

    // Verify preBufferOwnerCount was NOT cleared (DecRef returned false)
    auto targetSurfaceParams = static_cast<RSSurfaceRenderParams*>(target.get());
    EXPECT_NE(targetSurfaceParams->GetPreBuffer(), nullptr);
    EXPECT_NE(targetSurfaceParams->GetPreBufferOwnerCount(), nullptr);
}

/**
 * @tc.name: RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_Nullptr
 * @tc.desc: Test RSSurfaceRenderParams::OnSync when preBufferOwnerCount is nullptr
 *           Covers: dirtyType=BUFFER_INFO_DIRTY && preBufferOwnerCount_ == nullptr (skip if at line 617)
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_Nullptr, TestSize.Level1)
{
    // Create source params without preBufferOwnerCount
    RSSurfaceRenderParams sourceParams(1);
    sptr<SurfaceBuffer> preBuffer = SurfaceBuffer::Create();
    sourceParams.SetPreBuffer(preBuffer, nullptr);  // preBufferOwnerCount = nullptr
    sourceParams.SetBufferSynced(false);
    sourceParams.SetDirtyType(RSRenderParamsDirtyType::BUFFER_INFO_DIRTY);

    // Create target params
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSSurfaceRenderParams>(1);

    // Call OnSync - preBufferOwnerCount is nullptr, should skip if at line 617
    sourceParams.OnSync(target);

    // Verify preBuffer is copied to target (since dirtyType has BUFFER_INFO_DIRTY)
    auto targetSurfaceParams = static_cast<RSSurfaceRenderParams*>(target.get());
    EXPECT_NE(targetSurfaceParams->GetPreBuffer(), nullptr);
    // preBufferOwnerCount is nullptr, so target should also be nullptr
    EXPECT_EQ(targetSurfaceParams->GetPreBufferOwnerCount(), nullptr);
}

/**
 * @tc.name: RSSurfaceRenderParams_OnSync_BufferSynced_True
 * @tc.desc: Test RSSurfaceRenderParams::OnSync when bufferSynced is true
 *           Covers: dirtyType=BUFFER_INFO_DIRTY && preBufferOwnerCount!=nullptr && bufferSynced_==true (skip if at line 617)
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, RSSurfaceRenderParams_OnSync_BufferSynced_True, TestSize.Level1)
{
    // Create source params with bufferSynced = true
    RSSurfaceRenderParams sourceParams(1);
    sptr<SurfaceBuffer> preBuffer = SurfaceBuffer::Create();
    auto preBufferOwnerCount = std::make_shared<RSSurfaceHandler::BufferOwnerCount>();
    preBufferOwnerCount->bufferId_ = 100u;
    preBufferOwnerCount->refCount_.store(1);
    sourceParams.SetPreBuffer(preBuffer, preBufferOwnerCount);
    sourceParams.SetBufferSynced(true);  // bufferSynced = true
    sourceParams.SetDirtyType(RSRenderParamsDirtyType::BUFFER_INFO_DIRTY);

    // Create target params
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSSurfaceRenderParams>(1);

    // Call OnSync - bufferSynced is true, should skip if at line 617
    sourceParams.OnSync(target);

    // Verify preBuffer is copied to target (since dirtyType has BUFFER_INFO_DIRTY)
    auto targetSurfaceParams = static_cast<RSSurfaceRenderParams*>(target.get());
    EXPECT_NE(targetSurfaceParams->GetPreBuffer(), nullptr);
    // bufferSynced is true, so preBufferOwnerCount should NOT be cleared
    EXPECT_NE(targetSurfaceParams->GetPreBufferOwnerCount(), nullptr);
}

/**
 * @tc.name: RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_False_BufferSynced_True
 * @tc.desc: Test RSSurfaceRenderParams::OnSync when preBufferOwnerCount is nullptr and bufferSynced is true
 *           Covers: preBufferOwnerCount=false, bufferSynced=true (each variable covers true/false)
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_False_BufferSynced_True, TestSize.Level1)
{
    RSSurfaceRenderParams sourceParams(1);
    sptr<SurfaceBuffer> preBuffer = SurfaceBuffer::Create();
    sourceParams.SetPreBuffer(preBuffer, nullptr);  // preBufferOwnerCount = nullptr
    sourceParams.SetBufferSynced(true);  // bufferSynced = true
    sourceParams.SetDirtyType(RSRenderParamsDirtyType::BUFFER_INFO_DIRTY);

    std::unique_ptr<RSRenderParams> target = std::make_unique<RSSurfaceRenderParams>(1);
    sourceParams.OnSync(target);

    auto targetSurfaceParams = static_cast<RSSurfaceRenderParams*>(target.get());
    EXPECT_NE(targetSurfaceParams->GetPreBuffer(), nullptr);
    EXPECT_EQ(targetSurfaceParams->GetPreBufferOwnerCount(), nullptr);
}

/**
 * @tc.name: RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_False_BufferSynced_False
 * @tc.desc: Test RSSurfaceRenderParams::OnSync when preBufferOwnerCount is nullptr and bufferSynced is false
 *           Covers: preBufferOwnerCount=false, bufferSynced=false (each variable covers true/false)
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineLayerTest, RSSurfaceRenderParams_OnSync_PreBufferOwnerCount_False_BufferSynced_False, TestSize.Level1)
{
    RSSurfaceRenderParams sourceParams(1);
    sptr<SurfaceBuffer> preBuffer = SurfaceBuffer::Create();
    sourceParams.SetPreBuffer(preBuffer, nullptr);  // preBufferOwnerCount = nullptr
    sourceParams.SetBufferSynced(false);  // bufferSynced = false
    sourceParams.SetDirtyType(RSRenderParamsDirtyType::BUFFER_INFO_DIRTY);

    std::unique_ptr<RSRenderParams> target = std::make_unique<RSSurfaceRenderParams>(1);
    sourceParams.OnSync(target);

    auto targetSurfaceParams = static_cast<RSSurfaceRenderParams*>(target.get());
    EXPECT_NE(targetSurfaceParams->GetPreBuffer(), nullptr);
    EXPECT_EQ(targetSurfaceParams->GetPreBufferOwnerCount(), nullptr);
}

} // namespace OHOS::Rosen