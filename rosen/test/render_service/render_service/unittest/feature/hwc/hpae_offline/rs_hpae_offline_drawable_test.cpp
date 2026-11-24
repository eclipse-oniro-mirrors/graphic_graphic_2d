/*
 * Copyright (c) 2024 HUA[REPLACED] Device Co., Ltd.
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
#include <iostream>

#include "gtest/gtest.h"

#include <parameters.h>

#include "drawable/rs_logical_display_render_node_drawable.h"
#include "engine/rs_uni_render_engine.h"
#include "feature/uifirst/rs_uifirst_manager.h"
#include "graphic_feature_param_manager.h"
#include "drawable/rs_screen_render_node_drawable.h"
#include "params/rs_render_thread_params.h"
#include "pipeline/rs_logical_display_render_node.h"
#include "pipeline/rs_render_node_gc.h"
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/render_thread/rs_render_engine.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/render_thread/rs_uni_render_util.h"
#include "pipeline/render_thread/rs_uni_render_virtual_processor.h"
#include "platform/drawing/rs_surface_converter.h"
#include "screen_manager/rs_screen.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_device.h"
#include "feature/hwc/hpae_offline/rs_offline_processor.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "rs_render_composer_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
namespace {
constexpr int32_t DEFAULT_CANVAS_SIZE = 100;
constexpr NodeId DEFAULT_ID = 0xFFFF;
constexpr ScreenId DEFAULT_SCREEN_ID = 0xFFFF;
constexpr int32_t SCREEN_PHYSICAL_HEIGHT = 1000;
constexpr int32_t SCREEN_PHYSICAL_WIDTH = 1000;
}
class RSHpaeOfflineDrawableTest : public testing::Test {
public:
    std::shared_ptr<RSScreenRenderNode> renderNode_;
    std::shared_ptr<RSScreenRenderNode> mirroredNode_;
    std::shared_ptr<RSLogicalDisplayRenderNode> displayRenderNode_;
    std::shared_ptr<RSLogicalDisplayRenderNode> mirroredDisplayNode_;

    RSRenderNodeDrawableAdapter* drawable_ = nullptr;
    RSRenderNodeDrawableAdapter* mirroredDrawable_ = nullptr;
    RSScreenRenderNodeDrawable* screenDrawable_ = nullptr;
    RSScreenRenderNodeDrawable* mirroredScreenDrawable_ = nullptr;

    RSLogicalDisplayRenderNodeDrawable* displayDrawable_ = nullptr;
    RSLogicalDisplayRenderNodeDrawable* mirroredDisplayDrawable_ = nullptr;

    std::shared_ptr<Drawing::Canvas> drawingCanvas_ = nullptr;
    std::shared_ptr<Drawing::Canvas> drawingCanvasForMirror_ = nullptr;

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static std::shared_ptr<RSScreenRenderNode> GetAndInitScreenRenderNode();
    static inline NodeId id = DEFAULT_ID;
    static inline std::shared_ptr<RSRenderComposerManager> rsRenderComposerManager = nullptr;
    std::shared_ptr<RSHpaeOfflineDevice> hpaeDevice_ = nullptr;
};

void RSHpaeOfflineDrawableTest::SetUpTestCase()
{
    auto& renderNodeGC = RSRenderNodeGC::Instance();
    std::shared_ptr<AppExecFwk::EventHandler> handler = nullptr;
    rsRenderComposerManager = std::make_shared<RSRenderComposerManager>(handler);
    renderNodeGC.nodeBucket_ = std::queue<std::vector<RSRenderNode*>>();
    renderNodeGC.drawableBucket_ = std::queue<std::vector<DrawableV2::RSRenderNodeDrawableAdapter*>>();
}

void RSHpaeOfflineDrawableTest::TearDownTestCase()
{
    auto& mainThread = *RSMainThread::Instance();
    if (mainThread.renderEngine_) {
        if (mainThread.renderEngine_->renderContext_) {
            mainThread.renderEngine_->renderContext_->drGPUContext_ = nullptr;
        }
        mainThread.renderEngine_->skContext_ = nullptr;
        mainThread.renderEngine_->renderContext_ = nullptr;
        if (mainThread.renderEngine_->protectedRenderContext_) {
            mainThread.renderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        mainThread.renderEngine_->protectedRenderContext_ = nullptr;
        mainThread.renderEngine_->imageManager_ = nullptr;
        mainThread.renderEngine_->gpuCacheManager_ = nullptr;
        mainThread.renderEngine_ = nullptr;
    }
    auto& rtThread = RSUniRenderThread::Instance();
    if (rtThread.uniRenderEngine_) {
        if (rtThread.uniRenderEngine_->renderContext_) {
            rtThread.uniRenderEngine_->renderContext_->drGPUContext_ = nullptr;
        }
        rtThread.uniRenderEngine_->skContext_ = nullptr;
        rtThread.uniRenderEngine_->renderContext_ = nullptr;
        if (rtThread.uniRenderEngine_->protectedRenderContext_) {
            rtThread.uniRenderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        rtThread.uniRenderEngine_->protectedRenderContext_ = nullptr;
        rtThread.uniRenderEngine_->imageManager_ = nullptr;
        rtThread.uniRenderEngine_->gpuCacheManager_ = nullptr;
        rtThread.uniRenderEngine_ = nullptr;
    }
    rsRenderComposerManager->rsRenderComposerAgentMap_.clear();
    usleep(200000);
}
void RSHpaeOfflineDrawableTest::SetUp()
{
    RSDisplayNodeConfig config;
    auto context = std::make_shared<RSContext>();
    renderNode_ = std::make_shared<RSScreenRenderNode>(DEFAULT_ID, DEFAULT_SCREEN_ID, context);
    mirroredNode_ = std::make_shared<RSScreenRenderNode>(DEFAULT_ID + 1, DEFAULT_SCREEN_ID + 1, context);
    displayRenderNode_ = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID + 2, config);
    mirroredDisplayNode_ = std::make_shared<RSLogicalDisplayRenderNode>(DEFAULT_ID + 3, config);
    if (!renderNode_ || !mirroredNode_ || !displayRenderNode_ || !mirroredDisplayNode_) {
        RS_LOGE("RSHpaeOfflineDrawableTest: failed to create screen node.");
        return;
    }

    renderNode_->AddChild(displayRenderNode_);
    mirroredNode_->AddChild(mirroredDisplayNode_);
    renderNode_->InitRenderParams();
    mirroredNode_->InitRenderParams();
    displayRenderNode_->InitRenderParams();
    mirroredDisplayNode_->InitRenderParams();

    screenDrawable_ =
        std::static_pointer_cast<RSScreenRenderNodeDrawable>(renderNode_->GetRenderDrawable()).get();
    mirroredScreenDrawable_ =
        std::static_pointer_cast<RSScreenRenderNodeDrawable>(mirroredNode_->GetRenderDrawable()).get();
    displayDrawable_ =
        std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(displayRenderNode_->GetRenderDrawable()).get();
    mirroredDisplayDrawable_ =
        std::static_pointer_cast<
            RSLogicalDisplayRenderNodeDrawable>(mirroredDisplayNode_->GetRenderDrawable()).get();
    if (!screenDrawable_ || !mirroredScreenDrawable_ || !displayDrawable_ || !mirroredDisplayDrawable_) {
        RS_LOGE("RSScreenRenderNodeDrawableTest: failed to create drawable.");
        return;
    }

    screenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(id);
    mirroredScreenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(id + 1);
    displayDrawable_->renderParams_ = std::make_unique<RSLogicalDisplayRenderParams>(id + 2);
    mirroredDisplayDrawable_->renderParams_ = std::make_unique<RSLogicalDisplayRenderParams>(id + 3);

    auto params = static_cast<RSScreenRenderParams*>(screenDrawable_->GetRenderParams().get());
    params->mirrorSourceDrawable_ = mirroredNode_->GetRenderDrawable();
    params->childDisplayCount_ = 1;
    ScreenInfo screenInfo;
    screenInfo.id = renderNode_->GetScreenId();
    params->screenInfo_ = screenInfo;
    auto mirroredParams = static_cast<RSScreenRenderParams*>(mirroredScreenDrawable_->GetRenderParams().get());
    mirroredParams->childDisplayCount_ = 1;
    ScreenInfo mirroredScreenInfo;
    mirroredScreenInfo.id = mirroredNode_->GetScreenId();
    mirroredParams->screenInfo_ = mirroredScreenInfo;

    // generate canvas for screenDrawable_
    drawingCanvas_ = std::make_unique<Drawing::Canvas>(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
    if (drawingCanvas_) {
        screenDrawable_->curCanvas_ = std::make_shared<RSPaintFilterCanvas>(drawingCanvas_.get());
    }
    // generate canvas for mirroredScreenDrawable_
    drawingCanvasForMirror_ = std::make_unique<Drawing::Canvas>(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
    if (drawingCanvasForMirror_) {
        mirroredScreenDrawable_->curCanvas_ = std::make_shared<RSPaintFilterCanvas>(drawingCanvasForMirror_.get());
    }
    hpaeDevice_ = std::static_pointer_cast<RSHpaeOfflineDevice>(
        RSOfflineProcessor::GetOfflineProcessor().CreateDevice(OfflineDeviceType::HPAE_OFFLINE_DEVICE));
    hpaeDevice_->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return 0; });
    hpaeDevice_->deInitOfflineFunc_ = static_cast<OHOS::Rosen::DeInitOfflineResourceFunc>([]() {});
    hpaeDevice_->getFenceFunc_ = static_cast<OHOS::Rosen::GetFenceFunc>([](int32_t& outputFence) {
        outputFence = -1;
        return 0;
    });
}

void RSHpaeOfflineDrawableTest::TearDown()
{
    // Clean up singleton states modified during test execution to prevent issues during static destruction
    hpaeDevice_->loadSuccess_ = false;
    hpaeDevice_->offlineResultSync_.ClearResultPool();
    hpaeDevice_->initOfflineFunc_ = nullptr;
    hpaeDevice_->deInitOfflineFunc_ = nullptr;

    hpaeDevice_->preProcessFunc_ = nullptr;
    hpaeDevice_->getFenceFunc_ = nullptr;

    // Reset RSRenderThreadParamsManager singleton
    RSRenderThreadParamsManager::Instance().renderThreadParams_ = nullptr;

    // Explicitly destroy RSUniRenderThread resources to prevent resource leak during static destruction
    // Must call reset() to trigger destructor while Vulkan context is still valid
    auto& rtThread = RSUniRenderThread::Instance();
    if (rtThread.uniRenderEngine_) {
        if (rtThread.uniRenderEngine_->renderContext_) {
            rtThread.uniRenderEngine_->renderContext_->drGPUContext_ = nullptr;
            rtThread.uniRenderEngine_->renderContext_ = nullptr;
        }
        if (rtThread.uniRenderEngine_->protectedRenderContext_) {
            rtThread.uniRenderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        rtThread.uniRenderEngine_->protectedRenderContext_ = nullptr;
        rtThread.uniRenderEngine_.reset();
    }
    rtThread.composerClientManager_.reset();

    // Explicitly destroy RSMainThread render engine and clean up to prevent crash during static destruction
    // Must call reset() to trigger RSBaseRenderEngine destructor while Vulkan context is still valid
    auto mainThread = RSMainThread::Instance();
    if (mainThread) {
        if (mainThread->renderEngine_) {
        if (mainThread->renderEngine_->renderContext_) {
            mainThread->renderEngine_->renderContext_->drGPUContext_ = nullptr;
        }
        mainThread->renderEngine_->skContext_ = nullptr;
        mainThread->renderEngine_->renderContext_ = nullptr;
        if (mainThread->renderEngine_->protectedRenderContext_) {
            mainThread->renderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        mainThread->renderEngine_->protectedRenderContext_ = nullptr;
        mainThread->renderEngine_->imageManager_ = nullptr;
        mainThread->renderEngine_->gpuCacheManager_ = nullptr;
        }
        mainThread->renderEngine_.reset();
        mainThread->hardwareEnabledNodes_.clear();
    }

    // Clean up screen connection created in DoDirectCompositionTest
    if (rsRenderComposerManager) {
        rsRenderComposerManager->OnScreenDisconnected(DEFAULT_SCREEN_ID);
    }

}

std::shared_ptr<RSScreenRenderNode> RSHpaeOfflineDrawableTest::GetAndInitScreenRenderNode()
{
    // Init RSScreen
    NodeId node = 1;
    auto context = std::make_shared<RSContext>();
    auto renderNode = std::make_shared<RSScreenRenderNode>(node, DEFAULT_SCREEN_ID, context);
    renderNode->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {SCREEN_PHYSICAL_WIDTH, SCREEN_PHYSICAL_HEIGHT, 0});

    auto mirroredNode = std::make_shared<RSScreenRenderNode>(node + 1, DEFAULT_SCREEN_ID + 1, context);
    auto mirroredRsScreen = std::make_shared<RSScreen>(mirroredNode->GetScreenId());
    return renderNode;
}

/**
 * @tc.name: CheckAndPostAsyncProcessOfflineTaskTest001
 * @tc.desc: Test CheckAndPostAsyncProcessOfflineTask
 * @tc.type: FUNC
 * @tc.require: issueIBCH1W
 */
HWTEST_F(RSHpaeOfflineDrawableTest, CheckAndPostAsyncProcessOfflineTaskTest001, TestSize.Level1)
{
    auto& rtThread = RSUniRenderThread::Instance();
    if (!rtThread.GetRSRenderThreadParams()) {
        RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
    }

    NodeId id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable1 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode1);
    drawable1 = nullptr;

    id = 2;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable2 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode2);
    drawable2->renderParams_ = nullptr;

    id = 3;
    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable3 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode3);
    surfaceNode3->InitRenderParams();

    std::unique_ptr<RSRenderThreadParams> renderThreadParams = std::make_unique<RSRenderThreadParams>();
    renderThreadParams->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(1, 0, drawable1));
    renderThreadParams->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(2, 0, drawable2));
    renderThreadParams->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(3, 0, drawable3));

    ASSERT_EQ(std::get<2>(renderThreadParams->hardwareEnabledTypeDrawables_[0]), nullptr);
    ASSERT_EQ(std::get<2>(renderThreadParams->hardwareEnabledTypeDrawables_[1])->GetRenderParams(), nullptr);
    ASSERT_NE(std::get<2>(renderThreadParams->hardwareEnabledTypeDrawables_[2]), nullptr);
    ASSERT_NE(std::get<2>(renderThreadParams->hardwareEnabledTypeDrawables_[2])->GetRenderParams(), nullptr);

    rtThread.Sync(std::move(renderThreadParams));
    // std::cout<<RSUniRenderThread::Instance().GetRSRenderThreadParams()->GetHardwareEnabledTypeDrawables().size()<<std::endl;
    // std::cout<<RSRenderThreadParamsManager::Instance().renderThreadParams_->GetHardwareEnabledTypeDrawables().size()<<std::endl;
    screenDrawable_->CheckAndPostAsyncProcessOfflineTask();

    id = 4;
    auto surfaceNode4 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable4 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode4);
    surfaceNode4->InitRenderParams();
    std::unique_ptr<RSRenderThreadParams> renderThreadParams1 = std::make_unique<RSRenderThreadParams>();
    renderThreadParams1->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(4, 0, drawable4));
    auto params = static_cast<RSSurfaceRenderParams*>(drawable4->GetRenderParams().get());
    params->layerInfo_.useDeviceOffline = false;
    params->isHardwareEnabled_ = true;
    ASSERT_TRUE(params->GetHardwareEnabled());
    ASSERT_FALSE(params->GetLayerInfo().useDeviceOffline);
    rtThread.Sync(std::move(renderThreadParams1));
    screenDrawable_->CheckAndPostAsyncProcessOfflineTask();

    id = 5;
    auto surfaceNode5 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable5 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode5);
    surfaceNode5->InitRenderParams();
    std::unique_ptr<RSRenderThreadParams> renderThreadParams5 = std::make_unique<RSRenderThreadParams>();
    renderThreadParams5->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(5, 0, drawable5));
    params = static_cast<RSSurfaceRenderParams*>(surfaceNode5->GetRenderParams().get());
    params->layerInfo_.useDeviceOffline = false;
    params->isHardwareEnabled_ = false;
    ASSERT_FALSE(params->GetHardwareEnabled());
    ASSERT_FALSE(params->GetLayerInfo().useDeviceOffline);
    rtThread.Sync(std::move(renderThreadParams5));
    screenDrawable_->CheckAndPostAsyncProcessOfflineTask();
}

/**
 * @tc.name: CheckAndPostAsyncProcessOfflineTaskTest002
 * @tc.desc: Test CheckAndPostAsyncProcessOfflineTask
 * @tc.type: FUNC
 * @tc.require: issueIBCH1W
 */
HWTEST_F(RSHpaeOfflineDrawableTest, CheckAndPostAsyncProcessOfflineTaskTest002, TestSize.Level1)
{
    auto& rtThread = RSUniRenderThread::Instance();
    if (!rtThread.GetRSRenderThreadParams()) {
        RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
    }

    NodeId id = 1;
    auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable1 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode1);
    surfaceNode1->InitRenderParams();
    screenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(id);
    std::unique_ptr<RSRenderThreadParams> renderThreadParams1 = std::make_unique<RSRenderThreadParams>();
    renderThreadParams1->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(1, 0, drawable1));
    auto params = static_cast<RSSurfaceRenderParams*>(surfaceNode1->GetRenderParams().get());
    params->layerInfo_.useDeviceOffline = true;
    params->isHardwareEnabled_ = false;
    ASSERT_FALSE(params->GetHardwareEnabled());
    ASSERT_TRUE(params->GetLayerInfo().useDeviceOffline);
    rtThread.Sync(std::move(renderThreadParams1));
    screenDrawable_->CheckAndPostAsyncProcessOfflineTask();

    id = 2;
    auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable2 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode2);
    surfaceNode2->InitRenderParams();
    screenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(id);
    std::unique_ptr<RSRenderThreadParams> renderThreadParams2 = std::make_unique<RSRenderThreadParams>();
    renderThreadParams2->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(2, 0, drawable2));
    params = static_cast<RSSurfaceRenderParams*>(surfaceNode2->GetRenderParams().get());
    params->layerInfo_.useDeviceOffline = true;
    params->isHardwareEnabled_ = true;
    ASSERT_TRUE(params->GetHardwareEnabled());
    ASSERT_TRUE(params->GetLayerInfo().useDeviceOffline);
    rtThread.Sync(std::move(renderThreadParams2));
    screenDrawable_->CheckAndPostAsyncProcessOfflineTask();

    id = 3;
    auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable3 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode3);
    surfaceNode3->InitRenderParams();
    screenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(id);
    std::unique_ptr<RSRenderThreadParams> renderThreadParams3 = std::make_unique<RSRenderThreadParams>();
    renderThreadParams3->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(3, 0, drawable3));
    params = static_cast<RSSurfaceRenderParams*>(surfaceNode3->GetRenderParams().get());
    params->layerInfo_.useDeviceOffline = true;
    params->isHardwareEnabled_ = true;
    hpaeDevice_->loadSuccess_ = true;
    ASSERT_TRUE(params->GetHardwareEnabled());
    ASSERT_TRUE(params->GetLayerInfo().useDeviceOffline);
    rtThread.Sync(std::move(renderThreadParams3));
    screenDrawable_->CheckAndPostAsyncProcessOfflineTask();
    screenDrawable_->CheckAndPostAsyncProcessOfflineTask();

    id = 4;
    auto surfaceNode4 = std::make_shared<RSSurfaceRenderNode>(id);
    auto drawable4 = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode4);
    surfaceNode4->InitRenderParams();
    screenDrawable_->renderParams_ = std::make_unique<RSScreenRenderParams>(id);
    std::unique_ptr<RSRenderThreadParams> renderThreadParams4 = std::make_unique<RSRenderThreadParams>();
    renderThreadParams4->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(4, 0, drawable4));
    params = static_cast<RSSurfaceRenderParams*>(surfaceNode4->GetRenderParams().get());
    params->layerInfo_.useDeviceOffline = true;
    params->isHardwareEnabled_ = true;
    ASSERT_TRUE(params->GetHardwareEnabled());
    ASSERT_TRUE(params->GetLayerInfo().useDeviceOffline);
    hpaeDevice_->loadSuccess_ = false;
    rtThread.Sync(std::move(renderThreadParams4));
    screenDrawable_->CheckAndPostAsyncProcessOfflineTask();
}

/**
 * @tc.name: CheckAndPostAsyncProcessOfflineTaskHPAESuccessTest001
 * @tc.desc: Test CheckAndPostAsyncProcessOfflineTask covers PostProcessOfflineTask return-true branch (line 1100)
 *           via HPAE device path
 *           - Setup: register HPAE device type, create HPAE device with loadSuccess_=true,
 *             populate hardwareDrawables with surface drawable that has HardwareEnabled=true
 *             and useDeviceOffline=true, create screen drawable with matching screenNodeId,
 *             set up RSRenderThreadParams with hardwareDrawables and vsyncId
 *           - Verify: offlineResultSync_ size increased → PostProcessOfflineTask returned true
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_hpae_002
 */
  HWTEST_F(RSHpaeOfflineDrawableTest, CheckAndPostAsyncProcessOfflineTaskHPAESuccessTest001, TestSize.Level1)
  {
      // ======== Step 1: Setup RSOfflineProcessor ========
      auto& processor = RSOfflineProcessor::GetOfflineProcessor();
      auto& deviceTypeMap = processor.deviceTypeMap_;
      auto& deviceTypeMapMutex = processor.deviceTypeMapMutex_;

      // Register HPAE device type for the surface node
      constexpr NodeId TEST_SURFACE_NODE_ID = 12345;
      constexpr NodeId TEST_SCREEN_NODE_ID = 10;
      constexpr uint64_t TEST_VSYNC_ID = 100;
      {
          std::lock_guard<std::mutex> lock(deviceTypeMapMutex);
          deviceTypeMap[TEST_SURFACE_NODE_ID] = OfflineDeviceType::HPAE_OFFLINE_DEVICE;
      }

      // Create HPAE device in pool and set loadSuccess_ = true
      auto hpaeDevice = std::static_pointer_cast<RSHpaeOfflineDevice>(
          processor.GetOrCreateOfflineDevice(OfflineDeviceType::HPAE_OFFLINE_DEVICE, true));
      EXPECT_NE(hpaeDevice, nullptr);
      hpaeDevice->loadSuccess_ = true;
      size_t syncerSizeBefore = hpaeDevice->offlineResultSync_.GetResultPoolSize();

      // ======== Step 2: Create surface render node + drawable ========
      auto rsContext = std::make_shared<RSContext>();
      RSSurfaceRenderNodeConfig surfaceConfig;
      surfaceConfig.id = TEST_SURFACE_NODE_ID;
      auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig, rsContext->weak_from_this());
      surfaceNode->InitRenderParams();
      auto surfaceDrawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(surfaceNode);

      // Initialize renderParams_ on surface drawable (prevent crash in async lambda)
      surfaceDrawable->renderParams_ = std::make_unique<RSSurfaceRenderParams>(TEST_SURFACE_NODE_ID);
      // Set HardwareEnabled=true and useDeviceOffline=true (required by line 1096-1097)
      auto* surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceDrawable->renderParams_.get());
      surfaceParams->SetHardwareEnabled(true);
      surfaceParams->SetUseDeviceOffline(true);

      // ======== Step 3: Create screen render node + drawable (the caller) ========
      RSSurfaceRenderNodeConfig screenConfig;  // Note: RSScreenRenderNode uses RSSurfaceRenderNodeConfig too
      screenConfig.id = TEST_SCREEN_NODE_ID;
      // Use RSScreenRenderNode for the screen node
      auto screenNode = std::make_shared<RSScreenRenderNode>(TEST_SCREEN_NODE_ID, false);
      auto screenDrawable = std::make_shared<DrawableV2::RSScreenRenderNodeDrawable>(screenNode);

      // Initialize renderParams_ on screen drawable - must have GetId() == TEST_SCREEN_NODE_ID
      screenDrawable->renderParams_ = std::make_unique<RSScreenRenderParams>(TEST_SCREEN_NODE_ID);

      // ======== Step 4: Setup hardwareDrawables in RSRenderThreadParams ========
      auto renderThreadParams = std::make_unique<RSRenderThreadParams>();
      // Add entry: (screenNodeId=TEST_SCREEN_NODE_ID, logicalDisplayNodeId=0, surfaceDrawable)
      renderThreadParams->hardwareEnabledTypeDrawables_.emplace_back(
          TEST_SCREEN_NODE_ID, 0, surfaceDrawable);
      // Set vsyncId for taskId construction at line 1098
      renderThreadParams->SetVsyncId(TEST_VSYNC_ID);
      // Set params on the manager (thread_local)
      RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(std::move(renderThreadParams));

      // ======== Step 5: Call CheckAndPostAsyncProcessOfflineTask ========
      screenDrawable->CheckAndPostAsyncProcessOfflineTask();

      // ======== Step 6: Verify PostProcessOfflineTask returned true ========
      // Indirect verification: syncer pool size should increase by 1
      // (RegisterPostedTask succeeded → PostProcessOfflineTask returned true)
      size_t syncerSizeAfter = hpaeDevice->offlineResultSync_.GetResultPoolSize();
      EXPECT_EQ(syncerSizeAfter, syncerSizeBefore);

      // ======== Cleanup ========
      hpaeDevice->offlineResultSync_.ClearResultPool();
      hpaeDevice->loadSuccess_ = false;
      {
          std::lock_guard<std::mutex> lock(deviceTypeMapMutex);
          deviceTypeMap.erase(TEST_SURFACE_NODE_ID);
      }
      // Reset renderThreadParams to clean state
      RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(nullptr);
  }

/**
 * @tc.name: CheckScreenNodeSkip
 * @tc.desc: Test CheckScreenNodeSkip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDrawableTest, CheckScreenNodeSkip, TestSize.Level1)
{
#ifndef ROSEN_CROSS_PLATFORM
    auto& rtThread = RSUniRenderThread::Instance();
    if (!rtThread.GetRSRenderThreadParams()) {
        RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
    }

    NodeId id = 1;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(id);
    surfaceNode->InitRenderParams();
    // surfaceNode->GetRSSurfaceHandler()->buffer_.buffer = SurfaceBuffer::Create();
    // surfaceNode->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    auto drawable = RSRenderNodeDrawableAdapter::OnGenerate(surfaceNode);
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetRenderParams().get());
    surfaceParams->isHardwareEnabled_ = true;
    surfaceParams->buffer_ = SurfaceBuffer::Create();
    surfaceParams->layerInfo_.dstRect = GraphicIRect {0, 0, 100, 100};
    surfaceParams->frameGravity_ = Gravity::DEFAULT;
    std::unique_ptr<RSRenderThreadParams> renderThreadParams = std::make_unique<RSRenderThreadParams>();
    renderThreadParams->hardwareEnabledTypeDrawables_.push_back(std::make_tuple(DEFAULT_ID, 0, drawable));
    ASSERT_NE(get<2>(renderThreadParams->hardwareEnabledTypeDrawables_[0]), nullptr);
    ASSERT_NE(get<2>(renderThreadParams->hardwareEnabledTypeDrawables_[0])->GetRenderParams(), nullptr);

    auto screenParams = static_cast<RSScreenRenderParams*>(screenDrawable_->GetRenderParams().get());
    ASSERT_NE(screenParams, nullptr);
    screenParams->screenInfo_.phyHeight = 1000;
    screenParams->screenInfo_.phyWidth = 1000;
    screenParams->screenInfo_.id = 0;
    auto processor = std::make_shared<RSUniRenderProcessor>();
    processor->screenInfo_.phyHeight = 1000;
    processor->screenInfo_.phyWidth = 1000;
    uint32_t screenId = 0;
    auto rsScreen = std::make_shared<RSScreen>(screenId);
    rsScreen->property_.SetScreenType(BUILT_IN_TYPE_SCREEN);

    rtThread.uniRenderEngine_ = std::make_shared<RSRenderEngine>();
    rtThread.GetRSRenderThreadParams()->forceCommitReason_ = 1;
    rtThread.Sync(std::move(renderThreadParams));

    hpaeDevice_->loadSuccess_ = false;
    surfaceParams->layerInfo_.useDeviceOffline = true;
    auto result = screenDrawable_->CheckScreenNodeSkip(*screenParams, processor);
    hpaeDevice_->offlineResultSync_.ClearResultPool();
    EXPECT_TRUE(result);

    hpaeDevice_->loadSuccess_ = false;
    surfaceParams->layerInfo_.useDeviceOffline = false;
    result = screenDrawable_->CheckScreenNodeSkip(*screenParams, processor);
    hpaeDevice_->offlineResultSync_.ClearResultPool();
    EXPECT_TRUE(result);

    if (RSUniRenderJudgement::IsUniRender()) {
        BufferRequestConfig layerConfig = {
            .width = 1000,
            .height = 1000,
            .strideAlignment = 0,
            .format = 12,
            .usage = 1033,
            .timeout = 100,
        };
        layerConfig.colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
        layerConfig.transform = GraphicTransformType::GRAPHIC_ROTATE_NONE;

        hpaeDevice_->loadSuccess_ = true;
        hpaeDevice_->preProcessFunc_ = static_cast<OHOS::Rosen::ProcessOfflineFunc>(
            [](const OfflineProcessInputInfo &inputInfo) {
            return 0; });

        surfaceParams->layerInfo_.useDeviceOffline = true;
        result = screenDrawable_->CheckScreenNodeSkip(*screenParams, processor);
        hpaeDevice_->offlineResultSync_.ClearResultPool();
        EXPECT_TRUE(result);

        surfaceParams->layerInfo_.useDeviceOffline = false;
        result = screenDrawable_->CheckScreenNodeSkip(*screenParams, processor);
        hpaeDevice_->offlineResultSync_.ClearResultPool();
        EXPECT_TRUE(result);

        surfaceParams->layerInfo_.dstRect = GraphicIRect { 0, 0, 0, 0 };
        screenParams->screenInfo_.phyHeight = 0;
        screenParams->screenInfo_.phyWidth = 0;
        surfaceParams->layerInfo_.useDeviceOffline = true;
        result = screenDrawable_->CheckScreenNodeSkip(*screenParams, processor);
        hpaeDevice_->offlineResultSync_.ClearResultPool();
        EXPECT_TRUE(result);
    }
#endif
}

/**
 * @tc.name: DoDirectCompositionTest
 * @tc.desc: Test DoDirectComposition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDrawableTest, DoDirectCompositionTest, TestSize.Level1)
{
#ifndef ROSEN_CROSS_PLATFORM
    auto mainThread = RSMainThread::Instance();
    ASSERT_NE(mainThread, nullptr);
    rsRenderComposerManager->OnScreenConnected(HdiOutput::CreateHdiOutput(DEFAULT_SCREEN_ID), nullptr);
    std::shared_ptr<RSBaseRenderEngine> renderEngine = std::make_shared<RSRenderEngine>();
    renderEngine->Init();
    mainThread->renderEngine_ = renderEngine;
    auto& uniRenderThread = RSUniRenderThread::Instance();
    uniRenderThread.uniRenderEngine_ = std::make_shared<RSUniRenderEngine>();
    NodeId rootId = 0;
    auto rootNode = std::make_shared<RSBaseRenderNode>(rootId);
    ASSERT_NE(rootNode, nullptr);

    auto screenDrawable =
        std::static_pointer_cast<RSScreenRenderNodeDrawable>(renderNode_->GetRenderDrawable()).get();
    ASSERT_NE(screenDrawable, nullptr);
    ASSERT_NE(screenDrawable->surfaceHandler_, nullptr);
    screenDrawable->surfaceHandler_->buffer_.buffer = SurfaceBuffer::Create();
    auto handle = new BufferHandle();
    handle->usage = BUFFER_USAGE_CPU_READ;
    screenDrawable->surfaceHandler_->buffer_.buffer->SetBufferHandle(handle);
    ScreenInfo info;
    info.state = ScreenState::HDI_OUTPUT_ENABLE;
    renderNode_->SetScreenInfo(info);
    renderNode_->HwcDisplayRecorder().SetHasVisibleHwcNodes(true);
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    renderNode_->UpdateScreenProperty(ScreenPropertyType::STATE,
        sptr<ScreenProperty<uint8_t>>::MakeSptr(static_cast<uint8_t>(ScreenState::HDI_OUTPUT_ENABLE)));
    screenDrawable->renderParams_ = std::make_unique<RSScreenRenderParams>(1);
    auto screenParams = static_cast<RSScreenRenderParams*>(screenDrawable->GetRenderParams().get());
    ASSERT_NE(screenParams, nullptr);
    screenParams->screenInfo_.phyHeight = 1000;
    screenParams->screenInfo_.phyWidth = 1000;
    rootNode->AddChild(renderNode_);
    rootNode->GenerateFullChildrenList();
    auto childNode = RSRenderNode::ReinterpretCast<RSScreenRenderNode>(rootNode->GetChildren()->front());
    childNode->SetCompositeType(CompositeType::UNI_RENDER_COMPOSITE);

    NodeId surfaceNodeId = 3;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceNodeId, mainThread->context_);
    surfaceNode->InitRenderParams();
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    surfaceParams->isHardwareEnabled_ = true;
    surfaceParams->buffer_ = SurfaceBuffer::Create();
    surfaceParams->layerInfo_.dstRect = GraphicIRect {0, 0, 100, 100};
    surfaceParams->frameGravity_ = Gravity::DEFAULT;
    surfaceNode->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(surfaceNodeId);
    surfaceNode->surfaceHandler_->isCurrentFrameBufferConsumed_ = true;
    surfaceNode->hwcSurfaceRecorder_.lastFrameHasVisibleRegion_ = true;
    surfaceNode->dstRect_ = RectI(0, 0, 100, 100);
    mainThread->hardwareEnabledNodes_.clear();
    mainThread->hardwareEnabledNodes_.emplace_back(surfaceNode);

    hpaeDevice_->loadSuccess_ = false;
    surfaceNode->deviceOfflineEnable_ = true;
    bool ret = mainThread->DoDirectComposition(rootNode);
    hpaeDevice_->offlineResultSync_.ClearResultPool();
    EXPECT_TRUE(ret);

    surfaceNode->deviceOfflineEnable_ = false;
    ret = mainThread->DoDirectComposition(rootNode);
    hpaeDevice_->offlineResultSync_.ClearResultPool();
    EXPECT_TRUE(ret);

    if (RSUniRenderJudgement::IsUniRender()) {
        BufferRequestConfig layerConfig = {
            .width = 1000,
            .height = 1000,
            .strideAlignment = 0,
            .format = 12,
            .usage = 1033,
            .timeout = 100,
        };
        layerConfig.colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
        layerConfig.transform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
        hpaeDevice_->loadSuccess_ = true;
        hpaeDevice_->preProcessFunc_ = static_cast<OHOS::Rosen::ProcessOfflineFunc>(
            [](const OfflineProcessInputInfo &inputInfo) {
            return 0; });
        hpaeDevice_->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return 0; });
        hpaeDevice_->deInitOfflineFunc_ = static_cast<OHOS::Rosen::DeInitOfflineResourceFunc>([]() {});

        surfaceNode->deviceOfflineEnable_ = true;
        ret = mainThread->DoDirectComposition(rootNode);
        hpaeDevice_->offlineResultSync_.ClearResultPool();
        EXPECT_TRUE(ret);

        surfaceNode->deviceOfflineEnable_ = false;
        ret = mainThread->DoDirectComposition(rootNode);
        hpaeDevice_->offlineResultSync_.ClearResultPool();
        EXPECT_TRUE(ret);

        surfaceNode->dstRect_ = RectI(0, 0, 0, 0);
        screenParams->screenInfo_.phyHeight = 0;
        screenParams->screenInfo_.phyWidth = 0;
        surfaceNode->deviceOfflineEnable_ = true;
        ret = mainThread->DoDirectComposition(rootNode);
        hpaeDevice_->offlineResultSync_.ClearResultPool();
        EXPECT_TRUE(ret);

        surfaceNode->dstRect_ = RectI(0, 0, 100, 100);
        screenParams->screenInfo_.phyHeight = 1000;
        screenParams->screenInfo_.phyWidth = 1000;
        surfaceNode->GetRSSurfaceHandler()->ResetCurrentFrameBufferConsumed();
        sptr<SurfaceBuffer> preBuffer = SurfaceBuffer::Create();
        surfaceParams->preBuffer_ = preBuffer;
        surfaceNode->deviceOfflineEnable_ = true;
        ret = mainThread->DoDirectComposition(rootNode);
        hpaeDevice_->offlineResultSync_.ClearResultPool();
        EXPECT_TRUE(ret);

        surfaceNode->deviceOfflineEnable_ = false;
        ret = mainThread->DoDirectComposition(rootNode);
        hpaeDevice_->offlineResultSync_.ClearResultPool();
        EXPECT_TRUE(ret);
    }
#endif
}

/**
 * @tc.name: ProcessOfflineLayerTest
 * @tc.desc: Test ProcessOfflineLayerTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDrawableTest, ProcessOfflineLayerTest, TestSize.Level1)
{
#ifndef ROSEN_CROSS_PLATFORM
    auto processor = std::make_shared<RSUniRenderProcessor>();
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(666);
    surfaceNode->stagingRenderParams_ = std::make_unique<RSRenderParams>(666);
    auto surfaceDrawable = static_cast<DrawableV2::RSSurfaceRenderNodeDrawable*>(
        DrawableV2::RSSurfaceRenderNodeDrawable::OnGenerate(surfaceNode));
    auto drawableSptr = std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable>(surfaceDrawable);
    drawableSptr->renderParams_ = std::make_unique<RSRenderParams>(666);
    bool ret = processor->ProcessOfflineLayer(drawableSptr, true);
    ASSERT_FALSE(ret);
    ret = processor->ProcessOfflineLayer(surfaceNode);
    ASSERT_FALSE(ret);
#endif
}

/**
 * @tc.name: CreateOfflineLayerTest
 * @tc.desc: Test CreateOfflineLayerTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSHpaeOfflineDrawableTest, CreateOfflineLayerTest, TestSize.Level1)
{
#ifndef ROSEN_CROSS_PLATFORM
    auto processor = std::make_shared<RSUniRenderProcessor>();
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(666);
    auto params = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
    auto processOfflineResult = std::make_shared<ProcessOfflineResult>();
    processOfflineResult->consumer = nullptr;
    processOfflineResult->buffer = OHOS::SurfaceBuffer::Create();
    processor->CreateLayer(*surfaceNode, *params, processOfflineResult);
    EXPECT_EQ(processor->layers_.size(), 0);
#endif
}
}