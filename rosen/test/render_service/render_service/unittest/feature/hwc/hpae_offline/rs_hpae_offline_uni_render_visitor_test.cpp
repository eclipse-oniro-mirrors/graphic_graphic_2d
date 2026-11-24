/*
 * Copyright (c) 2022 HUA[REPLACED] Device Co., Ltd.
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

#include <memory>

#include "common/rs_common_hook.h"
#include "gtest/gtest.h"
#include "limit_number.h"
#include "pipeline/rs_test_util.h"
#include "system/rs_system_parameters.h"

#include "draw/color.h"
#include "monitor/self_drawing_node_monitor.h"
#include "drawable/rs_screen_render_node_drawable.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "pipeline/hardware_thread/rs_realtime_refresh_rate_manager.h"
#include "pipeline/hwc/rs_uni_hwc_visitor.h"
#include "pipeline/main_thread/rs_uni_render_visitor.h"
#include "engine/rs_uni_render_engine.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/render_thread/rs_uni_render_util.h"
#include "pipeline/rs_base_render_node.h"
#include "pipeline/rs_context.h"
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_effect_render_node.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/rs_processor_factory.h"
#include "pipeline/rs_proxy_render_node.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_render_thread.h"
#include "pipeline/rs_root_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "feature/occlusion_culling/rs_occlusion_handler.h"
#include "feature/round_corner_display/rs_round_corner_display.h"
#include "feature/round_corner_display/rs_round_corner_display_manager.h"
#include "feature/uifirst/rs_uifirst_manager.h"
#include "feature_cfg/graphic_feature_param_manager.h"
// hpae offline
#include "feature/hwc/hpae_offline/rs_hpae_offline_device.h"
#include "feature/hwc/hpae_offline/rs_offline_processor.h"

using namespace testing;
using namespace testing::ext;

namespace {
}

namespace OHOS::Rosen {
class RSChildrenDrawableAdapter : public RSDrawable {
public:
    RSChildrenDrawableAdapter() = default;
    ~RSChildrenDrawableAdapter() override = default;
    bool OnUpdate(const RSRenderNode& content) override { return true; }
    void OnSync() override {}
    void OnDraw(Drawing::Canvas* canvas, const Drawing::Rect* rect) const override {}

private:
    bool OnSharedTransition(const std::shared_ptr<RSRenderNode>& node) { return true; }
    friend class RSRenderNode;
};

class RSHpaeOfflineUniRSVisitorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    const uint32_t screenId_ = 3;
    const int32_t offsetX = 0; // screenOffset on x axis equals to 0
    const int32_t offsetY = 0; // screenOffset on y axis equals to 0

    sptr<RSScreenManager> screenManager_;
    ScreenInfo screenInfo_;
    std::shared_ptr<RSHpaeOfflineDevice> hpaeDevice_ = nullptr;
};

void RSHpaeOfflineUniRSVisitorTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}

void RSHpaeOfflineUniRSVisitorTest::TearDownTestCase()
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
    if (RSUniHwcPrevalidateUtil::GetInstance().preValidateHandle_ != nullptr) {
        RSUniHwcPrevalidateUtil::GetInstance().preValidateHandle_ = nullptr;
        RSUniHwcPrevalidateUtil::GetInstance().preValidateFunc_ = nullptr;
        RSUniHwcPrevalidateUtil::GetInstance().handleEventFunc_ = nullptr;
    }
}

void RSHpaeOfflineUniRSVisitorTest::TearDown()
{
    screenManager_ = sptr<RSScreenManager>::MakeSptr();
    screenManager_->screens_.erase(screenId_);
}

void RSHpaeOfflineUniRSVisitorTest::SetUp()
{
    if (RSUniRenderJudgement::IsUniRender()) {
        auto& uniRenderThread = RSUniRenderThread::Instance();
        uniRenderThread.uniRenderEngine_ = std::make_shared<RSUniRenderEngine>();
    }

    screenManager_ = sptr<RSScreenManager>::MakeSptr();
    ASSERT_NE(screenManager_, nullptr);
    uint32_t width = 2560;
    uint32_t height = 1080;
    ScreenColorGamut colorGamut = ScreenColorGamut::COLOR_GAMUT_SRGB;
    ScreenState state = ScreenState::UNKNOWN;
    ScreenRotation rotation = ScreenRotation::ROTATION_0;
    screenInfo_.width = width;
    screenInfo_.height = height;
    screenInfo_.phyWidth = width;
    screenInfo_.phyHeight = height;
    screenInfo_.colorGamut = colorGamut;
    screenInfo_.state = state;
    screenInfo_.rotation = rotation;

    hpaeDevice_ = std::static_pointer_cast<RSHpaeOfflineDevice>(
        RSOfflineProcessor::GetOfflineProcessor().GetOrCreateOfflineDevice(OfflineDeviceType::HPAE_OFFLINE_DEVICE, true));
    ASSERT_NE(hpaeDevice_, nullptr);
    hpaeDevice_->initOfflineFunc_ = static_cast<OHOS::Rosen::InitOfflineResourceFunc>([]() { return 0; });
    hpaeDevice_->deInitOfflineFunc_ = static_cast<OHOS::Rosen::DeInitOfflineResourceFunc>([]() {});
    hpaeDevice_->getFenceFunc_ = static_cast<OHOS::Rosen::GetFenceFunc>([](int32_t& outputFence) {
        outputFence = -1;
        return 0;
    });
}

/**
 * @tc.name: PrevalidateHwcNode001
 * @tc.desc: PrevalidateHwcNode001, verify PrevalidateHwcNode, size = 0
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSHpaeOfflineUniRSVisitorTest, PrevalidateHwcNode001, TestSize.Level1)
{
    // 初始化
    NodeId id = 1;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, 0, rsContext);
    auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
    ASSERT_NE(rsUniRenderVisitor, nullptr);

    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);

    screenNode->GetAllMainAndLeashSurfaces().push_back(surfaceNode);

    rsUniRenderVisitor->curScreenNode_ = screenNode;
    rsUniRenderVisitor->PrevalidateHwcNode();
    ASSERT_FALSE(surfaceNode->isHardwareForcedDisabled_); // surfaceNode->isHardwareForcedDisabled_ = true 表示无法走DSS叠加
}

/**
 * @tc.name: PrevalidateHwcNode002
 * @tc.desc: PrevalidateHwcNode002, verify PrevalidateHwcNode， size = 1,DEVICE
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSHpaeOfflineUniRSVisitorTest, PrevalidateHwcNode002, TestSize.Level1)
{
    // 初始化
    NodeId id = 1;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, 0, rsContext);
    auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
    ASSERT_NE(rsUniRenderVisitor, nullptr);
    screenNode->screenInfo_ = screenInfo_;

    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    auto surfaceNode1 = RSTestUtil::CreateSurfaceNodeWithBuffer();
    surfaceNode1->isOnTheTree_ = true;
    auto bufferHandle = surfaceNode1->surfaceHandler_->buffer_.buffer->GetBufferHandle();
    surfaceNode1->SetSrcRect({0, 0, 500, 500});
    surfaceNode1->SetDstRect({0, 0, 500, 500});
    bufferHandle->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_1010102;
    surfaceNode->AddChildHardwareEnabledNode(surfaceNode1);

    screenNode->GetAllMainAndLeashSurfaces().push_back(surfaceNode);

    RSUniHwcPrevalidateUtil::GetInstance().preValidateFunc_ =
        static_cast<OHOS::Rosen::PreValidateFunc>([](
            uint32_t id, const std::vector<RequestLayerInfo> &infos, std::map<uint64_t, RequestCompositionType> &strategy)
            {
                strategy[0] = RequestCompositionType::DEVICE;
                return 0;
            }
        );
    rsUniRenderVisitor->curScreenNode_ = screenNode;
    rsUniRenderVisitor->PrevalidateHwcNode();
    ASSERT_FALSE(surfaceNode->isHardwareForcedDisabled_); // surfaceNode->isHardwareForcedDisabled_ = true 表示无法走DSS叠加
    RSTestUtil::UnregisterConsumerListener();
}

/**
 * @tc.name: PrevalidateHwcNode003
 * @tc.desc: PrevalidateHwcNode003, verify PrevalidateHwcNode， size = 1,OFFLINE_DEVICE true
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSHpaeOfflineUniRSVisitorTest, PrevalidateHwcNode003, TestSize.Level1)
{
    // 初始化
    NodeId id = 1;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, 0, rsContext);
    auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
    ASSERT_NE(rsUniRenderVisitor, nullptr);
    screenNode->screenInfo_ = screenInfo_;

    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    auto surfaceNode1 = RSTestUtil::CreateSurfaceNodeWithBuffer();
    surfaceNode1->isOnTheTree_ = true;
    auto bufferHandle = surfaceNode1->surfaceHandler_->buffer_.buffer->GetBufferHandle();
    surfaceNode1->SetSrcRect({0, 0, 500, 500});
    surfaceNode1->SetDstRect({0, 0, 500, 500});
    bufferHandle->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_8888;
    surfaceNode->AddChildHardwareEnabledNode(surfaceNode1);
    auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
    nodeMap.renderNodeMap_.clear();
    nodeMap.RegisterRenderNode(surfaceNode1);

    screenNode->GetAllMainAndLeashSurfaces().push_back(surfaceNode);

    RSUniHwcPrevalidateUtil::GetInstance().preValidateFunc_ =
        static_cast<OHOS::Rosen::PreValidateFunc>([](
            uint32_t id, const std::vector<RequestLayerInfo> &infos, std::map<uint64_t, RequestCompositionType> &strategy)
            {
                strategy[infos[0].id] = RequestCompositionType::OFFLINE_DEVICE;
                return 0;
            }
        );
    rsUniRenderVisitor->curScreenNode_ = screenNode;

    hpaeDevice_->loadSuccess_ = true;
    hpaeDevice_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId, OfflineProcessOutputInfo& outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            return 0;
        });
    rsUniRenderVisitor->PrevalidateHwcNode();
    ASSERT_FALSE(surfaceNode->isHardwareForcedDisabled_); // surfaceNode->isHardwareForcedDisabled_ = true 表示无法走DSS叠加
    nodeMap.renderNodeMap_.clear();
    RSTestUtil::UnregisterConsumerListener();
}

/**
 * @tc.name: PrevalidateHwcNode004
 * @tc.desc: PrevalidateHwcNode004, verify PrevalidateHwcNode， size = 1,OFFLINE_DEVICE false
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSHpaeOfflineUniRSVisitorTest, PrevalidateHwcNode004, TestSize.Level1)
{
    // 初始化
    NodeId id = 1;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, 0, rsContext);
    auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
    ASSERT_NE(rsUniRenderVisitor, nullptr);
    screenNode->screenInfo_ = screenInfo_;

    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    auto surfaceNode1 = RSTestUtil::CreateSurfaceNodeWithBuffer();
    surfaceNode1->isOnTheTree_ = true;
    auto bufferHandle = surfaceNode1->surfaceHandler_->buffer_.buffer->GetBufferHandle();
    surfaceNode1->SetSrcRect({0, 0, 500, 500});
    surfaceNode1->SetDstRect({0, 0, 500, 500});
    bufferHandle->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_8888;
    surfaceNode->AddChildHardwareEnabledNode(surfaceNode1);
    auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
    nodeMap.renderNodeMap_.clear();
    nodeMap.RegisterRenderNode(surfaceNode1);

    screenNode->GetAllMainAndLeashSurfaces().push_back(surfaceNode);

    RSUniHwcPrevalidateUtil::GetInstance().preValidateFunc_ =
        static_cast<OHOS::Rosen::PreValidateFunc>([](
            uint32_t id, const std::vector<RequestLayerInfo> &infos, std::map<uint64_t, RequestCompositionType> &strategy)
            {
                strategy[infos[0].id] = RequestCompositionType::OFFLINE_DEVICE;
                return 0;
            }
        );
    rsUniRenderVisitor->curScreenNode_ = screenNode;

    hpaeDevice_->loadSuccess_ = true;
    hpaeDevice_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            return 0;
        });

    rsUniRenderVisitor->PrevalidateHwcNode();
    ASSERT_FALSE(surfaceNode->isHardwareForcedDisabled_); // surfaceNode->isHardwareForcedDisabled_ = true 表示无法走DSS叠加
    nodeMap.renderNodeMap_.clear();
    RSTestUtil::UnregisterConsumerListener();
}

/**
 * @tc.name: PrevalidateHwcNode005
 * @tc.desc: PrevalidateHwcNode005, verify PrevalidateHwcNode， curMainAndLeashSurfaces.size() = 0
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSHpaeOfflineUniRSVisitorTest, PrevalidateHwcNode005, TestSize.Level1)
{
    // 初始化
    NodeId id = 1;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, 0, rsContext);
    auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
    ASSERT_NE(rsUniRenderVisitor, nullptr);
    screenNode->screenInfo_ = screenInfo_;
    rsUniRenderVisitor->curScreenNode_ = screenNode;
    rsUniRenderVisitor->PrevalidateHwcNode();
}

/**
 * @tc.name: UpdateHwcNodeEnableByPrevalidate
 * @tc.desc: UpdateHwcNodeEnableByPrevalidate, verify UpdateHwcNodeEnableByPrevalidate
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSHpaeOfflineUniRSVisitorTest, UpdateHwcNodeEnableByPrevalidate003, TestSize.Level1)
{
    // 初始化
    NodeId id = 1;
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, 0, rsContext);
    auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
    ASSERT_NE(rsUniRenderVisitor, nullptr);
    screenNode->screenInfo_ = screenInfo_;

    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    auto surfaceNode1 = RSTestUtil::CreateSurfaceNodeWithBuffer();
    surfaceNode1->isOnTheTree_ = true;
    auto bufferHandle = surfaceNode1->surfaceHandler_->buffer_.buffer->GetBufferHandle();
    surfaceNode1->SetSrcRect({0, 0, 500, 500});
    surfaceNode1->SetDstRect({0, 0, 500, 500});
    bufferHandle->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_8888;
    surfaceNode1->vcldInfo_.enable = true;
    surfaceNode->AddChildHardwareEnabledNode(surfaceNode1);
    auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
    nodeMap.renderNodeMap_.clear();
    nodeMap.RegisterRenderNode(surfaceNode1);

    screenNode->GetAllMainAndLeashSurfaces().push_back(surfaceNode);

    RSUniHwcPrevalidateUtil::GetInstance().preValidateFunc_ =
        static_cast<OHOS::Rosen::PreValidateFunc>([](
            uint32_t id, const std::vector<RequestLayerInfo> &infos, std::map<uint64_t, RequestCompositionType> &strategy)
            {
                strategy[infos[0].id] = RequestCompositionType::OFFLINE_VCLD_OFF;
                return 0;
            }
        );
    rsUniRenderVisitor->curScreenNode_ = screenNode;

    hpaeDevice_->loadSuccess_ = false;
    hpaeDevice_->getConfigFunc_ =
        static_cast<OHOS::Rosen::GetOfflineConfigFunc>([](NodeId, OfflineProcessOutputInfo &outputInfo) {
            outputInfo.bufferConfig.width = 128;
            outputInfo.bufferConfig.height = 128;
            return 0;
        });

    rsUniRenderVisitor->PrevalidateHwcNode();
    ASSERT_TRUE(surfaceNode1->GetVcldInfo().enable);
    nodeMap.renderNodeMap_.clear();
    RSTestUtil::UnregisterConsumerListener();
}
}