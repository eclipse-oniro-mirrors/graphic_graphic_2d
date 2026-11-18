/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include <parameters.h>

#include "common/rs_common_def.h"
#include "common/rs_special_layer_manager.h"
#include "composer/composer_client/pipeline/rs_composer_client_manager.h"
#include "engine/rs_uni_render_engine.h"
#include "drawable/rs_logical_display_render_node_drawable.h"
#include "drawable/rs_render_node_drawable.h"
#include "feature/dirty/rs_uni_dirty_compute_util.h"
#include "feature/special_layer/rs_special_layer_utils.h"
#include "feature/multi_screen/rs_multi_screen_util.h"
#include "graphic_feature_param_manager.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/rs_logical_display_render_node.h"
#include "pipeline/rs_render_node_gc.h"
#include "pipeline/rs_processor_factory.h"
#include "pipeline/render_thread/rs_render_engine.h"
#include "pipeline/render_thread/rs_uni_render_virtual_processor.h"
#include "platform/common/rs_system_properties.h"
#include "platform/ohos/backend/rs_surface_frame_ohos_raster.h"
#include "platform/ohos/backend/rs_surface_ohos_raster.h"
#include "render/rs_pixel_map_util.h"
#include "screen_manager/rs_screen.h"
#include "screen_manager/rs_screen_property.h"
#include "screen_manager/screen_types.h"
#include "utils/rect.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
namespace {
constexpr NodeId DEFAULT_ID = 0xFFFF;
constexpr NodeId SCREEN_NODE_ID = DEFAULT_ID + 1;
constexpr NodeId DISPLAY_NODE_ID = DEFAULT_ID + 2;
constexpr NodeId MIRROR_SOURCE_SCREEN_NODE_ID = DEFAULT_ID + 3;
constexpr NodeId MIRROR_SOURCE_DISPLAY_NODE_ID = DEFAULT_ID + 4;
constexpr NodeId RECORD_SURFACE_NODE_ID = DEFAULT_ID + 5;
constexpr int32_t DEFAULT_CANVAS_SIZE = 100;
constexpr ScreenId SCREEN_ID = 10086;
constexpr uint32_t DEFAULT_CANVAS_WIDTH = 800;
constexpr uint32_t DEFAULT_CANVAS_HEIGHT = 600;
} // namespace
class RSMultiScreenUtilTest : public testing::Test {
public:
    std::shared_ptr<RSLogicalDisplayRenderNode> displayNode_;
    std::shared_ptr<RSLogicalDisplayRenderNode> mirrorSourceDisplayNode_;
    std::shared_ptr<RSScreenRenderNode> screenNode_;
    std::shared_ptr<RSScreenRenderNode> mirrorSourceScreenNode_;

    RSLogicalDisplayRenderNodeDrawable* displayDrawable_ = nullptr;
    RSLogicalDisplayRenderNodeDrawable* mirrorSourceDisplayDrawable_ = nullptr;
    RSScreenRenderNodeDrawable* screenDrawable_ = nullptr;
    RSScreenRenderNodeDrawable* mirrorSourceScreenDrawable_ = nullptr;

    RSLogicalDisplayRenderParams* displayParams_ = nullptr;
    RSLogicalDisplayRenderParams* mirrorSourceDisplayParams_ = nullptr;
    RSScreenRenderParams* screenParams_ = nullptr;
    RSScreenRenderParams* mirrorSourceScreenParams_ = nullptr;

    std::shared_ptr<Drawing::Canvas> canvas_ = nullptr;
    std::shared_ptr<RSPaintFilterCanvas> paintFilterCanvas_ = nullptr;

    std::shared_ptr<RSUniRenderVirtualProcessor> virtualProcessor_ = nullptr;

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    // Arms all screen-level record gates so a case can then break exactly one of them.
    void ArmWindowRecordScreenGates(RSLogicalDisplayRenderParams& params,
        const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& output,
        const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& source,
        const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& bbox);
};

void RSMultiScreenUtilTest::SetUpTestCase()
{
    auto& renderNodeGC = RSRenderNodeGC::Instance();
    renderNodeGC.nodeBucket_ = std::queue<std::vector<RSRenderNode*>>();
    renderNodeGC.drawableBucket_ = std::queue<std::vector<DrawableV2::RSRenderNodeDrawableAdapter*>>();
}

void RSMultiScreenUtilTest::TearDownTestCase() {}

void RSMultiScreenUtilTest::SetUp()
{
    RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();

    RSDisplayNodeConfig config;
    screenNode_ = std::make_shared<RSScreenRenderNode>(SCREEN_NODE_ID, SCREEN_ID);
    displayNode_ = std::make_shared<RSLogicalDisplayRenderNode>(DISPLAY_NODE_ID, config);
    mirrorSourceScreenNode_ = std::make_shared<RSScreenRenderNode>(MIRROR_SOURCE_SCREEN_NODE_ID, SCREEN_ID);
    mirrorSourceDisplayNode_ = std::make_shared<RSLogicalDisplayRenderNode>(MIRROR_SOURCE_DISPLAY_NODE_ID, config);
    if (!displayNode_ || !mirrorSourceDisplayNode_ || !screenNode_ || !mirrorSourceScreenNode_) {
        FAIL() << "Failed to create node!";
    }

    screenNode_->InitRenderParams();
    displayNode_->InitRenderParams();
    mirrorSourceScreenNode_->InitRenderParams();
    mirrorSourceDisplayNode_->InitRenderParams();

    screenDrawable_ =
        std::static_pointer_cast<RSScreenRenderNodeDrawable>(screenNode_->renderDrawable_).get();
    displayDrawable_ =
        std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(displayNode_->renderDrawable_).get();
    mirrorSourceScreenDrawable_ =
        std::static_pointer_cast<RSScreenRenderNodeDrawable>(mirrorSourceScreenNode_->renderDrawable_).get();
    mirrorSourceDisplayDrawable_ =
        std::static_pointer_cast<RSLogicalDisplayRenderNodeDrawable>(mirrorSourceDisplayNode_->renderDrawable_).get();
    if (!displayDrawable_ || !mirrorSourceDisplayDrawable_ || !screenDrawable_ || !mirrorSourceScreenDrawable_) {
        FAIL() << "Failed to create drawable!";
    }

    screenParams_ = static_cast<RSScreenRenderParams*>(screenDrawable_->GetRenderParams().get());
    displayParams_ = static_cast<RSLogicalDisplayRenderParams*>(displayDrawable_->GetRenderParams().get());
    mirrorSourceScreenParams_ =
        static_cast<RSScreenRenderParams*>(mirrorSourceScreenDrawable_->GetRenderParams().get());
    mirrorSourceDisplayParams_ =
        static_cast<RSLogicalDisplayRenderParams*>(mirrorSourceDisplayDrawable_->GetRenderParams().get());
    if (!displayParams_ || !mirrorSourceDisplayParams_ || !screenParams_ || !mirrorSourceScreenParams_) {
        FAIL() << "Failed to init render params!";
    }

    screenParams_->screenInfo_.id = screenNode_->GetScreenId();
    screenParams_->renderNodeType_ = screenNode_->GetType();
    screenParams_->mirrorSourceDrawable_ = mirrorSourceScreenNode_->GetRenderDrawable();
    screenParams_->logicalDisplayNodeDrawables_.emplace_back(displayNode_->renderDrawable_);
    displayParams_->screenId_ = screenNode_->GetScreenId();
    displayParams_->renderNodeType_ = displayNode_->GetType();
    displayParams_->SetAncestorScreenDrawable(screenNode_->GetRenderDrawable());
    displayParams_->mirrorSourceDrawable_ = mirrorSourceDisplayNode_->GetRenderDrawable();
    mirrorSourceScreenParams_->screenInfo_.id = mirrorSourceScreenNode_->GetScreenId();
    mirrorSourceScreenParams_->renderNodeType_ = mirrorSourceScreenNode_->GetType();
    mirrorSourceScreenParams_->logicalDisplayNodeDrawables_.emplace_back(mirrorSourceDisplayNode_->renderDrawable_);
    mirrorSourceDisplayParams_->screenId_ = mirrorSourceScreenNode_->GetScreenId();
    mirrorSourceDisplayParams_->renderNodeType_ = mirrorSourceDisplayNode_->GetType();
    mirrorSourceDisplayParams_->SetAncestorScreenDrawable(mirrorSourceScreenNode_->GetRenderDrawable());

    virtualProcessor_ = std::make_shared<RSUniRenderVirtualProcessor>();
    if (!virtualProcessor_) {
        FAIL() << "Failed to create RSUniRenderVirtualProcessor!";
    }

    // Set canvas for drawable
    canvas_ = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
    if (!canvas_) {
        FAIL() << "Failed to create canvas for displayDrawable_!";
    }

    paintFilterCanvas_ = std::make_shared<RSPaintFilterCanvas>(canvas_.get());
    virtualProcessor_->canvas_ = paintFilterCanvas_;
    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
}

void RSMultiScreenUtilTest::TearDown()
{
    // Some testcases reset drawable renderParams_ or null drawable pointers, so params must be
    // re-derived from nodes here to avoid dangling raw pointers.
    // logicalDisplayNodeDrawables_ holds strong refs to display drawables and must be cleared
    // before nodes are reset: deferred-deleted screen drawables (RSRenderNodeGC buckets) keep
    // their params alive, otherwise display drawables never die and their stale drawable-cache
    // entries make OnGenerate skip renderDrawable_ setup for new nodes in the next SetUp.
    auto cleanupScreenDrawable = [](const RSRenderNodeDrawableAdapter::SharedPtr& drawable) {
        if (drawable == nullptr || drawable->renderParams_ == nullptr) {
            return;
        }
        auto* params = static_cast<RSScreenRenderParams*>(drawable->renderParams_.get());
        params->logicalDisplayNodeDrawables_.clear();
        auto& props = params->screenProperty_.screenProperties_;
        for (auto& [key, sptrVal] : props) {
            sptrVal.ForceSetRefPtr(nullptr);
        }
        props.clear();
    };
    if (screenNode_ != nullptr) {
        cleanupScreenDrawable(screenNode_->GetRenderDrawable());
    }
    if (mirrorSourceScreenNode_ != nullptr) {
        cleanupScreenDrawable(mirrorSourceScreenNode_->GetRenderDrawable());
    }
    displayDrawable_ = nullptr;
    mirrorSourceDisplayDrawable_ = nullptr;
    screenDrawable_ = nullptr;
    mirrorSourceScreenDrawable_ = nullptr;
    displayParams_ = nullptr;
    mirrorSourceDisplayParams_ = nullptr;
    screenParams_ = nullptr;
    mirrorSourceScreenParams_ = nullptr;
    displayNode_.reset();
    mirrorSourceDisplayNode_.reset();
    screenNode_.reset();
    mirrorSourceScreenNode_.reset();
    canvas_.reset();
    paintFilterCanvas_.reset();
    virtualProcessor_.reset();
    // clear RSRenderThreadParams after each testcase
    RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
}

void RSMultiScreenUtilTest::ArmWindowRecordScreenGates(RSLogicalDisplayRenderParams& params,
    const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& output,
    const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& source,
    const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& bbox)
{
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { RECORD_SURFACE_NODE_ID };
    screenParams_->logicalDisplayNodeDrawables_ = { output };
    params.SetWindowRecordConfig(recordConfig);
    params.SetOnVirtualScreen(true);
    params.SetShouldPaint(true);
    params.recordSourceDisplayDrawable_ = source;
    source->GetRenderParams()->SetShouldPaint(true);
    params.recordWhiteListIds_ = { RECORD_SURFACE_NODE_ID };
    params.hasPaintableRecordSurface_ = true;
    params.recordSurfaceDrawables_ = { bbox };
    bbox->GetRenderParams()->SetAbsDrawRect({ 0, 0, 100, 100 });
    screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
}

/**
 * @tc.name: RSMultiScreenUtilBasicTest001
 * @tc.desc: Test GetScreenParams and GetMirrorSourceParams, they are important and basic functions
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, RSMultiScreenUtilBasicTest001, TestSize.Level1)
{
    // Pay attention!
    // This is a important and basic test, you must ensure this testcase passed all!
    // If this case failed, it may lead to a significant drop in coverage even if other testcases do not failed!

    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(mirrorSourceScreenDrawable_, nullptr);
    ASSERT_NE(mirrorSourceDisplayDrawable_, nullptr);

    EXPECT_NE(screenParams_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    EXPECT_NE(mirrorSourceScreenParams_, nullptr);
    EXPECT_NE(mirrorSourceDisplayParams_, nullptr);

    auto [tempScreenDrawable, tempScreenParams] = displayDrawable_->GetScreenParams(*displayParams_);
    EXPECT_NE(tempScreenDrawable, nullptr);
    EXPECT_NE(tempScreenParams, nullptr);

    auto [tempMirrorSourceDisplayDrawable,
          tempMirrorSourceDisplayParams,
          tempMirrorSourceScreenDrawable,
          tempMirrorSourceScreenParams] = displayDrawable_->GetMirrorSourceParams(*displayParams_);
    EXPECT_NE(tempMirrorSourceDisplayDrawable, nullptr);
    EXPECT_NE(tempMirrorSourceDisplayParams, nullptr);
    EXPECT_NE(tempMirrorSourceScreenDrawable, nullptr);
    EXPECT_NE(tempMirrorSourceScreenParams, nullptr);
}

/**
 * @tc.name: HandleMirrorDisplayTest001
 * @tc.desc: Test HandleMirrorDisplay
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorDisplayTest001, TestSize.Level1)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();

    // when uniParam is nullptr
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(nullptr);
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, processor);

    // restore uniParam for other test cases
    auto uniRenderThreadParams = std::make_unique<RSRenderThreadParams>();
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(std::move(uniRenderThreadParams));

    // when screenParams is nullptr
    displayParams_->SetAncestorScreenDrawable(nullptr);
    auto [_, screenParams] = displayDrawable_->GetScreenParams(*displayParams_);
    EXPECT_EQ(screenParams, nullptr);
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    EXPECT_NE(displayParams_, nullptr);
}

/**
 * @tc.name: HandleMirrorDisplayTest002
 * @tc.desc: Test HandleMirrorDisplay
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorDisplayTest002, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();

    // when processor is nullptr
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);

    // when processor UpdateMirrorInfo failed
    displayDrawable_->renderParams_ = nullptr;
    bool res = processor->UpdateMirrorInfo(*displayDrawable_);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: HandleMirrorDisplayTest003
 * @tc.desc: Test HandleMirrorDisplay
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorDisplayTest003, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    virtualProcessor_->isMirror_ = false;
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);

    // when compositeType_ of params is UNI_RENDER_COMPOSITE
    displayParams_->compositeType_ = CompositeType::UNI_RENDER_COMPOSITE;
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);

    // when compositeType_ of params is not UNI_RENDER_COMPOSITE
    displayParams_->compositeType_ = CompositeType::UNI_RENDER_VIRTUAL_MIRROR_COMPOSITE;
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    EXPECT_NE(displayParams_, nullptr);
}

/**
 * @tc.name: HandleMirrorScreenTest001
 * @tc.desc: Test HandleMirrorScreen
 * @tc.type: FUNC
 * @tc.require: #ICQ74B
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorScreenTest001, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();

    // when uniParam is nullptr
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(nullptr);
    RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, *mirrorSourceScreenParams_, *screenParams_, processor);

    // restore uniParam for other test cases
    auto uniRenderThreadParams = std::make_unique<RSRenderThreadParams>();
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(std::move(uniRenderThreadParams));

    // when processor is nullptr
    RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, *mirrorSourceScreenParams_, *screenParams_, nullptr);

    // when processor is not nullptr but init failed
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PAUSE));
    bool res = processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());
    EXPECT_FALSE(res);
    RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, *mirrorSourceScreenParams_, *screenParams_, processor);
    EXPECT_NE(mirrorSourceScreenParams_, nullptr);
}

/**
 * @tc.name: HandleMirrorScreenTest002
 * @tc.desc: Test HandleMirrorScreen
 * @tc.type: FUNC
 * @tc.require: #ICQ74B
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorScreenTest002, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();

    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    bool res = processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());
    EXPECT_FALSE(res);
    processor->SetDisplaySkipInMirror(true);
    RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, *mirrorSourceScreenParams_, *screenParams_, processor);
    processor->SetDisplaySkipInMirror(false);
    RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, *mirrorSourceScreenParams_, *screenParams_, processor);
    EXPECT_NE(mirrorSourceScreenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendDisplayTest001
 * @tc.desc: Test HandleVirtualExtendDisplay
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendDisplayTest001, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    // when processor UpdateMirrorInfo failed
    virtualProcessor_->isMirror_ = true;
    mirrorSourceDisplayDrawable_->renderParams_ = nullptr;
    bool res = virtualProcessor_->UpdateMirrorInfo(*displayDrawable_);
    EXPECT_FALSE(res);
    RSMultiScreenUtil::HandleVirtualExtendDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);

    // when processor is nullptr
    RSMultiScreenUtil::HandleVirtualExtendDisplay(*displayDrawable_, *displayParams_, nullptr);

    // when screenParams is nullptr
    displayParams_->SetAncestorScreenDrawable(nullptr);
    auto [_, screenParams] = displayDrawable_->GetScreenParams(*displayParams_);
    EXPECT_EQ(screenParams, nullptr);
    RSMultiScreenUtil::HandleVirtualExtendDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);

    // when uniParam is nullptr
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(nullptr);
    RSMultiScreenUtil::HandleVirtualExtendDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);

    // restore uniParam for other test cases
    auto uniRenderThreadParams = std::make_unique<RSRenderThreadParams>();
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(std::move(uniRenderThreadParams));
}

/**
 * @tc.name: HandleVirtualExtendScreenTest001
 * @tc.desc: Test HandleVirtualExtendScreen
 * @tc.type: FUNC
 * @tc.require: #ICQ74B
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest001, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();

    // when uniParam is nullptr
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(nullptr);
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);

    // restore uniParam for other test cases
    auto uniRenderThreadParams = std::make_unique<RSRenderThreadParams>();
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(std::move(uniRenderThreadParams));

    // when processor is nullptr
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, nullptr);

    // when processor is not nullptr but init failed
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PAUSE));
    bool res = processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());
    EXPECT_FALSE(res);
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest002
 * @tc.desc: Test HandleVirtualExtendScreen
 * @tc.type: FUNC
 * @tc.require: #ICQ74B
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest002, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    ScreenId screenId = 7;
    auto &uniThread = RSUniRenderThread::Instance();
    uniThread.composerClientManager_ = std::make_shared<RSComposerClientManager>();
    sptr<IRSRenderToComposerConnection> conn = nullptr;
    auto client = std::make_shared<RSComposerClient>(conn);
    client->SetOutput(std::make_shared<HdiOutput>(screenId));
    uniThread.composerClientManager_->AddComposerClient(screenId, client);
    // when processor is not RSUniRenderVirtualProcessor
    auto processor = std::make_shared<RSUniRenderProcessor>(screenId);

    // processor is not RSUniRenderVirtualProcessor
    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest003
 * @tc.desc: Test HandleVirtualExtendScreen
 * @tc.type: FUNC
 * @tc.require: #ICQ74B
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest003, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();

    // when processor init success
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);

    // set uniParam dirty and test
    uniParam->SetVirtualExpandScreenDirtyEnabled(false);
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->SetVirtualDirtyEnabled(true);
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    uniParam->SetVirtualDirtyEnabled(false);
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    screenParams_->SetHasMirrorScreen(true);
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest004
 * @tc.desc: Test HandleVirtualExtendScreen with dirty align enabled and valid GpuTile
 * @tc.type: FUNC
 * @tc.require: issue23778
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest004, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    // Enable virtual expand screen dirty and dirty align
    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->isDirtyAlignEnabled_ = true;

    // Set valid GpuTile
    RSUniDirtyComputeUtil::SetDamageRegionGpuTile({ 64, 64 });

    // Test with multiple dirty regions (size > dirtyRegionCountThresholdYf)
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);

    // Reset state
    uniParam->isDirtyAlignEnabled_ = false;
    RSUniDirtyComputeUtil::SetDamageRegionGpuTile({ 0, 0 });
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest005
 * @tc.desc: Test HandleVirtualExtendScreen with dirty align disabled
 * @tc.type: FUNC
 * @tc.require: issue23778
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest005, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    // Enable virtual expand screen dirty but disable dirty align
    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->isDirtyAlignEnabled_ = false;

    // Set valid GpuTile (should not take the Clear path since dirty align is disabled)
    RSUniDirtyComputeUtil::SetDamageRegionGpuTile({ 64, 64 });

    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);

    // Reset state
    RSUniDirtyComputeUtil::SetDamageRegionGpuTile({ 0, 0 });
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest006
 * @tc.desc: Test HandleVirtualExtendScreen with invalid GpuTile
 * @tc.type: FUNC
 * @tc.require: issue23778
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest006, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    // Enable virtual expand screen dirty and dirty align
    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->isDirtyAlignEnabled_ = true;

    // Set invalid GpuTile (zero values), should take ClipRegion path
    RSUniDirtyComputeUtil::SetDamageRegionGpuTile({ 0, 0 });

    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);

    // Reset state
    uniParam->isDirtyAlignEnabled_ = false;
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest007
 * @tc.desc: Test HandleVirtualExtendScreen with single dirty region
 * @tc.type: FUNC
 * @tc.require: issue23778
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest007, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    // Enable virtual expand screen dirty and dirty align
    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->isDirtyAlignEnabled_ = true;

    // Set valid GpuTile but with single dirty region (size <= dirtyRegionCountThresholdYf)
    RSUniDirtyComputeUtil::SetDamageRegionGpuTile({ 64, 64 });

    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);

    // Reset state
    uniParam->isDirtyAlignEnabled_ = false;
    RSUniDirtyComputeUtil::SetDamageRegionGpuTile({ 0, 0 });
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest008
 * @tc.desc: Test HandleVirtualExtendScreen with IsVirtualDirtyDfxEnabled true, takes else branch
 * @tc.type: FUNC
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest008, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->isVirtualDirtyDfxEnabled_ = true;
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    uniParam->isVirtualDirtyDfxEnabled_ = false;
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest009
 * @tc.desc: Test HandleVirtualExtendScreen with IsMultiSurfaceExtendMode true, takes else branch
 * @tc.type: FUNC
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest009, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    processor->needsOffscreenRender_ = true;
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    processor->needsOffscreenRender_ = false;
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest010
 * @tc.desc: Test HandleVirtualExtendScreen with all conditions satisfied, enters if branch
 * @tc.type: FUNC
 * @tc.require: #24870
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest010, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    screenParams_->childDisplayCount_ = 1;

    auto csurf = IConsumerSurface::Create("SetMultiSurfCfg_SF");
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    ASSERT_NE(rsSurface, nullptr);
    auto rasterFrame = std::make_unique<RSSurfaceFrameOhosRaster>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);

    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), std::move(rasterFrame));
    config.canvas = paintFilterCanvas_;
    config.region = RectI(0, 0, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    processor->surfaceFrames_.push_back(std::move(config));

    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->isVirtualDirtyDfxEnabled_ = false;
    processor->needsOffscreenRender_ = false;
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    processor->surfaceFrames_.clear();
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest011
 * @tc.desc: Test HandleVirtualExtendScreen with IsVirtualExpandScreenDirtyEnabled false, enters else branch
 * @tc.type: FUNC
 * @tc.require: #24870
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest011, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    screenParams_->childDisplayCount_ = 1;

    auto csurf = IConsumerSurface::Create("SetMultiSurfCfg_SF");
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    ASSERT_NE(rsSurface, nullptr);
    auto rasterFrame = std::make_unique<RSSurfaceFrameOhosRaster>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);

    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), std::move(rasterFrame));
    config.canvas = paintFilterCanvas_;
    config.region = RectI(0, 0, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    processor->surfaceFrames_.push_back(std::move(config));

    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    uniParam->SetVirtualExpandScreenDirtyEnabled(false);
    uniParam->isVirtualDirtyDfxEnabled_ = false;
    processor->needsOffscreenRender_ = false;
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    processor->surfaceFrames_.clear();
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest012
 * @tc.desc: Test HandleVirtualExtendScreen with IsVirtualExpandScreenDirtyEnabled true and
 *           IsVirtualDirtyDfxEnabled true, enters else branch
 * @tc.type: FUNC
 * @tc.require: #24870
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest012, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    screenParams_->childDisplayCount_ = 1;

    auto csurf = IConsumerSurface::Create("SetMultiSurfCfg_SF");
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    ASSERT_NE(rsSurface, nullptr);
    auto rasterFrame = std::make_unique<RSSurfaceFrameOhosRaster>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);

    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), std::move(rasterFrame));
    config.canvas = paintFilterCanvas_;
    config.region = RectI(0, 0, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    processor->surfaceFrames_.push_back(std::move(config));

    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->isVirtualDirtyDfxEnabled_ = true;
    processor->needsOffscreenRender_ = false;
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    uniParam->isVirtualDirtyDfxEnabled_ = false;
    processor->surfaceFrames_.clear();
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest013
 * @tc.desc: Test HandleVirtualExtendScreen with IsVirtualExpandScreenDirtyEnabled true,
 *           IsVirtualDirtyDfxEnabled false, and IsMultiSurfaceExtendMode true, enters else branch
 * @tc.type: FUNC
 * @tc.require: #24870
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest013, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PLAY));
    screenParams_->childDisplayCount_ = 1;

    auto csurf = IConsumerSurface::Create("SetMultiSurfCfg_SF");
    ASSERT_NE(csurf, nullptr);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(pSurface);
    ASSERT_NE(rsSurface, nullptr);
    auto rasterFrame = std::make_unique<RSSurfaceFrameOhosRaster>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);

    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), std::move(rasterFrame));
    config.canvas = paintFilterCanvas_;
    config.region = RectI(0, 0, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    processor->surfaceFrames_.push_back(std::move(config));
    processor->surfaceFrames_.push_back(SurfaceFrameConfig{});

    processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());

    uniParam->SetVirtualExpandScreenDirtyEnabled(true);
    uniParam->isVirtualDirtyDfxEnabled_ = false;
    processor->needsOffscreenRender_ = true;
    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor);
    processor->needsOffscreenRender_ = false;
    processor->surfaceFrames_.clear();
    EXPECT_NE(screenParams_, nullptr);
}

/**
 * @tc.name: HandleVirtualExtendScreenTest014
 * @tc.desc: Test HandleVirtualExtendScreen when renderEngine is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAXXXX
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest014, TestSize.Level1)
{
#ifdef RS_ENABLE_VK
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);

    std::shared_ptr<RSBaseRenderEngine> renderEngine = nullptr;
    int32_t tid = 0;

    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_, processor, renderEngine, tid);
#endif // RS_ENABLE_VK
}

/**
 * @tc.name: HandleVirtualExtendScreenTest015
 * @tc.desc: Test HandleVirtualExtendScreen when renderEngine is not nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAXXXX
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest015, TestSize.Level1)
{
#ifdef RS_ENABLE_VK
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);

    int32_t tid = -200;

    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_,
        processor, RSUniRenderThread::Instance().GetRenderEngine(), tid);
#endif // RS_ENABLE_VK
}

/**
 * @tc.name: HandleVirtualExtendScreenTest016
 * @tc.desc: Test HandleVirtualExtendScreen when renderEngine is not nullptr and tid is zero
 * @tc.type: FUNC
 * @tc.require: issueIAXXXX
 */
HWTEST_F(RSMultiScreenUtilTest, HandleVirtualExtendScreenTest016, TestSize.Level1)
{
#ifdef RS_ENABLE_VK
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);

    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    ASSERT_NE(processor, nullptr);

    int32_t tid = 0;

    RSMultiScreenUtil::HandleVirtualExtendScreen(*screenDrawable_, *screenParams_,
        processor, RSUniRenderThread::Instance().GetRenderEngine(), tid);
#endif // RS_ENABLE_VK
}

/**
 * @tc.name: DrawPhysicalMirrorDisplayTest001
 * @tc.desc: Test DrawPhysicalMirrorDisplay when curCanvas_ is nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorDisplayTest001, TestSize.Level1)
{
    // when default
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    // when mirrorSouceScreenParams is nullptr
    mirrorSourceScreenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    // when mirrorSourceScreenDrawable is nullptr
    mirrorSourceScreenDrawable_ = nullptr;
    mirrorSourceDisplayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    // when mirrorSourceDisplayParams is nullptr
    mirrorSourceDisplayDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    // when mirrorSourceDisplayDrawable is nullptr
    mirrorSourceDisplayDrawable_ = nullptr;
    displayParams_->mirrorSourceDrawable_.reset();
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    // when curScreenParams is nullptr
    screenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    // when curScreenDrawable is nullptr
    screenDrawable_ = nullptr;
    displayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    // when canvas is nullptr
    displayDrawable_->curCanvas_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    EXPECT_EQ(displayDrawable_->curCanvas_, nullptr);
}

/**
 * @tc.name: DrawPhysicalMirrorDisplayTest002
 * @tc.desc: Test DrawPhysicalMirrorDisplay when has protected layer
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorDisplayTest002, TestSize.Level1)
{
    RSSpecialLayerManager slManager;
    slManager.Set(SpecialLayerType::HAS_PROTECTED, true);
    mirrorSourceDisplayParams_->specialLayerManager_ = slManager;
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    auto uniParams = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(uniParams));
    RSMultiScreenUtil::DrawPhysicalMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    EXPECT_TRUE(mirrorSourceDisplayParams_->GetSpecialLayerMgr().Find(SpecialLayerType::HAS_PROTECTED));
}

/**
 * @tc.name: DrawPhysicalMirrorFromCacheTest001
 * @tc.desc: Test DrawPhysicalMirrorFromCache when drawable or params is nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorFromCacheTest001, TestSize.Level1)
{
    // when default
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    // when curScreenParams is nullptr
    screenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    // when curScreenDrawable is nullptr
    screenDrawable_ = nullptr;
    displayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    // when mirrorSourceScreenDrawable is nullptr
    mirrorSourceScreenDrawable_ = nullptr;
    mirrorSourceDisplayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    // when mirrorSourceDisplayParams is nullptr
    mirrorSourceDisplayDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    EXPECT_NE(displayDrawable_, nullptr);
}

/**
 * @tc.name: DrawPhysicalMirrorFromCacheTest002
 * @tc.desc: Test DrawPhysicalMirrorFromCache when cacheImage is not nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorFromCacheTest002, TestSize.Level1)
{
    mirrorSourceScreenDrawable_->cacheImgForCapture_ = std::make_shared<Drawing::Image>();

    // when rosen.cacheimage.mirror.enabled is 0
    system::SetParameter("rosen.cacheimage.mirror.enabled", "0");
    EXPECT_FALSE(RSSystemProperties::GetDrawMirrorCacheImageEnabled());
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    // restore to 1
    system::SetParameter("rosen.cacheimage.mirror.enabled", "1");
    EXPECT_TRUE(RSSystemProperties::GetDrawMirrorCacheImageEnabled());

    // when enableVisibleRect is false
    displayDrawable_->enableVisibleRect_ = false;
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    // when enableVisibleRect is true
    displayDrawable_->enableVisibleRect_ = true;
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    EXPECT_NE(mirrorSourceScreenDrawable_->GetCacheImgForCapture(), nullptr);
}

/**
 * @tc.name: DrawPhysicalMirrorFromCacheTest003
 * @tc.desc: Test DrawPhysicalMirrorFromCache when cacheImage is nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorFromCacheTest003, TestSize.Level1)
{
    // enableVisibleRect is false
    displayDrawable_->enableVisibleRect_ = false;
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    // enableVisibleRect is true
    displayDrawable_->enableVisibleRect_ = true;
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);
    EXPECT_EQ(mirrorSourceScreenDrawable_->GetCacheImgForCapture(), nullptr);
}

/**
 * @tc.name: DrawPhysicalMirrorFromCacheTest004
 * @tc.desc: Test DrawPhysicalMirrorFromCache when drawable.isMirrorSLRCopy_ && scaleManager
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorFromCacheTest004, TestSize.Level1)
{
    // when default，we set isMirrorSLRCopy_ to true and scaleManager valid
    displayDrawable_->isMirrorSLRCopy_ = true;
    displayDrawable_->scaleManager_ = std::make_shared<RSSLRScaleFunction>(1.0f, 1.0f, 1.0f, 1.0f);
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);

    // then set scaleManager to nullptr
    displayDrawable_->isMirrorSLRCopy_ = true;
    displayDrawable_->scaleManager_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);

    // then set isMirrorSLRCopy_ to false
    displayDrawable_->isMirrorSLRCopy_ = false;
    displayDrawable_->scaleManager_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorFromCache(*displayDrawable_, *displayParams_);

    // restore isMirrorSLRCopy_ to false
    displayDrawable_->isMirrorSLRCopy_ = false;
    displayDrawable_->scaleManager_ = nullptr;
    EXPECT_FALSE(displayDrawable_->isMirrorSLRCopy_);
}

/**
 * @tc.name: DrawPhysicalMirrorRebuildTest001
 * @tc.desc: Test DrawPhysicalMirrorRebuild when drawable or params is nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorRebuildTest001, TestSize.Level1)
{
    auto uniParams = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(uniParams));
    auto processor = std::make_shared<RSUniRenderProcessor>();
    RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;

    // when default, test once
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    // when mirrorSourceScreenParams is nullptr
    mirrorSourceScreenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    // when screenPrams is nullptr
    screenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    // when screenDrawable is nullptr
    screenDrawable_ = nullptr;
    displayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    // when mirrorSourceDisplayParams is nullptr
    mirrorSourceDisplayDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    // when uniParam is nullptr
    RSRenderThreadParamsManager::Instance().renderThreadParams_ = nullptr;
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    // restore uniParam
    RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
    EXPECT_NE(RSUniRenderThread::Instance().GetRSRenderThreadParams(), nullptr);
}

/**
 * @tc.name: DrawPhysicalMirrorRebuildTest002
 * @tc.desc: Test DrawPhysicalMirrorRebuild when IsExternalScreenSecure is true
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorRebuildTest002, TestSize.Level1)
{
    auto isExternalScreenSecure = MultiScreenParam::IsExternalScreenSecure();
    MultiScreenParam::SetExternalScreenSecure(true);
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(displayParams_->GetCompositeType(), 0);
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    EXPECT_TRUE(MultiScreenParam::IsExternalScreenSecure());
    MultiScreenParam::SetExternalScreenSecure(isExternalScreenSecure);
}

/**
 * @tc.name: DrawPhysicalMirrorRebuildTest003
 * @tc.desc: Test DrawPhysicalMirrorRebuild when IsExternalScreenSecure is false and hasSecSurface is true
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorRebuildTest003, TestSize.Level1)
{
    RSSpecialLayerManager slManager;
    slManager.Set(SpecialLayerType::HAS_SECURITY, true);
    mirrorSourceDisplayParams_->specialLayerManager_ = slManager;
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(displayParams_->GetCompositeType(), 0);
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    EXPECT_TRUE(mirrorSourceDisplayParams_->GetSpecialLayerMgr().Find(SpecialLayerType::HAS_SECURITY));
}

/**
 * @tc.name: DrawPhysicalMirrorRebuildTest004
 * @tc.desc: Test DrawPhysicalMirrorRebuild
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorRebuildTest004, TestSize.Level1)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(displayParams_->GetCompositeType(), 0);
    RSSpecialLayerManager slManager;
    slManager.Set(SpecialLayerType::HAS_SECURITY, true);
    mirrorSourceDisplayParams_->specialLayerManager_ = slManager;
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    EXPECT_NE(displayDrawable_, nullptr);
}

/**
 * @tc.name: DrawPhysicalMirrorRebuildTest005
 * @tc.desc: Test DrawPhysicalMirrorRebuild
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorRebuildTest005, TestSize.Level1)
{
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(displayParams_->GetCompositeType(), 0);
    RSSpecialLayerManager slManager;
    slManager.Set(SpecialLayerType::HAS_SECURITY, false);
    mirrorSourceDisplayParams_->specialLayerManager_ = slManager;
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    EXPECT_FALSE(mirrorSourceDisplayParams_->GetSpecialLayerMgr().Find(SpecialLayerType::HAS_SECURITY));
}

/**
 * @tc.name: DrawPhysicalMirrorRebuildTest006
 * @tc.desc: Test DrawPhysicalMirrorRebuild when hasSecSurface && IsExternalScreenSecure
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawPhysicalMirrorRebuildTest006, TestSize.Level1)
{
    auto isExternalScreenSecure = MultiScreenParam::IsExternalScreenSecure();

    // default, hasSecSurface is false and isExternalScreenSecure is false
    std::shared_ptr<RSComposerClientManager> rsComposerClientMgr = std::make_shared<RSComposerClientManager>();
    RSUniRenderThread::Instance().composerClientManager_ = rsComposerClientMgr;
    auto processor = RSProcessorFactory::CreateProcessor(displayParams_->GetCompositeType(), 0);
    MultiScreenParam::SetExternalScreenSecure(false);
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);

    // do something to make hasSecSurface is false and isExternalScreenSecure is true
    MultiScreenParam::SetExternalScreenSecure(true);
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);

    // do something to make hasSecSurface is true and isExternalScreenSecure is true
    RSSpecialLayerManager slManager;
    slManager.Set(SpecialLayerType::HAS_SECURITY, true);
    mirrorSourceDisplayParams_->specialLayerManager_ = slManager;
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);

    // do something to make hasSecSurface is true and isExternalScreenSecure is false
    MultiScreenParam::SetExternalScreenSecure(false);
    RSMultiScreenUtil::DrawPhysicalMirrorRebuild(*displayDrawable_, *displayParams_, processor);
    EXPECT_TRUE(mirrorSourceDisplayParams_->GetSpecialLayerMgr().Find(SpecialLayerType::HAS_SECURITY));

    // reset isExternalScreenSecure
    MultiScreenParam::SetExternalScreenSecure(isExternalScreenSecure);
    slManager.Set(SpecialLayerType::HAS_SECURITY, false);
    mirrorSourceDisplayParams_->specialLayerManager_ = slManager;
}

/**
 * @tc.name: DrawVirtualMirrorDisplayTest001
 * @tc.desc: Test DrawVirtualMirrorDisplay when drawable or params is nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorDisplayTest001, TestSize.Level1)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    processor->canvas_ = paintFilterCanvas_;
    auto uniParams = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(uniParams));

    // when processor is not RSUniRenderVirtualProcessor, it will be transformed to nullptr in the function
    auto otherProcessor = std::make_shared<RSUniRenderProcessor>();
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, otherProcessor);
    // when screenParams is nullptr
    screenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    // when mirrorSourceScreenParams is nullptr
    mirrorSourceScreenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    EXPECT_EQ(mirrorSourceScreenDrawable_->renderParams_, nullptr);
    // when mirrorSourceDisplayParams is nullptr
    mirrorSourceDisplayDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    EXPECT_EQ(mirrorSourceDisplayDrawable_->renderParams_, nullptr);
    // when mirrorSourceDisplayDrawable is nullptr
    mirrorSourceDisplayDrawable_ = nullptr;
    displayParams_->mirrorSourceDrawable_.reset();
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, nullptr);
    EXPECT_EQ(mirrorSourceDisplayDrawable_, nullptr);
}

/**
 * @tc.name: DrawVirtualMirrorDisplayTest002
 * @tc.desc: Test DrawVirtualMirrorDisplay when mirroredParams isSecurityDisplay != params isSecurityDisplay
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorDisplayTest002, TestSize.Level1)
{
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    processor->canvas_ = paintFilterCanvas_;
    auto uniParams = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(uniParams));

    // when default
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    EXPECT_FALSE(processor->GetDrawVirtualMirrorCopy());

    // when mirrorSourceDisplayParams isSecurityDisplay != displayParams isSecurityDisplay
    displayParams_->isSecurityDisplay_ = true;
    mirrorSourceDisplayParams_->isSecurityDisplay_ = false;
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    EXPECT_FALSE(processor->GetDrawVirtualMirrorCopy());

    // and then set specialLayerType HAS_SPECIAL_LAYER
    RSSpecialLayerManager slManager;
    slManager.Set(SpecialLayerType::HAS_SECURITY, true);
    mirrorSourceDisplayParams_->specialLayerManager_ = slManager;
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    EXPECT_FALSE(processor->GetDrawVirtualMirrorCopy());

    // when cacheImage is not nullptr
    mirrorSourceScreenDrawable_->cacheImgForCapture_ = std::make_shared<Drawing::Image>();
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    EXPECT_NE(mirrorSourceScreenDrawable_->cacheImgForCapture_, nullptr);

    // when GetVirtualScreenMuteStatus is true
    mirrorSourceScreenDrawable_->cacheImgForCapture_ = nullptr;
    displayParams_->virtualScreenMuteStatus_ = true;
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    EXPECT_FALSE(processor->GetDrawVirtualMirrorCopy());
}

/**
 * @tc.name: DrawVirtualMirrorDisplayTest003
 * @tc.desc: Test DrawVirtualMirrorDisplay when mirroredScreenIsPause is true
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorDisplayTest003, TestSize.Level1)
{
    VirtualScreenStatus status = mirrorSourceScreenParams_->screenProperty_.GetVirtualScreenStatus();
    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(VIRTUAL_SCREEN_PAUSE);
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    // recover virtualScreenStatus
    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(status);
    EXPECT_FALSE(virtualProcessor_->GetDrawVirtualMirrorCopy());
}

/**
 * @tc.name: DrawVirtualMirrorDisplayTest004
 * @tc.desc: Test DrawVirtualMirrorDisplay when mirroredParams SetHDRPresent
 * @tc.type: FUNC
 * @tc.require: issue21104
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorDisplayTest004, TestSize.Level1)
{
    mirrorSourceScreenParams_->SetHDRPresent(false);
    auto uniParams = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(uniParams));
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    EXPECT_FALSE(virtualProcessor_->GetDrawVirtualMirrorCopy());

    auto screenParams = static_cast<RSScreenRenderParams*>(screenDrawable_->GetRenderParams().get());
    mirrorSourceScreenParams_->SetHDRPresent(true);
    screenParams->SetHDRPresent(true);
    RSMultiScreenUtil::DrawVirtualMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    EXPECT_FALSE(virtualProcessor_->GetDrawVirtualMirrorCopy());
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest001
 * @tc.desc: Test DrawVirtualMirrorFromCache when drawable or params is nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest001, TestSize.Level1)
{
    RSRenderThreadParams uniParam;

    // when the canvas of processor is nullptr
    virtualProcessor_->canvas_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when mirrorSourceScreenParams is nullptr
    mirrorSourceScreenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when mirrorSourceScreenDrawable is nullptr
    mirrorSourceScreenDrawable_ = nullptr;
    mirrorSourceDisplayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when mirrorSourceDisplayParams is nullptr
    mirrorSourceDisplayDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when mirrorSourceDisplayDrawable is nullptr
    mirrorSourceDisplayDrawable_ = nullptr;
    displayParams_->mirrorSourceDrawable_.reset();
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when screenPrams is nullptr
    screenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when screenDrawable is nullptr
    screenDrawable_ = nullptr;
    displayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_EQ(screenDrawable_, nullptr);
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest002
 * @tc.desc: Test DrawVirtualMirrorFromCache
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest002, TestSize.Level1)
{
    RSRenderThreadParams uniParam;

    // when default, isVirtualDirtyEnabled_ is false
    uniParam.isVirtualDirtyEnabled_ = false;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_FALSE(uniParam.IsVirtualDirtyEnabled());

    // when isVirtualDirtyEnabled_ is true
    uniParam.isVirtualDirtyEnabled_ = true;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_TRUE(uniParam.IsVirtualDirtyEnabled());

    // restore isVirtualDirtyEnabled_ to false
    uniParam.isVirtualDirtyEnabled_ = false;

    // when slrManager is nullptr
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when slrManager is not nullptr
    virtualProcessor_->slrManager_ = std::make_shared<RSSLRScaleFunction>(1.0f, 1.0f, 1.0f, 1.0f);
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_NE(displayDrawable_, nullptr);
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest003
 * @tc.desc: Test DrawVirtualMirrorFromCache when enableVisibleRect_ is true
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest003, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    displayDrawable_->enableVisibleRect_ = true;
    // when GetTop > 0
    displayDrawable_->curVisibleRect_ = { 1, 1, 1, 1 };
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when GetTop > 0
    displayDrawable_->curVisibleRect_ = { 0, 0, 0, 0 };
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_NE(displayDrawable_, nullptr);
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest004
 * @tc.desc: Test DrawVirtualMirrorFromCache when cacheImg is not nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest004, TestSize.Level1)
{
    RSRenderThreadParams uniParam;

    // when cacheImg is not nullptr
    mirrorSourceScreenDrawable_->cacheImgForCapture_ = std::make_shared<Drawing::Image>();
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // enableVisibleRect_ is false
    displayDrawable_->enableVisibleRect_ = false;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_FALSE(displayDrawable_->enableVisibleRect_);
    // enableVisibleRect_ is true
    displayDrawable_->enableVisibleRect_ = true;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_TRUE(displayDrawable_->enableVisibleRect_);
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest005
 * @tc.desc: Test DrawVirtualMirrorFromCache when isSamplingOn is true/false
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest005, TestSize.Level1)
{
    RSRenderThreadParams uniParam;

    // when isSamplingOn is false
    ScreenInfo screenInfo;
    screenInfo.isSamplingOn = false;
    mirrorSourceScreenParams_->screenInfo_ = screenInfo;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_FALSE(mirrorSourceScreenParams_->GetScreenInfo().isSamplingOn);
    // when isSamplingOn is true
    screenInfo.isSamplingOn = true;
    mirrorSourceScreenParams_->screenInfo_ = screenInfo;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_TRUE(mirrorSourceScreenParams_->GetScreenInfo().isSamplingOn);
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest006
 * @tc.desc: Test DrawVirtualMirrorFromCache when curVisibleRect_.top/left is not zero
 * @tc.type: FUNC
 * @tc.require: #20348
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest006, TestSize.Level1)
{
    RSRenderThreadParams uniParam;

    uniParam.isVirtualDirtyEnabled_ = true;
    displayDrawable_->enableVisibleRect_ = true;
    displayDrawable_->curVisibleRect_ = { 0, 0, 1, 1 };
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    displayDrawable_->curVisibleRect_ = { 1, 0, 1, 1 };
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    displayDrawable_->curVisibleRect_ = { 0, 1, 1, 1 };
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    displayDrawable_->enableVisibleRect_ = false;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    uniParam.isVirtualDirtyEnabled_ = false;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_NE(displayDrawable_, nullptr);
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest007
 * @tc.desc: Test DrawVirtualMirrorFromCache with ProcessSingleSelfDrawingNode
 * @tc.type: FUNC
 * @tc.require: issue22872
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest007, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    uniParam.isVirtualDirtyEnabled_ = false;

    // when ProcessSingleSelfDrawingNode is false
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "0");
    EXPECT_FALSE(RSSystemProperties::GetVirtualSelfDrawOptEnabled());
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // restore
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "1");
    EXPECT_TRUE(RSSystemProperties::GetVirtualSelfDrawOptEnabled());
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest008
 * @tc.desc: Test DrawVirtualMirrorFromCache when mirrorSourceScreen sampling on
 * @tc.type: FUNC
 * @tc.require: issue22872
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest008, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    virtualProcessor_->SetDisplaySkipInMirror(false);
    mirrorSourceScreenParams_->layerSkipContext_.screenLayerInvalid_ = false;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    mirrorSourceScreenParams_->screenInfo_.isSamplingOn = true;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_TRUE(mirrorSourceScreenParams_->screenInfo_.isSamplingOn);
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest009
 * @tc.desc: Test DrawVirtualMirrorFromCache when cacheImage && RSSystemProperties::GetDrawMirrorCacheImageEnabled()
 * @tc.type: FUNC
 * @tc.require: issue22872
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest009, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    uniParam.isVirtualDirtyEnabled_ = false;

    // ensure ProcessSingleSelfDrawingNode is false
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "0");
    EXPECT_FALSE(RSSystemProperties::GetVirtualSelfDrawOptEnabled());

    // when cacheImage is nullptr
    mirrorSourceScreenDrawable_->cacheImgForCapture_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // when cacheImage is not nullptr, but GetDrawMirrorCacheImageEnabled is false
    mirrorSourceScreenDrawable_->cacheImgForCapture_ = std::make_shared<Drawing::Image>();
    system::SetParameter("rosen.cacheimage.mirror.enabled", "0");
    EXPECT_FALSE(RSSystemProperties::GetDrawMirrorCacheImageEnabled());
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // when cacheImage is not nullptr and GetDrawMirrorCacheImageEnabled is true
    mirrorSourceScreenDrawable_->cacheImgForCapture_ = std::make_shared<Drawing::Image>();
    EXPECT_NE(mirrorSourceScreenDrawable_->cacheImgForCapture_, nullptr);
    system::SetParameter("rosen.cacheimage.mirror.enabled", "1");
    EXPECT_TRUE(RSSystemProperties::GetDrawMirrorCacheImageEnabled());
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // restore
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "1");
    EXPECT_TRUE(RSSystemProperties::GetVirtualSelfDrawOptEnabled());
    system::SetParameter("rosen.cacheimage.mirror.enabled", "1");
    EXPECT_TRUE(RSSystemProperties::GetDrawMirrorCacheImageEnabled());
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest010
 * @tc.desc: Test DrawVirtualMirrorFromCache when mirroredScreenProperty samplingMode is DEVICE_GPU or not
 * @tc.type: FUNC
 * @tc.require: issue no.
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest010, TestSize.Level0)
{
    RSRenderThreadParams uniParam;
    uniParam.isVirtualDirtyEnabled_ = false;

    // Set physical and render resolutions for mirrorSourceScreenParams so rog ratios are non-trivial
    // samplingMode is DEVICE_DSS, GetRogWidthRatio and GetRogHeightRatio is or not 0
    // Branch 1: SamplingMode is not DEVICE_GPU (default OFFSCREEN), the if-branch is false
    EXPECT_NE(mirrorSourceScreenParams_->screenProperty_.GetSamplingMode(), ScreenSamplingMode::DEVICE_GPU);
    constexpr int32_t PHY_WIDTH = 200;
    constexpr int32_t PHY_HEIGHT = 400;
    constexpr int32_t RENDER_WIDTH = 100;
    constexpr int32_t RENDER_HEIGHT = 200;
    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::RENDER_RESOLUTION>(
        {RENDER_WIDTH, RENDER_HEIGHT});
    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {0, 0, 60});
    EXPECT_NO_FATAL_FAILURE(
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam));

    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {0, PHY_HEIGHT, 60});
    EXPECT_NO_FATAL_FAILURE(
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam));

    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {PHY_WIDTH, 0, 60});
    EXPECT_NO_FATAL_FAILURE(
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam));

    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {PHY_WIDTH, PHY_HEIGHT, 60});
    EXPECT_NO_FATAL_FAILURE(
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam));

    // Branch 2: SamplingMode is DEVICE_GPU, the if-branch is true
    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::SAMPLING_MODE>(
        static_cast<uint32_t>(ScreenSamplingMode::DEVICE_GPU));
    EXPECT_EQ(mirrorSourceScreenParams_->screenProperty_.GetSamplingMode(), ScreenSamplingMode::DEVICE_GPU);
    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {0, 0, 60});
    EXPECT_NO_FATAL_FAILURE(
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam));

    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {0, PHY_HEIGHT, 60});
    EXPECT_NO_FATAL_FAILURE(
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam));

    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {PHY_WIDTH, 0, 60});
    EXPECT_NO_FATAL_FAILURE(
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam));

    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::PHYSICAL_RESOLUTION_REFRESHRATE>(
        {PHY_WIDTH, PHY_HEIGHT, 60});
    EXPECT_NE(mirrorSourceScreenParams_->screenProperty_.GetRogWidthRatio(), 1.0f);
    EXPECT_NE(mirrorSourceScreenParams_->screenProperty_.GetRogHeightRatio(), 1.0f);
    EXPECT_NO_FATAL_FAILURE(
        RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam));
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest020
 * @tc.desc: Test DrawVirtualMirrorFromCache skips ProcessSingleSelfDrawingNode when slrManager is active
 * @tc.type: FUNC
 * @tc.require: issue 32701
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest020, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    uniParam.isVirtualDirtyEnabled_ = false;

    // enable ProcessSingleSelfDrawingNode optimization
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "1");
    EXPECT_TRUE(RSSystemProperties::GetVirtualSelfDrawOptEnabled());

    // set slrManager so hasMirrorScale is true, optimization is skipped and normal path runs
    virtualProcessor_->slrManager_ = std::make_shared<RSSLRScaleFunction>(1.0f, 1.0f, 1.0f, 1.0f);
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_NE(displayDrawable_, nullptr);

    // restore
    virtualProcessor_->slrManager_ = nullptr;
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "1");
}

/**
 * @tc.name: DrawVirtualMirrorFromCacheTest021
 * @tc.desc: Test DrawVirtualMirrorFromCache skips ProcessSingleSelfDrawingNode when isSamplingOn is active
 * @tc.type: FUNC
 * @tc.require: issue 32701
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorFromCacheTest021, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    uniParam.isVirtualDirtyEnabled_ = false;

    // enable ProcessSingleSelfDrawingNode optimization
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "1");
    EXPECT_TRUE(RSSystemProperties::GetVirtualSelfDrawOptEnabled());

    // set isSamplingOn so hasMirrorScale is true, optimization is skipped and normal path runs
    ScreenInfo screenInfo;
    screenInfo.isSamplingOn = true;
    mirrorSourceScreenParams_->screenInfo_ = screenInfo;
    RSMultiScreenUtil::DrawVirtualMirrorFromCache(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_TRUE(mirrorSourceScreenParams_->GetScreenInfo().isSamplingOn);

    // restore
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "1");
}

/**
 * @tc.name: DrawVirtualMirrorRebuildTest001
 * @tc.desc: Test DrawVirtualMirrorRebuild when drawable or params is nullptr
 * @tc.type: FUNC
 * @tc.require: issueICCRA8
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorRebuildTest001, TestSize.Level1)
{
    RSRenderThreadParams uniParam;

    // when the canvas of processor is nullptr
    virtualProcessor_->canvas_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when mirrorSouceScreenParams is nullptr
    mirrorSourceScreenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when mirrorSourceDisplayParams is nullptr
    mirrorSourceDisplayDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when mirrorSourceDisplayDrawable is nullptr
    mirrorSourceDisplayDrawable_ = nullptr;
    displayParams_->mirrorSourceDrawable_.reset();
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when curScreenParams is nullptr
    screenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // when curScreenDrawable is nullptr
    screenDrawable_ = nullptr;
    displayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    EXPECT_EQ(screenDrawable_, nullptr);
}

/**
 * @tc.name: DrawVirtualMirrorRebuildTest002
 * @tc.desc: Test DrawVirtualMirrorRebuild when has security layer
 * @tc.type: FUNC
 * @tc.require: issueICCRA8
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorRebuildTest002, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    RSSpecialLayerManager slManager;
    slManager.specialLayerType_ = SpecialLayerType::HAS_SECURITY;
    mirrorSourceDisplayParams_->specialLayerManager_ = slManager;
    bool hasSecurity = mirrorSourceDisplayParams_->GetSpecialLayerMgr().Find(SpecialLayerType::HAS_SECURITY);
    EXPECT_EQ(hasSecurity, true);
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // when it is enableVisibleRect
    displayDrawable_->enableVisibleRect_ = true;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
}

/**
 * @tc.name: DrawVirtualMirrorRebuildTest003
 * @tc.desc: Test DrawVirtualMirrorRebuild when uniParam.IsVirtualDirtyEnabled() && !enableVisibleRect
 * @tc.type: FUNC
 * @tc.require: issue22872
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorRebuildTest003, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    EXPECT_FALSE(displayParams_->GetVirtualScreenMuteStatus());

    // when uniParam.IsVirtualDirtyEnabled() == false
    uniParam.SetVirtualDirtyEnabled(false);
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // when uniParam.IsVirtualDirtyEnabled() == true, but !enableVisibleRect_ == false
    uniParam.SetVirtualDirtyEnabled(true);
    displayDrawable_->enableVisibleRect_ = true;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // set uniParam.IsVirtualDirtyEnabled() == true, and !enableVisibleRect_ is true
    uniParam.SetVirtualDirtyEnabled(true);
    displayDrawable_->enableVisibleRect_ = false;
    // After set, when processer->GetDisplaySkipInMirror() == true
    virtualProcessor_->displaySkipInMirror_ = true;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
    // After set, when processer->GetDisplaySkipInMirror() == false
    virtualProcessor_->displaySkipInMirror_ = false;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
}

/**
 * @tc.name: DrawVirtualMirrorRebuildTest004
 * @tc.desc: Test DrawVirtualMirrorRebuild with ProcessSingleSelfDrawingNode
 * @tc.type: FUNC
 * @tc.require: issue22872
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorRebuildTest004, TestSize.Level1)
{
    RSRenderThreadParams uniParam;
    uniParam.SetVirtualDirtyEnabled(false);

    // when ProcessSingleSelfDrawingNode is false
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "0");
    EXPECT_FALSE(RSSystemProperties::GetVirtualSelfDrawOptEnabled());
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // then, when mirrorSourceDisplayDrawable->ShouldPaint() == true
    mirrorSourceDisplayParams_->shouldPaint_ = true;
    mirrorSourceDisplayParams_->contentEmpty_ = false;
    EXPECT_TRUE(mirrorSourceDisplayDrawable_->ShouldPaint());
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // then, when mirrorSourceDisplayDrawable->ShouldPaint() == false
    mirrorSourceDisplayParams_->shouldPaint_ = false;
    mirrorSourceDisplayParams_->contentEmpty_ = true;
    EXPECT_FALSE(mirrorSourceDisplayDrawable_->ShouldPaint());
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

    // restore
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "1");
    EXPECT_TRUE(RSSystemProperties::GetVirtualSelfDrawOptEnabled());
}

/**
 * @tc.name: DrawVirtualExtendTest001
 * @tc.desc: Test DrawVirtualExtend when drawable or params is nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualExtendTest001, TestSize.Level1)
{
    // when processor is nullptr
    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, nullptr);

    // when screenParams is nullptr
    displayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, nullptr);
    EXPECT_TRUE(displayParams_->GetAncestorScreenDrawable().expired());
}

/**
 * @tc.name: DrawVirtualExtendTest002
 * @tc.desc: Test DrawVirtualExtend when processor->IsMultiSurfaceExtendMode() and screenParam->GetHDRPresent()
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualExtendTest002, TestSize.Level1)
{
    EXPECT_NE(virtualProcessor_, nullptr);

    // when processor->IsMultiSurfaceExtendMode() == true, and screenParam->GetHDRPresent() == true
    virtualProcessor_->needsOffscreenRender_ = true;
    screenParams_->hasHdrPresent_ = true;
    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, virtualProcessor_);

    // when processor->IsMultiSurfaceExtendMode() == true, and screenParam->GetHDRPresent() == false
    virtualProcessor_->needsOffscreenRender_ = true;
    screenParams_->hasHdrPresent_ = false;
    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, virtualProcessor_);

    // when processor->IsMultiSurfaceExtendMode() == false, and screenParam->GetHDRPresent() == true
    virtualProcessor_->needsOffscreenRender_ = false;
    screenParams_->hasHdrPresent_ = true;
    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, virtualProcessor_);

    // when processor->IsMultiSurfaceExtendMode() == false, and screenParam->GetHDRPresent() == false
    virtualProcessor_->needsOffscreenRender_ = false;
    screenParams_->hasHdrPresent_ = false;
    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, virtualProcessor_);
}

/**
 * @tc.name: DrawVirtualExtendTest003
 * @tc.desc: Test DrawVirtualExtend when offscreenImage is nullptr or not nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualExtendTest003, TestSize.Level1)
{
    // At first, set processor->IsMultiSurfaceExtendMode() == true
    virtualProcessor_->needsOffscreenRender_ = true;
    EXPECT_TRUE(virtualProcessor_->IsMultiSurfaceExtendMode());

    // Then set offscreenImage as nullptr
    displayDrawable_->offscreenSurface_ = nullptr;
    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, virtualProcessor_);

    // we hope offscreenImage finally got is not nullptr
    displayDrawable_->offscreenSurface_ = std::make_shared<Drawing::Surface>();
    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, virtualProcessor_);
}

/**
 * @tc.name: DrawVirtualExtendTest004
 * @tc.desc: Test DrawVirtualExtend releases temporary offscreen state in multi-surface mode
 * @tc.type: FUNC
 * @tc.require: #26773
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualExtendTest004, TestSize.Level1)
{
    auto surface = Drawing::Surface::MakeRasterN32Premul(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
    ASSERT_NE(surface, nullptr);
    ASSERT_NE(surface->MakeSurface(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE), nullptr);
    auto originalCanvas = std::make_shared<RSPaintFilterCanvas>(surface.get());
    displayDrawable_->curCanvas_ = originalCanvas.get();
    displayParams_->frameRect_ = { 0.f, 0.f, DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE };
    virtualProcessor_->needsOffscreenRender_ = true;

    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, virtualProcessor_);

    EXPECT_EQ(displayDrawable_->curCanvas_, originalCanvas.get());
    EXPECT_EQ(displayDrawable_->canvasBackup_, nullptr);
    EXPECT_EQ(displayDrawable_->offscreenCanvas_, nullptr);
    EXPECT_EQ(displayDrawable_->offscreenSurface_, nullptr);
}

/**
 * @tc.name: DrawVirtualExtendTest005
 * @tc.desc: Test DrawVirtualExtend preserves the original canvas when offscreen preparation fails
 * @tc.type: FUNC
 * @tc.require: #26773
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualExtendTest005, TestSize.Level1)
{
    auto originalCanvas = displayDrawable_->curCanvas_;
    displayParams_->frameRect_ = { 0.f, 0.f, DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE };
    displayDrawable_->offscreenCanvas_ = std::make_shared<RSPaintFilterCanvas>(canvas_.get());
    displayDrawable_->offscreenSurface_ = std::make_shared<Drawing::Surface>();
    virtualProcessor_->needsOffscreenRender_ = true;
    ASSERT_EQ(displayDrawable_->curCanvas_->GetSurface(), nullptr);

    RSMultiScreenUtil::DrawVirtualExtend(*displayDrawable_, *displayParams_, virtualProcessor_);

    EXPECT_EQ(displayDrawable_->curCanvas_, originalCanvas);
    EXPECT_EQ(displayDrawable_->canvasBackup_, nullptr);
    EXPECT_EQ(displayDrawable_->offscreenCanvas_, nullptr);
    EXPECT_EQ(displayDrawable_->offscreenSurface_, nullptr);
}

/**
 * @tc.name: DumpRenderStrategyTest001
 * @tc.desc: Test DumpRenderStrategy
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, DumpRenderStrategyTest001, TestSize.Level1)
{
    displayDrawable_->lastFrameRenderStrategy_ = RenderStrategy::INVALID;
    RSMultiScreenUtil::DumpRenderStrategy(*displayDrawable_, INVALID_SCREEN_ID, RenderStrategy::INVALID, "");
    RSMultiScreenUtil::DumpRenderStrategy(
        *displayDrawable_, INVALID_SCREEN_ID, RenderStrategy::DRAW_VIRTUAL_MIRROR_FROM_CACHE, "");
    EXPECT_EQ(displayDrawable_->lastFrameRenderStrategy_, RenderStrategy::DRAW_VIRTUAL_MIRROR_FROM_CACHE);
}

/**
 * @tc.name: GetMultiScreenParamsTest001
 * @tc.desc: Test GetMultiScreenParams when drawable or params is nullptr
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSMultiScreenUtilTest, GetMultiScreenParamsTest001, TestSize.Level1)
{
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(mirrorSourceDisplayParams_, nullptr);
    // when default, all params is valid
    RSMultiScreenUtil::GetMultiScreenParams(*displayParams_);
    // when mirrorSourceScreenParams is nullptr
    mirrorSourceScreenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::GetMultiScreenParams(*displayParams_);
    // when mirrorSourceScreenDrawable is nullptr
    mirrorSourceScreenDrawable_ = nullptr;
    mirrorSourceDisplayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::GetMultiScreenParams(*displayParams_);
    // when mirrorSourceDisplayParams is nullptr
    mirrorSourceDisplayDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::GetMultiScreenParams(*displayParams_);
    // when mirrorSourceDisplayDrawable is nullptr
    mirrorSourceDisplayDrawable_ = nullptr;
    displayParams_->mirrorSourceDrawable_.reset();
    RSMultiScreenUtil::GetMultiScreenParams(*displayParams_);
    // when screenParams is nullptr
    screenDrawable_->renderParams_ = nullptr;
    RSMultiScreenUtil::GetMultiScreenParams(*displayParams_);
    // when screenDrawable nodeType is not SCREEN_NODE
    screenDrawable_->nodeType_ = RSRenderNodeType::UNKNOW;
    RSMultiScreenUtil::GetMultiScreenParams(*displayParams_);
    // when screenDrawable is nullptr
    screenDrawable_ = nullptr;
    displayParams_->SetAncestorScreenDrawable(nullptr);
    RSMultiScreenUtil::GetMultiScreenParams(*displayParams_);
    EXPECT_EQ(screenDrawable_, nullptr);
}

/**
 * @tc.name: ComputeGravityRectInvalidSizeTest
 * @tc.desc: Invalid canvas or content sizes return an empty rect so callers skip clip/scale
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, ComputeGravityRectInvalidSizeTest, TestSize.Level1)
{
    auto expectEmptyRect = [](const Drawing::RectI& rect) {
        EXPECT_EQ(rect.GetLeft(), 0);
        EXPECT_EQ(rect.GetTop(), 0);
        EXPECT_EQ(rect.GetRight(), 0);
        EXPECT_EQ(rect.GetBottom(), 0);
    };

    // content size is the divisor: zero and negative values must not reach the float scale path
    expectEmptyRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 0, 300, WindowRecordFit::ASPECT_FIT));
    expectEmptyRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 300, 0, WindowRecordFit::ASPECT_FIT));
    expectEmptyRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, -1, 300, WindowRecordFit::ASPECT_FIT));
    expectEmptyRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 300, -1, WindowRecordFit::ASPECT_FIT_TOP_LEFT));

    // canvas size is guarded here so every caller can rely on the returned rect
    expectEmptyRect(RSMultiScreenUtil::ComputeGravityRect(0, 600, 300, 300, WindowRecordFit::ASPECT_FIT));
    expectEmptyRect(RSMultiScreenUtil::ComputeGravityRect(800, 0, 300, 300, WindowRecordFit::ASPECT_FIT));
    expectEmptyRect(RSMultiScreenUtil::ComputeGravityRect(-800, 600, 300, 300, WindowRecordFit::ASPECT_FIT));
    expectEmptyRect(RSMultiScreenUtil::ComputeGravityRect(800, -600, 300, 300, WindowRecordFit::ASPECT_FIT));
}

/**
 * @tc.name: ComputeGravityRectAspectFitTest
 * @tc.desc: Aspect-fit centers the scaled content, horizontally and vertically
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, ComputeGravityRectAspectFitTest, TestSize.Level1)
{
    auto expectRect = [](const Drawing::RectI& rect, int32_t left, int32_t top, int32_t right, int32_t bottom) {
        EXPECT_EQ(rect.GetLeft(), left);
        EXPECT_EQ(rect.GetTop(), top);
        EXPECT_EQ(rect.GetRight(), right);
        EXPECT_EQ(rect.GetBottom(), bottom);
    };

    // canvas 800x600, content 500x1000: scale 0.6 -> 300x600, centered horizontally
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT),
        250, 0, 550, 600);
    // aspect fit ignores rotation
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT,
        ScreenRotation::ROTATION_270), 250, 0, 550, 600);

    // canvas 800x600, content 1000x500: scale 0.8 -> 800x400, centered vertically
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 1000, 500, WindowRecordFit::ASPECT_FIT),
        0, 100, 800, 500);
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 1000, 500, WindowRecordFit::ASPECT_FIT,
        ScreenRotation::ROTATION_90), 0, 100, 800, 500);
}

/**
 * @tc.name: ComputeGravityRectTopLeftTest
 * @tc.desc: Top-left placement maps canvas (0,0) to a different buffer corner per rotation
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, ComputeGravityRectTopLeftTest, TestSize.Level1)
{
    auto expectRect = [](const Drawing::RectI& rect, int32_t left, int32_t top, int32_t right, int32_t bottom) {
        EXPECT_EQ(rect.GetLeft(), left);
        EXPECT_EQ(rect.GetTop(), top);
        EXPECT_EQ(rect.GetRight(), right);
        EXPECT_EQ(rect.GetBottom(), bottom);
    };

    // canvas 800x600, content 500x1000: scaled size 300x600
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT),
        0, 0, 300, 600);
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_90), 0, 0, 300, 600);
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_180), 500, 0, 800, 600);
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_270), 500, 0, 800, 600);

    // canvas 800x600, content 1000x500: scaled size 800x400
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 1000, 500, WindowRecordFit::ASPECT_FIT_TOP_LEFT),
        0, 0, 800, 400);
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 1000, 500, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_90), 0, 200, 800, 600);
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 1000, 500, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_180), 0, 200, 800, 600);
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 1000, 500, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_270), 0, 0, 800, 400);
}

/**
 * @tc.name: ComputeGravityRectInvalidRotationTest
 * @tc.desc: An unknown rotation falls back to the unrotated top-left placement
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, ComputeGravityRectInvalidRotationTest, TestSize.Level1)
{
    auto expectRect = [](const Drawing::RectI& rect, int32_t left, int32_t top, int32_t right, int32_t bottom) {
        EXPECT_EQ(rect.GetLeft(), left);
        EXPECT_EQ(rect.GetTop(), top);
        EXPECT_EQ(rect.GetRight(), right);
        EXPECT_EQ(rect.GetBottom(), bottom);
    };

    // canvas 800x600, content 500x1000: scaled size 300x600
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::INVALID_SCREEN_ROTATION), 0, 0, 300, 600);
    // default rotation argument behaves like ROTATION_0
    expectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT),
        0, 0, 300, 600);
}

/**
 * @tc.name: HandleWindowRecordScreenGatesTest001
 * @tc.desc: Screen-level session gates skip before a buffer request only for their own condition
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenGatesTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(screenNode_, nullptr);
    ASSERT_EQ(screenParams_->logicalDisplayNodeDrawables_.size(), 1u);
    auto sourceDrawable = displayNode_->GetRenderDrawable();
    auto bboxDrawable = mirrorSourceDisplayNode_->GetRenderDrawable();
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(sourceDrawable->GetRenderParams(), nullptr);
    ASSERT_NE(bboxDrawable, nullptr);
    ASSERT_NE(bboxDrawable->GetRenderParams(), nullptr);
    const bool prevShouldPaint = sourceDrawable->GetRenderParams()->GetShouldPaint();
    const RectI prevBBoxRect = bboxDrawable->GetRenderParams()->GetAbsDrawRect();

    // Record ids without the virtual-screen flag are not an active session; the source is cleared too.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    displayParams_->SetOnVirtualScreen(false);
    displayParams_->recordSourceDisplayDrawable_.reset();
    EXPECT_FALSE(displayParams_->IsRecordSessionActive());
    ASSERT_FALSE(displayParams_->GetRecordWhiteListIds().empty());
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // No display drawable at all: no record-active display, so no buffer is requested.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    screenParams_->logicalDisplayNodeDrawables_.clear();
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Null and wrong-type entries are ignored before any downcast.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    screenParams_->logicalDisplayNodeDrawables_ = { nullptr, screenNode_->GetRenderDrawable() };
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Active session and a populated whitelist, but no resolved source display: SKIP_FRAME.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    displayParams_->recordSourceDisplayDrawable_.reset();
    ASSERT_TRUE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    ASSERT_FALSE(displayParams_->GetRecordWhiteListIds().empty());
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    sourceDrawable->GetRenderParams()->SetShouldPaint(prevShouldPaint);
    bboxDrawable->GetRenderParams()->SetAbsDrawRect(prevBBoxRect);
}

/**
 * @tc.name: HandleWindowRecordScreenSnapshotGatesTest001
 * @tc.desc: Screen-level snapshot gates skip before a buffer request only for their own condition
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenSnapshotGatesTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    auto sourceDrawable = displayNode_->GetRenderDrawable();
    auto bboxDrawable = mirrorSourceDisplayNode_->GetRenderDrawable();
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(sourceDrawable->GetRenderParams(), nullptr);
    ASSERT_NE(bboxDrawable, nullptr);
    ASSERT_NE(bboxDrawable->GetRenderParams(), nullptr);
    const bool prevShouldPaint = sourceDrawable->GetRenderParams()->GetShouldPaint();
    const RectI prevBBoxRect = bboxDrawable->GetRenderParams()->GetAbsDrawRect();

    // A source display that should not be painted skips before the processor gate.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    sourceDrawable->GetRenderParams()->SetShouldPaint(false);
    EXPECT_FALSE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // A non-paintable configured surface skips before the processor gate.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    displayParams_->hasPaintableRecordSurface_ = false;
    EXPECT_FALSE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    EXPECT_TRUE(sourceDrawable->GetRenderParams()->GetShouldPaint());
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Live source snapshot with an empty whitelist: SKIP_FRAME.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    displayParams_->recordWhiteListIds_.clear();
    ASSERT_FALSE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    ASSERT_TRUE(displayParams_->GetRecordWhiteListIds().empty());
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Every loop gate satisfied: execution reaches the processor gate.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);

    sourceDrawable->GetRenderParams()->SetShouldPaint(prevShouldPaint);
    bboxDrawable->GetRenderParams()->SetAbsDrawRect(prevBBoxRect);
}

/**
 * @tc.name: HandleWindowRecordScreenGeometryGatesTest001
 * @tc.desc: Screen-level record gate rejects missing or empty record-window geometry before the processor
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenGeometryGatesTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(mirrorSourceDisplayNode_, nullptr);

    auto sourceDrawable = displayNode_->GetRenderDrawable();
    auto bboxDrawable = mirrorSourceDisplayNode_->GetRenderDrawable();
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(sourceDrawable->GetRenderParams(), nullptr);
    ASSERT_NE(bboxDrawable, nullptr);
    ASSERT_NE(bboxDrawable->GetRenderParams(), nullptr);
    auto& bboxParams = *bboxDrawable->GetRenderParams();
    const bool prevShouldPaint = sourceDrawable->GetRenderParams()->GetShouldPaint();
    const RectI prevBBoxRect = bboxParams.GetAbsDrawRect();

    // A paintable surface snapshot without any main-window drawable yields no bbox.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    displayParams_->recordSurfaceDrawables_.clear();
    ASSERT_TRUE(displayParams_->HasPaintableRecordSurface());
    ASSERT_FALSE(displayParams_->GetRecordWhiteListIds().empty());
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // A zero-area main window yields a degenerate bbox and no output buffer.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    bboxParams.SetAbsDrawRect({ 0, 0, 0, 0 });
    ASSERT_TRUE(bboxParams.GetAbsDrawRect().IsEmpty());
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Valid geometry reaches the processor gate and is shared with the display pass.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    ASSERT_FALSE(bboxParams.GetAbsDrawRect().IsEmpty());
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI(0, 0, 100, 100));

    // A later invalid frame clears the cached bbox instead of reusing it.
    ArmWindowRecordScreenGates(*displayParams_, displayNode_->GetRenderDrawable(), sourceDrawable, bboxDrawable);
    bboxParams.SetAbsDrawRect({ 0, 0, 0, 0 });
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI());

    sourceDrawable->GetRenderParams()->SetShouldPaint(prevShouldPaint);
    bboxParams.SetAbsDrawRect(prevBBoxRect);
}

/**
 * @tc.name: HandleWindowRecordGatesTest001
 * @tc.desc: Display-level record early returns keep canvas, capture param and filter lists untouched
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordGatesTest001, TestSize.Level1)
{
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(screenNode_, nullptr);
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);

    // Restore the thread-local capture param on exit.
    struct CaptureParamRestorer {
        CaptureParam saved_ = RSUniRenderThread::GetCaptureParam();
        ~CaptureParamRestorer()
        {
            RSUniRenderThread::SetCaptureParam(saved_);
        }
    } captureParamRestorer;

    auto sourceDrawable = std::static_pointer_cast<RSRenderNodeDrawable>(displayNode_->GetRenderDrawable());
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(sourceDrawable->GetRenderParams(), nullptr);
    const bool prevShouldPaint = sourceDrawable->GetRenderParams()->GetShouldPaint();

    const uint32_t saveCount = paintFilterCanvas_->GetSaveCount();
    const bool prevWindowRecordFlag = RSUniRenderThread::GetCaptureParam().isWindowRecord_;
    const auto prevWhiteList = RSUniRenderThread::Instance().GetWhiteList();
    auto expectNoSideEffect = [&]() {
        EXPECT_EQ(paintFilterCanvas_->GetSaveCount(), saveCount);
        EXPECT_EQ(RSUniRenderThread::GetCaptureParam().isWindowRecord_, prevWindowRecordFlag);
        EXPECT_EQ(RSUniRenderThread::Instance().GetWhiteList(), prevWhiteList);
        EXPECT_TRUE(RSUniRenderThread::GetCaptureParam().isSnapshot_);
    };

    // Passing gates: canvas present, non-empty whitelist, paintable source, preset capture param.
    auto armPassingRecordGates = [&]() {
        displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
        displayParams_->recordWhiteListIds_ = { RECORD_SURFACE_NODE_ID };
        displayParams_->recordSourceDisplayDrawable_ = displayNode_->GetRenderDrawable();
        sourceDrawable->GetRenderParams()->SetShouldPaint(true);
        RSUniRenderThread::GetCaptureParam().isSnapshot_ = true;
    };
    auto runRecordGate = [&]() {
        RSMultiScreenUtil::HandleWindowRecord(*displayDrawable_, *displayParams_, *virtualProcessor_);
    };

    // null canvas: return before any canvas state is touched
    armPassingRecordGates();
    displayDrawable_->curCanvas_ = nullptr;
    runRecordGate();
    expectNoSideEffect();

    // Empty record whitelist with a live, paintable source.
    armPassingRecordGates();
    displayParams_->recordWhiteListIds_.clear();
    ASSERT_TRUE(displayParams_->GetRecordWhiteListIds().empty());
    ASSERT_FALSE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    runRecordGate();
    expectNoSideEffect();

    // populated whitelist but the source display snapshot is missing
    armPassingRecordGates();
    displayParams_->recordSourceDisplayDrawable_.reset();
    ASSERT_TRUE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    ASSERT_FALSE(displayParams_->GetRecordWhiteListIds().empty());
    runRecordGate();
    expectNoSideEffect();

    // source snapshot resolves to the wrong node type
    armPassingRecordGates();
    displayParams_->recordSourceDisplayDrawable_ = screenNode_->GetRenderDrawable();
    auto wrongTypeSource = displayParams_->GetRecordSourceDisplayDrawable().lock();
    ASSERT_NE(wrongTypeSource, nullptr);
    ASSERT_EQ(wrongTypeSource->GetNodeType(), RSRenderNodeType::SCREEN_NODE);
    runRecordGate();
    expectNoSideEffect();

    // source is a logical display but not paintable
    armPassingRecordGates();
    ASSERT_TRUE(sourceDrawable->ShouldPaint());
    sourceDrawable->GetRenderParams()->SetShouldPaint(false);
    ASSERT_FALSE(sourceDrawable->ShouldPaint());
    runRecordGate();
    expectNoSideEffect();

    // No cached or recomputable geometry: must fail before capture.
    armPassingRecordGates();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    displayParams_->recordSurfaceDrawables_.clear();
    runRecordGate();
    expectNoSideEffect();

    RSUniRenderThread::ResetCaptureParam();
    EXPECT_FALSE(RSUniRenderThread::GetCaptureParam().isSnapshot_);

    sourceDrawable->GetRenderParams()->SetShouldPaint(prevShouldPaint);
    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
}

/**
 * @tc.name: HandleWindowRecordUpdatesSourceRotationTest001
 * @tc.desc: Verify origin rotation follows source display rotation changes during recording
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordUpdatesSourceRotationTest001, TestSize.Level1)
{
    auto sourceDrawable = std::static_pointer_cast<RSRenderNodeDrawable>(mirrorSourceDisplayNode_->GetRenderDrawable());
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(sourceDrawable->GetRenderParams(), nullptr);
    const bool prevShouldPaint = sourceDrawable->GetRenderParams()->GetShouldPaint();
    const auto prevOriginRotation = displayDrawable_->GetOriginScreenRotation();

    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
    displayParams_->recordWhiteListIds_ = { RECORD_SURFACE_NODE_ID };
    displayParams_->recordSourceDisplayDrawable_ = mirrorSourceDisplayNode_->GetRenderDrawable();
    displayParams_->recordSurfaceDrawables_.clear();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI(0, 0, 100, 100));
    sourceDrawable->GetRenderParams()->SetShouldPaint(true);
    mirrorSourceDisplayParams_->SetScreenRotation(ScreenRotation::ROTATION_0);

    RSMultiScreenUtil::HandleWindowRecord(*displayDrawable_, *displayParams_, *virtualProcessor_);
    EXPECT_EQ(displayDrawable_->GetOriginScreenRotation(), ScreenRotation::ROTATION_0);

    mirrorSourceDisplayParams_->SetScreenRotation(ScreenRotation::ROTATION_90);
    RSMultiScreenUtil::HandleWindowRecord(*displayDrawable_, *displayParams_, *virtualProcessor_);
    EXPECT_EQ(displayDrawable_->GetOriginScreenRotation(), ScreenRotation::ROTATION_90);

    sourceDrawable->GetRenderParams()->SetShouldPaint(prevShouldPaint);
    displayDrawable_->SetOriginScreenRotation(prevOriginRotation);
    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
}

/**
 * @tc.name: HandleWindowRecordScreenBBoxSkipsInvalidRectTest001
 * @tc.desc: Degenerate record rects must not contribute to the record bbox min/max merge
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenBBoxSkipsInvalidRectTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayDrawable_, nullptr);
    auto validRectDrawable = mirrorSourceDisplayNode_->GetRenderDrawable();
    auto degenerateRectDrawable = screenNode_->GetRenderDrawable();
    ASSERT_NE(validRectDrawable, nullptr);
    ASSERT_NE(degenerateRectDrawable, nullptr);
    ASSERT_NE(validRectDrawable->GetRenderParams(), nullptr);
    ASSERT_NE(degenerateRectDrawable->GetRenderParams(), nullptr);
    auto& validRectParams = *validRectDrawable->GetRenderParams();
    auto& degenerateRectParams = *degenerateRectDrawable->GetRenderParams();

    // The two drawables below only supply the record-window rects read by ComputeRecordBBox.
    ArmWindowRecordScreenGates(
        *displayParams_, displayNode_->GetRenderDrawable(), validRectDrawable, validRectDrawable);

    // Only the valid contributor defines the bbox; the distant zero-area rect must be skipped.
    validRectParams.SetAbsDrawRect({ 100, 100, 100, 100 });
    degenerateRectParams.SetAbsDrawRect({ 500, 500, 0, 0 });
    displayParams_->recordSurfaceDrawables_ = { validRectDrawable, degenerateRectDrawable };
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI(100, 100, 200, 200));

    // All contributors degenerate: no bbox, so the frame is skipped and the cache stays cleared.
    validRectParams.SetAbsDrawRect({ 0, 0, 0, 0 });
    degenerateRectParams.SetAbsDrawRect({ 500, 500, 0, 0 });
    displayParams_->recordSurfaceDrawables_ = { validRectDrawable, degenerateRectDrawable };
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI());
}

/**
 * @tc.name: HandleWindowRecordScreenBBoxRejectsOverflowingRectTest001
 * @tc.desc: A positive-size record rect whose right/bottom does not fit in int32 must be dropped instead of
 *           overflowing the bbox merge
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenBBoxRejectsOverflowingRectTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayDrawable_, nullptr);
    auto normalRectDrawable = mirrorSourceDisplayNode_->GetRenderDrawable();
    auto overflowRectDrawable = screenNode_->GetRenderDrawable();
    ASSERT_NE(normalRectDrawable, nullptr);
    ASSERT_NE(overflowRectDrawable, nullptr);
    ASSERT_NE(normalRectDrawable->GetRenderParams(), nullptr);
    ASSERT_NE(overflowRectDrawable->GetRenderParams(), nullptr);
    auto& normalRectParams = *normalRectDrawable->GetRenderParams();
    auto& overflowRectParams = *overflowRectDrawable->GetRenderParams();

    // Origin near INT32_MAX with positive size: right/bottom overflow int32, so the rect must be dropped.
    constexpr int32_t NEAR_INT32_MAX = 0x7FFFFF00;
    constexpr int32_t OVERFLOW_SIZE = 0x400;
    const RectI overflowingRect(NEAR_INT32_MAX, NEAR_INT32_MAX, OVERFLOW_SIZE, OVERFLOW_SIZE);

    ArmWindowRecordScreenGates(
        *displayParams_, displayNode_->GetRenderDrawable(), normalRectDrawable, normalRectDrawable);

    // The overflowing rect must not extend the bbox beyond the ordinary rect.
    normalRectParams.SetAbsDrawRect({ 100, 100, 100, 100 });
    overflowRectParams.SetAbsDrawRect(overflowingRect);
    displayParams_->recordSurfaceDrawables_ = { normalRectDrawable, overflowRectDrawable };
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI(100, 100, 200, 200));

    // No representable contributor: no bbox, so the frame is skipped and the cache stays cleared.
    normalRectParams.SetAbsDrawRect({ 500, 500, 0, 0 });
    displayParams_->recordSurfaceDrawables_ = { overflowRectDrawable, normalRectDrawable };
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI());
}

/**
 * @tc.name: HandleWindowRecordScreenOutputGateAndMuteTest001
 * @tc.desc: Output paintability gates the record pass and a muted paintable output bypasses the record content gates
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenOutputGateAndMuteTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(mirrorSourceDisplayParams_, nullptr);
    ASSERT_NE(mirrorSourceDisplayDrawable_, nullptr);
    auto outputDrawable = mirrorSourceDisplayNode_->GetRenderDrawable();
    auto sourceDrawable = displayNode_->GetRenderDrawable();
    ASSERT_NE(outputDrawable, nullptr);
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(outputDrawable->GetRenderParams(), nullptr);

    // The output display owns the record config; the source display is a distinct paintable node.
    ArmWindowRecordScreenGates(*mirrorSourceDisplayParams_, outputDrawable, sourceDrawable, sourceDrawable);

    // A non-paintable output is rejected before the processor, muted or not.
    mirrorSourceDisplayParams_->SetShouldPaint(false);
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
    mirrorSourceDisplayParams_->virtualScreenMuteStatus_ = true;
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // A muted paintable output draws only the security mask and bypasses the content gates.
    mirrorSourceDisplayParams_->SetShouldPaint(true);
    mirrorSourceDisplayParams_->recordSourceDisplayDrawable_.reset();
    mirrorSourceDisplayParams_->recordWhiteListIds_.clear();
    mirrorSourceDisplayParams_->hasPaintableRecordSurface_ = false;
    mirrorSourceDisplayParams_->recordSurfaceDrawables_.clear();
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);
    EXPECT_EQ(mirrorSourceDisplayDrawable_->GetWindowRecordBBox(), Drawing::RectI());

    mirrorSourceDisplayParams_->virtualScreenMuteStatus_ = false;
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
}

/**
 * @tc.name: HandleWindowRecordMuteDrawsMaskWithoutSourceTest001
 * @tc.desc: An active mute draws the security mask even when no record source, whitelist or bbox resolves
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordMuteDrawsMaskWithoutSourceTest001, TestSize.Level1)
{
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);

    const bool prevMute = displayParams_->GetVirtualScreenMuteStatus();
    const uint32_t prevSaveCount = paintFilterCanvas_->GetSaveCount();

    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
    displayParams_->recordSurfaceDrawables_.clear();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    ASSERT_TRUE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    ASSERT_TRUE(displayParams_->GetRecordWhiteListIds().empty());

    // Muted output without resolvable content still draws the mask.
    displayParams_->virtualScreenMuteStatus_ = true;
    displayDrawable_->virtualDirtyNeedRefresh_ = false;
    paintFilterCanvas_->SetDisableFilterCache(true);
    RSMultiScreenUtil::HandleWindowRecord(*displayDrawable_, *displayParams_, *virtualProcessor_);
    EXPECT_TRUE(displayDrawable_->virtualDirtyNeedRefresh_);
    // No mask image: DrawSecurityMask clears to black and drops the filter cache.
    EXPECT_FALSE(paintFilterCanvas_->GetDisableFilterCache());
    EXPECT_EQ(paintFilterCanvas_->GetSaveCount(), prevSaveCount);

    // Control: without mute the canvas and dirty flag stay untouched.
    displayParams_->virtualScreenMuteStatus_ = false;
    displayDrawable_->virtualDirtyNeedRefresh_ = false;
    paintFilterCanvas_->SetDisableFilterCache(true);
    RSMultiScreenUtil::HandleWindowRecord(*displayDrawable_, *displayParams_, *virtualProcessor_);
    EXPECT_FALSE(displayDrawable_->virtualDirtyNeedRefresh_);
    EXPECT_TRUE(paintFilterCanvas_->GetDisableFilterCache());
    EXPECT_EQ(paintFilterCanvas_->GetSaveCount(), prevSaveCount);

    displayParams_->virtualScreenMuteStatus_ = prevMute;
    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
}
} // namespace OHOS::Rosen
