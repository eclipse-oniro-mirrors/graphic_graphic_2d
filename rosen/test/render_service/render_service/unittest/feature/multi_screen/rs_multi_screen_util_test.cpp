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

void ExpectRect(const Drawing::RectI& rect, int32_t left, int32_t top, int32_t right, int32_t bottom)
{
    EXPECT_EQ(rect.GetLeft(), left);
    EXPECT_EQ(rect.GetTop(), top);
    EXPECT_EQ(rect.GetRight(), right);
    EXPECT_EQ(rect.GetBottom(), bottom);
}

// Record capture reads and rewrites the thread-local capture param; start from a clean value and
// restore the caller's state on every exit.
class ScopedCaptureParam {
public:
    ScopedCaptureParam()
        : saved_(RSUniRenderThread::GetCaptureParam())
    {
        RSUniRenderThread::SetCaptureParam(CaptureParam());
    }
    ~ScopedCaptureParam()
    {
        RSUniRenderThread::SetCaptureParam(saved_);
    }
    ScopedCaptureParam(const ScopedCaptureParam&) = delete;
    ScopedCaptureParam& operator=(const ScopedCaptureParam&) = delete;

private:
    CaptureParam saved_;
};

// Mirror/record source capture rewrites the process-wide draw offsets; restore them on every exit
// path so an aborted expectation cannot leak into later tests.
class ScopedRenderNodeOffset {
public:
    ScopedRenderNodeOffset(int32_t offsetX, int32_t offsetY)
        : savedX_(RSRenderNodeDrawable::offsetX_), savedY_(RSRenderNodeDrawable::offsetY_)
    {
        RSRenderNodeDrawable::offsetX_ = offsetX;
        RSRenderNodeDrawable::offsetY_ = offsetY;
    }
    ~ScopedRenderNodeOffset()
    {
        RSRenderNodeDrawable::offsetX_ = savedX_;
        RSRenderNodeDrawable::offsetY_ = savedY_;
    }
    ScopedRenderNodeOffset(const ScopedRenderNodeOffset&) = delete;
    ScopedRenderNodeOffset& operator=(const ScopedRenderNodeOffset&) = delete;

private:
    int32_t savedX_;
    int32_t savedY_;
};

class SourceDisplayOffsetProbe final : public RSDrawable {
public:
    SourceDisplayOffsetProbe(int32_t& observedX, int32_t& observedY)
        : observedX_(observedX), observedY_(observedY) {}

    void OnDraw(Drawing::Canvas*, const Drawing::Rect*) const override
    {
        observedX_ = RSRenderNodeDrawable::offsetX_;
        observedY_ = RSRenderNodeDrawable::offsetY_;
    }

    void OnSync() override {}

private:
    int32_t& observedX_;
    int32_t& observedY_;
};

// Draws one real logical-display drawable from the screen drawable's children slot so the shared
// mirror entry runs through the production traversal while staying a test-only probe.
class DisplayDrawProbe final : public RSDrawable {
public:
    explicit DisplayDrawProbe(RSLogicalDisplayRenderNodeDrawable& target) : target_(target) {}

    void OnDraw(Drawing::Canvas* canvas, const Drawing::Rect*) const override
    {
        if (canvas != nullptr) {
            target_.OnDraw(*canvas);
        }
    }

    void OnSync() override {}

private:
    RSLogicalDisplayRenderNodeDrawable& target_;
};

// Successful virtual-mirror processor fixture: a real init needs an output surface and render
// engine that this target does not provide, so count the shared lifecycle's publication directly.
class CountingVirtualMirrorProcessor final : public RSUniRenderVirtualProcessor {
public:
    bool InitForRenderThread(DrawableV2::RSScreenRenderNodeDrawable&, std::shared_ptr<RSBaseRenderEngine>,
        int32_t = 0) override
    {
        return true;
    }
    void PostProcess() override
    {
        ++postProcessCount_;
    }
    int postProcessCount_ = 0;
};

// Pushes a real cancel-capable frame so an aborted virtual pass can be observed through its surface.
RSRenderFrame* PushVirtualMirrorFrame(RSUniRenderVirtualProcessor& processor)
{
    auto consumer = IConsumerSurface::Create("RSMultiScreenUtilVirtualFrame");
    if (consumer == nullptr) {
        return nullptr;
    }
    auto producer = consumer->GetProducer();
    if (producer == nullptr) {
        return nullptr;
    }
    auto surface = Surface::CreateSurfaceAsProducer(producer);
    if (surface == nullptr) {
        return nullptr;
    }
    auto rsSurface = std::make_shared<RSSurfaceOhosRaster>(surface);
    if (rsSurface == nullptr) {
        return nullptr;
    }
    auto rasterFrame = std::make_unique<RSSurfaceFrameOhosRaster>(DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT);
    SurfaceFrameConfig config;
    config.frame = std::make_unique<RSRenderFrame>(
        std::static_pointer_cast<RSSurfaceOhos>(rsSurface), std::move(rasterFrame));
    auto* frame = config.frame.get();
    processor.surfaceFrames_.push_back(std::move(config));
    return frame;
}

// Pushes a real producer surface with no frame so SetScreenInfoForWindowRecord has a queue to
// write producer metadata into, then the test reads it back through Surface::GetScreenInfo.
sptr<Surface> PushScreenInfoSurface(RSUniRenderVirtualProcessor& processor)
{
    auto consumer = IConsumerSurface::Create("RSMultiScreenUtilScreenInfo");
    if (consumer == nullptr) {
        return nullptr;
    }
    auto producer = consumer->GetProducer();
    if (producer == nullptr) {
        return nullptr;
    }
    auto surface = Surface::CreateSurfaceAsProducer(producer);
    if (surface == nullptr) {
        return nullptr;
    }
    SurfaceFrameConfig config;
    config.surface = surface;
    processor.surfaceFrames_.push_back(std::move(config));
    return surface;
}

// Reads back the producer metadata a record frame writes for the current and original rects.
void ExpectSurfaceScreenInfo(const sptr<Surface>& surface, int32_t currentW, int32_t currentH,
    int32_t originalW, int32_t originalH)
{
    if (surface == nullptr) {
        ADD_FAILURE() << "screen-info surface is null";
        return;
    }
    Rect currentRect = { -1, -1, -1, -1 };
    Rect originalRect = { -1, -1, -1, -1 };
    float angle = -1.0f;
    EXPECT_EQ(surface->GetScreenInfo(currentRect, originalRect, angle), GSERROR_OK);
    EXPECT_EQ(currentRect.x, 0);
    EXPECT_EQ(currentRect.y, 0);
    EXPECT_EQ(currentRect.w, currentW);
    EXPECT_EQ(currentRect.h, currentH);
    EXPECT_EQ(originalRect.x, 0);
    EXPECT_EQ(originalRect.y, 0);
    EXPECT_EQ(originalRect.w, originalW);
    EXPECT_EQ(originalRect.h, originalH);
    EXPECT_EQ(angle, 0.0f);
}
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

    // Arms the display-level record gates so a case can then break exactly one of them. The
    // screen-visible child list and the output skip state stay in the test body: they are the
    // preconditions a multi-display or repeated-call case varies.
    void ArmWindowRecordDisplayGates(RSLogicalDisplayRenderParams& params,
        const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& source,
        const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& bbox);

    // Arms an active record capture on a virtual MIRROR output with a distinct paintable source and
    // the already published mirror relation.
    void ArmWindowRecordCapture(RSLogicalDisplayRenderParams& params);
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

void RSMultiScreenUtilTest::ArmWindowRecordDisplayGates(RSLogicalDisplayRenderParams& params,
    const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& source,
    const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& bbox)
{
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { RECORD_SURFACE_NODE_ID };
    params.SetWindowRecordConfig(recordConfig);
    params.SetOnVirtualScreen(true);
    params.displayMode_ = DisplayMode::MIRROR;
    params.SetShouldPaint(true);
    params.recordSourceDisplayDrawable_ = source;
    source->GetRenderParams()->SetShouldPaint(true);
    params.recordWhiteListIds_ = { RECORD_SURFACE_NODE_ID };
    params.hasPaintableRecordSurface_ = true;
    params.recordSurfaceDrawables_ = { bbox };
    bbox->GetRenderParams()->SetAbsDrawRect({ 0, 0, 100, 100 });
}

void RSMultiScreenUtilTest::ArmWindowRecordCapture(RSLogicalDisplayRenderParams& params)
{
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);
    ASSERT_NE(mirrorSourceDisplayDrawable_, nullptr);
    ASSERT_NE(mirrorSourceDisplayParams_, nullptr);
    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { RECORD_SURFACE_NODE_ID };
    params.SetWindowRecordConfig(recordConfig);
    params.SetOnVirtualScreen(true);
    params.displayMode_ = DisplayMode::MIRROR;
    // The record display consumes the already published mirror relation; it must not select a
    // second source during the draw pass.
    params.mirrorSourceDrawable_ = mirrorSourceDisplayNode_->GetRenderDrawable();
    params.recordWhiteListIds_ = { RECORD_SURFACE_NODE_ID };
    params.recordSourceDisplayDrawable_ = mirrorSourceDisplayNode_->GetRenderDrawable();
    // The cached output bbox skips recomputation so the source needs no surface rects.
    params.recordSurfaceDrawables_.clear();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI(0, 0, 100, 100));
    mirrorSourceDisplayParams_->SetShouldPaint(true);
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
    RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, mirrorSourceScreenParams_, *screenParams_, processor);

    // restore uniParam for other test cases
    auto uniRenderThreadParams = std::make_unique<RSRenderThreadParams>();
    RSRenderThreadParamsManager::Instance().SetRSRenderThreadParams(std::move(uniRenderThreadParams));

    // when processor is nullptr
    RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, mirrorSourceScreenParams_, *screenParams_, nullptr);

    // when processor is not nullptr but init failed
    screenParams_->screenProperty_.Set<ScreenPropertyType::SCREEN_STATUS>(static_cast<uint32_t>(VIRTUAL_SCREEN_PAUSE));
    bool res = processor->InitForRenderThread(*screenDrawable_, RSUniRenderThread::Instance().GetRenderEngine());
    EXPECT_FALSE(res);
    RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, mirrorSourceScreenParams_, *screenParams_, processor);
    EXPECT_NE(mirrorSourceScreenParams_, nullptr);
}

/**
 * @tc.name: HandleMirrorScreenTest002
 * @tc.desc: A post-request virtual skip cancels its acquired frame through the single shared guard,
 * and a later successful pass publishes without cancelling
 * @tc.type: FUNC
 * @tc.require: #ICQ74B
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorScreenTest002, TestSize.Level1)
{
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    EXPECT_NE(uniParam, nullptr);

    auto processor = std::make_shared<CountingVirtualMirrorProcessor>();
    processor->canvas_ = paintFilterCanvas_;
    screenParams_->hasWindowRecordDisplay_ = false;

    // A null source is only legal for the current muted record mask: an ordinary virtual call must
    // be rejected before init/publication.
    screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
    EXPECT_FALSE(RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, nullptr, *screenParams_, processor));
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
    EXPECT_EQ(processor->postProcessCount_, 0);

    // The virtual pass acquires its frame first, then displaySkip requests an abort. The shared guard
    // is the only cancel owner and the per-pass request is cleared for the next frame.
    processor->SetDisplaySkipInMirror(true);
    auto* canceledFrame = PushVirtualMirrorFrame(*processor);
    ASSERT_NE(canceledFrame, nullptr);
    EXPECT_FALSE(RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, mirrorSourceScreenParams_,
        *screenParams_, processor));
    EXPECT_EQ(processor->postProcessCount_, 0);
    EXPECT_EQ(canceledFrame->GetSurface(), nullptr);
    EXPECT_FALSE(processor->GetDisplaySkipInMirror());
    processor->surfaceFrames_.clear();

    // A later pass publishes once; the disarmed guard leaves the acquired frame to the pass.
    auto* publishedFrame = PushVirtualMirrorFrame(*processor);
    ASSERT_NE(publishedFrame, nullptr);
    EXPECT_TRUE(RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, mirrorSourceScreenParams_,
        *screenParams_, processor));
    EXPECT_EQ(processor->postProcessCount_, 1);
    EXPECT_NE(publishedFrame->GetSurface(), nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::MIRROR_DRAWABLE_SKIP);
    processor->surfaceFrames_.clear();
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
 * @tc.name: HandleMirrorDisplayRecordForcesRebuildTest001
 * @tc.desc: A record output always rebuilds its published source while ordinary mirror still selects the
 *           whole-screen cache; the record whitelist is injected with the real security state
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorDisplayRecordForcesRebuildTest001, TestSize.Level1)
{
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(mirrorSourceDisplayNode_, nullptr);
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);

    auto uniParams = std::make_unique<RSRenderThreadParams>();
    RSUniRenderThread::Instance().Sync(std::move(uniParams));
    virtualProcessor_->canvas_ = paintFilterCanvas_;
    auto surface = PushScreenInfoSurface(*virtualProcessor_);
    ASSERT_NE(surface, nullptr);
    mirrorSourceScreenDrawable_->cacheImgForCapture_ = std::make_shared<Drawing::Image>();
    ASSERT_NE(mirrorSourceScreenDrawable_->GetCacheImgForCapture(), nullptr);

    // Ordinary mirror keeps its cache/rebuild decision: a valid whole-screen cache selects FROM_CACHE.
    displayParams_->SetWindowRecordConfig(RSWindowRecordConfig());
    displayParams_->mirrorSourceDrawable_ = mirrorSourceDisplayNode_->GetRenderDrawable();
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    EXPECT_TRUE(virtualProcessor_->GetDrawVirtualMirrorCopy());
    EXPECT_EQ(displayDrawable_->lastFrameRenderStrategy_, RenderStrategy::DRAW_VIRTUAL_MIRROR_FROM_CACHE);

    // Record forces REBUILD even though the same cache image exists.
    ArmWindowRecordDisplayGates(*displayParams_, mirrorSourceDisplayNode_->GetRenderDrawable(),
        mirrorSourceDisplayNode_->GetRenderDrawable());
    displayParams_->recordSurfaceDrawables_.clear();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI(0, 0, 100, 100));
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    EXPECT_FALSE(virtualProcessor_->GetDrawVirtualMirrorCopy());
    EXPECT_EQ(displayDrawable_->lastFrameRenderStrategy_, RenderStrategy::DRAW_VIRTUAL_MIRROR_REBUILD);
    // The common special-layer state carries the record whitelist with the real (false) security state.
    EXPECT_EQ(displayDrawable_->lastSpecialLayerRenderParam_.whiteList,
        std::unordered_set<NodeId>({ RECORD_SURFACE_NODE_ID }));
    EXPECT_FALSE(displayDrawable_->lastSpecialLayerRenderParam_.securityDisplay);

    // Content keeps the existing producer metadata: original window bbox and current buffer rect.
    ExpectSurfaceScreenInfo(surface, DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE,
        DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
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
 * @tc.name: DrawVirtualMirrorRebuildHdrGateTest001
 * @tc.desc: A record rebuild keeps SDR canvas handling and never enables the HDR virtual-screen canvas even
 *           when the output screen reports HDRPresent, while an ordinary rebuild still enables it
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, DrawVirtualMirrorRebuildHdrGateTest001, TestSize.Level1)
{
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    screenParams_->SetHDRPresent(true);
    ASSERT_TRUE(screenParams_->GetHDRPresent());
    ASSERT_FALSE(paintFilterCanvas_->GetHdrOn());
    ASSERT_FALSE(paintFilterCanvas_->GetHDREnabledVirtualScreen());
    const auto prevDisplayMode = displayParams_->displayMode_;

    // Record rebuild: SDR-only canvas, flagged as a multi-screen draw.
    {
        RSRenderThreadParams uniParam;
        ArmWindowRecordCapture(*displayParams_);
        ASSERT_TRUE(displayParams_->IsRecordSessionActive());
        RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
        EXPECT_FALSE(paintFilterCanvas_->GetHdrOn());
        EXPECT_FALSE(paintFilterCanvas_->GetHDREnabledVirtualScreen());
        EXPECT_TRUE(paintFilterCanvas_->IsOnMultipleScreen());
    }

    // Leave the record session so the ordinary arm of the HDR gate runs.
    displayParams_->SetWindowRecordConfig(RSWindowRecordConfig());
    displayParams_->SetOnVirtualScreen(false);
    displayParams_->displayMode_ = prevDisplayMode;
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
    displayParams_->mirrorSourceDrawable_ = mirrorSourceDisplayNode_->GetRenderDrawable();
    mirrorSourceDisplayParams_->SetShouldPaint(true);

    // Ordinary rebuild with HDRPresent enables the HDR virtual-screen canvas.
    {
        RSRenderThreadParams uniParam;
        uniParam.SetVirtualDirtyEnabled(false);
        ASSERT_FALSE(displayParams_->IsRecordSessionActive());
        RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);
        EXPECT_TRUE(paintFilterCanvas_->GetHdrOn());
        EXPECT_TRUE(paintFilterCanvas_->GetHDREnabledVirtualScreen());
    }

    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    paintFilterCanvas_->SetHdrOn(false);
    paintFilterCanvas_->SetHDREnabledVirtualScreen(false);
    paintFilterCanvas_->SetOnMultipleScreen(false);
}

/**
 * @tc.name: WindowRecordSourceCaptureAppliesSourceOffsetTest001
 * @tc.desc: Both the ordinary virtual-rebuild and the record mirror-display call sites capture with the source
 *           screen offset and keep it in effect instead of restoring stale entry offsets, while parent matrix,
 *           op-drop, offscreen and capture-param state are still restored
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, WindowRecordSourceCaptureAppliesSourceOffsetTest001, TestSize.Level1)
{
    constexpr int32_t OUTPUT_OFFSET_X = 7;
    constexpr int32_t OUTPUT_OFFSET_Y = 11;
    constexpr int32_t SOURCE_OFFSET_X = 1920;
    constexpr int32_t SOURCE_OFFSET_Y = 1080;
    constexpr float PARENT_TRANSLATE_X = 5.0f;
    constexpr float PARENT_TRANSLATE_Y = 9.0f;
    ScopedRenderNodeOffset offsetRestorer(OUTPUT_OFFSET_X, OUTPUT_OFFSET_Y);
    const auto savedParentMatrix = RSRenderParams::GetParentSurfaceMatrix();
    const auto savedDrawCmdList = mirrorSourceDisplayDrawable_->drawCmdList_;
    const auto savedDrawCmdIndex = mirrorSourceDisplayDrawable_->drawCmdIndex_;
    const auto savedSourceOffset = std::make_pair(mirrorSourceScreenParams_->GetScreenProperty().GetOffsetX(),
        mirrorSourceScreenParams_->GetScreenProperty().GetOffsetY());
    const bool savedOffscreenMirror = paintFilterCanvas_->GetIsDrawingOffscreenMirror();

    int32_t observedOffsetX = -1;
    int32_t observedOffsetY = -1;
    auto probe = std::make_shared<SourceDisplayOffsetProbe>(observedOffsetX, observedOffsetY);
    mirrorSourceDisplayDrawable_->drawCmdList_ = { probe };
    mirrorSourceDisplayDrawable_->drawCmdIndex_.childrenIndex_ = 0;
    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::OFFSET>(
        std::make_pair(SOURCE_OFFSET_X, SOURCE_OFFSET_Y));
    mirrorSourceDisplayParams_->SetShouldPaint(true);
    mirrorSourceDisplayParams_->contentEmpty_ = false;

    // Phase 1: an ordinary virtual-mirror rebuild captures at the source offset and keeps it in
    // effect (no stale entry-offset restore), while restoring the parent matrix, op-drop and
    // capture-param state it entered with.
    {
        ScopedCaptureParam captureParamRestorer;
        RSUniRenderThread::GetCaptureParam().isWindowRecord_ = true;
        Drawing::Matrix enteringParentMatrix;
        enteringParentMatrix.Translate(PARENT_TRANSLATE_X, PARENT_TRANSLATE_Y);
        RSRenderParams::SetParentSurfaceMatrix(enteringParentMatrix);
        paintFilterCanvas_->SetIsDrawingOffscreenMirror(false);
        RSRenderThreadParams uniParam;
        uniParam.SetVirtualDirtyEnabled(false);
        uniParam.SetOpDropped(true);
        system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "0");
        ASSERT_FALSE(displayParams_->IsRecordSessionActive());

        RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, virtualProcessor_, uniParam);

        EXPECT_EQ(observedOffsetX, SOURCE_OFFSET_X);
        EXPECT_EQ(observedOffsetY, SOURCE_OFFSET_Y);
        // The unified mirror behavior keeps the source-screen offset; the entry global offset is
        // deliberately not restored because restoring it would apply stale source coordinates.
        EXPECT_EQ(RSRenderNodeDrawable::offsetX_, SOURCE_OFFSET_X);
        EXPECT_EQ(RSRenderNodeDrawable::offsetY_, SOURCE_OFFSET_Y);
        EXPECT_TRUE(RSUniRenderThread::GetCaptureParam().isWindowRecord_);
        EXPECT_FLOAT_EQ(RSRenderParams::GetParentSurfaceMatrix().Get(Drawing::Matrix::TRANS_X),
            PARENT_TRANSLATE_X);
        EXPECT_FLOAT_EQ(RSRenderParams::GetParentSurfaceMatrix().Get(Drawing::Matrix::TRANS_Y),
            PARENT_TRANSLATE_Y);
        EXPECT_FALSE(paintFilterCanvas_->GetIsDrawingOffscreenMirror());
        EXPECT_TRUE(uniParam.IsOpDropped());
    }

    // Restore the default optimization flag before the record call site runs.
    system::SetParameter("rosen.uni.virtualSelfDrawOptEnabled.enabled", "1");

    // Phase 2: the record mirror-display capture path observes the same source offset and leaves it
    // in effect, while preserving the entry offscreen-mirror flag on both starting values.
    {
        ScopedCaptureParam captureParamRestorer;
        observedOffsetX = -1;
        observedOffsetY = -1;
        ArmWindowRecordCapture(*displayParams_);
        virtualProcessor_->canvas_ = paintFilterCanvas_;
        // Both entry offscreen values must be preserved while the source offset is applied and left
        // in effect instead of restoring a stale output offset.
        const bool offscreenValues[] = { false, true };
        for (bool offscreen : offscreenValues) {
            paintFilterCanvas_->SetIsDrawingOffscreenMirror(offscreen);
            ASSERT_TRUE(displayParams_->IsRecordSessionActive());
            RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
            EXPECT_EQ(observedOffsetX, SOURCE_OFFSET_X);
            EXPECT_EQ(observedOffsetY, SOURCE_OFFSET_Y);
            EXPECT_EQ(RSRenderNodeDrawable::offsetX_, SOURCE_OFFSET_X);
            EXPECT_EQ(RSRenderNodeDrawable::offsetY_, SOURCE_OFFSET_Y);
            EXPECT_EQ(paintFilterCanvas_->GetIsDrawingOffscreenMirror(), offscreen);
        }
    }

    paintFilterCanvas_->SetIsDrawingOffscreenMirror(savedOffscreenMirror);
    RSRenderParams::SetParentSurfaceMatrix(savedParentMatrix);
    mirrorSourceDisplayDrawable_->drawCmdList_ = savedDrawCmdList;
    mirrorSourceDisplayDrawable_->drawCmdIndex_ = savedDrawCmdIndex;
    mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::OFFSET>(savedSourceOffset);
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
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
 * @tc.name: ComputeGravityRectTest001
 * @tc.desc: Invalid sizes return an empty rect, aspect-fit centers the content, and top-left placement maps
 *           canvas (0,0) to a different buffer corner per rotation
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, ComputeGravityRectTest001, TestSize.Level1)
{
    // content size is the divisor: zero and negative values must not reach the float scale path
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 0, 300, WindowRecordFit::ASPECT_FIT), 0, 0, 0, 0);
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 300, -1, WindowRecordFit::ASPECT_FIT_TOP_LEFT),
        0, 0, 0, 0);
    // canvas size is guarded here so every caller can rely on the returned rect
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, -600, 300, 300, WindowRecordFit::ASPECT_FIT), 0, 0, 0, 0);

    // canvas 800x600, content 500x1000: scale 0.6 -> 300x600, centered horizontally; fit ignores rotation
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT),
        250, 0, 550, 600);
    // canvas 800x600, content 1000x500: scale 0.8 -> 800x400, centered vertically
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 1000, 500, WindowRecordFit::ASPECT_FIT),
        0, 100, 800, 500);

    // canvas 800x600, content 500x1000: scaled size 300x600; 0/90 and 180/270 coincide for this data set,
    // but all four rotation arms must still execute.
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT),
        0, 0, 300, 600);
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_90), 0, 0, 300, 600);
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_180), 500, 0, 800, 600);
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 500, 1000, WindowRecordFit::ASPECT_FIT_TOP_LEFT,
        ScreenRotation::ROTATION_270), 500, 0, 800, 600);

    // canvas 800x600, content 1000x500: scaled size 800x400 (distinct shape keeps the same placement rules)
    ExpectRect(RSMultiScreenUtil::ComputeGravityRect(800, 600, 1000, 500, WindowRecordFit::ASPECT_FIT_TOP_LEFT),
        0, 0, 800, 400);
}

/**
 * @tc.name: HandleWindowRecordScreenGateLadderTest001
 * @tc.desc: Screen-level record gates skip before a buffer request only for their own condition, and only an
 *           all-gates-open frame reaches the processor check
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenGateLadderTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(screenNode_, nullptr);
    ASSERT_NE(mirrorSourceDisplayNode_, nullptr);
    // The output display owns the record config; a distinct source drawable keeps the source
    // paintability gate from being masked by the output gate.
    auto sourceDrawable = mirrorSourceDisplayNode_->GetRenderDrawable();
    auto bboxDrawable = sourceDrawable;
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(sourceDrawable->GetRenderParams(), nullptr);
    const bool prevShouldPaint = sourceDrawable->GetRenderParams()->GetShouldPaint();
    const RectI prevBBoxRect = sourceDrawable->GetRenderParams()->GetAbsDrawRect();
    const auto prevDisplayMode = displayParams_->displayMode_;

    auto arm = [&]() {
        screenParams_->logicalDisplayNodeDrawables_ = { displayNode_->GetRenderDrawable() };
        screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
        ArmWindowRecordDisplayGates(*displayParams_, sourceDrawable, bboxDrawable);
    };
    auto run = [&]() { RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr); };

    // Record ids without the virtual-screen flag are not an active session; the source is cleared too.
    arm();
    displayParams_->SetOnVirtualScreen(false);
    displayParams_->recordSourceDisplayDrawable_.reset();
    EXPECT_FALSE(displayParams_->IsRecordSessionActive());
    ASSERT_FALSE(displayParams_->GetRecordWhiteListIds().empty());
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Two output displays are rejected before any display state or bbox cache is touched.
    const Drawing::RectI ownerSentinel(1, 2, 3, 4);
    const Drawing::RectI laterSentinel(11, 22, 33, 44);
    arm();
    displayDrawable_->SetWindowRecordBBox(ownerSentinel);
    mirrorSourceDisplayDrawable_->SetWindowRecordBBox(laterSentinel);
    screenParams_->logicalDisplayNodeDrawables_ = { displayDrawable_, mirrorSourceDisplayDrawable_ };
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), ownerSentinel);
    EXPECT_EQ(mirrorSourceDisplayDrawable_->GetWindowRecordBBox(), laterSentinel);

    // A null entry and a wrong-type entry are rejected independently before any downcast.
    arm();
    screenParams_->logicalDisplayNodeDrawables_ = { nullptr };
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    arm();
    screenParams_->logicalDisplayNodeDrawables_ = { screenNode_->GetRenderDrawable() };
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Active session and a populated whitelist, but no resolved source display: SKIP_FRAME.
    arm();
    displayParams_->recordSourceDisplayDrawable_.reset();
    ASSERT_TRUE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    ASSERT_FALSE(displayParams_->GetRecordWhiteListIds().empty());
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // A source display that should not be painted skips before the processor gate.
    arm();
    sourceDrawable->GetRenderParams()->SetShouldPaint(false);
    EXPECT_TRUE(displayParams_->GetShouldPaint());
    EXPECT_FALSE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // A non-paintable configured surface skips before the processor gate.
    arm();
    displayParams_->hasPaintableRecordSurface_ = false;
    EXPECT_FALSE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    EXPECT_TRUE(sourceDrawable->GetRenderParams()->GetShouldPaint());
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Live source snapshot with an empty whitelist: SKIP_FRAME.
    arm();
    displayParams_->recordWhiteListIds_.clear();
    ASSERT_FALSE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    ASSERT_TRUE(displayParams_->GetRecordWhiteListIds().empty());
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Every loop gate satisfied: execution reaches the processor gate.
    arm();
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);

    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
    displayParams_->SetWindowRecordConfig(RSWindowRecordConfig());
    displayParams_->SetOnVirtualScreen(false);
    displayParams_->displayMode_ = prevDisplayMode;
    screenParams_->logicalDisplayNodeDrawables_ = { displayNode_->GetRenderDrawable() };
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    mirrorSourceDisplayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    sourceDrawable->GetRenderParams()->SetShouldPaint(prevShouldPaint);
    sourceDrawable->GetRenderParams()->SetAbsDrawRect(prevBBoxRect);
}

/**
 * @tc.name: HandleWindowRecordScreenBBoxTest001
 * @tc.desc: Screen-level record geometry rejects a missing, empty or unrepresentable contributor and caches
 *           only the merged valid window bbox
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenBBoxTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(mirrorSourceDisplayNode_, nullptr);
    ASSERT_NE(screenNode_, nullptr);

    auto sourceDrawable = displayNode_->GetRenderDrawable();
    auto validRectDrawable = mirrorSourceDisplayNode_->GetRenderDrawable();
    auto rejectedRectDrawable = screenNode_->GetRenderDrawable();
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(sourceDrawable->GetRenderParams(), nullptr);
    ASSERT_NE(validRectDrawable, nullptr);
    ASSERT_NE(validRectDrawable->GetRenderParams(), nullptr);
    ASSERT_NE(rejectedRectDrawable, nullptr);
    ASSERT_NE(rejectedRectDrawable->GetRenderParams(), nullptr);
    auto& validRectParams = *validRectDrawable->GetRenderParams();
    auto& rejectedRectParams = *rejectedRectDrawable->GetRenderParams();
    const bool prevShouldPaint = sourceDrawable->GetRenderParams()->GetShouldPaint();
    const RectI prevValidRect = validRectParams.GetAbsDrawRect();
    const RectI prevRejectedRect = rejectedRectParams.GetAbsDrawRect();
    const auto prevDisplayMode = displayParams_->displayMode_;

    auto arm = [&]() {
        screenParams_->logicalDisplayNodeDrawables_ = { displayNode_->GetRenderDrawable() };
        screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
        ArmWindowRecordDisplayGates(*displayParams_, sourceDrawable, validRectDrawable);
    };
    auto run = [&]() { RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr); };

    // A paintable surface snapshot without any main-window drawable yields no bbox.
    arm();
    displayParams_->recordSurfaceDrawables_.clear();
    ASSERT_TRUE(displayParams_->HasPaintableRecordSurface());
    ASSERT_FALSE(displayParams_->GetRecordWhiteListIds().empty());
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // A zero-area sole contributor is skipped and still yields no bbox.
    arm();
    validRectParams.SetAbsDrawRect({ 0, 0, 0, 0 });
    ASSERT_TRUE(validRectParams.GetAbsDrawRect().IsEmpty());
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // Valid geometry reaches the processor gate and is shared with the display pass.
    arm();
    validRectParams.SetAbsDrawRect({ 0, 0, 100, 100 });
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI(0, 0, 100, 100));

    // A positive-size contributor near INT32_MAX is not empty; its int64-widened right/bottom exceeds
    // INT32_MAX and is dropped by that guard; the ordinary rect still owns the bbox.
    constexpr int32_t NEAR_INT32_MAX = 0x7FFFFF00;
    constexpr int32_t OVERFLOW_SIZE = 0x400;
    validRectParams.SetAbsDrawRect({ 100, 100, 100, 100 });
    rejectedRectParams.SetAbsDrawRect(RectI(NEAR_INT32_MAX, NEAR_INT32_MAX, OVERFLOW_SIZE, OVERFLOW_SIZE));
    ASSERT_FALSE(rejectedRectParams.GetAbsDrawRect().IsEmpty());
    displayParams_->recordSurfaceDrawables_ = { validRectDrawable, rejectedRectDrawable };
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI(100, 100, 200, 200));

    // No representable contributor: the frame is skipped and the cached bbox is cleared.
    validRectParams.SetAbsDrawRect({ 0, 0, 0, 0 });
    displayParams_->recordSurfaceDrawables_ = { validRectDrawable, rejectedRectDrawable };
    run();
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
    EXPECT_EQ(displayDrawable_->GetWindowRecordBBox(), Drawing::RectI());

    displayParams_->recordSurfaceDrawables_.clear();
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
    displayParams_->SetWindowRecordConfig(RSWindowRecordConfig());
    displayParams_->SetOnVirtualScreen(false);
    displayParams_->displayMode_ = prevDisplayMode;
    screenParams_->logicalDisplayNodeDrawables_ = { displayNode_->GetRenderDrawable() };
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    sourceDrawable->GetRenderParams()->SetShouldPaint(prevShouldPaint);
    validRectParams.SetAbsDrawRect(prevValidRect);
    rejectedRectParams.SetAbsDrawRect(prevRejectedRect);
}

/**
 * @tc.name: HandleMirrorDisplayRecordGatesAndRotationTest001
 * @tc.desc: Display-level record early returns keep the save stack, capture param and filter lists untouched,
 *           while a passing frame follows first-time and changed source rotation
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorDisplayRecordGatesAndRotationTest001, TestSize.Level1)
{
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(screenNode_, nullptr);
    ASSERT_NE(mirrorSourceDisplayNode_, nullptr);
    ASSERT_NE(mirrorSourceDisplayDrawable_, nullptr);
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);

    auto sourceDrawable = std::static_pointer_cast<RSRenderNodeDrawable>(
        mirrorSourceDisplayNode_->GetRenderDrawable());
    ASSERT_NE(sourceDrawable, nullptr);
    ASSERT_NE(sourceDrawable->GetRenderParams(), nullptr);
    const bool prevShouldPaint = sourceDrawable->GetRenderParams()->GetShouldPaint();
    const auto prevOriginRotation = displayDrawable_->GetOriginScreenRotation();
    const auto prevDisplayMode = displayParams_->displayMode_;
    ScopedCaptureParam captureParamRestorer;

    const uint32_t saveCount = paintFilterCanvas_->GetSaveCount();
    const bool prevWindowRecordFlag = RSUniRenderThread::GetCaptureParam().isWindowRecord_;
    const auto prevWhiteList = RSUniRenderThread::Instance().GetWhiteList();
    auto expectNoSideEffect = [&]() {
        EXPECT_EQ(paintFilterCanvas_->GetSaveCount(), saveCount);
        EXPECT_EQ(RSUniRenderThread::GetCaptureParam().isWindowRecord_, prevWindowRecordFlag);
        EXPECT_EQ(RSUniRenderThread::Instance().GetWhiteList(), prevWhiteList);
        EXPECT_TRUE(RSUniRenderThread::GetCaptureParam().isSnapshot_);
    };
    auto arm = [&]() {
        virtualProcessor_->canvas_ = paintFilterCanvas_;
        ArmWindowRecordCapture(*displayParams_);
        RSUniRenderThread::GetCaptureParam().isSnapshot_ = true;
    };
    auto run = [&]() {
        RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    };

    // null canvas: return before any capture or canvas state is touched.
    arm();
    virtualProcessor_->canvas_ = nullptr;
    run();
    expectNoSideEffect();

    // Empty record whitelist with a live, paintable source.
    arm();
    displayParams_->recordWhiteListIds_.clear();
    ASSERT_TRUE(displayParams_->GetRecordWhiteListIds().empty());
    ASSERT_FALSE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    run();
    expectNoSideEffect();

    // Published source relation missing.
    arm();
    displayParams_->mirrorSourceDrawable_.reset();
    displayParams_->recordSourceDisplayDrawable_.reset();
    ASSERT_TRUE(displayParams_->GetMirrorSourceDrawable().expired());
    ASSERT_FALSE(displayParams_->GetRecordWhiteListIds().empty());
    run();
    expectNoSideEffect();

    // Source is a logical display but not paintable.
    arm();
    ASSERT_TRUE(sourceDrawable->ShouldPaint());
    sourceDrawable->GetRenderParams()->SetShouldPaint(false);
    ASSERT_FALSE(sourceDrawable->ShouldPaint());
    run();
    expectNoSideEffect();

    // No cached or recomputable geometry: must fail before capture.
    arm();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    displayParams_->recordSurfaceDrawables_.clear();
    run();
    expectNoSideEffect();

    // A passing frame follows the first-time source rotation.
    mirrorSourceDisplayParams_->SetScreenRotation(ScreenRotation::ROTATION_0);
    arm();
    ASSERT_TRUE(displayParams_->IsRecordSessionActive());
    run();
    EXPECT_EQ(displayDrawable_->GetOriginScreenRotation(), ScreenRotation::ROTATION_0);

    // A changed source rotation is followed by the same passing frame.
    mirrorSourceDisplayParams_->SetScreenRotation(ScreenRotation::ROTATION_90);
    arm();
    ASSERT_TRUE(displayParams_->IsRecordSessionActive());
    run();
    EXPECT_EQ(displayDrawable_->GetOriginScreenRotation(), ScreenRotation::ROTATION_90);

    displayDrawable_->SetOriginScreenRotation(prevOriginRotation);
    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    displayParams_->recordSurfaceDrawables_.clear();
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
    displayParams_->SetWindowRecordConfig(RSWindowRecordConfig());
    displayParams_->SetOnVirtualScreen(false);
    displayParams_->displayMode_ = prevDisplayMode;
    sourceDrawable->GetRenderParams()->SetShouldPaint(prevShouldPaint);
    mirrorSourceDisplayParams_->SetScreenRotation(ScreenRotation::ROTATION_0);
}

/**
 * @tc.name: HandleWindowRecordScreenOutputGateAndMuteTest001
 * @tc.desc: Output paintability gates the record pass; a muted paintable output reaches the shared
 * virtual-mirror lifecycle without a source while a non-mute source-less output skips before it.
 * With the real virtual processor the mask stops at the common init failure; a successful fixture
 * then publishes exactly one mask PostProcess. Record-to-ordinary sequencing is not asserted here.
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
    screenParams_->logicalDisplayNodeDrawables_ = { outputDrawable };
    screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
    ArmWindowRecordDisplayGates(*mirrorSourceDisplayParams_, sourceDrawable, sourceDrawable);

    // A non-paintable output is rejected before the processor, muted or not.
    mirrorSourceDisplayParams_->SetShouldPaint(false);
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, nullptr);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // A muted paintable output needs no source and reaches the shared virtual-mirror lifecycle: the
    // observable proof is that it passes the screen gate and the virtual-processor gate, then stops
    // at the common processor init (RENDER_ENGINE_NULL), not at the content SKIP_FRAME gate.
    mirrorSourceDisplayParams_->SetShouldPaint(true);
    mirrorSourceDisplayParams_->virtualScreenMuteStatus_ = true;
    mirrorSourceDisplayParams_->recordSourceDisplayDrawable_.reset();
    mirrorSourceDisplayParams_->recordWhiteListIds_.clear();
    mirrorSourceDisplayParams_->hasPaintableRecordSurface_ = false;
    mirrorSourceDisplayParams_->recordSurfaceDrawables_.clear();
    screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, virtualProcessor_);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::RENDER_ENGINE_NULL);
    EXPECT_EQ(mirrorSourceDisplayDrawable_->GetWindowRecordBBox(), Drawing::RectI());

    // The same source-less output without mute must not request a buffer even with a live processor.
    mirrorSourceDisplayParams_->virtualScreenMuteStatus_ = false;
    screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, virtualProcessor_);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);

    // A successful processor fixture publishes the muted, source-less output exactly once.
    auto maskProcessor = std::make_shared<CountingVirtualMirrorProcessor>();
    maskProcessor->canvas_ = paintFilterCanvas_;
    screenParams_->hasWindowRecordDisplay_ = true;
    mirrorSourceDisplayParams_->virtualScreenMuteStatus_ = true;
    screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, maskProcessor);
    EXPECT_EQ(maskProcessor->postProcessCount_, 1);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::MIRROR_DRAWABLE_SKIP);
    EXPECT_EQ(mirrorSourceDisplayDrawable_->GetWindowRecordBBox(), Drawing::RectI());
}

/**
 * @tc.name: HandleWindowRecordScreenContentLiveSourceTest001
 * @tc.desc: A live published source reaches record content capture through the shared virtual lifecycle and
 *           publishes exactly once, exercising the strong drawable ownership used for the mirror call
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenContentLiveSourceTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(mirrorSourceDisplayNode_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);
    auto sourceAdapter = mirrorSourceDisplayNode_->GetRenderDrawable();
    ASSERT_NE(sourceAdapter, nullptr);
    ASSERT_NE(sourceAdapter->GetRenderParams(), nullptr);
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    ASSERT_NE(uniParam, nullptr);

    auto processor = std::make_shared<CountingVirtualMirrorProcessor>();
    processor->canvas_ = paintFilterCanvas_;
    uniParam->SetRSProcessor(processor);
    auto* frame = PushVirtualMirrorFrame(*processor);
    ASSERT_NE(frame, nullptr);

    screenParams_->logicalDisplayNodeDrawables_ = { displayNode_->GetRenderDrawable() };
    screenParams_->hasWindowRecordDisplay_ = true;
    screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
    // The record output consumes the already published mirror relation.
    displayParams_->mirrorSourceDrawable_ = sourceAdapter;
    ArmWindowRecordDisplayGates(*displayParams_, sourceAdapter, sourceAdapter);
    ASSERT_TRUE(displayParams_->IsRecordSessionActive());
    ASSERT_TRUE(displayParams_->GetShouldPaint());
    auto probe = std::make_shared<DisplayDrawProbe>(*displayDrawable_);
    const auto savedDrawCmdList = screenDrawable_->drawCmdList_;
    const auto savedDrawCmdIndex = screenDrawable_->drawCmdIndex_;
    DrawCmdIndex probeIndex;
    probeIndex.childrenIndex_ = 0;
    screenDrawable_->drawCmdList_ = { probe };
    screenDrawable_->drawCmdIndex_ = probeIndex;

    RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, processor);

    screenDrawable_->drawCmdList_ = savedDrawCmdList;
    screenDrawable_->drawCmdIndex_ = savedDrawCmdIndex;
    EXPECT_EQ(processor->postProcessCount_, 1);
    EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::MIRROR_DRAWABLE_SKIP);
    EXPECT_EQ(displayDrawable_->lastFrameRenderStrategy_, RenderStrategy::DRAW_VIRTUAL_MIRROR_REBUILD);
    EXPECT_NE(frame->GetSurface(), nullptr);
    EXPECT_FALSE(processor->GetDisplaySkipInMirror());
    processor->surfaceFrames_.clear();
    uniParam->SetRSProcessor(nullptr);
}

/**
 * @tc.name: WindowRecordContentFailureCancelsMirrorFrameTest001
 * @tc.desc: A record content early gate (invalid geometry) restores the canvas and requests the shared virtual
 *           skip, so the acquired frame is cancelled and PostProcess never runs
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, WindowRecordContentFailureCancelsMirrorFrameTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(screenParams_, nullptr);
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    ASSERT_NE(uniParam, nullptr);

    auto processor = std::make_shared<CountingVirtualMirrorProcessor>();
    processor->canvas_ = paintFilterCanvas_;
    uniParam->SetRSProcessor(processor);
    auto* frame = PushVirtualMirrorFrame(*processor);
    ASSERT_NE(frame, nullptr);

    ArmWindowRecordCapture(*displayParams_);
    ASSERT_TRUE(displayParams_->IsRecordSessionActive());
    displayParams_->SetShouldPaint(true);
    displayParams_->SetContentEmpty(false);
    // Break content geometry after the display-level arm: no cached bbox and no recomputable offer.
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    displayParams_->recordSurfaceDrawables_.clear();
    screenParams_->logicalDisplayNodeDrawables_ = { displayNode_->GetRenderDrawable() };
    screenParams_->hasWindowRecordDisplay_ = true;
    screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
    processor->SetDisplaySkipInMirror(false);
    auto probe = std::make_shared<DisplayDrawProbe>(*displayDrawable_);
    const auto savedDrawCmdList = screenDrawable_->drawCmdList_;
    const auto savedDrawCmdIndex = screenDrawable_->drawCmdIndex_;
    DrawCmdIndex probeIndex;
    probeIndex.childrenIndex_ = 0;
    screenDrawable_->drawCmdList_ = { probe };
    screenDrawable_->drawCmdIndex_ = probeIndex;

    EXPECT_FALSE(RSMultiScreenUtil::HandleMirrorScreen(*screenDrawable_, mirrorSourceScreenParams_,
        *screenParams_, processor));

    screenDrawable_->drawCmdList_ = savedDrawCmdList;
    screenDrawable_->drawCmdIndex_ = savedDrawCmdIndex;
    EXPECT_EQ(processor->postProcessCount_, 0);
    EXPECT_EQ(frame->GetSurface(), nullptr);
    // DrawVirtualMirrorScreen consumes the per-pass request; the shared guard owns the cancellation.
    EXPECT_FALSE(processor->GetDisplaySkipInMirror());

    processor->surfaceFrames_.clear();
    uniParam->SetRSProcessor(nullptr);
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
    displayParams_->SetWindowRecordConfig(RSWindowRecordConfig());
    displayParams_->SetOnVirtualScreen(false);
    screenParams_->hasWindowRecordDisplay_ = false;
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
}

/**
 * @tc.name: HandleWindowRecordScreenRejectsUnsupportedRotationTest001
 * @tc.desc: A source rotation or source screen correction outside the four upright quadrants is skipped before
 *           publishing the source, including INVALID and a wrapped negative value; ROTATION_0 stays valid
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleWindowRecordScreenRejectsUnsupportedRotationTest001, TestSize.Level1)
{
    ASSERT_NE(screenDrawable_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(mirrorSourceDisplayNode_, nullptr);
    ASSERT_NE(mirrorSourceDisplayParams_, nullptr);
    ASSERT_NE(mirrorSourceScreenParams_, nullptr);
    auto sourceAdapter = mirrorSourceDisplayNode_->GetRenderDrawable();
    ASSERT_NE(sourceAdapter, nullptr);
    ASSERT_NE(sourceAdapter->GetRenderParams(), nullptr);
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    ASSERT_NE(uniParam, nullptr);

    auto processor = std::make_shared<CountingVirtualMirrorProcessor>();
    processor->canvas_ = paintFilterCanvas_;
    uniParam->SetRSProcessor(processor);
    auto arm = [&]() {
        screenParams_->logicalDisplayNodeDrawables_ = { displayNode_->GetRenderDrawable() };
        screenParams_->hasWindowRecordDisplay_ = true;
        screenDrawable_->SetDrawSkipType(DrawSkipType::NONE);
        displayParams_->mirrorSourceDrawable_ = sourceAdapter;
        ArmWindowRecordDisplayGates(*displayParams_, sourceAdapter, sourceAdapter);
    };
    auto run = [&](ScreenRotation rotation, ScreenRotation correction) {
        arm();
        mirrorSourceDisplayParams_->SetScreenRotation(rotation);
        mirrorSourceScreenParams_->screenProperty_.Set<ScreenPropertyType::CORRECTION>(
            static_cast<uint32_t>(correction));
        processor->postProcessCount_ = 0;
        RSMultiScreenUtil::HandleWindowRecordScreen(*screenDrawable_, *screenParams_, processor);
    };

    // Invalid source rotation, invalid source screen correction, and wrapped negative values all fail
    // closed before SetWindowRecordSource or any buffer acquisition.
    const std::pair<ScreenRotation, ScreenRotation> invalidCases[] = {
        { ScreenRotation::INVALID_SCREEN_ROTATION, ScreenRotation::ROTATION_0 },
        { static_cast<ScreenRotation>(-1), ScreenRotation::ROTATION_0 },
        { ScreenRotation::ROTATION_0, ScreenRotation::INVALID_SCREEN_ROTATION },
        { ScreenRotation::ROTATION_0, static_cast<ScreenRotation>(-1) },
    };
    for (const auto& [rotation, correction] : invalidCases) {
        run(rotation, correction);
        EXPECT_EQ(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
        EXPECT_EQ(processor->postProcessCount_, 0);
    }

    // Valid control: upright source rotation and correction still reach the shared lifecycle.
    run(ScreenRotation::ROTATION_270, ScreenRotation::ROTATION_90);
    EXPECT_NE(screenDrawable_->GetDrawSkipType(), DrawSkipType::SKIP_FRAME);
    EXPECT_EQ(processor->postProcessCount_, 1);
}

/**
 * @tc.name: WindowRecordMaskMetadataFailureRequestsCancelTest001
 * @tc.desc: A record mask with a null canvas or an unplaceable zero-size canvas requests the shared virtual skip
 *           instead of publishing mask content
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, WindowRecordMaskMetadataFailureRequestsCancelTest001, TestSize.Level1)
{
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);
    const bool prevMute = displayParams_->GetVirtualScreenMuteStatus();
    auto processor = std::make_shared<RSUniRenderVirtualProcessor>();
    processor->SetDisplaySkipInMirror(false);
    ArmWindowRecordCapture(*displayParams_);

    // Null canvas: HandleMirrorDisplay hands the mask straight to the processor-owned cancel request.
    displayParams_->virtualScreenMuteStatus_ = true;
    displayDrawable_->virtualDirtyNeedRefresh_ = false;
    processor->canvas_ = nullptr;
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, processor);
    EXPECT_TRUE(processor->GetDisplaySkipInMirror());
    EXPECT_FALSE(displayDrawable_->virtualDirtyNeedRefresh_);

    // Unplaceable canvas: rebuild's record mask metadata path must also fail closed.
    processor->SetDisplaySkipInMirror(false);
    displayParams_->virtualScreenMuteStatus_ = true;
    displayDrawable_->virtualDirtyNeedRefresh_ = false;
    Drawing::Canvas zeroCanvas(0, 0);
    auto zeroFilterCanvas = std::make_shared<RSPaintFilterCanvas>(&zeroCanvas);
    processor->canvas_ = zeroFilterCanvas;
    displayDrawable_->curCanvas_ = zeroFilterCanvas.get();
    RSRenderThreadParams uniParam;
    RSMultiScreenUtil::DrawVirtualMirrorRebuild(*displayDrawable_, *displayParams_, processor, uniParam);
    EXPECT_TRUE(processor->GetDisplaySkipInMirror());
    EXPECT_FALSE(displayDrawable_->virtualDirtyNeedRefresh_);

    displayParams_->virtualScreenMuteStatus_ = prevMute;
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
    displayParams_->SetWindowRecordConfig(RSWindowRecordConfig());
    displayParams_->SetOnVirtualScreen(false);
    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
}

/**
 * @tc.name: HandleMirrorDisplayRecordMaskWithoutSourceTest001
 * @tc.desc: A muted record output draws its mask before any source lookup and reports full-output current
 *           geometry plus an empty original-window rect
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSMultiScreenUtilTest, HandleMirrorDisplayRecordMaskWithoutSourceTest001, TestSize.Level1)
{
    ASSERT_NE(displayDrawable_, nullptr);
    ASSERT_NE(displayParams_, nullptr);
    ASSERT_NE(displayNode_, nullptr);
    ASSERT_NE(virtualProcessor_, nullptr);
    ASSERT_NE(paintFilterCanvas_, nullptr);

    const bool prevMute = displayParams_->GetVirtualScreenMuteStatus();
    auto surface = PushScreenInfoSurface(*virtualProcessor_);
    ASSERT_NE(surface, nullptr);
    virtualProcessor_->canvas_ = paintFilterCanvas_;

    ArmWindowRecordDisplayGates(*displayParams_, displayNode_->GetRenderDrawable(), displayNode_->GetRenderDrawable());
    displayParams_->recordWhiteListIds_.clear();
    displayParams_->recordSourceDisplayDrawable_.reset();
    displayParams_->recordSurfaceDrawables_.clear();
    displayParams_->mirrorSourceDrawable_.reset();
    displayDrawable_->SetWindowRecordBBox(Drawing::RectI());
    ASSERT_TRUE(displayParams_->GetRecordSourceDisplayDrawable().expired());
    ASSERT_TRUE(displayParams_->GetRecordWhiteListIds().empty());

    // Muted output without resolvable content still draws the mask, without resolving a source.
    displayParams_->virtualScreenMuteStatus_ = true;
    displayDrawable_->virtualDirtyNeedRefresh_ = false;
    paintFilterCanvas_->SetDisableFilterCache(true);
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    EXPECT_TRUE(displayDrawable_->virtualDirtyNeedRefresh_);
    // No mask image: DrawSecurityMask clears to black and drops the filter cache.
    EXPECT_FALSE(paintFilterCanvas_->GetDisableFilterCache());

    ExpectSurfaceScreenInfo(surface, DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE, 0, 0);

    // Control: without mute the source-less relation cannot reach a rebuild, so the record filter
    // state and dirty flag stay untouched.
    displayParams_->virtualScreenMuteStatus_ = false;
    displayDrawable_->virtualDirtyNeedRefresh_ = false;
    paintFilterCanvas_->SetDisableFilterCache(true);
    RSMultiScreenUtil::HandleMirrorDisplay(*displayDrawable_, *displayParams_, virtualProcessor_);
    EXPECT_FALSE(displayDrawable_->virtualDirtyNeedRefresh_);
    EXPECT_TRUE(paintFilterCanvas_->GetDisableFilterCache());

    displayParams_->virtualScreenMuteStatus_ = prevMute;
    displayDrawable_->curCanvas_ = paintFilterCanvas_.get();
}

} // namespace OHOS::Rosen
