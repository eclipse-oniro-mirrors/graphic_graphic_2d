/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "params/rs_render_params.h"
#include "params/rs_surface_render_params.h"
#include "limit_number.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSRenderParamsOneTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static void DisplayTestInfo();
};

void RSRenderParamsOneTest::SetUpTestCase() {}
void RSRenderParamsOneTest::TearDownTestCase() {}
void RSRenderParamsOneTest::SetUp() {}
void RSRenderParamsOneTest::TearDown() {}
void RSRenderParamsOneTest::DisplayTestInfo()
{
    return;
}

/**
 * @tc.name: SetAlphaTest001
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require: issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetAlphaTest001, TestSize.Level1)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->alpha_ = 1.0;
    float alpha = 1.0;
    params.SetAlpha(alpha);
    EXPECT_TRUE(renderParams != nullptr);
}

/**
 * @tc.name: OnSyncTest001
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require: issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, OnSyncTest001, TestSize.Level1)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[3];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    RSRenderParams params(id);
    params.childHasVisibleEffect_ = true;
    params.OnSync(target);
}

/**
 * @tc.name: ApplyAlphaAndMatrixToCanvasTest001
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require: issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, ApplyAlphaAndMatrixToCanvasTest001, TestSize.Level1)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[0];
    RSRenderParams params(id);
    Drawing::Canvas canvas;
    RSPaintFilterCanvas paintFilterCanvas(&canvas);
    params.ApplyAlphaAndMatrixToCanvas(paintFilterCanvas, true);
    EXPECT_TRUE(id != -1);
}

/**
 * @tc.name: SetAlphaOffScreenTest001
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require: issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetAlphaOffScreenTest001, TestSize.Level1)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[0];
    RSRenderParams params(id);
    bool alphaOffScreen = false;
    params.SetAlphaOffScreen(alphaOffScreen);
    EXPECT_TRUE(!params.GetAlphaOffScreen());
}

/**
 * @tc.name: SetAlphaOffScreenTest_002
 * @tc.desc: Test function SetAlphaOffScreen, alphaOffScreen != params.alphaOffScreen_
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetAlphaOffScreenTest_002, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    RSRenderParams params(id);
    bool alphaOffScreen = false;
    params.alphaOffScreen_ = true;
    EXPECT_TRUE(alphaOffScreen != params.alphaOffScreen_);

    params.SetAlphaOffScreen(alphaOffScreen);
    EXPECT_FALSE(params.GetAlphaOffScreen());
    EXPECT_TRUE(params.needSync_);
}

/**
 * @tc.name: SetAlphaTest_002
 * @tc.desc: Test function SetAlpha，alpha != renderParams->alpha_
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetAlphaTest_002, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->alpha_ = 1.0f;
    float alpha = 0.1;
    EXPECT_TRUE(alpha != renderParams->alpha_);

    renderParams->SetAlpha(alpha);
    EXPECT_TRUE(renderParams->needSync_);
}

/**
 * @tc.name: ApplyAlphaAndMatrixToCanvasTest_002
 * @tc.desc: Test function ApplyAlphaAndMatrixToCanvas, UNLIKELY(HasSandBox()) is true and applyMatrix is false
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, ApplyAlphaAndMatrixToCanvasTest_002, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->hasSandBox_ = true;
    EXPECT_TRUE(UNLIKELY(renderParams->HasSandBox()));
    Drawing::Canvas canvas;
    RSPaintFilterCanvas paintFilterCanvas(&canvas);
    renderParams->alpha_ = 0.5;
    auto alphaClamped = std::clamp(renderParams->alpha_, 0.f, 1.f);
    Drawing::Matrix matrix;
    matrix.SetMatrix(1, 2, 3, 4, 5, 6, 7, 8, 9);
    renderParams->SetParentSurfaceMatrix(matrix);
    renderParams->matrix_.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);

    Drawing::Matrix canvasMatrix;
    canvasMatrix.SetMatrix(2, 2, 3, 4, 5, 6, 7, 8, 9);
    RSPaintFilterCanvas::CanvasStatus canvasStatus = {0.1, canvasMatrix, nullptr};
    paintFilterCanvas.SetCanvasStatus(canvasStatus);

    renderParams->ApplyAlphaAndMatrixToCanvas(paintFilterCanvas, false);
    EXPECT_EQ(paintFilterCanvas.GetCanvasStatus().matrix_, canvasMatrix); // not SetMatrix
}

/**
 * @tc.name: ApplyAlphaAndMatrixToCanvasTest_003
 * @tc.desc: Test function ApplyAlphaAndMatrixToCanvas, UNLIKELY(HasSandBox()) and applyMatrix is true
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, ApplyAlphaAndMatrixToCanvasTest_003, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->hasSandBox_ = true;
    EXPECT_TRUE(UNLIKELY(renderParams->HasSandBox()));
    Drawing::Canvas canvas;
    RSPaintFilterCanvas paintFilterCanvas(&canvas);
    renderParams->alpha_ = 0.5;
    auto alphaClamped = std::clamp(renderParams->alpha_, 0.f, 1.f);

    Drawing::Matrix matrix;
    matrix.SetMatrix(1, 2, 3, 4, 5, 6, 7, 8, 9);
    renderParams->SetParentSurfaceMatrix(matrix);
    renderParams->matrix_.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    renderParams->ApplyAlphaAndMatrixToCanvas(paintFilterCanvas, true);
    EXPECT_EQ(paintFilterCanvas.GetCanvasStatus().matrix_, renderParams->GetParentSurfaceMatrix()); // SetMatrix
}

/**
 * @tc.name: ApplyAlphaAndMatrixToCanvasTest_004
 * @tc.desc: Test function ApplyAlphaAndMatrixToCanvas， not HasSandBox and not applyMatrix
 * and alpha_ < 1.0f and (drawingCacheType_ == RSDrawingCacheType::FORCED_CACHE) and alphaOffScreen_ is false
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, ApplyAlphaAndMatrixToCanvasTest_004, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->hasSandBox_ = false;
    EXPECT_FALSE(UNLIKELY(renderParams->HasSandBox()));
    Drawing::Canvas canvas;
    RSPaintFilterCanvas paintFilterCanvas(&canvas);
    renderParams->alpha_ = 0.5;

    renderParams->drawingCacheType_ = RSDrawingCacheType::FORCED_CACHE;
    renderParams->alphaOffScreen_ = false;
    paintFilterCanvas.envStack_.top().hasOffscreenLayer_ = false;
    renderParams->ApplyAlphaAndMatrixToCanvas(paintFilterCanvas, false);
    EXPECT_TRUE(paintFilterCanvas.envStack_.top().hasOffscreenLayer_); // SaveLayer
}

/**
 * @tc.name: ApplyAlphaAndMatrixToCanvasTest_005
 * @tc.desc: Test function ApplyAlphaAndMatrixToCanvas， not HasSandBox and not applyMatrix
 * and alpha_ < 1.0f and (drawingCacheType_ != RSDrawingCacheType::FORCED_CACHE) and alphaOffScreen_ is true
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, ApplyAlphaAndMatrixToCanvasTest_005, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->hasSandBox_ = false;
    EXPECT_FALSE(UNLIKELY(renderParams->HasSandBox()));
    Drawing::Canvas canvas;
    RSPaintFilterCanvas paintFilterCanvas(&canvas);
    renderParams->alpha_ = 0.5;

    renderParams->drawingCacheType_ = RSDrawingCacheType::TARGETED_CACHE;
    renderParams->alphaOffScreen_ = true;
    paintFilterCanvas.envStack_.top().hasOffscreenLayer_ = false;
    renderParams->ApplyAlphaAndMatrixToCanvas(paintFilterCanvas, false);
    EXPECT_TRUE(paintFilterCanvas.envStack_.top().hasOffscreenLayer_); // SaveLayer
}

/**
 * @tc.name: SetFrameRectTest_001
 * @tc.desc: Test function SetFrameRect
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetFrameRectTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    Drawing::RectF frameRect(0.0f, 0.0f, 1.0f, 1.0f);

    renderParams->needSync_ = false;
    renderParams->frameRect_ = frameRect;
    renderParams->SetFrameRect(frameRect);
    EXPECT_FALSE(renderParams->needSync_);
}

/**
 * @tc.name: SetBoundsRectTest_001
 * @tc.desc: Test function SetBoundsRect
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetBoundsRectTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    Drawing::RectF boundsRect(0.0f, 0.0f, 1.0f, 1.0f);

    renderParams->needSync_ = false;
    renderParams->boundsRect_ = boundsRect;
    renderParams->SetBoundsRect(boundsRect);
    EXPECT_FALSE(renderParams->needSync_);
}

/**
 * @tc.name: SetLocalDrawRectTest_001
 * @tc.desc: Test function SetLocalDrawRect
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetLocalDrawRectTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    OHOS::Rosen::RectT<float> localDrawRect(0.0f, 0.0f, 1.0f, 1.0f);
    renderParams->localDrawRect_.left_ = 0.0f;
    renderParams->localDrawRect_.top_ = 0.0f;
    renderParams->localDrawRect_.width_ = 1.3;
    renderParams->localDrawRect_.height_ = 1.3;
    EXPECT_FALSE(renderParams->localDrawRect_.IsNearEqual(localDrawRect));
    renderParams->needSync_ = false;

    renderParams->SetLocalDrawRect(localDrawRect);
    EXPECT_TRUE(renderParams->needSync_);
}

/**
 * @tc.name: SetHasSandBoxTest_001
 * @tc.desc: Test function SetHasSandBox
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetHasSandBoxTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->needSync_ = false;
    renderParams->hasSandBox_ = false;
    bool hasSandbox = true;

    EXPECT_NE(renderParams->hasSandBox_, hasSandbox);
    renderParams->SetHasSandBox(hasSandbox);
    EXPECT_TRUE(renderParams->needSync_);
}

/**
 * @tc.name: SetContentEmptyTest_001
 * @tc.desc: Test function SetContentEmpty
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetContentEmptyTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->contentEmpty_ = false;
    bool contentEmpty = true;
    renderParams->needSync_ = false;

    renderParams->SetContentEmpty(contentEmpty);
    EXPECT_TRUE(renderParams->needSync_);
}

/**
 * @tc.name: GetLocalDrawRectTest_001
 * @tc.desc: Test function GetLocalDrawRect
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, GetLocalDrawRectTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    OHOS::Rosen::RectT<float> localDrawRect(0.0f, 0.0f, 1.0f, 1.0f);
    renderParams->localDrawRect_.left_ = 0.0f;
    renderParams->localDrawRect_.top_ = 0.0f;
    renderParams->localDrawRect_.width_ = 1.0f;
    renderParams->localDrawRect_.height_ = 1.0f;
    EXPECT_EQ(renderParams->GetLocalDrawRect(), localDrawRect);
}

/**
 * @tc.name: SetChildHasVisibleEffectTest_001
 * @tc.desc: Test function SetChildHasVisibleEffect
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetChildHasVisibleEffectTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    bool val = true;
    renderParams->childHasVisibleEffect_   = val;
    renderParams->needSync_ = false;

    renderParams->SetChildHasVisibleEffect(val);
    EXPECT_FALSE(renderParams->needSync_);
}

/**
 * @tc.name: SetChildHasVisibleFilterTest_001
 * @tc.desc: Test function SetChildHasVisibleFilter
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetChildHasVisibleFilterTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    bool val = true;
    renderParams->childHasVisibleFilter_  = val;
    renderParams->needSync_ = false;

    renderParams->SetChildHasVisibleFilter(val);
    EXPECT_FALSE(renderParams->needSync_);
}

/**
 * @tc.name: SetDrawingCacheIncludePropertyTest_001
 * @tc.desc: Test function SetDrawingCacheIncludeProperty
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetDrawingCacheIncludePropertyTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());

    bool includeProperty = false;
    renderParams->drawingCacheIncludeProperty_  = true;
    renderParams->needSync_ = false;

    EXPECT_NE(renderParams->drawingCacheIncludeProperty_, includeProperty);
    renderParams->SetDrawingCacheIncludeProperty(includeProperty);
    EXPECT_TRUE(renderParams->needSync_);
}

/**
 * @tc.name: GetNeedUpdateCacheTest_001
 * @tc.desc: Test function GetNeedUpdateCache
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, GetNeedUpdateCacheTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->isNeedUpdateCache_ = false;

    EXPECT_FALSE(renderParams->GetNeedUpdateCache());
}

/**
 * @tc.name: SetNeedFilterTest_001
 * @tc.desc: Test function SetNeedFilter
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetNeedFilterTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->needFilter_ = false;
    bool needFilter = true;
    renderParams->needSync_ = false;

    renderParams->SetNeedFilter(needFilter);
    EXPECT_TRUE(renderParams->needSync_);
}

/**
 * @tc.name: OpincSetCacheChangeFlagTest_001
 * @tc.desc: Test function OpincSetCacheChangeFlag, not lastFrameSynced
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, OpincSetCacheChangeFlagTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->isOpincStateChanged_ = false;
    renderParams->needSync_  = false;

    bool state = true;
    bool lastFrameSynced = false;
    renderParams->OpincSetCacheChangeFlag(state, lastFrameSynced);
    EXPECT_TRUE(renderParams->needSync_);
    EXPECT_TRUE(renderParams->isOpincStateChanged_);
}
/**
 * @tc.name: GetCanvasDrawingSurfaceChangedTest_001
 * @tc.desc: Test function GetCanvasDrawingSurfaceChanged
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, GetCanvasDrawingSurfaceChangedTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->canvasDrawingNodeSurfaceChanged_ = false;

    EXPECT_FALSE(renderParams->GetCanvasDrawingSurfaceChanged());
}
/**
 * @tc.name: OnCanvasDrawingSurfaceChangeTest_001
 * @tc.desc: Test function OnCanvasDrawingSurfaceChange
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, OnCanvasDrawingSurfaceChangeTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());

    constexpr NodeId targetId = TestSrc::limitNumber::Uint64[5];
    const std::unique_ptr<RSRenderParams> targetParams = std::make_unique<RSRenderParams>(targetId);

    renderParams->canvasDrawingNodeSurfaceChanged_ = true;
    renderParams->surfaceParams_.width = 2.0;
    renderParams->surfaceParams_.height = 2.0;

    renderParams->OnCanvasDrawingSurfaceChange(targetParams);
    EXPECT_EQ(targetParams->canvasDrawingNodeSurfaceChanged_, true);
    EXPECT_EQ(targetParams->surfaceParams_.width, renderParams->surfaceParams_.width);
    EXPECT_FALSE(renderParams->canvasDrawingNodeSurfaceChanged_);
}
/**
 * @tc.name: GetCanvasDrawingSurfaceParamsTest_001
 * @tc.desc: Test function GetCanvasDrawingSurfaceParams
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, GetCanvasDrawingSurfaceParamsTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->surfaceParams_.height = 2;
    renderParams->surfaceParams_.width = 3;
    auto surfaceParams = renderParams->GetCanvasDrawingSurfaceParams();
    EXPECT_EQ(surfaceParams.height, renderParams->surfaceParams_.height);
}
/**
 * @tc.name: SetForegroundFilterCacheTest_001
 * @tc.desc: Test function SetForegroundFilterCache
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetForegroundFilterCacheTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());
    renderParams->needSync_ = false;
    renderParams->foregroundFilterCache_ = std::make_shared<RSFilter>(); // type_(FilterType::NONE)
    auto foregroundFilterCache = std::make_shared<RSFilter>();
    foregroundFilterCache->type_ = RSFilter::FilterType::BLUR;
    EXPECT_NE(foregroundFilterCache, renderParams->foregroundFilterCache_);

    renderParams->SetForegroundFilterCache(foregroundFilterCache);

    EXPECT_TRUE(renderParams->needSync_);
}
/**
 * @tc.name: OnSyncTest_002
 * @tc.desc: Test function OnSync
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, OnSyncTest_002, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());

    constexpr NodeId targetId = TestSrc::limitNumber::Uint64[5];
    const std::unique_ptr<RSRenderParams> targetParams = std::make_unique<RSRenderParams>(targetId);

    targetParams->drawingCacheType_ = RSDrawingCacheType::DISABLED_CACHE;
    renderParams->drawingCacheType_ = RSDrawingCacheType::FORCED_CACHE;
    renderParams->dirtyType_.set(RSRenderParamsDirtyType::DRAWING_CACHE_TYPE_DIRTY);

    renderParams->OnSync(targetParams);
}
/**
 * @tc.name: GetLayerInfoTest_001
 * @tc.desc: Test function GetLayerInfo
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, GetLayerInfoTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());

    RSLayerInfo defaultLayerInfo = {};
}
/**
 * @tc.name: SetUiFirstRootNodeTest_001
 * @tc.desc: Test function SetUiFirstRootNode
 * @tc.type:FUNC
 * @tc.require:issueIB7RF8
 */
HWTEST_F(RSRenderParamsOneTest, SetUiFirstRootNodeTest_001, TestSize.Level2)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    std::unique_ptr<RSRenderParams> target = std::make_unique<RSRenderParams>(id);
    RSRenderParams params(id);
    auto renderParams = static_cast<RSRenderParams*>(target.get());

    renderParams->uifirstRootNodeId_ = 0;
    NodeId uifirstRootNodeId = 1;
    renderParams->needSync_ = false;
    renderParams->SetUiFirstRootNode(uifirstRootNodeId);
    EXPECT_TRUE(renderParams->needSync_);
}
} // namespace OHOS::Rosen