/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "drawable/rs_property_drawable_utils.h"
#include "draw/surface.h"
#include "property/rs_properties_painter.h"
#include "render/rs_drawing_filter.h"
#include "skia_adapter/skia_image.h"
#include "skia_adapter/skia_image_info.h"
#include "skia_adapter/skia_surface.h"
#include "render/rs_linear_gradient_blur_shader_filter.h"
#include "render/rs_magnifier_shader_filter.h"

namespace OHOS::Rosen {
class RSPropertyDrawableUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSPropertyDrawableUtilsTest::SetUpTestCase() {}
void RSPropertyDrawableUtilsTest::TearDownTestCase() {}
void RSPropertyDrawableUtilsTest::SetUp() {}
void RSPropertyDrawableUtilsTest::TearDown() {}

/**
 * @tc.name: RRect2DrawingRRectAndCreateShadowPathTest001
 * @tc.desc: RRect2DrawingRRect and CreateShadowPath test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, RRect2DrawingRRectAndCreateShadowPathTest001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);
    Drawing::Path path;
    path.AddRect({0, 0, 10, 10});
    std::shared_ptr<RSPath> rsPath = RSPath::CreateRSPath(path);
    EXPECT_NE(rsPath, nullptr);
    std::shared_ptr<RSPath> clipBounds = std::make_shared<RSPath>();
    RRect rrect(RectT<float>(0.0f, 0.0f, 1.0f, 1.0f), 0.0f, 1.0f);
    rsPropertyDrawableUtils->CreateShadowPath(rsPath, clipBounds, rrect);
    rsPath = nullptr;
    rsPropertyDrawableUtils->CreateShadowPath(rsPath, clipBounds, rrect);
    clipBounds = nullptr;
    rsPropertyDrawableUtils->CreateShadowPath(rsPath, clipBounds, rrect);
}

/**
 * @tc.name: GetRRectForDrawingBorderTest002
 * @tc.desc: GetRRectForDrawingBorder test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, GetRRectForDrawingBorderTest002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);
    RSProperties properties;
    properties.rrect_ = RRect(RectT<float>(0.0f, 0.0f, 1.0f, 1.0f), 0.0f, 1.0f);
    std::shared_ptr<RSBorder> border = std::make_shared<RSBorder>();
    EXPECT_NE(border, nullptr);
    EXPECT_EQ(rsPropertyDrawableUtils->GetRRectForDrawingBorder(properties, border, false),
        RRect(RectT<float>(0.0f, 0.0f, 1.0f, 1.0f), 0.0f, 1.0f));
    EXPECT_EQ(rsPropertyDrawableUtils->GetInnerRRectForDrawingBorder(properties, border, true),
        RRect(RectT<float>(0.0f, 0.0f, 1.0f, 1.0f), 0.0f, 1.0f));
    border = nullptr;
    rsPropertyDrawableUtils->GetRRectForDrawingBorder(properties, border, false);
    rsPropertyDrawableUtils->GetInnerRRectForDrawingBorder(properties, border, true);
}

/**
 * @tc.name: GetDarkColorTest004
 * @tc.desc: GetDarkColor test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, GetDarkColorTest004, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);
    RSColor color(255, 255, 255, 255);
    rsPropertyDrawableUtils->GetDarkColor(color);
}

/**
 * @tc.name: DrawShadowAndCeilMatrixTransTest005
 * @tc.desc: DrawShadow and CeilMatrixTrans test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, DrawShadowAndCeilMatrixTransTest005, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);
    Drawing::Canvas canvasTest1;
    Drawing::Path pathTest1;
    Color spotColor;
    rsPropertyDrawableUtils->DrawShadow(&canvasTest1, pathTest1, 1.0f, 1.0f, 1.0f, false, spotColor);
    Drawing::Canvas canvasTest2;
    Drawing::Path pathTest2;
    rsPropertyDrawableUtils->DrawShadow(&canvasTest2, pathTest2, 1.0f, 1.0f, 1.0f, true, spotColor);
}

/**
 * @tc.name: DrawAndBeginForegroundFilterTest006
 * @tc.desc: DrawFilter and BeginForegroundFilter test
 * @tc.type: FUNC
 * @tc.require:issueIA5Y41
 */
HWTEST_F(RSPropertyDrawableUtilsTest, DrawAndBeginForegroundFilterTest006, testing::ext::TestSize.Level1)
{
    // first: DrawFilter test
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);
    Drawing::Canvas canvasTest1;
    RSPaintFilterCanvas paintFilterCanvasTest1(&canvasTest1);
    std::shared_ptr<RSDrawingFilter> rsFilter = nullptr;
    std::unique_ptr<RSFilterCacheManager> cacheManager = std::make_unique<RSFilterCacheManager>();
    paintFilterCanvasTest1.surface_ = nullptr;
    rsPropertyDrawableUtils->DrawFilter(&paintFilterCanvasTest1, rsFilter, cacheManager, false, false);
    std::vector<std::pair<float, float>> fractionStops;
    auto para = std::make_shared<RSLinearGradientBlurPara>(1.f, fractionStops, GradientDirection::LEFT);
    auto rsFilterTest = std::make_shared<RSLinearGradientBlurShaderFilter>(para, 1.f, 1.f);
    rsFilterTest->type_ = RSShaderFilter::LINEAR_GRADIENT_BLUR;
    EXPECT_NE(rsFilterTest, nullptr);
    rsFilter = std::make_shared<RSDrawingFilter>(rsFilterTest);
    EXPECT_NE(rsFilter, nullptr);
    rsFilter->type_ = RSFilter::BLUR;
    rsFilter->imageFilter_ = std::make_shared<Drawing::ImageFilter>();
    EXPECT_NE(rsFilter->imageFilter_, nullptr);
    rsPropertyDrawableUtils->DrawFilter(&paintFilterCanvasTest1, rsFilter, cacheManager, true, false);
    rsPropertyDrawableUtils->DrawFilter(nullptr, rsFilter, cacheManager, false, false);
    auto surface = Drawing::Surface::MakeRasterN32Premul(10, 10);
    paintFilterCanvasTest1.surface_ = surface.get();
    paintFilterCanvasTest1.SetDisableFilterCache(false);
    rsPropertyDrawableUtils->DrawFilter(&paintFilterCanvasTest1, rsFilter, cacheManager, true, false);
    paintFilterCanvasTest1.SetDisableFilterCache(true);
    rsPropertyDrawableUtils->DrawFilter(&paintFilterCanvasTest1, rsFilter, cacheManager, true, false);
    auto magnifierParams = std::make_shared<RSMagnifierParams>();
    auto magnifierFilter = std::make_shared<RSMagnifierShaderFilter>(magnifierParams);
    magnifierFilter->type_ = RSShaderFilter::MAGNIFIER;
    rsFilter = std::make_shared<RSDrawingFilter>(magnifierFilter);
    rsFilter->type_ = RSFilter::BLUR;
    rsFilter->imageFilter_ = std::make_shared<Drawing::ImageFilter>();
    rsPropertyDrawableUtils->DrawFilter(&paintFilterCanvasTest1, rsFilter, cacheManager, true, false);

    // second: BeginForegroundFilter test
    Drawing::Canvas canvasTest2;
    RSPaintFilterCanvas paintFilterCanvasTest2(&canvasTest2);
    paintFilterCanvasTest2.surface_ = nullptr;
    RectF bounds = RectF(1.0f, 1.0f, 1.0f, 1.0f);
    rsPropertyDrawableUtils->BeginForegroundFilter(paintFilterCanvasTest2, bounds);
    Drawing::Surface surfaceTest2;
    paintFilterCanvasTest2.surface_ = &surfaceTest2;
    rsPropertyDrawableUtils->BeginForegroundFilter(paintFilterCanvasTest2, bounds);
    auto surfaceTest3 = Drawing::Surface::MakeRasterN32Premul(10, 10);
    paintFilterCanvasTest2.surface_ = surfaceTest3.get();
    rsPropertyDrawableUtils->BeginForegroundFilter(paintFilterCanvasTest2, bounds);
    EXPECT_NE(paintFilterCanvasTest2.surface_->Width(), 0);
    EXPECT_NE(paintFilterCanvasTest2.surface_->Height(), 0);

    // third: DrawFilterWithDRM test
    Drawing::Canvas canvasTest3;
    RSPaintFilterCanvas paintFilterCanvasTest3(&canvasTest3);
    rsPropertyDrawableUtils->DrawFilterWithDRM(&paintFilterCanvasTest3, true);
    rsPropertyDrawableUtils->DrawFilterWithDRM(&paintFilterCanvasTest3, false);
}

/**
 * @tc.name: BDrawForegroundFilterTest007
 * @tc.desc: DrawForegroundFilter test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, BDrawForegroundFilterTest007, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);
    Drawing::Canvas canvasTest;
    RSPaintFilterCanvas paintFilterCanvas(&canvasTest);
    std::shared_ptr<RSFilter> rsFilter = nullptr;
    rsPropertyDrawableUtils->DrawForegroundFilter(paintFilterCanvas, rsFilter);
    paintFilterCanvas.surface_ = nullptr;
    rsFilter = std::make_shared<RSFilter>();
    rsPropertyDrawableUtils->DrawForegroundFilter(paintFilterCanvas, rsFilter);
    Drawing::Surface surface;
    paintFilterCanvas.surface_ = &surface;
    rsPropertyDrawableUtils->DrawForegroundFilter(paintFilterCanvas, rsFilter);
}

/**
 * @tc.name: RSPropertyDrawableUtilsTest008
 * @tc.desc: GetAndResetBlurCnt and DrawBackgroundEffect test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, RSPropertyDrawableUtilsTest008, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);
    // GetAndResetBlurCnt test
    rsPropertyDrawableUtils->g_blurCnt = 0;
    EXPECT_EQ(rsPropertyDrawableUtils->GetAndResetBlurCnt(), 0);
    // DrawBackgroundEffect test
    Drawing::Canvas canvasTest1;
    RSPaintFilterCanvas paintFilterCanvas(&canvasTest1);
    std::shared_ptr<RSFilter> rsFilter = nullptr;
    std::unique_ptr<RSFilterCacheManager> cacheManager = std::make_unique<RSFilterCacheManager>();
    Drawing::RectI bounds(0.0, 0.0, 400.0, 400.0);
    rsPropertyDrawableUtils->DrawBackgroundEffect(&paintFilterCanvas, rsFilter, cacheManager, false, bounds);
    rsFilter = std::make_shared<RSFilter>();
    rsFilter->type_ = RSFilter::NONE;
    paintFilterCanvas.surface_ = nullptr;
    rsPropertyDrawableUtils->DrawBackgroundEffect(&paintFilterCanvas, rsFilter, cacheManager, false, bounds);
    Drawing::Surface surface;
    paintFilterCanvas.surface_ = &surface;
    Drawing::Canvas canvasTest2;
    paintFilterCanvas.canvas_ = &canvasTest2;
    rsPropertyDrawableUtils->DrawBackgroundEffect(&paintFilterCanvas, rsFilter, cacheManager, false, bounds);
    paintFilterCanvas.SetDisableFilterCache(true);
    auto surfaceTwo = Drawing::Surface::MakeRasterN32Premul(10, 10);
    paintFilterCanvas.surface_ = surfaceTwo.get();
    rsPropertyDrawableUtils->DrawBackgroundEffect(&paintFilterCanvas, rsFilter, cacheManager, false, bounds);
    int lastBlurCnt = rsPropertyDrawableUtils->g_blurCnt;
    ASSERT_NE(lastBlurCnt, 0);
    rsPropertyDrawableUtils->DrawBackgroundEffect(nullptr, rsFilter, cacheManager, false, bounds);
    ASSERT_EQ(lastBlurCnt, lastBlurCnt);
}

/**
 * @tc.name: DrawColorFilterTest009
 * @tc.desc: DrawColorFilter test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, DrawColorFilterTest009, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);

    Drawing::Canvas canvasTest1;
    std::shared_ptr<Drawing::ColorFilter> colorFilter = nullptr;
    rsPropertyDrawableUtils->DrawColorFilter(&canvasTest1, colorFilter);

    colorFilter = std::make_shared<Drawing::ColorFilter>();
    Drawing::Canvas canvasTest2;
    RSPaintFilterCanvas paintFilterCanvas(&canvasTest2);
    paintFilterCanvas.surface_ = nullptr;
    rsPropertyDrawableUtils->DrawColorFilter(&paintFilterCanvas, colorFilter);

    Drawing::Surface surface;
    paintFilterCanvas.surface_ = &surface;
    rsPropertyDrawableUtils->DrawColorFilter(&paintFilterCanvas, colorFilter);
}

/**
 * @tc.name: DrawLightUpEffectTest010
 * @tc.desc: DrawLightUpEffect and DrawDynamicDim test
 * @tc.type: FUNC
 * @tc.require:issueIA5Y41
 */
HWTEST_F(RSPropertyDrawableUtilsTest, DrawLightUpEffectTest010, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest1 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest1, nullptr);
    Drawing::Canvas canvasTest1;
    RSPaintFilterCanvas paintFilterCanvasTest1(&canvasTest1);
    paintFilterCanvasTest1.surface_ = nullptr;
    rsPropertyDrawableUtilsTest1->DrawLightUpEffect(&paintFilterCanvasTest1, -1.0f);
    rsPropertyDrawableUtilsTest1->DrawLightUpEffect(&paintFilterCanvasTest1, 1.0f);
    rsPropertyDrawableUtilsTest1->DrawLightUpEffect(&paintFilterCanvasTest1, 0.0f);
    Drawing::Surface surfaceTest1;
    paintFilterCanvasTest1.surface_ = &surfaceTest1;
    rsPropertyDrawableUtilsTest1->DrawLightUpEffect(&paintFilterCanvasTest1, 0.0f);

    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest2 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest2, nullptr);
    Drawing::Canvas canvasTest2;
    RSPaintFilterCanvas paintFilterCanvasTest2(&canvasTest2);
    paintFilterCanvasTest2.surface_ = nullptr;
    rsPropertyDrawableUtilsTest2->DrawDynamicDim(&paintFilterCanvasTest2, -1.0f);
    rsPropertyDrawableUtilsTest1->DrawDynamicDim(&paintFilterCanvasTest2, 1.0f);
    rsPropertyDrawableUtilsTest2->DrawDynamicDim(&paintFilterCanvasTest2, 0.0f);
    Drawing::Surface surfaceTest2;
    paintFilterCanvasTest2.surface_ = &surfaceTest2;
    std::shared_ptr<Drawing::SkiaSurface> implTest2 = std::make_shared<Drawing::SkiaSurface>();
    EXPECT_NE(implTest2, nullptr);
    implTest2->skSurface_ = nullptr;
    paintFilterCanvasTest2.surface_->impl_ = implTest2;
    rsPropertyDrawableUtilsTest2->DrawDynamicDim(&paintFilterCanvasTest2, 0.0f);
}

/**
 * @tc.name: TransformativeShaderTest011
 * @tc.desc: MakeDynamicDimShader MakeBinarizationShader MakeDynamicBrightnessBlender MakeDynamicBrightnessBuilder test
 * @tc.type: FUNC
 * @tc.require:issueIA5Y41
 */
HWTEST_F(RSPropertyDrawableUtilsTest, TransformativeShaderTest011, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest1 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest1, nullptr);
    std::shared_ptr<Drawing::ShaderEffect> imageShaderTest1 = std::make_shared<Drawing::ShaderEffect>();
    EXPECT_NE(rsPropertyDrawableUtilsTest1->MakeDynamicDimShader(1.0f, imageShaderTest1), nullptr);

    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest2 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest2, nullptr);
    std::shared_ptr<Drawing::ShaderEffect> imageShaderTest2 = std::make_shared<Drawing::ShaderEffect>();
    EXPECT_NE(rsPropertyDrawableUtilsTest2->MakeBinarizationShader(1.0f, 1.0f, 1.0f, 1.0f, imageShaderTest2), nullptr);

    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest3 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest3, nullptr);
    EXPECT_NE(rsPropertyDrawableUtilsTest3->MakeDynamicBrightnessBuilder(), nullptr);

    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest4 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest4, nullptr);
    RSDynamicBrightnessPara params;
    EXPECT_NE(rsPropertyDrawableUtilsTest4->MakeDynamicBrightnessBlender(params), nullptr);
}
/**
 * @tc.name: DrawBinarizationTest012
 * @tc.desc: DrawBinarization test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, DrawBinarizationTest012, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest, nullptr);

    Drawing::Canvas canvasTest;
    RSPaintFilterCanvas paintFilterCanvasTest(&canvasTest);

    std::optional<Vector4f> aiInvert = std::nullopt;
    rsPropertyDrawableUtilsTest->DrawBinarization(&paintFilterCanvasTest, aiInvert);

    aiInvert = 1.0f;
    paintFilterCanvasTest.surface_ = nullptr;
    rsPropertyDrawableUtilsTest->DrawBinarization(&paintFilterCanvasTest, aiInvert);

    Drawing::Surface surface;
    paintFilterCanvasTest.surface_ = &surface;
    rsPropertyDrawableUtilsTest->DrawBinarization(&paintFilterCanvasTest, aiInvert);
}

/**
 * @tc.name: DrawPixelStretchTest013
 * @tc.desc: DrawPixelStretch test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, DrawPixelStretchTest013, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest, nullptr);
    Drawing::Canvas canvasTest;
    RSPaintFilterCanvas paintFilterCanvasTest(&canvasTest);
    RectF boundsRect = RectF(0.0f, 0.0f, 1.0f, 1.0f);
    std::optional<Vector4f> pixelStretch = std::nullopt;
    rsPropertyDrawableUtilsTest->DrawPixelStretch(
        &paintFilterCanvasTest, pixelStretch, boundsRect, true, Drawing::TileMode::CLAMP);
    pixelStretch = 1.0f;
    paintFilterCanvasTest.surface_ = nullptr;
    rsPropertyDrawableUtilsTest->DrawPixelStretch(
        &paintFilterCanvasTest, pixelStretch, boundsRect, true, Drawing::TileMode::CLAMP);
    Drawing::Surface surface;
    paintFilterCanvasTest.surface_ = &surface;
    rsPropertyDrawableUtilsTest->DrawPixelStretch(
        &paintFilterCanvasTest, pixelStretch, boundsRect, true, Drawing::TileMode::CLAMP);
}

/**
 * @tc.name: DrawShadowTestAndDrawUseEffectTest014
 * @tc.desc: DrawShadow and DrawUseEffect test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, DrawShadowTestAndDrawUseEffectTest014, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest1 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest1, nullptr);
    Drawing::Canvas canvasTest1;
    Drawing::Path path;
    Color spotColor;
    rsPropertyDrawableUtilsTest1->DrawShadow(&canvasTest1, path, 1.0f, 1.0f, 1.0f, true, spotColor);
    EXPECT_EQ(spotColor.GetAlpha(), 0);

    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest2 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest2, nullptr);
    Drawing::Canvas canvasTest2;
    RSPaintFilterCanvas paintFilterCanvasTest(&canvasTest2);
    std::shared_ptr<RSPaintFilterCanvas::CachedEffectData> effectData = nullptr;
    paintFilterCanvasTest.SetEffectData(effectData);
    rsPropertyDrawableUtilsTest2->DrawUseEffect(&paintFilterCanvasTest);
    effectData = std::make_shared<RSPaintFilterCanvas::CachedEffectData>();
    EXPECT_NE(effectData, nullptr);
    effectData->cachedImage_ = nullptr;
    paintFilterCanvasTest.SetEffectData(effectData);
    rsPropertyDrawableUtilsTest2->DrawUseEffect(&paintFilterCanvasTest);

    std::shared_ptr<Drawing::Image> cachedImage = std::make_shared<Drawing::Image>();
    EXPECT_NE(cachedImage, nullptr);
    effectData->cachedImage_ = cachedImage;
    paintFilterCanvasTest.SetEffectData(effectData);
    paintFilterCanvasTest.SetVisibleRect(Drawing::Rect(0.0f, 0.0f, 1.0f, 1.0f));
    rsPropertyDrawableUtilsTest2->DrawUseEffect(&paintFilterCanvasTest);
}

/**
 * @tc.name: GetInvertedBackgroundColorTest015
 * @tc.desc: BeginBlender and GetInvertBackgroundColor test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, GetInvertedBackgroundColorTest015, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest1 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest1, nullptr);
    Drawing::Canvas canvasTest1;
    RSPaintFilterCanvas paintFilterCanvasTest1(&canvasTest1);
    paintFilterCanvasTest1.envStack_.top().hasOffscreenLayer_ = false;
    std::shared_ptr<Drawing::Blender> blender = std::make_shared<Drawing::Blender>();
    EXPECT_NE(blender, nullptr);

    rsPropertyDrawableUtilsTest1->BeginBlender(paintFilterCanvasTest1, blender, 0, true);
    EXPECT_EQ(paintFilterCanvasTest1.alphaStack_.size(), 1);
    rsPropertyDrawableUtilsTest1->BeginBlender(paintFilterCanvasTest1, blender, 1, true);
    EXPECT_EQ(paintFilterCanvasTest1.alphaStack_.size(), 2);

    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest2 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest2, nullptr);
    Drawing::Canvas canvasTest2;
    RSPaintFilterCanvas paintFilterCanvasTest2(&canvasTest2);
    Color backgroundColor;
    backgroundColor.alpha_ = 0xff;
    EXPECT_EQ(rsPropertyDrawableUtilsTest2->GetInvertBackgroundColor(
                  paintFilterCanvasTest2, false, Vector4f(0.0f, 0.0f, 0.0f, 1.0f), backgroundColor),
        RSPropertyDrawableUtils::CalculateInvertColor(backgroundColor));

    backgroundColor.alpha_ = 0;
    Drawing::Surface surfaceTest2;
    paintFilterCanvasTest2.surface_ = &surfaceTest2;
    rsPropertyDrawableUtilsTest2->GetInvertBackgroundColor(
        paintFilterCanvasTest2, false, Vector4f(0.0f, 0.0f, 0.0f, 1.0f), backgroundColor);
}

/**
 * @tc.name: IsDangerousBlendModeAndEndBlenderTest016
 * @tc.desc: IsDangerousBlendMode and EndBlender test
 * @tc.type: FUNC
 * @tc.require:issueI9SCBR
 */
HWTEST_F(RSPropertyDrawableUtilsTest, IsDangerousBlendModeAndEndBlenderTest016, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest1 = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest1, nullptr);
    EXPECT_EQ(rsPropertyDrawableUtilsTest1->IsDangerousBlendMode(1, 0), 0);
    EXPECT_EQ(rsPropertyDrawableUtilsTest1->IsDangerousBlendMode(1, 1), 1);

    Drawing::Canvas canvasTest;
    RSPaintFilterCanvas paintFilterCanvasTest1(&canvasTest);
    rsPropertyDrawableUtilsTest1->EndBlender(paintFilterCanvasTest1, 0);
    rsPropertyDrawableUtilsTest1->EndBlender(paintFilterCanvasTest1, 1);
}

/**
 * @tc.name: GetColorForShadowSynTest017
 * @tc.desc: GetColorForShadowSyn and GpuScaleImage test
 * @tc.type: FUNC
 * @tc.require:issueIA5Y41
 */
HWTEST_F(RSPropertyDrawableUtilsTest, GetColorForShadowSynTest017, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest, nullptr);

    Drawing::Canvas canvasTest1;
    Drawing::Path path;
    Color color;
    RSPaintFilterCanvas paintFilterCanvas(&canvasTest1);
    paintFilterCanvas.surface_ = nullptr;
    rsPropertyDrawableUtilsTest->GetColorForShadowSyn(&paintFilterCanvas, path, color, false);
    path.AddRect({0, 0, 5, 5});
    auto surface = Drawing::Surface::MakeRasterN32Premul(10, 10);
    paintFilterCanvas.surface_ = surface.get();
    rsPropertyDrawableUtilsTest->GetColorForShadowSyn(&paintFilterCanvas, path, color, false);

    Drawing::Canvas canvasTest2;
    std::shared_ptr<Drawing::Image> image = std::make_shared<Drawing::Image>();
    EXPECT_NE(image, nullptr);
    std::shared_ptr<Drawing::SkiaImage> imageImpl = std::make_shared<Drawing::SkiaImage>();
    image->imageImplPtr = imageImpl;
    rsPropertyDrawableUtilsTest->GpuScaleImage(&canvasTest2, image);
}

/**
 * @tc.name: GetShadowRegionImageTest018
 * @tc.desc: GetShadowRegionImage test
 * @tc.type: FUNC
 * @tc.require:issueIA5Y41
 */
HWTEST_F(RSPropertyDrawableUtilsTest, GetShadowRegionImageTest018, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest, nullptr);

    Drawing::Canvas canvasTest;
    RSPaintFilterCanvas paintFilterCanvas(&canvasTest);
    Drawing::Path drPath;
    Drawing::Matrix matrix;
    auto resultTest1 = rsPropertyDrawableUtilsTest->GetShadowRegionImage(&paintFilterCanvas, drPath, matrix);
    EXPECT_EQ(resultTest1, nullptr);
    auto surface = Drawing::Surface::MakeRasterN32Premul(10, 10);
    paintFilterCanvas.surface_ = surface.get();
    auto resultTest2 = rsPropertyDrawableUtilsTest->GetShadowRegionImage(&paintFilterCanvas, drPath, matrix);
    EXPECT_EQ(resultTest2, nullptr);
    drPath.AddRect({0, 0, 5, 5});
    auto resultTest3 = rsPropertyDrawableUtilsTest->GetShadowRegionImage(&paintFilterCanvas, drPath, matrix);
    EXPECT_NE(resultTest3, nullptr);
}

/**
 * @tc.name: DrawShadowMaskFilterTest019
 * @tc.desc: DrawShadowMaskFilter test
 * @tc.type: FUNC
 * @tc.require:issueIA5Y41
 */
HWTEST_F(RSPropertyDrawableUtilsTest, DrawShadowMaskFilterTest019, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest, nullptr);
    Drawing::Canvas canvasTest;
    Drawing::Path path;
    path.AddRect({0, 0, 5, 5});
    rsPropertyDrawableUtilsTest->DrawShadowMaskFilter(&canvasTest, path, 1.f, 1.f, 1.f, false,
        Color(255, 255, 255, 255));
    ASSERT_TRUE(true);
}

/**
 * @tc.name: GetGravityMatrixTest020
 * @tc.desc: GetGravityMatrix test
 * @tc.type: FUNC
 * @tc.require:issueIA5Y41
 */
HWTEST_F(RSPropertyDrawableUtilsTest, GetGravityMatrixTest020, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtilsTest = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtilsTest, nullptr);
    Drawing::Rect rect(0, 0, 10, 10);
    Drawing::Rect rectTwo(0, 0, 0, 10);
    Drawing::Rect rectThree(0, 0, 0, 0.0000001);
    Drawing::Matrix matrix;
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::CENTER, rect, 10, 10, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::CENTER, rect, 20, 20, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::TOP, rect, 20, 20, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::BOTTOM, rect, 20, 20, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::LEFT, rect, 20, 20, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RIGHT, rect, 20, 20, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::TOP_LEFT, rect, 20, 20, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::TOP_RIGHT, rect, 20, 20, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::BOTTOM_LEFT, rect, 20, 20, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::BOTTOM_RIGHT, rect, 20, 20, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE, rect, 0, 0, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE, rect, 20, 20, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT, rect, 0, 0, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT, rectTwo, 10, 10, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT, rect, 20, 20, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_TOP_LEFT, rect, 0, 0, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_TOP_LEFT, rect, 20, 20, matrix));
    ASSERT_FALSE(
        rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_BOTTOM_RIGHT, rect, 0, 0, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(
        Gravity::RESIZE_ASPECT_BOTTOM_RIGHT, rectTwo, 10, 10, matrix));
    ASSERT_TRUE(
        rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_BOTTOM_RIGHT, rect, 20, 20, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_FILL, rect, 0, 0, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(
        Gravity::RESIZE_ASPECT_FILL, rectThree, 10, 100000000, matrix));
    ASSERT_TRUE(rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_FILL, rect, 20, 20, matrix));
    ASSERT_FALSE(
        rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_FILL_TOP_LEFT, rect, 0, 0, matrix));
    ASSERT_TRUE(
        rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_FILL_TOP_LEFT, rect, 20, 20, matrix));
    ASSERT_FALSE(
        rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_FILL_BOTTOM_RIGHT, rect, 0, 0, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(
        Gravity::RESIZE_ASPECT_FILL_BOTTOM_RIGHT, rectThree, 10, 100000000, matrix));
    ASSERT_TRUE(
        rsPropertyDrawableUtilsTest->GetGravityMatrix(Gravity::RESIZE_ASPECT_FILL_BOTTOM_RIGHT, rect, 20, 20, matrix));
    ASSERT_FALSE(rsPropertyDrawableUtilsTest->GetGravityMatrix(static_cast<Gravity>(22), rect, 20, 20, matrix));
}

/**
 * @tc.name: RSFilterSetPixelStretchTest021
 * @tc.desc: RSFilterSetPixelStretch test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSPropertyDrawableUtilsTest, RSFilterSetPixelStretchTest021, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);

    RSProperties properties;
    std::shared_ptr<RSFilter> rsFilter = nullptr;
    EXPECT_FALSE(rsPropertyDrawableUtils->RSFilterSetPixelStretch(properties, rsFilter));

    std::shared_ptr<RSShaderFilter> rsFilterTest = std::make_shared<RSShaderFilter>();
    std::shared_ptr<RSDrawingFilter> filter = std::make_shared<RSDrawingFilter>(rsFilterTest);
    EXPECT_FALSE(rsPropertyDrawableUtils->RSFilterSetPixelStretch(properties, filter));

    std::shared_ptr<RSShaderFilter> rsFilterTest2 = std::make_shared<RSShaderFilter>();
    rsFilterTest2->type_ = RSShaderFilter::MESA;
    std::shared_ptr<RSDrawingFilter> filter2 = std::make_shared<RSDrawingFilter>(rsFilterTest2);
    EXPECT_FALSE(rsPropertyDrawableUtils->RSFilterSetPixelStretch(properties, filter2));

    // -1.0f: stretch offset param
    Vector4f pixelStretchTest(-1.0f, -1.0f, -1.0f, -1.0f);
    properties.pixelStretch_ = pixelStretchTest;
    EXPECT_TRUE(rsPropertyDrawableUtils->RSFilterSetPixelStretch(properties, filter2));

    // 1.0f: stretch offset param
    Vector4f pixelStretchTest2(1.0f, 1.0f, 1.0f, 1.0f);
    properties.pixelStretch_ = pixelStretchTest2;
    EXPECT_FALSE(rsPropertyDrawableUtils->RSFilterSetPixelStretch(properties, filter2));
}

/**
 * @tc.name: RSFilterRemovePixelStretchTest022
 * @tc.desc: RSFilterRemovePixelStretch test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSPropertyDrawableUtilsTest, RSFilterRemovePixelStretchTest022, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RSPropertyDrawableUtils> rsPropertyDrawableUtils = std::make_shared<RSPropertyDrawableUtils>();
    EXPECT_NE(rsPropertyDrawableUtils, nullptr);

    std::shared_ptr<RSFilter> rsFilter = nullptr;
    rsPropertyDrawableUtils->RSFilterRemovePixelStretch(rsFilter);

    std::shared_ptr<RSShaderFilter> rsFilterTest = std::make_shared<RSShaderFilter>();
    std::shared_ptr<RSDrawingFilter> filter = std::make_shared<RSDrawingFilter>(rsFilterTest);
    rsPropertyDrawableUtils->RSFilterRemovePixelStretch(filter);

    std::shared_ptr<RSShaderFilter> rsFilterTest2 = std::make_shared<RSShaderFilter>();
    rsFilterTest2->type_ = RSShaderFilter::MESA;
    std::shared_ptr<RSDrawingFilter> filter2 = std::make_shared<RSDrawingFilter>(rsFilterTest2);
    rsPropertyDrawableUtils->RSFilterRemovePixelStretch(filter2);
}
} // namespace OHOS::Rosen