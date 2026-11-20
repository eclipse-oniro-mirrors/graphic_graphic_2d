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

#include "drawable/rs_property_drawable_utils.h"

#include "common/rs_obj_abs_geometry.h"
#include "common/rs_optional_trace.h"
#include "drawable/rs_effect_drawable_utils.h"
#include "effect/rs_render_property_tag.h"
#include "effect/rs_render_shape_base.h"
#include "ge_render.h"
#include "ge_shader_filter_params.h"
#include "ge_visual_effect.h"
#include "ge_visual_effect_container.h"
#include <limits>
#include "modifier/rs_render_property.h"
#include "platform/common/rs_log.h"
#include "property/rs_color_picker_def.h"
#include "property/rs_properties_painter.h"
#include "property/rs_spatial_effect_manager.h"
#include "render/rs_color_picker.h"
#include "render/rs_drawing_filter.h"
#include "render/rs_effect_luminance_manager.h"
#include "feature/filter_cache_manager/rs_filter_cache_manager.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr int TRACE_LEVEL_TWO = 2;
constexpr int PARAM_DOUBLE = 2;
} // namespace

Drawing::RoundRect RSPropertyDrawableUtils::RRect2DrawingRRect(const RRect& rr)
{
    Drawing::Rect rect = Drawing::Rect(
        rr.rect_.left_, rr.rect_.top_, rr.rect_.left_ + rr.rect_.width_, rr.rect_.top_ + rr.rect_.height_);

    // set radius for all 4 corner of RRect
    constexpr uint32_t NUM_OF_CORNERS_IN_RECT = 4;
    std::vector<Drawing::Point> radii(NUM_OF_CORNERS_IN_RECT);
    for (uint32_t i = 0; i < NUM_OF_CORNERS_IN_RECT; i++) {
        radii.at(i).SetX(rr.radius_[i].x_);
        radii.at(i).SetY(rr.radius_[i].y_);
    }
    return { rect, radii };
}

RectI RSPropertyDrawableUtils::DrawingRectI2RectI(const Drawing::RectI& r)
{
    return { r.left_, r.top_, r.GetWidth(), r.GetHeight() };
}

Drawing::Rect RSPropertyDrawableUtils::Rect2DrawingRect(const RectF& r)
{
    return { r.left_, r.top_, r.left_ + r.width_, r.top_ + r.height_ };
}

Vector4f RSPropertyDrawableUtils::Rect2Vector4f(const RectF& r)
{
    return { r.left_, r.top_, r.left_ + r.width_, r.top_ + r.height_ };
}

RRect RSPropertyDrawableUtils::GetRRectForDrawingBorder(
    const RSProperties& properties, const std::shared_ptr<RSBorder>& border, const bool& isOutline)
{
    if (!border) {
        return {};
    }

    return isOutline ? RRect(properties.GetRRect().rect_.MakeOutset(border->GetWidthFour()), border->GetRadiusFour())
                     : properties.GetRRect();
}

RRect RSPropertyDrawableUtils::GetInnerRRectForDrawingBorder(
    const RSProperties& properties, const std::shared_ptr<RSBorder>& border, const bool& isOutline)
{
    if (!border) {
        return {};
    }
    return isOutline ? properties.GetRRect() : properties.GetInnerRRect();
}

Color RSPropertyDrawableUtils::GetColorForShadowSyn(Drawing::Canvas* canvas, Drawing::Path& path, const Color& color,
    const int& colorStrategy)
{
    RSColor colorPicked;
    auto shadowAlpha = color.GetAlpha();
    auto matrix = canvas->GetTotalMatrix();
    if (PickColorSyn(canvas, path, matrix, colorPicked, colorStrategy)) {
        GetDarkColor(colorPicked);
    } else {
        shadowAlpha = 0;
    }
    return Color(colorPicked.GetRed(), colorPicked.GetGreen(), colorPicked.GetBlue(), shadowAlpha);
}

std::shared_ptr<Drawing::Image> RSPropertyDrawableUtils::GetShadowRegionImage(Drawing::Canvas* canvas,
    Drawing::Path& drPath, Drawing::Matrix& matrix)
{
    if (canvas == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GetShadowRegionImage canvas is null");
        return nullptr;
    }
    Drawing::Rect clipBounds = drPath.GetBounds();
    Drawing::RectI clipIBounds = { static_cast<int>(clipBounds.GetLeft()), static_cast<int>(clipBounds.GetTop()),
        static_cast<int>(clipBounds.GetRight()), static_cast<int>(clipBounds.GetBottom()) };
    Drawing::Surface* drSurface = canvas->GetSurface();
    if (drSurface == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GetShadowRegionImage drSurface is null");
        return nullptr;
    }
    const int deviceWidth = drSurface->Width();
    const int deviceHeight = drSurface->Height();
    Drawing::Rect regionRect = {0, 0, clipIBounds.GetWidth(), clipIBounds.GetHeight()};
    Drawing::Rect regionRectDev;
    matrix.MapRect(regionRectDev, regionRect);
    int32_t fLeft = std::clamp(int(regionRectDev.GetLeft()), 0, deviceWidth - 1);
    int32_t fTop = std::clamp(int(regionRectDev.GetTop()), 0, deviceHeight - 1);
    int32_t fRight = std::clamp(int(regionRectDev.GetRight()), 0, deviceWidth - 1);
    int32_t fBottom = std::clamp(int(regionRectDev.GetBottom()), 0, deviceHeight - 1);
    if (fLeft == fRight || fTop == fBottom) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GetShadowRegionImage Shadow Rect Invalid");
        return nullptr;
    }
    Drawing::RectI regionBounds = { fLeft, fTop, fRight, fBottom };
    std::shared_ptr<Drawing::Image> shadowRegionImage = drSurface->GetImageSnapshot(regionBounds);
    return shadowRegionImage;
}

bool RSPropertyDrawableUtils::PickColorSyn(Drawing::Canvas* canvas, Drawing::Path& drPath, Drawing::Matrix& matrix,
    RSColor& colorPicked, const int& colorStrategy)
{
    std::shared_ptr<Drawing::Image> shadowRegionImage = GetShadowRegionImage(canvas, drPath, matrix);
    if (shadowRegionImage == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::PickColorSyn GetImageSnapshot Failed");
        return false;
    }
    auto scaledImage = GpuScaleImage(canvas ? canvas->GetGPUContext() : nullptr, shadowRegionImage);
    if (scaledImage == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::PickColorSyn GpuScaleImageids null");
        return false;
    }
    std::shared_ptr<Drawing::Pixmap> dst;
    const int buffLen = scaledImage->GetWidth() * scaledImage->GetHeight();
    auto pixelPtr = std::make_unique<uint32_t[]>(buffLen);
    auto info = scaledImage->GetImageInfo();
    dst = std::make_shared<Drawing::Pixmap>(info, pixelPtr.get(), info.GetWidth() * info.GetBytesPerPixel());
    bool flag = scaledImage->ReadPixels(*dst, 0, 0);
    if (!flag) {
        ROSEN_LOGE("RSPropertyDrawableUtils::PickColorSyn ReadPixel Failed");
        return false;
    }
    uint32_t errorCode = 0;
    std::shared_ptr<RSColorPicker> colorPicker = RSColorPicker::CreateColorPicker(dst, errorCode);
    if (colorPicker == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::PickColorSyn colorPicker is null");
        return false;
    }
    if (errorCode != 0) {
        return false;
    }
    Drawing::ColorQuad color;
    if (colorStrategy == SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_MAIN) {
        colorPicker->GetLargestProportionColor(color);
    } else {
        colorPicker->GetAverageColor(color);
    }
    colorPicked = RSColor(Drawing::Color::ColorQuadGetR(color), Drawing::Color::ColorQuadGetG(color),
        Drawing::Color::ColorQuadGetB(color), Drawing::Color::ColorQuadGetA(color));
    return true;
}

bool RSPropertyDrawableUtils::PickColor(std::shared_ptr<Drawing::GPUContext> context,
    std::shared_ptr<Drawing::Image> image, Drawing::ColorQuad& colorPicked)
{
    image = GpuScaleImage(context, image);
    if (image == nullptr) {
        RS_LOGE("RSPropertyDrawableUtils::PickColor GpuScaleImage failed");
        return false;
    }
    const int buffLen = image->GetWidth() * image->GetHeight();
    auto pixelPtr = std::make_unique<uint32_t[]>(buffLen);
    auto info = image->GetImageInfo();
    auto dst = std::make_shared<Drawing::Pixmap>(info, pixelPtr.get(), info.GetWidth() * info.GetBytesPerPixel());
    if (!dst) {
        RS_LOGE("RSPropertyDrawableUtils::PickColor PixelMap creation failed");
        return false;
    }
    bool flag = image->ReadPixels(*dst, 0, 0);
    if (!flag) {
        RS_LOGE("RSPropertyDrawableUtils::PickColor ReadPixel Failed");
        return false;
    }
    // Use direct average calculation to avoid quantization artifacts
    if (RSColorPicker::GetAverageColorDirect(dst, colorPicked) != 0) {
        RS_LOGE("RSPropertyDrawableUtils::PickColor GetAverageColorDirect failed");
        return false;
    }
    return true;
}

namespace {
constexpr char PASS_THROUGH_PROG[] = R"(
    uniform shader imageInput;

    half4 main(float2 xy) {
        half4 c = imageInput.eval(xy);
        return half4(c.rgb, 1.0);
    }
)";

// Validate image dimensions to prevent divide by zero and overflow
bool IsImageValid(const Drawing::Image& image)
{
    if (image.GetWidth() <= 0 || image.GetHeight() <= 0) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GpuScaleImage invalid image dimensions");
        return false;
    }
    constexpr int maxDimension = 65535; // Prevent overflow in area calculation
    if (image.GetWidth() > maxDimension || image.GetHeight() > maxDimension) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GpuScaleImage image dimensions too large");
        return false;
    }
    const int64_t imageArea = static_cast<int64_t>(image.GetWidth()) * image.GetHeight();
    if (imageArea > std::numeric_limits<int32_t>::max()) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GpuScaleImage image area too large");
        return false;
    }
    return true;
}
// Color picker image scaling constants
constexpr int SMALL_IMAGE_AREA_THRESHOLD = 10000; // 100 * 100 pixels
constexpr int SMALL_SCALED_IMAGE_SIZE = 8;
constexpr int LARGE_SCALED_IMAGE_SIZE = 64;
} // namespace

std::shared_ptr<Drawing::Image> RSPropertyDrawableUtils::GpuScaleImage(
    std::shared_ptr<Drawing::GPUContext> context, std::shared_ptr<Drawing::Image> image)
{
    if (!image || !IsImageValid(*image)) {
        return nullptr;
    }

    static auto effectBuilder =
        std::make_shared<Drawing::RuntimeShaderBuilder>(Drawing::RuntimeEffect::CreateForShader(PASS_THROUGH_PROG));
    if (!effectBuilder) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GpuScaleImage effect is null");
        return nullptr;
    }

    // Safe to calculate area without overflow after dimension check
    int targetSize = (image->GetWidth() * image->GetHeight() < SMALL_IMAGE_AREA_THRESHOLD) ? SMALL_SCALED_IMAGE_SIZE
                                                                                           : LARGE_SCALED_IMAGE_SIZE;
    auto pcInfo = Drawing::ImageInfo::MakeN32Premul(targetSize, targetSize);
    Drawing::Matrix matrix;
    matrix.SetScale(
        static_cast<float>(targetSize) / image->GetWidth(), static_cast<float>(targetSize) / image->GetHeight());

    // Create offscreen surface for GPU scale operation
    auto offscreenSurface = Drawing::Surface::MakeRenderTarget(context.get(), true, pcInfo);
    if (!offscreenSurface) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GpuScaleImage failed to create offscreen surface");
        return nullptr;
    }
    auto canvas = offscreenSurface->GetCanvas();
    if (UNLIKELY(canvas == nullptr)) {
        ROSEN_LOGE("RSPropertyDrawableUtils::GpuScaleImage failed to get offscreen canvas");
        return nullptr;
    }
    effectBuilder->SetChild("imageInput",
        Drawing::ShaderEffect::CreateImageShader(*image, Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP,
            Drawing::SamplingOptions { Drawing::FilterMode::NEAREST, Drawing::MipmapMode::NONE }, matrix));
    auto paint = effectBuilder->MakeShader(nullptr, false);
    canvas->AttachBrush(paint);
    canvas->DrawRect(Drawing::Rect(0, 0, pcInfo.GetWidth(), pcInfo.GetHeight()));
    return offscreenSurface->GetImageSnapshot();
}

void RSPropertyDrawableUtils::GetDarkColor(RSColor& color)
{
    // convert to lab
    float minColorRange = 0;
    float maxColorRange = 255;
    float R = float(color.GetRed()) / maxColorRange;
    float G = float(color.GetGreen()) / maxColorRange;
    float B = float(color.GetBlue()) / maxColorRange;

    float X = 0.4124 * R + 0.3576 * G + 0.1805 * B;
    float Y = 0.2126 * R + 0.7152 * G + 0.0722 * B;
    float Z = 0.0193 * R + 0.1192 * G + 0.9505 * B;

    float Xn = 0.9505;
    float Yn = 1.0000;
    float Zn = 1.0889999;
    float Fx = (X / Xn) > 0.008856 ? pow((X / Xn), 1.0 / 3) : (7.787 * (X / Xn) + 16.0 / 116);
    float Fy = (Y / Yn) > 0.008856 ? pow((Y / Yn), 1.0 / 3) : (7.787 * (Y / Yn) + 16.0 / 116);
    float Fz = (Z / Zn) > 0.008856 ? pow((Z / Zn), 1.0 / 3) : (7.787 * (Z / Zn) + 16.0 / 116);
    float L = 116 * Fy - 16;
    float a = 500 * (Fx - Fy);
    float b = 200 * (Fy - Fz);

    float standardLightness = 75.0;
    if (L > standardLightness) {
        float L1 = standardLightness;
        float xw = 0.9505;
        float yw = 1.0000;
        float zw = 1.0889999;

        float fy = (L1 + 16) / 116;
        float fx = fy + (a / 500);
        float fz = fy - (b / 200);

        float X1 = xw * ((pow(fx, 3) > 0.008856) ? pow(fx, 3) : ((fx - 16.0 / 116) / 7.787));
        float Y1 = yw * ((pow(fy, 3) > 0.008856) ? pow(fy, 3) : ((fy - 16.0 / 116) / 7.787));
        float Z1 = zw * ((pow(fz, 3) > 0.008856) ? pow(fz, 3) : ((fz - 16.0 / 116) / 7.787));

        float DarkR = 3.2406 * X1 - 1.5372 * Y1 - 0.4986 * Z1;
        float DarkG = -0.9689 * X1 + 1.8758 * Y1 + 0.0415 * Z1;
        float DarkB = 0.0557 * X1 - 0.2040 * Y1 + 1.0570 * Z1;

        DarkR = std::clamp(maxColorRange * DarkR, minColorRange, maxColorRange);
        DarkG = std::clamp(maxColorRange * DarkG, minColorRange, maxColorRange);
        DarkB = std::clamp(maxColorRange * DarkB, minColorRange, maxColorRange);

        color = RSColor(DarkR, DarkG, DarkB, color.GetAlpha());
    }
}

void RSPropertyDrawableUtils::BeginOffscreen(RSPaintFilterCanvas& canvas, const RectF& bounds)
{
    RS_OPTIONAL_TRACE_NAME("RSPropertyDrawableUtils::BeginOffscreen");
    auto surface = canvas.GetSurface();
    if (!surface) {
        return;
    }
    std::shared_ptr<Drawing::Surface> offscreenSurface = nullptr;
    if (ROSEN_LNE(surface->GetHdrScale(), 1.0f) &&
        surface->GetImageInfo().GetColorType() == Drawing::ColorType::COLORTYPE_RGBA_1010102) {
        auto info = Drawing::ImageInfo(bounds.width_, bounds.height_,
            Drawing::ColorType::COLORTYPE_RGBA_F16, surface->GetImageInfo().GetAlphaType(),
            surface->GetImageInfo().GetColorSpace());
        offscreenSurface = surface->MakeSurface(info);
    } else {
        offscreenSurface = surface->MakeSurface(bounds.width_, bounds.height_);
    }
    if (!offscreenSurface) {
        return;
    }
    auto offscreenCanvas = std::make_shared<RSPaintFilterCanvas>(offscreenSurface.get());
    offscreenCanvas->CopyConfigurationToOffscreenCanvas(canvas);
    canvas.StoreCanvas();
    canvas.SaveEnv();
    canvas.ReplaceMainScreenData(offscreenSurface, offscreenCanvas);
    offscreenCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);
    canvas.SavePCanvasList();
    canvas.RemoveAll();
    canvas.AddCanvas(offscreenCanvas.get());
    canvas.SetEffectData(offscreenCanvas->GetEffectData());
    canvas.SetFilterClipBounds(offscreenCanvas->GetFilterClipBounds());
}

std::shared_ptr<Drawing::Image> RSPropertyDrawableUtils::EndOffscreen(RSPaintFilterCanvas& canvas)
{
    RS_OPTIONAL_TRACE_NAME("RSPropertyDrawableUtils::EndOffscreen");
    auto surface = canvas.GetSurface();
    std::shared_ptr<Drawing::Image> imageSnapshot = nullptr;
    if (surface) {
        imageSnapshot = surface->GetImageSnapshot();
    } else {
        ROSEN_LOGD("RSPropertyDrawableUtils::EndOffscreen surface null");
    }
    // Swap the canvas back to the main screen surface, undoing BeginOffscreen.
    canvas.RestorePCanvasList();
    canvas.SwapBackMainScreenData();
    canvas.RestoreEnv();
    return imageSnapshot;
}

void RSPropertyDrawableUtils::DrawForegroundFilter(RSPaintFilterCanvas& canvas,
    const std::shared_ptr<RSFilter>& rsFilter, std::optional<RectF> drawRect)
{
    RS_OPTIONAL_TRACE_NAME("DrawForegroundFilter restore");
    auto imageSnapshot = EndOffscreen(canvas);

    if (rsFilter == nullptr) {
        return;
    }

    if (imageSnapshot == nullptr) {
        ROSEN_LOGD("RSPropertyDrawableUtils::DrawForegroundFilter image null");
        return;
    }

    Drawing::Rect dst = drawRect.has_value() ? Rect2DrawingRect(drawRect.value()) :
        Drawing::Rect(0, 0, imageSnapshot->GetWidth(), imageSnapshot->GetHeight());

    if (rsFilter->IsDrawingFilter()) {
        auto rsDrawingFilter = std::static_pointer_cast<RSDrawingFilter>(rsFilter);
        rsDrawingFilter->SetDisableFilterCache(canvas.GetDisableFilterCache());
        rsDrawingFilter->DrawImageRect(canvas, imageSnapshot, Drawing::Rect(0, 0, imageSnapshot->GetWidth(),
            imageSnapshot->GetHeight()), dst);
        return;
    }

    auto foregroundFilter = std::static_pointer_cast<RSDrawingFilterOriginal>(rsFilter);
    if (foregroundFilter->GetFilterType() == RSFilter::MOTION_BLUR) {
        if (canvas.GetDisableFilterCache()) {
            foregroundFilter->DisableMotionBlur(true);
        } else {
            foregroundFilter->DisableMotionBlur(false);
        }
    }

    foregroundFilter->DrawImageRect(canvas, imageSnapshot, Drawing::Rect(0, 0, imageSnapshot->GetWidth(),
        imageSnapshot->GetHeight()), dst);
}

void RSPropertyDrawableUtils::DrawColorFilter(
    Drawing::Canvas* canvas, const std::shared_ptr<Drawing::ColorFilter>& colorFilter, bool isColorMatrixFilter)
{
    if (canvas == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawColorFilter canvas is null");
        return;
    }
    if (colorFilter == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawColorFilter null colorFilter.");
        return;
    }

    Drawing::Brush brush;
    brush.SetAntiAlias(true);
    Drawing::Filter filter;
    filter.SetColorFilter(colorFilter);
    brush.SetFilter(filter);
    auto surface = canvas->GetSurface();
    if (surface == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawColorFilter surface is null");
        return;
    }
    auto clipBounds = canvas->GetLocalClipBounds();
    Drawing::AutoCanvasRestore acr(*canvas, false);
    Drawing::SaveLayerOps slo(&clipBounds, &brush, Drawing::SaveLayerOps::Flags::INIT_WITH_PREVIOUS);
    auto* paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(canvas);
    if (isColorMatrixFilter) {
        paintFilterCanvas->SaveAlpha();
        paintFilterCanvas->SetAlpha(1.0f);
    }
    paintFilterCanvas->SaveLayer(slo);
    if (isColorMatrixFilter) {
        paintFilterCanvas->RestoreAlpha();
    }
}

void RSPropertyDrawableUtils::DrawPixelStretch(Drawing::Canvas* canvas,
    const std::optional<Vector4f>& pixelStretch, const RectF& boundsRect,
    const bool boundsGeoValid, const Drawing::TileMode pixelStretchTileMode)
{
    if (!pixelStretch.has_value()) {
        ROSEN_LOGD("RSPropertyDrawableUtils::DrawPixelStretch pixelStretch has no value");
        return;
    }
    if (std::isinf(pixelStretch->x_) || std::isinf(pixelStretch->y_) ||
        std::isinf(pixelStretch->z_) || std::isinf(pixelStretch->w_)) {
        ROSEN_LOGD("RSPropertyDrawableUtils::DrawPixelStretch skip original pixelStretch");
        return;
    }
    auto surface = canvas->GetSurface();
    if (surface == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawPixelStretch surface null");
        return;
    }

    /*  Calculates the relative coordinates of the clipbounds
        with respect to the origin of the current canvas coordinates */
    Drawing::Matrix worldToLocalMat;
    if (!canvas->GetTotalMatrix().Invert(worldToLocalMat)) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawPixelStretch get invert matrix failed.");
        return;
    }
    Drawing::Rect localClipBounds;
    canvas->Save();
    canvas->ClipRect(Rect2DrawingRect(boundsRect), Drawing::ClipOp::INTERSECT, false);
    auto tmpBounds = canvas->GetDeviceClipBounds();
    RS_OPTIONAL_TRACE_NAME_FMT_LEVEL(TRACE_LEVEL_TWO,
        "RSPropertyDrawableUtils::DrawPixelStretch, tmpBounds: %s", tmpBounds.ToString().c_str());
    canvas->Restore();
    Drawing::Rect clipBounds(
        tmpBounds.GetLeft(), tmpBounds.GetTop(), tmpBounds.GetRight() - 1, tmpBounds.GetBottom() - 1);
    Drawing::Rect fClipBounds(clipBounds.GetLeft(), clipBounds.GetTop(), clipBounds.GetRight(), clipBounds.GetBottom());

    if (!worldToLocalMat.MapRect(localClipBounds, fClipBounds)) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawPixelStretch map rect failed.");
        return;
    }
    auto bounds = Rect2DrawingRect(boundsRect);
    if (!bounds.Intersect(localClipBounds)) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawPixelStretch intersect clipbounds failed");
        return;
    }

    auto scaledBounds = Drawing::Rect(bounds.GetLeft() - pixelStretch->x_, bounds.GetTop() - pixelStretch->y_,
        bounds.GetRight() + pixelStretch->z_, bounds.GetBottom() + pixelStretch->w_);
    if (!scaledBounds.IsValid() || !bounds.IsValid() || !clipBounds.IsValid()) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawPixelStretch invalid scaled bounds");
        return;
    }

    Drawing::RectI rectI(static_cast<int>(fClipBounds.GetLeft()), static_cast<int>(fClipBounds.GetTop()),
        static_cast<int>(fClipBounds.GetRight()), static_cast<int>(fClipBounds.GetBottom()));
    auto image = surface->GetImageSnapshot(rectI);
    if (image == nullptr) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawPixelStretch image null");
        return;
    }

    Drawing::Brush brush;
    Drawing::Matrix inverseMat;
    Drawing::Matrix rotateMat;
    if (boundsGeoValid) {
        auto transMat = canvas->GetTotalMatrix();
        /* transMat.getSkewY() is the sin of the rotation angle(sin0 = 0,sin90 =1 sin180 = 0,sin270 = -1),
            if transMat.getSkewY() is not 0 or -1 or 1,the rotation angle is not a multiple of 90,not Stretch*/
        auto skewY = transMat.Get(Drawing::Matrix::SKEW_Y);
        if (ROSEN_EQ(skewY, 0.f) || ROSEN_EQ(skewY, 1.f) || ROSEN_EQ(skewY, -1.f)) {
        } else {
            ROSEN_LOGD("rotate degree is not 0 or 90 or 180 or 270,return.");
            return;
        }
        rotateMat.SetScale(transMat.Get(Drawing::Matrix::SCALE_X), transMat.Get(Drawing::Matrix::SCALE_Y));
        rotateMat.Set(Drawing::Matrix::SKEW_X, transMat.Get(Drawing::Matrix::SKEW_X));
        rotateMat.Set(Drawing::Matrix::SKEW_Y, transMat.Get(Drawing::Matrix::SKEW_Y));
        rotateMat.PreTranslate(-bounds.GetLeft(), -bounds.GetTop());
        rotateMat.PostTranslate(bounds.GetLeft(), bounds.GetTop());

        Drawing::Rect transBounds;
        rotateMat.MapRect(transBounds, bounds);
        rotateMat.Set(Drawing::Matrix::TRANS_X, bounds.GetLeft() - transBounds.GetLeft());
        rotateMat.Set(Drawing::Matrix::TRANS_Y, bounds.GetTop() - transBounds.GetTop());
        if (!rotateMat.Invert(inverseMat)) {
            ROSEN_LOGE("RSPropertyDrawableUtils::DrawPixelStretch get invert matrix failed.");
        }
    }

    Drawing::AutoCanvasRestore acr(*canvas, true);
    canvas->Translate(bounds.GetLeft(), bounds.GetTop());
    Drawing::SamplingOptions samplingOptions;
    constexpr static float EPS = 1e-5f;
    if (pixelStretch->x_ > EPS || pixelStretch->y_ > EPS || pixelStretch->z_ > EPS || pixelStretch->w_ > EPS) {
        brush.SetShaderEffect(Drawing::ShaderEffect::CreateImageShader(
            *image, pixelStretchTileMode, pixelStretchTileMode, samplingOptions, inverseMat));
        canvas->AttachBrush(brush);
        canvas->DrawRect(Drawing::Rect(-pixelStretch->x_, -pixelStretch->y_,
            -pixelStretch->x_ + scaledBounds.GetWidth(), -pixelStretch->y_ + scaledBounds.GetHeight()));
        canvas->DetachBrush();
    } else {
        inverseMat.PostScale(
            scaledBounds.GetWidth() / bounds.GetWidth(), scaledBounds.GetHeight() / bounds.GetHeight());
        brush.SetShaderEffect(Drawing::ShaderEffect::CreateImageShader(
            *image, pixelStretchTileMode, pixelStretchTileMode, samplingOptions, inverseMat));

        canvas->Translate(-pixelStretch->x_, -pixelStretch->y_);
        canvas->AttachBrush(brush);
        canvas->DrawRect(Drawing::Rect(pixelStretch->x_, pixelStretch->y_, pixelStretch->x_ + bounds.GetWidth(),
            pixelStretch->y_ + bounds.GetHeight()));
        canvas->DetachBrush();
    }
}

Drawing::Path RSPropertyDrawableUtils::CreateShadowPath(const std::shared_ptr<RSPath> rsPath,
    const std::shared_ptr<RSPath>& clipBounds, const RRect& rrect)
{
    Drawing::Path path;
    if (rsPath && rsPath->GetDrawingPath().IsValid()) {
        path = rsPath->GetDrawingPath();
    } else if (clipBounds) {
        path = clipBounds->GetDrawingPath();
    } else {
        path.AddRoundRect(RRect2DrawingRRect(rrect));
    }
    return path;
}

void RSPropertyDrawableUtils::DrawShadow(Drawing::Canvas* canvas, Drawing::Path& path, const float& offsetX,
    const float& offsetY, const float& elevation, const bool& isFilled, Color spotColor,
    const bool& useBoundsClip, const RRect& rRect_)
{
    RS_OPTIONAL_TRACE_NAME_FMT_LEVEL(TRACE_LEVEL_TWO,
        "RSPropertyDrawableUtils::DrawShadow, ShadowElevation: %f, ShadowOffsetX: "
        "%f, ShadowOffsetY: %f, bounds: %s",
        elevation, offsetX, offsetY, path.GetBounds().ToString().c_str());
    Drawing::AutoCanvasRestore acr(*canvas, true);
    if (!isFilled) {
        if (useBoundsClip) {
            canvas->ClipRoundRect(RSPropertyDrawableUtils::RRect2DrawingRRect(rRect_),
                Drawing::ClipOp::DIFFERENCE, true);
        } else {
            canvas->ClipPath(path, Drawing::ClipOp::DIFFERENCE, true);
        }
    }
    path.Offset(offsetX, offsetY);
    Drawing::Point3 planeParams = {0.0f, 0.0f, elevation};
    std::vector<Drawing::Point> pt{{path.GetBounds().GetLeft() + path.GetBounds().GetWidth() / 2,
        path.GetBounds().GetTop() + path.GetBounds().GetHeight() / 2}};
    canvas->GetTotalMatrix().MapPoints(pt, pt, 1);
    Drawing::Point3 lightPos = {pt[0].GetX(), pt[0].GetY(), DEFAULT_LIGHT_HEIGHT};
    Color ambientColor = Color::FromArgbInt(DEFAULT_AMBIENT_COLOR);
    ambientColor.MultiplyAlpha(canvas->GetAlpha());
    spotColor.MultiplyAlpha(canvas->GetAlpha());
    canvas->DrawShadowStyle(path, planeParams, lightPos, DEFAULT_LIGHT_RADIUS, Drawing::Color(ambientColor.AsArgbInt()),
        Drawing::Color(spotColor.AsArgbInt()), Drawing::ShadowFlags::TRANSPARENT_OCCLUDER, true);
}

void RSPropertyDrawableUtils::DrawShadowMaskFilter(Drawing::Canvas* canvas, Drawing::Path& path, const float& offsetX,
    const float& offsetY, const float& radius, const bool& isFilled, Color spotColor, bool disableSDFBlur,
    const bool& useBoundsClip, const RRect& rRect_)
{
    if (UNLIKELY(canvas == nullptr)) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawShadowMaskFilter canvas is null");
        return;
    }
    RS_OPTIONAL_TRACE_NAME_FMT_LEVEL(TRACE_LEVEL_TWO,
        "RSPropertyDrawableUtils::DrawShadowMaskFilter, Radius: %f, ShadowOffsetX: "
        "%f, ShadowOffsetY: %f, bounds: %s",
        radius, offsetX, offsetY, path.GetBounds().ToString().c_str());
    Drawing::AutoCanvasRestore acr(*canvas, true);
    if (!isFilled) {
        if (useBoundsClip) {
            canvas->ClipRoundRect(RSPropertyDrawableUtils::RRect2DrawingRRect(rRect_),
                Drawing::ClipOp::DIFFERENCE, true);
        } else {
            canvas->ClipPath(path, Drawing::ClipOp::DIFFERENCE, true);
        }
    }
    path.Offset(offsetX, offsetY);
    Drawing::Brush brush;
    brush.SetColor(Drawing::Color::ColorQuadSetARGB(
        spotColor.GetAlpha(), spotColor.GetRed(), spotColor.GetGreen(), spotColor.GetBlue()));
    brush.SetAntiAlias(true);
    if (ROSEN_GNE(radius, 0.f)) {
        Drawing::Filter filter;
        filter.SetMaskFilter(
            Drawing::MaskFilter::CreateBlurMaskFilter(Drawing::BlurType::NORMAL, radius, true, disableSDFBlur));
        brush.SetFilter(filter);
    }
    canvas->AttachBrush(brush);
    auto stencilVal = canvas->GetStencilVal();
    if (stencilVal > 0) {
        --stencilVal; // shadow positioned under app window
    }
    if (stencilVal > Drawing::Canvas::INVALID_STENCIL_VAL && stencilVal < canvas->GetMaxStencilVal()) {
        RS_OPTIONAL_TRACE_NAME_FMT("DrawPathWithStencil, stencilVal: %" PRId64 "", stencilVal);
        canvas->DrawPathWithStencil(path, static_cast<uint32_t>(stencilVal));
    } else {
        canvas->DrawPath(path);
    }
    canvas->DetachBrush();
}

void RSPropertyDrawableUtils::DrawUseEffect(RSPaintFilterCanvas* canvas, UseEffectType useEffectType)
{
    const auto& effectData = useEffectType == UseEffectType::EFFECT_COMPONENT ?
        canvas->GetEffectData() : canvas->GetBehindWindowData();
    if (effectData == nullptr || effectData->cachedImage_ == nullptr ||
        !RSFilterCacheManager::IsEffectMergeEnabled()) {
        return;
    }
    RS_TRACE_FUNC();
    Drawing::AutoCanvasRestore acr(*canvas, true);
    // Align the current coordinate system with the one that the effect data was generated from. In most cases,
    // the two coordinate systems are the same, so the cachedMatrix_ should be set to identity.
    canvas->SetMatrix(effectData->cachedMatrix_);
    auto visibleRect = canvas->GetVisibleRect();
    visibleRect.Round();
    auto visibleIRect = Drawing::RectI(
        static_cast<int>(visibleRect.GetLeft()), static_cast<int>(visibleRect.GetTop()),
        static_cast<int>(visibleRect.GetRight()), static_cast<int>(visibleRect.GetBottom()));
    if (!visibleIRect.IsEmpty()) {
        canvas->ClipRect(visibleIRect, Drawing::ClipOp::INTERSECT);
    }
    Drawing::Brush brush;
    canvas->AttachBrush(brush);
    // Draw the cached image in the coordinate system where the effect data is generated. The image content
    // outside the device clip bounds will be automatically clipped.
    auto cachedImageSrcRect = Drawing::Rect(0, 0, effectData->cachedImage_->GetWidth(),
        effectData->cachedImage_->GetHeight());
    canvas->DrawImageRect(*effectData->cachedImage_, cachedImageSrcRect, effectData->cachedRect_,
        Drawing::SamplingOptions(Drawing::FilterMode::LINEAR), Drawing::SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT);
    RS_OPTIONAL_TRACE_NAME_FMT("RSPropertyDrawableUtils::DrawUseEffect cachedRect_:%s, DeviceClipBounds:%s, "
        "IdentityMatrix: %d", effectData->cachedRect_.ToString().c_str(),
        canvas->GetDeviceClipBounds().ToString().c_str(), effectData->cachedMatrix_.IsIdentity());
    canvas->DetachBrush();
}

std::shared_ptr<Drawing::Image> RSPropertyDrawableUtils::DrawDepthOcclusion(Drawing::Canvas* canvas,
    const std::shared_ptr<Drawing::Image>& snapshot, const std::shared_ptr<Drawing::Image>& depthMap,
    const Vector4f& depthPlane, const Vector2f& nearFar, float occlusionWeight, const Drawing::Matrix& invMatrix)
{
    if (!canvas || !snapshot) {
        ROSEN_LOGE("RSPropertyDrawableUtils::DrawDepthOcclusion canvas or snapshot is null");
        return nullptr;
    }

    auto imageInfo = snapshot->GetImageInfo();
    Drawing::Rect src(0, 0, imageInfo.GetWidth(), imageInfo.GetHeight());
    Drawing::Rect dst = src;

    auto geVisualEffect = std::make_shared<Drawing::GEVisualEffect>(Drawing::GE_FILTER_DEPTH_OCCLUSION,
        Drawing::DrawingPaintType::BRUSH);

    geVisualEffect->SetParam(Drawing::GE_FILTER_DEPTH_OCCLUSION_DEPTH_MAP, depthMap);
    geVisualEffect->SetParam(Drawing::GE_FILTER_DEPTH_OCCLUSION_MATRIX, invMatrix);
    geVisualEffect->SetParam(Drawing::GE_FILTER_DEPTH_OCCLUSION_DEPTH_PLANE, depthPlane);
    geVisualEffect->SetParam(Drawing::GE_FILTER_DEPTH_OCCLUSION_WEIGHT, occlusionWeight);
    geVisualEffect->SetParam(Drawing::GE_FILTER_DEPTH_OCCLUSION_NEAR, nearFar.x_);
    geVisualEffect->SetParam(Drawing::GE_FILTER_DEPTH_OCCLUSION_FAR, nearFar.y_);

    auto geContainer = std::make_shared<Drawing::GEVisualEffectContainer>();
    geContainer->AddToChainedFilter(geVisualEffect);

    auto geRender = std::make_shared<GraphicsEffectEngine::GERender>();
    GraphicsEffectEngine::GERender::ShaderFilterEffectContext context;
    context.image = snapshot;
    context.src = src;
    context.dst = dst;

    return geRender->ApplyImageEffect(*canvas, *geContainer, context, Drawing::SamplingOptions());
}

Color RSPropertyDrawableUtils::CalculateInvertColor(const Color& backgroundColor)
{
    uint32_t a = backgroundColor.GetAlpha();
    uint32_t r = 255 - backgroundColor.GetRed(); // 255 max red channel value
    uint32_t g = 255 - backgroundColor.GetGreen(); // 255 max green channel value
    uint32_t b = 255 - backgroundColor.GetBlue(); // 255 max blue channel value
    return Color(r, g, b, a);
}

Color RSPropertyDrawableUtils::GetInvertBackgroundColor(RSPaintFilterCanvas& canvas, bool needClipToBounds,
    const Vector4f& boundsRect, const Color& backgroundColor)
{
    Drawing::AutoCanvasRestore acr(canvas, true);
    if (!needClipToBounds) {
        RS_LOGI("RSPropertyDrawableUtils::GetInvertBackgroundColor not GetClipToBounds");
        Drawing::Rect rect = Drawing::Rect(0, 0, boundsRect.z_, boundsRect.w_);
        canvas.ClipRect(rect, Drawing::ClipOp::INTERSECT, false);
    }
    if (backgroundColor.GetAlpha() == 0xff) { // 0xff = 255, max alpha value
        RS_LOGI("RSPropertyDrawableUtils::GetInvertBackgroundColor not alpha");
        return RSPropertyDrawableUtils::CalculateInvertColor(backgroundColor);
    }
    auto surface = canvas.GetSurface();
    std::shared_ptr<Drawing::Image> imageSnapshot = surface == nullptr ?
        nullptr :
        surface->GetImageSnapshot(canvas.GetDeviceClipBounds());
    if (imageSnapshot == nullptr) {
        RS_LOGI("RSPropertyDrawableUtils::GetInvertBackgroundColor imageSnapshot null");
        return Color(0);
    }
    auto colorPicker = RSPropertiesPainter::CalcAverageColor(imageSnapshot);
    return RSPropertyDrawableUtils::CalculateInvertColor(Color(
        Drawing::Color::ColorQuadGetR(colorPicker), Drawing::Color::ColorQuadGetG(colorPicker),
        Drawing::Color::ColorQuadGetB(colorPicker), Drawing::Color::ColorQuadGetA(colorPicker)));
}

bool RSPropertyDrawableUtils::GetGravityMatrix(const Gravity& gravity, const Drawing::Rect& rect, const float& w,
    const float& h, Drawing::Matrix& mat)
{
    if (w == rect.GetWidth() && h == rect.GetHeight()) {
        return false;
    }
    mat = Drawing::Matrix();

    switch (gravity) {
        case Gravity::CENTER: {
            mat.PreTranslate((rect.GetWidth() - w) / PARAM_DOUBLE, (rect.GetHeight() - h) / PARAM_DOUBLE);
            return true;
        }
        case Gravity::TOP: {
            mat.PreTranslate((rect.GetWidth() - w) / PARAM_DOUBLE, 0);
            return true;
        }
        case Gravity::BOTTOM: {
            mat.PreTranslate((rect.GetWidth() - w) / PARAM_DOUBLE, rect.GetHeight() - h);
            return true;
        }
        case Gravity::LEFT: {
            mat.PreTranslate(0, (rect.GetHeight() - h) / PARAM_DOUBLE);
            return true;
        }
        case Gravity::RIGHT: {
            mat.PreTranslate(rect.GetWidth() - w, (rect.GetHeight() - h) / PARAM_DOUBLE);
            return true;
        }
        case Gravity::TOP_LEFT: {
            return false;
        }
        case Gravity::TOP_RIGHT: {
            mat.PreTranslate(rect.GetWidth() - w, 0);
            return true;
        }
        case Gravity::BOTTOM_LEFT: {
            mat.PreTranslate(0, rect.GetHeight() - h);
            return true;
        }
        case Gravity::BOTTOM_RIGHT: {
            mat.PreTranslate(rect.GetWidth() - w, rect.GetHeight() - h);
            return true;
        }
        case Gravity::RESIZE: {
            if (ROSEN_EQ(w, 0.f) || ROSEN_EQ(h, 0.f)) {
                return false;
            }
            mat.PreScale(rect.GetWidth() / w, rect.GetHeight() / h);
            return true;
        }
        case Gravity::RESIZE_ASPECT: {
            if (ROSEN_EQ(w, 0.f) || ROSEN_EQ(h, 0.f)) {
                return false;
            }
            float scale = std::min(rect.GetWidth() / w, rect.GetHeight() / h);
            if (ROSEN_EQ(scale, 0.f)) {
                return false;
            }
            mat.PreScale(scale, scale);
            mat.PreTranslate((rect.GetWidth() / scale - w) / PARAM_DOUBLE,
                (rect.GetHeight() / scale - h) / PARAM_DOUBLE);
            return true;
        }
        case Gravity::RESIZE_ASPECT_TOP_LEFT: {
            if (ROSEN_EQ(w, 0.f) || ROSEN_EQ(h, 0.f)) {
                return false;
            }
            float scale = std::min(rect.GetWidth() / w, rect.GetHeight() / h);
            mat.PreScale(scale, scale);
            return true;
        }
        case Gravity::RESIZE_ASPECT_BOTTOM_RIGHT: {
            if (ROSEN_EQ(w, 0.f) || ROSEN_EQ(h, 0.f)) {
                return false;
            }
            float scale = std::min(rect.GetWidth() / w, rect.GetHeight() / h);
            if (ROSEN_EQ(scale, 0.f)) {
                return false;
            }
            mat.PreScale(scale, scale);
            mat.PreTranslate(rect.GetWidth() / scale - w, rect.GetHeight() / scale - h);
            return true;
        }
        case Gravity::RESIZE_ASPECT_FILL: {
            if (ROSEN_EQ(w, 0.f) || ROSEN_EQ(h, 0.f)) {
                return false;
            }
            float scale = std::max(rect.GetWidth() / w, rect.GetHeight() / h);
            if (ROSEN_EQ(scale, 0.f)) {
                return false;
            }
            mat.PreScale(scale, scale);
            mat.PreTranslate((rect.GetWidth() / scale - w) / PARAM_DOUBLE,
                (rect.GetHeight() / scale - h) / PARAM_DOUBLE);
            return true;
        }
        case Gravity::RESIZE_ASPECT_FILL_TOP_LEFT: {
            if (ROSEN_EQ(w, 0.f) || ROSEN_EQ(h, 0.f)) {
                return false;
            }
            float scale = std::max(rect.GetWidth() / w, rect.GetHeight() / h);
            mat.PreScale(scale, scale);
            return true;
        }
        case Gravity::RESIZE_ASPECT_FILL_BOTTOM_RIGHT: {
            if (ROSEN_EQ(w, 0.f) || ROSEN_EQ(h, 0.f)) {
                return false;
            }
            float scale = std::max(rect.GetWidth() / w, rect.GetHeight() / h);
            if (ROSEN_EQ(scale, 0.f)) {
                return false;
            }
            mat.PreScale(scale, scale);
            mat.PreTranslate(rect.GetWidth() / scale - w, rect.GetHeight() / scale - h);
            return true;
        }
        default: {
            ROSEN_LOGE("GetGravityMatrix unknow gravity=[%{public}d]", gravity);
            return false;
        }
    }
}

Drawing::RectI RSPropertyDrawableUtils::GetRectByStrategy(
    const Drawing::Rect& rect, RoundingStrategyType roundingStrategy)
{
    switch (roundingStrategy) {
        case RoundingStrategyType::ROUND_IN:
            return Drawing::RectI(std::ceil(rect.GetLeft()), std::ceil(rect.GetTop()), std::floor(rect.GetRight()),
                std::floor(rect.GetBottom()));
        case RoundingStrategyType::ROUND_OUT:
            return Drawing::RectI(std::floor(rect.GetLeft()), std::floor(rect.GetTop()), std::ceil(rect.GetRight()),
                std::ceil(rect.GetBottom()));
        case RoundingStrategyType::ROUND_OFF:
            return Drawing::RectI(std::round(rect.GetLeft()), std::round(rect.GetTop()), std::round(rect.GetRight()),
                std::round(rect.GetBottom()));
        case RoundingStrategyType::ROUND_STATIC_CAST_INT:
            return Drawing::RectI(static_cast<int>(rect.GetLeft()), static_cast<int>(rect.GetTop()),
                static_cast<int>(rect.GetRight()), static_cast<int>(rect.GetBottom()));
        default:
            return Drawing::RectI(std::floor(rect.GetLeft()), std::floor(rect.GetTop()), std::ceil(rect.GetRight()),
                std::ceil(rect.GetBottom()));
    }
}

std::shared_ptr<RSNGRenderShapeBase> RSPropertyDrawableUtils::GetResolvedSDFShape(const RSProperties& properties)
{
    auto sdfShape = properties.GetSDFShape();
    if (!sdfShape || sdfShape->GetType() != RSNGEffectType::SDF_DISTORT_OP_SHAPE) {
        return sdfShape;
    }
    auto foregroundFilter = properties.GetForegroundFilter();
    if (!foregroundFilter || !foregroundFilter->IsDrawingFilter()) {
        return sdfShape;
    }
    auto drawingFilter = std::static_pointer_cast<RSDrawingFilter>(foregroundFilter);
    auto renderFilter = drawingFilter->GetNGRenderFilter();
    if (!renderFilter || renderFilter->GetType() != RSNGEffectType::DISTORTION_COLLAPSE) {
        return sdfShape;
    }
    auto distortOpShape = std::static_pointer_cast<RSNGRenderSDFDistortOpShape>(sdfShape);
    auto innerShape = distortOpShape->Getter<SDFDistortOpShapeShapeRenderTag>()->Get();
    return innerShape ? innerShape : sdfShape;
}
} // namespace Rosen
} // namespace OHOS
