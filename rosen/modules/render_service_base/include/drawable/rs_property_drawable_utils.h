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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_UTILS_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_UTILS_H

#include "property/rs_properties.h"

namespace OHOS {
namespace Rosen {
class RSPropertyDrawableUtils {
public:
    static Drawing::RoundRect RRect2DrawingRRect(const RRect& rr);
    static Drawing::Rect Rect2DrawingRect(const RectF& r);
    static RRect GetRRectForDrawingBorder(
        const RSProperties& properties, const std::shared_ptr<RSBorder>& border, const bool& isOutline);
    static RRect GetInnerRRectForDrawingBorder(
        const RSProperties& properties, const std::shared_ptr<RSBorder>& border, const bool& isOutline);
    static Color GetColorForShadowSyn(Drawing::Canvas* canvas, Drawing::Path& path, const Color& color,
        const int& colorStrategy);
    static std::shared_ptr<Drawing::Image> GetShadowRegionImage(Drawing::Canvas* canvas,
        Drawing::Path& drPath, Drawing::Matrix& matrix);
    static bool PickColorSyn(Drawing::Canvas* canvas, Drawing::Path& drPath, Drawing::Matrix& matrix,
        RSColor& colorPicked, const int& colorStrategy);
    static std::shared_ptr<Drawing::Image> GpuScaleImage(Drawing::Canvas* canvas,
        const std::shared_ptr<Drawing::Image> image);
    static void GetDarkColor(RSColor& color);
    static void CeilMatrixTrans(Drawing::Canvas* canvas);
    static void BeginForegroundFilter(RSPaintFilterCanvas& canvas, const RectF& bounds);
    static void DrawForegroundFilter(RSPaintFilterCanvas& canvas, const std::shared_ptr<RSFilter>& rsFilter);
    static void DrawFilter(Drawing::Canvas* canvas, const std::shared_ptr<RSFilter>& rsFilter,
        const std::unique_ptr<RSFilterCacheManager>& cacheManager, const bool isForegroundFilter);
    static void DrawBackgroundEffect(RSPaintFilterCanvas* canvas, const std::shared_ptr<RSFilter>& rsFilter,
        const std::unique_ptr<RSFilterCacheManager>& cacheManager,
        Drawing::RectI& bounds, bool behindWindow = false);
    static void DrawColorFilter(Drawing::Canvas* canvas, const std::shared_ptr<Drawing::ColorFilter>& colorFilter);
    static void DrawLightUpEffect(Drawing::Canvas* canvas, const float lightUpEffectDegree);
    static std::shared_ptr<Drawing::Blender> MakeLightUpEffectBlender(const float lightUpDeg);
    static void DrawDynamicDim(Drawing::Canvas* canvas, const float dynamicDimDegree);
    static std::shared_ptr<Drawing::ShaderEffect> MakeDynamicDimShader(float dynamicDimDeg,
        std::shared_ptr<Drawing::ShaderEffect> imageShader);
    static std::shared_ptr<Drawing::ShaderEffect> MakeBinarizationShader(float low, float high, float thresholdLow,
        float thresholdHigh, std::shared_ptr<Drawing::ShaderEffect> imageShader);
    static std::shared_ptr<Drawing::RuntimeBlenderBuilder> MakeDynamicBrightnessBuilder();
    static std::shared_ptr<Drawing::Blender> MakeDynamicBrightnessBlender(const RSDynamicBrightnessPara& params,
        float ratio = 1.0f);
    static void DrawBinarization(Drawing::Canvas* canvas, const std::optional<Vector4f>& aiInvert);
    static void DrawPixelStretch(Drawing::Canvas* canvas, const std::optional<Vector4f>& pixelStretch,
        const RectF& boundsRect, const bool boundsGeoValid, const Drawing::TileMode pixelStretchTileMode);
    static Drawing::Path CreateShadowPath(const std::shared_ptr<RSPath> rsPath,
        const std::shared_ptr<RSPath>& clipBounds, const RRect& rrect);
    static void DrawShadow(Drawing::Canvas* canvas, Drawing::Path& path, const float& offsetX, const float& offsetY,
        const float& elevation, const bool& isFilled, Color spotColor);
    static void DrawShadowMaskFilter(Drawing::Canvas* canvas, Drawing::Path& path, const float& offsetX,
        const float& offsetY, const float& radius, const bool& isFilled, Color spotColor);
    static void DrawUseEffect(RSPaintFilterCanvas* canvas, UseEffectType useEffectType);

    static bool IsDangerousBlendMode(int blendMode, int blendApplyType);
    static void BeginBlender(RSPaintFilterCanvas& canvas, std::shared_ptr<Drawing::Blender> blender,
        int blendModeApplyType, bool isDangerous);
    static void EndBlender(RSPaintFilterCanvas& canvas, int blendModeApplyType);

    static Color CalculateInvertColor(const Color& backgroundColor);
    static Color GetInvertBackgroundColor(RSPaintFilterCanvas& canvas, bool needClipToBounds,
        const Vector4f& boundsRect, const Color& backgroundColor);
    RSB_EXPORT static int GetAndResetBlurCnt();
    static bool GetGravityMatrix(const Gravity& gravity, const Drawing::Rect& rect, const float& w, const float& h,
        Drawing::Matrix& mat);
    static bool RSFilterSetPixelStretch(const RSProperties& property, const std::shared_ptr<RSFilter>& filter);
    static void RSFilterRemovePixelStretch(const std::shared_ptr<RSFilter>& filter);
    static void DrawFilterWithDRM(Drawing::Canvas* canvas, bool isDark);

    static std::shared_ptr<RSFilter> GenerateBehindWindowFilter(float radius, float saturation, float brightness,
        RSColor maskColor);

    static bool IsBlurFilterType(const RSFilter::FilterType& filterType);

    static float GetBlurFilterRadius(const std::shared_ptr<RSFilter>& rsFilter);
private:
    static std::shared_ptr<Drawing::ColorFilter> GenerateMaterialColorFilter(float sat, float brt);
    static std::shared_ptr<Drawing::RuntimeEffect> binarizationShaderEffect_;
    static std::shared_ptr<Drawing::RuntimeEffect> dynamicDimShaderEffect_;
    static std::shared_ptr<Drawing::RuntimeEffect> dynamicBrightnessBlenderEffect_;
    static std::shared_ptr<Drawing::RuntimeEffect> lightUpEffectBlender_;
    inline static int g_blurCnt = 0;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_UTILS_H
