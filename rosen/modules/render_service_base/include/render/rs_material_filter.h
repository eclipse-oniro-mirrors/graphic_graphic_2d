/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef RENDER_SERVICE_BASE_RENDER_RENDER_RS_MATERIAL_FILTER_H
#define RENDER_SERVICE_BASE_RENDER_RENDER_RS_MATERIAL_FILTER_H

#include <optional>

#include "include/effects/SkRuntimeEffect.h"
#include "common/rs_color.h"
#include "render/rs_hps_blur.h"
#include "render/rs_skia_filter.h"
#include "render/rs_kawase_blur.h"

#include "effect/color_filter.h"
#include "draw/color.h"
#include "effect/color_matrix.h"
#include "effect/image_filter.h"

namespace OHOS {
namespace Rosen {
enum MATERIAL_BLUR_STYLE : int {
    // card blur style
    STYLE_CARD_THIN_LIGHT  = 1,
    STYLE_CARD_LIGHT       = 2,
    STYLE_CARD_THICK_LIGHT = 3,
    STYLE_CARD_THIN_DARK   = 4,
    STYLE_CARD_DARK        = 5,
    STYLE_CARD_THICK_DARK  = 6,

    // background blur style
    STYLE_BACKGROUND_SMALL_LIGHT  = 101,
    STYLE_BACKGROUND_MEDIUM_LIGHT = 102,
    STYLE_BACKGROUND_LARGE_LIGHT  = 103,
    STYLE_BACKGROUND_XLARGE_LIGHT = 104,
    STYLE_BACKGROUND_SMALL_DARK   = 105,
    STYLE_BACKGROUND_MEDIUM_DARK  = 106,
    STYLE_BACKGROUND_LARGE_DARK   = 107,
    STYLE_BACKGROUND_XLARGE_DARK  = 108
};
// material blur style params
struct MaterialParam {
    float radius = 0.f;
    float saturation = 0.f;
    float brightness = 1.f;
    RSColor maskColor = {};
    bool disableSystemAdaptation = false;
};
class RSB_EXPORT RSMaterialFilter : public RSDrawingFilterOriginal {
public:
    RSMaterialFilter(int style, float dipScale, BLUR_COLOR_MODE mode, float ratio,
        bool disableSystemAdaptation = true);
    RSMaterialFilter(MaterialParam materialParam, BLUR_COLOR_MODE mode);
    RSMaterialFilter(const RSMaterialFilter&) = delete;
    RSMaterialFilter operator=(const RSMaterialFilter&) = delete;
    ~RSMaterialFilter() override;
    std::shared_ptr<RSFilter> TransformFilter(float fraction) const;
    bool IsValid() const override;
    void PreProcess(std::shared_ptr<Drawing::Image> image) override;
    void PostProcess(Drawing::Canvas& canvas) override;
    std::shared_ptr<RSDrawingFilterOriginal> Compose(
        const std::shared_ptr<RSDrawingFilterOriginal>& other) const override;
    std::string GetDescription() override;
    std::string GetDetailedDescription() override;

    void DrawImageRect(Drawing::Canvas& canvas, const std::shared_ptr<Drawing::Image>& image,
        const Drawing::Rect& src, const Drawing::Rect& dst) const override;
    float GetRadius() const;
    float GetSaturation() const;
    float GetBrightness() const;
    RSColor GetMaskColor() const;
    BLUR_COLOR_MODE GetColorMode() const;
    bool GetDisableSystemAdaptation() const;
    bool CanSkipFrame() const override;

    void SetGreyCoef(const std::optional<Vector2f>& greyCoef) override;
    bool NeedForceSubmit() const override;

private:
    BLUR_COLOR_MODE colorMode_;
    float radius_ {};
    float saturation_ = 1.f;
    float brightness_ = 1.f;
    RSColor maskColor_ = RSColor();
    std::optional<Vector2f> greyCoef_;

    std::shared_ptr<Drawing::ColorFilter> GetColorFilter(float sat, float brightness);
    std::shared_ptr<Drawing::ImageFilter> CreateMaterialStyle(MATERIAL_BLUR_STYLE style, float dipScale, float ratio);
    std::shared_ptr<Drawing::ImageFilter> CreateMaterialFilter(float radius, float sat, float brightness);
    static float RadiusVp2Sigma(float radiusVp, float dipScale);

    std::shared_ptr<Drawing::ColorFilter> colorFilter_;
    bool disableSystemAdaptation_ {true};
    friend class RSMarshallingHelper;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_RENDER_RENDER_RS_BLUR_FILTER_H
