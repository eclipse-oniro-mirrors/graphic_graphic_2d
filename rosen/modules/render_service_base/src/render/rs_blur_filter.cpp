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

#include "render/rs_blur_filter.h"

#ifdef USE_M133_SKIA
#include "src/core/SkChecksum.h"
#else
#include "src/core/SkOpts.h"
#endif

#include "common/rs_common_def.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"


namespace OHOS {
namespace Rosen {
const bool KAWASE_BLUR_ENABLED = RSSystemProperties::GetKawaseEnabled();
const auto BLUR_TYPE = KAWASE_BLUR_ENABLED ? Drawing::ImageBlurType::KAWASE : Drawing::ImageBlurType::GAUSS;
RSBlurFilter::RSBlurFilter(float blurRadiusX, float blurRadiusY, bool disableSystemAdaptation) :
    RSDrawingFilterOriginal(Drawing::ImageFilter::CreateBlurImageFilter(blurRadiusX, blurRadiusY,
        Drawing::TileMode::CLAMP, nullptr, BLUR_TYPE)),
    blurRadiusX_(blurRadiusX),
    blurRadiusY_(blurRadiusY),
    disableSystemAdaptation_(disableSystemAdaptation)
{
    type_ = FilterType::BLUR;

    float blurRadiusXForHash = DecreasePrecision(blurRadiusX);
    float blurRadiusYForHash = DecreasePrecision(blurRadiusY);
#ifdef USE_M133_SKIA
    const auto hashFunc = SkChecksum::Hash32;
#else
    const auto hashFunc = SkOpts::hash;
#endif
    hash_ = hashFunc(&type_, sizeof(type_), 0);
    hash_ = hashFunc(&blurRadiusXForHash, sizeof(blurRadiusXForHash), hash_);
    hash_ = hashFunc(&blurRadiusYForHash, sizeof(blurRadiusYForHash), hash_);
    hash_ = hashFunc(&disableSystemAdaptation, sizeof(disableSystemAdaptation), hash_);
}

RSBlurFilter::~RSBlurFilter() = default;

float RSBlurFilter::GetBlurRadiusX()
{
    return blurRadiusX_;
}

float RSBlurFilter::GetBlurRadiusY()
{
    return blurRadiusY_;
}

bool RSBlurFilter::GetDisableSystemAdaptation()
{
    return disableSystemAdaptation_;
}

std::string RSBlurFilter::GetDescription()
{
    return "RSBlurFilter blur radius is " + std::to_string(blurRadiusX_) + " sigma";
}

std::string RSBlurFilter::GetDetailedDescription()
{
    return "RSBlurFilterBlur, radius: " + std::to_string(blurRadiusX_) + " sigma" +
        ", greyCoef1: " + std::to_string(greyCoef_ == std::nullopt ? 0.0f : greyCoef_->x_) +
        ", greyCoef2: " + std::to_string(greyCoef_ == std::nullopt ? 0.0f : greyCoef_->y_);
}

bool RSBlurFilter::IsValid() const
{
    constexpr float epsilon = 0.999f;
    return blurRadiusX_ > epsilon || blurRadiusY_ > epsilon;
}

std::shared_ptr<RSDrawingFilterOriginal> RSBlurFilter::Compose(
    const std::shared_ptr<RSDrawingFilterOriginal>& other) const
{
    std::shared_ptr<RSBlurFilter> result = std::make_shared<RSBlurFilter>(blurRadiusX_, blurRadiusY_,
        disableSystemAdaptation_);
    result->imageFilter_ = Drawing::ImageFilter::CreateComposeImageFilter(imageFilter_, other->GetImageFilter());
    auto otherHash = other->Hash();
#ifdef USE_M133_SKIA
    const auto hashFunc = SkChecksum::Hash32;
#else
    const auto hashFunc = SkOpts::hash;
#endif
    result->hash_ = hashFunc(&otherHash, sizeof(otherHash), hash_);
    return result;
}

void RSBlurFilter::DrawImageRect(Drawing::Canvas& canvas, const std::shared_ptr<Drawing::Image>& image,
    const Drawing::Rect& src, const Drawing::Rect& dst) const
{
    auto brush = GetBrush();
    std::shared_ptr<Drawing::Image> greyImage = image;
    if (greyCoef_.has_value()) {
        greyImage = RSPropertiesPainter::DrawGreyAdjustment(canvas, image, greyCoef_.value());
    }
    if (greyImage == nullptr) {
        greyImage = image;
    }
    // if kawase blur failed, use gauss blur
    static bool DDGR_ENABLED = RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR;
    KawaseParameter param = KawaseParameter(src, dst, blurRadiusX_, nullptr, brush.GetColor().GetAlphaF());
    if (!DDGR_ENABLED && KAWASE_BLUR_ENABLED &&
        KawaseBlurFilter::GetKawaseBlurFilter()->ApplyKawaseBlur(canvas, greyImage, param)) {
        return;
    }
    canvas.AttachBrush(brush);
    canvas.DrawImageRect(*greyImage, src, dst, Drawing::SamplingOptions());
    canvas.DetachBrush();
}

void RSBlurFilter::SetGreyCoef(const std::optional<Vector2f>& greyCoef)
{
    greyCoef_ = greyCoef;
}

bool RSBlurFilter::CanSkipFrame() const
{
    constexpr float HEAVY_BLUR_THRESHOLD = 25.0f;
    return blurRadiusX_ > HEAVY_BLUR_THRESHOLD && blurRadiusY_ > HEAVY_BLUR_THRESHOLD;
};
} // namespace Rosen
} // namespace OHOS
