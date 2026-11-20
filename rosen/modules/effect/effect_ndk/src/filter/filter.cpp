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

#include "filter.h"

#include <algorithm>

#include "utils/log.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr size_t MAX_CUSTOM_TAG_NAME_LEN = 64;
}
Filter::Filter(std::shared_ptr<OHOS::Media::PixelMap> pixelMap) : srcPixelMap_(pixelMap)
{}

std::shared_ptr<OHOS::Media::PixelMap> Filter::GetSrcPixelMap()
{
    return srcPixelMap_;
}

bool Filter::Render(bool forceCPU)
{
    if (srcPixelMap_ == nullptr) {
        return false;
    }
    EffectImageRender imageRender;
    std::string tagName = customTagName_;
    if (tagName.empty()) {
        tagName = GetDefaultTagName();
    }
    auto error = imageRender.Render(srcPixelMap_, effectFilters_, forceCPU, dstPixelMap_,
        customTagId_, tagName, &gpuMemoryStatistics_);
    return error == DrawingError::ERR_OK;
}

void Filter::SetGpuResourceTag(uint32_t customTagId, const std::string& customTagName)
{
    customTagId_ = customTagId;
    customTagName_ = customTagName.substr(0, MAX_CUSTOM_TAG_NAME_LEN);
}

std::string Filter::GetGpuMemoryStatistics() const
{
    return gpuMemoryStatistics_;
}

bool Filter::RenderNativeBuffer(
    bool forceCPU, OH_NativeBuffer *dstNativeBuffer, int32_t *syncFenceFd, bool releaseGpuContext)
{
    if (dstNativeBuffer == nullptr) {
        return false;
    }
    if (srcPixelMap_ == nullptr) {
        return false;
    }
    EffectImageRender imageRender;
    std::string tagName = customTagName_;
    if (tagName.empty()) {
        tagName = GetDefaultTagName();
    }
    auto dstNativeBufferSharedPtr = std::shared_ptr<OH_NativeBuffer>(dstNativeBuffer, [](OH_NativeBuffer* p) {});
    auto error = imageRender.RenderNativeBuffer(srcPixelMap_, dstNativeBufferSharedPtr, effectFilters_, syncFenceFd,
        releaseGpuContext, customTagId_, tagName, &gpuMemoryStatistics_);
    return error == DrawingError::ERR_OK;
}

void Filter::AddNextFilter(std::shared_ptr<EffectImageFilter> filter, const std::string& filterType)
{
    effectFilters_.emplace_back(filter);
    if (std::find(filterTypeNames_.begin(), filterTypeNames_.end(), filterType) == filterTypeNames_.end()) {
        filterTypeNames_.emplace_back(filterType);
    }
}

std::string Filter::GetDefaultTagName() const
{
    std::string name;
    for (const auto& filterType : filterTypeNames_) {
        if (!name.empty()) {
            name += "+";
        }
        name += filterType;
    }
    return name;
}

std::shared_ptr<OHOS::Media::PixelMap> Filter::GetPixelMap(bool useCpuRender)
{
    if (!Render(useCpuRender)) {
        return nullptr;
    }
    return dstPixelMap_;
}

bool Filter::Blur(float radius, Drawing::TileMode tileMode)
{
    auto blur = EffectImageFilter::Blur(radius, tileMode);
    if (!blur) {
        return false;
    }
    AddNextFilter(blur, "blur");
    return true;
}

bool Filter::Blur(float radius, float angle, Drawing::TileMode tileMode)
{
    auto blur = EffectImageFilter::Blur(radius, angle, tileMode);
    if (!blur) {
        return false;
    }
    AddNextFilter(blur, "blur");
    return true;
}

bool Filter::Brightness(float brightness)
{
    auto bright = EffectImageFilter::Brightness(brightness);
    if (!bright) {
        return false;
    }
    AddNextFilter(bright, "brightness");
    return true;
}

bool Filter::Scale(float scaleX, float scaleY, Drawing::FilterMode filterMode, Drawing::MipmapMode mipmapMode)
{
    auto scale = EffectImageFilter::Scale(scaleX, scaleY, filterMode, mipmapMode);
    if (!scale) {
        return false;
    }
    AddNextFilter(scale, "scale");
    return true;
}

bool Filter::Grayscale()
{
    auto grayscale = EffectImageFilter::Grayscale();
    if (!grayscale) {
        return false;
    }
    AddNextFilter(grayscale, "grayscale");
    return true;
}

bool Filter::Invert()
{
    auto invert = EffectImageFilter::Invert();
    if (!invert) {
        return false;
    }
    AddNextFilter(invert, "invert");
    return true;
}

bool Filter::MapColorByBrightness(const std::vector<Vector4f>& colors, const std::vector<float>& positions)
{
    auto filter = EffectImageFilter::MapColorByBrightness(colors, positions);
    if (!filter) {
        return false;
    }
    AddNextFilter(filter, "mapColorByBrightness");
    return true;
}

bool Filter::GammaCorrection(float gamma)
{
    auto filter = EffectImageFilter::GammaCorrection(gamma);
    if (!filter) {
        return false;
    }
    AddNextFilter(filter, "gammaCorrection");
    return true;
}

bool Filter::SetColorMatrix(const Drawing::ColorMatrix& matrix)
{
    auto applyColorMatrix = EffectImageFilter::ApplyColorMatrix(matrix);
    if (!applyColorMatrix) {
        return false;
    }
    AddNextFilter(applyColorMatrix, "setColorMatrix");
    return true;
}

bool Filter::WaterGlass(const std::shared_ptr<Drawing::GEWaterGlassDataParams>& params)
{
    auto glass = EffectImageFilter::WaterGlass(params);
    AddNextFilter(glass, "waterGlass");

    return true;
}

bool Filter::ReededGlass(const std::shared_ptr<Drawing::GEReededGlassDataParams>& params)
{
    auto glass = EffectImageFilter::ReededGlass(params);

    AddNextFilter(glass, "reededGlass");

    return true;
}

bool Filter::MaskTransition(const std::shared_ptr<OHOS::Media::PixelMap>& topLayer,
    const std::shared_ptr<Drawing::GEShaderMask>& mask, float factor, bool inverse)
{
    auto filter = EffectImageFilter::MaskTransition(topLayer, mask, factor, inverse);
    if (!filter) {
        return false;
    }
    AddNextFilter(filter, "maskTransition");
    return true;
}
 
bool Filter::WaterDropletTransition(const std::shared_ptr<OHOS::Media::PixelMap>& topLayer,
    const std::shared_ptr<Drawing::GEWaterDropletTransitionFilterParams>& geWaterDropletParams)
{
    auto filter = EffectImageFilter::WaterDropletTransition(topLayer, geWaterDropletParams);
    if (!filter) {
        return false;
    }
    AddNextFilter(filter, "waterDropletTransition");
    return true;
}

} // namespace Rosen
} // namespace OHOS