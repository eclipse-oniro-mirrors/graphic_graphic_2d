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
#include "render/rs_render_mesa_blur_filter.h"

#include "ge_visual_effect.h"
#include "ge_visual_effect_container.h"
#include "include/gpu/GrDirectContext.h"
#include "src/core/SkOpts.h"

#include "effect/color_matrix.h"
#include "effect/runtime_shader_builder.h"
#include "platform/common/rs_system_properties.h"

namespace OHOS {
namespace Rosen {
RSMESABlurShaderFilter::RSMESABlurShaderFilter(int radius)
    : RSRenderFilterParaBase(RSUIFilterType::MESA), radius_(radius)
{
    CalculateHash();
}

RSMESABlurShaderFilter::RSMESABlurShaderFilter(int radius, float greyCoefLow, float greyCoefHigh)
    : RSRenderFilterParaBase(RSUIFilterType::MESA), radius_(radius), greyCoefLow_(greyCoefLow),
      greyCoefHigh_(greyCoefHigh)
{
    CalculateHash();
}

RSMESABlurShaderFilter::~RSMESABlurShaderFilter() = default;

int RSMESABlurShaderFilter::GetRadius() const
{
    return radius_;
}

void RSMESABlurShaderFilter::SetRadius(int radius)
{
    radius_ = radius;
    CalculateHash();
}

void RSMESABlurShaderFilter::SetPixelStretchParams(std::shared_ptr<RSPixelStretchParams>& param)
{
    {
        std::lock_guard<std::mutex> lock(pixelStretchParamsMutex_);
        pixelStretchParam_ = std::move(param);
    }
    CalculateHash();
}

void RSMESABlurShaderFilter::CalculateHash()
{
    hash_ = SkOpts::hash(&radius_, sizeof(radius_), 0);
    hash_ = SkOpts::hash(&greyCoefLow_, sizeof(greyCoefLow_), hash_);
    hash_ = SkOpts::hash(&greyCoefHigh_, sizeof(greyCoefHigh_), hash_);
    if (auto localParams = GetPixelStretchParams()) {
        hash_ = SkOpts::hash(&localParams->offsetX_, sizeof(localParams->offsetX_), hash_);
        hash_ = SkOpts::hash(&localParams->offsetY_, sizeof(localParams->offsetY_), hash_);
        hash_ = SkOpts::hash(&localParams->offsetZ_, sizeof(localParams->offsetZ_), hash_);
        hash_ = SkOpts::hash(&localParams->offsetW_, sizeof(localParams->offsetW_), hash_);
        hash_ = SkOpts::hash(&localParams->tileMode_, sizeof(localParams->tileMode_), hash_);
        hash_ = SkOpts::hash(&localParams->width_, sizeof(localParams->width_), hash_);
        hash_ = SkOpts::hash(&localParams->height_, sizeof(localParams->height_), hash_);
    }
}

std::string RSMESABlurShaderFilter::GetDetailedDescription() const
{
    std::string filterString = ", MESA radius: " + std::to_string(radius_) + " sigma";
    filterString = filterString + ", greyCoef1: " + std::to_string(greyCoefLow_);
    filterString = filterString + ", greyCoef2: " + std::to_string(greyCoefHigh_);
    if (auto localParams = GetPixelStretchParams()) {
        filterString = filterString + ", pixel stretch offsetX: " + std::to_string(localParams->offsetX_);
        filterString = filterString + ", offsetY: " + std::to_string(localParams->offsetY_);
        filterString = filterString + ", offsetZ: " + std::to_string(localParams->offsetZ_);
        filterString = filterString + ", offsetW: " + std::to_string(localParams->offsetW_);
        filterString = filterString + ", tileMode: " + std::to_string(localParams->tileMode_);
        filterString = filterString + ", width: " + std::to_string(localParams->width_);
        filterString = filterString + ", height: " + std::to_string(localParams->height_);
    }
    return filterString;
}

void RSMESABlurShaderFilter::GenerateGEVisualEffect(
    std::shared_ptr<Drawing::GEVisualEffectContainer> visualEffectContainer)
{
    auto mesaFilter = std::make_shared<Drawing::GEVisualEffect>("MESA_BLUR", Drawing::DrawingPaintType::BRUSH);
    mesaFilter->SetParam("MESA_BLUR_RADIUS", (int)radius_); // blur radius
    mesaFilter->SetParam("MESA_BLUR_GREY_COEF_1", greyCoefLow_);
    mesaFilter->SetParam("MESA_BLUR_GREY_COEF_2", greyCoefHigh_);
    if (auto localParams = GetPixelStretchParams()) {
        mesaFilter->SetParam("OFFSET_X", localParams->offsetX_);
        mesaFilter->SetParam("OFFSET_Y", localParams->offsetY_);
        mesaFilter->SetParam("OFFSET_Z", localParams->offsetZ_);
        mesaFilter->SetParam("OFFSET_W", localParams->offsetW_);
        mesaFilter->SetParam("TILE_MODE", localParams->tileMode_);
        mesaFilter->SetParam("WIDTH", localParams->width_);
        mesaFilter->SetParam("HEIGHT", localParams->height_);
    } else {
        mesaFilter->SetParam("OFFSET_X", 0.f);
        mesaFilter->SetParam("OFFSET_Y", 0.f);
        mesaFilter->SetParam("OFFSET_Z", 0.f);
        mesaFilter->SetParam("OFFSET_W", 0.f);
        mesaFilter->SetParam("TILE_MODE", 0);
        mesaFilter->SetParam("WIDTH", 0.f);
        mesaFilter->SetParam("HEIGHT", 0.f);
    }
    visualEffectContainer->AddToChainedFilter(mesaFilter);
}
} // namespace Rosen
} // namespace OHOS
