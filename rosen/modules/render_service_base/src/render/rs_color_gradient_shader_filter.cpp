/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "render/rs_color_gradient_shader_filter.h"

#include "pipeline/rs_paint_filter_canvas.h"

#ifdef USE_M133_SKIA
#include "src/core/SkChecksum.h"
#else
#include "src/core/SkOpts.h"
#endif

namespace OHOS {
namespace Rosen {

RSColorGradientShaderFilter::RSColorGradientShaderFilter(std::vector<float> colors, std::vector<float> positions,
    std::vector<float> strengths, std::shared_ptr<RSShaderMask> mask)
    : colors_(colors), positions_(positions), strengths_(strengths), mask_(mask)
{
    type_ = ShaderFilterType::COLOR_GRADIENT;
#ifdef USE_M133_SKIA
    const auto hashFunc = SkChecksum::Hash32;
#else
    const auto hashFunc = SkOpts::hash;
#endif
    hash_ = hashFunc(colors_.data(), colors_.size() * sizeof(float), hash_);
    hash_ = hashFunc(positions_.data(), positions_.size() * sizeof(float), hash_);
    hash_ = hashFunc(strengths_.data(), strengths_.size() * sizeof(float), hash_);
    if (mask_) {
        auto maskHash = mask_->Hash();
        hash_ = hashFunc(&maskHash, sizeof(maskHash), hash_);
    }
}

void RSColorGradientShaderFilter::GenerateGEVisualEffect(
    std::shared_ptr<Drawing::GEVisualEffectContainer> visualEffectContainer)
{
    if (visualEffectContainer == nullptr) {
        return;
    }
    auto colorGradientFilter = std::make_shared<Drawing::GEVisualEffect>("COLOR_GRADIENT",
        Drawing::DrawingPaintType::BRUSH);
    colorGradientFilter->SetParam("COLOR", colors_);
    colorGradientFilter->SetParam("POSITION", positions_);
    colorGradientFilter->SetParam("STRENGTH", strengths_);
    if (mask_) {
        colorGradientFilter->SetParam("MASK", mask_->GenerateGEShaderMask());
    }

    visualEffectContainer->AddToChainedFilter(colorGradientFilter);
}

const std::vector<float> RSColorGradientShaderFilter::GetColors() const
{
    return colors_;
}

const std::vector<float> RSColorGradientShaderFilter::GetPositions() const
{
    return positions_;
}

const std::vector<float> RSColorGradientShaderFilter::GetStrengths() const
{
    return strengths_;
}

const std::shared_ptr<RSShaderMask>& RSColorGradientShaderFilter::GetMask() const
{
    return mask_;
}
} // Rosen
} // OHOS