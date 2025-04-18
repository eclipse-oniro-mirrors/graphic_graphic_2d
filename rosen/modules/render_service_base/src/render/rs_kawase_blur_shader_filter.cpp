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
#include "render/rs_kawase_blur_shader_filter.h"

#include "effect/color_matrix.h"
#include "effect/runtime_shader_builder.h"
#include "include/gpu/GrDirectContext.h"
#include "platform/common/rs_system_properties.h"
#include "src/core/SkOpts.h"


namespace OHOS {
namespace Rosen {
RSKawaseBlurShaderFilter::RSKawaseBlurShaderFilter(int radius)
    : radius_(radius)
{
    type_ = ShaderFilterType::KAWASE;
#ifndef ENABLE_M133_SKIA
    hash_ = SkOpts::hash(&radius_, sizeof(radius_), 0);
#else
    hash_ = SkChecksum::Hash32(&radius_, sizeof(radius_), 0);
#endif
}

RSKawaseBlurShaderFilter::~RSKawaseBlurShaderFilter() = default;

int RSKawaseBlurShaderFilter::GetRadius() const
{
    return radius_;
}

std::string RSKawaseBlurShaderFilter::GetDescription() const
{
    std::string filterString = ", radius: " + std::to_string(radius_) + " sigma";
    if (RSSystemProperties::GetForceKawaseDisabled()) {
        filterString = filterString + ", replaced by Mesa.";
    }
    return filterString;
}

void RSKawaseBlurShaderFilter::GenerateGEVisualEffect(
    std::shared_ptr<Drawing::GEVisualEffectContainer> visualEffectContainer)
{
    if (RSSystemProperties::GetForceKawaseDisabled()) {
        // Substitute the blur algorithm
        auto kawaseFilter = std::make_shared<Drawing::GEVisualEffect>("MESA_BLUR", Drawing::DrawingPaintType::BRUSH);
        kawaseFilter->SetParam("MESA_BLUR_RADIUS", (int)radius_); // blur radius
        visualEffectContainer->AddToChainedFilter(kawaseFilter);
        return;
    }
    auto kawaseFilter = std::make_shared<Drawing::GEVisualEffect>("KAWASE_BLUR", Drawing::DrawingPaintType::BRUSH);
    kawaseFilter->SetParam("KAWASE_BLUR_RADIUS", (int)radius_); // blur radius
    visualEffectContainer->AddToChainedFilter(kawaseFilter);
}
} // namespace Rosen
} // namespace OHOS