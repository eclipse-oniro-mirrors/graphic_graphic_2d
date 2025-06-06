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
#include "render/rs_render_kawase_blur_filter.h"

#include "ge_visual_effect.h"
#include "ge_visual_effect_container.h"

#include "effect/color_matrix.h"
#include "effect/runtime_shader_builder.h"
#include "platform/common/rs_system_properties.h"

#ifdef USE_M133_SKIA
#include "src/core/SkChecksum.h"
#include "include/gpu/ganesh/GrDirectContext.h"
#else
#include "src/core/SkOpts.h"
#include "include/gpu/GrDirectContext.h"
#endif

namespace OHOS {
namespace Rosen {
#ifdef ROSEN_OHOS
bool RSKawaseBlurShaderFilter::isMesablurAllEnable_ = RSSystemProperties::GetForceKawaseDisabled();
#else
bool RSKawaseBlurShaderFilter::isMesablurAllEnable_ = false;
#endif
RSKawaseBlurShaderFilter::RSKawaseBlurShaderFilter(int radius)
    : RSRenderFilterParaBase(RSUIFilterType::KAWASE), radius_(radius)
{
#ifdef USE_M133_SKIA
    const auto hashFunc = SkChecksum::Hash32;
#else
    const auto hashFunc = SkOpts::hash;
#endif
    hash_ = hashFunc(&radius_, sizeof(radius_), 0);
}

void RSKawaseBlurShaderFilter::SetMesablurAllEnabledByCCM(bool flag)
{
    isMesablurAllEnable_ = isMesablurAllEnable_ || flag;
}

int RSKawaseBlurShaderFilter::GetRadius() const
{
    return radius_;
}

void RSKawaseBlurShaderFilter::GetDescription(std::string& out) const
{
    out += ", radius: " + std::to_string(radius_) + " sigma";
    if (isMesablurAllEnable_) {
        out += ", replaced by Mesa.";
    }
}

void RSKawaseBlurShaderFilter::GenerateGEVisualEffect(
    std::shared_ptr<Drawing::GEVisualEffectContainer> visualEffectContainer)
{
    if (isMesablurAllEnable_) {
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