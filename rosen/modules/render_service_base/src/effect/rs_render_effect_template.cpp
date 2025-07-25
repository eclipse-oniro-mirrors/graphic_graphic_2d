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

#include "effect/rs_render_effect_template.h"

#include "effect/rs_render_mask_base.h"
#include "ge_visual_effect.h"
#include "ge_visual_effect_container.h"
#include "render/rs_path.h"
#include "render/rs_pixel_map_util.h"

namespace OHOS {
namespace Rosen {
void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, float value)
{
    geFilter.SetParam(desc, value);
}

void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, bool value)
{
    geFilter.SetParam(desc, value);
}

void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, const Vector4f& value)
{
    geFilter.SetParam(desc, value);
}

void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, const Vector3f& value)
{
    geFilter.SetParam(desc, value);
}

void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, const Vector2f& value)
{
    geFilter.SetParam(desc, std::make_pair(value.x_, value.y_));
}

void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, std::shared_ptr<RSNGRenderMaskBase> value)
{
    std::shared_ptr<Drawing::GEVisualEffect> geVisualEffect = value ? value->GenerateGEVisualEffect() : nullptr;
    std::shared_ptr<Drawing::GEShaderMask> geMask = geVisualEffect ? geVisualEffect->GenerateShaderMask() : nullptr;
    geFilter.SetParam(desc, geMask);
}

void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, const VectorVector2F& value)
{
    geFilter.SetParam(desc, value);
}

void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, std::shared_ptr<Media::PixelMap> value)
{
    auto image = RSPixelMapUtil::ExtractDrawingImage(value);
    geFilter.SetParam(desc, image);
}

void RSNGRenderEffectHelper::UpdateVisualEffectParamImpl(Drawing::GEVisualEffect& geFilter,
    const std::string& desc, const std::vector<float>& value)
{
    geFilter.SetParam(desc, value);
}

std::shared_ptr<Drawing::GEVisualEffect> RSNGRenderEffectHelper::CreateGEVisualEffect(RSNGEffectType type)
{
    return std::make_shared<Drawing::GEVisualEffect>(GetEffectTypeString(type), Drawing::DrawingPaintType::BRUSH);
}

void RSNGRenderEffectHelper::AppendToGEContainer(std::shared_ptr<Drawing::GEVisualEffectContainer>& ge,
    std::shared_ptr<Drawing::GEVisualEffect> geShader)
{
    if (!ge) {
        return;
    }
    ge->AddToChainedFilter(geShader);
}
} // namespace Rosen
} // namespace OHOS
