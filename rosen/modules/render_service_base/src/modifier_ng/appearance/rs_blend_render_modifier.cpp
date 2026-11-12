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

#include "modifier_ng/appearance/rs_blend_render_modifier.h"

#include "effect/rs_render_blender_base.h"

namespace OHOS::Rosen::ModifierNG {
const RSBlendRenderModifier::LegacyPropertyApplierMap RSBlendRenderModifier::LegacyPropertyApplierMap_ = {
    { RSPropertyType::COLOR_BLEND_MODE, RSRenderModifier::PropertyApplyHelper<int, &RSProperties::SetColorBlendMode> },
    { RSPropertyType::COLOR_BLEND_APPLY_TYPE,
        RSRenderModifier::PropertyApplyHelper<int, &RSProperties::SetColorBlendApplyType> },
    // NG blender: store the NG object only; unpacking happens in RSBeginBlenderDrawable.
    { RSPropertyType::FOREGROUND_NG_BLENDER,
        RSRenderModifier::PropertyApplyHelper<std::shared_ptr<RSNGRenderBlenderBase>, &RSProperties::SetNGBlender> },
};

void RSBlendRenderModifier::ResetProperties(RSProperties& properties)
{
    properties.SetColorBlendMode(0);
    properties.SetColorBlendApplyType(0);
    properties.SetNGBlender(nullptr);
}
} // namespace OHOS::Rosen::ModifierNG
