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

#include "modifier_ng/appearance/rs_blend_modifier.h"

#include "ui_effect/property/include/rs_ui_blender_base.h"

namespace OHOS::Rosen::ModifierNG {
void RSBlendModifier::SetColorBlendMode(RSColorBlendMode colorBlendMode)
{
    Setter<RSProperty>(RSPropertyType::COLOR_BLEND_MODE, static_cast<int>(colorBlendMode));
}

RSColorBlendMode RSBlendModifier::GetColorBlendMode() const
{
    return static_cast<RSColorBlendMode>(Getter(RSPropertyType::COLOR_BLEND_MODE, 0));
}

void RSBlendModifier::SetColorBlendApplyType(RSColorBlendApplyType colorBlendApplyType)
{
    Setter<RSProperty>(RSPropertyType::COLOR_BLEND_APPLY_TYPE, static_cast<int>(colorBlendApplyType));
}

RSColorBlendApplyType RSBlendModifier::GetColorBlendApplyType() const
{
    return static_cast<RSColorBlendApplyType>(Getter(RSPropertyType::COLOR_BLEND_APPLY_TYPE, 0));
}

void RSBlendModifier::SetNGBlenderBase(std::shared_ptr<RSNGBlenderBase> blender)
{
    Setter<RSProperty>(RSPropertyType::FOREGROUND_NG_BLENDER, blender);
}

} // namespace OHOS::Rosen::ModifierNG
