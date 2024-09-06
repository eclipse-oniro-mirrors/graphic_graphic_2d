/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "modifier/rs_property_modifier.h"

#include "modifier/rs_modifier_type.h"
#include "modifier/rs_render_modifier.h"

namespace OHOS {
namespace Rosen {

RSEnvForegroundColorModifier::RSEnvForegroundColorModifier(const std::shared_ptr<RSPropertyBase>& property)
    : RSForegroundModifier(property, RSModifierType::ENV_FOREGROUND_COLOR)
{}
RSModifierType RSEnvForegroundColorModifier::GetModifierType() const
{
    return RSModifierType::ENV_FOREGROUND_COLOR;
}
std::shared_ptr<RSRenderModifier> RSEnvForegroundColorModifier::CreateRenderModifier() const
{
    auto renderProperty = GetRenderProperty();
    auto renderModifier = std::make_shared<RSEnvForegroundColorRenderModifier>(renderProperty);
    return renderModifier;
}

RSEnvForegroundColorStrategyModifier::RSEnvForegroundColorStrategyModifier(
    const std::shared_ptr<RSPropertyBase>& property)
    : RSForegroundModifier(property, RSModifierType::ENV_FOREGROUND_COLOR_STRATEGY)
{}
RSModifierType RSEnvForegroundColorStrategyModifier::GetModifierType() const
{
    return RSModifierType::ENV_FOREGROUND_COLOR_STRATEGY;
}
std::shared_ptr<RSRenderModifier> RSEnvForegroundColorStrategyModifier::CreateRenderModifier() const
{
    auto renderProperty = GetRenderProperty();
    auto renderModifier = std::make_shared<RSEnvForegroundColorStrategyRenderModifier>(renderProperty);
    return renderModifier;
}

#define DECLARE_ANIMATABLE_MODIFIER_CREATE(MODIFIER_NAME)                                          \
    std::shared_ptr<RSRenderModifier> RS##MODIFIER_NAME##Modifier::CreateRenderModifier() const    \
    {                                                                                              \
        auto renderProperty = GetRenderProperty();                                                 \
        auto renderModifier = std::make_shared<RS##MODIFIER_NAME##RenderModifier>(renderProperty); \
        return renderModifier;                                                                     \
    }

#define DECLARE_ANIMATABLE_MODIFIER(MODIFIER_NAME, TYPE, MODIFIER_TYPE, DELTA_OP, MODIFIER_TIER, THRESHOLD_TYPE) \
    RS##MODIFIER_NAME##Modifier::RS##MODIFIER_NAME##Modifier(const std::shared_ptr<RSPropertyBase>& property)    \
        : RS##MODIFIER_TIER##Modifier(property, RSModifierType::MODIFIER_TYPE)                                   \
    {                                                                                                            \
        property_->SetThresholdType(ThresholdType::THRESHOLD_TYPE);                                              \
    }                                                                                                            \
    RSModifierType RS##MODIFIER_NAME##Modifier::GetModifierType() const                                          \
    {                                                                                                            \
        return RSModifierType::MODIFIER_TYPE;                                                                    \
    }                                                                                                            \
    DECLARE_ANIMATABLE_MODIFIER_CREATE(MODIFIER_NAME)

#define DECLARE_NOANIMATABLE_MODIFIER_CREATE(MODIFIER_NAME)                                        \
    std::shared_ptr<RSRenderModifier> RS##MODIFIER_NAME##Modifier::CreateRenderModifier() const    \
    {                                                                                              \
        auto renderProperty = GetRenderProperty();                                                 \
        auto renderModifier = std::make_shared<RS##MODIFIER_NAME##RenderModifier>(renderProperty); \
        return renderModifier;                                                                     \
    }

#define DECLARE_NOANIMATABLE_MODIFIER(MODIFIER_NAME, TYPE, MODIFIER_TYPE, MODIFIER_TIER)                            \
    RS##MODIFIER_NAME##Modifier::RS##MODIFIER_NAME##Modifier(const std::shared_ptr<RSPropertyBase>& property)       \
        : RS##MODIFIER_TIER##Modifier(property, RSModifierType::MODIFIER_TYPE)                                      \
    {}                                                                                                              \
    RSModifierType RS##MODIFIER_NAME##Modifier::GetModifierType() const                                             \
    {                                                                                                               \
        return RSModifierType::MODIFIER_TYPE;                                                                       \
    }                                                                                                               \
    DECLARE_NOANIMATABLE_MODIFIER_CREATE(MODIFIER_NAME)

#include "modifier/rs_modifiers_def.in"

#undef DECLARE_ANIMATABLE_MODIFIER
#undef DECLARE_NOANIMATABLE_MODIFIER
} // namespace Rosen
} // namespace OHOS
