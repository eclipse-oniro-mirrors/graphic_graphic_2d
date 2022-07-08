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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_EXTENDED_MODIFIER_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_EXTENDED_MODIFIER_H

#include "modifier/rs_modifier_base.h"
#include "common/rs_common_def.h"
#include "common/rs_macros.h"

class SkCanvas;

namespace OHOS {
namespace Rosen {
class RSExtendedModifierHelper {
public:
    static RSDrawingContext CreateDrawingContext(NodeId nodeId);
    static std::shared_ptr<RSRenderModifier> CreateRenderModifier(
        RSDrawingContext& ctx, PropertyId id, RSModifierType type);
    static std::shared_ptr<RSAnimatableRenderProperty<std::shared_ptr<DrawCmdList>>> CreateDrawCmdListRenderProp(
        RSDrawingContext& ctx, PropertyId id);
};

template<typename T>
class RS_EXPORT RSExtendedModifier : public RSAnimatableModifier<T> {
public:
    RSExtendedModifier(const std::shared_ptr<RSProperty<T>> property)
        : RSAnimatableModifier<T>(property, RSModifierType::EXTENDED)
    {
        RSAnimatableModifier<T>::property_->SetIsCustom(true);
    }
    RSModifierType GetModifierType() override
    {
        return RSModifierType::EXTENDED;
    }
    virtual ~RSExtendedModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;

protected:
    RSExtendedModifier(const std::shared_ptr<RSProperty<T>> property, const RSModifierType type)
        : RSAnimatableModifier<T>(property, type)
    {
        RSAnimatableModifier<T>::property_->SetIsCustom(true);
    }
    void UpdateToRender() override;
};

template<typename T>
class RS_EXPORT RSContentStyleModifier : public RSExtendedModifier<T> {
public:
    RSContentStyleModifier(const std::shared_ptr<RSProperty<T>> property)
        : RSExtendedModifier<T>(property, RSModifierType::CONTENT_STYLE)
    {}
    RSModifierType GetModifierType() override
    {
        return RSModifierType::CONTENT_STYLE;
    }
};

template<typename T>
class RS_EXPORT RSOverlayStyleModifier : public RSExtendedModifier<T> {
public:
    RSOverlayStyleModifier(const std::shared_ptr<RSProperty<T>> property)
        : RSExtendedModifier<T>(property, RSModifierType::OVERLAY_STYLE)
    {}
    RSModifierType GetModifierType() override
    {
        return RSModifierType::OVERLAY_STYLE;
    }
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_EXTENDED_MODIFIER_H
