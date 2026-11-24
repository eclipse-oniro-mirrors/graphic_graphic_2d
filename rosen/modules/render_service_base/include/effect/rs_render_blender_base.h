/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_BASE_EFFECT_RS_RENDER_BLENDER_BASE_H
#define RENDER_SERVICE_BASE_EFFECT_RS_RENDER_BLENDER_BASE_H

#include "effect/rs_render_effect_template.h"
#include "effect/rs_render_property_tag.h"
#include "transaction/rs_marshalling_helper.h"

namespace OHOS {
namespace Rosen {

// Server-side NG blender base. Unlike filter/shader/mask, blenders keep their GLSL here and
// generate no GE effects; the drawable side unpacks the NG properties.
class RSB_EXPORT RSNGRenderBlenderBase : public RSNGRenderEffectBase<RSNGRenderBlenderBase> {
public:
    virtual ~RSNGRenderBlenderBase() = default;

    static std::shared_ptr<RSNGRenderBlenderBase> Create(RSNGEffectType type);

    [[nodiscard]] static bool Unmarshalling(Parcel& parcel, std::shared_ptr<RSNGRenderBlenderBase>& val);
};

template<RSNGEffectType Type, typename... PropertyTags>
class RSNGRenderBlenderTemplate : public RSNGRenderEffectTemplate<RSNGRenderBlenderBase, Type, PropertyTags...> {
public:
    using EffectTemplateBase = RSNGRenderEffectTemplate<RSNGRenderBlenderBase, Type, PropertyTags...>;

    RSNGRenderBlenderTemplate() : EffectTemplateBase() {}
    ~RSNGRenderBlenderTemplate() override = default;
    RSNGRenderBlenderTemplate(const std::tuple<PropertyTags...>& properties) noexcept
        : EffectTemplateBase(properties) {}
};

#define ADD_PROPERTY_TAG(Effect, Prop) Effect##Prop##RenderTag
#define DECLARE_BLENDER(BlenderName, BlenderType, ...) \
    using RSNGRender##BlenderName = RSNGRenderBlenderTemplate<RSNGEffectType::BlenderType, __VA_ARGS__>

#include "effect/rs_render_blender_def.in"

#undef ADD_PROPERTY_TAG
#undef DECLARE_BLENDER

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_EFFECT_RS_RENDER_BLENDER_BASE_H
