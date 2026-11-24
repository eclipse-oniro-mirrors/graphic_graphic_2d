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

#ifndef ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_UI_BLENDER_BASE_H
#define ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_UI_BLENDER_BASE_H

#include "effect/rs_render_blender_base.h"
#include "ui_effect/effect/include/blender.h"
#include "ui_effect/property/include/rs_ui_property_tag.h"
#include "ui_effect/property/include/rs_ui_template.h"

namespace OHOS {
namespace Rosen {

class RSNGBlenderBase : public RSNGEffectBase<RSNGBlenderBase, RSNGRenderBlenderBase> {
public:
    virtual ~RSNGBlenderBase() = default;

    static std::shared_ptr<RSNGBlenderBase> Create(RSNGEffectType type);

    // Convert an old-style Blender (pure data) into an NG blender via convertorLUT.
    static std::shared_ptr<RSNGBlenderBase> Create(const Blender* blender);
};

template<RSNGEffectType Type, typename... PropertyTags>
using RSNGBlenderTemplate = RSNGEffectTemplate<RSNGBlenderBase,
        RSNGRenderBlenderTemplate<Type, typename PropertyTags::RenderPropertyTagType...>, Type, PropertyTags...>;

#define ADD_PROPERTY_TAG(Effect, Prop) Effect##Prop##Tag

#define DECLARE_BLENDER(BlenderName, BlenderType, ...) \
    using RSNG##BlenderName = RSNGBlenderTemplate<RSNGEffectType::BlenderType, __VA_ARGS__>

#include "effect/rs_render_blender_def.in"

#undef ADD_PROPERTY_TAG
#undef DECLARE_BLENDER

} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_UI_BLENDER_BASE_H
