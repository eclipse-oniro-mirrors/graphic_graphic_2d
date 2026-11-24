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

#include "effect/rs_render_blender_base.h"

#include <unordered_map>

#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
using BlenderCreator = std::function<std::shared_ptr<RSNGRenderBlenderBase>()>;

static std::unordered_map<RSNGEffectType, BlenderCreator> creatorLUT = {
    {RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER, [] {
            return std::make_shared<RSNGRenderColorfulBrightnessBlender>();
        }
    },
    {RSNGEffectType::BRIGHTNESS_BLENDER, [] {
            return std::make_shared<RSNGRenderBrightnessBlender>();
        }
    },
    {RSNGEffectType::HDR_DARKEN_BLENDER, [] {
            return std::make_shared<RSNGRenderHdrDarkenBlender>();
        }
    },
};

std::shared_ptr<RSNGRenderBlenderBase> RSNGRenderBlenderBase::Create(RSNGEffectType type)
{
    auto it = creatorLUT.find(type);
    return it != creatorLUT.end() ? it->second() : nullptr;
}

[[nodiscard]] bool RSNGRenderBlenderBase::Unmarshalling(Parcel& parcel, std::shared_ptr<RSNGRenderBlenderBase>& val)
{
    std::shared_ptr<RSNGRenderBlenderBase> head = nullptr;
    auto current = head;
    for (size_t effectCount = 0; effectCount < EFFECT_COUNT_LIMIT; ++effectCount) {
        RSNGEffectTypeUnderlying type = 0;
        if (!RSMarshallingHelper::Unmarshalling(parcel, type)) {
            ROSEN_LOGE("RSNGRenderBlenderBase: Unmarshalling type failed");
            return false;
        }

        if (type == END_OF_CHAIN) {
            val = head;
            return true;
        }

        auto blender = Create(static_cast<RSNGEffectType>(type));
        if (!blender || !blender->OnUnmarshalling(parcel)) {
            ROSEN_LOGE("RSNGRenderBlenderBase: Unmarshalling blender failed with type %{public}d", type);
            return false;
        }
        if (!current) {
            head = blender;
        } else {
            current->nextEffect_ = blender;
        }
        current = blender;
    }

    ROSEN_LOGE("RSNGRenderBlenderBase: UnMarshalling blender count arrive limit(%{public}zu)",
        EFFECT_COUNT_LIMIT);
    return false;
}
} // namespace Rosen
} // namespace OHOS
