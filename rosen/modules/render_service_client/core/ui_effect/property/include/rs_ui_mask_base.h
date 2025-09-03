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

#ifndef ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_UI_MASK_BASE_H
#define ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_UI_MASK_BASE_H

#include "effect/rs_render_mask_base.h"
#include "ui_effect/mask/include/mask_para.h"
#include "ui_effect/property/include/rs_ui_property_tag.h"
#include "ui_effect/property/include/rs_ui_template.h"

namespace OHOS {
namespace Rosen {

class RSNGMaskBase : public RSNGEffectBase<RSNGMaskBase, RSNGRenderMaskBase> {
public:
    virtual ~RSNGMaskBase() = default;

    static std::shared_ptr<RSNGMaskBase> Create(RSNGEffectType type);

    static std::shared_ptr<RSNGMaskBase> Create(std::shared_ptr<MaskPara> maskPara);
};

template<RSNGEffectType Type, typename... PropertyTags>
using RSNGMaskTemplate = RSNGEffectTemplate<RSNGMaskBase, Type, PropertyTags...>;

#define ADD_PROPERTY_TAG(Effect, Prop) Effect##Prop##Tag

#define DECLARE_MASK(MaskName, MaskType, ...) \
    using RSNG##MaskName = RSNGMaskTemplate<RSNGEffectType::MaskType, __VA_ARGS__>

DECLARE_MASK(RippleMask, RIPPLE_MASK,
    ADD_PROPERTY_TAG(RippleMask, Center),
    ADD_PROPERTY_TAG(RippleMask, Radius),
    ADD_PROPERTY_TAG(RippleMask, Width),
    ADD_PROPERTY_TAG(RippleMask, Offset)
);

DECLARE_MASK(DoubleRippleMask, DOUBLE_RIPPLE_MASK,
    ADD_PROPERTY_TAG(DoubleRippleMask, Center1),
    ADD_PROPERTY_TAG(DoubleRippleMask, Center2),
    ADD_PROPERTY_TAG(DoubleRippleMask, Radius),
    ADD_PROPERTY_TAG(DoubleRippleMask, Width),
    ADD_PROPERTY_TAG(DoubleRippleMask, Turbulence),
    ADD_PROPERTY_TAG(DoubleRippleMask, HaloThickness)
);

DECLARE_MASK(PixelMapMask, PIXEL_MAP_MASK,
    ADD_PROPERTY_TAG(PixelMapMask, Src),
    ADD_PROPERTY_TAG(PixelMapMask, Dst),
    ADD_PROPERTY_TAG(PixelMapMask, FillColor),
    ADD_PROPERTY_TAG(PixelMapMask, Image)
);

DECLARE_MASK(RadialGradientMask, RADIAL_GRADIENT_MASK,
    ADD_PROPERTY_TAG(RadialGradientMask, Center),
    ADD_PROPERTY_TAG(RadialGradientMask, RadiusX),
    ADD_PROPERTY_TAG(RadialGradientMask, RadiusY),
    ADD_PROPERTY_TAG(RadialGradientMask, Colors),
    ADD_PROPERTY_TAG(RadialGradientMask, Positions)
);

DECLARE_MASK(WaveGradientMask, WAVE_GRADIENT_MASK,
    ADD_PROPERTY_TAG(WaveGradientMask, WaveCenter),
    ADD_PROPERTY_TAG(WaveGradientMask, WaveWidth),
    ADD_PROPERTY_TAG(WaveGradientMask, PropagationRadius),
    ADD_PROPERTY_TAG(WaveGradientMask, BlurRadius),
    ADD_PROPERTY_TAG(WaveGradientMask, TurbulenceStrength)
);

DECLARE_MASK(FrameGradientMask, FRAME_GRADIENT_MASK,
    ADD_PROPERTY_TAG(FrameGradientMask, GradientBezierControlPoints),
    ADD_PROPERTY_TAG(FrameGradientMask, CornerRadius),
    ADD_PROPERTY_TAG(FrameGradientMask, FrameWidth)
);

#undef DECLARE_MASK
#undef ADD_PROPERTY_TAG

} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_UI_MASK_BASE_H
