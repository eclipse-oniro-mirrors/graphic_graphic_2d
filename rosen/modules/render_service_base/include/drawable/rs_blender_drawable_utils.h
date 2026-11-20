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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_BLENDER_DRAWABLE_UTILS_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_BLENDER_DRAWABLE_UTILS_H

#include <memory>

#include "effect/runtime_blender_builder.h"

namespace OHOS::Rosen {
class RSProperties;
class RSNGRenderBlenderBase;
class RSPaintFilterCanvas;
struct RSDynamicBrightnessPara;
struct RSHdrDarkenBlenderPara;
struct RSColorfulBrightnessBlenderPara;

namespace Drawing {
class RuntimeEffect;
}

/*
 * Blender utilities on the drawable side: unpacks NG blender property tags into
 * flat params, builds the concrete blenders from in-repo GLSL, and applies or
 * restores blenders on the canvas. Blenders keep their GLSL in this repository,
 * so these stay on the drawable side instead of the effect base.
 */
class RSBlenderDrawableUtils {
public:
    /* Returns nullptr for invalid params or unregistered types; callers fall back to blendMode. */
    static std::shared_ptr<Drawing::Blender> MakeBlenderFromNG(
        const std::shared_ptr<RSNGRenderBlenderBase>& blender);

    /* EDR applies only to colorful/brightness blenders, driven by their HdrEnabled tag. */
    static bool GetNGBlenderEnableEDR(const RSProperties& properties);

    static std::shared_ptr<Drawing::RuntimeBlenderBuilder> MakeDynamicBrightnessBuilder();
    static std::shared_ptr<Drawing::RuntimeBlenderBuilder> MakeDynamicBrightnessLinearBuilder();
    /* Returns nullptr when dynamic brightness is disabled or the runtime effect fails. */
    static std::shared_ptr<Drawing::Blender> MakeDynamicBrightnessBlender(const RSDynamicBrightnessPara& params);
    static std::shared_ptr<Drawing::Blender> MakeHdrDarkenBlender(const RSHdrDarkenBlenderPara& params);
    static std::shared_ptr<Drawing::Blender> MakeColorfulBrightnessBlender(
        const RSColorfulBrightnessBlenderPara& params);

    static bool IsDangerousBlendMode(int blendMode, int blendApplyType);
    static void BeginBlender(RSPaintFilterCanvas& canvas, std::shared_ptr<Drawing::Blender> blender,
        int blendModeApplyType, bool isDangerous);
    static void EndBlender(RSPaintFilterCanvas& canvas, int blendModeApplyType);

private:
    static std::shared_ptr<Drawing::RuntimeEffect> dynamicBrightnessBlenderEffect_;
    static std::shared_ptr<Drawing::RuntimeEffect> dynamicBrightnessLinearBlenderEffect_;
    static std::shared_ptr<Drawing::RuntimeEffect> hdrDarkenBlenderEffect_;
};
} // namespace OHOS::Rosen

#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_BLENDER_DRAWABLE_UTILS_H
