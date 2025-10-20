/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_UIEFFECT_EFFECT_NAPI_H
#define OHOS_UIEFFECT_EFFECT_NAPI_H

#include <hilog/log.h>
#include <iostream>

#include "effect/include/background_color_effect_para.h"
#include "effect/include/blender.h"
#include "effect/include/border_light_effect_para.h"
#include "effect/include/brightness_blender.h"
#include "effect/include/color_gradient_effect_para.h"
#include "effect/include/shadow_blender.h"

#include "effect/include/visual_effect.h"
#include "effect/include/visual_effect_para.h"

#include "effect/include/harmonium_effect_para.h"

#include "mask/include/mask.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Rosen {

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD001405

#undef LOG_TAG
#define LOG_TAG "UiEffect_Effect"
#define UIEFFECT_LOG_D(fmt, ...) HILOG_DEBUG(LOG_CORE, fmt, ##__VA_ARGS__)
#define UIEFFECT_LOG_I(fmt, ...) HILOG_INFO(LOG_CORE, fmt, ##__VA_ARGS__)
#define UIEFFECT_LOG_E(fmt, ...) HILOG_ERROR(LOG_CORE, fmt, ##__VA_ARGS__)

class EffectNapi {
public:
    EffectNapi();
    ~EffectNapi();
    static napi_value Init(napi_env env, napi_value exports);

private:
    static thread_local napi_ref sConstructor_;
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize);

    static napi_value CreateEffect(napi_env env, napi_callback_info info);
    static napi_value CreateBrightnessBlender(napi_env env, napi_callback_info info);
    static napi_value CreateHdrBrightnessBlender(napi_env env, napi_callback_info info);
    static napi_value SetBackgroundColorBlender(napi_env env, napi_callback_info info);
    static bool ParseBrightnessBlender(napi_env env, napi_value jsObject, BrightnessBlender* blender);
    static napi_value CreateShadowBlender(napi_env env, napi_callback_info info);
    static bool CheckCreateShadowBlender(napi_env env, napi_value jsObject);
    static bool ParseShadowBlender(napi_env env, napi_value jsObject, ShadowBlender* blender);
    static napi_value CreateBorderLight(napi_env env, napi_callback_info info);
    static bool GetBorderLight(napi_env env, napi_value* param, size_t length,
        std::shared_ptr<BorderLightEffectPara>& para);
    static napi_value CreateColorGradientEffect(napi_env env, napi_callback_info info);
    static bool GetColorGradientArray(napi_env env, napi_value* argValue,
        std::shared_ptr<ColorGradientEffectPara>& para, uint32_t arraySize);
    static float GetSpecialValue(napi_env env, napi_value argValue);
    static napi_value CreateHarmoniumEffect(napi_env env, napi_callback_info info);

    std::shared_ptr<VisualEffect> m_EffectObj = nullptr;
};
} // namespace Rosen
} // namespace OHOS
#endif // OHOS_UIEFFECT_EFFECT_NAPI_H
