/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "js_brush.h"

#include <cstdint>

#include "js_drawing_utils.h"
#include "color_filter_napi/js_color_filter.h"
#include "image_filter_napi/js_image_filter.h"
#include "mask_filter_napi/js_mask_filter.h"
#include "shader_effect_napi/js_shader_effect.h"
#include "shadow_layer_napi/js_shadow_layer.h"

namespace OHOS::Rosen {
namespace Drawing {
thread_local napi_ref JsBrush::constructor_ = nullptr;
const std::string CLASS_NAME = "Brush";
napi_value JsBrush::Init(napi_env env, napi_value exportObj)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("setColor", SetColor),
        DECLARE_NAPI_FUNCTION("getColor", GetColor),
        DECLARE_NAPI_FUNCTION("setAntiAlias", SetAntiAlias),
        DECLARE_NAPI_FUNCTION("isAntiAlias", IsAntiAlias),
        DECLARE_NAPI_FUNCTION("setAlpha", SetAlpha),
        DECLARE_NAPI_FUNCTION("getAlpha", GetAlpha),
        DECLARE_NAPI_FUNCTION("setColorFilter", SetColorFilter),
        DECLARE_NAPI_FUNCTION("getColorFilter", GetColorFilter),
        DECLARE_NAPI_FUNCTION("setImageFilter", SetImageFilter),
        DECLARE_NAPI_FUNCTION("setMaskFilter", SetMaskFilter),
        DECLARE_NAPI_FUNCTION("setBlendMode", SetBlendMode),
        DECLARE_NAPI_FUNCTION("setShadowLayer", SetShadowLayer),
        DECLARE_NAPI_FUNCTION("setShaderEffect", SetShaderEffect),
        DECLARE_NAPI_FUNCTION("reset", Reset),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
                                           sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    if (status != napi_ok) {
        ROSEN_LOGE("JsBrush::Init Failed to define Brush class");
        return nullptr;
    }

    status = napi_create_reference(env, constructor, 1, &constructor_);
    if (status != napi_ok) {
        ROSEN_LOGE("JsBrush::Init Failed to create reference of constructor");
        return nullptr;
    }

    status = napi_set_named_property(env, exportObj, CLASS_NAME.c_str(), constructor);
    if (status != napi_ok) {
        ROSEN_LOGE("JsBrush::Init Failed to set constructor");
        return nullptr;
    }
    return exportObj;
}

napi_value JsBrush::Constructor(napi_env env, napi_callback_info info)
{
    size_t argCount = ARGC_ONE;
    napi_value argv[ARGC_ONE] = {nullptr};
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, argv, &jsThis, nullptr);
    if (status != napi_ok) {
        ROSEN_LOGE("JsBrush::Constructor failed to napi_get_cb_info");
        return nullptr;
    }

    JsBrush* jsBrush = nullptr;
    if (argCount == 0) {
        jsBrush = new(std::nothrow) JsBrush();
    } else {
        JsBrush* otherBrush = nullptr;
        GET_UNWRAP_PARAM(ARGC_ZERO, otherBrush);
        Brush* brush = otherBrush->GetBrush();
        if (brush != nullptr) {
            jsBrush = new(std::nothrow) JsBrush(*brush);
        }
    }
    if (jsBrush == nullptr) {
        ROSEN_LOGE("JsBrush::Constructor jsBrush is nullptr");
        return nullptr;
    }

    status = napi_wrap(env, jsThis, jsBrush, JsBrush::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsBrush;
        ROSEN_LOGE("JsBrush::Constructor Failed to wrap native instance");
        return nullptr;
    }
    return jsThis;
}

void JsBrush::Destructor(napi_env env, void* nativeObject, void* finalize)
{
    (void)finalize;
    if (nativeObject != nullptr) {
        JsBrush* napi = reinterpret_cast<JsBrush*>(nativeObject);
        delete napi;
    }
}

JsBrush::JsBrush()
{
    brush_ = new Brush();
}

JsBrush::JsBrush(const Brush& brush)
{
    brush_ = new Brush(brush);
}

JsBrush::~JsBrush()
{
    delete brush_;
}

napi_value JsBrush::SetColor(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (!jsBrush) {
        return nullptr;
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetColor brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    size_t argc = ARGC_FOUR;
    napi_value argv[ARGC_FOUR] = {nullptr};
    CHECK_PARAM_NUMBER_WITH_OPTIONAL_PARAMS(argv, argc, ARGC_ONE, ARGC_FOUR);

    Drawing::Color drawingColor;
    if (argc == ARGC_ONE) {
        bool isJsColor = false;
        napi_has_named_property(env, argv[ARGC_ZERO], JSPROPERTY[0], &isJsColor);
        if (isJsColor) {
            int32_t argb[ARGC_FOUR] = {0};
            if (!ConvertFromJsColor(env, argv[ARGC_ZERO], argb, ARGC_FOUR)) {
                ROSEN_LOGE("JsBrush::SetColor Argv[0] is invalid");
                return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                    "Parameter verification failed. The range of color channels must be [0, 255].");
            }
            drawingColor = Color::ColorQuadSetARGB(argb[ARGC_ZERO], argb[ARGC_ONE], argb[ARGC_TWO], argb[ARGC_THREE]);
        } else {
            uint32_t hexNumber = 0;
            GET_UINT32_PARAM(ARGC_ZERO, hexNumber);
            uint32_t alpha = (hexNumber >> 24) & 0xFF;
            uint32_t red = (hexNumber >> 16) & 0xFF;
            uint32_t green = (hexNumber >> 8) & 0xFF;
            uint32_t blue = hexNumber & 0xFF;
            drawingColor = Color::ColorQuadSetARGB(alpha, red, green, blue);
        }
    } else if (argc == ARGC_FOUR) {
        int32_t alpha = 0;
        GET_COLOR_PARAM(ARGC_ZERO, alpha);
        int32_t red = 0;
        GET_COLOR_PARAM(ARGC_ONE, red);
        int32_t green = 0;
        GET_COLOR_PARAM(ARGC_TWO, green);
        int32_t blue = 0;
        GET_COLOR_PARAM(ARGC_THREE, blue);
        drawingColor = Color::ColorQuadSetARGB(alpha, red, green, blue);
    } else {
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Incorrect number of parameters.");
    }
    brush->SetColor(drawingColor);
    return nullptr;
}

napi_value JsBrush::GetColor(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::GetColor brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    const Color& color = brush->GetColor();
    return GetColorAndConvertToJsValue(env, color);
}

napi_value JsBrush::SetAntiAlias(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (!jsBrush) {
        return nullptr;
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetAntiAlias brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    bool aa = false;
    GET_BOOLEAN_PARAM(ARGC_ZERO, aa);

    brush->SetAntiAlias(aa);
    return nullptr;
}

napi_value JsBrush::SetAlpha(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (!jsBrush) {
        return nullptr;
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetAlpha brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    int32_t alpha = 0;
    if (!ConvertFromJsNumber(env, argv[ARGC_ZERO], alpha, 0, Color::RGB_MAX)) {
        ROSEN_LOGE("JsBrush::SetAlpha Argv[0] is invalid");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "Parameter verification failed. The alpha range must be [0, 255].");
    }

    brush->SetAlpha(alpha);
    return nullptr;
}

napi_value JsBrush::IsAntiAlias(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::IsAntiAlias brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    return CreateJsValue(env, brush->IsAntiAlias());
}

napi_value JsBrush::GetAlpha(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::GetAlpha brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    uint32_t alpha = brush->GetAlpha();
    return CreateJsNumber(env, alpha);
}

napi_value JsBrush::SetColorFilter(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (!jsBrush) {
        return nullptr;
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetColorFilter brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    JsColorFilter* jsColorFilter = nullptr;
    napi_unwrap(env, argv[0], reinterpret_cast<void **>(&jsColorFilter));

    Filter filter = brush->GetFilter();
    filter.SetColorFilter(jsColorFilter ? jsColorFilter->GetColorFilter() : nullptr);
    brush->SetFilter(filter);
    return nullptr;
}

napi_value JsBrush::GetColorFilter(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (jsBrush == nullptr) {
        ROSEN_LOGE("JsBrush::GetColorFilter jsBrush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::GetColorFilter brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }
    if (brush->HasFilter()) {
        return JsColorFilter::Create(env, brush->GetFilter().GetColorFilter());
    }
    return nullptr;
}

napi_value JsBrush::SetImageFilter(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (jsBrush == nullptr) {
        ROSEN_LOGE("JsBrush::SetImageFilter jsBrush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetImageFilter brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    JsImageFilter* jsImageFilter = nullptr;
    napi_unwrap(env, argv[ARGC_ZERO], reinterpret_cast<void **>(&jsImageFilter));

    Filter filter = brush->GetFilter();
    filter.SetImageFilter(jsImageFilter != nullptr ? jsImageFilter->GetImageFilter() : nullptr);
    brush->SetFilter(filter);
    return nullptr;
}

napi_value JsBrush::SetMaskFilter(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (jsBrush == nullptr) {
        ROSEN_LOGE("JsBrush::SetMaskFilter jsBrush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetMaskFilter brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    JsMaskFilter* jsMaskFilter = nullptr;
    napi_unwrap(env, argv[ARGC_ZERO], reinterpret_cast<void **>(&jsMaskFilter));

    Filter filter = brush->GetFilter();
    filter.SetMaskFilter(jsMaskFilter ? jsMaskFilter->GetMaskFilter() : nullptr);
    brush->SetFilter(filter);
    return nullptr;
}

napi_value JsBrush::SetBlendMode(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (!jsBrush) {
        return nullptr;
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetBlendMode brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    int32_t mode = 0;
    GET_ENUM_PARAM(ARGC_ZERO, mode, 0, static_cast<int32_t>(BlendMode::LUMINOSITY));

    brush->SetBlendMode(static_cast<BlendMode>(mode));
    return nullptr;
}

napi_value JsBrush::SetShadowLayer(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    if (jsBrush == nullptr) {
        ROSEN_LOGE("JsBrush::SetShadowLayer jsBrush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetShadowLayer brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    JsShadowLayer* jsShadowLayer = nullptr;
    napi_unwrap(env, argv[ARGC_ZERO], reinterpret_cast<void **>(&jsShadowLayer));

    brush->SetLooper(jsShadowLayer ? jsShadowLayer->GetBlurDrawLooper() : nullptr);
    return nullptr;
}

napi_value JsBrush::SetShaderEffect(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::SetShaderEffect brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    JsShaderEffect* jsShaderEffect = nullptr;
    GET_UNWRAP_PARAM_OR_NULL(ARGC_ZERO, jsShaderEffect);

    brush->SetShaderEffect(jsShaderEffect ? jsShaderEffect->GetShaderEffect() : nullptr);
    return nullptr;
}

napi_value JsBrush::Reset(napi_env env, napi_callback_info info)
{
    JsBrush* jsBrush = CheckParamsAndGetThis<JsBrush>(env, info);
    Brush* brush = jsBrush->GetBrush();
    if (brush == nullptr) {
        ROSEN_LOGE("JsBrush::Reset brush is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    brush->Reset();
    return nullptr;
}

Brush* JsBrush::GetBrush()
{
    return brush_;
}
} // namespace Drawing
} // namespace OHOS::Rosen
