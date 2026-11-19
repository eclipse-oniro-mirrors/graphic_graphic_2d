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

#include "blender_napi.h"

#include "effect/include/blender_base.h"
#include "effect/include/brightness_blender.h"
#include "effect/include/colorful_brightness_blender.h"
#include "effect/include/hdr_darken_blender.h"
#include "effect_napi.h"
#include "ui_effect_napi_utils.h"

namespace OHOS {
namespace Rosen {
using namespace UIEffect;

namespace {
bool CheckCreateBrightnessBlender(napi_env env, napi_value jsObject)
{
    bool result = true;
    napi_status status = napi_has_named_property(env, jsObject, "cubicRate", &result);
    if (!((status == napi_ok) && result)) {
        return false;
    }
    status = napi_has_named_property(env, jsObject, "quadraticRate", &result);
    if (!((status == napi_ok) && result)) {
        return false;
    }
    status = napi_has_named_property(env, jsObject, "linearRate", &result);
    if (!((status == napi_ok) && result)) {
        return false;
    }
    status = napi_has_named_property(env, jsObject, "degree", &result);
    if (!((status == napi_ok) && result)) {
        return false;
    }
    status = napi_has_named_property(env, jsObject, "saturation", &result);
    if (!((status == napi_ok) && result)) {
        return false;
    }
    status = napi_has_named_property(env, jsObject, "fraction", &result);
    if (!((status == napi_ok) && result)) {
        return false;
    }
    status = napi_has_named_property(env, jsObject, "positiveCoefficient", &result);
    if (!((status == napi_ok) && result)) {
        return false;
    }
    status = napi_has_named_property(env, jsObject, "negativeCoefficient", &result);
    if (!((status == napi_ok) && result)) {
        return false;
    }
    return true;
}

bool CheckJsArgNotNull(napi_env env, napi_value argv, const char* paramName)
{
    napi_valuetype type = UIEffectNapiUtils::GetType(env, argv);
    if (type == napi_null || type == napi_undefined) {
        BLENDER_LOG_E("BlenderNapi CheckJsArgNotNull %{public}s is null or undefined", paramName);
        return false;
    }
    return true;
}
} // namespace

static const std::string CLASS_NAME = "BlenderBase";

thread_local napi_ref BlenderNapi::sConstructor_ = nullptr;

napi_value BlenderNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createColorfulBrightnessBlender", CreateColorfulBrightnessBlender),
        DECLARE_NAPI_STATIC_FUNCTION("createBrightnessBlender", CreateBrightnessBlender),
        DECLARE_NAPI_STATIC_FUNCTION("createHdrDarkenBlender", CreateHdrDarkenBlender),
    };

    napi_value constructor = nullptr;

    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        UIEFFECT_ARRAY_SIZE(static_prop), static_prop, &constructor);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok, nullptr, BLENDER_LOG_E("BlenderNapi Init define class fail"));

    status = napi_create_reference(env, constructor, 1, &sConstructor_);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok, nullptr, BLENDER_LOG_E("BlenderNapi Init create reference fail"));

    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok, nullptr, BLENDER_LOG_E("BlenderNapi Init get global fail"));

    status = napi_set_named_property(env, global, CLASS_NAME.c_str(), constructor);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok, nullptr, BLENDER_LOG_E("BlenderNapi Init set global fail"));

    status = napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok, nullptr, BLENDER_LOG_E("BlenderNapi Init set exports fail"));

    return exports;
}

napi_value BlenderNapi::Constructor(napi_env env, napi_callback_info info)
{
    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok, nullptr,
        BLENDER_LOG_E("BlenderNapi Constructor parsing input fail"));

    BlenderNapi* blenderNapi = new(std::nothrow) BlenderNapi();
    UIEFFECT_NAPI_CHECK_RET_D(blenderNapi != nullptr, nullptr,
        BLENDER_LOG_E("BlenderNapi Constructor blenderNapi is nullptr"));
    status = napi_wrap(env, jsThis, blenderNapi, BlenderNapi::Destructor, nullptr, nullptr);
    UIEFFECT_NAPI_CHECK_RET_DELETE_POINTER(status == napi_ok, nullptr, blenderNapi,
        BLENDER_LOG_E("BlenderNapi Constructor wrap fail"));
    return jsThis;
}

void BlenderNapi::Destructor(napi_env env, void* nativeObject, void* finalize)
{
    BlenderNapi* blenderNapi = static_cast<BlenderNapi*>(nativeObject);
    UIEFFECT_NAPI_CHECK_RET_VOID_D(blenderNapi != nullptr,
        BLENDER_LOG_E("BlenderNapi Destructor nativeObject is nullptr"));

    delete blenderNapi;
    blenderNapi = nullptr;
}

napi_value BlenderNapi::Create(napi_env env, const std::shared_ptr<Blender>& blender)
{
    napi_value blenderObj = nullptr;
    napi_status status = napi_create_object(env, &blenderObj);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok && blenderObj != nullptr, nullptr,
        BLENDER_LOG_E("BlenderNapi Create fail to create new object"));

    // No NG conversion here; RSNode::SetBlender converts the wrapped blender via convertorLUT.
    auto* blenderBase = new(std::nothrow) BlenderBase();
    UIEFFECT_NAPI_CHECK_RET_D(blenderBase != nullptr, nullptr,
        BLENDER_LOG_E("BlenderNapi Create blenderBase is nullptr"));
    blenderBase->SetBlender(blender);

    // Type tag is mandatory: ArkUI unwraps via napi_unwrap_s with BLENDER_TYPE_TAG
    // (BlenderBase inherits Blender).
    status = napi_wrap_s(env, blenderObj, blenderBase,
        [](napi_env env, void* data, void* hint) {
            BlenderBase* blenderBaseObj = static_cast<BlenderBase*>(data);
            delete blenderBaseObj;
        },
        nullptr, &BLENDER_TYPE_TAG, nullptr);
    UIEFFECT_NAPI_CHECK_RET_DELETE_POINTER(status == napi_ok, nullptr, blenderBase,
        BLENDER_LOG_E("BlenderNapi Create wrap fail"));
    return blenderObj;
}

napi_value BlenderNapi::CreateColorfulBrightnessBlender(napi_env env, napi_callback_info info)
{
    size_t realArgc = NUM_2;
    napi_value argv[NUM_2];
    napi_value thisVar = nullptr;
    napi_status status;

    UIEFFECT_JS_ARGS(env, info, status, realArgc, argv, thisVar);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok && (realArgc == NUM_1 || realArgc == NUM_2), nullptr,
        BLENDER_LOG_E("BlenderNapi CreateColorfulBrightnessBlender parsing input fail"));

    napi_value nativeObj = argv[NUM_0];
    UIEFFECT_NAPI_CHECK_RET_D(nativeObj != nullptr, nullptr,
        BLENDER_LOG_E("BlenderNapi CreateColorfulBrightnessBlender nativeObj is nullptr"));

    auto blender = std::make_shared<ColorfulBrightnessBlender>();
    napi_value optionsObj = (realArgc >= NUM_2) ? argv[NUM_1] : nullptr;
    UIEFFECT_NAPI_CHECK_RET_D(CheckCreateBrightnessBlender(env, nativeObj) &&
        EffectNapi::ParseColorfulBrightnessBlender(env, nativeObj, optionsObj, blender.get()), nullptr,
        BLENDER_LOG_E("BlenderNapi CreateColorfulBrightnessBlender fail"));

    return Create(env, blender);
}

napi_value BlenderNapi::CreateBrightnessBlender(napi_env env, napi_callback_info info)
{
    size_t realArgc = NUM_2;
    napi_value argv[NUM_2];
    napi_value thisVar = nullptr;
    napi_status status;

    UIEFFECT_JS_ARGS(env, info, status, realArgc, argv, thisVar);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok && (realArgc == NUM_1 || realArgc == NUM_2), nullptr,
        BLENDER_LOG_E("BlenderNapi CreateBrightnessBlender parsing input fail"));

    napi_value nativeObj = argv[NUM_0];
    UIEFFECT_NAPI_CHECK_RET_D(nativeObj != nullptr, nullptr,
        BLENDER_LOG_E("BlenderNapi CreateBrightnessBlender nativeObj is nullptr"));

    auto blender = std::make_shared<BrightnessBlender>();
    UIEFFECT_NAPI_CHECK_RET_D(CheckCreateBrightnessBlender(env, nativeObj) &&
        EffectNapi::ParseBrightnessBlender(env, nativeObj, blender.get()), nullptr,
        BLENDER_LOG_E("BlenderNapi CreateBrightnessBlender fail"));

    // hdrEnabled is optional and defaults to false
    bool hdrEnabled = false;
    if (realArgc >= NUM_2) {
        napi_valuetype type = UIEffectNapiUtils::GetType(env, argv[NUM_1]);
        if (type == napi_boolean) {
            status = napi_get_value_bool(env, argv[NUM_1], &hdrEnabled);
            UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok, nullptr,
                BLENDER_LOG_E("BlenderNapi CreateBrightnessBlender parse hdrEnabled fail"));
        } else {
            UIEFFECT_NAPI_CHECK_RET_D(type == napi_undefined || type == napi_null, nullptr,
                BLENDER_LOG_E("BlenderNapi CreateBrightnessBlender invalid hdrEnabled type"));
        }
    }
    blender->SetHdr(hdrEnabled);

    return Create(env, blender);
}

napi_value BlenderNapi::CreateHdrDarkenBlender(napi_env env, napi_callback_info info)
{
    size_t realArgc = NUM_2;
    napi_value argv[NUM_2];
    napi_value thisVar = nullptr;
    napi_status status;

    UIEFFECT_JS_ARGS(env, info, status, realArgc, argv, thisVar);
    UIEFFECT_NAPI_CHECK_RET_D(status == napi_ok && (realArgc == NUM_1 || realArgc == NUM_2), nullptr,
        BLENDER_LOG_E("BlenderNapi CreateHdrDarkenBlender parsing input fail"));

    UIEFFECT_NAPI_CHECK_RET_D(CheckJsArgNotNull(env, argv[NUM_0], "hdrBrightnessRatio"), nullptr,
        BLENDER_LOG_E("BlenderNapi CreateHdrDarkenBlender hdrBrightnessRatio check fail"));

    auto blender = std::make_shared<HdrDarkenBlender>();
    float hdrBrightnessRatio = EffectNapi::GetSpecialValue(env, argv[NUM_0]);
    // grayscaleFactor is optional and defaults to standard grayscale weights
    Vector3f grayscaleFactor = {0.299f, 0.587f, 0.114f};
    if (realArgc >= NUM_2) {
        napi_valuetype type = UIEffectNapiUtils::GetType(env, argv[NUM_1]);
        if (type == napi_object) {
            UIEFFECT_NAPI_CHECK_RET_D(ParsegrayscaleFactor(env, argv[NUM_1], grayscaleFactor), nullptr,
                BLENDER_LOG_E("BlenderNapi CreateHdrDarkenBlender parse grayscaleFactor fail"));
        } else {
            UIEFFECT_NAPI_CHECK_RET_D(type == napi_undefined || type == napi_null, nullptr,
                BLENDER_LOG_E("BlenderNapi CreateHdrDarkenBlender invalid grayscaleFactor type"));
        }
    }
    blender->SetGrayscaleFactor(grayscaleFactor);
    blender->SetHdrBrightnessRatio(hdrBrightnessRatio);

    return Create(env, blender);
}
} // namespace Rosen
} // namespace OHOS
