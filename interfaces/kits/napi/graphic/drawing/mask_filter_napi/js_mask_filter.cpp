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

#include "js_mask_filter.h"
#include "js_drawing_utils.h"
#include "native_value.h"

namespace OHOS::Rosen {
namespace Drawing {
const std::string CLASS_NAME = "MaskFilter";
thread_local napi_ref JsMaskFilter::constructor_ = nullptr;
napi_value JsMaskFilter::Init(napi_env env, napi_value exportObj)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createBlurMaskFilter", JsMaskFilter::CreateBlurMaskFilter),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
                                           sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMaskFilter::Init failed to define maskFilter class");
        return nullptr;
    }

    status = napi_create_reference(env, constructor, 1, &constructor_);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMaskFilter::Init failed to create reference of constructor");
        return nullptr;
    }

    status = napi_set_named_property(env, exportObj, CLASS_NAME.c_str(), constructor);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMaskFilter::Init failed to set constructor");
        return nullptr;
    }

    status = napi_define_properties(env, exportObj, sizeof(properties) / sizeof(properties[0]), properties);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMaskFilter::Init failed to define static function");
        return nullptr;
    }
    return exportObj;
}

void JsMaskFilter::Finalizer(napi_env env, void* data, void* hint)
{
    std::unique_ptr<JsMaskFilter>(static_cast<JsMaskFilter*>(data));
}

JsMaskFilter::~JsMaskFilter()
{
    m_maskFilter = nullptr;
}

napi_value JsMaskFilter::Constructor(napi_env env, napi_callback_info info)
{
    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMaskFilter::Constructor failed to napi_get_cb_info");
        return nullptr;
    }

    JsMaskFilter *jsMaskFilter = new JsMaskFilter();
    status = napi_wrap(env, jsThis, jsMaskFilter, JsMaskFilter::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsMaskFilter;
        ROSEN_LOGE("JsMaskFilter::Constructor failed to wrap native instance");
        return nullptr;
    }
    return jsThis;
}

void JsMaskFilter::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    (void)finalize;
    if (nativeObject != nullptr) {
        JsMaskFilter *napi = reinterpret_cast<JsMaskFilter *>(nativeObject);
        delete napi;
    }
}

napi_value JsMaskFilter::CreateBlurMaskFilter(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGC_TWO] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_TWO);

    int32_t blurType = 0;
    GET_ENUM_PARAM(ARGC_ZERO, blurType, 0, static_cast<int32_t>(BlurType::INNER));

    double sigma = 0.0;
    GET_DOUBLE_PARAM(ARGC_ONE, sigma);

    if (sigma <= 0) {
        ROSEN_LOGE("JsMaskFilter::CreateBlurMaskFilter Argv[0] is invalid");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "Parameter verification failed. sigma must be greater than 0.");
    }

    auto maskFilter = MaskFilter::CreateBlurMaskFilter(static_cast<BlurType>(blurType), sigma);
    return JsMaskFilter::Create(env, maskFilter);
}

napi_value JsMaskFilter::Create(napi_env env, std::shared_ptr<MaskFilter> maskFilter)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    if (objValue == nullptr || maskFilter == nullptr) {
        ROSEN_LOGE("JsMaskFilter::Create object is null!");
        return nullptr;
    }

    std::unique_ptr<JsMaskFilter> jsMaskFilter = std::make_unique<JsMaskFilter>(maskFilter);
    napi_wrap(env, objValue, jsMaskFilter.release(), JsMaskFilter::Finalizer, nullptr, nullptr);

    if (objValue == nullptr) {
        ROSEN_LOGE("JsMaskFilter::Create object value is null!");
        return nullptr;
    }
    return objValue;
}

std::shared_ptr<MaskFilter> JsMaskFilter::GetMaskFilter()
{
    return m_maskFilter;
}
} // namespace Drawing
} // namespace OHOS::Rosen
