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

#include "js_matrix.h"
#include "js_drawing_utils.h"
#include "native_value.h"

namespace OHOS::Rosen {
namespace Drawing {
thread_local napi_ref JsMatrix::constructor_ = nullptr;
const std::string CLASS_NAME = "Matrix";
napi_value JsMatrix::Init(napi_env env, napi_value exportObj)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("preRotate", JsMatrix::PreRotate),
        DECLARE_NAPI_FUNCTION("preScale", JsMatrix::PreScale),
        DECLARE_NAPI_FUNCTION("preTranslate", JsMatrix::PreTranslate),
        DECLARE_NAPI_FUNCTION("setRotation", JsMatrix::SetRotation),
        DECLARE_NAPI_FUNCTION("setScale", JsMatrix::SetScale),
        DECLARE_NAPI_FUNCTION("setTranslation", JsMatrix::SetTranslation),
        DECLARE_NAPI_FUNCTION("setMatrix", JsMatrix::SetMatrix),
        DECLARE_NAPI_FUNCTION("preConcat", JsMatrix::PreConcat),
        DECLARE_NAPI_FUNCTION("isEqual", JsMatrix::IsEqual),
        DECLARE_NAPI_FUNCTION("invert", JsMatrix::Invert),
        DECLARE_NAPI_FUNCTION("isIdentity", JsMatrix::IsIdentity),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
                                           sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMatrix::Init Failed to define Matrix class");
        return nullptr;
    }

    status = napi_create_reference(env, constructor, 1, &constructor_);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMatrix::Init Failed to create reference of constructor");
        return nullptr;
    }

    status = napi_set_named_property(env, exportObj, CLASS_NAME.c_str(), constructor);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMatrix::Init Failed to set constructor");
        return nullptr;
    }

    return exportObj;
}

napi_value JsMatrix::Constructor(napi_env env, napi_callback_info info)
{
    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    if (status != napi_ok) {
        ROSEN_LOGE("JsMatrix::Constructor failed to napi_get_cb_info");
        return nullptr;
    }

    JsMatrix* jsMatrix = new(std::nothrow) JsMatrix(std::make_shared<Matrix>());
    if (jsMatrix == nullptr) {
        ROSEN_LOGE("JsMatrix::Constructor Failed to create jsMatrix");
        return nullptr;
    }

    status = napi_wrap(env, jsThis, jsMatrix, JsMatrix::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsMatrix;
        ROSEN_LOGE("JsMatrix::Constructor Failed to wrap native instance");
        return nullptr;
    }
    return jsThis;
}

void JsMatrix::Destructor(napi_env env, void* nativeObject, void* finalize)
{
    (void)finalize;
    if (nativeObject != nullptr) {
        JsMatrix* napi = reinterpret_cast<JsMatrix*>(nativeObject);
        delete napi;
    }
}

napi_value JsMatrix::PreRotate(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnPreRotate(env, info) : nullptr;
}

napi_value JsMatrix::OnPreRotate(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnPreRotate matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_THREE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_THREE);

    double degree = 0.0;
    GET_DOUBLE_PARAM(ARGC_ZERO, degree);
    double px = 0.0;
    GET_DOUBLE_PARAM(ARGC_ONE, px);
    double py = 0.0;
    GET_DOUBLE_PARAM(ARGC_TWO, py);

    JS_CALL_DRAWING_FUNC(m_matrix->PreRotate(degree, px, py));
    return nullptr;
}

napi_value JsMatrix::PreScale(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnPreScale(env, info) : nullptr;
}

napi_value JsMatrix::OnPreScale(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnPreScale matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_FOUR] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_FOUR);

    double sx = 0.0;
    GET_DOUBLE_PARAM(ARGC_ZERO, sx);
    double sy = 0.0;
    GET_DOUBLE_PARAM(ARGC_ONE, sy);
    double px = 0.0;
    GET_DOUBLE_PARAM(ARGC_TWO, px);
    double py = 0.0;
    GET_DOUBLE_PARAM(ARGC_THREE, py);

    JS_CALL_DRAWING_FUNC(m_matrix->PreScale(sx, sy, px, py));
    return nullptr;
}

napi_value JsMatrix::PreTranslate(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnPreTranslate(env, info) : nullptr;
}

napi_value JsMatrix::OnPreTranslate(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnPreTranslate matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_TWO] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_TWO);

    double dx = 0.0;
    GET_DOUBLE_PARAM(ARGC_ZERO, dx);
    double dy = 0.0;
    GET_DOUBLE_PARAM(ARGC_ONE, dy);

    JS_CALL_DRAWING_FUNC(m_matrix->PreTranslate(dx, dy));
    return nullptr;
}

napi_value JsMatrix::SetRotation(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnSetRotation(env, info) : nullptr;
}

napi_value JsMatrix::OnSetRotation(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnSetRotation matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_THREE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_THREE);

    double degree = 0.0;
    GET_DOUBLE_PARAM(ARGC_ZERO, degree);
    double px = 0.0;
    GET_DOUBLE_PARAM(ARGC_ONE, px);
    double py = 0.0;
    GET_DOUBLE_PARAM(ARGC_TWO, py);

    JS_CALL_DRAWING_FUNC(m_matrix->Rotate(degree, px, py));
    return nullptr;
}

napi_value JsMatrix::SetScale(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnSetScale(env, info) : nullptr;
}

napi_value JsMatrix::OnSetScale(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnSetScale matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_FOUR] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_FOUR);

    double sx = 0.0;
    GET_DOUBLE_PARAM(ARGC_ZERO, sx);
    double sy = 0.0;
    GET_DOUBLE_PARAM(ARGC_ONE, sy);
    double px = 0.0;
    GET_DOUBLE_PARAM(ARGC_TWO, px);
    double py = 0.0;
    GET_DOUBLE_PARAM(ARGC_THREE, py);

    JS_CALL_DRAWING_FUNC(m_matrix->Scale(sx, sy, px, py));
    return nullptr;
}

napi_value JsMatrix::SetTranslation(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnSetTranslation(env, info) : nullptr;
}

napi_value JsMatrix::OnSetTranslation(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnSetTranslation matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_TWO] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_TWO);

    double dx = 0.0;
    GET_DOUBLE_PARAM(ARGC_ZERO, dx);
    double dy = 0.0;
    GET_DOUBLE_PARAM(ARGC_ONE, dy);

    JS_CALL_DRAWING_FUNC(m_matrix->Translate(dx, dy));
    return nullptr;
}

napi_value JsMatrix::SetMatrix(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnSetMatrix(env, info) : nullptr;
}

napi_value JsMatrix::OnSetMatrix(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnSetMatrix matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    uint32_t arrayLength = 0;
    if ((napi_get_array_length(env, argv[ARGC_ZERO], &arrayLength) != napi_ok)) {
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid array length params.");
    }

    if (arrayLength != ARGC_NINE) { // arrayLength must be an nine number
        ROSEN_LOGE("JsMatrix::OnSetMatrix count of array is not nine : %{public}u", arrayLength);
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "parameter array length verification failed.");
    }

    scalar matrixPara[arrayLength];
    for (size_t i = 0; i < arrayLength; i++) {
        bool hasElement = false;
        napi_has_element(env, argv[ARGC_ZERO], i, &hasElement);
        if (!hasElement) {
            ROSEN_LOGE("JsMatrix::OnSetMatrix parameter check error");
            return nullptr;
        }

        napi_value element = nullptr;
        napi_get_element(env, argv[ARGC_ZERO], i, &element);

        double value = 0.0;
        ConvertFromJsNumber(env, element, value);
        matrixPara[i] = value;
    }

    m_matrix->SetMatrix(matrixPara[ARGC_ZERO], matrixPara[ARGC_ONE], matrixPara[ARGC_TWO],
        matrixPara[ARGC_THREE], matrixPara[ARGC_FOUR], matrixPara[ARGC_FIVE], matrixPara[ARGC_SIX],
        matrixPara[ARGC_SEVEN], matrixPara[ARGC_EIGHT]);
    return nullptr;
}

napi_value JsMatrix::PreConcat(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnPreConcat(env, info) : nullptr;
}

napi_value JsMatrix::OnPreConcat(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnPreConcat matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    JsMatrix* jsMatrix = nullptr;
    GET_UNWRAP_PARAM(ARGC_ZERO, jsMatrix);

    if (jsMatrix->GetMatrix() == nullptr) {
        ROSEN_LOGE("JsMatrix::OnPreConcat matrix is nullptr");
        return nullptr;
    }

    m_matrix->PreConcat(*jsMatrix->GetMatrix());
    return nullptr;
}

napi_value JsMatrix::IsEqual(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnIsEqual(env, info) : nullptr;
}

napi_value JsMatrix::OnIsEqual(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnIsEqual matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    JsMatrix* jsMatrix = nullptr;
    GET_UNWRAP_PARAM(ARGC_ZERO, jsMatrix);

    if (jsMatrix->GetMatrix() == nullptr) {
        ROSEN_LOGE("JsMatrix::OnIsEqual matrix is nullptr");
        return CreateJsValue(env, false);
    }

    return CreateJsValue(env, m_matrix->operator == (*jsMatrix->GetMatrix()));
}

napi_value JsMatrix::Invert(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnInvert(env, info) : nullptr;
}

napi_value JsMatrix::OnInvert(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnInvert matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    napi_value argv[ARGC_ONE] = {nullptr};
    CHECK_PARAM_NUMBER_WITHOUT_OPTIONAL_PARAMS(argv, ARGC_ONE);

    JsMatrix* jsMatrix = nullptr;
    GET_UNWRAP_PARAM(ARGC_ZERO, jsMatrix);

    if (jsMatrix->GetMatrix() == nullptr) {
        ROSEN_LOGE("JsMatrix::OnInvert matrix is nullptr");
        return nullptr;
    }

    return CreateJsValue(env, m_matrix->Invert(*jsMatrix->GetMatrix()));
}

napi_value JsMatrix::IsIdentity(napi_env env, napi_callback_info info)
{
    JsMatrix* me = CheckParamsAndGetThis<JsMatrix>(env, info);
    return (me != nullptr) ? me->OnIsIdentity(env, info) : nullptr;
}

napi_value JsMatrix::OnIsIdentity(napi_env env, napi_callback_info info)
{
    if (m_matrix == nullptr) {
        ROSEN_LOGE("JsMatrix::OnIsIdentity matrix is nullptr");
        return NapiThrowError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
    }

    return CreateJsValue(env, m_matrix->IsIdentity());
}

JsMatrix::~JsMatrix()
{
    m_matrix = nullptr;
}

std::shared_ptr<Matrix> JsMatrix::GetMatrix()
{
    return m_matrix;
}
}
}