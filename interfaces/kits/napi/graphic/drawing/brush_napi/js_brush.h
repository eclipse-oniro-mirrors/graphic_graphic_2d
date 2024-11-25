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

#ifndef OHOS_ROSEN_JS_BRUSH_H
#define OHOS_ROSEN_JS_BRUSH_H

#include <native_engine/native_engine.h>
#include <native_engine/native_value.h>

#include "draw/brush.h"

namespace OHOS::Rosen {
namespace Drawing {
class JsBrush final {
public:
    JsBrush();
    explicit JsBrush(const Brush& brush);
    ~JsBrush();

    static napi_value Init(napi_env env, napi_value exportObj);
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize);

    static napi_value SetColor(napi_env env, napi_callback_info info);
    static napi_value GetColor(napi_env env, napi_callback_info info);
    static napi_value SetAntiAlias(napi_env env, napi_callback_info info);
    static napi_value IsAntiAlias(napi_env env, napi_callback_info info);
    static napi_value SetAlpha(napi_env env, napi_callback_info info);
    static napi_value GetAlpha(napi_env env, napi_callback_info info);
    static napi_value SetColorFilter(napi_env env, napi_callback_info info);
    static napi_value GetColorFilter(napi_env env, napi_callback_info info);
    static napi_value SetImageFilter(napi_env env, napi_callback_info info);
    static napi_value SetMaskFilter(napi_env env, napi_callback_info info);
    static napi_value SetBlendMode(napi_env env, napi_callback_info info);
    static napi_value SetShadowLayer(napi_env env, napi_callback_info info);
    static napi_value SetShaderEffect(napi_env env, napi_callback_info info);
    static napi_value Reset(napi_env env, napi_callback_info info);

    Brush* GetBrush();

private:
    static thread_local napi_ref constructor_;

    Brush* brush_;
};
} // namespace Drawing
} // namespace OHOS::Rosen
#endif // OHOS_ROSEN_JS_BRUSH_H