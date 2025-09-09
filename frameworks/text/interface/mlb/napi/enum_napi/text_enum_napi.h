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

#ifndef OHOS_ROSEN_TEXT_ENUM_NAPI_H
#define OHOS_ROSEN_TEXT_ENUM_NAPI_H

#include <memory>
#include <native_engine/native_engine.h>
#include <native_engine/native_value.h>
#include "typography_create.h"
#include "typography_style.h"

namespace OHOS::Rosen {
class JsEnum {
public:
    JsEnum() = default;
    ~JsEnum() = default;
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsEnumIntInit(napi_env env, napi_value exports);
};
} // namespace OHOS::Rosen
#endif // OHOS_ROSEN_JS_ENUM_NAPI_H