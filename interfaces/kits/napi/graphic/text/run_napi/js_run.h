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

#ifndef OHOS_ROSEN_JS_RUN_H
#define OHOS_ROSEN_JS_RUN_H

#include <native_engine/native_engine.h>
#include <native_engine/native_value.h>
#include "run.h"
#include "typography.h"

namespace OHOS::Rosen {
class JsRun final {
public:
    JsRun();

    void SetRun(std::unique_ptr<Run> run);
    static napi_value CreateRun(napi_env env, napi_callback_info info);
    static napi_value Init(napi_env env, napi_value exportObj);
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize);
    static napi_value GetGlyphCount(napi_env env, napi_callback_info info);
    static napi_value GetGlyphs(napi_env env, napi_callback_info info);
    static napi_value GetPositions(napi_env env, napi_callback_info info);
    static napi_value GetOffsets(napi_env env, napi_callback_info info);
    static napi_value GetFont(napi_env env, napi_callback_info info);
    static napi_value Paint(napi_env env, napi_callback_info info);
    static napi_value GetStringRange(napi_env env, napi_callback_info info);
    static napi_value GetStringIndices(napi_env env, napi_callback_info info);
    static napi_value GetImageBounds(napi_env env, napi_callback_info info);
    static napi_value GetTypographicBounds(napi_env env, napi_callback_info info);
    static napi_value GetAdvances(napi_env env, napi_callback_info info);
    static napi_value GetTextDirection(napi_env env, napi_callback_info info);
    void SetParagraph(std::shared_ptr<Typography> paragraph);

private:
    static std::mutex constructorMutex_;
    static thread_local napi_ref constructor_;
    napi_value OnGetGlyphCount(napi_env env, napi_callback_info info);
    napi_value OnGetGlyphs(napi_env env, napi_callback_info info);
    napi_value OnGetPositions(napi_env env, napi_callback_info info);
    napi_value OnGetOffsets(napi_env env, napi_callback_info info);
    napi_value OnGetFont(napi_env env, napi_callback_info info);
    napi_value OnPaint(napi_env env, napi_callback_info info);
    napi_value OnGetStringRange(napi_env env, napi_callback_info info);
    napi_value OnGetStringIndices(napi_env env, napi_callback_info info);
    napi_value OnGetImageBounds(napi_env env, napi_callback_info info);
    napi_value OnGetTypographicBounds(napi_env env, napi_callback_info info);
    napi_value OnGetAdvances(napi_env env, napi_callback_info info);
    napi_value OnGetTextDirection(napi_env env, napi_callback_info info);

    static bool CreateConstructor(napi_env env);
    std::unique_ptr<Run> run_;
    std::shared_ptr<Typography> paragraph_ = nullptr;
};
} // namespace OHOS::Rosen
#endif // OHOS_ROSEN_JS_RUN_H