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

#ifndef OHOS_ROSEN_JS_FONTCOLLECTION_H
#define OHOS_ROSEN_JS_FONTCOLLECTION_H

#include <native_engine/native_engine.h>
#include <native_engine/native_value.h>
#include <memory>

#include "font_collection.h"
#include "napi_common.h"
#include "resource_manager.h"

namespace OHOS::Rosen {
class JsFontCollection final {
public:
    JsFontCollection();

    static napi_value Init(napi_env env, napi_value exportObj);
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize);
    static napi_value LoadFontSync(napi_env env, napi_callback_info info);
    static napi_value GetGlobalInstance(napi_env env, napi_callback_info info);
    static napi_value ClearCaches(napi_env env, napi_callback_info info);
    static napi_value LoadFontAsync(napi_env env, napi_callback_info info);
    static napi_value UnloadFontSync(napi_env env, napi_callback_info info);
    static napi_value UnloadFontAsync(napi_env env, napi_callback_info info);
    static napi_status CreateFontCollection(napi_env env, napi_value constructor, napi_value* obj);
    static napi_status SetFontCollection(napi_env env, napi_value obj, std::shared_ptr<FontCollection> fontCollection);

    std::shared_ptr<FontCollection> GetFontCollection();
private:
    static bool CreateConstructor(napi_env env);
    static std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager(const std::string& moduleName);
    static thread_local napi_ref constructor_;
    static std::mutex constructorMutex_;
    napi_value OnLoadFont(napi_env env, napi_callback_info info);
    napi_value OnUnloadFont(napi_env env, napi_callback_info info);
    napi_value OnUnloadFontAsync(napi_env env, napi_callback_info info);
    napi_value OnClearCaches(napi_env env, napi_callback_info info);
    bool SplitAbsoluteFontPath(std::string& absolutePath);
    bool LoadFontFromResource(const std::string familyName, ResourceInfo& info);
    bool ParseResourceType(napi_env env, napi_value value, ResourceInfo& info);
    bool GetResourcePartData(napi_env env, ResourceInfo& info, napi_value paramsNApi,
        napi_value bundleNameNApi, napi_value moduleNameNApi);
    bool LoadFontFromPath(const std::string path, const std::string familyName);
    napi_value OnLoadFontAsync(napi_env env, napi_callback_info info);

    std::shared_ptr<FontCollection> fontcollection_ = nullptr;
};
} // namespace OHOS::Rosen
#endif // OHOS_ROSEN_JS_FONTCOLLECTION_H