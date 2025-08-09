/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_font_collection.h"

#include <codecvt>
#include <cstdint>
#include <sys/stat.h>

#include "ani_common.h"
#include "ani_resource_parser.h"
#include "ani_text_utils.h"
#include "fontcollection_napi/js_fontcollection.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "utils/text_log.h"

namespace OHOS::Text::ANI {
using namespace OHOS::Rosen;

namespace {
void LoadString(
    ani_env* env, ani_object path, std::shared_ptr<OHOS::Rosen::FontCollection> fontCollection, std::string familyName)
{
    std::unique_ptr<uint8_t[]> data;
    size_t dataLen = 0;

    std::string pathStr;
    ani_status ret = AniTextUtils::AniToStdStringUtf8(env, reinterpret_cast<ani_string>(path), pathStr);
    if (ret != ANI_OK) {
        return;
    }
    if (!AniTextUtils::SplitAbsoluteFontPath(pathStr) || !AniTextUtils::ReadFile(pathStr, dataLen, data)) {
        TEXT_LOGE("Failed to split absolute font path");
        return;
    }
    fontCollection->LoadFont(familyName, data.get(), dataLen);
}

void LoadResource(
    ani_env* env, ani_object path, std::shared_ptr<OHOS::Rosen::FontCollection> fontCollection, std::string familyName)
{
    std::unique_ptr<uint8_t[]> data;
    size_t dataLen = 0;

    AniResource resource = AniResourceParser::ParseResource(env, path);
    if (!AniResourceParser::ResolveResource(resource, dataLen, data)) {
        TEXT_LOGE("Failed to resolve resource");
        return;
    }
    fontCollection->LoadFont(familyName, data.get(), dataLen);
}
} // namespace

AniFontCollection::AniFontCollection()
{
    fontCollection_ = FontCollection::From(nullptr);
}

AniFontCollection::AniFontCollection(std::shared_ptr<FontCollection> fc)
{
    fontCollection_ = fc;
}

void AniFontCollection::Constructor(ani_env* env, ani_object object)
{
    AniFontCollection* aniFontCollection = new AniFontCollection();
    ani_status ret = env->Object_SetFieldByName_Long(object, NATIVE_OBJ, reinterpret_cast<ani_long>(aniFontCollection));
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to create ani font collection obj");
        delete aniFontCollection;
        aniFontCollection = nullptr;
        return;
    }
}

ani_object AniFontCollection::GetGlobalInstance(ani_env* env, ani_class cls)
{
    static AniFontCollection aniFontCollection = AniFontCollection(FontCollection::Create());

    ani_object obj = AniTextUtils::CreateAniObject(env, ANI_CLASS_FONT_COLLECTION, ":V");
    ani_status ret = env->Object_SetFieldByName_Long(obj, NATIVE_OBJ, reinterpret_cast<ani_long>(&aniFontCollection));
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to create ani font collection obj");
        return nullptr;
    }
    return obj;
}

void AniFontCollection::LoadFontSync(ani_env* env, ani_object obj, ani_string name, ani_object path)
{
    std::string familyName;
    ani_status ret = AniTextUtils::AniToStdStringUtf8(env, name, familyName);
    if (ret != ANI_OK) {
        return;
    }
    auto aniFontCollection = AniTextUtils::GetNativeFromObj<AniFontCollection>(env, obj);
    if (aniFontCollection == nullptr || aniFontCollection->fontCollection_ == nullptr) {
        TEXT_LOGE("Null font collection");
        return;
    }

    ani_class stringClass;
    env->FindClass("Lstd/core/String;", &stringClass);
    ani_boolean isString = false;
    env->Object_InstanceOf(path, stringClass, &isString);

    if (isString) {
        LoadString(env, path, aniFontCollection->fontCollection_, familyName);
        return;
    }

    ani_class resourceClass;
    env->FindClass("Lglobal/resource/Resource", &resourceClass);
    ani_boolean isResource = false;
    env->Object_InstanceOf(path, resourceClass, &isResource);
    if (isResource) {
        LoadResource(env, path, aniFontCollection->fontCollection_, familyName);
        return;
    }
}

void AniFontCollection::ClearCaches(ani_env* env, ani_object obj)
{
    auto aniFontCollection = AniTextUtils::GetNativeFromObj<AniFontCollection>(env, obj);
    if (aniFontCollection == nullptr || aniFontCollection->fontCollection_ == nullptr) {
        TEXT_LOGE("Null font collection");
        return;
    }
    aniFontCollection->fontCollection_->ClearCaches();
}

ani_status AniFontCollection::AniInit(ani_vm* vm, uint32_t* result)
{
    ani_env* env = nullptr;
    ani_status ret = vm->GetEnv(ANI_VERSION_1, &env);
    if (ret != ANI_OK || env == nullptr) {
        TEXT_LOGE("Failed to get env, ret %{public}d", ret);
        return ANI_NOT_FOUND;
    }

    ani_class cls = nullptr;
    ret = env->FindClass(ANI_CLASS_FONT_COLLECTION, &cls);
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to find class: %{public}s, ret %{public}d", ANI_CLASS_FONT_COLLECTION, ret);
        return ANI_NOT_FOUND;
    }

    std::string globalInstance = ":" + std::string(ANI_CLASS_FONT_COLLECTION);
    std::string loadFontSync = "C{std.core.String}X{C{global.resource.Resource}C{std.core.String}}:";

    std::array methods = {
        ani_native_function{"constructorNative", ":V", reinterpret_cast<void*>(Constructor)},
        ani_native_function{"getGlobalInstance", globalInstance.c_str(), reinterpret_cast<void*>(GetGlobalInstance)},
        ani_native_function{"loadFontSync", loadFontSync.c_str(), reinterpret_cast<void*>(LoadFontSync)},
        ani_native_function{"clearCaches", ":V", reinterpret_cast<void*>(ClearCaches)},
        ani_native_function{"nativeTransferStatic", "Lstd/interop/ESValue;:Lstd/core/Object;",
            reinterpret_cast<void*>(NativeTransferStatic)},
        ani_native_function{
            "nativeTransferDynamic", "J:Lstd/interop/ESValue;", reinterpret_cast<void*>(NativeTransferDynamic)},
    };

    ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to bind methods for FontCollection: %{public}s", ANI_CLASS_FONT_COLLECTION);
        return ANI_ERROR;
    }
    return ANI_OK;
}

std::shared_ptr<FontCollection> AniFontCollection::GetFontCollection()
{
    return fontCollection_;
}

ani_object AniFontCollection::NativeTransferStatic(ani_env* env, ani_class cls, ani_object input)
{
    if (env == nullptr) {
        TEXT_LOGE("null env");
        return AniTextUtils::CreateAniUndefined(env);
    }
    void* unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(env, input, &unwrapResult);
    if (!success) {
        TEXT_LOGE("Failed to unwrap input");
        return AniTextUtils::CreateAniUndefined(env);
    }
    if (unwrapResult == nullptr) {
        TEXT_LOGE("Null unwrapResult");
        return AniTextUtils::CreateAniUndefined(env);
    }
    JsFontCollection* jsFontcollection = reinterpret_cast<JsFontCollection*>(unwrapResult);
    if (jsFontcollection == nullptr) {
        TEXT_LOGE("Null jsFontcollection");
        return AniTextUtils::CreateAniUndefined(env);
    }
    std::shared_ptr<FontCollection> fontCollection = jsFontcollection->GetFontCollection();

    ani_object object = AniTextUtils::CreateAniObject(env, ANI_CLASS_FONT_COLLECTION, ":V");
    AniFontCollection* aniFontCollection = new AniFontCollection();
    aniFontCollection->fontCollection_ = fontCollection;
    ani_status ret = env->Object_SetFieldByName_Long(object, NATIVE_OBJ, reinterpret_cast<ani_long>(aniFontCollection));
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to create ani font collection obj");
        delete aniFontCollection;
        aniFontCollection = nullptr;
        return AniTextUtils::CreateAniUndefined(env);
    }
    return object;
}

ani_object AniFontCollection::NativeTransferDynamic(ani_env* aniEnv, ani_class cls, ani_long nativeObj)
{
    AniFontCollection* aniFontCollection = reinterpret_cast<AniFontCollection*>(nativeObj);
    if (aniFontCollection == nullptr || aniFontCollection->fontCollection_ == nullptr) {
        TEXT_LOGE("Null font collection");
        return AniTextUtils::CreateAniUndefined(aniEnv);
    }
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(aniEnv, &napiEnv)) {
        TEXT_LOGE("Failed to open napi scope");
        return AniTextUtils::CreateAniUndefined(aniEnv);
    }

    napi_value objValue = {};
    if (napi_create_object(napiEnv, &objValue) != napi_ok) {
        TEXT_LOGE("Failed to create napi object");
        return AniTextUtils::CreateAniUndefined(aniEnv);
    }

    objValue = JsFontCollection::Init(napiEnv, objValue);
    JsFontCollection::SetFontCollection(napiEnv, objValue, aniFontCollection->GetFontCollection());

    hybridgref ref = nullptr;
    if(!hybridgref_create_from_napi(napiEnv, objValue, &ref)) {
        TEXT_LOGE("Failed to create hybrid reference");
        return AniTextUtils::CreateAniUndefined(aniEnv);
    }

    ani_object result = nullptr;
    if (!hybridgref_get_esvalue(aniEnv, ref, &result)) {
        TEXT_LOGE("Failed to get esvalue from hybrid reference");
        return AniTextUtils::CreateAniUndefined(aniEnv);
    }

    hybridgref_delete_from_napi(napiEnv, ref);
    if (!arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr)) {
        TEXT_LOGE("Failed to close napi scope");
        return AniTextUtils::CreateAniUndefined(aniEnv);
    }
    return result;
}
} // namespace OHOS::Text::ANI