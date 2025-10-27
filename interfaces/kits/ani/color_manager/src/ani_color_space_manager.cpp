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

#include "ani_color_space_manager.h"
#include "ani_color_space_utils.h"

#include <memory>
#include <string>

namespace OHOS {
namespace ColorManager {

namespace {
    static const char *COLOR_SPACE_ENUM_NAME =
        "@ohos.graphics.colorSpaceManager.colorSpaceManager.ColorSpace";
    static const char *COLOR_SPACE_MANAGER_CLS_NAME =
        "@ohos.graphics.colorSpaceManager.colorSpaceManager.ColorSpaceManagerInner";
    static const char *ERROR_CLS_NAME = "escompat.Error";
    static const char *MAKE_POINT_METHOD_NAME = "makePoint";
    static const char *NATIVE_PTR_FIELD_NAME = "nativePtr";
    ani_class gColorSpaceManagerCls = nullptr;
    ani_enum gEnumType = nullptr;
    ani_field gNativePtrField = nullptr;
    ani_method gMakePointMethod = nullptr;
    std::unordered_map<OHOS::ColorManager::ColorSpaceName, ani_enum_item> gNativeToEnumMap;
}

static ani_error CreateAniError(ani_env *env, std::string&& errMsg)
{
    ani_class cls {};
    if (ANI_OK != env->FindClass(ERROR_CLS_NAME, &cls)) {
        ACMLOGE("Not found class '%{public}s'.", ERROR_CLS_NAME);
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "C{std.core.String}:", &ctor)) {
        ACMLOGE("Not found ctor '%{public}s'.", ERROR_CLS_NAME);
        return nullptr;
    }
    ani_string error_msg;
    env->String_NewUTF8(errMsg.c_str(), 17U, &error_msg);
    ani_object errorObject;
    env->Object_New(cls, ctor, &errorObject, error_msg);
    return static_cast<ani_error>(errorObject);
}

bool CheckColorSpaceTypeRange(ani_env *env, const ApiColorSpaceType csType)
{
    if (csType >= ApiColorSpaceType::TYPE_END) {
        ACMLOGE("[ANI]ColorSpaceType is invalid: %{public}u", csType);
        ani_error aniErr = CreateAniError(env,
            "BusinessError 401: Parameter error, csType value is out of range.");
        env->ThrowError(aniErr);
        return false;
    }
    if (csType == ApiColorSpaceType::UNKNOWN || csType == ApiColorSpaceType::CUSTOM) {
        ACMLOGE("[ANI]ColorSpaceType is invalid: %{public}u", csType);
        std::string errMsg = "Parameter value is abnormal. Cannot create color"
            " manager object using ApiColorSpaceType " +
            std::to_string(static_cast<int32_t>(ApiColorSpaceType::CUSTOM));
        ani_error aniErr = CreateAniError(env, errMsg.c_str());
        env->ThrowError(aniErr);
        return false;
    }
    return true;
}

ani_status CacheNativePtr(ani_env *env)
{
    if (gColorSpaceManagerCls == nullptr) {
        if (ANI_OK != env->FindClass(COLOR_SPACE_MANAGER_CLS_NAME, &gColorSpaceManagerCls)) {
            ACMLOGE("[ANI]CacheNativePtr FindClass Failed");
            return ANI_ERROR;
        }
    }

    if (ANI_OK != env->Class_FindField(gColorSpaceManagerCls, NATIVE_PTR_FIELD_NAME, &gNativePtrField)) {
        ACMLOGE("[ANI]CacheNativePtr FindField Failed");
        return ANI_ERROR;
    }
    return ANI_OK;
}

AniColorSpaceManager* AniColorSpaceManager::Unwrap(ani_env *env, ani_object object)
{
    if (gNativePtrField == nullptr) {
        if (ANI_OK != CacheNativePtr(env)) {
            ACMLOGE("[ANI]Unwrap CacheNativePtr Failed");
            return nullptr;
        }
    }

    ani_long nativePtrLong;
    if (ANI_OK != env->Object_GetField_Long(object, gNativePtrField, &nativePtrLong)) {
        ACMLOGE("[ANI]Object_GetField_Long failed");
        return nullptr;
    }
    return reinterpret_cast<AniColorSpaceManager *>(nativePtrLong);
}

ani_object AniColorSpaceManager::Wrap(ani_env *env, AniColorSpaceManager *nativeHandle)
{
    if (env == nullptr || nativeHandle == nullptr) {
        ACMLOGE("%{public}s [ANI]env or nativeHandle is nullptr", __func__);
        return nullptr;
    }

    ani_class cls;
    if (ANI_OK != env->FindClass(COLOR_SPACE_MANAGER_CLS_NAME, &cls)) {
        ACMLOGE("%{public}s Failed to find class: %{public}s", __func__, COLOR_SPACE_MANAGER_CLS_NAME);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        ACMLOGE("%{public}s Failed to find method!", __func__);
        return nullptr;
    }

    ani_object result = nullptr;
    if (ANI_OK != env->Object_New(cls, ctor, &result, reinterpret_cast<ani_long>(nativeHandle))) {
        ACMLOGE("%{public}s Failed to create object!", __func__);
        return nullptr;
    }
    return result;
}

ani_object AniColorSpaceManager::CreateByColorSpace(ani_env* env, ani_enum_item enumObj)
{
    ani_object result = nullptr;

    ani_int intValue;
    if (ANI_OK != env->EnumItem_GetValue_Int(enumObj, &intValue)) {
        ACMLOGE("Enum_GetEnumItemByIndex Failed");
        return result;
    }
    
    ApiColorSpaceType csType = ApiColorSpaceType(intValue);
    if (!CheckColorSpaceTypeRange(env, csType)) {
        return result;
    }

    auto colorSpace = std::make_shared<ColorSpace>(JS_TO_NATIVE_COLOR_SPACE_NAME_MAP.at(csType));
    std::unique_ptr<AniColorSpaceManager> nativeHandle = std::make_unique<AniColorSpaceManager>(colorSpace);
    ani_class cls;
    if (ANI_OK != env->FindClass(COLOR_SPACE_MANAGER_CLS_NAME, &cls)) {
        ACMLOGI("Failed to find class: %{public}s", COLOR_SPACE_MANAGER_CLS_NAME);
        return result;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        ACMLOGI("Failed to find method: %{public}s", "ctor");
        return result;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &result, reinterpret_cast<ani_long>(nativeHandle.release()))) {
        ACMLOGI("New PhotoAccessHelper Fail");
    }

    return result;
}

ani_object AniColorSpaceManager::CreateByColorSpacePrimaries(ani_env* env, ani_object aniPrimaries, ani_double gamma)
{
    ani_object result = nullptr;

    ColorSpacePrimaries primaries;
    if (!ParseColorSpacePrimaries(env, aniPrimaries, primaries)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries failed");
        ani_error aniErr = CreateAniError(env,
            "BusinessError 401: Parameter error, the first parameter cannot be convert to ColorSpacePrimaries.");
        env->ThrowError(aniErr);
        return result;
    }
    auto colorSpace = std::make_shared<ColorSpace>(primaries, static_cast<float>(gamma));
    std::unique_ptr<AniColorSpaceManager> nativeHandle = std::make_unique<AniColorSpaceManager>(colorSpace);
    ani_class cls;
    if (ANI_OK != env->FindClass(COLOR_SPACE_MANAGER_CLS_NAME, &cls)) {
        ACMLOGI("Failed to find class: %{public}s", COLOR_SPACE_MANAGER_CLS_NAME);
        return result;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        ACMLOGI("Failed to find method: %{public}s", "ctor");
        return result;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &result, reinterpret_cast<ani_long>(nativeHandle.release()))) {
        ACMLOGI("New PhotoAccessHelper Fail");
    }

    return result;
}

ani_status AniColorSpaceManager::AniColorSpaceManagerInit(ani_env *env)
{
    ani_class cls;
    ani_status status = env->FindClass(COLOR_SPACE_MANAGER_CLS_NAME, &cls);
    if (status != ANI_OK) {
        ACMLOGI("Failed to find class: %{public}s", COLOR_SPACE_MANAGER_CLS_NAME);
        return status;
    }

    std::array methods = {
        ani_native_function {"getColorSpaceName", nullptr, reinterpret_cast<void *>(GetColorSpaceName)},
        ani_native_function {"getWhitePoint", nullptr, reinterpret_cast<void *>(GetWhitePoint)},
        ani_native_function {"getGamma", nullptr, reinterpret_cast<void *>(GetGamma)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ACMLOGI("Failed to bind native methods to: %{public}s", COLOR_SPACE_MANAGER_CLS_NAME);
        return status;
    }

    if (ANI_OK != env->FindEnum(COLOR_SPACE_ENUM_NAME, &gEnumType)) {
        ACMLOGE("[ANI]Find Enum Failed");
        return ANI_ERROR;
    }

    ani_enum_item enumItem = nullptr;
    for (auto& iter : NATIVE_TO_STRING_MAP) {
        env->Enum_GetEnumItemByName(gEnumType, iter.second.c_str(), &enumItem);
        gNativeToEnumMap.emplace(iter.first, enumItem);
    }

    if (ANI_OK != CacheNativePtr(env)) {
        ACMLOGE("[ANI]AniColorSpaceManagerInit CacheNativePtr Failed");
        return ANI_ERROR;
    }

    if (ANI_OK != env->Class_FindMethod(gColorSpaceManagerCls, MAKE_POINT_METHOD_NAME, nullptr, &gMakePointMethod)) {
        ACMLOGE("[ANI]FindMethod Failed");
        return ANI_ERROR;
    }
    return ANI_OK;
}

ani_enum_item AniColorSpaceManager::GetColorSpaceName([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj)
{
    if (env == nullptr) {
        ACMLOGE("[ANI]env is nullptr");
        return nullptr;
    }

    auto ptr = Unwrap(env, obj);
    if (!ptr) {
        ACMLOGE("[ANI]AniColorSpaceManager Unwrap failed");
        return nullptr;
    }

    return ptr->OnGetColorSpaceName(env, obj);
}

ani_ref AniColorSpaceManager::GetWhitePoint([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj)
{
    if (env == nullptr) {
        ACMLOGE("[ANI]env is nullptr");
        return nullptr;
    }

    auto ptr = Unwrap(env, obj);
    if (!ptr) {
        ACMLOGE("[ANI]AniColorSpaceManager Unwrap failed");
        return nullptr;
    }

    return ptr->OnGetWhitePoint(env, obj);
}

ani_double AniColorSpaceManager::GetGamma([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj)
{
    if (env == nullptr) {
        ACMLOGE("[ANI]env is nullptr");
        return 0;
    }

    auto ptr = Unwrap(env, obj);
    if (!ptr) {
        ACMLOGE("[ANI]AniColorSpaceManager Unwrap failed");
        return 0;
    }

    return ptr->OnGetGamma(env, obj);
}

ani_enum_item AniColorSpaceManager::OnGetColorSpaceName(ani_env *env, ani_object obj)
{
    ani_enum_item value = nullptr;
    if (colorSpaceToken_ == nullptr) {
        ACMLOGE("[ANI]colorSpaceToken_ is nullptr");
        ani_error aniErr = CreateAniError(env,
            "Parameter check fails. Native color space object is nullptr.");
        env->ThrowError(aniErr);
        return value;
    }
    ColorSpaceName csName = colorSpaceToken_->GetColorSpaceName();
    auto iter = gNativeToEnumMap.find(csName);
    if (iter != gNativeToEnumMap.end()) {
        ACMLOGD("[ANI]get color space name %{public}u", csName);
        return iter->second;
    }
    ACMLOGE("[ANI]get color space name %{public}u, but not in api type", csName);
    std::string errMsg = "BusinessError 401: Parameter error, the type of colorspace " +
        std::to_string(static_cast<int32_t>(csName)) + "must be in supported type list.";
    ani_error aniErr = CreateAniError(env, errMsg.c_str());
    env->ThrowError(aniErr);
    return value;
}

ani_ref AniColorSpaceManager::OnGetWhitePoint(ani_env *env, ani_object obj)
{
    ani_ref arrayValue = nullptr;
    if (colorSpaceToken_ == nullptr) {
        ACMLOGE("[ANI]colorSpaceToken_ is nullptr");
        ani_error aniErr = CreateAniError(env,
            "Parameter check fails. Native color space object is nullptr.");
        env->ThrowError(aniErr);
        return arrayValue;
    }

    std::array<float, DIMES_2> wp = colorSpaceToken_->GetWhitePoint();
    if (ANI_OK != env->Object_CallMethod_Ref(obj, gMakePointMethod, &arrayValue, wp[0], wp[1])) {
        ACMLOGE("[ANI]Object_CallMethod_Ref failed");
    }
    return arrayValue;
}

ani_double AniColorSpaceManager::OnGetGamma(ani_env *env, ani_object obj)
{
    ani_double value = 0;
    if (colorSpaceToken_ == nullptr) {
        ACMLOGE("[ANI]colorSpaceToken_ is nullptr");
        
        ani_error aniErr = CreateAniError(env,
            "Parameter check fails. Native color space object is nullptr.");
        env->ThrowError(aniErr);
        return value;
    }
    value = colorSpaceToken_->GetGamma();
    return value;
}

bool AniColorSpaceManager::ParseColorSpacePrimaries(ani_env *env, ani_object obj, ColorSpacePrimaries& primaries)
{
    double val;
    if (ANI_OK != env->Object_GetPropertyByName_Double(obj, "redX", &val)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries redX falied");
        return false;
    }
    primaries.rX = static_cast<float>(val);
    if (ANI_OK != env->Object_GetPropertyByName_Double(obj, "redY", &val)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries redY falied");
        return false;
    }
    primaries.rY = static_cast<float>(val);
    if (ANI_OK != env->Object_GetPropertyByName_Double(obj, "greenX", &val)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries greenX falied");
        return false;
    }
    primaries.gX = static_cast<float>(val);
    if (ANI_OK != env->Object_GetPropertyByName_Double(obj, "greenY", &val)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries greenY falied");
        return false;
    }
    primaries.gY = static_cast<float>(val);
    if (ANI_OK != env->Object_GetPropertyByName_Double(obj, "blueX", &val)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries blueX falied");
        return false;
    }
    primaries.bX = static_cast<float>(val);
    if (ANI_OK != env->Object_GetPropertyByName_Double(obj, "blueY", &val)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries blueY falied");
        return false;
    }
    primaries.bY = static_cast<float>(val);
    if (ANI_OK != env->Object_GetPropertyByName_Double(obj, "whitePointX", &val)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries whitePointX falied");
        return false;
    }
    primaries.wX = static_cast<float>(val);
    if (ANI_OK != env->Object_GetPropertyByName_Double(obj, "whitePointY", &val)) {
        ACMLOGE("[ANI]ParseColorSpacePrimaries whitePointY falied");
        return false;
    }
    primaries.wY = static_cast<float>(val);
    return true;
}
}  // namespace ColorManager
}  // namespace OHOS
