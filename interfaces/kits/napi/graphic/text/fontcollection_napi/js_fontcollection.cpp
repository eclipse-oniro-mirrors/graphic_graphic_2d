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

#include <fstream>
#include "js_fontcollection.h"
#include "log_wrapper.h"
#include "napi_async_work.h"

namespace OHOS::Rosen {
namespace {
constexpr size_t FILE_HEAD_LENGTH = 7; // 7 is the size of "file://"
const std::string CLASS_NAME = "FontCollection";
const std::string LOCAL_BIND_PATH = "/data/storage/el1/bundle/";
const std::string HAP_POSTFIX = ".hap";
const int32_t GLOBAL_ERROR = 10000;
struct FontArgumentsConcreteContext : public ContextBase {
    std::string familyName;
    std::string filePath;
    ResourceInfo info;
};

bool ParseContextFilePath(napi_env env, napi_value* argv, std::shared_ptr<FontArgumentsConcreteContext> context)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[ARGC_ONE], &valueType);

    if (valueType == napi_object) {
        return false;
    } else if (valueType == napi_string) {
        if (!ConvertFromJsValue(env, argv[ARGC_ONE], context->filePath)) {
            std::string errMessage("ParseContextFilePath ConvertFromJsValue failed, context->filePath = ");
            errMessage += context->filePath;
            context->status = napi_invalid_arg;
            context->errMessage = errMessage;
            (context)->errCode = static_cast<int32_t>(TextErrorCode::ERROR_INVALID_PARAM);
            TEXT_LOGE("%{public}s", errMessage.c_str());
        }
    }
    return true;
}
}

thread_local napi_ref JsFontCollection::constructor_ = nullptr;
napi_value JsFontCollection::Constructor(napi_env env, napi_callback_info info)
{
    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    if (status != napi_ok) {
        TEXT_LOGE("failed from napi_get_cb_info");
        return nullptr;
    }

    JsFontCollection* jsFontCollection = new(std::nothrow) JsFontCollection();
    status = napi_wrap(env, jsThis, jsFontCollection,
        JsFontCollection::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsFontCollection;
        TEXT_LOGE("failed from napi_wrap");
        return nullptr;
    }
    return jsThis;
}

napi_value JsFontCollection::Init(napi_env env, napi_value exportObj)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getGlobalInstance", JsFontCollection::GetGlobalInstance),
        DECLARE_NAPI_FUNCTION("loadFontSync", JsFontCollection::LoadFontSync),
        DECLARE_NAPI_FUNCTION("clearCaches", JsFontCollection::ClearCaches),
        DECLARE_NAPI_FUNCTION("loadFont", JsFontCollection::LoadFontAsync),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_create_reference(env, constructor, 1, &constructor_);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_set_named_property(env, exportObj, CLASS_NAME.c_str(), constructor);
    if (status != napi_ok) {
        return nullptr;
    }
    return exportObj;
}

void JsFontCollection::Destructor(napi_env env, void* nativeObject, void* finalize)
{
    (void)finalize;
    if (nativeObject != nullptr) {
        JsFontCollection* napi = reinterpret_cast<JsFontCollection*>(nativeObject);
        delete napi;
    }
}

JsFontCollection::JsFontCollection()
{
    fontcollection_ = OHOS::Rosen::FontCollection::From(nullptr);
}

std::shared_ptr<FontCollection> JsFontCollection::GetFontCollection()
{
    return fontcollection_;
}

napi_value JsFontCollection::GetGlobalInstance(napi_env env, napi_callback_info info)
{
    napi_value constructor = nullptr;
    napi_status status = napi_get_reference_value(env, constructor_, &constructor);
    if (status != napi_ok || !constructor) {
        TEXT_LOGE("Failed to get constructor object");
        return nullptr;
    }

    napi_value object = nullptr;
    status = napi_new_instance(env, constructor, 0, nullptr, &object);
    if (status != napi_ok || !object) {
        TEXT_LOGE("Failed to instantiate instance");
        return nullptr;
    }

    JsFontCollection* jsFontCollection = nullptr;
    status = napi_unwrap(env, object, reinterpret_cast<void**>(&jsFontCollection));
    if (status != napi_ok || !jsFontCollection) {
        TEXT_LOGE("Failed to unwrap JsFontCollection");
        return nullptr;
    }
    jsFontCollection->fontcollection_ = OHOS::Rosen::FontCollection::Create();

    return object;
}

napi_value JsFontCollection::LoadFontSync(napi_env env, napi_callback_info info)
{
    JsFontCollection* me = CheckParamsAndGetThis<JsFontCollection>(env, info);
    return (me != nullptr) ? me->OnLoadFont(env, info) : nullptr;
}

bool JsFontCollection::SpiltAbsoluteFontPath(std::string& absolutePath)
{
    auto iter = absolutePath.find_first_of(':');
    if (iter == std::string::npos) {
        TEXT_LOGE("font file directory is not absolute path");
        return false;
    }
    std::string head = absolutePath.substr(0, iter);
    if ((head == "file" && absolutePath.size() > FILE_HEAD_LENGTH)) {
        absolutePath = absolutePath.substr(iter + 3); // 3 means skip "://"
        // the file format is like "file://system/fonts...",
        return true;
    }

    return false;
}

std::unique_ptr<Global::Resource::ResourceManager> JsFontCollection::GetResourManager(const std::string& moudleName)
{
    auto hapPath = LOCAL_BIND_PATH + moudleName + HAP_POSTFIX;
    auto resManager = Global::Resource::CreateResourceManager();
    if (!resManager) {
        return nullptr;
    }
    resManager->AddResource(hapPath.c_str());
    return std::unique_ptr<Global::Resource::ResourceManager>(resManager);
}

bool JsFontCollection::GetResourcePartData(napi_env env, ResourceInfo& info, napi_value paramsNApi,
    napi_value bundleNameNApi, napi_value moduleNameNApi)
{
    napi_valuetype valueType = napi_undefined;
    bool isArray = false;
    if (napi_is_array(env, paramsNApi, &isArray) != napi_ok) {
        return false;
    }
    if (!isArray) {
        return false;
    }

    uint32_t arrayLength = 0;
    napi_get_array_length(env, paramsNApi, &arrayLength);
    for (uint32_t i = 0; i < arrayLength; i++) {
        size_t ret = 0;
        napi_value indexValue = nullptr;
        napi_get_element(env, paramsNApi, i, &indexValue);
        napi_typeof(env, indexValue, &valueType);
        if (valueType == napi_string) {
            size_t strLen = GetParamLen(env, indexValue) + 1;
            std::unique_ptr<char[]> indexStr = std::make_unique<char[]>(strLen);
            napi_get_value_string_utf8(env, indexValue, indexStr.get(), strLen, &ret);
            info.params.emplace_back(indexStr.get());
        } else if (valueType == napi_number) {
            int32_t num;
            napi_get_value_int32(env, indexValue, &num);
            info.params.emplace_back(std::to_string(num));
        } else {
            TEXT_LOGE("invalid argument %{public}d", valueType);
            return false;
        }
    }

    napi_typeof(env, bundleNameNApi, &valueType);
    if (valueType == napi_string) {
        size_t ret = 0;
        size_t strLen = GetParamLen(env, bundleNameNApi) + 1;
        std::unique_ptr<char[]> bundleNameStr = std::make_unique<char[]>(strLen);
        napi_get_value_string_utf8(env, bundleNameNApi, bundleNameStr.get(), strLen, &ret);
        info.bundleName = bundleNameStr.get();
    }

    napi_typeof(env, moduleNameNApi, &valueType);
    if (valueType == napi_string) {
        size_t ret = 0;
        size_t strLen = GetParamLen(env, moduleNameNApi) + 1;
        std::unique_ptr<char[]> moduleNameStr = std::make_unique<char[]>(strLen);
        napi_get_value_string_utf8(env, moduleNameNApi, moduleNameStr.get(), strLen, &ret);
        info.moduleName = moduleNameStr.get();
    }

    return true;
}

bool JsFontCollection::ParseResourceType(napi_env env, napi_value value, ResourceInfo& info)
{
    napi_value idNApi = nullptr;
    napi_value typeNApi = nullptr;
    napi_value paramsNApi = nullptr;
    napi_value bundleNameNApi = nullptr;
    napi_value moduleNameNApi = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType == napi_object) {
        napi_get_named_property(env, value, "id", &idNApi);
        napi_get_named_property(env, value, "type", &typeNApi);
        napi_get_named_property(env, value, "params", &paramsNApi);
        napi_get_named_property(env, value, "bundleName", &bundleNameNApi);
        napi_get_named_property(env, value, "moduleName", &moduleNameNApi);
    } else {
        return false;
    }

    napi_typeof(env, idNApi, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, idNApi, &info.resId);
    }

    napi_typeof(env, typeNApi, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, typeNApi, &info.type);
    }
    if (!GetResourcePartData(env, info, paramsNApi, bundleNameNApi, moduleNameNApi)) {
        return false;
    }

    return true;
}

bool JsFontCollection::ParseResourcePath(const std::string familyName, ResourceInfo& info)
{
    int32_t state = 0;

    auto reSourceManager = GetResourManager(info.moduleName);
    if (reSourceManager == nullptr) {
        return false;
    }

    if (info.type == static_cast<int32_t>(ResourceType::STRING)) {
        std::string rPath;
        if (info.resId < 0 && !info.params.empty() && info.params[0].size() > 0) {
            rPath = info.params[0];
        } else {
            state = reSourceManager->GetStringById(info.resId, rPath);
            if (state >= GLOBAL_ERROR || state < 0) {
                return false;
            }
            if (!SpiltAbsoluteFontPath(rPath) || !GetFontFileProperties(rPath, familyName)) {
                return false;
            }
        }
    } else if (info.type == static_cast<int32_t>(ResourceType::RAWFILE)) {
        size_t dataLen = 0;
        std::unique_ptr<uint8_t[]> rawData;

        if (info.params.empty()) {
            return false;
        }

        state = reSourceManager->GetRawFileFromHap(info.params[0], dataLen, rawData);
        if (state >= GLOBAL_ERROR || state < 0) {
            return false;
        }
        if (!fontcollection_->LoadFont(familyName.c_str(), rawData.get(), dataLen)) {
            return false;
        }
        return true;
    } else {
        TEXT_LOGE("incorrect path type of font file");
        return false;
    }
    return true;
}

bool JsFontCollection::GetFontFileProperties(const std::string path, const std::string familyName)
{
    size_t datalen;

    if (fontcollection_ == nullptr) {
        TEXT_LOGE("fontcollection_ is nullptr");
        return false;
    }

    char tmpPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), tmpPath) == nullptr) {
        return false;
    }

    std::ifstream f(tmpPath);
    if (!f.good()) {
        return false;
    }

    std::ifstream ifs(tmpPath, std::ios_base::in);
    if (!ifs.is_open()) {
        return false;
    }

    ifs.seekg(0, ifs.end);
    if (!ifs.good()) {
        ifs.close();
        return false;
    }

    datalen = static_cast<size_t>(ifs.tellg());
    if (ifs.fail()) {
        ifs.close();
        return false;
    }

    ifs.seekg(ifs.beg);
    if (!ifs.good()) {
        ifs.close();
        return false;
    }

    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(datalen);
    ifs.read(buffer.get(), datalen);
    if (!ifs.good()) {
        ifs.close();
        return false;
    }
    ifs.close();
    const uint8_t* rawData = reinterpret_cast<uint8_t*>(buffer.get());
    if (!fontcollection_->LoadFont(familyName.c_str(), rawData, datalen)) {
        return false;
    }
    return true;
}

napi_value JsFontCollection::OnLoadFont(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = {nullptr};
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
        argc < ARGC_TWO) {
        return nullptr;
    }
    std::string familyName;
    std::string familySrc;
    if (!ConvertFromJsValue(env, argv[0], familyName)) {
        TEXT_LOGE("OnLoadFont argv[0] convert fail");
        return nullptr;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[1], &valueType);
    if (valueType != napi_object) {
        if (!ConvertFromJsValue(env, argv[1], familySrc)) {
            TEXT_LOGE("OnLoadFont argv[1] convert fail");
            return nullptr;
        }
        if (!SpiltAbsoluteFontPath(familySrc) || !GetFontFileProperties(familySrc, familyName)) {
            return nullptr;
        }
        return NapiGetUndefined(env);
    }

    ResourceInfo resourceInfo;
    if (!ParseResourceType(env, argv[1], resourceInfo) || !ParseResourcePath(familyName, resourceInfo)) {
        return nullptr;
    }

    return NapiGetUndefined(env);
}

napi_value JsFontCollection::ClearCaches(napi_env env, napi_callback_info info)
{
    JsFontCollection* me = CheckParamsAndGetThis<JsFontCollection>(env, info);
    return (me != nullptr) ? me->OnClearCaches(env, info) : nullptr;
}

napi_value JsFontCollection::OnClearCaches(napi_env env, napi_callback_info info)
{
    if (fontcollection_ == nullptr) {
        TEXT_LOGE("JsFontCollection is nullptr");
        return NapiThrowError(env, TextErrorCode::ERROR_INVALID_PARAM,
            "JsFontCollection::OnClearCaches fontCollection is nullptr.");
    }
    fontcollection_->ClearCaches();
    return NapiGetUndefined(env);
}

napi_value JsFontCollection::LoadFontAsync(napi_env env, napi_callback_info info)
{
    JsFontCollection* me = CheckParamsAndGetThis<JsFontCollection>(env, info);
    return (me != nullptr) ? me->OnLoadFontAsync(env, info) : nullptr;
}

napi_value JsFontCollection::OnLoadFontAsync(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<FontArgumentsConcreteContext>();
    NAPI_CHECK_AND_THROW_ERROR(context != nullptr, TextErrorCode::ERR_NO_MEMORY, "OnLoadFontAsync failed, no memory");

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        TEXT_ERROR_CHECK(argv != nullptr, return, "OnLoadFontAsync inputParser argv is nullptr");
        NAPI_CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, napi_invalid_arg,
            "OnLoadFontAsync inputParser status error", TextErrorCode::ERROR_INVALID_PARAM);
        NAPI_CHECK_ARGS_RETURN_VOID(context, argc >= ARGC_TWO, napi_invalid_arg,
            "OnLoadFontAsync inputParser argc is invalid", TextErrorCode::ERROR_INVALID_PARAM);
        NAPI_CHECK_ARGS_RETURN_VOID(context, ConvertFromJsValue(env, argv[0], context->familyName), napi_invalid_arg,
            "OnLoadFontAsync inputParser familyName is invalid", TextErrorCode::ERROR_INVALID_PARAM);

        if (!ParseContextFilePath(env, argv, context)) {
            auto* fontCollection = reinterpret_cast<JsFontCollection*>(context->native);
            NAPI_CHECK_ARGS_RETURN_VOID(context, fontCollection != nullptr, napi_invalid_arg,
                "OnLoadFontAsync inputParser failed fontCollection is nullptr", TextErrorCode::ERROR_INVALID_PARAM);
            NAPI_CHECK_ARGS_RETURN_VOID(context, fontCollection->ParseResourceType(env, argv[ARGC_ONE], context->info),
                napi_invalid_arg, "OnLoadFontAsync inputParser failed parse resource error",
                TextErrorCode::ERROR_INVALID_PARAM);
        }
    };

    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        TEXT_ERROR_CHECK(context != nullptr, return, "OnLoadFontAsync executor error, context is nullptr");

        auto* fontCollection = reinterpret_cast<JsFontCollection*>(context->native);
        NAPI_CHECK_ARGS_RETURN_VOID(context, fontCollection != nullptr, napi_generic_failure,
            "OnLoadFontAsync executor error, fontCollection is nullptr", TextErrorCode::ERROR_INVALID_PARAM);
        NAPI_CHECK_ARGS_RETURN_VOID(context, fontCollection->fontcollection_ != nullptr, napi_generic_failure,
            "OnLoadFontAsync executor error, fontcollection_ is nullptr", TextErrorCode::ERROR_INVALID_PARAM);

        if (!context->filePath.empty()) {
            NAPI_CHECK_ARGS_RETURN_VOID(context, fontCollection->SpiltAbsoluteFontPath(context->filePath),
                napi_invalid_arg, "OnLoadFontAsync executor SpiltAbsoluteFontPath failed",
                TextErrorCode::ERROR_INVALID_PARAM);

            NAPI_CHECK_ARGS_RETURN_VOID(context, fontCollection->GetFontFileProperties(context->filePath,
                context->familyName), napi_invalid_arg, "OnLoadFontAsync executor GetFontFileProperties failed",
                TextErrorCode::ERROR_INVALID_PARAM);
        } else {
            NAPI_CHECK_ARGS_RETURN_VOID(context, fontCollection->ParseResourcePath(context->familyName, context->info),
                napi_invalid_arg, "OnLoadFontAsync executor load font failed, path is invalid",
                TextErrorCode::ERROR_INVALID_PARAM);
        }
    };

    auto complete = [env](napi_value& output) {
        output = NapiGetUndefined(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "OnLoadFontAsync", executor, complete);
}
} // namespace OHOS::Rosen
