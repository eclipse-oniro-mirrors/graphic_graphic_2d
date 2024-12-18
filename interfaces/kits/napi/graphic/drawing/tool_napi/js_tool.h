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

#ifndef OHOS_ROSEN_JS_TOOL_H
#define OHOS_ROSEN_JS_TOOL_H

#include <memory>
#include <native_engine/native_engine.h>
#include <native_engine/native_value.h>

#ifdef ROSEN_OHOS
#include "resource_manager.h"
#endif

namespace OHOS::Rosen {
namespace Drawing {

#ifdef ROSEN_OHOS
struct ResourceInfo {
    int32_t resId = 0;
    int32_t type = 0;
    std::vector<std::string> params;
};

enum class ResourceType {
    COLOR = 10001,
    STRING = 10003,
    INTEGER = 10007,
    RAWFILE = 30000,
};
#endif

class JsTool final {
public:
    JsTool();
    ~JsTool();

    static napi_value Init(napi_env env, napi_value exportObj);
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize);

    static napi_value makeColorFromResourceColor(napi_env env, napi_callback_info info);

#ifdef ROSEN_OHOS
    static size_t GetParamLen(napi_env env, napi_value param);
    static std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager();
    static bool GetResourceInfo(napi_env env, napi_value value, ResourceInfo& info);
    static bool GetResourceInfoParams(napi_env env, ResourceInfo& info, napi_value paramsNApi);
    static bool GetResourceRawFileDataBuffer(std::unique_ptr<uint8_t[]>&& buffer,
        size_t& len, ResourceInfo& info);

    static unsigned int HandleIncorrectColor(const std::string& newColorStr);
    static bool GetResourceColor(napi_env env, napi_value res, Color& result);
    static unsigned int GetColorNumberResult(unsigned int origin);
    static bool GetColorStringResult(std::string colorStr, unsigned int& result);
    static bool MatchColorWithMagic(std::string& colorStr, uint32_t maskAlpha, unsigned int& result);
    static bool MatchColorWithMagicMini(std::string& colorStr, uint32_t maskAlpha, unsigned int& result);
    static bool MatchColorWithRGB(const std::string& colorStr, unsigned int& result);
    static bool MatchColorWithRGBA(const std::string& colorStr, unsigned int& result);
    static bool FastCheckColorType(const std::string& colorStr, const std::string& expectPrefix,
        const std::vector<size_t>& expectLengths);
    static bool IsHexNumber(std::string& colorStr);
    static bool HandleRGBValue(int value, int& result);
    static bool IsOpacityValid(double value);
    static bool GetColorObjectResult(napi_env env, napi_value value, unsigned int& result);
#endif

private:
    static thread_local napi_ref constructor_;
};
} // namespace Drawing
} // namespace OHOS::Rosen
#endif // OHOS_ROSEN_JS_TOOL_H