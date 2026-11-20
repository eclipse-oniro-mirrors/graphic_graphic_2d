/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_UIEFFECT_BLENDER_NAPI_H
#define OHOS_UIEFFECT_BLENDER_NAPI_H

#include <hilog/log.h>
#include <memory>

#include "effect/include/blender.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Rosen {

class BlenderBase;

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD001405

#undef LOG_TAG
#define LOG_TAG "UiEffect_Blender"
#define BLENDER_LOG_D(fmt, ...) HILOG_DEBUG(LOG_CORE, fmt, ##__VA_ARGS__)
#define BLENDER_LOG_I(fmt, ...) HILOG_INFO(LOG_CORE, fmt, ##__VA_ARGS__)
#define BLENDER_LOG_E(fmt, ...) HILOG_ERROR(LOG_CORE, fmt, ##__VA_ARGS__)

class BlenderNapi {
public:
    BlenderNapi() = default;
    ~BlenderNapi() = default;
    static napi_value Init(napi_env env, napi_value exports);

private:
    static thread_local napi_ref sConstructor_;
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void* nativeObject, void* finalize);

    static napi_value Create(napi_env env, const std::shared_ptr<Blender>& blender);
    static napi_value CreateColorfulBrightnessBlender(napi_env env, napi_callback_info info);
    static napi_value CreateBrightnessBlender(napi_env env, napi_callback_info info);
    static napi_value CreateHdrDarkenBlender(napi_env env, napi_callback_info info);
};
} // namespace Rosen
} // namespace OHOS
#endif // OHOS_UIEFFECT_BLENDER_NAPI_H
