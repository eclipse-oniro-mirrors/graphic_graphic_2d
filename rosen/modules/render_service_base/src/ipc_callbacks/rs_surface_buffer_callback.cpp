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

#include "ipc_callbacks/rs_surface_buffer_callback.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
RSDefaultSurfaceBufferCallback::RSDefaultSurfaceBufferCallback(
    std::function<void(uint64_t, const std::vector<uint32_t>&)> callback) : callback_(callback)
{
}

void RSDefaultSurfaceBufferCallback::OnFinish(
    uint64_t uid, const std::vector<uint32_t>& surfaceBufferIds)
{
    if (callback_) {
        std::invoke(callback_, uid, surfaceBufferIds);
    }
}

sptr<IRemoteObject> RSDefaultSurfaceBufferCallback::AsObject()
{
    return nullptr;
}
} // namespace Rosen
} // namespace OHOS
