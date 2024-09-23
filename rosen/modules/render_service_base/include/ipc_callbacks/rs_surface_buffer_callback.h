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

#ifndef ROSEN_RENDER_SERVICE_BASE_ISURFACE_BUFFER_CALLBACK_H
#define ROSEN_RENDER_SERVICE_BASE_ISURFACE_BUFFER_CALLBACK_H

#include <vector>
#include <iremote_broker.h>

#include "common/rs_common_def.h"

namespace OHOS {
namespace Rosen {
class RSISurfaceBufferCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.rosen.SurfaceBufferListener");

    RSISurfaceBufferCallback() = default;
    virtual ~RSISurfaceBufferCallback() noexcept = default;

    // Uid and BufferQueue are a one-to-one mapping relationship. This API is used
    // when an application has multiple XComponent components, and it notifies ArkUI
    // which BufferQueue's Buffer can be released after it has been consumed.
    virtual void OnFinish(uint64_t uid, const std::vector<uint32_t>& surfaceBufferIds) = 0;
};
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_BASE_ISURFACE_BUFFER_CALLBACK_H
