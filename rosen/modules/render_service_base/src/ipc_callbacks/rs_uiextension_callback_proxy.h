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

#ifndef ROSEN_RENDER_SERVICE_BASE_IUIEXTENSION_CALLBACK_PROXY_H
#define ROSEN_RENDER_SERVICE_BASE_IUIEXTENSION_CALLBACK_PROXY_H

#include <iremote_proxy.h>

#include "ipc_callbacks/rs_iuiextension_callback.h"
#include "ipc_callbacks/rs_iuiextension_callback_ipc_interface_code.h"

namespace OHOS {
namespace Rosen {
class RSUIExtensionCallbackProxy : public IRemoteProxy<RSIUIExtensionCallback> {
public:
    explicit RSUIExtensionCallbackProxy(const sptr<IRemoteObject>& impl);
    virtual ~RSUIExtensionCallbackProxy() noexcept = default;

    void OnUIExtension(std::shared_ptr<RSUIExtensionData> uiExtensionData, uint64_t userId) override;

private:
    static inline BrokerDelegator<RSUIExtensionCallbackProxy> delegator_;
};
} // namespace Rosen
} // namespace OHOS
#endif // ROSEN_OHOS