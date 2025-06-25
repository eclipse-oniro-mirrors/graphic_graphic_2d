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

#ifndef ROSEN_RENDER_SERVICE_BASE_ITRANSACTION_DATA_CALLBACK_PROXY_H
#define ROSEN_RENDER_SERVICE_BASE_ITRANSACTION_DATA_CALLBACK_PROXY_H

#include <iremote_proxy.h>

#include "ipc_callbacks/rs_transaction_data_callback.h"
#include "ipc_callbacks/rs_transaction_data_callback_ipc_interface_code.h"

namespace OHOS {
namespace Rosen {
class RSTransactionDataCallbackProxy : public IRemoteProxy<RSITransactionDataCallback> {
public:
    explicit RSTransactionDataCallbackProxy(const sptr<IRemoteObject>& impl);
    virtual ~RSTransactionDataCallbackProxy() noexcept = default;

    void OnAfterProcess(int32_t pid, uint64_t timeStamp) override;

private:
    static inline BrokerDelegator<RSTransactionDataCallbackProxy> delegator_;
};
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_BASE_ITRANSACTION_DATA_CALLBACK_PROXY_H