/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ROSEN_RENDER_SERVICE_BASE_TRANSACTION_RS_RENDER_SERVICE_STUB_H
#define ROSEN_RENDER_SERVICE_BASE_TRANSACTION_RS_RENDER_SERVICE_STUB_H

#include <iremote_stub.h>
#include <message_option.h>
#include <message_parcel.h>

#include "platform/ohos/rs_irender_service.h"
#include "platform/ohos/rs_irender_service_ipc_interface_code_access_verifier.h"
#include "ipc_security/rs_ipc_interface_code_security_manager.h"
#include "rs_render_service_security_utils.h"

namespace OHOS {
namespace Rosen {
class RSRenderServiceStub : public IRemoteStub<RSIRenderService> {
public:
    RSRenderServiceStub() = default;
    ~RSRenderServiceStub() noexcept = default;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
    virtual sptr<RSIRenderServiceConnection> GetConnection(sptr<RSIConnectionToken>& token) = 0;
private:
    static const RSInterfaceCodeSecurityManager securityManager_;
    RSRenderServiceSecurityUtils securityUtils_;
};
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_BASE_TRANSACTION_RS_RENDER_SERVICE_STUB_H