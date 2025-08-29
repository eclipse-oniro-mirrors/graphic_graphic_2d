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

#include "rs_render_service_stub.h"

#include <iremote_proxy.h>

namespace OHOS {
namespace Rosen {
class RSConnectionTokenProxy : public IRemoteProxy<RSIConnectionToken> {
public:
    explicit RSConnectionTokenProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<RSIConnectionToken>(impl) {}
    virtual ~RSConnectionTokenProxy() noexcept = default;

private:
    static inline BrokerDelegator<RSConnectionTokenProxy> delegator_;
};

int RSRenderServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
#ifdef ENABLE_IPC_SECURITY_ACCESS_COUNTER
    auto accessCount = securityUtils_.GetCodeAccessCounter(code);
    if (!securityManager_.IsAccessTimesRestricted(code, accessCount)) {
        RS_LOGE("RSRenderServiceStub::OnRemoteRequest This Function[ID=%{public}u] invoke times:%{public}d"
            "by pid[%{public}d]", code, accessCount, GetCallingPid());
        return ERR_INVALID_STATE;
    }
#endif
#ifdef ENABLE_IPC_SECURITY_ACCESS_COUNTER
    securityUtils_.IncreaseAccessCounter(code);
#endif
    int ret = ERR_NONE;
    switch (code) {
        case static_cast<uint32_t>(RSIRenderServiceInterfaceCode::CREATE_CONNECTION): {
            auto interfaceToken = data.ReadInterfaceToken();
            if (interfaceToken != RSIRenderService::GetDescriptor()) {
                RS_LOGE("RSRenderServiceStub::CREATE_CONNECTION Read interfaceToken failed!");
                ret = ERR_INVALID_STATE;
                break;
            }

            auto remoteObj = data.ReadRemoteObject();
            if (remoteObj == nullptr) {
                RS_LOGE("RSRenderServiceStub::CREATE_CONNECTION Read remoteObj failed!");
                ret = ERR_NULL_OBJECT;
                break;
            }

            if (!remoteObj->IsProxyObject()) {
                ret = ERR_UNKNOWN_OBJECT;
                break;
            }

            auto token = iface_cast<RSIConnectionToken>(remoteObj);
            auto newConn = CreateConnection(token);
            if (newConn != nullptr) {
                if (!reply.WriteBool(true)) {
                    RS_LOGE("RSRenderServiceStub::CREATE_CONNECTION Write failed!");
                    ret = ERR_INVALID_REPLY;
                    break;
                }
                if (!reply.WriteRemoteObject(newConn->AsObject())) {
                    RS_LOGE("RSRenderServiceStub::CREATE_CONNECTION Write remoteObj failed!");
                    ret = ERR_INVALID_REPLY;
                }
            } else {
                if (!reply.WriteBool(false)) {
                    RS_LOGE("RSRenderServiceStub::CREATE_CONNECTION Write failed and newConn == nullptr");
                    ret = ERR_INVALID_REPLY;
                }
            }
            break;
        }
        case static_cast<uint32_t>(RSIRenderServiceInterfaceCode::REMOVE_CONNECTION): {
            auto interfaceToken = data.ReadInterfaceToken();
            if (interfaceToken != RSIRenderService::GetDescriptor()) {
                RS_LOGE("RSRenderServiceStub::REMOVE_CONNECTION Read interfaceToken failed!");
                ret = ERR_INVALID_STATE;
                break;
            }

            auto remoteObj = data.ReadRemoteObject();
            if (remoteObj == nullptr) {
                RS_LOGE("RSRenderServiceStub::REMOVE_CONNECTION Read remoteObj failed!");
                ret = ERR_NULL_OBJECT;
                break;
            }

            if (!remoteObj->IsProxyObject()) {
                RS_LOGE("RSRenderServiceStub::REMOVE_CONNECTION remoteObj !IsProxyObject() failed!");
                ret = ERR_UNKNOWN_OBJECT;
                break;
            }

            auto token = iface_cast<RSIConnectionToken>(remoteObj);
            bool isConnectionRemoved = RemoveConnection(token);
            reply.WriteBool(isConnectionRemoved);
            break;
        }
        default: {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }

    return ret;
}

const RSInterfaceCodeSecurityManager RSRenderServiceStub::securityManager_ = \
    RSInterfaceCodeSecurityManager::CreateInstance<RSIRenderServiceInterfaceCodeAccessVerifier>();
} // namespace Rosen
} // namespace OHOS
