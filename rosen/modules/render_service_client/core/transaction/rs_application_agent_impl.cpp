/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "rs_application_agent_impl.h"

#ifdef ROSEN_OHOS
#include "platform/ohos/rs_render_service_connect_hub.h"
#endif
#include "rs_trace.h"
#include "ui/rs_ui_director.h"
#include "sandbox_utils.h"

namespace OHOS {
namespace Rosen {
#ifdef OHOS_PLATFORM
static sptr<RSApplicationAgentImpl> gRSApplicationAgentImplInstance;
#endif
RSApplicationAgentImpl* RSApplicationAgentImpl::Instance()
{
#ifdef OHOS_PLATFORM
    if (gRSApplicationAgentImplInstance == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (gRSApplicationAgentImplInstance == nullptr) {
            gRSApplicationAgentImplInstance = new RSApplicationAgentImpl();
        }
    }
    return gRSApplicationAgentImplInstance.GetRefPtr();
#else
    return nullptr;
#endif
}

void RSApplicationAgentImpl::RegisterRSApplicationAgent()
{
    static bool isRegistered = false;
    if (isRegistered) {
        return;
    }
    isRegistered = true;
#ifdef ROSEN_OHOS
    RSRenderServiceConnectHub::SetOnConnectCallback(
        [weakThis = wptr<RSApplicationAgentImpl>(this)](sptr<RSIRenderServiceConnection>& conn) {
            sptr<IApplicationAgent> appSptr = weakThis.promote();
            if (appSptr == nullptr) {
                return;
            }
            // Not necessory to set pid
            conn->RegisterApplicationAgent(0, appSptr);
        });
#endif
}

#ifdef ROSEN_OHOS
void RSApplicationAgentImpl::OnTransaction(std::shared_ptr<RSTransactionData> transactionData)
{
    RS_TRACE_NAME("RSApplicationAgentImpl::OnTransaction");
    RSUIDirector::RecvMessages(transactionData);
}
#endif
}
}
