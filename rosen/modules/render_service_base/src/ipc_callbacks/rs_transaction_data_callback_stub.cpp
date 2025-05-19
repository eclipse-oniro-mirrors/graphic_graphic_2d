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

#include "rs_transaction_data_callback_stub.h"
#include "platform/common/rs_log.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {
int RSTransactionDataCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    auto token = data.ReadInterfaceToken();
    if (token != RSITransactionDataCallback::GetDescriptor()) {
        ROSEN_LOGE("RSTransactionDataCallbackStub: token ERR_INVALID_STATE");
        return ERR_INVALID_STATE;
    }
    int ret = ERR_NONE;
    switch (code) {
        case static_cast<uint32_t>(RSITransactionDataCallbackInterfaceCode::ON_AFTER_PROCESS): {
            pid_t pid = {};
            uint64_t timestamp = {};
            auto readRet = data.ReadInt32(pid) && data.ReadUint64(timestamp);
            if (!readRet) {
                RS_LOGE("RSTransactionDataCallbackStub: Read Remote Data ERROR");
            }
            RS_TRACE_NAME_FMT("789 test 10. manager already decode, timeStamp: %" PRIu64 " pid: %d", timeStamp, pid);
            RS_LOGD("789 test 10. manager already decode, timeStamp: %{public}" PRIu64 " pid: %{public}d", timeStamp, pid);
            OnAfterProcess(pid, timeStamp);
            break;
        }
        default: {
            RS_LOGE("RSTransactionDataCallbackStub: Unhandled enumeration value");
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
        }
    }

    return ret;
}
} // namespace Rosen
} // namespace OHOS
