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

#include "vsync_connection_proxy.h"
#include "graphic_common.h"
#include "vsync_log.h"

namespace OHOS {
namespace Rosen {
VSyncConnectionProxy::VSyncConnectionProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IVSyncConnection>(impl)
{
}

VsyncError VSyncConnectionProxy::RequestNextVSync()
{
    return RequestNextVSync("unknown", 0);
}

VsyncError VSyncConnectionProxy::RequestNextVSync(const std::string& fromWhom, int64_t lastVSyncTS)
{
    MessageOption opt(MessageOption::TF_ASYNC);
    MessageParcel arg;
    MessageParcel ret;

    arg.WriteInterfaceToken(GetDescriptor());
    arg.WriteString(fromWhom);
    arg.WriteInt64(lastVSyncTS);
    int res = Remote()->SendRequest(IVSYNC_CONNECTION_REQUEST_NEXT_VSYNC, arg, ret, opt);
    if (res != NO_ERROR) {
        VLOGE("ipc send fail, error:%{public}d", res);
        return VSYNC_ERROR_UNKOWN;
    }
    return VSYNC_ERROR_OK;
}

VsyncError VSyncConnectionProxy::SetUiDvsyncSwitch(bool dvsyncSwitch)
{
    MessageOption opt(MessageOption::TF_ASYNC);
    MessageParcel arg;
    MessageParcel ret;

    arg.WriteInterfaceToken(GetDescriptor());
    arg.WriteBool(dvsyncSwitch);
    int res = Remote()->SendRequest(IVSYNC_CONNECTION_SET_UI_DVSYNC_SWITCH, arg, ret, opt);
    if (res != NO_ERROR) {
        VLOGE("ipc send fail, error:%{public}d", res);
        return VSYNC_ERROR_UNKOWN;
    }
    return VSYNC_ERROR_OK;
}

VsyncError VSyncConnectionProxy::SetUiDvsyncConfig(int32_t bufferCount)
{
    MessageOption opt(MessageOption::TF_ASYNC);
    MessageParcel arg;
    MessageParcel ret;

    arg.WriteInterfaceToken(GetDescriptor());
    arg.WriteBool(dvsyncSwitch);
    if (!arg.WriteInt32(bufferCount)) {
        VLOGE("SetUiDvsyncConfig bufferCount error");
        return VSYNC_ERROR_BINDER_ERROR;
    }
    int res = Remote()->SendRequest(IVSYNC_CONNECTION_SET_UI_DVSYNC_CONFIG, arg, ret, opt);
    if (res != NO_ERROR) {
        return VSYNC_ERROR_BINDER_ERROR;
    }
    return VSYNC_ERROR_OK;
}

VsyncError VSyncConnectionProxy::GetReceiveFd(int32_t &fd)
{
    MessageOption opt;
    MessageParcel arg;
    MessageParcel ret;

    arg.WriteInterfaceToken(GetDescriptor());
    int res = Remote()->SendRequest(IVSYNC_CONNECTION_GET_RECEIVE_FD, arg, ret, opt);
    if (res != NO_ERROR) {
        VLOGE("GetReceiveFd Failed, res = %{public}d", res);
        return VSYNC_ERROR_BINDER_ERROR;
    }
    fd = ret.ReadFileDescriptor();
    if (fd <= 0) {
        VLOGE("GetReceiveFd Invalid fd:%{public}d", fd);
        return VSYNC_ERROR_API_FAILED;
    }
    return VSYNC_ERROR_OK;
}

VsyncError VSyncConnectionProxy::SetVSyncRate(int32_t rate)
{
    if (rate < -1) {
        return VSYNC_ERROR_INVALID_ARGUMENTS;
    }
    MessageOption opt;
    MessageParcel arg;
    MessageParcel ret;

    arg.WriteInterfaceToken(GetDescriptor());
    arg.WriteInt32(rate);
    int res = Remote()->SendRequest(IVSYNC_CONNECTION_SET_RATE, arg, ret, opt);
    if (res != NO_ERROR) {
        return VSYNC_ERROR_BINDER_ERROR;
    }
    return VSYNC_ERROR_OK;
}

VsyncError VSyncConnectionProxy::Destroy()
{
    MessageOption opt;
    MessageParcel arg;
    MessageParcel ret;

    arg.WriteInterfaceToken(GetDescriptor());
    int res = Remote()->SendRequest(IVSYNC_CONNECTION_DESTROY, arg, ret, opt);
    if (res != NO_ERROR) {
        return VSYNC_ERROR_BINDER_ERROR;
    }
    return VSYNC_ERROR_OK;
}
} // namespace Vsync
} // namespace OHOS
