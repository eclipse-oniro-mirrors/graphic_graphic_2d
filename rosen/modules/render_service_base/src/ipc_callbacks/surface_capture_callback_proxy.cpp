/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "surface_capture_callback_proxy.h"
#include <message_option.h>
#include <message_parcel.h>
#include "platform/common/rs_log.h"
#include "ipc_callbacks/rs_ipc_callbacks_check.h"

namespace OHOS {
namespace Rosen {
RSSurfaceCaptureCallbackProxy::RSSurfaceCaptureCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<RSISurfaceCaptureCallback>(impl)
{
}

bool RSSurfaceCaptureCallbackProxy::WriteSurfaceCaptureConfig(
    const RSSurfaceCaptureConfig& captureConfig, MessageParcel& data)
{
    // send mainScreenRect only to reduce ipc data size
    if (!data.WriteBool(captureConfig.isHdrCapture) ||
        !data.WriteBool(captureConfig.needF16WindowCaptureForScRGB) ||
        !data.WriteFloat(captureConfig.mainScreenRect.left_) ||
        !data.WriteFloat(captureConfig.mainScreenRect.top_) ||
        !data.WriteFloat(captureConfig.mainScreenRect.right_) ||
        !data.WriteFloat(captureConfig.mainScreenRect.bottom_) ||
        !data.WriteUint64(captureConfig.uiCaptureInRangeParam.endNodeId) ||
        !data.WriteBool(captureConfig.uiCaptureInRangeParam.useBeginNodeSize) ||
        !data.WriteFloat(captureConfig.specifiedAreaRect.left_) ||
        !data.WriteFloat(captureConfig.specifiedAreaRect.top_) ||
        !data.WriteFloat(captureConfig.specifiedAreaRect.right_) ||
        !data.WriteFloat(captureConfig.specifiedAreaRect.bottom_)) {
        ROSEN_LOGE("RSSurfaceCaptureCallbackProxy::WriteSurfaceCaptureConfig Write CaptureConfig failed");
        return false;
    }
    return true;
}

void RSSurfaceCaptureCallbackProxy::OnSurfaceCapture(NodeId id, const RSSurfaceCaptureConfig& captureConfig,
    Media::PixelMap* pixelmap, Media::PixelMap* pixelmapHDR)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(RSISurfaceCaptureCallback::GetDescriptor())) {
        ROSEN_LOGE("SurfaceCaptureCallbackProxy::OnSurfaceCapture WriteInterfaceToken failed");
        return;
    }
    if (!data.WriteUint64(id)) {
        ROSEN_LOGE("SurfaceCaptureCallbackProxy::OnSurfaceCapture WriteUint64 failed");
        return;
    }
    if (!WriteSurfaceCaptureConfig(captureConfig, data)) {
        ROSEN_LOGE("SurfaceCaptureCallbackProxy::OnSurfaceCapture WriteSurfaceCaptureConfig failed");
        return;
    }
    if (!data.WriteParcelable(pixelmap)) {
        ROSEN_LOGE("SurfaceCaptureCallbackProxy::OnSurfaceCapture WriteParcelable failed");
        return;
    }
    if (captureConfig.isHdrCapture && !data.WriteParcelable(pixelmapHDR)) {
        ROSEN_LOGE("SurfaceCaptureCallbackProxy::OnSurfaceCapture WriteParcelable failed");
        return;
    }
    option.SetFlags(MessageOption::TF_ASYNC);
    uint32_t code = captureConfig.isHdrCapture ?
        static_cast<uint32_t>(RSISurfaceCaptureCallbackInterfaceCode::ON_SURFACE_CAPTURE_HDR) :
        static_cast<uint32_t>(RSISurfaceCaptureCallbackInterfaceCode::ON_SURFACE_CAPTURE);
    int32_t err = SendRequestRemote::SendRequest(Remote(), code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("SurfaceCaptureCallbackProxy: SendRequest() error");
    }
}
} // namespace Rosen
} // namespace OHOS
