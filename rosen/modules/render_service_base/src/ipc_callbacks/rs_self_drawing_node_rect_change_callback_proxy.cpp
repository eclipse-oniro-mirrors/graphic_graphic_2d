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

#include "rs_self_drawing_node_rect_change_callback_proxy.h"

#include <message_option.h>
#include <message_parcel.h>

#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
RSSelfDrawingNodeRectChangeCallbackProxy::RSSelfDrawingNodeRectChangeCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<RSISelfDrawingNodeRectChangeCallback>(impl)
{
}

void RSSelfDrawingNodeRectChangeCallbackProxy::OnSelfDrawingNodeRectChange(
    std::shared_ptr<RSSelfDrawingNodeRectData> SelfDrawingNodeRectData)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(RSISelfDrawingNodeRectChangeCallback::GetDescriptor())) {
        ROSEN_LOGE("RSSelfDrawingNodeRectChangeCallbackProxy::OnSelfDrawingNodeRectChange WriteInterfaceToken failed");
        return;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        ROSEN_LOGE("RSSelfDrawingNodeRectChangeCallbackProxy::OnSelfDrawingNodeRectChange remote is null!");
        return;
    }

    option.SetFlags(MessageOption::TF_ASYNC);
    if (!data.WriteParcelable(SelfDrawingNodeRectData.get())) {
        ROSEN_LOGE("RSSelfDrawingNodeRectChangeCallbackProxy::OnSelfDrawingNodeRectChange WriteParcelable failed");
        return;
    }

    uint32_t code =
        static_cast<uint32_t>(RSISelfDrawingNodeRectChangeCallbackInterfaceCode::ON_SELF_DRAWING_NODE_RECT_CHANGED);
    int32_t err = remote->SendRequest(code, data, reply, option);
    if (err != NO_ERROR) {
        ROSEN_LOGE("RSSelfDrawingNodeRectChangeCallbackProxy::OnSelfDrawingNodeRectChange error = %{public}d", err);
    }
}
} // namespace Rosen
} // namespace OHOS