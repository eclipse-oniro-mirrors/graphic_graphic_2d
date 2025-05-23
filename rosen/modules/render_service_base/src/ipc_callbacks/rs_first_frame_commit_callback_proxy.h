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

#ifndef ROSEN_RENDER_SERVICE_BASE_FIRST_FRAME_COMMIT_CALLBACK_PROXY_H
#define ROSEN_RENDER_SERVICE_BASE_FIRST_FRAME_COMMIT_CALLBACK_PROXY_H

#include <iremote_proxy.h>

#include "ipc_callbacks/rs_ifirst_frame_commit_callback.h"
#include "ipc_callbacks/rs_ifirst_frame_commit_callback_ipc_interface_code.h"

namespace OHOS {
namespace Rosen {
class RSFirstFrameCommitCallbackProxy : public IRemoteProxy<RSIFirstFrameCommitCallback> {
public:
    explicit RSFirstFrameCommitCallbackProxy(const sptr<IRemoteObject>& impl);
    virtual ~RSFirstFrameCommitCallbackProxy() noexcept = default;

    void OnFirstFrameCommit(uint64_t screenId, int64_t timestamp) override;

private:
    static inline BrokerDelegator<RSFirstFrameCommitCallbackProxy> delegator_;
};
} // namespace Rosen
} // namespace OHOS
#endif