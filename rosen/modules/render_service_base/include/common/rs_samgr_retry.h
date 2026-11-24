/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_BASE_COMMON_RS_SAMGR_RETRY_H
#define RENDER_SERVICE_BASE_COMMON_RS_SAMGR_RETRY_H

#include <errors.h>
#include <iservice_registry.h>
#include <unistd.h>

#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
// bounded retry for synchronous samgr IPC (AddSystemAbility/SubscribeSystemAbility) failures;
// wait grows linearly per retry (1000us * retry count), following the ConnectToServer pattern
constexpr int32_t SAMGR_CALL_MAX_RETRY = 5;
constexpr int32_t SAMGR_CALL_RETRY_INTERVAL_US = 1000; // 1ms base, linear backoff per retry

// caller passes __func__ (or a caller tag) and the samgr call as a lambda that takes the
// samgr proxy and returns int32_t (ERR_OK on success); returns true when the call succeeded
template<typename Call>
bool RetrySamgrCall(const char* caller, Call&& call)
{
    for (int32_t retryCnt = 0; retryCnt < SAMGR_CALL_MAX_RETRY; retryCnt++) {
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            RS_LOGE("%{public}s: GetSystemAbilityManager fail, retry [%{public}d/%{public}d]",
                caller, retryCnt + 1, SAMGR_CALL_MAX_RETRY);
            usleep(SAMGR_CALL_RETRY_INTERVAL_US * (retryCnt + 1));
            continue;
        }
        int32_t ret = call(samgr);
        if (ret == ERR_OK) {
            return true;
        }
        RS_LOGE("%{public}s: samgr call failed, ret [%{public}d], retry [%{public}d/%{public}d]",
            caller, ret, retryCnt + 1, SAMGR_CALL_MAX_RETRY);
        usleep(SAMGR_CALL_RETRY_INTERVAL_US * (retryCnt + 1));
    }
    RS_LOGE("%{public}s: samgr call failed after [%{public}d] retries", caller, SAMGR_CALL_MAX_RETRY);
    return false;
}
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_COMMON_RS_SAMGR_RETRY_H
