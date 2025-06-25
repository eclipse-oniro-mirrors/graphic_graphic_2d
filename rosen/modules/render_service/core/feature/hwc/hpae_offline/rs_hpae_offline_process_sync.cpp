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
#include "feature/hwc/hpae_offline/rs_hpae_offline_process_sync.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_util.h"
#include "common/rs_optional_trace.h"

namespace OHOS {
namespace Rosen {

std::weak_ptr<ProcessOfflineStatus> RSHpaeOfflineProcessSync::RegisterPostedTask(
    uint64_t taskId)
{
    RS_OPTIONAL_TRACE_NAME_FMT("hpae_offline: Register task [%" PRIu64 "].", taskId);
    RS_OFFLINE_LOGD("hpae_offline: Register task [%{public}" PRIu64 "].", taskId);
    auto status = std::make_shared<ProcessOfflineStatus>();
    std::weak_ptr<ProcessOfflineStatus> statusWeakPtr = status;
    {
        std::lock_guard<std::mutex> lock(poolMtx_);
        if (resultPool_.find(taskId) == resultPool_.end()) {
            resultPool_[taskId] = status;
        } else {
            RS_OFFLINE_LOGW("Task with %{public}" PRIu64 " already exists.", taskId);
        }
    }
    return statusWeakPtr;
}

void RSHpaeOfflineProcessSync::MarkTaskDoneAndSetResult(
    std::weak_ptr<ProcessOfflineStatus> statusWeakPtr,
    const ProcessOfflineResult& processOfflineResult)
{
    if (auto status = statusWeakPtr.lock()) {
        RS_OFFLINE_LOGD("task done, set result and notify.");
        {
            std::lock_guard<std::mutex> lock(status->mtx);
            status->done = true;
            status->result = processOfflineResult;
            status->cv.notify_one();
        }
    }
}

std::shared_ptr<ProcessOfflineStatus> RSHpaeOfflineProcessSync::GetTaskStatus(uint64_t taskId)
{
    std::lock_guard<std::mutex> lock(poolMtx_);
    auto iter = resultPool_.find(taskId);
    if (iter == resultPool_.end()) {
        RS_OFFLINE_LOGW("%{public}s, taskPool has not wanted task.", __func__);
        return nullptr;
    }
    auto status = std::move(iter->second);
    resultPool_.erase(iter);
    return status;
}

bool RSHpaeOfflineProcessSync::WaitForTaskAndGetResult(uint64_t taskId,
    ProcessOfflineResult& processOfflineResult, std::chrono::milliseconds timeout)
{
    RS_TRACE_NAME_FMT("hpae_offline: Wait for offline task.", __func__);
    auto status = GetTaskStatus(taskId);
    if (!status) {
        RS_OFFLINE_LOGE("%{public}s, task is null.", __func__);
        return false;
    }

    std::unique_lock<std::mutex> lock(status->mtx);
    if (timeout == std::chrono::milliseconds::max()) {
        status->cv.wait(lock, [status] { return status->done;});
    } else {
        if (!status->cv.wait_for(lock, timeout, [status] { return status->done; })) {
            status->timeout = true;
            RS_OFFLINE_LOGW("%{public}s, wait task[%{public}" PRIu64 "] timeout!!!", __func__, taskId);
            return false;
        }
    }
    processOfflineResult = status->result;
    return true;
}

int32_t RSHpaeOfflineProcessSync::GetResultPoolSize()
{
    std::lock_guard<std::mutex> lock(poolMtx_);
    return resultPool_.size();
}

void RSHpaeOfflineProcessSync::ClearResultPool()
{
    std::lock_guard<std::mutex> lock(poolMtx_);
    resultPool_.clear();
}

} // namespace Rosen
} // namespace OHOS