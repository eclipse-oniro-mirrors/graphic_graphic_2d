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

#ifndef RENDER_SERVICE_DELAYED_RESOURCE_HANDLER_H
#define RENDER_SERVICE_DELAYED_RESOURCE_HANDLER_H

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>

#include "refbase.h"

namespace OHOS {
namespace Rosen {

class RSDelayedResourceHandler : public RefBase {
public:
    explicit RSDelayedResourceHandler(pid_t pid);
    ~RSDelayedResourceHandler() noexcept override = default;

    void SetDelayedCleanupEnabled(bool enabled);
    bool IsDelayedCleanupEnabled() const;

    void OnRemoteDied();
    void TriggerImmediateCleanup();

    void SetServiceCleanupCallback(std::function<void()> callback);
    void SetRenderCleanupCallback(std::function<void()> callback);
    void SetActiveConnectionCheckCallback(std::function<bool(pid_t)> callback);

private:
    void ScheduleDelayedCleanup();
    void ExecuteResourceCleanup();
    void CancelScheduledCleanup();

    pid_t pid_;
    std::atomic<bool> isDelayedCleanupEnabled_{false};
    std::atomic<bool> cleanupExecuted_{false};
    std::atomic<bool> cancelled_{false};

    std::mutex mutex_;
    std::condition_variable conditionVariable_;
    bool timerStarted_{false};

    std::function<void()> serviceCleanupCallback_;
    std::function<void()> renderCleanupCallback_;
    std::function<bool(pid_t)> hasActiveConnectionForPid_;
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_DELAYED_RESOURCE_HANDLER_H
