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

#include "rs_delayed_resource_handler.h"

#include <thread>

#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {

namespace {
constexpr int32_t DELAYED_CLEANUP_SECONDS = 10;
}

RSDelayedResourceHandler::RSDelayedResourceHandler(pid_t pid) : pid_(pid)
{
    RS_LOGI("DelayedResourceHandler created for pid %{public}d", pid_);
}

void RSDelayedResourceHandler::SetDelayedCleanupEnabled(bool enabled)
{
    bool previousValue = isDelayedCleanupEnabled_.exchange(enabled);
    if (previousValue != enabled) {
        RS_LOGI("DelayedResourceHandler pid %{public}d status changed: %{public}d -> %{public}d", pid_, previousValue,
            enabled);
    }
}

bool RSDelayedResourceHandler::IsDelayedCleanupEnabled() const
{
    return isDelayedCleanupEnabled_.load();
}

void RSDelayedResourceHandler::SetServiceCleanupCallback(std::function<void()> callback)
{
    serviceCleanupCallback_ = std::move(callback);
}

void RSDelayedResourceHandler::SetRenderCleanupCallback(std::function<void()> callback)
{
    renderCleanupCallback_ = std::move(callback);
}

void RSDelayedResourceHandler::SetActiveConnectionCheckCallback(std::function<bool(pid_t)> callback)
{
    hasActiveConnectionForPid_ = std::move(callback);
}

void RSDelayedResourceHandler::OnRemoteDied()
{
    if (cleanupExecuted_.load()) {
        RS_LOGI("DelayedResourceHandler pid %{public}d cleanup already executed, ignore", pid_);
        return;
    }

    if (!isDelayedCleanupEnabled_.load()) {
        RS_LOGI("DelayedResourceHandler pid %{public}d not enabled, immediate cleanup", pid_);
        ExecuteResourceCleanup();
        return;
    }

    RS_LOGI("DelayedResourceHandler pid %{public}d death detected, scheduling delayed cleanup in %{public}ds", pid_,
        DELAYED_CLEANUP_SECONDS);
    ScheduleDelayedCleanup();
}

void RSDelayedResourceHandler::ScheduleDelayedCleanup()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (timerStarted_) {
        RS_LOGW("DelayedResourceHandler pid %{public}d delayed cleanup already scheduled, ignore", pid_);
        return;
    }
    timerStarted_ = true;
    cancelled_ = false;

    std::thread([sptr = sptr<RSDelayedResourceHandler>(this)]() {
        auto& handler = *sptr;
        std::unique_lock<std::mutex> lock(handler.mutex_);
        bool wasCancelled = handler.conditionVariable_.wait_for(
            lock, std::chrono::seconds(DELAYED_CLEANUP_SECONDS), [&handler]() { return handler.cancelled_.load(); });
        if (wasCancelled) {
            RS_LOGI("DelayedResourceHandler pid %{public}d delayed cleanup was cancelled", handler.pid_);
            return;
        }
        handler.ExecuteResourceCleanup();
    }).detach();
}

void RSDelayedResourceHandler::ExecuteResourceCleanup()
{
    if (cleanupExecuted_.exchange(true)) {
        RS_LOGW("DelayedResourceHandler pid %{public}d ExecuteResourceCleanup called but already executed", pid_);
        return;
    }

    if (hasActiveConnectionForPid_ && hasActiveConnectionForPid_(pid_)) {
        RS_LOGW("DelayedResourceHandler pid %{public}d DELAYED CLEANUP WARNING: active connection exists "
                "for same pid! Possible PID reuse. This cleanup may accidentally affect nodes from a "
                "newer process.",
            pid_);
    } else {
        RS_LOGI("DelayedResourceHandler pid %{public}d delayed cleanup: no PID reuse detected", pid_);
    }
    hasActiveConnectionForPid_ = nullptr;

    RS_LOGI("DelayedResourceHandler pid %{public}d delayed cleanup: executing service callback", pid_);
    if (serviceCleanupCallback_) {
        serviceCleanupCallback_();
        serviceCleanupCallback_ = nullptr;
    }

    RS_LOGI("DelayedResourceHandler pid %{public}d delayed cleanup: executing render callback", pid_);
    if (renderCleanupCallback_) {
        renderCleanupCallback_();
        renderCleanupCallback_ = nullptr;
    }

    RS_LOGI("DelayedResourceHandler pid %{public}d delayed cleanup: completed", pid_);
}

void RSDelayedResourceHandler::TriggerImmediateCleanup()
{
    RS_LOGI("DelayedResourceHandler pid %{public}d immediate cleanup triggered", pid_);
    CancelScheduledCleanup();
    ExecuteResourceCleanup();
}

void RSDelayedResourceHandler::CancelScheduledCleanup()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!timerStarted_) {
        RS_LOGI("DelayedResourceHandler pid %{public}d cancel: no delayed cleanup to cancel", pid_);
        return;
    }
    cancelled_ = true;
    conditionVariable_.notify_all();
    RS_LOGI("DelayedResourceHandler pid %{public}d delayed cleanup cancelled", pid_);
}

} // namespace Rosen
} // namespace OHOS