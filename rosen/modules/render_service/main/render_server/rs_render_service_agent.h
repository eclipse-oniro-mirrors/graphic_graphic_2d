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

#ifndef RENDER_SERVICE_MAIN_RENDER_SERVER_RS_RENDER_SERVICE_AGENT_H
#define RENDER_SERVICE_MAIN_RENDER_SERVER_RS_RENDER_SERVICE_AGENT_H

#include <chrono>
#include <future>
#include <optional>
#include <type_traits>
#include <utility>

#include "feature/hyper_graphic_manager/hgm_context.h"
#include "rs_render_service.h"

namespace OHOS {
namespace Rosen {
namespace St {
template<typename Task>
class ScheduledTask : public RefBase {
public:
    static auto Create(Task&& task)
    {
        sptr<ScheduledTask<Task>> t(new ScheduledTask(std::move(task)));
        return std::make_pair(t, t->task_.get_future());
    }

    void Run() { task_(); }

private:
    explicit ScheduledTask(Task&& task) : task_(std::move(task)) {}
    ~ScheduledTask() override = default;

    using Return = std::invoke_result_t<Task>;
    std::packaged_task<Return()> task_;
};
} // namespace St

class RSRenderServiceAgent : public RefBase {
public:
    explicit RSRenderServiceAgent(RSRenderService& renderService) : renderService_(renderService) {}
    ~RSRenderServiceAgent() noexcept = default;

    void PostTaskImmediate(const std::function<void()>& task);
    void PostTaskImmediateInPlace(const std::function<void()>& task);
    void PostSyncTaskImmediate(const std::function<void()>& task);
    template<typename Task, typename Return = std::invoke_result_t<Task>>
    std::future<Return> ScheduleTask(Task&& task)
    {
        auto [scheduledTask, taskFuture] = St::ScheduledTask<Task>::Create(std::move(task));
        PostTaskImmediate([t(std::move(scheduledTask))]() { t->Run(); });
        return std::move(taskFuture);
    }

    // schedules the task and waits with SCHEDULE_TASK_TIMEOUT_MS; returns false on timeout.
    // the task may still execute later on the main thread, so tasks must not capture
    // references to caller-local storage nor raw `this`/raw member pointers: everything
    // the task uses must be captured by value (smart-pointer copies extend lifetime) and
    // results must be returned by value
    template<typename Task, typename Return = std::invoke_result_t<Task>>
    std::enable_if_t<std::is_void_v<Return>, bool> ScheduleTaskAndWait(
        Task&& task, int64_t timeoutMs = SCHEDULE_TASK_TIMEOUT_MS)
    {
        auto taskFuture = ScheduleTask(std::forward<Task>(task));
        if (taskFuture.wait_for(std::chrono::milliseconds(timeoutMs)) != std::future_status::ready) {
            ReportSyncTaskTimeout(timeoutMs);
            return false;
        }
        return true;
    }

    // value-returning variant; returns std::nullopt on timeout
    template<typename Task, typename Return = std::invoke_result_t<Task>>
    std::enable_if_t<!std::is_void_v<Return>, std::optional<Return>> ScheduleTaskAndWait(
        Task&& task, int64_t timeoutMs = SCHEDULE_TASK_TIMEOUT_MS)
    {
        auto taskFuture = ScheduleTask(std::forward<Task>(task));
        if (taskFuture.wait_for(std::chrono::milliseconds(timeoutMs)) != std::future_status::ready) {
            ReportSyncTaskTimeout(timeoutMs);
            return std::nullopt;
        }
        return taskFuture.get();
    }

    sptr<IRemoteObject> GetConnectToRenderToken(ScreenId screenId);
    void RemoveToken(const sptr<RSIConnectionToken>& token);

    // Hgm
    std::shared_ptr<HgmContext> GetHgmContext() const { return renderService_.GetHgmContext(); }
    void HandlePowerStatus(ScreenId screenId, ScreenPowerStatus status);

    // Dfx
    void GetRefreshInfoToSP(std::string& dumpString, NodeId nodeId);
    void FpsDump(std::string& dumpString, const std::string& arg);
    void CollectDump(std::string& dumpString);

    // Game Scene Handler
    void HandleGameSceneChanged() const;

    std::pair<sptr<IRSRenderToComposerConnection>, sptr<VSyncConnection>> GetProcessInfo(
        ScreenId screenId, sptr<IRemoteObject> vsyncToken);

    HgmProcessCallback& GetHgmProcessCallback() { return hgmProcessCallback_; }
    void RegisterHgmProcessCallback(HgmProcessCallback hgmProcessCallback);

private:
    RSRenderService& renderService_;
    HgmProcessCallback hgmProcessCallback_ = nullptr;

    // bounded wait for tasks scheduled to the render service main thread; binder threads must
    // never block on it indefinitely, otherwise a stuck main thread drains the binder pool
    static constexpr int64_t SCHEDULE_TASK_TIMEOUT_MS = 3000; // 3s

    static void ReportSyncTaskTimeout(int64_t timeoutMs);
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_MAIN_RENDER_SERVER_RS_RENDER_SERVICE_AGENT_H