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

#ifndef RENDER_SERVICE_MAIN_RENDER_SERVER_RS_RENDER_MULTI_PROCESS_MANAGER_H
#define RENDER_SERVICE_MAIN_RENDER_SERVER_RS_RENDER_MULTI_PROCESS_MANAGER_H

#include <chrono>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <refbase.h>
#include <unordered_map>
#include <unordered_set>

#include "platform/ohos/transaction/zidl/rs_iconnect_to_render_process.h"
#include "rs_render_mode_config.h"
#include "rs_render_process_manager.h"

namespace OHOS {
namespace Rosen {
class ProcessToken {
public:
    ProcessToken(pid_t pid, uint64_t timeStamp) : pid_(pid), timestamp_(timeStamp) {}
    bool operator==(const ProcessToken& other) const
    {
        return GetPid() == other.GetPid() && GetTimestamp() == other.GetTimestamp();
    }
    struct Hash {
        size_t operator()(const ProcessToken& token) const
        {
            return std::hash<pid_t>()(token.GetPid()) ^ (std::hash<uint64_t>()(token.GetTimestamp()) << 1);
        }
    };
    pid_t GetPid() const { return pid_; }
    uint64_t GetTimestamp() const { return timestamp_; }

private:
    pid_t pid_ = -1;
    uint64_t timestamp_ = 0;
};

class RSRenderComposerManager;
class RSRenderComposerAgent;
class RSMultiRenderProcessManager : public RSRenderProcessManager {
public:
    explicit RSMultiRenderProcessManager(RSRenderService& renderService);
    ~RSMultiRenderProcessManager() noexcept override = default;

    sptr<IRemoteObject> OnScreenConnected(
        ScreenId screenId, const std::shared_ptr<HdiOutput>& output, const sptr<RSScreenProperty>& property) override;
    void OnScreenDisconnected(ScreenId screenId) override;
    void OnScreenPropertyChanged(
        ScreenId screenId, ScreenPropertyType type, const sptr<ScreenPropertyBase>& property) override;
    void OnScreenRefresh(ScreenId screenId) override;
    void OnVirtualScreenConnected(
        ScreenId screenId, ScreenId associatedScreenId, const sptr<RSScreenProperty>& property) override;
    void OnVirtualScreenDisconnected(ScreenId screenId) override;

    void RecordComposerToRenderConnection(pid_t pid, sptr<IRSComposerToRenderConnection> composerToRenderConnection);
    sptr<RSScreenProperty> GetPendingScreenProperty(pid_t pid);
    bool SetRenderProcessReadyPromise(pid_t pid, const sptr<RSIServiceToRenderConnection>& serviceToRenderConnection,
        const sptr<RSIConnectToRenderProcess>& connectToRenderConnection);

    sptr<RSIServiceToRenderConnection> GetServiceToRenderConn(ScreenId screenId) const override;
    std::vector<sptr<RSIServiceToRenderConnection>> GetServiceToRenderConns() const override;
    sptr<RSIConnectToRenderProcess> GetConnectToRenderConnection(ScreenId screenId) const override;

    std::shared_ptr<RSIpcPersistenceManager> GetIpcPersistenceManager() const override;

    bool IsValidRenderProcessPid(pid_t pid) const override;

private:

    sptr<IRemoteObject> HandleExistingGroup(ProcessToken token, ScreenId screenId,
        const std::shared_ptr<HdiOutput>& output, const sptr<RSScreenProperty>& property);
    sptr<IRemoteObject> HandleNewGroup(GroupId groupId, ScreenId screenId,
        const std::shared_ptr<HdiOutput>& output, const sptr<RSScreenProperty>& property);
    GroupId GetGroupIdByScreenId(ScreenId screenId) const;
    std::optional<GroupId> CheckGroupIdByScreenId(ScreenId screenId) const;

    std::optional<ProcessToken> GetRenderProcessTokenByGroupId(GroupId groupId) const;
    std::optional<ProcessToken> GetRenderProcessTokenByGroupIdLocked(GroupId groupId) const;
    void UpdateGroupIdToRenderProcessToken(GroupId groupId, ProcessToken token);
    void UpdateGroupIdToRenderProcessTokenLocked(GroupId groupId, ProcessToken token);
    void RemoveGroupIdByRenderProcessToken(ProcessToken token);
    void RemoveGroupIdByRenderProcessTokenLocked(ProcessToken token);

    std::optional<ProcessToken> GetValidRenderProcessTokenByPid(pid_t pid) const;
    std::optional<ProcessToken> GetValidRenderProcessTokenByPidLocked(pid_t pid) const;

    // GetServiceToRenderConnByToken is with lock and returns nullptr when no connection is found for the given token
    sptr<RSIServiceToRenderConnection> GetServiceToRenderConnByToken(ProcessToken token) const;
    // GotServiceToRenderConnByToken is with lock and throws std::out_of_range when no connection is found
    sptr<RSIServiceToRenderConnection> GotServiceToRenderConnByToken(ProcessToken token) const;
    // GetServiceToRenderConnByTokenLocked is without lock and returns nullptr when no connection is found
    sptr<RSIServiceToRenderConnection> GetServiceToRenderConnByTokenLocked(ProcessToken token) const;

    sptr<RSIConnectToRenderProcess> GetConnectToRenderConnByToken(ProcessToken token) const;
    sptr<RSIConnectToRenderProcess> GotConnectToRenderConnByToken(ProcessToken token) const;
    sptr<RSIConnectToRenderProcess> GetConnectToRenderConnByTokenLocked(ProcessToken token) const;

    sptr<IRSComposerToRenderConnection> GotComposerToRenderConnByToken(ProcessToken token) const;
    sptr<IRSComposerToRenderConnection> GetComposerToRenderConnByToken(ProcessToken token) const;
    sptr<IRSComposerToRenderConnection> GetComposerToRenderConnByTokenLocked(ProcessToken token) const;

    ScreenId InsertVirtualToPhysicalScreenMap(ScreenId screenId, ScreenId associatedScreenId);
    std::optional<ScreenId> DeleteVirtualToPhysicalScreenMap(ScreenId id);
    ScreenId FindVirtualToPhysicalScreenMap(ScreenId screenId);

    class RenderProcessDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit RenderProcessDeathRecipient(ProcessToken token, wptr<RSMultiRenderProcessManager> manager)
            : token_(token), manager_(manager) {}
        ~RenderProcessDeathRecipient() noexcept override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& token) override;

    private:
        ProcessToken token_;
        wptr<RSMultiRenderProcessManager> manager_;
    };

    void RegisterDeathRecipient(ProcessToken token, const sptr<IRemoteObject>& binderObject);
    void RegisterDeathRecipientLocked(ProcessToken token, const sptr<IRemoteObject>& binderObject);
    void UnregisterDeathRecipient(ProcessToken token);
    void UnregisterDeathRecipientLocked(ProcessToken token);
    void HandleRenderProcessDeath(ProcessToken token);
    std::unordered_map<ProcessToken, sptr<RenderProcessDeathRecipient>, ProcessToken::Hash> deathRecipients_;

    void AddValidRenderProcessToken(ProcessToken token);
    void AddValidRenderProcessTokenLocked(ProcessToken token);
    void RemoveValidRenderProcessToken(ProcessToken token);
    void RemoveValidRenderProcessTokenLocked(ProcessToken token);
    bool IsValidRenderProcessTokenLocked(ProcessToken token) const;

    void AddScreenOutputToProcess(ProcessToken token, ScreenId screenId, const std::shared_ptr<HdiOutput>& output);
    void AddScreenOutputToProcessLocked(ProcessToken token, ScreenId screenId,
        const std::shared_ptr<HdiOutput>& output);
    void RemoveScreenOutputFromProcess(ProcessToken token, ScreenId screenId);

    mutable std::mutex mutex_;
    mutable std::condition_variable validPidCv_;
    std::unordered_set<ProcessToken, ProcessToken::Hash> validRenderProcessTokens_;
    std::unordered_map<GroupId, ProcessToken> groupIdToRenderProcessToken_;
    std::unordered_map<ProcessToken, std::promise<bool>, ProcessToken::Hash> renderProcessReadyPromises_;
    std::unordered_map<ProcessToken, sptr<IRSComposerToRenderConnection>, ProcessToken::Hash>
        composerToRenderConnections_;
    std::unordered_map<ProcessToken, sptr<RSIServiceToRenderConnection>, ProcessToken::Hash>
        serviceToRenderConnections_;
    std::unordered_map<ProcessToken, sptr<RSIConnectToRenderProcess>, ProcessToken::Hash> connectToRenderConnections_;
    std::unordered_map<ProcessToken, std::vector<std::pair<ScreenId, std::shared_ptr<HdiOutput>>>, ProcessToken::Hash>
        processToScreenOutputMap_;
    std::function<void(std::vector<std::pair<ScreenId, std::shared_ptr<HdiOutput>>>&)> renderProcessDeathCallback_;

    mutable std::mutex virtualScreenMutex_;
    std::map<ScreenId, ScreenId> virtualToPhysicalScreenMap_;

    struct PendingScreenConnectInfo {
        ScreenId screenId = INVALID_SCREEN_ID;
        sptr<RSScreenProperty> property = nullptr;
    };
    std::unordered_map<ProcessToken, PendingScreenConnectInfo, ProcessToken::Hash> pendingScreenConnectInfos_;

    const std::shared_ptr<RSIpcPersistenceManager> ipcPersistenceManager_;

    std::deque<std::chrono::steady_clock::time_point> subprocessDeathTimes_;
    std::mutex subprocessDeathTimesMutex_;
    void CheckAndHandleSubprocessDeathOverflow();
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_MAIN_RENDER_SERVER_RS_RENDER_MULTI_PROCESS_MANAGER_H
