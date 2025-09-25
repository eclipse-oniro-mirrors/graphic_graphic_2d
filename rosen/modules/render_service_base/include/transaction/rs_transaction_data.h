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

#ifndef ROSEN_RENDER_SERVICE_BASE_RS_TRANSACTION_DATA_H
#define ROSEN_RENDER_SERVICE_BASE_RS_TRANSACTION_DATA_H

#include <memory>
#include <mutex>
#include <parcel.h>
#include <vector>

#include "common/rs_macros.h"
#include "pipeline/rs_context.h"

namespace OHOS {
namespace Rosen {
class RSCommand;
class RSB_EXPORT RSTransactionData : public Parcelable {
public:
    RSTransactionData() = default;
    RSTransactionData(const RSTransactionData&) = delete;
    RSTransactionData& operator=(const RSTransactionData&) = delete;
    RSTransactionData(RSTransactionData&& other);
    RSTransactionData& operator=(const RSTransactionData&&) = delete;
    ~RSTransactionData() override;

    [[nodiscard]] static RSTransactionData* Unmarshalling(Parcel& parcel);
    bool Marshalling(Parcel& parcel) const override;
    void AlarmRsNodeLog() const;

    unsigned long GetCommandCount() const
    {
        return payload_.size();
    }

    bool IsEmpty() const
    {
        return payload_.empty();
    }

    void Process(RSContext& context);
    void ProcessBySingleFrameComposer(RSContext& context);
    static void AddAlarmLog(std::function<void(uint64_t, int, int)> func);

    void Clear();

    uint64_t GetTimestamp() const
    {
        return timestamp_;
    }

    void SetTimestamp(const uint64_t timestamp)
    {
        timestamp_ = timestamp;
    }

    void ProfilerPushOffsets(Parcel& parcel, uint32_t parcelNumber);

    std::string GetAbilityName() const
    {
        return abilityName_;
    }

    void SetAbilityName(const std::string& abilityName)
    {
        abilityName_ = abilityName;
    }

    void SetIsCached(bool isCached)
    {
        isCached_ = isCached;
    }

    bool GetIsCached()
    {
        return isCached_;
    }

    void SetSendingPid(pid_t pid)
    {
        pid_ = pid;
    }

    pid_t GetSendingPid() const
    {
        return pid_;
    }

    void SetSendingTid(pid_t tid)
    {
        tid_ = tid;
    }

    pid_t GetSendingTid() const
    {
        return tid_;
    }

    void SetIndex(uint64_t index)
    {
        index_ = index;
    }

    uint64_t GetIndex() const
    {
        return index_;
    }

    size_t GetMarshallingIndex() const
    {
        return marshallingIndex_;
    }

    std::vector<std::tuple<NodeId, FollowType, std::unique_ptr<RSCommand>>>& GetPayload()
    {
        return payload_;
    }

    bool IsNeedSync() const
    {
        return needSync_;
    }

    bool IsNeedCloseSync() const
    {
        return needCloseSync_;
    }

    void MarkNeedSync()
    {
        needSync_ = true;
    }

    void MarkNeedCloseSync()
    {
        needCloseSync_ = true;
    }

    void SetSyncTransactionNum(const int32_t syncTransactionCount)
    {
        syncTransactionCount_ = syncTransactionCount;
    }

    int32_t GetSyncTransactionNum() const
    {
        return syncTransactionCount_;
    }

    void SetSyncId(const uint64_t syncId)
    {
        syncId_ = syncId;
    }

    uint64_t GetSyncId() const
    {
        return syncId_;
    }

    void SetParentPid(const int32_t parentPid)
    {
        parentPid_ = parentPid;
    }

    int32_t GetParentPid() const
    {
        return parentPid_;
    }

    bool IsCallingPidValid(pid_t callingPid, const RSRenderNodeMap& nodeMap) const;
    void DumpCommand(std::string& dumpString);

    void SetDVSyncUpdate(bool dvsyncTimeUpdate)
    {
        dvsyncTimeUpdate_ = dvsyncTimeUpdate;
    }

    bool GetDVSyncUpdate() const
    {
        return dvsyncTimeUpdate_;
    }

    void SetDVSyncTime(uint64_t dvsyncTime)
    {
        dvsyncTime_ = dvsyncTime;
    }

    uint64_t GetDVSyncTime() const
    {
        return dvsyncTime_;
    }

private:
    void AddCommand(std::unique_ptr<RSCommand>& command, NodeId nodeId, FollowType followType);
    void AddCommand(std::unique_ptr<RSCommand>&& command, NodeId nodeId, FollowType followType);
    void MoveCommandByNodeId(std::unique_ptr<RSTransactionData>& transactionData, NodeId nodeId);
    void MoveAllCommand(std::unique_ptr<RSTransactionData>& transactionData);

    bool UnmarshallingCommand(Parcel& parcel);

    std::string PrintCommandMapDesc(
        const std::unordered_map<NodeId, std::set<std::pair<uint16_t, uint16_t>>>& commandTypeMap) const;

    std::vector<std::tuple<NodeId, FollowType, std::unique_ptr<RSCommand>>> payload_ = {};
    uint64_t timestamp_ = 0;
    uint64_t token_ = 0;
    std::string abilityName_;
    pid_t pid_ = 0;
    // only use for hybrid render client, no need to marshalling
    pid_t tid_ = 0;
    uint64_t index_ = 0;
    mutable size_t marshallingIndex_ = 0;
    bool needSync_ { false };
    bool needCloseSync_ { false };
    bool isCached_ { false };
    int32_t syncTransactionCount_ { 0 };
    int32_t parentPid_ { -1 };
    uint64_t syncId_ { 0 };
    uint32_t parcelNumber_ { 0 };
    static std::function<void(uint64_t, int, int)> alarmLogFunc;
    mutable std::mutex commandMutex_;
    std::vector<uint32_t> commandOffsets_;
    bool dvsyncTimeUpdate_ = false;
    uint64_t dvsyncTime_ = 0;

    friend class RSTransactionProxy;
    friend class RSTransactionHandler;
    friend class RSMessageProcessor;
    friend class RSMainThread;
};
using TransactionDataMap = std::unordered_map<pid_t, std::vector<std::unique_ptr<RSTransactionData>>>;
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_BASE_RS_TRANSACTION_DATA_H
