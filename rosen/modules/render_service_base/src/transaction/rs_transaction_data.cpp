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

#include "transaction/rs_transaction_data.h"

#include "command/rs_canvas_node_command.h"
#include "command/rs_command.h"
#include "command/rs_command_factory.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#include "rs_profiler.h"

namespace OHOS {
namespace Rosen {
namespace {
static constexpr size_t PARCEL_MAX_CPACITY = 4000 * 1024; // upper bound of parcel capacity
static constexpr size_t PARCEL_SPLIT_THRESHOLD = 1800 * 1024; // should be < PARCEL_MAX_CPACITY
}

std::function<void(uint64_t, int, int)> RSTransactionData::alarmLogFunc = [](uint64_t nodeId, int count, int num) {
    ROSEN_LOGW("rsNode:%{public}" PRId64 " send %{public}d commands, "
                "total num of rsNode is %{public}d", nodeId, count, num);
};

RSTransactionData* RSTransactionData::Unmarshalling(Parcel& parcel)
{
    auto transactionData = new RSTransactionData();
    if (transactionData->UnmarshallingCommand(parcel)) {
        return transactionData;
    }
    ROSEN_LOGE("RSTransactionData Unmarshalling Failed");
    delete transactionData;
    return nullptr;
}

void RSTransactionData::AddAlarmLog(std::function<void(uint64_t, int, int)> func)
{
    alarmLogFunc = func;
}

RSTransactionData::~RSTransactionData()
{
    Clear();
}

void RSTransactionData::AlarmRsNodeLog() const
{
    std::unordered_map<NodeId, int> commandNodeIdCount;
    for (size_t countIndex = 0; countIndex < payload_.size();countIndex++) {
        auto nodeId = std::get<0>(payload_[countIndex]);

        if (commandNodeIdCount.count(nodeId)) {
            commandNodeIdCount[nodeId] += 1;
        } else {
            commandNodeIdCount[nodeId] = 1;
        }
    }

    int maxCount = 0;
    NodeId maxNodeId = -1;
    int rsNodeNum = 0;

    for (auto it = commandNodeIdCount.begin(); it != commandNodeIdCount.end(); ++it) {
        if (it->second > maxCount) {
            maxNodeId = it->first;
            maxCount = it->second;
        }
        rsNodeNum++;
    }
        
    RSTransactionData::alarmLogFunc(maxNodeId, maxCount, rsNodeNum);
}

bool RSTransactionData::Marshalling(Parcel& parcel) const
{
    parcel.SetMaxCapacity(PARCEL_MAX_CPACITY);
    // to correct actual marshaled command size later, record its position in parcel
    size_t recordPosition = parcel.GetWritePosition();
    std::unique_lock<std::mutex> lock(commandMutex_);
    bool success = parcel.WriteInt32(static_cast<int32_t>(payload_.size()));
    size_t marshaledSize = 0;
    static bool isUniRender = RSSystemProperties::GetUniRenderEnabled();
    success = success && parcel.WriteBool(isUniRender);
    while (marshallingIndex_ < payload_.size()) {
        auto& [nodeId, followType, command] = payload_[marshallingIndex_];
        
        if (!isUniRender) {
            success = success && parcel.WriteUint64(nodeId);
            success = success && parcel.WriteUint8(static_cast<uint8_t>(followType));
        }
        if (!command) {
            parcel.WriteUint8(0);
            RS_LOGW("failed RSTransactionData::Marshalling, command is nullptr");
        } else if (command->indexVerifier_ != marshallingIndex_) {
            parcel.WriteUint8(0);
            RS_LOGW("failed RSTransactionData::Marshalling, indexVerifier is wrong, SIGSEGV may have occurred");
        } else {
            parcel.WriteUint8(1);
            success = success && command->Marshalling(parcel);
        }
        if (!success) {
            ROSEN_LOGE("failed RSTransactionData::Marshalling type:%{public}s", command->PrintType().c_str());
            return false;
        }
        ++marshallingIndex_;
        ++marshaledSize;
        if ((RSSystemProperties::GetUnmarshParallelFlag() &&
            parcel.GetDataSize() > RSSystemProperties::GetUnMarshParallelSize()) ||
            parcel.GetDataSize() > PARCEL_SPLIT_THRESHOLD) {
            break;
        }
    }
    if (marshaledSize < payload_.size()) {
        // correct command size recorded in Parcel
        *reinterpret_cast<int32_t*>(parcel.GetData() + recordPosition) = static_cast<int32_t>(marshaledSize);
        ROSEN_LOGW("RSTransactionData::Marshalling data split to several parcels"
                   ", marshaledSize:%{public}zu, marshallingIndex_:%{public}zu, total count:%{public}zu"
                   ", parcel size:%{public}zu, threshold:%{public}zu.",
            marshaledSize, marshallingIndex_, payload_.size(), parcel.GetDataSize(), PARCEL_SPLIT_THRESHOLD);

        AlarmRsNodeLog();
    }
    success = success && parcel.WriteBool(needSync_);
    success = success && parcel.WriteBool(needCloseSync_);
    success = success && parcel.WriteInt32(syncTransactionCount_);
    success = success && parcel.WriteUint64(timestamp_);
    success = success && parcel.WriteInt32(pid_);
    success = success && parcel.WriteUint64(index_);
    success = success && parcel.WriteUint64(syncId_);
    success = success && parcel.WriteInt32(parentPid_);
    return success;
}

void RSTransactionData::ProcessBySingleFrameComposer(RSContext& context)
{
    std::unique_lock<std::mutex> lock(commandMutex_);
    for (auto& [nodeId, followType, command] : payload_) {
        if (command != nullptr &&
            command->GetType() == RSCommandType::CANVAS_NODE &&
            command->GetSubType() == RSCanvasNodeCommandType::CANVAS_NODE_UPDATE_RECORDING) {
            command->Process(context);
        }
    }
}

void RSTransactionData::Process(RSContext& context)
{
    std::unique_lock<std::mutex> lock(commandMutex_);
    for (auto& [nodeId, followType, command] : payload_) {
        if (command != nullptr) {
            if (!command->IsCallingPidValid()) {
                continue;
            }
            command->Process(context);
        }
    }
}

void RSTransactionData::Clear()
{
    std::unique_lock<std::mutex> lock(commandMutex_);
    payload_.clear();
    payload_.shrink_to_fit();
    timestamp_ = 0;
}

void RSTransactionData::AddCommand(std::unique_ptr<RSCommand>& command, NodeId nodeId, FollowType followType)
{
    std::unique_lock<std::mutex> lock(commandMutex_);
    if (command) {
        command->indexVerifier_ = payload_.size();
        payload_.emplace_back(nodeId, followType, std::move(command));
    }
}

void RSTransactionData::AddCommand(std::unique_ptr<RSCommand>&& command, NodeId nodeId, FollowType followType)
{
    std::unique_lock<std::mutex> lock(commandMutex_);
    if (command) {
        command->indexVerifier_ = payload_.size();
        payload_.emplace_back(nodeId, followType, std::move(command));
    }
}

bool RSTransactionData::UnmarshallingCommand(Parcel& parcel)
{
    Clear();

    int commandSize = 0;
    if (!parcel.ReadInt32(commandSize)) {
        ROSEN_LOGE("RSTransactionData::UnmarshallingCommand cannot read commandSize");
        return false;
    }
    uint8_t followType = 0;
    NodeId nodeId = 0;
    uint8_t hasCommand = 0;
    uint16_t commandType = 0;
    uint16_t commandSubType = 0;

    size_t readableSize = parcel.GetReadableBytes();
    size_t len = static_cast<size_t>(commandSize);
    if (len > readableSize || len > payload_.max_size()) {
        ROSEN_LOGE("RSTransactionData UnmarshallingCommand Failed read vector, size:%{public}zu,"
            " readAbleSize:%{public}zu", len, readableSize);
        return false;
    }

    bool isUniRender = false;
    if (!parcel.ReadBool(isUniRender)) {
        ROSEN_LOGE("RSTransactionData::UnmarshallingCommand cannot read isUniRender");
        return false;
    }
    ClearCommandMap();
    std::unique_lock<std::mutex> payloadLock(commandMutex_, std::defer_lock);
    for (size_t i = 0; i < len; i++) {
        if (!isUniRender) {
            if (!parcel.ReadUint64(nodeId)) {
                ROSEN_LOGE("RSTransactionData::UnmarshallingCommand cannot read nodeId");
                return false;
            }
            if (!parcel.ReadUint8(followType)) {
                ROSEN_LOGE("RSTransactionData::UnmarshallingCommand cannot read followType");
                return false;
            }
        }
        if (!parcel.ReadUint8(hasCommand)) {
            ROSEN_LOGE("RSTransactionData::UnmarshallingCommand cannot read hasCommand");
            return false;
        }
        if (hasCommand) {
            if (!(parcel.ReadUint16(commandType) && parcel.ReadUint16(commandSubType))) {
                return false;
            }
            auto func = RSCommandFactory::Instance().GetUnmarshallingFunc(commandType, commandSubType);
            if (func == nullptr) {
                return false;
            }
            auto command = (*func)(parcel);
            if (command == nullptr) {
                ROSEN_LOGE("failed RSTransactionData::UnmarshallingCommand, type=%{public}d subtype=%{public}d",
                    commandType, commandSubType);
                return false;
            }
            InsertCommandToMap(command->GetNodeId(), command->GetUniqueType());
            RS_PROFILER_PATCH_COMMAND(parcel, command);
            payloadLock.lock();
            payload_.emplace_back(nodeId, static_cast<FollowType>(followType), std::move(command));
            payloadLock.unlock();
        } else {
            continue;
        }
    }
    int32_t pid;
    return parcel.ReadBool(needSync_) && parcel.ReadBool(needCloseSync_) && parcel.ReadInt32(syncTransactionCount_) &&
        parcel.ReadUint64(timestamp_) && ({RS_PROFILER_PATCH_TRANSACTION_TIME(parcel, timestamp_); true;}) &&
        parcel.ReadInt32(pid) && ({RS_PROFILER_PATCH_PID(parcel, pid); pid_ = pid; true;}) &&
        parcel.ReadUint64(index_) && parcel.ReadUint64(syncId_) && parcel.ReadInt32(parentPid_);
}

void RSTransactionData::ClearCommandMap()
{
    std::lock_guard<std::mutex> lock(pidToCommandMapMutex_);
    pidToCommandMap_.clear();
}

void RSTransactionData::InsertCommandToMap(NodeId nodeId, std::pair<uint16_t, uint16_t> commandType)
{
    pid_t commandPid = ExtractPid(nodeId);
    std::lock_guard<std::mutex> lock(pidToCommandMapMutex_);
    pidToCommandMap_[commandPid][nodeId].insert(commandType);
}

bool RSTransactionData::IsCallingPidValid(pid_t callingPid, const RSRenderNodeMap& nodeMap, pid_t& conflictCommandPid,
    std::string& commandMapDesc) const
{
    // Since GetCallingPid interface always returns 0 in asynchronous binder in Linux kernel system,
    // we temporarily add a white list to avoid abnormal functionality or abnormal display.
    // The white list will be removed after GetCallingPid interface can return real PID.
    if (callingPid == 0) {
        return true;
    }

    bool isCallingPidValid = true;
    std::unordered_set<NodeId> invalidNodeIdSet;
    {
        std::lock_guard<std::mutex> lock(pidToCommandMapMutex_);
        for (const auto& [commandPid, commandTypeMap] : pidToCommandMap_) {
            if (callingPid == commandPid) {
                continue;
            }
            for (const auto& [nodeId, _] : commandTypeMap) {
                if (nodeMap.IsUIExtensionSurfaceNode(nodeId)) {
                    continue;
                }
                if (isCallingPidValid) {
                    conflictCommandPid = commandPid;
                    commandMapDesc = PrintCommandMapDesc(commandTypeMap);
                }
                invalidNodeIdSet.insert(nodeId);
                isCallingPidValid = false;
            }
        }
    }
    std::unique_lock<std::mutex> lock(commandMutex_);
    for (auto& [nodeId, _, command] : payload_) {
        if (invalidNodeIdSet.find(nodeId) != invalidNodeIdSet.end()) {
            command->SetCallingPidValid(false);
        }
    }
    return isCallingPidValid;
}

std::string RSTransactionData::PrintCommandMapDesc(
    const std::unordered_map<NodeId, std::set<std::pair<uint16_t, uint16_t>>>& commandTypeMap) const
{
    std::string commandMapDesc = "{ ";
    for (const auto& [nodeId, commandTypeSet] : commandTypeMap) {
        std::string commandSetDesc = std::to_string(nodeId) + ": [";
        for (const auto& [commandType, commandSubType] : commandTypeSet) {
            std::string commandDesc = "(" + std::to_string(commandType) + "," + std::to_string(commandSubType) + "),";
            commandSetDesc += commandDesc;
        }
        commandSetDesc += "], ";
        commandMapDesc += commandSetDesc;
    }
    commandMapDesc += "}";
    return commandMapDesc;
}

} // namespace Rosen
} // namespace OHOS
