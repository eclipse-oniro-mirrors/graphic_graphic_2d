/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_PROFILER_H
#define RENDER_SERVICE_PROFILER_H

#include <string>

#include "common/rs_common_def.h"
#include "pipeline/rs_render_node.h"

namespace OHOS {
class MessageParcel;
class MessageOption;

} // namespace OHOS

namespace OHOS::Rosen {

class RSRenderService;
class RSMainThread;
class RSRenderServiceConnection;
class RSTransactionData;
class RSRenderNode;
class ArgList;

class RSProfiler {
public:
    static void Init(RSRenderService* renderService);
    static bool IsEnabled();

    static void MainThreadOnFrameBegin();
    static void MainThreadOnFrameEnd();
    static void MainThreadOnRenderBegin();
    static void MainThreadOnRenderEnd();
    static void MainThreadOnProcessCommand();

    static void RenderServiceOnCreateConnection(pid_t remotePid);
    static void RenderServiceConnectionOnRemoteRequest(RSRenderServiceConnection* connection, uint32_t code,
        MessageParcel& data, MessageParcel& reply, MessageOption& option);

    static void UnmarshalThreadOnRecvParcel(const MessageParcel* parcel, RSTransactionData* data);

    static const char* GetProcessNameByPID(int pid);

    static uint64_t TimePauseApply(uint64_t time);

private:
    using Command = void (*)(const ArgList&);
    static constexpr int gfxMetricsSendInterval = 8;

    static bool IsRecording();
    static bool IsPlaying();

    static void AwakeRenderServiceThread();
    static std::shared_ptr<RSRenderNode> GetRenderNode(uint64_t id);
    static void SendTelemetry(double startTime);
    static void ProcessSendingRdc();

    static Command GetCommand(const std::string& command);
    static void ProcessCommands();
    static void Respond(const std::string& message);
    static void DumpNodeModifiers(const ArgList& args);
    static void DumpConnections(const ArgList& args);
    static void DumpNodeProperties(const ArgList& args);
    static void DumpTree(const ArgList& args);
    static void DumpSurfaces(const ArgList& args);
    static void DumpNodeSurface(const ArgList& args);
    static void PatchNode(const ArgList& args);
    static void KillNode(const ArgList& args);
    static void AttachChild(const ArgList& args);
    static void KillPid(const ArgList& args);
    static void GetRoot(const ArgList& args);
    static void GetDeviceInfo(const ArgList& args);

    static void SaveRdc(const ArgList& args);

    static void RecordStart(const ArgList& args);
    static void RecordStop(const ArgList& args);
    static void RecordUpdate();

    static void PlaybackStart(const ArgList& args);
    static void PlaybackStop(const ArgList& args);
    static void PlaybackUpdate();

    static void PlaybackPrepare(const ArgList& args);
    static void PlaybackPause(const ArgList& args);
    static void PlaybackPauseAt(const ArgList& args);
    static void PlaybackPauseClear(const ArgList& args);
    static void PlaybackResume(const ArgList& args);

    static constexpr uint32_t shift32 = 32;
public:
    inline static constexpr pid_t ExtractPid(NodeId id)
    {
        // extract high 32 bits of nodeid/animationId/propertyId as pid
        return static_cast<pid_t>(id >> shift32);
    }

    inline static constexpr pid_t GetMockPid(pid_t pid)
    {
        constexpr uint32_t shift30 = 30;
        return (1 << shift30) | pid;
    }

    inline static constexpr NodeId ExtractNodeLocalID(NodeId id)
    {
        constexpr uint32_t maskU32 = 0xFFffFFff;
        return (id & maskU32);
    }

    inline static constexpr NodeId ComposeNodeID( uint64_t pid, uint64_t nodeLocalID)
    {
        return (static_cast<NodeId>(pid) << shift32) | nodeLocalID;
    }

    inline static constexpr NodeId ComposeMockNodeID(uint64_t id, uint64_t nodeLocalID)
    {
        return ComposeNodeID(GetMockPid(id), nodeLocalID);
    }

    inline static constexpr NodeId GetRootNodeId(NodeId id)
    {
        return ((static_cast<NodeId>(id) << shift32) | 1);
    }
};

} // namespace OHOS::Rosen

#endif // RENDER_SERVICE_PROFILER_H