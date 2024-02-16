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

namespace OHOS {
class MessageParcel;
class MessageOption;
} // namespace OHOS

namespace OHOS::Rosen {

class RSRenderService;
class RSMainThread;
class RSRenderServiceConnection;
class RSTransactionData;

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
    static bool IsRecording();
    static bool IsPlaying();

    static void ProcessCommands();
    static void ProcessRecording();

    static void AwakeRenderServiceThread();

    static void Respond(const std::string& message);
    static void DumpNodeModifiers(uint64_t id);
    static void DumpConnections();
    static void DumpNodeProperties(uint64_t id);
    static void DumpTree(const std::string& node);
    static void DumpSurfaces(uint32_t pid);
    static void DumpNodeSurface(uint64_t id);
    static void PatchNode(uint64_t id);
    static void KillNode(uint64_t id);
    static void AttachChild(uint64_t parentPid, uint64_t parentNodeId, uint64_t childPid, uint64_t childNodeId);
    static void KillPid(uint32_t pid);
    static void GetRoot();
    static void GetDeviceInfo();

    static void SaveRdc();
    static void ProcessSendingRdc();

    static void SendTelemetry(double startTime);

    static void RecordStart();
    static void RecordStop();

    static void PlaybackStart(pid_t pid, double pauseTime = 0.0);
    static void PlaybackStop();
    static void PlaybackUpdate();

    static void PlaybackPrepare(uint32_t pid);
    static void PlaybackPause();
    static void PlaybackPauseAt(double time);
    static void PlaybackPauseClear();
    static void PlaybackResume();
};

} // namespace OHOS::Rosen

#endif // RENDER_SERVICE_PROFILER_H