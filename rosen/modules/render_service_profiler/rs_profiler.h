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

#ifdef RS_PROFILER_ENABLED

#include <map>
#include <string>

#include "recording/draw_cmd_list.h"

#include "common/rs_vector4.h"
#include "params/rs_display_render_params.h"

#define RS_PROFILER_INIT(renderSevice) RSProfiler::Init(renderSevice)
#define RS_PROFILER_ON_FRAME_BEGIN() RSProfiler::OnFrameBegin()
#define RS_PROFILER_ON_FRAME_END() RSProfiler::OnFrameEnd()
#define RS_PROFILER_ON_RENDER_BEGIN() RSProfiler::OnRenderBegin()
#define RS_PROFILER_ON_RENDER_END() RSProfiler::OnRenderEnd()
#define RS_PROFILER_ON_PROCESS_COMMAND() RSProfiler::OnProcessCommand()
#define RS_PROFILER_ON_CREATE_CONNECTION(pid) RSProfiler::OnCreateConnection(pid)
#define RS_PROFILER_ON_REMOTE_REQUEST(connection, code, data, reply, option) \
    RSProfiler::OnRemoteRequest(connection, code, data, reply, option)
#define RS_PROFILER_ON_PARCEL_RECEIVE(parcel, data) RSProfiler::OnRecvParcel(parcel, data)
#define RS_PROFILER_COPY_PARCEL(parcel) RSProfiler::CopyParcel(parcel)
#define RS_PROFILER_PATCH_NODE_ID(parcel, id) id = RSProfiler::PatchNodeId(parcel, id)
#define RS_PROFILER_PATCH_TYPEFACE_GLOBALID(parcel, id) id = RSProfiler::PatchNodeId(parcel, id)
#define RS_PROFILER_PATCH_PID(parcel, pid) pid = RSProfiler::PatchPid(parcel, pid)
#define RS_PROFILER_PATCH_TIME(time) time = RSProfiler::PatchTime(time)
#define RS_PROFILER_PATCH_TRANSACTION_TIME(parcel, time) time = RSProfiler::PatchTransactionTime(parcel, time)
#define RS_PROFILER_PATCH_COMMAND(parcel, command) RSProfiler::PatchCommand(parcel, command)
#define RS_PROFILER_EXECUTE_COMMAND(command) RSProfiler::ExecuteCommand(command)
#define RS_PROFILER_MARSHAL_PIXELMAP(parcel, map) RSProfiler::MarshalPixelMap(parcel, map)
#define RS_PROFILER_UNMARSHAL_PIXELMAP(parcel) RSProfiler::UnmarshalPixelMap(parcel)
#define RS_PROFILER_SKIP_PIXELMAP(parcel) RSProfiler::SkipPixelMap(parcel)
#define RS_PROFILER_MARSHAL_DRAWINGIMAGE(image, compressData) RSProfiler::MarshalDrawingImage(image, compressData)
#define RS_PROFILER_SET_DIRTY_REGION(dirtyRegion) RSProfiler::SetDirtyRegion(dirtyRegion)
#define RS_PROFILER_WRITE_PARCEL_DATA(parcel) RSProfiler::WriteParcelData(parcel)
#define RS_PROFILER_READ_PARCEL_DATA(parcel, size, isMalloc) RSProfiler::ReadParcelData(parcel, size, isMalloc)
#define RS_PROFILER_SKIP_PARCEL_DATA(parcel, size) RSProfiler::SkipParcelData(parcel, size)
#define RS_PROFILER_GET_FRAME_NUMBER() RSProfiler::GetFrameNumber()
#define RS_PROFILER_ON_PARALLEL_RENDER_BEGIN() RSProfiler::OnParallelRenderBegin()
#define RS_PROFILER_ON_PARALLEL_RENDER_END(renderFrameNumber) RSProfiler::OnParallelRenderEnd(renderFrameNumber)
#define RS_PROFILER_SHOULD_BLOCK_HWCNODE() RSProfiler::ShouldBlockHWCNode()
#define RS_PROFILER_ANIME_SET_START_TIME(id, time) RSProfiler::AnimeSetStartTime(id, time)
#define RS_PROFILER_REPLAY_FIX_TRINDEX(curIndex, lastIndex) RSProfiler::ReplayFixTrIndex(curIndex, lastIndex)
#define RS_PROFILER_PATCH_TYPEFACE_ID(parcel, val) RSProfiler::PatchTypefaceId(parcel, val)
#define RS_PROFILER_DRAWING_NODE_ADD_CLEAROP(drawCmdList) RSProfiler::DrawingNodeAddClearOp(drawCmdList)
#else
#define RS_PROFILER_INIT(renderSevice)
#define RS_PROFILER_ON_FRAME_BEGIN()
#define RS_PROFILER_ON_FRAME_END()
#define RS_PROFILER_ON_RENDER_BEGIN()
#define RS_PROFILER_ON_RENDER_END()
#define RS_PROFILER_ON_PROCESS_COMMAND()
#define RS_PROFILER_ON_CREATE_CONNECTION(pid)
#define RS_PROFILER_ON_REMOTE_REQUEST(connection, code, data, reply, option)
#define RS_PROFILER_ON_PARCEL_RECEIVE(parcel, data)
#define RS_PROFILER_COPY_PARCEL(parcel) std::make_shared<MessageParcel>()
#define RS_PROFILER_PATCH_NODE_ID(parcel, id)
#define RS_PROFILER_PATCH_TYPEFACE_GLOBALID(parcel, id)
#define RS_PROFILER_PATCH_PID(parcel, pid)
#define RS_PROFILER_PATCH_TIME(time)
#define RS_PROFILER_PATCH_TRANSACTION_TIME(parcel, time)
#define RS_PROFILER_PATCH_COMMAND(parcel, command)
#define RS_PROFILER_EXECUTE_COMMAND(command)
#define RS_PROFILER_MARSHAL_PIXELMAP(parcel, map) (map)->Marshalling(parcel)
#define RS_PROFILER_UNMARSHAL_PIXELMAP(parcel) Media::PixelMap::Unmarshalling(parcel)
#define RS_PROFILER_SKIP_PIXELMAP(parcel) false
#define RS_PROFILER_MARSHAL_DRAWINGIMAGE(image, compressData)
#define RS_PROFILER_SET_DIRTY_REGION(dirtyRegion)
#define RS_PROFILER_WRITE_PARCEL_DATA(parcel)
#define RS_PROFILER_READ_PARCEL_DATA(parcel, size, isMalloc) RSMarshallingHelper::ReadFromAshmem(parcel, size, isMalloc)
#define RS_PROFILER_SKIP_PARCEL_DATA(parcel, size) false
#define RS_PROFILER_GET_FRAME_NUMBER() 0
#define RS_PROFILER_ON_PARALLEL_RENDER_BEGIN()
#define RS_PROFILER_ON_PARALLEL_RENDER_END(renderFrameNumber)
#define RS_PROFILER_SHOULD_BLOCK_HWCNODE() false
#define RS_PROFILER_ANIME_SET_START_TIME(id, time) time
#define RS_PROFILER_REPLAY_FIX_TRINDEX(curIndex, lastIndex)
#define RS_PROFILER_PATCH_TYPEFACE_ID(parcel, val)
#define RS_PROFILER_DRAWING_NODE_ADD_CLEAROP(drawCmdList) (drawCmdList)->ClearOp()
#endif

#ifdef RS_PROFILER_ENABLED

namespace OHOS {
class Parcel;
class MessageParcel;
class MessageOption;

} // namespace OHOS

namespace OHOS::Media {
class PixelMap;
} // namespace OHOS::Media

namespace OHOS::Rosen {

class RSRenderService;
class RSMainThread;
class RSIRenderServiceConnection;
class RSRenderServiceConnection;
class RSTransactionData;
class RSRenderNode;
class RSRenderModifier;
class RSProperties;
class RSContext;
class RSDisplayRenderNode;
class RSRenderNodeMap;
class RSAnimationManager;
class RSRenderAnimation;
class RSCommand;
class ArgList;
class JsonWriter;
class RSFile;

enum class Mode { NONE = 0, READ = 1, WRITE = 2, READ_EMUL = 3, WRITE_EMUL = 4 };

class RSProfiler final {
public:
    static void Init(RSRenderService* renderService);
    static void StartNetworkThread();

    // see RSMainThread::Init
    static void OnFrameBegin();
    static void OnFrameEnd();
    static void OnRenderBegin();
    static void OnRenderEnd();
    static void OnParallelRenderBegin();
    static void OnParallelRenderEnd(uint32_t frameNumber);
    static void OnProcessCommand();

    // see RSRenderService::CreateConnection
    static void OnCreateConnection(pid_t pid);

    // see RenderServiceConnection::OnRemoteRequest
    static void OnRemoteRequest(RSIRenderServiceConnection* connection, uint32_t code, MessageParcel& parcel,
        MessageParcel& reply, MessageOption& option);

    // see UnmarshalThread::RecvParcel
    static void OnRecvParcel(const MessageParcel* parcel, RSTransactionData* data);

    RSB_EXPORT static std::shared_ptr<MessageParcel> CopyParcel(const MessageParcel& parcel);
    RSB_EXPORT static uint64_t PatchTime(uint64_t time);
    RSB_EXPORT static uint64_t PatchTransactionTime(const Parcel& parcel, uint64_t timeAtRecordProcess);

    RSB_EXPORT static void PatchTypefaceId(const Parcel& parcel, std::shared_ptr<Drawing::DrawCmdList>& val);

    template<typename T>
    static T PatchNodeId(const Parcel& parcel, T id)
    {
        return static_cast<T>(PatchPlainNodeId(parcel, static_cast<NodeId>(id)));
    }

    template<typename T>
    static T PatchPid(const Parcel& parcel, T pid)
    {
        return static_cast<T>(PatchPlainPid(parcel, static_cast<pid_t>(pid)));
    }

    RSB_EXPORT static void PatchCommand(const Parcel& parcel, RSCommand* command);
    RSB_EXPORT static void ExecuteCommand(const RSCommand* command);
    RSB_EXPORT static bool MarshalPixelMap(Parcel& parcel, const std::shared_ptr<Media::PixelMap>& map);
    RSB_EXPORT static Media::PixelMap* UnmarshalPixelMap(Parcel& parcel);
    RSB_EXPORT static bool SkipPixelMap(Parcel& parcel);
    RSB_EXPORT static void MarshalDrawingImage(std::shared_ptr<Drawing::Image>& image,
        std::shared_ptr<Drawing::Data>& compressData);
    RSB_EXPORT static void SetDirtyRegion(const Occlusion::Region& dirtyRegion);

    RSB_EXPORT static void WriteParcelData(Parcel& parcel);
    RSB_EXPORT static const void* ReadParcelData(Parcel& parcel, size_t size, bool& isMalloc);
    RSB_EXPORT static bool SkipParcelData(Parcel& parcel, size_t size);
    RSB_EXPORT static uint32_t GetFrameNumber();
    RSB_EXPORT static bool ShouldBlockHWCNode();

    RSB_EXPORT static std::unordered_map<AnimationId, std::vector<int64_t>> &AnimeGetStartTimes();
    RSB_EXPORT static int64_t AnimeSetStartTime(AnimationId id, int64_t nanoTime);
    RSB_EXPORT static std::string SendMessageBase();
    RSB_EXPORT static void SendMessageBase(const std::string& msg);
    RSB_EXPORT static void ReplayFixTrIndex(uint64_t curIndex, uint64_t& lastIndex);

public:
    RSB_EXPORT static bool IsParcelMock(const Parcel& parcel);
    RSB_EXPORT static bool IsSharedMemoryEnabled();
    RSB_EXPORT static bool IsBetaRecordEnabled();
    RSB_EXPORT static bool IsBetaRecordEnabledWithMetrics();
    RSB_EXPORT static Mode GetMode();

    RSB_EXPORT static void DrawingNodeAddClearOp(const std::shared_ptr<Drawing::DrawCmdList>& drawCmdList);
    RSB_EXPORT static void SetDrawingCanvasNodeRedraw(bool enable);

private:
    static const char* GetProcessNameByPid(int pid);

    RSB_EXPORT static void EnableSharedMemory();
    RSB_EXPORT static void DisableSharedMemory();

    // Beta record
    RSB_EXPORT static void EnableBetaRecord();
    RSB_EXPORT static bool IsBetaRecordSavingTriggered();
    static void StartBetaRecord();
    static void StopBetaRecord();
    static bool IsBetaRecordStarted();
    static void UpdateBetaRecord();
    static void SaveBetaRecord();
    static bool IsBetaRecordInactive();
    static void RequestVSyncOnBetaRecordInactivity();
    static void LaunchBetaRecordNotificationThread();
    static void LaunchBetaRecordMetricsUpdateThread();
    static void WriteBetaRecordFileThread(RSFile& file, const std::string& path);
    static bool OpenBetaRecordFile(RSFile& file);
    static bool SaveBetaRecordFile(RSFile& file);
    static void WriteBetaRecordMetrics(RSFile& file, double time);
    static void UpdateDirtyRegionBetaRecord(double currentFrameDirtyRegion);

    RSB_EXPORT static void SetMode(Mode mode);
    RSB_EXPORT static bool IsEnabled();

    RSB_EXPORT static uint32_t GetCommandCount();
    RSB_EXPORT static uint32_t GetCommandExecuteCount();
    RSB_EXPORT static std::string GetCommandParcelList(double recordStartTime);

    RSB_EXPORT static const std::vector<pid_t>& GetPids();
    RSB_EXPORT static NodeId GetParentNode();
    RSB_EXPORT static void SetSubstitutingPid(const std::vector<pid_t>& pids, pid_t pid, NodeId parent);
    RSB_EXPORT static pid_t GetSubstitutingPid();

private:
    RSB_EXPORT static void SetTransactionTimeCorrection(double replayStartTime, double recordStartTime);
    RSB_EXPORT static void TimePauseAt(uint64_t curTime, uint64_t newPauseAfterTime);
    RSB_EXPORT static void TimePauseResume(uint64_t curTime);
    RSB_EXPORT static void TimePauseClear();
    RSB_EXPORT static uint64_t TimePauseGet();

    RSB_EXPORT static std::shared_ptr<RSDisplayRenderNode> GetDisplayNode(const RSContext& context);
    RSB_EXPORT static Vector4f GetScreenRect(const RSContext& context);

    // RSRenderNodeMap
    RSB_EXPORT static void FilterForPlayback(RSContext& context, pid_t pid);
    RSB_EXPORT static void FilterMockNode(RSContext& context);

    RSB_EXPORT static void GetSurfacesTrees(
        const RSContext& context, std::map<std::string, std::tuple<NodeId, std::string>>& list);
    RSB_EXPORT static void GetSurfacesTrees(const RSContext& context, pid_t pid, std::map<NodeId, std::string>& list);
    RSB_EXPORT static size_t GetRenderNodeCount(const RSContext& context);
    RSB_EXPORT static NodeId GetRandomSurfaceNode(const RSContext& context);

    RSB_EXPORT static void MarshalNodes(const RSContext& context, std::stringstream& data, uint32_t fileVersion);
    RSB_EXPORT static void MarshalTree(const RSRenderNode& node, std::stringstream& data, uint32_t fileVersion);
    RSB_EXPORT static void MarshalNode(const RSRenderNode& node, std::stringstream& data, uint32_t fileVersion);
    RSB_EXPORT static void MarshalNodeModifiers(
        const RSRenderNode& node, std::stringstream& data, uint32_t fileVersion);

    RSB_EXPORT static void UnmarshalNodes(RSContext& context, std::stringstream& data, uint32_t fileVersion);
    RSB_EXPORT static void UnmarshalTree(RSContext& context, std::stringstream& data, uint32_t fileVersion);
    RSB_EXPORT static void UnmarshalNode(RSContext& context, std::stringstream& data, uint32_t fileVersion);
    RSB_EXPORT static void UnmarshalNode(
        RSContext& context, std::stringstream& data, NodeId nodeId, uint32_t fileVersion);
    RSB_EXPORT static void UnmarshalNodeModifiers(RSRenderNode& node, std::stringstream& data, uint32_t fileVersion);

    RSB_EXPORT static NodeId AdjustNodeId(NodeId nodeId, bool clearMockFlag);

    // RSRenderNode
    RSB_EXPORT static std::string DumpRenderProperties(const RSRenderNode& node);
    RSB_EXPORT static std::string DumpModifiers(const RSRenderNode& node);
    RSB_EXPORT static std::string DumpSurfaceNode(const RSRenderNode& node);

    // JSON
    static void RenderServiceTreeDump(JsonWriter& out, pid_t pid);
    RSB_EXPORT static void DumpNode(const RSRenderNode& node, JsonWriter& out,
        bool clearMockFlag = false, bool absRoot = false);
    RSB_EXPORT static void DumpNodeAbsoluteProperties(const RSRenderNode& node, JsonWriter& out);
    RSB_EXPORT static void DumpNodeAnimations(const RSAnimationManager& animationManager, JsonWriter& out);
    RSB_EXPORT static void DumpNodeAnimation(const RSRenderAnimation& animation, JsonWriter& out);
    RSB_EXPORT static void DumpNodeBaseInfo(const RSRenderNode& node, JsonWriter& out, bool clearMockFlag);
    RSB_EXPORT static void DumpNodeSubsurfaces(const RSRenderNode& node, JsonWriter& out);
    RSB_EXPORT static void DumpNodeSubClassNode(const RSRenderNode& node, JsonWriter& out);
    RSB_EXPORT static void DumpNodeOptionalFlags(const RSRenderNode& node, JsonWriter& out);
    RSB_EXPORT static void DumpNodeDrawCmdModifiers(const RSRenderNode& node, JsonWriter& out);
    RSB_EXPORT static void DumpNodeDrawCmdModifier(
        const RSRenderNode& node, JsonWriter& out, int type, RSRenderModifier& modifier);
    RSB_EXPORT static void DumpNodeProperties(const RSProperties& properties, JsonWriter& out);
    RSB_EXPORT static void DumpNodePropertiesClip(const RSProperties& properties, JsonWriter& out);
    RSB_EXPORT static void DumpNodePropertiesTransform(const RSProperties& properties, JsonWriter& out);
    RSB_EXPORT static void DumpNodePropertiesNonSpatial(const RSProperties& properties, JsonWriter& out);
    RSB_EXPORT static void DumpNodePropertiesDecoration(const RSProperties& properties, JsonWriter& out);
    RSB_EXPORT static void DumpNodePropertiesEffects(const RSProperties& properties, JsonWriter& out);
    RSB_EXPORT static void DumpNodePropertiesShadow(const RSProperties& properties, JsonWriter& out);
    RSB_EXPORT static void DumpNodePropertiesColor(const RSProperties& properties, JsonWriter& out);
    RSB_EXPORT static void DumpNodeChildrenListUpdate(const RSRenderNode& node, JsonWriter& out);

    // RSAnimationManager
    RSB_EXPORT static void FilterAnimationForPlayback(RSAnimationManager& manager);

    RSB_EXPORT static NodeId PatchPlainNodeId(const Parcel& parcel, NodeId id);
    RSB_EXPORT static pid_t PatchPlainPid(const Parcel& parcel, pid_t pid);

    RSB_EXPORT static uint32_t PerfTreeFlatten(
        std::shared_ptr<RSRenderNode> node, std::vector<std::pair<NodeId, uint32_t>>& nodeSet,
        std::unordered_map<NodeId, uint32_t>& mapNode2Count, int depth);
    RSB_EXPORT static uint32_t CalcNodeCmdListCount(RSRenderNode& node);
    RSB_EXPORT static void CalcPerfNodePrepare(NodeId nodeId, uint32_t timeCount, bool excludeDown);
    RSB_EXPORT static void CalcPerfNodePrepareLo(const std::shared_ptr<RSRenderNode>& node, bool forceExcludeNode);
    static void PrintNodeCacheLo(const std::shared_ptr<RSRenderNode>& node);

    static uint64_t RawNowNano();
    static uint64_t NowNano();
    static double Now();

    static bool IsRecording();
    static bool IsPlaying();

    static bool IsLoadSaveFirstScreenInProgress();
    static std::string FirstFrameMarshalling(uint32_t fileVersion);
    static void FirstFrameUnmarshalling(const std::string& data, uint32_t fileVersion);
    static void HiddenSpaceTurnOff();
    static void HiddenSpaceTurnOn();

    static void ScheduleTask(std::function<void()> && task);
    static void RequestNextVSync();
    static void AwakeRenderServiceThread();
    static void ResetAnimationStamp();

    static void CreateMockConnection(pid_t pid);
    static RSRenderServiceConnection* GetConnection(pid_t pid);
    static pid_t GetConnectionPid(RSIRenderServiceConnection* connection);
    static std::vector<pid_t> GetConnectionsPids();

    static std::shared_ptr<RSRenderNode> GetRenderNode(uint64_t id);
    static void ProcessSendingRdc();

    static void BlinkNodeUpdate();
    static void CalcPerfNodeUpdate();
    static void CalcPerfNodeAllStep();
    static void CalcNodeWeigthOnFrameEnd(uint64_t frameLength);

    RSB_EXPORT static uint32_t GetNodeDepth(const std::shared_ptr<RSRenderNode> node);

    static void TypefaceMarshalling(std::stringstream& stream, uint32_t fileVersion);
    static void TypefaceUnmarshalling(std::stringstream& stream, uint32_t fileVersion);

    // Network interface
    static void Invoke(const std::vector<std::string>& line);
    static void ProcessPauseMessage();
    static void ProcessCommands();
    static void Respond(const std::string& message);
    static void SetSystemParameter(const ArgList& args);
    static void GetSystemParameter(const ArgList& args);
    static void Reset(const ArgList& args);
    static void DumpSystemParameters(const ArgList& args);
    static void DumpNodeModifiers(const ArgList& args);
    static void DumpConnections(const ArgList& args);
    static void DumpNodeProperties(const ArgList& args);
    static void DumpTree(const ArgList& args);
    static void DumpTreeToJson(const ArgList& args);
    static void DumpSurfaces(const ArgList& args);
    static void DumpNodeSurface(const ArgList& args);
    static void ClearFilter(const ArgList& args);
    static void PrintNodeCache(const ArgList& args);
    static void PrintNodeCacheAll(const ArgList& args);
    static void PatchNode(const ArgList& args);
    static void KillNode(const ArgList& args);
    static void BlinkNode(const ArgList& args);
    static void AttachChild(const ArgList& args);
    static void KillPid(const ArgList& args);
    static void GetRoot(const ArgList& args);
    static void GetDeviceInfo(const ArgList& args);
    static void GetDeviceFrequency(const ArgList& args);
    static void FixDeviceEnv(const ArgList& args);
    static void GetPerfTree(const ArgList& args);
    static void CalcPerfNode(const ArgList& args);
    static void CalcPerfNodeAll(const ArgList& args);
    static void SocketShutdown(const ArgList& args);
    static void DumpDrawingCanvasNodes(const ArgList& args);

    static void Version(const ArgList& args);
    static void FileVersion(const ArgList& args);

    static void SaveSkp(const ArgList& args);
    static void SaveRdc(const ArgList& args);
    static void DrawingCanvasRedrawEnable(const ArgList& args);

    static void RecordStart(const ArgList& args);
    static void RecordStop(const ArgList& args);
    static void RecordUpdate();

    static void PlaybackStart(const ArgList& args);
    static void PlaybackStop(const ArgList& args);
    static double PlaybackUpdate(double deltaTime);

    static void RecordSendBinary(const ArgList& args);

    static void PlaybackPrepare(const ArgList& args);
    static void PlaybackPrepareFirstFrame(const ArgList& args);
    static void PlaybackPause(const ArgList& args);
    static void PlaybackPauseAt(const ArgList& args);
    static void PlaybackPauseClear(const ArgList& args);
    static void PlaybackResume(const ArgList& args);

    static void TestSaveFrame(const ArgList& args);
    static void TestLoadFrame(const ArgList& args);
    static void TestSwitch(const ArgList& args);

    static void OnFlagChangedCallback(const char *key, const char *value, void *context);
    static void OnWorkModeChanged();
    static void ProcessSignalFlag();

private:
    using CommandRegistry = std::map<std::string, void (*)(const ArgList&)>;
    static const CommandRegistry COMMANDS;
    // set to true in DT only
    RSB_EXPORT static bool testing_;

    // flag for enabling profiler
    RSB_EXPORT static bool enabled_;
    // flag for enabling profiler beta recording feature
    RSB_EXPORT static bool betaRecordingEnabled_;
    // flag to start network thread
    RSB_EXPORT static int8_t signalFlagChanged_;

    inline static const char SYS_KEY_ENABLED[] = "persist.graphic.profiler.enabled";
    inline static const char SYS_KEY_BETARECORDING[] = "persist.graphic.profiler.betarecording";
    // flag for enabling DRAWING_CANVAS_NODE redrawing
    RSB_EXPORT static std::atomic_bool dcnRedraw_;
};

} // namespace OHOS::Rosen

#endif // RS_PROFILER_ENABLED

#endif // RENDER_SERVICE_PROFILER_H