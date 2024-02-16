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

#include "rs_profiler.h"

#include <filesystem>

#include "foundation/graphic/graphic_2d/utils/log/rs_trace.h"
#include "rs_profiler_base.h"
#include "rs_profiler_capturedata.h"
#include "rs_profiler_file.h"
#include "rs_profiler_network.h"
#include "rs_profiler_telemetry.h"
#include "rs_profiler_utils.h"

#include "pipeline/rs_main_thread.h"
#include "pipeline/rs_render_service_connection.h"
#include "pipeline/rs_uni_render_util.h"

namespace OHOS::Rosen {

// (user): Move to RSProfiler
static RSRenderService* renderService_ = nullptr;
static RSMainThread* renderServiceThread_ = nullptr;
static RSContext* renderServiceContext_ = nullptr;
static uint64_t frameBeginTimestamp_ = 0u;
static double dirtyRegionPercentage_ = 0.0;
static bool rdcSent_ = true;

static RSFile recordFile_ {};
static double recordStartTime_ = 0.0;

static RSFile playbackFile_ {};
static double playbackStartTime_ = 0.0;
static NodeId playbackParentNodeId_ = 0;
static int playbackPid_ = 0;
static bool playbackShouldBeTerminated_ = false;

static pid_t GetPid(uint64_t id)
{
    constexpr uint32_t BITS = 32u;
    return (id >> BITS);
}

static pid_t GetPid(const std::shared_ptr<RSBaseRenderNode>& node)
{
    return node ? GetPid(node->GetId()) : 0;
}

static NodeId GetNodeId(uint64_t id)
{
    constexpr uint32_t mask = 0xFFFFFFFF;
    return (id & mask);
}

static NodeId GetNodeId(const std::shared_ptr<RSBaseRenderNode>& node)
{
    return node ? GetNodeId(node->GetId()) : 0;
}

static NodeId GetRootNodeId(uint64_t id)
{
    constexpr uint32_t bits = 32u;
    return ((static_cast<NodeId>(id) << bits) | 1);
}

/*
    To visualize the damage region (as it's set for KHR_partial_update), you can set the following variable:
    'hdc shell param set rosen.dirtyregiondebug.enabled 6'
*/
static double GetDirtyRegionRelative(RSContext& context)
{
    const std::shared_ptr<RSBaseRenderNode>& rootNode = context.GetGlobalRootRenderNode();
    // without these checks device might get stuck on startup
    if (!rootNode || (rootNode->GetChildrenCount() != 1)) {
        return -1.0;
    }

    std::shared_ptr<RSDisplayRenderNode> displayNode =
        RSBaseRenderNode::ReinterpretCast<RSDisplayRenderNode>(rootNode->GetSortedChildren().front());
    if (!displayNode) {
        return -1.0;
    }

    std::shared_ptr<RSBaseRenderNode> nodePtr = displayNode->shared_from_this();
    std::shared_ptr<RSDisplayRenderNode> displayNodePtr = nodePtr->ReinterpretCastTo<RSDisplayRenderNode>();
    if (!displayNodePtr) {
        return -1.0;
    }

    const RectI displayResolution = displayNodePtr->GetDirtyManager()->GetSurfaceRect();
    const double displayWidth = displayResolution.GetWidth();
    const double displayHeight = displayResolution.GetHeight();
    const uint32_t bufferAge = 3;
    // not to update the RSRenderFrame/DirtyManager and just calculate dirty region
    const bool isAlignedDirtyRegion = false;
    RSUniRenderUtil::MergeDirtyHistory(displayNodePtr, bufferAge, isAlignedDirtyRegion);
    std::vector<NodeId> hasVisibleDirtyRegionSurfaceVec;
    const Occlusion::Region dirtyRegion =
        RSUniRenderUtil::MergeVisibleDirtyRegion(displayNodePtr, hasVisibleDirtyRegionSurfaceVec, isAlignedDirtyRegion);

    const std::vector<Occlusion::Rect>& visibleDirtyRects = dirtyRegion.GetRegionRects();
    double accumulatedArea = 0.0;
    for (const Occlusion::Rect& rect : visibleDirtyRects) {
        const int width = rect.right_ - rect.left_;
        const int height = rect.bottom_ - rect.top_;
        accumulatedArea += width * height;
    }

    const double dirtyRegionPercentage = accumulatedArea / (displayWidth * displayHeight);
    return dirtyRegionPercentage;
}

void RSProfiler::Init(RSRenderService* renderService)
{
    renderService_ = renderService;
    renderServiceThread_ = renderService ? RSMainThread::Instance() : nullptr;

    if (renderServiceThread_) {
        renderServiceContext_ = &renderServiceThread_->GetContext();
    }

    static std::thread const THREAD(Network::Run);
}

void RSProfiler::RenderServiceOnCreateConnection(pid_t remotePid)
{
    if (IsRecording()) {
        if (recordStartTime_ == 0.0) {
            recordStartTime_ = Utils::Now();
        }

        recordFile_.AddHeaderPID(remotePid);
    }
}

void RSProfiler::RenderServiceConnectionOnRemoteRequest(RSRenderServiceConnection* connection, uint32_t code,
    MessageParcel& data, MessageParcel& /*reply*/, MessageOption& option)
{
    if (IsRecording() && (recordStartTime_ > 0.0)) {
        pid_t connectionPid = renderService_->GetConnectionPID(connection);
        const auto& pidList = recordFile_.GetHeaderPIDList();
        if (std::find(std::begin(pidList), std::end(pidList), connectionPid) != std::end(pidList)) {
            int writeInt = 0;

            const double curTime = Utils::Now();
            double dt = curTime - recordStartTime_;

            std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);

            char headerType = 1; // parcel data
            ss.write(reinterpret_cast<const char*>(&headerType), sizeof(headerType));

            ss.write(reinterpret_cast<const char*>(&dt), sizeof(dt));

            // set sending pid
            ss.write(reinterpret_cast<const char*>(&connectionPid), sizeof(connectionPid));

            ss.write(reinterpret_cast<const char*>(&code), sizeof(code));

            writeInt = data.GetDataSize();
            ss.write(reinterpret_cast<const char*>(&writeInt), sizeof(writeInt));
            ss.write(reinterpret_cast<const char*>(data.GetData()), data.GetDataSize());

            writeInt = option.GetFlags();
            ss.write(reinterpret_cast<const char*>(&writeInt), sizeof(writeInt));
            writeInt = option.GetWaitTime();
            ss.write(reinterpret_cast<const char*>(&writeInt), sizeof(writeInt));

            Network::SendBinary(reinterpret_cast<void*>(ss.str().data()), ss.str().size());
            constexpr int headerSize = 8;
            recordFile_.WriteRSData(
                dt, reinterpret_cast<void*>(ss.str().data() + (1 + headerSize)), ss.str().size() - (1 + headerSize));
        }
    }

    if (playbackFile_.IsOpen()) {
        RSProfilerBase::SpecParseModeSet(SpecParseMode::READ);
        RSProfilerBase::SpecParseReplacePIDSet(playbackFile_.GetHeaderPIDList(), playbackPid_, playbackParentNodeId_);
    } else if (IsRecording()) {
        RSProfilerBase::SpecParseModeSet(SpecParseMode::WRITE);
    } else {
        RSProfilerBase::SpecParseModeSet(SpecParseMode::NONE);
    }
}

void RSProfiler::UnmarshalThreadOnRecvParcel(const MessageParcel* parcel, RSTransactionData* data)
{
    if (parcel && RSProfilerBase::IsParcelMock(*parcel)) {
        constexpr uint32_t bits = 30u;
        data->SetSendingPid(data->GetSendingPid() | (1 << bits));
    }
}

uint64_t RSProfiler::TimePauseApply(uint64_t time)
{
    return RSProfilerBase::TimePauseApply(time);
}

void RSProfiler::MainThreadOnProcessCommand()
{
    if (IsPlaying()) {
        renderServiceThread_->ResetAnimationStamp();
    }
}

void RSProfiler::MainThreadOnRenderBegin()
{
    if (IsRecording()) {
        constexpr double ratioToPercent = 100.0;
        dirtyRegionPercentage_ = GetDirtyRegionRelative(*renderServiceContext_) * ratioToPercent;
    }
}

void RSProfiler::MainThreadOnRenderEnd() {}

void RSProfiler::MainThreadOnFrameBegin()
{
    frameBeginTimestamp_ = Utils::RawNowNano();
}

void RSProfiler::MainThreadOnFrameEnd()
{
    ProcessCommands();
    ProcessSendingRdc();
    ProcessRecording();
}

bool RSProfiler::IsEnabled()
{
    return renderService_&& renderServiceThread_ && renderServiceContext_;
}

bool RSProfiler::IsRecording()
{
    return IsEnabled() && recordFile_.IsOpen();
}

bool RSProfiler::IsPlaying()
{
    return IsEnabled() && playbackFile_.IsOpen();
}

void RSProfiler::AwakeRenderServiceThread()
{
    if (renderServiceThread_) {
        renderServiceThread_->PostTask([]() {
            renderServiceThread_->SetAccessibilityConfigChanged();
            renderServiceThread_->RequestNextVSync();
        });
    }
}

void RSProfiler::SaveRdc()
{
    rdcSent_ = false;
    RSSystemProperties::SetSaveRDC(true);
    AwakeRenderServiceThread();
    Respond("Recording current frame cmds (for .rdc) into : /data/default.drawing");
}

void RSProfiler::ProcessSendingRdc()
{
    if (!RSSystemProperties::GetSaveRDC() || rdcSent_) {
        return;
    }

    AwakeRenderServiceThread();

    const std::string path("/data/storage/el2/base/temp/HuaweiGraphicsProfiler");
    if (!std::filesystem::exists(path)) {
        return;
    }

    std::vector<std::string> files;
    for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(path)) {
        const std::filesystem::path& path = entry.path();
        if (path.extension() == "rdc") {
            files.emplace_back(path.c_str());
        }
    }

    const size_t filesRequired = 3;
    if (files.size() == filesRequired) {
        std::sort(files.begin(), files.end());
        Network::SendRdc(files[1]);
        RSSystemProperties::SetSaveRDC(false);
        rdcSent_ = true;
    }
}

void RSProfiler::ProcessRecording()
{
    const uint64_t frameStartTime = frameBeginTimestamp_;
    const uint64_t framelenNanosecs = Utils::RawNowNano() - frameStartTime;
    const double dirtyPercent = dirtyRegionPercentage_;

    if (renderService_ && IsRecording() && recordStartTime_ > 0.0) {
        const double curTime = frameStartTime * 1e-9; // Utils::Now();
        const double timeSinceRecordStart = curTime - recordStartTime_;
        if (timeSinceRecordStart > 0.0) {
            RSCaptureData cd;
            cd.SetTime(timeSinceRecordStart);
            cd.SetProperty(RSCaptureData::KEY_RS_FRAME_LEN, framelenNanosecs);
            cd.SetProperty(RSCaptureData::KEY_RS_CMD_COUNT, RSProfilerBase::ParsedCmdCountGet());
            cd.SetProperty(RSCaptureData::KEY_RS_PIXEL_IMAGE_ADDED, RSProfilerBase::ImagesAddedCountGet());
            constexpr double d10 = 10.0;
            cd.SetProperty(RSCaptureData::KEY_RS_DIRTY_REGION, floor(dirtyPercent * d10) / d10);

            std::vector<char> cdData;
            cd.Serialize(cdData);

            const char headerType = 2; // TYPE: RS METRICS
            cdData.insert(cdData.begin(), headerType);

            Network::SendBinary((void*)cdData.data(), cdData.size());
            recordFile_.WriteRSMetrics(0, timeSinceRecordStart, (void*)cdData.data(), cdData.size());
        }
    }
}

void RSProfiler::Respond(const std::string& message)
{
    Network::SendMessage(message);
}

void RSProfiler::DumpConnections()
{
    if (renderService_) {
        std::string out;
        renderService_->DumpConnections(out);
        Respond(out);
    }
}

void RSProfiler::DumpNodeModifiers(uint64_t id)
{
    if (!renderServiceContext_) {
        return;
    }

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();
    if (const std::shared_ptr<RSBaseRenderNode> node = nodeMap.GetRenderNode(id)) {
        std::string out;
        node->DumpModifiers(out);
        Respond("Modifiers=" + out);
    }
}

void RSProfiler::DumpNodeProperties(uint64_t id)
{
    if (!renderServiceContext_) {
        return;
    }

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();
    if (const std::shared_ptr<RSBaseRenderNode> node = nodeMap.GetRenderNode(id)) {
        std::string out;
        node->DumpRenderProperties(out);
        Respond("RenderProperties=" + out);
    }
}

void RSProfiler::DumpTree(const std::string& node)
{
    if (!renderServiceContext_) {
        return;
    }

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();

    std::map<std::string, std::tuple<NodeId, std::string>> list;
    nodeMap.GetSurfacesTrees(list);

    std::string out = "Tree: count=" + std::to_string(static_cast<int>(nodeMap.GetRenderNodeCount())) +
                      " time=" + std::to_string(Utils::Now()) + "\n";

    for (const auto& item : list) {
        if (std::strstr(item.first.data(), node.data())) {
            out += "*** " + item.first + " pid=" + std::to_string(GetPid(std::get<0>(item.second))) +
                   " lowId=" + std::to_string(GetNodeId(std::get<0>(item.second))) + "\n" + std::get<1>(item.second) +
                   "\n";
        }
    }

    Respond(out);
}

void RSProfiler::DumpSurfaces(uint32_t pid)
{
    if (!renderServiceContext_) {
        return;
    }

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();

    std::map<NodeId, std::string> surfaces;
    nodeMap.GetSurfacesTreesByPid(pid, surfaces);

    std::string out;
    for (const auto& item : surfaces) {
        out += "*** " + std::to_string(item.first) + " pid=" + std::to_string(GetPid(item.first)) +
               " lowId=" + std::to_string(GetNodeId(item.first)) + "\n" + item.second + "\n";
    }

    out += "TREE: count=" + std::to_string(static_cast<int32_t>(nodeMap.GetRenderNodeCount())) +
           " time=" + std::to_string(Utils::Now()) + "\n";

    Respond(out);
}

void RSProfiler::DumpNodeSurface(uint64_t id)
{
    if (renderService_) {
        std::string out;
        renderService_->DumpSurfaceNode(out, GetRootNodeId(id));
        Respond(out);
    }
}

void RSProfiler::PatchNode(uint64_t id)
{
    if (!renderServiceContext_) {
        return;
    }

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();
    std::shared_ptr<RSBaseRenderNode> node = nodeMap.GetRenderNode(id);
    if (!node) {
        return;
    }

    const Vector4f screenRect = RSProfilerBase::GetScreenRect();

    auto surfaceNode = static_cast<RSSurfaceRenderNode*>(node.get());
    {
        auto& region = const_cast<Occlusion::Region&>(surfaceNode->GetVisibleRegion());
        region = Occlusion::Region({ screenRect.x_, screenRect.y_, screenRect.z_, screenRect.w_ });
    }

    auto* renderNode = static_cast<RSRenderNode*>(node.get());
    {
        RSProperties& properties = renderNode->GetMutableRenderProperties();
        properties.SetBounds(screenRect);
        properties.SetFrame(screenRect);
        properties.SetDrawRegion(std::make_shared<RectF>(screenRect));
    }

    AwakeRenderServiceThread();
}

void RSProfiler::KillNode(uint64_t id)
{
    if (!renderServiceContext_) {
        return;
    }

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();
    if (const std::shared_ptr<RSBaseRenderNode> node = nodeMap.GetRenderNode(id)) {
        node->RemoveFromTree(false);
        AwakeRenderServiceThread();
        Respond("OK");
    }
}

void RSProfiler::AttachChild(uint64_t parentPid, uint64_t parentNodeId, uint64_t childPid, uint64_t childNodeId)
{
    const RSRenderNodeMap& nodeMap = renderServiceThread_->GetContext().GetMutableNodeMap();

    std::shared_ptr<RSBaseRenderNode> parent = nodeMap.GetRenderNode((parentPid << 32) | parentNodeId);
    std::shared_ptr<RSBaseRenderNode> child = nodeMap.GetRenderNode((childPid << 32) | childNodeId);

    if (parent && child) {
        parent->AddChild(child);
        AwakeRenderServiceThread();
        Respond("OK");
    }
}

void RSProfiler::KillPid(uint32_t pid)
{
    if (!renderServiceContext_) {
        return;
    }

    RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();
    const NodeId rootNodeId = GetRootNodeId(pid);
    std::shared_ptr<RSBaseRenderNode> node = nodeMap.GetRenderNode(rootNodeId);
    std::shared_ptr<RSBaseRenderNode> parent = node ? node->GetParent().lock() : nullptr;
    const NodeId parentNodeId = parent ? parent->GetId() : 0;

    nodeMap.FilterNodeByPid(pid);
    AwakeRenderServiceThread();

    Respond(
        "parentPid=" + std::to_string(GetPid(parentNodeId)) + " parentNode=" + std::to_string(GetNodeId(parentNodeId)));
}

void RSProfiler::GetRoot()
{
    if (!renderServiceContext_) {
        return;
    }

    std::string out;

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();
    std::shared_ptr<RSRenderNode> node = nodeMap.GetRenderNode<RSRenderNode>(nodeMap.GetRandomSurfaceNode());
    while (node && (node->GetId() != 0)) {
        std::string type;
        const RSRenderNodeType nodeType = node->GetType();
        if (nodeType == RSRenderNodeType::UNKNOW) {
            type = "UNKNOWN";
        } else if (nodeType == RSRenderNodeType::RS_NODE) {
            type = "RS_NONE";
        } else if (nodeType == RSRenderNodeType::DISPLAY_NODE) {
            type = "DISPLAY_NODE";
        } else if (nodeType == RSRenderNodeType::SURFACE_NODE) {
            type = "SURFACE_NODE";
        } else if (nodeType == RSRenderNodeType::EFFECT_NODE) {
            type = "EFFECT_NODE";
        } else if (nodeType == RSRenderNodeType::ROOT_NODE) {
            type = "ROOT_NODE";
        } else if (nodeType == RSRenderNodeType::CANVAS_DRAWING_NODE) {
            type = "CANVAS_DRAWING_NODE";
        }

        if (!type.empty()) {
            out += "pid=" + std::to_string(GetPid(node)) + " node_id=" + std::to_string(GetNodeId(node)) + "|" + type +
                   ";\n";
        }

        node = node->GetParent().lock();
    };

    if (node) {
        out += "ROOT_ID=" + std::to_string(node->GetId()); // DISPLAY_NODE;ohos.sceneboard
    }

    Respond(out);
}

void RSProfiler::GetDeviceInfo()
{
    Respond(RSTelemetry::GetDeviceInfoString());
}

void RSProfiler::SendTelemetry(double startTime)
{
    const DeviceInfo deviceInfo = RSTelemetry::GetDeviceInfo();

    std::stringstream load;
    std::stringstream frequency;
    for (uint32_t k = 0; k < deviceInfo.cpu.cores; k++) {
        load << deviceInfo.cpu.coreLoad[k];
        if (k + 1 < deviceInfo.cpu.cores) {
            load << ";";
        }
        frequency << deviceInfo.cpu.coreFrequency[k];
        if (k + 1 < deviceInfo.cpu.cores) {
            frequency << ";";
        }
    }

    const double deltaTime = Utils::Now() - startTime;
    RSCaptureData captureData;
    captureData.SetTime(deltaTime);
    captureData.SetProperty(RSCaptureData::KEY_CPU_TEMP, deviceInfo.cpu.temperature);
    captureData.SetProperty(RSCaptureData::KEY_CPU_CURRENT, deviceInfo.cpu.current);
    captureData.SetProperty(RSCaptureData::KEY_CPU_LOAD, load.str());
    captureData.SetProperty(RSCaptureData::KEY_CPU_FREQ, frequency.str());
    captureData.SetProperty(RSCaptureData::KEY_GPU_LOAD, deviceInfo.gpu.load);
    captureData.SetProperty(RSCaptureData::KEY_GPU_FREQ, deviceInfo.gpu.frequency);

    std::vector<char> out;
    const char headerType = 3; // TYPE: GFX METRICS
    captureData.Serialize(out);
    out.insert(out.begin(), headerType);
    Network::SendBinary(out.data(), out.size());
}

void RSProfiler::RecordStart()
{
    auto& imageMap = RSProfilerBase::ImageMapGet();
    imageMap.clear();

    recordFile_.Create(RSFile::GetDefaultPath());
    recordFile_.SetImageMapPtr(
        reinterpret_cast<std::map<uint64_t, ReplayImageCacheRecordFile>*>(&RSProfilerBase::ImageMapGet()));
    recordFile_.AddLayer(); // add 0 layer

    auto& nodeMap = renderServiceContext_->GetMutableNodeMap();
    nodeMap.FilterNodeReplayed();

    recordStartTime_ = 0.0f;

    std::thread thread([]() {
        if (renderService_) {
            while (IsRecording()) {
                if (recordStartTime_ > 0.0) {
                    SendTelemetry(recordStartTime_);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(8));
            }
        }
    });
    thread.detach();

    Respond("Network: Record start");
}

void RSProfiler::RecordStop()
{
    double writeStartTime = recordStartTime_;

    recordStartTime_ = 0.0;

    if (IsRecording()) {
        recordFile_.SetWriteTime(writeStartTime);

        std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);

        // DOUBLE WORK - send header of file
        char headerType = 0;
        ss.write(reinterpret_cast<const char*>(&headerType), sizeof(headerType));

        ss.write(reinterpret_cast<const char*>(&writeStartTime), sizeof(writeStartTime));

        int pidCnt = recordFile_.GetHeaderPIDList().size();
        ss.write(reinterpret_cast<const char*>(&pidCnt), sizeof(pidCnt));
        for (auto item : recordFile_.GetHeaderPIDList()) {
            ss.write(reinterpret_cast<const char*>(&item), sizeof(item));
        }

        auto& imageMap = RSProfilerBase::ImageMapGet();

        std::stringstream ss3;
        uint32_t imageMapCount = imageMap.size();
        ss.write(reinterpret_cast<const char*>(&imageMapCount), sizeof(imageMapCount));
        for (auto item : imageMap) {
            ss.write(reinterpret_cast<const char*>(&item.first), sizeof(item.first));
            ss.write(reinterpret_cast<const char*>(&item.second.skipBytes), sizeof(item.second.skipBytes));
            ss.write(reinterpret_cast<const char*>(&item.second.imageSize), sizeof(item.second.imageSize));
            ss.write(reinterpret_cast<const char*>(item.second.image.get()), item.second.imageSize);
            ss3 << "[" << item.first << ", " << item.second.imageSize << "] ";
        }

        Network::SendBinary((void*)ss.str().c_str(), ss.str().size());

        std::stringstream ss2;
        for (auto item : recordFile_.GetHeaderPIDList()) {
            ss2 << item << ";";
        }

        recordFile_.Close();
    }

    Respond("Network: Record stop");
}

void RSProfiler::PlaybackStart(pid_t pid, double pauseTime)
{
    playbackPid_ = pid;

    auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
    nodeMap.FilterForReplay(playbackPid_);
    nodeMap.FilterNodeReplayed();

    NodeId processRootNodeId = (((NodeId)playbackPid_) << 32) | 1;
    playbackParentNodeId_ = 0;
    auto processRootNode = RSBaseRenderNode::ReinterpretCast<RSRenderNode>(nodeMap.GetRenderNode(processRootNodeId));
    if (processRootNode != nullptr) {
        auto parent = RSBaseRenderNode::ReinterpretCast<RSRenderNode>(processRootNode->GetParent().lock());
        if (parent != nullptr) {
            parent->RemoveChild(processRootNode);
            playbackParentNodeId_ = parent->GetId();
        }
    }

    playbackFile_.SetImageMapPtr((std::map<uint64_t, ReplayImageCacheRecordFile>*)&RSProfilerBase::ImageMapGet());
    playbackFile_.Open(RSFile::GetDefaultPath());
    if (!playbackFile_.IsOpen()) {
        return;
    }

    auto pidList = playbackFile_.GetHeaderPIDList();
    std::stringstream ss;
    ss << "READ START: infile_pid=[";
    for (size_t i = 0; i < pidList.size(); i++) {
        ss << pidList[i] << " ";
        renderService_->CreateMockConnection((1 << 30) | pidList[i]);
    }
    ss << "] ";

    ss << "new_assigned_pid=[";
    for (size_t i = 0; i < pidList.size(); i++) {
        ss << (pidList[i] + (1 << 30)) << " ";
    }
    ss << "] ";

    auto table = RSProfilerBase::ImageMapGet();
    ss << "image_count=" << table.size() << " ";

    ss << "cur_parend_pid=" << (playbackParentNodeId_ >> 32)
       << " cur_parent_node=" << (playbackParentNodeId_ & 0xFFffFFff);

    playbackStartTime_ = Utils::Now();

    const double recordPlayTime = 0.0;
    if (pauseTime > 0.0) {
        uint64_t curTimeRaw = Utils::RawNowNano();
        const uint64_t pauseTimeStart = curTimeRaw + (pauseTime - recordPlayTime) * 1'000'000'000;
        RSProfilerBase::TimePauseAt(curTimeRaw, pauseTimeStart);
    }

    AwakeRenderServiceThread();

    playbackShouldBeTerminated_ = false;

    std::thread thread([]() {
        if (renderService_) {
            while (playbackFile_.IsOpen()) {
                const int64_t timeStart = Utils::RawNowNano();

                PlaybackUpdate();
                SendTelemetry(playbackStartTime_);

                const int64_t dt = Utils::RawNowNano() - timeStart;

                const int64_t delayNanosec = 8000000 - dt;
                if (delayNanosec > 0) {
                    std::this_thread::sleep_for(std::chrono::nanoseconds(delayNanosec));
                }

                // PLEASE CHECK
                AwakeRenderServiceThread();
            }
        }
    });
    thread.detach();

    Respond("Playback start");
}

void RSProfiler::PlaybackStop()
{
    if (playbackPid_ > 0) {
        auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
        nodeMap.FilterForReplay(playbackPid_);
        nodeMap.FilterNodeReplayed();
    }
    playbackShouldBeTerminated_ = true;

    Respond("Playback stop");
}

void RSProfiler::PlaybackUpdate()
{
    if (!playbackFile_.IsOpen()) {
        return;
    }

    const double curTime = Utils::Now();
    const double curDt = curTime - playbackStartTime_;

    std::vector<uint8_t> data;
    double readTime;
    while (!playbackShouldBeTerminated_ && playbackFile_.ReadRSData(curDt, data, readTime)) {
        std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
        ss.write(reinterpret_cast<const char*>(data.data()), data.size());
        ss.seekg(0);

        pid_t sendingPid;
        ss.read(reinterpret_cast<char*>(&sendingPid), sizeof(sendingPid));

        RSRenderServiceConnection* connection = renderService_->GetConnectionByPID((1 << 30) | sendingPid);
        std::vector<pid_t>& pidList = playbackFile_.GetHeaderPIDList();
        if (!connection) {
            connection = renderService_->GetConnectionByPID((1 << 30) | pidList[0]);
        }
        if (!connection) {
            continue;
        }

        uint32_t code;
        ss.read(reinterpret_cast<char*>(&code), sizeof(code));

        int dataSize;
        ss.read(reinterpret_cast<char*>(&dataSize), sizeof(dataSize));
        auto* data = new uint8_t[dataSize];
        ss.read(reinterpret_cast<char*>(data), dataSize);

#pragma pack(push, 1)
        struct {
            uint8_t dum {};
            MessageParcel mpData;
        } pacelMissalignment;
#pragma pack(pop)

        pacelMissalignment.mpData.WriteBuffer(data, dataSize);

        MessageOption option;
        int readInt;
        ss.read(reinterpret_cast<char*>(&readInt), sizeof(readInt));
        option.SetFlags(readInt);
        ss.read(reinterpret_cast<char*>(&readInt), sizeof(readInt));
        option.SetWaitTime(readInt);

        RS_LOGD("RSMainThread::MainLoop Server REPLAY ReadRSFileOneFrame CODE=%d data_size=%d parcel_pointer=%p",
            (int)code, (int)dataSize, (void*)&pacelMissalignment.mpData);

        MessageParcel parcelReply;
        connection->OnRemoteRequest(code, pacelMissalignment.mpData, parcelReply, option);

        std::stringstream ss2;
        for (auto value : playbackFile_.GetHeaderPIDList()) {
            ss2 << value << " ";
        }
    }

    if (playbackShouldBeTerminated_ || playbackFile_.RSDataEOF()) {
        playbackStartTime_ = 0.0;
        playbackFile_.Close();
        playbackPid_ = 0;
        RSProfilerBase::TimePauseClear();
    }
}

void RSProfiler::PlaybackPrepare(uint32_t pid)
{
    if (!renderServiceContext_ || (pid == 0)) {
        return;
    }

    renderServiceContext_->GetMutableNodeMap().FilterForReplay(pid);
    AwakeRenderServiceThread();
    Respond("OK");
}

void RSProfiler::PlaybackPause()
{
    if (!playbackFile_.IsOpen()) {
        return;
    }
    if (playbackStartTime_ <= 0.0) {
        return;
    }

    const uint64_t curTimeRaw = Utils::RawNowNano();
    const double recordPlayTime = Utils::Now() - playbackStartTime_;

    RSProfilerBase::TimePauseAt(curTimeRaw, curTimeRaw);
    Respond("OK: " + std::to_string(recordPlayTime));
}

void RSProfiler::PlaybackPauseAt(double time)
{
    if (!playbackFile_.IsOpen()) {
        return;
    }
    if (playbackStartTime_ <= 0.0) {
        return;
    }

    const double recordPlayTime = Utils::Now() - playbackStartTime_;

    if (recordPlayTime > time) {
        return;
    }

    RS_LOGD("RSMainThread::MainLoop Server REPLAY record_play_time=%lf record_pause_time=%lf", recordPlayTime, time);

    const uint64_t curTimeRaw = Utils::RawNowNano();
    const uint64_t pauseTimeStart = curTimeRaw + (time - recordPlayTime) * 1'000'000'000;

    RSProfilerBase::TimePauseAt(curTimeRaw, pauseTimeStart);

    renderServiceThread_->ResetAnimationStamp();

    Respond("OK");
}

void RSProfiler::PlaybackPauseClear()
{
    RSProfilerBase::TimePauseClear();
    Respond("OK");
}

void RSProfiler::PlaybackResume()
{
    if (!playbackFile_.IsOpen()) {
        return;
    }
    if (playbackStartTime_ <= 0.0) {
        return;
    }

    const uint64_t curTimeRaw =
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();

    RSProfilerBase::TimePauseResume(curTimeRaw);

    renderServiceThread_->ResetAnimationStamp();

    Respond("OK");
}

void RSProfiler::ProcessCommands()
{
    const std::lock_guard<std::mutex> guard(Network::commandMutex_);
    if (Network::commandData_.empty()) {
        return;
    }

    const std::string command = Network::commandData_[0];

    constexpr int minCmdLen = 2;
    if (command == "info") {
        GetDeviceInfo();
    } else if (command == "rsrecord_replay") {
        if (Network::commandData_.size() > 2) {
            const pid_t pid = std::atoi(Network::commandData_[1].data());
            const double pauseTime =
                (Network::commandData_.size() > 3) ? std::atof(Network::commandData_[2].data()) : 0.0;
            PlaybackStart(pid, pauseTime);
        }
    } else if (command == "rsrecord_replay_stop") {
        PlaybackStop();
    } else if (command == "rsrecord_start") {
        RecordStart();
    } else if (command == "rsrecord_stop") {
        RecordStop();
    } else if (command == "rstree_contains") {
        if (Network::commandData_.size() >= minCmdLen) {
            DumpTree(Network::commandData_[1]);
        }
    } else if (command == "rsrecord_pause_at") {
        if (Network::commandData_.size() >= minCmdLen) {
            PlaybackPauseAt(std::atof(Network::commandData_[1].data()));
        }
    } else if (command == "rsrecord_pause_now") {
        PlaybackPause();
    } else if (command == "rsrecord_pause_resume") {
        PlaybackResume();
    } else if (command == "rsrecord_pause_clear") {
        PlaybackPauseClear();
    } else if (command == "rstree_fix") {
        if (Network::commandData_.size() >= minCmdLen) {
            PatchNode(std::atoll(Network::commandData_[1].data()));
        }
    } else if (command == "rstree_kill_node") {
        if (Network::commandData_.size() >= minCmdLen) {
            KillNode(std::atoll(Network::commandData_[1].data()));
        }
    } else if (command == "rstree_setparent") {
        constexpr int rstreeSetparentCmdMinLen = 5;
        if (Network::commandData_.size() >= rstreeSetparentCmdMinLen) {
            AttachChild(std::atoll(Network::commandData_[1].data()), std::atoll(Network::commandData_[2].data()),
                std::atoll(Network::commandData_[3].data()), std::atoll(Network::commandData_[4].data()));
        }
    } else if (command == "rstree_getroot") {
        GetRoot();
    } else if (command == "rstree_node_mod") {
        if (Network::commandData_.size() >= minCmdLen && !Network::commandData_[1].empty()) {
            DumpNodeModifiers(std::atoll(Network::commandData_[1].data()));
        }
    } else if (command == "rstree_node_prop") {
        if (Network::commandData_.size() >= minCmdLen && !Network::commandData_[1].empty()) {
            DumpNodeProperties(std::atoll(Network::commandData_[1].data()));
        }
    } else if (command == "rstree_pid") {
        if (Network::commandData_.size() >= minCmdLen && !Network::commandData_[1].empty()) {
            DumpSurfaces(std::atoi(Network::commandData_[1].data()));
        }
    } else if (command == "rssurface_pid") {
        if (Network::commandData_.size() >= minCmdLen && !Network::commandData_[1].empty()) {
            DumpNodeSurface(std::atoi(Network::commandData_[1].data()));
        }
    } else if (command == "rstree_kill_pid") {
        if (Network::commandData_.size() >= minCmdLen && !Network::commandData_[1].empty()) {
            KillPid(std::atoi(Network::commandData_[1].data()));
        }
    } else if (command == "rstree_prepare_replay") {
        if (Network::commandData_.size() >= minCmdLen && !Network::commandData_[1].empty()) {
            PlaybackPrepare(std::atoi(Network::commandData_[1].data()));
        }
    } else if (command == "rscon_print") {
        DumpConnections();
    } else if (command == "save_rdc") {
        SaveRdc();
    } else {
        Respond("Unknown command");
    }

    Network::commandData_.clear();
}

} // namespace OHOS::Rosen