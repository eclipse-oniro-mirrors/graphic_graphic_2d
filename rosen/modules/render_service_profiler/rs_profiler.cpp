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

constexpr int nanosecsInSec = 1'000'000'000;

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

namespace {
pid_t GetPid(const std::shared_ptr<RSRenderNode>& node)
{
    return node ? RSProfiler::ExtractPid(node->GetId()) : 0;
}

NodeId GetNodeId(const std::shared_ptr<RSRenderNode>& node)
{
    return node ? RSProfiler::ExtractNodeLocalID(node->GetId()) : 0;
}

} // namespace

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
    RecordUpdate();
}

bool RSProfiler::IsEnabled()
{
    return renderService_ && renderServiceThread_ && renderServiceContext_;
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

std::shared_ptr<RSRenderNode> RSProfiler::GetRenderNode(uint64_t id)
{
    return renderServiceContext_ ? renderServiceContext_->GetMutableNodeMap().GetRenderNode(id) : nullptr;
}

void RSProfiler::SaveRdc(const ArgList& /*args*/)
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

void RSProfiler::RecordUpdate()
{
    if (!IsRecording() || (recordStartTime_ <= 0.0)) {
        return;
    }

    const uint64_t frameLengthNanosecs = Utils::RawNowNano() - frameBeginTimestamp_;

    const double currentTime = frameBeginTimestamp_ * 1e-9; // Utils::Now();
    const double timeSinceRecordStart = currentTime - recordStartTime_;
    if (timeSinceRecordStart > 0.0) {
        RSCaptureData captureData;
        captureData.SetTime(timeSinceRecordStart);
        captureData.SetProperty(RSCaptureData::KEY_RS_FRAME_LEN, frameLengthNanosecs);
        captureData.SetProperty(RSCaptureData::KEY_RS_CMD_COUNT, RSProfilerBase::ParsedCmdCountGet());
        captureData.SetProperty(RSCaptureData::KEY_RS_PIXEL_IMAGE_ADDED, RSProfilerBase::ImagesAddedCountGet());
        captureData.SetProperty(RSCaptureData::KEY_RS_DIRTY_REGION, floor(dirtyRegionPercentage_ * 10.0) / 10.0);

        std::vector<char> out;
        captureData.Serialize(out);

        const char headerType = 2; // TYPE: RS METRICS
        out.insert(out.begin(), headerType);

        Network::SendBinary(out.data(), out.size());
        recordFile_.WriteRSMetrics(0, timeSinceRecordStart, out.data(), out.size());
    }
}

void RSProfiler::Respond(const std::string& message)
{
    Network::SendMessage(message);
}

void RSProfiler::DumpConnections(const ArgList& /*args*/)
{
    if (renderService_) {
        std::string out;
        renderService_->DumpConnections(out);
        Respond(out);
    }
}

void RSProfiler::DumpNodeModifiers(const ArgList& args)
{
    if (const auto node = GetRenderNode(args.Node())) {
        std::string out;
        node->DumpModifiers(out);
        Respond("Modifiers=" + out);
    }
}

void RSProfiler::DumpNodeProperties(const ArgList& args)
{
    if (const auto node = GetRenderNode(args.Node())) {
        std::string out;
        node->DumpRenderProperties(out);
        Respond("RenderProperties=" + out);
    }
}

void RSProfiler::DumpTree(const ArgList& args)
{
    if (!renderServiceContext_) {
        return;
    }

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();

    std::map<std::string, std::tuple<NodeId, std::string>> list;
    nodeMap.GetSurfacesTrees(list);

    std::string out = "Tree: count=" + std::to_string(static_cast<int>(nodeMap.GetRenderNodeCount())) +
                      " time=" + std::to_string(Utils::Now()) + "\n";

    const std::string& node = args.String();
    for (const auto& item : list) {
        if (std::strstr(item.first.data(), node.data())) {
            out += "*** " + item.first + " pid=" + std::to_string(ExtractPid(std::get<0>(item.second))) +
                   " lowId=" + std::to_string(ExtractNodeLocalID(std::get<0>(item.second))) + "\n" +
                   std::get<1>(item.second) + "\n";
        }
    }

    Respond(out);
}

void RSProfiler::DumpSurfaces(const ArgList& args)
{
    if (!renderServiceContext_) {
        return;
    }

    const RSRenderNodeMap& nodeMap = renderServiceContext_->GetMutableNodeMap();

    std::map<NodeId, std::string> surfaces;
    nodeMap.GetSurfacesTreesByPid(args.Pid(), surfaces);

    std::string out;
    for (const auto& item : surfaces) {
        out += "*** " + std::to_string(item.first) + " pid=" + std::to_string(ExtractPid(item.first)) +
               " lowId=" + std::to_string(ExtractNodeLocalID(item.first)) + "\n" + item.second + "\n";
    }

    out += "TREE: count=" + std::to_string(static_cast<int32_t>(nodeMap.GetRenderNodeCount())) +
           " time=" + std::to_string(Utils::Now()) + "\n";

    Respond(out);
}

void RSProfiler::DumpNodeSurface(const ArgList& args)
{
    if (renderService_) {
        std::string out;
        renderService_->DumpSurfaceNode(out, GetRootNodeId(args.Node()));
        Respond(out);
    }
}

void RSProfiler::PatchNode(const ArgList& args)
{
    const auto node = GetRenderNode(args.Node());
    if (!node) {
        return;
    }

    const Vector4f screenRect = RSProfilerBase::GetScreenRect();

    auto surfaceNode = static_cast<RSSurfaceRenderNode*>(node.get());
    {
        auto& region = const_cast<Occlusion::Region&>(surfaceNode->GetVisibleRegion());
        region = Occlusion::Region({ screenRect.x_, screenRect.y_, screenRect.z_, screenRect.w_ });
    }

    RSProperties& properties = node->GetMutableRenderProperties();
    properties.SetBounds(screenRect);
    properties.SetFrame(screenRect);
    properties.SetDrawRegion(std::make_shared<RectF>(screenRect));

    AwakeRenderServiceThread();
}

void RSProfiler::KillNode(const ArgList& args)
{
    if (const auto node = GetRenderNode(args.Node())) {
        node->RemoveFromTree(false);
        AwakeRenderServiceThread();
        Respond("OK");
    }
}

void RSProfiler::AttachChild(const ArgList& args)
{
    auto parent = GetRenderNode(ComposeNodeID(args.Pid(0), args.Node(1)));
    auto child = GetRenderNode(ComposeNodeID(args.Pid(2), args.Node(3)));

    if (parent && child) {
        parent->AddChild(child);
        AwakeRenderServiceThread();
        Respond("OK");
    }
}

void RSProfiler::KillPid(const ArgList& args)
{
    const uint32_t pid = args.Pid();
    if (const auto node = GetRenderNode(GetRootNodeId(pid))) {
        const auto parent = node->GetParent().lock();
        const std::string out =
            "parentPid=" + std::to_string(GetPid(parent)) + " parentNode=" + std::to_string(GetNodeId(parent));

        renderServiceContext_->GetMutableNodeMap().FilterNodeByPid(pid);
        AwakeRenderServiceThread();
        Respond(out);
    }
}

void RSProfiler::GetRoot(const ArgList& /*args*/)
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

void RSProfiler::GetDeviceInfo(const ArgList& /*args*/)
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

void RSProfiler::RecordStart(const ArgList& /*args*/)
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
                std::this_thread::sleep_for(std::chrono::milliseconds(gfxMetricsSendInterval));
            }
        }
    });
    thread.detach();

    Respond("Network: Record start");
}

void RSProfiler::RecordStop(const ArgList& /*args*/)
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

void RSProfiler::PlaybackStart(const ArgList& args)
{
    playbackPid_ = args.Pid(0);

    auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
    nodeMap.FilterForReplay(playbackPid_);
    nodeMap.FilterNodeReplayed();

    NodeId processRootNodeId = GetRootNodeId(playbackPid_);
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
        renderService_->CreateMockConnection(GetMockPid(pidList[i]));
    }
    ss << "] ";

    ss << "new_assigned_pid=[";
    for (size_t i = 0; i < pidList.size(); i++) {
        ss << GetMockPid(pidList[i]) << " ";
    }
    ss << "] ";

    auto table = RSProfilerBase::ImageMapGet();
    ss << "image_count=" << table.size() << " ";

    ss << "cur_parend_pid=" << ExtractPid(playbackParentNodeId_)
       << " cur_parent_node=" << ExtractNodeLocalID(playbackParentNodeId_);

    playbackStartTime_ = Utils::Now();

    const double recordPlayTime = 0.0;
    const double pauseTime = args.Fp64(1);
    if (pauseTime > 0.0) {
        uint64_t curTimeRaw = Utils::RawNowNano();
        const uint64_t pauseTimeStart = curTimeRaw + (pauseTime - recordPlayTime) * nanosecsInSec;
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

void RSProfiler::PlaybackStop(const ArgList& /*args*/)
{
    if (playbackPid_ > 0) {
        auto& nodeMap = renderServiceContext_->GetMutableNodeMap();
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

        RSRenderServiceConnection* connection = renderService_->GetConnectionByPID(GetMockPid(sendingPid));
        std::vector<pid_t>& pidList = playbackFile_.GetHeaderPIDList();
        if (!connection) {
            connection = renderService_->GetConnectionByPID(GetMockPid(pidList[0]));
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

void RSProfiler::PlaybackPrepare(const ArgList& args)
{
    const uint32_t pid = args.Pid();
    if (!renderServiceContext_ || (pid == 0)) {
        return;
    }

    renderServiceContext_->GetMutableNodeMap().FilterForReplay(pid);
    AwakeRenderServiceThread();
    Respond("OK");
}

void RSProfiler::PlaybackPause(const ArgList& /*args*/)
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

void RSProfiler::PlaybackPauseAt(const ArgList& args)
{
    if (!playbackFile_.IsOpen()) {
        return;
    }
    if (playbackStartTime_ <= 0.0) {
        return;
    }

    const double pauseTime = args.Fp64();
    const double recordPlayTime = Utils::Now() - playbackStartTime_;
    if (recordPlayTime > pauseTime) {
        return;
    }

    const uint64_t curTimeRaw = Utils::RawNowNano();
    const uint64_t pauseTimeStart = curTimeRaw + (pauseTime - recordPlayTime) * nanosecsInSec;

    RSProfilerBase::TimePauseAt(curTimeRaw, pauseTimeStart);

    renderServiceThread_->ResetAnimationStamp();

    Respond("OK");
}

void RSProfiler::PlaybackPauseClear(const ArgList& /*args*/)
{
    RSProfilerBase::TimePauseClear();
    Respond("OK");
}

void RSProfiler::PlaybackResume(const ArgList& /*args*/)
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

RSProfiler::Command RSProfiler::GetCommand(const std::string& command)
{
    static const std::map<std::string, Command> COMMANDS = {
        { "rstree_contains", DumpTree },
        { "rstree_fix", PatchNode },
        { "rstree_kill_node", KillNode },
        { "rstree_setparent", AttachChild },
        { "rstree_getroot", GetRoot },
        { "rstree_node_mod", DumpNodeModifiers },
        { "rstree_node_prop", DumpNodeProperties },
        { "rstree_pid", DumpSurfaces },
        { "rstree_kill_pid", KillPid },
        { "rstree_prepare_replay", PlaybackPrepare },
        { "rsrecord_start", RecordStart },
        { "rsrecord_stop", RecordStop },
        { "rsrecord_replay", PlaybackStart },
        { "rsrecord_replay_stop", PlaybackStop },
        { "rsrecord_pause_now", PlaybackPause },
        { "rsrecord_pause_at", PlaybackPauseAt },
        { "rsrecord_pause_resume", PlaybackResume },
        { "rsrecord_pause_clear", PlaybackPauseClear },
        { "rssurface_pid", DumpNodeSurface },
        { "rscon_print", DumpConnections },
        { "save_rdc", SaveRdc },
        { "info", GetDeviceInfo },
    };

    if (command.empty()) {
        return nullptr;
    }

    const auto delegate = COMMANDS.find(command);
    return (delegate != COMMANDS.end()) ? delegate->second : nullptr;
}

void RSProfiler::ProcessCommands()
{
    const std::lock_guard<std::mutex> guard(Network::incomingMutex_);
    auto& commandData = Network::incoming_;
    if (commandData.empty()) {
        return;
    }
    
    const std::string command = commandData[0];
    const ArgList args = (commandData.size() > 1) ? ArgList({ commandData.begin() + 1, commandData.end() }) : ArgList();
    commandData.clear();

    if (const Command delegate = GetCommand(command)) {
        delegate(args);
    } else if (!command.empty()) {
        Respond("Command has not been found: " + command);
    }
}

} // namespace OHOS::Rosen