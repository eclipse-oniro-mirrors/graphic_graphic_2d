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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <sys/mman.h>
#include <type_traits>
#include <utility>
#include <vector>

#include "message_parcel.h"
#include "rs_profiler.h"
#include "rs_profiler_cache.h"
#include "rs_profiler_capture_recorder.h"
#include "rs_profiler_file.h"
#include "rs_profiler_log.h"
#include "rs_profiler_network.h"
#include "rs_profiler_utils.h"
#include "sys_binder.h"

#include "animation/rs_animation_manager.h"
#include "command/rs_base_node_command.h"
#include "command/rs_canvas_drawing_node_command.h"
#include "command/rs_canvas_node_command.h"
#include "command/rs_effect_node_command.h"
#include "command/rs_proxy_node_command.h"
#include "command/rs_root_node_command.h"
#include "command/rs_surface_node_command.h"
#include "modifier_ng/rs_modifier_ng_type.h"
#include "pipeline/rs_canvas_drawing_render_node.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_screen_render_node.h"
#include "transaction/rs_ashmem_helper.h"

#include "render/rs_shader_filter.h"
#include "ge_shader_filter.h"

namespace OHOS::Rosen {
std::atomic_bool RSProfiler::recordAbortRequested_ = false;
std::atomic_uint32_t RSProfiler::mode_ = static_cast<uint32_t>(Mode::NONE);
    static thread_local uint32_t g_subMode = static_cast<uint32_t>(SubMode::NONE);
static std::vector<pid_t> g_pids;
static pid_t g_pid = 0;
static NodeId g_parentNode = 0;
static std::atomic<uint32_t> g_commandCount = 0;        // UNMARSHALLING RSCOMMAND COUNT
static std::atomic<uint32_t> g_commandExecuteCount = 0; // EXECUTE RSCOMMAND COUNT

static std::mutex g_msgBaseMutex;
static std::queue<std::string> g_msgBaseList;

static std::mutex g_rsLogListMutex;
static std::queue<RSProfilerLogMsg> g_rsLogList;

static std::mutex g_mutexCommandOffsets;
static std::map<uint32_t, std::vector<uint32_t>> g_parcelNumber2Offset;

static uint64_t g_pauseAfterTime = 0;
static int64_t g_pauseCumulativeTime = 0;
static int64_t g_transactionTimeCorrection = 0;
static int64_t g_replayStartTimeNano = 0.0;
static double g_replaySpeed = 1.0f;

static const size_t PARCEL_MAX_CAPACITY = 234 * 1024 * 1024;

static std::unordered_map<AnimationId, std::vector<int64_t>> g_animeStartMap;

bool RSProfiler::testing_ = false;
std::vector<std::shared_ptr<RSRenderNode>> RSProfiler::testTree_ = std::vector<std::shared_ptr<RSRenderNode>>();
bool RSProfiler::enabled_ = RSSystemProperties::GetProfilerEnabled();
bool RSProfiler::hrpServiceEnabled_ = RSSystemProperties::GetProfilerEnabled();
bool RSProfiler::betaRecordingEnabled_ = RSSystemProperties::GetBetaRecordingMode() != 0;
std::atomic<int8_t> RSProfiler::signalFlagChanged_ = 0;
std::atomic_bool RSProfiler::dcnRedraw_ = false;
std::atomic_bool RSProfiler::renderNodeKeepDrawCmdList_ = false;
std::vector<RSRenderNode::WeakPtr> g_childOfDisplayNodesPostponed;
std::unordered_map<AnimationId, int64_t> RSProfiler::animationsTimes_;

static TextureRecordType g_textureRecordType = TextureRecordType::LZ4;

static std::shared_ptr<ProfilerMarshallingJob> g_marshallingJob;
static bool g_marshalFirstFrameThread = false;

constexpr size_t GetParcelMaxCapacity()
{
    return PARCEL_MAX_CAPACITY;
}

bool RSProfiler::IsEnabled()
{
    return enabled_ || testing_;
}

bool RSProfiler::IsHrpServiceEnabled()
{
    return hrpServiceEnabled_;
}

bool RSProfiler::IsBetaRecordEnabled()
{
#ifdef RS_PROFILER_BETA_ENABLED
    return betaRecordingEnabled_;
#else
    return false;
#endif
}

bool RSProfiler::IsNoneMode()
{
    return GetMode() == Mode::NONE;
}

bool RSProfiler::IsReadMode()
{
    return GetMode() == Mode::READ;
}

bool RSProfiler::IsReadEmulationMode()
{
    return GetSubMode() == SubMode::READ_EMUL;
}

bool RSProfiler::IsWriteMode()
{
    return GetMode() == Mode::WRITE;
}

bool RSProfiler::IsWriteEmulationMode()
{
    return GetSubMode() == SubMode::WRITE_EMUL;
}

bool RSProfiler::IsSavingMode()
{
    return GetMode() == Mode::SAVING;
}

void RSProfiler::AddLightBlursMetrics(uint32_t areaBlurs)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }

    GetCustomMetrics().AddInt(RSPROFILER_METRIC_LIGHT_BLUR_OPERATIONS, 1);
    GetCustomMetrics().AddInt(RSPROFILER_METRIC_BLUR_OPERATIONS, 1);
    GetCustomMetrics().AddFloat(RSPROFILER_METRIC_BLUR_AREA_OPERATIONS, areaBlurs);
}
void RSProfiler::AddAnimationNodeMetrics(RSRenderNodeType type, int32_t size)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }

    GetCustomMetrics().AddInt(RSPROFILER_METRIC_ANIMATION_NODE, 1);
    GetCustomMetrics().AddFloat(RSPROFILER_METRIC_ANIMATION_NODE_SIZE, size);

    int profiler_node_type = -1;
    switch (type) {
        case RSRenderNodeType::SURFACE_NODE:
            profiler_node_type = RSPROFILER_METRIC_ANIMATION_NODE_TYPE_SURFACE_NODE;
            break;
        case RSRenderNodeType::PROXY_NODE:
            profiler_node_type = RSPROFILER_METRIC_ANIMATION_NODE_TYPE_PROXY_NODE;
            break;
        case RSRenderNodeType::CANVAS_NODE:
            profiler_node_type = RSPROFILER_METRIC_ANIMATION_NODE_TYPE_CANVAS_NODE;
            break;
        case RSRenderNodeType::EFFECT_NODE:
            profiler_node_type = RSPROFILER_METRIC_ANIMATION_NODE_TYPE_EFFECT_NODE;
            break;
        case RSRenderNodeType::ROOT_NODE:
            profiler_node_type = RSPROFILER_METRIC_ANIMATION_NODE_TYPE_ROOT_NODE;
            break;
        case RSRenderNodeType::CANVAS_DRAWING_NODE:
            profiler_node_type = RSPROFILER_METRIC_ANIMATION_NODE_TYPE_CANVAS_DRAWING_NODE;
            break;
        default:  // exclude RSRenderNodeType::(RS_NODE, UNKNOW, DISPLAY_NODE)
            break;
    }

    if (profiler_node_type >= 0) {
        GetCustomMetrics().AddInt(profiler_node_type, 1);
    }
}

void RSProfiler::AddAnimationStart(AnimationId id, int64_t timestamp_ns)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }
    animationsTimes_[id] = timestamp_ns;
}

void RSProfiler::AddAnimationFinish(AnimationId id, int64_t timestamp_ns)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }
    if (animationsTimes_.count(id) == 1) {
        GetCustomMetrics().AddFloat(
            RSPROFILER_METRIC_ANIMATION_DURATION, float(timestamp_ns - animationsTimes_[id]) / 1'000'000'000.f);
        animationsTimes_.erase(id);
    }
}

void RSProfiler::AddHPSBlursMetrics(uint32_t areaBlurs)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }

    GetCustomMetrics().AddInt(RSPROFILER_METRIC_HPS_BLUR_OPERATIONS, 1);
    GetCustomMetrics().AddInt(RSPROFILER_METRIC_BLUR_OPERATIONS, 1);
    GetCustomMetrics().AddFloat(RSPROFILER_METRIC_BLUR_AREA_OPERATIONS, areaBlurs);
}

void RSProfiler::AddKawaseBlursMetrics(uint32_t areaBlurs)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }

    GetCustomMetrics().AddInt(RSPROFILER_METRIC_KAWASE_BLUR_OPERATIONS, 1);
    GetCustomMetrics().AddInt(RSPROFILER_METRIC_BLUR_OPERATIONS, 1);
    GetCustomMetrics().AddFloat(RSPROFILER_METRIC_BLUR_AREA_OPERATIONS, areaBlurs);
}

void RSProfiler::AddMESABlursMetrics(uint32_t areaBlurs)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }

    GetCustomMetrics().AddInt(RSPROFILER_METRIC_MESA_BLUR_OPERATIONS, 1);
    GetCustomMetrics().AddInt(RSPROFILER_METRIC_BLUR_OPERATIONS, 1);
    GetCustomMetrics().AddFloat(RSPROFILER_METRIC_BLUR_AREA_OPERATIONS, areaBlurs);
}

void RSProfiler::LogShaderCall(const std::string& shaderType, const std::shared_ptr<Drawing::Image>& srcImage,
    const Drawing::Rect& dstRect, const std::shared_ptr<Drawing::Image>& outImage)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }

    if (shaderType == "KAWASE_BLUR") {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_KAWASE_BLUR_SHADER_CALLS, 1);
    } else if (shaderType == "MESA_BLUR") {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_MESA_BLUR_SHADER_CALLS, 1);
    } else if (shaderType == "AIBAR") {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_AIBAR_BLUR_SHADER_CALLS, 1);
    } else if (shaderType == "GREY") {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_GREY_BLUR_SHADER_CALLS, 1);
    } else if (shaderType == "LINEAR_GRADIENT_BLUR") {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_LINEAR_GRADIENT_BLUR_SHADER_CALLS, 1);
    } else if (shaderType == "MAGNIFIER") {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_MAGNIFIER_SHADER_CALLS, 1);
    } else if (shaderType == "WATER_RIPPLE") {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_WATER_RIPPLE_BLUR_SHADER_CALLS, 1);
    }
    GetCustomMetrics().AddInt(RSPROFILER_METRIC_BLUR_SHADER_CALLS, 1);
    GetCustomMetrics().AddFloat(RSPROFILER_METRIC_BLUR_AREA_SHADER_CALLS, srcImage->GetWidth() * srcImage->GetHeight());
}

uint32_t RSProfiler::GetCommandCount()
{
    const uint32_t count = g_commandCount;
    g_commandCount = 0;
    return count;
}

uint32_t RSProfiler::GetCommandExecuteCount()
{
    const uint32_t count = g_commandExecuteCount;
    g_commandExecuteCount = 0;
    return count;
}

void RSProfiler::EnableSharedMemory()
{
    RSMarshallingHelper::EndNoSharedMem();
}

void RSProfiler::DisableSharedMemory()
{
    RSMarshallingHelper::BeginNoSharedMem(std::this_thread::get_id());
}

bool RSProfiler::IsSharedMemoryEnabled()
{
    return RSMarshallingHelper::GetUseSharedMem(std::this_thread::get_id());
}

bool RSProfiler::IsParcelMock(const Parcel& parcel)
{
    // gcc C++ optimization error (?): this is not working without volatile
    const volatile auto address = reinterpret_cast<uint64_t>(&parcel);
    return ((address & 1u) != 0);
}

bool RSProfiler::IsPlaybackParcel(const Parcel& parcel)
{
    return (IsReadMode() || IsReadEmulationMode())
        && IsParcelMock(parcel);
}

std::shared_ptr<MessageParcel> RSProfiler::CopyParcel(const MessageParcel& parcel)
{
    if (!IsEnabled()) {
        return std::make_shared<MessageParcel>();
    }

    if (IsParcelMock(parcel)) {
        auto* buffer = new(std::nothrow) uint8_t[sizeof(MessageParcel) + 1];
        if (!buffer) {
            return std::make_shared<MessageParcel>();
        }
        auto* mpPtr = new (buffer + 1) MessageParcel;
        return std::shared_ptr<MessageParcel>(mpPtr, [](MessageParcel* ptr) {
            ptr->~MessageParcel();
            auto* allocPtr = reinterpret_cast<uint8_t*>(ptr);
            allocPtr--;
            delete[] allocPtr;
        });
    }

    return std::make_shared<MessageParcel>();
}

NodeId RSProfiler::PatchPlainNodeId(const Parcel& parcel, NodeId id)
{
    if (!IsEnabled()) {
        return id;
    }

    if ((!IsReadMode() && !IsReadEmulationMode()) || !IsParcelMock(parcel)) {
        return id;
    }

    return Utils::PatchNodeId(id);
}

void RSProfiler::PatchTypefaceId(const Parcel& parcel, std::shared_ptr<Drawing::DrawCmdList>& val)
{
    if (!val || !IsEnabled()) {
        return;
    }

    if (IsReadEmulationMode()) {
        val->PatchTypefaceIds();
    } else if (IsReadMode()) {
        if (IsParcelMock(parcel)) {
            val->PatchTypefaceIds();
        }
    }
}

pid_t RSProfiler::PatchPlainPid(const Parcel& parcel, pid_t pid)
{
    if (!IsEnabled() || (!IsReadMode() && !IsReadEmulationMode()) || !IsParcelMock(parcel)) {
        return pid;
    }

    return Utils::GetMockPid(pid);
}

void RSProfiler::SetMode(Mode mode)
{
    mode_ = static_cast<uint32_t>(mode);
    if (IsNoneMode()) {
        g_pauseAfterTime = 0;
        g_pauseCumulativeTime = 0;
        g_replayStartTimeNano = 0;
    }
}

Mode RSProfiler::GetMode()
{
    return static_cast<Mode>(mode_.load());
}

void RSProfiler::SetSubMode(SubMode subMode)
{
    g_subMode = static_cast<uint32_t>(subMode);
}

SubMode RSProfiler::GetSubMode()
{
    return static_cast<SubMode>(g_subMode);
}

void RSProfiler::SetSubstitutingPid(const std::vector<pid_t>& pids, pid_t pid, NodeId parent)
{
    g_pids = pids;
    g_pid = pid;
    g_parentNode = parent;
}

NodeId RSProfiler::GetParentNode()
{
    return g_parentNode;
}

const std::vector<pid_t>& RSProfiler::GetPids()
{
    return g_pids;
}

pid_t RSProfiler::GetSubstitutingPid()
{
    return g_pid;
}

uint64_t RSProfiler::PatchTime(uint64_t time)
{
    if (!IsEnabled()) {
        return time;
    }
    if (!IsReadMode() && !IsReadEmulationMode()) {
        return time;
    }
    if (time == 0.0) {
        return 0.0;
    }
    if (time >= g_pauseAfterTime && g_pauseAfterTime > 0) {
        return (static_cast<int64_t>(g_pauseAfterTime) - g_pauseCumulativeTime - g_replayStartTimeNano) *
            BaseGetPlaybackSpeed() + g_replayStartTimeNano;
    }
    return (static_cast<int64_t>(time) - g_pauseCumulativeTime - g_replayStartTimeNano) *
        BaseGetPlaybackSpeed() + g_replayStartTimeNano;
}

uint64_t RSProfiler::PatchTransactionTime(const Parcel& parcel, uint64_t time)
{
    if (!IsEnabled()) {
        return time;
    }

    if (!IsReadMode()) {
        return time;
    }
    if (time == 0.0) {
        return 0.0;
    }
    if (!IsParcelMock(parcel)) {
        return time;
    }

    return PatchTime(time + g_transactionTimeCorrection);
}

void RSProfiler::TimePauseAt(uint64_t curTime, uint64_t newPauseAfterTime, bool immediate)
{
    if (g_pauseAfterTime > 0) {
        // second time pause
        if (curTime > g_pauseAfterTime) {
            g_pauseCumulativeTime += static_cast<int64_t>(curTime - g_pauseAfterTime);
        }
    }
    g_pauseAfterTime = newPauseAfterTime;
    if (immediate) {
        g_pauseCumulativeTime += static_cast<int64_t>(curTime - g_pauseAfterTime);
        g_pauseAfterTime = curTime;
    }
}

void RSProfiler::TimePauseResume(uint64_t curTime)
{
    if (g_pauseAfterTime > 0) {
        if (curTime > g_pauseAfterTime) {
            g_pauseCumulativeTime += static_cast<int64_t>(curTime - g_pauseAfterTime);
        }
    }
    g_pauseAfterTime = 0;
}

void RSProfiler::TimePauseClear()
{
    g_pauseCumulativeTime = 0;
    g_pauseAfterTime = 0;
}

uint64_t RSProfiler::TimePauseGet()
{
    return g_pauseAfterTime;
}

std::shared_ptr<RSScreenRenderNode> RSProfiler::GetScreenNode(const RSContext& context)
{
    const std::shared_ptr<RSBaseRenderNode>& root = context.GetGlobalRootRenderNode();
    // without these checks device might get stuck on startup
    if (!root || !root->GetChildrenCount()) {
        return nullptr;
    }

    const auto& children = *root->GetChildren();
    if (children.empty()) {
        return nullptr;
    }
    for (const auto& screenNode : children) {   // apply multiple screen nodes
        if (!screenNode) {
            continue;
        }
        const auto& screenNodeChildren = screenNode->GetChildren();
        if (!screenNodeChildren || screenNodeChildren->empty()) {
            continue;
        }
        return RSBaseRenderNode::ReinterpretCast<RSScreenRenderNode>(screenNode);
    }
    return nullptr;
}

Vector4f RSProfiler::GetScreenRect(const RSContext& context)
{
    std::shared_ptr<RSScreenRenderNode> node = GetScreenNode(context);
    if (!node) {
        return {};
    }

    const RectI rect = node->GetDirtyManager()->GetSurfaceRect();
    return { rect.GetLeft(), rect.GetTop(), rect.GetRight(), rect.GetBottom() };
}

void RSProfiler::FilterForPlayback(RSContext& context, pid_t pid)
{
    auto& map = context.GetMutableNodeMap();

    auto canBeRemoved = [](NodeId node, pid_t pid) -> bool {
        return (ExtractPid(node) == pid) && (Utils::ExtractNodeId(node) != 1);
    };

    // remove all nodes belong to given pid (by matching higher 32 bits of node id)
    auto iter = map.renderNodeMap_.find(pid);
    if (iter != map.renderNodeMap_.end()) {
        auto& subMap = iter->second;
        EraseIf(subMap, [](const auto& pair) -> bool {
            if (Utils::ExtractNodeId(pair.first) == 1) {
                return false;
            }
            // remove node from tree
            pair.second->RemoveFromTree(false);
            return true;
        });
        if (subMap.empty()) {
            map.renderNodeMap_.erase(pid);
        }
    }

    EraseIf(
        map.surfaceNodeMap_, [pid, canBeRemoved](const auto& pair) -> bool { return canBeRemoved(pair.first, pid); });

    EraseIf(map.residentSurfaceNodeMap_,
        [pid, canBeRemoved](const auto& pair) -> bool { return canBeRemoved(pair.first, pid); });

    EraseIf(
        map.screenNodeMap_, [pid, canBeRemoved](const auto& pair) -> bool { return canBeRemoved(pair.first, pid); });

    if (auto fallbackNode = map.GetAnimationFallbackNode()) {
        fallbackNode->GetAnimationManager().FilterAnimationByPid(pid);
    }
}

void RSProfiler::FilterMockNode(RSContext& context)
{
    std::unordered_set<pid_t> pidSet;

    auto& nodeMap = context.GetMutableNodeMap();
    nodeMap.TraversalNodes([&pidSet](const std::shared_ptr<RSBaseRenderNode>& node) {
        if (node == nullptr) {
            return;
        }
        if (Utils::IsNodeIdPatched(node->GetId())) {
            pidSet.insert(Utils::ExtractPid(node->GetId()));
        }
    });

    for (auto pid : pidSet) {
        nodeMap.FilterNodeByPid(pid, true);
    }

    if (auto fallbackNode = nodeMap.GetAnimationFallbackNode()) {
        // remove all fallback animations belong to given pid
        FilterAnimationForPlayback(fallbackNode->GetAnimationManager());
    }
}

void RSProfiler::GetSurfacesTrees(
    const RSContext& context, std::map<std::string, std::tuple<NodeId, std::string>>& list)
{
    constexpr uint32_t treeDumpDepth = 2;

    list.clear();

    const RSRenderNodeMap& map = const_cast<RSContext&>(context).GetMutableNodeMap();
    for (const auto& [_, subMap] : map.renderNodeMap_) {
        for (const auto& [_, node] : subMap) {
            if (node->GetType() == RSRenderNodeType::SURFACE_NODE) {
                std::string tree;
                node->DumpTree(treeDumpDepth, tree);
                const auto surfaceNode = node->ReinterpretCastTo<RSSurfaceRenderNode>();
                list.insert({ surfaceNode->GetName(), { surfaceNode->GetId(), tree } });
            }
        }
    }
}

void RSProfiler::GetSurfacesTrees(const RSContext& context, pid_t pid, std::map<NodeId, std::string>& list)
{
    constexpr uint32_t treeDumpDepth = 2;

    list.clear();

    const RSRenderNodeMap& map = const_cast<RSContext&>(context).GetMutableNodeMap();
    for (const auto& [_, subMap] : map.renderNodeMap_) {
        for (const auto& [_, node] : subMap) {
            if (node->GetId() == Utils::GetRootNodeId(pid)) {
                std::string tree;
                node->DumpTree(treeDumpDepth, tree);
                list.insert({ node->GetId(), tree });
            }
        }
    }
}

size_t RSProfiler::GetRenderNodeCount(const RSContext& context)
{
    return const_cast<RSContext&>(context).GetMutableNodeMap().GetSize();
}

NodeId RSProfiler::GetRandomSurfaceNode(const RSContext& context)
{
    const RSRenderNodeMap& map = const_cast<RSContext&>(context).GetMutableNodeMap();
    for (const auto& item : map.surfaceNodeMap_) {
        return item.first;
    }
    return 0;
}

void RSProfiler::MarshalNodes(const RSContext& context, std::stringstream& data, uint32_t fileVersion,
    std::shared_ptr<ProfilerMarshallingJob> job)
{
    const auto& map = const_cast<RSContext&>(context).GetMutableNodeMap();
    if (job) {
        job->offsetNodeCount = data.str().size();
    }
    const uint32_t count = static_cast<uint32_t>(map.GetSize());
    data.write(reinterpret_cast<const char*>(&count), sizeof(count));
    const auto& rootRenderNode = context.GetGlobalRootRenderNode();
    if (rootRenderNode == nullptr) {
        RS_LOGE("RSProfiler::MarshalNodes rootRenderNode is nullptr");
        return;
    }

    std::vector<std::shared_ptr<RSRenderNode>> nodes;
    nodes.emplace_back(rootRenderNode);

    for (const auto& [_, subMap] : map.renderNodeMap_) {
        for (const auto& [_, node] : subMap) {
            if (!node) {
                continue;
            }
            if (job && node->GetId()) {
                job->AddNode(node->GetId());
            } else {
                MarshalNode(*node, data, fileVersion);
            }
            std::shared_ptr<RSRenderNode> parent = node->GetParent().lock();
            if (!parent && (node != rootRenderNode)) {
                nodes.emplace_back(node);
            }
        }
    }

    if (job) {
        job->offsetNodes = data.str().size();
    }

    const uint32_t nodeCount = static_cast<uint32_t>(nodes.size());
    data.write(reinterpret_cast<const char*>(&nodeCount), sizeof(nodeCount));
    for (const auto& node : nodes) { // no nullptr in nodes, omit check
        MarshalTree(*node, data, fileVersion);
    }

    g_marshallingJob = job;
}

void RSProfiler::MarshalTree(const RSRenderNode& node, std::stringstream& data, uint32_t fileVersion)
{
    const NodeId nodeId = node.GetId();
    data.write(reinterpret_cast<const char*>(&nodeId), sizeof(nodeId));

    const uint32_t count = node.children_.size();
    data.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& child : node.children_) {
        if (auto node = child.lock().get()) {
            const NodeId nodeId = node->GetId();
            data.write(reinterpret_cast<const char*>(&nodeId), sizeof(nodeId));
            MarshalTree(*node, data, fileVersion);
        }
    }
}

void RSProfiler::MarshalNode(const RSRenderNode& node, std::stringstream& data, uint32_t fileVersion,
    bool skipDrawCmdModifiers, bool isBetaRecording)
{
    const RSRenderNodeType nodeType = node.GetType();
    data.write(reinterpret_cast<const char*>(&nodeType), sizeof(nodeType));

    const NodeId nodeId = node.GetId();
    data.write(reinterpret_cast<const char*>(&nodeId), sizeof(nodeId));

    const bool isTextureExportNode = node.GetIsTextureExportNode();
    data.write(reinterpret_cast<const char*>(&isTextureExportNode), sizeof(isTextureExportNode));

    if (node.GetType() == RSRenderNodeType::SURFACE_NODE) {
        const auto& surfaceNode = reinterpret_cast<const RSSurfaceRenderNode&>(node);
        const std::string name = surfaceNode.GetName();
        uint32_t size = name.size();
        data.write(reinterpret_cast<const char*>(&size), sizeof(size));
        data.write(reinterpret_cast<const char*>(name.c_str()), size);

        const std::string bundleName = "";
        size = bundleName.size();
        data.write(reinterpret_cast<const char*>(&size), sizeof(size));
        data.write(reinterpret_cast<const char*>(bundleName.c_str()), size);

        const RSSurfaceNodeType type = surfaceNode.GetSurfaceNodeType();
        data.write(reinterpret_cast<const char*>(&type), sizeof(type));

        const uint8_t backgroundAlpha = surfaceNode.GetAbilityBgAlpha();
        data.write(reinterpret_cast<const char*>(&backgroundAlpha), sizeof(backgroundAlpha));

        const uint8_t globalAlpha = surfaceNode.GetGlobalAlpha();
        data.write(reinterpret_cast<const char*>(&globalAlpha), sizeof(globalAlpha));
    }

    const float positionZ = node.GetRenderProperties().GetPositionZ();
    data.write(reinterpret_cast<const char*>(&positionZ), sizeof(positionZ));

    const float pivotZ = node.GetRenderProperties().GetPivotZ();
    data.write(reinterpret_cast<const char*>(&pivotZ), sizeof(pivotZ));

    const bool isOnTree = node.IsOnTheTree();
    data.write(reinterpret_cast<const char*>(&isOnTree), sizeof(isOnTree));

    if (fileVersion >= RSFILE_VERSION_RENDER_METRICS_ADDED) {
        const uint8_t nodeGroupType = node.nodeGroupType_;
        data.write(reinterpret_cast<const char*>(&nodeGroupType), sizeof(nodeGroupType));
    }

    if (fileVersion >= RSFILE_VERSION_ISREPAINT_BOUNDARY) {
        const bool isRepaintBoundary = node.IsRepaintBoundary();
        data.write(reinterpret_cast<const char*>(&isRepaintBoundary), sizeof(isRepaintBoundary));
    }

    MarshalNodeModifiers(node, data, fileVersion, skipDrawCmdModifiers, isBetaRecording);
}

static void MarshalRenderModifier(const ModifierNG::RSRenderModifier& modifier, std::stringstream& data)
{
    Parcel parcel;
    parcel.SetMaxCapacity(GetParcelMaxCapacity());

    // Parcel Code - can be any, in our case I selected -1 to support already captured subtrees
    parcel.WriteInt32(-1);
    // MARSHAL PARCEL VERSION
    if (!RSMarshallingHelper::MarshallingTransactionVer(parcel)) {
        return;
    }

    const_cast<ModifierNG::RSRenderModifier&>(modifier).Marshalling(parcel);
    const size_t dataSize = parcel.GetDataSize();
    data.write(reinterpret_cast<const char*>(&dataSize), sizeof(dataSize));
    data.write(reinterpret_cast<const char*>(parcel.GetData()), dataSize);

    // Remove all file descriptors
    binder_size_t* object = reinterpret_cast<binder_size_t*>(parcel.GetObjectOffsets());
    size_t objectNum = parcel.GetOffsetsSize();
    uintptr_t parcelData = parcel.GetData();

    const size_t maxObjectNum = INT_MAX;
    if (!object || (objectNum > maxObjectNum)) {
        return;
    }

    for (size_t i = 0; i < objectNum; i++) {
        const flat_binder_object* flat = reinterpret_cast<flat_binder_object*>(parcelData + object[i]);
        if (!flat) {
            return;
        }
        if (flat->hdr.type == BINDER_TYPE_FD && flat->handle > 0) {
            ::close(flat->handle);
        }
    }
}

static uint32_t MarshalDrawCmdModifiers(
    ModifierNG::RSRenderModifier& modifier, bool skipDrawCmdModifiers, std::stringstream& data)
{
    auto propertyType = ModifierNG::ModifierTypeConvertor::GetPropertyType(modifier.GetType());
    auto oldCmdList = modifier.Getter<Drawing::DrawCmdListPtr>(propertyType, nullptr);
    if (oldCmdList && skipDrawCmdModifiers) {
        return 0;
    }
    if (!oldCmdList) {
        MarshalRenderModifier(modifier, data);
        return 1;
    }

    auto newCmdList = std::make_shared<Drawing::DrawCmdList>(
        oldCmdList->GetWidth(), oldCmdList->GetHeight(), Drawing::DrawCmdList::UnmarshalMode::IMMEDIATE);
    oldCmdList->ProfilerMarshallingDrawOps(newCmdList.get());
    newCmdList->PatchTypefaceIds(oldCmdList);
    modifier.Setter<Drawing::DrawCmdListPtr>(propertyType, newCmdList);
    MarshalRenderModifier(modifier, data);
    modifier.Setter<Drawing::DrawCmdListPtr>(propertyType, oldCmdList);
    return 1;
}

static std::shared_ptr<ModifierNG::RSRenderModifier> CreateSnapshotModifier(const RSRenderNode& node, uint32_t version)
{
    if (!node.IsInstanceOf<RSCanvasDrawingRenderNode>() || (version < RSFILE_VERSION_SELF_DRAWING_RESTORES)) {
        return nullptr;
    }

    const auto drawable = node.GetRenderDrawable();
    const auto image = drawable ? drawable->Snapshot() : nullptr;
    if (!image) {
        return nullptr;
    }

    const auto drawOp = std::make_shared<Drawing::DrawImageOpItem>(*image, 0, 0,
        Drawing::SamplingOptions(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::LINEAR), Drawing::Paint());

    auto cmdList = std::make_shared<Drawing::DrawCmdList>(
        image->GetWidth(), image->GetHeight(), Drawing::DrawCmdList::UnmarshalMode::DEFERRED);
    cmdList->AddDrawOp(drawOp);
    cmdList->MarshallingDrawOps();

    const auto property = std::make_shared<RSRenderProperty<Drawing::DrawCmdListPtr>>(cmdList, 0);
    return ModifierNG::RSRenderModifier::MakeRenderModifier(ModifierNG::RSModifierType::CONTENT_STYLE, property);
}

void RSProfiler::MarshalNodeModifiers(const RSRenderNode& node, std::stringstream& data, uint32_t fileVersion,
    bool skipDrawCmdModifiers, bool isBetaRecording)
{
    data.write(reinterpret_cast<const char*>(&node.instanceRootNodeId_), sizeof(node.instanceRootNodeId_));
    data.write(reinterpret_cast<const char*>(&node.firstLevelNodeId_), sizeof(node.firstLevelNodeId_));

    uint32_t modifierNGCount = 0;
    long long countOffset = data.tellp();
    data.write(reinterpret_cast<const char*>(&modifierNGCount), sizeof(modifierNGCount));
    if (skipDrawCmdModifiers) {
        return;
    }

    for (const auto& [_, slot] : node.GetAllModifiers()) {
        for (auto& modifierNG : slot) {
            if (!modifierNG || modifierNG->GetType() == ModifierNG::RSModifierType::PARTICLE_EFFECT) {
                continue;
            }
            modifierNGCount += MarshalDrawCmdModifiers(*modifierNG, skipDrawCmdModifiers, data);
        }
    }

    if (!isBetaRecording) {
        const auto snapshot = CreateSnapshotModifier(node, fileVersion);
        if (snapshot) {
            MarshalRenderModifier(*snapshot, data); // mustn't be called in beta-recording mode
            modifierNGCount++;
        }
    }

    data.seekp(countOffset, std::ios_base::beg);
    data.write(reinterpret_cast<const char*>(&modifierNGCount), sizeof(modifierNGCount));
    data.seekp(0, std::ios_base::end);
}

static std::string CreateRenderSurfaceNode(RSContext& context,
                                           NodeId id,
                                           bool isTextureExportNode,
                                           std::stringstream& data)
{
    constexpr uint32_t nameSizeMax = 4096;
    uint32_t size = 0u;
    data.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (size > nameSizeMax) {
        return "CreateRenderSurfaceNode unmarshalling failed, file is damaged";
    }

    std::string name;
    name.resize(size, ' ');
    data.read(reinterpret_cast<char*>(name.data()), size);

    data.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (size > nameSizeMax) {
        return "CreateRenderSurfaceNode unmarshalling failed, file is damaged";
    }
    std::string bundleName;
    bundleName.resize(size, ' ');
    data.read(reinterpret_cast<char*>(bundleName.data()), size);

    RSSurfaceNodeType nodeType = RSSurfaceNodeType::DEFAULT;
    data.read(reinterpret_cast<char*>(&nodeType), sizeof(nodeType));

    uint8_t backgroundAlpha = 0u;
    data.read(reinterpret_cast<char*>(&backgroundAlpha), sizeof(backgroundAlpha));

    uint8_t globalAlpha = 0u;
    data.read(reinterpret_cast<char*>(&globalAlpha), sizeof(globalAlpha));

    const RSSurfaceRenderNodeConfig config = { .id = id,
        .name = name + "_",
        .nodeType = nodeType,
        .additionalData = nullptr,
        .isTextureExportNode = isTextureExportNode,
        .isSync = false };

    if (auto node = SurfaceNodeCommandHelper::CreateWithConfigInRS(config, context)) {
        context.GetMutableNodeMap().RegisterRenderNode(node);
        node->SetAbilityBGAlpha(backgroundAlpha);
        node->SetGlobalAlpha(globalAlpha);
    }
    return "";
}

std::string RSProfiler::UnmarshalNodes(RSContext& context, std::stringstream& data, uint32_t fileVersion)
{
    std::string errReason;

    uint32_t count = 0;
    data.read(reinterpret_cast<char*>(&count), sizeof(count));
    for (uint32_t i = 0; i < count; i++) {
        errReason = UnmarshalNode(context, data, fileVersion);
        if (errReason.size()) {
            return errReason;
        }
    }

    data.read(reinterpret_cast<char*>(&count), sizeof(count));
    for (uint32_t i = 0; i < count; i++) {
        errReason = UnmarshalTree(context, data, fileVersion);
        if (errReason.size()) {
            return errReason;
        }
    }

    MarkReplayNodesDirty(context);
    return "";
}

void RSProfiler::MarkReplayNodesDirty(RSContext& context)
{
    auto& nodeMap = context.GetMutableNodeMap();
    nodeMap.TraversalNodes([](const std::shared_ptr<RSBaseRenderNode>& node) {
        if (node == nullptr) {
            return;
        }
        if (Utils::IsNodeIdPatched(node->GetId())) {
            node->SetContentDirty();
            node->SetDirty();
        }
    });
}

std::string RSProfiler::UnmarshalNode(RSContext& context, std::stringstream& data, uint32_t fileVersion)
{
    RSRenderNodeType nodeType = RSRenderNodeType::UNKNOW;
    data.read(reinterpret_cast<char*>(&nodeType), sizeof(nodeType));

    NodeId nodeId = 0;
    data.read(reinterpret_cast<char*>(&nodeId), sizeof(nodeId));
    nodeId = Utils::PatchNodeId(nodeId);

    bool isTextureExportNode = false;
    data.read(reinterpret_cast<char*>(&isTextureExportNode), sizeof(isTextureExportNode));

    if (data.eof()) {
        return "UnmarshalNode failed, file is damaged";
    }

    if (nodeType == RSRenderNodeType::RS_NODE) {
        RootNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    } else if (nodeType == RSRenderNodeType::SCREEN_NODE) {
        RootNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    } else if (nodeType == RSRenderNodeType::LOGICAL_DISPLAY_NODE) {
        RootNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    } else if (nodeType == RSRenderNodeType::SURFACE_NODE) {
        std::string errReason = CreateRenderSurfaceNode(context, nodeId, isTextureExportNode, data);
        if (errReason.size()) {
            return errReason;
        }
    } else if (nodeType == RSRenderNodeType::PROXY_NODE) {
        ProxyNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    } else if (nodeType == RSRenderNodeType::CANVAS_NODE) {
        RSCanvasNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    } else if (nodeType == RSRenderNodeType::EFFECT_NODE) {
        EffectNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    } else if (nodeType == RSRenderNodeType::ROOT_NODE) {
        RootNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    } else if (nodeType == RSRenderNodeType::CANVAS_DRAWING_NODE) {
        RSCanvasDrawingNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    } else {
        RootNodeCommandHelper::Create(context, nodeId, isTextureExportNode);
    }
    
    return UnmarshalNode(context, data, nodeId, fileVersion, nodeType);
}

std::string RSProfiler::UnmarshalNode(
    RSContext& context, std::stringstream& data, NodeId nodeId, uint32_t fileVersion, RSRenderNodeType nodeType)
{
    float positionZ = 0.0f;
    data.read(reinterpret_cast<char*>(&positionZ), sizeof(positionZ));
    float pivotZ = 0.0f;
    data.read(reinterpret_cast<char*>(&pivotZ), sizeof(pivotZ));
    NodePriorityType priority = NodePriorityType::MAIN_PRIORITY;
    data.read(reinterpret_cast<char*>(&priority), sizeof(priority));
    bool isOnTree = false;
    data.read(reinterpret_cast<char*>(&isOnTree), sizeof(isOnTree));

    uint8_t nodeGroupType = 0;
    if (fileVersion >= RSFILE_VERSION_RENDER_METRICS_ADDED) {
        data.read(reinterpret_cast<char*>(&nodeGroupType), sizeof(nodeGroupType));
    }

    bool isRepaintBoundary = false;
    if (fileVersion >= RSFILE_VERSION_ISREPAINT_BOUNDARY) {
        data.read(reinterpret_cast<char*>(&isRepaintBoundary), sizeof(isRepaintBoundary));
    }

    if (auto node = context.GetMutableNodeMap().GetRenderNode(nodeId)) {
        node->GetMutableRenderProperties().SetPositionZ(positionZ);
        node->GetMutableRenderProperties().SetPivotZ(pivotZ);
        node->nodeGroupType_ = nodeGroupType;
#ifdef SUBTREE_PARALLEL_ENABLE
        node->MarkRepaintBoundary(isRepaintBoundary);
#endif
        return UnmarshalNodeModifiers(*node, data, fileVersion, nodeType);
    }
    return "";
}

static std::shared_ptr<ModifierNG::RSRenderModifier> UnmarshalRenderModifier(
    std::stringstream& data, std::string& errReason)
{
    errReason = "";

    constexpr size_t bufferSizeMax = 50'000'000;
    size_t bufferSize = 0;
    data.read(reinterpret_cast<char*>(&bufferSize), sizeof(bufferSize));
    if (bufferSize > bufferSizeMax) {
        errReason = "UnmarshalRenderModifier failed, file is damaged";
        return nullptr;
    }

    std::vector<uint8_t> buffer;
    buffer.resize(bufferSize);
    data.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    if (data.eof()) {
        errReason = "UnmarshalRenderModifier failed, file is damaged";
        return nullptr;
    }

    uint8_t parcelMemory[sizeof(Parcel) + 1];
    auto* parcel = new (parcelMemory + 1) Parcel;
    parcel->SetMaxCapacity(GetParcelMaxCapacity());
    parcel->WriteBuffer(buffer.data(), buffer.size());

    int32_t versionPrefix = parcel->ReadInt32();
    if (versionPrefix == -1) {
        RSMarshallingHelper::UnmarshallingTransactionVer(*parcel);
    } else {
        parcel->RewindRead(0);
    }

    auto ptr = ModifierNG::RSRenderModifier::Unmarshalling(*parcel);
    if (!ptr) {
        constexpr size_t minBufferSize = 2;
        if (buffer.size() >= minBufferSize) {
            const auto typeModifier = *(reinterpret_cast<ModifierNG::RSModifierType *>(&buffer[0]));
            errReason = ModifierNG::RSModifierTypeString::GetModifierTypeString(typeModifier);
        } else {
            errReason = "RSRenderModifier buffer too short";
        }
        errReason += ", size=" + std::to_string(buffer.size());
    }

    return ptr;
}

static void SetupCanvasDrawingRenderNode(RSRenderNode& node)
{
    if (!node.IsInstanceOf<RSCanvasDrawingRenderNode>()) {
        return;
    }

    int32_t width = 0;
    int32_t height = 0;
    for (const auto& modifier : node.GetModifiersNG(ModifierNG::RSModifierType::CONTENT_STYLE)) {
        const auto cmdList = modifier ? modifier->GetPropertyDrawCmdList() : nullptr;
        if (cmdList) {
            width = std::max(width, cmdList->GetWidth());
            height = std::max(height, cmdList->GetHeight());
        }
    }

    if ((width > 0) && (height > 0)) {
        static_cast<RSCanvasDrawingRenderNode&>(node).ResetSurface(width, height);
    }
}

std::string RSProfiler::UnmarshalNodeModifiers(
    RSRenderNode& node, std::stringstream& data, uint32_t fileVersion, RSRenderNodeType nodeType)
{
    bool disableModifiers =
        (nodeType == RSRenderNodeType::LOGICAL_DISPLAY_NODE || nodeType == RSRenderNodeType::SCREEN_NODE);

    data.read(reinterpret_cast<char*>(&node.instanceRootNodeId_), sizeof(node.instanceRootNodeId_));
    node.instanceRootNodeId_ = Utils::PatchNodeId(node.instanceRootNodeId_);

    data.read(reinterpret_cast<char*>(&node.firstLevelNodeId_), sizeof(node.firstLevelNodeId_));
    node.firstLevelNodeId_ = Utils::PatchNodeId(node.firstLevelNodeId_);

    int32_t modifierCount = 0;
    data.read(reinterpret_cast<char*>(&modifierCount), sizeof(modifierCount));
    for (int32_t i = 0; i < modifierCount; i++) {
        std::string errModifierCode = "";
        auto ptr = UnmarshalRenderModifier(data, errModifierCode);
        if (!ptr) {
            RSProfiler::SendMessageBase("LOADERROR: Modifier format changed [" + errModifierCode + "]");
            continue;
        }
        if (!disableModifiers) {
            node.AddModifier(ptr);
        }
    }

    if (data.eof()) {
        return "UnmarshalNodeModifiers failed, file is damaged";
    }

    SetupCanvasDrawingRenderNode(node);
    node.ApplyModifiers();
    return "";
}

std::string RSProfiler::UnmarshalTree(RSContext& context, std::stringstream& data, uint32_t fileVersion)
{
    const auto& map = context.GetMutableNodeMap();

    NodeId nodeId = 0;
    data.read(reinterpret_cast<char*>(&nodeId), sizeof(nodeId));
    nodeId = Utils::PatchNodeId(nodeId);

    uint32_t count = 0;
    data.read(reinterpret_cast<char*>(&count), sizeof(count));

    auto node = map.GetRenderNode(nodeId);
    if (!node) {
        return "Error nodeId was not found";
    }
    for (uint32_t i = 0; i < count; i++) {
        NodeId nodeId = 0;
        data.read(reinterpret_cast<char*>(&nodeId), sizeof(nodeId));
        if (node) {
            node->AddChild(map.GetRenderNode(Utils::PatchNodeId(nodeId)), i);
        }
        UnmarshalTree(context, data, fileVersion);
    }
    return "";
}

std::string RSProfiler::DumpRenderProperties(const RSRenderNode& node)
{
    return node.renderProperties_.Dump();
}

std::string RSProfiler::DumpModifiers(const RSRenderNode& node)
{
    std::string out;
    out += "<";
    for (uint16_t type = 0; type < ModifierNG::MODIFIER_TYPE_COUNT; type++) {
        auto slot = node.GetModifiersNG(static_cast<ModifierNG::RSModifierType>(type));
        if (slot.empty()) {
            continue;
        }
        if (!slot[0]->IsCustom()) {
            continue;
        }
        out += "(";
        out += std::to_string(type);
        out += ", ";
        for (auto& modifier : slot) {
            out += "[";
            const auto modifierId = modifier->GetId();
            out += std::to_string(Utils::ExtractPid(modifierId));
            out += "|";
            out += std::to_string(Utils::ExtractNodeId(modifierId));
            out += " type=";
            out += std::to_string(type);
            out += " [modifier dump is not implemented yet]";
            out += "]";
        }
        out += ")";
    }
    out += ">";
    return out;
}

std::string RSProfiler::DumpSurfaceNode(const RSRenderNode& node)
{
    if (node.GetType() != RSRenderNodeType::SURFACE_NODE) {
        return "";
    }

    std::string out;
    const auto& surfaceNode = (static_cast<const RSSurfaceRenderNode&>(node));
    const auto parent = node.parent_.lock();
    out += ", Parent [" + (parent ? std::to_string(parent->GetId()) : "null") + "]";
    out += ", Name [" + surfaceNode.GetName() + "]";
    if (surfaceNode.GetRSSurfaceHandler()) {
        out += ", hasConsumer: " + std::to_string(surfaceNode.GetRSSurfaceHandler()->HasConsumer());
    }
    std::string contextAlpha = std::to_string(surfaceNode.contextAlpha_);
    std::string propertyAlpha = std::to_string(surfaceNode.GetRenderProperties().GetAlpha());
    out += ", Alpha: " + propertyAlpha + " (include ContextAlpha: " + contextAlpha + ")";
    out += ", Visible: " + std::to_string(surfaceNode.GetRenderProperties().GetVisible());
    out += ", " + surfaceNode.GetVisibleRegion().GetRegionInfo();
    out += ", OcclusionBg: " + std::to_string(surfaceNode.GetAbilityBgAlpha());
    out += ", Properties: " + node.GetRenderProperties().Dump();
    return out;
}

// RSAnimationManager
void RSProfiler::FilterAnimationForPlayback(RSAnimationManager& manager)
{
    EraseIf(manager.animations_, [](const auto& pair) -> bool {
        if (!Utils::IsNodeIdPatched(pair.first)) {
            return false;
        }
        pair.second->Finish();
        pair.second->Detach();
        return true;
    });
}

void RSProfiler::SetTransactionTimeCorrection(double replayStartTime, double recordStartTime)
{
    g_transactionTimeCorrection = static_cast<int64_t>((replayStartTime - recordStartTime) * NS_TO_S);
    g_replayStartTimeNano = replayStartTime * NS_TO_S;
}

std::string RSProfiler::GetParcelCommandList()
{
    const std::lock_guard<std::mutex> guard(g_mutexCommandOffsets);
    if (g_parcelNumber2Offset.size()) {
        const auto it = g_parcelNumber2Offset.begin();
        std::stringstream stream(std::ios::in | std::ios::out | std::ios::binary);
        stream.write(reinterpret_cast<const char*>(&it->first), sizeof(it->first));
        stream.write(reinterpret_cast<const char*>(it->second.data()), it->second.size() * sizeof(uint32_t));
        g_parcelNumber2Offset.erase(it);
        return stream.str();
    }
    return "";
}

void RSProfiler::PushOffset(std::vector<uint32_t>& commandOffsets, uint32_t offset)
{
    if (!IsEnabled()) {
        return;
    }
    if (IsWriteMode()) {
        commandOffsets.push_back(offset);
    }
}

void RSProfiler::TransactionUnmarshallingStart(const Parcel& parcel, uint32_t parcelNumber)
{
    std::stringstream stream(std::ios::in | std::ios::out | std::ios::binary);
    stream.write(reinterpret_cast<const char*>(&parcelNumber), sizeof(parcelNumber));
    SendRSLogBase(RSProfilerLogType::PARCEL_UNMARSHALLING_START, stream.str());
}

void RSProfiler::PushOffsets(const Parcel& parcel, uint32_t parcelNumber, std::vector<uint32_t>& commandOffsets)
{
    if (!IsEnabled()) {
        return;
    }
    if (!parcelNumber) {
        return;
    }
    if (IsWriteMode()) {
        const std::lock_guard<std::mutex> guard(g_mutexCommandOffsets);
        g_parcelNumber2Offset[parcelNumber] = commandOffsets;

        std::stringstream stream(std::ios::in | std::ios::out | std::ios::binary);
        stream.write(reinterpret_cast<const char*>(&parcelNumber), sizeof(parcelNumber));
        stream.write(reinterpret_cast<const char*>(commandOffsets.data()), commandOffsets.size() * sizeof(uint32_t));
        SendRSLogBase(RSProfilerLogType::PARCEL_UNMARSHALLING_END, stream.str());
    }
}

void RSProfiler::PatchCommand(const Parcel& parcel, RSCommand* command)
{
    if (!IsEnabled()) {
        return;
    }
    if (command == nullptr) {
        return;
    }

    if (command && IsParcelMock(parcel)) {
        command->Patch(Utils::PatchNodeId);
    }
    
    if (IsWriteMode()) {
        g_commandCount++;
        MarshallingTouch(command->GetNodeId());
    }
}

void RSProfiler::MarshallingTouch(NodeId nodeId)
{
    auto job = g_marshallingJob;
    if (job && job->GetUnfinishedCount() && job->marshallingTick) {
        job->marshallingTick(nodeId, false);
    }
}

void RSProfiler::ExecuteCommand(const RSCommand* command)
{
    if (!IsEnabled()) {
        return;
    }
    if (!IsWriteMode() && !IsReadMode()) {
        return;
    }
    if (command == nullptr) {
        return;
    }

    g_commandExecuteCount++;
}

uint32_t RSProfiler::PerfTreeFlatten(const std::shared_ptr<RSRenderNode> node,
    std::vector<std::pair<NodeId, uint32_t>>& nodeSet,
    std::unordered_map<NodeId, uint32_t>& mapNode2Count, uint32_t depth)
{
    if (!node) {
        return 0;
    }

    constexpr uint32_t depthToAnalyze = 10;
    uint32_t drawCmdListCount = CalcNodeCmdListCount(*node);
    if (node->GetSortedChildren()) {
        uint32_t valuableChildrenCount = 0;
        for (auto& child : *node->GetSortedChildren()) {
            if (child && child->GetType() != RSRenderNodeType::EFFECT_NODE && depth < depthToAnalyze) {
                nodeSet.emplace_back(child->id_, depth + 1);
            }
        }
        for (auto& child : *node->GetSortedChildren()) {
            if (child) {
                drawCmdListCount += PerfTreeFlatten(child, nodeSet, mapNode2Count, depth + 1);
                valuableChildrenCount++;
            }
        }
    }

    if (drawCmdListCount > 0) {
        mapNode2Count[node->id_] = drawCmdListCount;
    }
    return drawCmdListCount;
}

uint32_t RSProfiler::CalcNodeCmdListCount(RSRenderNode& node)
{
    uint32_t nodeCmdListCount = 0;
    for (uint16_t type = 0; type < ModifierNG::MODIFIER_TYPE_COUNT; type++) {
        auto slot = node.GetModifiersNG(static_cast<ModifierNG::RSModifierType>(type));
        if (slot.empty()) {
            continue;
        }
        if (!slot[0]->IsCustom()) {
            continue;
        }
        for (auto& modifier : slot) {
            std::shared_ptr<RSRenderProperty<Drawing::DrawCmdListPtr>> propertyPtr = nullptr;
            if (modifier != nullptr) {
                propertyPtr = std::static_pointer_cast<RSRenderProperty<Drawing::DrawCmdListPtr>>(
                    modifier->GetProperty(ModifierNG::ModifierTypeConvertor::GetPropertyType(modifier->GetType())));
            }
            auto propertyValue = propertyPtr ? propertyPtr->Get() : nullptr;
            if (propertyValue && propertyValue->GetOpItemSize() > 0) {
                nodeCmdListCount = 1;
            }
        }
    }
    return nodeCmdListCount;
}

void RSProfiler::MarshalDrawingImage(std::shared_ptr<Drawing::Image>& image,
    std::shared_ptr<Drawing::Data>& compressData)
{
    if (IsEnabled() && !IsSharedMemoryEnabled()) {
        image = nullptr;
        compressData = nullptr;
    }
}

void RSProfiler::EnableBetaRecord()
{
    RSSystemProperties::SetBetaRecordingMode(1);
}

bool RSProfiler::IsBetaRecordSavingTriggered()
{
    constexpr uint32_t savingMode = 2u;
    return RSSystemProperties::GetBetaRecordingMode() == savingMode;
}

bool RSProfiler::IsBetaRecordEnabledWithMetrics()
{
    constexpr uint32_t metricsMode = 3u;
    return RSSystemProperties::GetBetaRecordingMode() == metricsMode;
}

void RSProfiler::SetDrawingCanvasNodeRedraw(bool enable)
{
    dcnRedraw_ = enable && IsEnabled();
}

void RSProfiler::DrawingNodeAddClearOp(const std::shared_ptr<Drawing::DrawCmdList>& drawCmdList)
{
    if (dcnRedraw_ || !drawCmdList) {
        return;
    }
    drawCmdList->ClearOp();
}

void RSProfiler::SetRenderNodeKeepDrawCmd(bool enable)
{
    renderNodeKeepDrawCmdList_ = enable && IsEnabled();
}

void RSProfiler::KeepDrawCmd(bool& drawCmdListNeedSync)
{
    drawCmdListNeedSync = !renderNodeKeepDrawCmdList_;
}

static uint64_t NewAshmemDataCacheId()
{
    static std::atomic_uint32_t id = 0u;
    return Utils::ComposeDataId(Utils::GetPid(), id++);
}

static void CacheAshmemData(uint64_t id, const uint8_t* data, size_t size)
{
    if (RSProfiler::IsWriteMode() && data && (size > 0)) {
        Image ashmem;
        ashmem.data.insert(ashmem.data.end(), data, data + size);
        ImageCache::Add(id, std::move(ashmem));
    }
}

static const uint8_t* GetCachedAshmemData(uint64_t id)
{
    const auto ashmem = RSProfiler::IsReadMode() ? ImageCache::Get(id) : nullptr;
    return ashmem ? ashmem->data.data() : nullptr;
}

void RSProfiler::WriteParcelData(Parcel& parcel)
{
    bool isClientEnabled = RSSystemProperties::GetProfilerEnabled();
    if (!parcel.WriteBool(isClientEnabled)) {
        HRPE("Unable to write is_client_enabled");
        return;
    }

    if (!isClientEnabled) {
        return;
    }

    if (!parcel.WriteUint64(NewAshmemDataCacheId())) {
        HRPE("Unable to write NewAshmemDataCacheId failed");
        return;
    }
}

const void* RSProfiler::ReadParcelData(Parcel& parcel, size_t size, bool& isMalloc)
{
    bool isClientEnabled = false;
    if (!parcel.ReadBool(isClientEnabled)) {
        HRPE("Unable to read is_client_enabled");
        return nullptr;
    }
    if (!isClientEnabled) {
        return RSMarshallingHelper::ReadFromAshmem(parcel, size, isMalloc);
    }

    const uint64_t id = parcel.ReadUint64();
    if (auto data = GetCachedAshmemData(id)) {
        constexpr uint32_t skipBytes = 24u;
        parcel.SkipBytes(skipBytes);
        isMalloc = false;
        return data;
    }

    auto data = RSMarshallingHelper::ReadFromAshmem(parcel, size, isMalloc);
    CacheAshmemData(id, reinterpret_cast<const uint8_t*>(data), size);
    return data;
}

bool RSProfiler::SkipParcelData(Parcel& parcel, size_t size)
{
    bool isClientEnabled = false;
    if (!parcel.ReadBool(isClientEnabled)) {
        HRPE("RSProfiler::SkipParcelData read isClientEnabled failed");
        return false;
    }
    if (!isClientEnabled) {
        return false;
    }

    [[maybe_unused]] const uint64_t id = parcel.ReadUint64();

    if (IsReadMode()) {
        constexpr uint32_t skipBytes = 24u;
        parcel.SkipBytes(skipBytes);
        return true;
    }

    return false;
}

uint32_t RSProfiler::GetNodeDepth(const std::shared_ptr<RSRenderNode> node)
{
    uint32_t depth = 0;
    for (auto curNode = node; curNode != nullptr; depth++) {
        curNode = curNode ? curNode->GetParent().lock() : nullptr;
    }
    return depth;
}

std::string RSProfiler::ReceiveMessageBase()
{
    const std::lock_guard<std::mutex> guard(g_msgBaseMutex);
    if (g_msgBaseList.empty()) {
        return "";
    }
    std::string value = g_msgBaseList.front();
    g_msgBaseList.pop();
    return value;
}

void RSProfiler::SendMessageBase(const std::string& msg)
{
    const std::lock_guard<std::mutex> guard(g_msgBaseMutex);
    g_msgBaseList.push(msg);
}

std::unordered_map<AnimationId, std::vector<int64_t>>& RSProfiler::AnimeGetStartTimes()
{
    return g_animeStartMap;
}

void RSProfiler::ReplayFixTrIndex(uint64_t curIndex, uint64_t& lastIndex)
{
    if (!IsEnabled()) {
        return;
    }
    if (IsReadMode()) {
        if (lastIndex == 0) {
            lastIndex = curIndex - 1;
        }
    }
}

int64_t RSProfiler::AnimeSetStartTime(AnimationId id, int64_t nanoTime)
{
    if (!IsEnabled()) {
        return nanoTime;
    }

    if (IsReadMode()) {
        if (!g_animeStartMap.count(id)) {
            return nanoTime;
        }
        int64_t minDt = INT64_MAX, minTime = nanoTime - g_replayStartTimeNano;
        for (const auto recordedTime : g_animeStartMap[id]) {
            int64_t dt = abs(recordedTime - (nanoTime - g_replayStartTimeNano));
            if (dt < minDt) {
                minDt = dt;
                minTime = recordedTime;
            }
        }
        return minTime + g_replayStartTimeNano;
    } else if (IsWriteMode()) {
        if (g_animeStartMap.count(id)) {
            g_animeStartMap[Utils::PatchNodeId(id)].push_back(nanoTime);
        } else {
            std::vector<int64_t> list;
            list.push_back(nanoTime);
            g_animeStartMap.insert({ Utils::PatchNodeId(id), list });
        }
    }

    return nanoTime;
}

bool RSProfiler::ProcessAddChild(RSRenderNode* parent, RSRenderNode::SharedPtr child, int index)
{
    if (!parent || !child || !IsEnabled()) {
        return false;
    }
    if (!IsReadMode()) {
        return false;
    }

    if (parent->GetType() == RSRenderNodeType::SCREEN_NODE &&
        ! (child->GetId() & Utils::ComposeNodeId(Utils::GetMockPid(0), 0))) {
        // BLOCK LOCK-SCREEN ATTACH TO SCREEN
        g_childOfDisplayNodesPostponed.clear();
        g_childOfDisplayNodesPostponed.emplace_back(child);
        return true;
    }
    return false;
}

std::vector<RSRenderNode::WeakPtr>& RSProfiler::GetChildOfDisplayNodesPostponed()
{
    return g_childOfDisplayNodesPostponed;
}

void RSProfiler::RequestRecordAbort()
{
    recordAbortRequested_ = true;
}

bool RSProfiler::IsRecordAbortRequested()
{
    return recordAbortRequested_;
}

bool RSProfiler::BaseSetPlaybackSpeed(double speed)
{
    float invSpeed = 1.0f;
    if (speed <= .0f) {
        return false;
    } else {
        invSpeed /= speed > 0.0f ? speed : 1.0f;
    }

    if (IsReadMode()) {
        if (Utils::Now() >= g_pauseAfterTime && g_pauseAfterTime > 0) {
            // paused can change speed but need adjust start time then
            int64_t curTime = static_cast<int64_t>(g_pauseAfterTime) - g_pauseCumulativeTime - g_replayStartTimeNano;
            g_pauseCumulativeTime = static_cast<int64_t>(g_pauseAfterTime) - g_replayStartTimeNano -
                    curTime * g_replaySpeed * invSpeed;
            g_replaySpeed = speed;
            return true;
        }
        // change of speed when replay in progress is not possible
        return false;
    }
    g_replaySpeed = speed;
    return true;
}

double RSProfiler::BaseGetPlaybackSpeed()
{
    return g_replaySpeed;
}

void RSProfiler::MarshalSubTreeLo(RSContext& context, std::stringstream& data,
    const RSRenderNode& node, uint32_t fileVersion)
{
    NodeId nodeId = node.GetId();
    data.write(reinterpret_cast<const char*>(&nodeId), sizeof(nodeId));

    MarshalNode(node, data, fileVersion);

    const uint32_t count = node.children_.size();
    data.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& child : node.children_) {
        if (auto childNode = child.lock().get()) {
            MarshalSubTreeLo(context, data, *childNode, fileVersion);
        }
    }
}

std::string RSProfiler::UnmarshalSubTreeLo(RSContext& context, std::stringstream& data,
    RSRenderNode& attachNode, uint32_t fileVersion)
{
    NodeId nodeId;
    data.read(reinterpret_cast<char*>(&nodeId), sizeof(nodeId));

    std::string errorReason = UnmarshalNode(context, data, fileVersion);
    if (errorReason.size()) {
        return errorReason;
    }

    auto node = context.GetMutableNodeMap().GetRenderNode(Utils::PatchNodeId(nodeId));
    if (!node) {
        return "Failed to create node";
    }

    attachNode.AddChild(node);

    uint32_t childCount;
    data.read(reinterpret_cast<char*>(&childCount), sizeof(childCount));
    for (uint32_t i = 0; i < childCount; i++) {
        errorReason = UnmarshalSubTreeLo(context, data, *node, fileVersion);
        if (errorReason.size()) {
            return errorReason;
        }
    }
    return errorReason;
}

TextureRecordType RSProfiler::GetTextureRecordType()
{
    if (IsBetaRecordEnabled() || g_marshalFirstFrameThread) {
        return TextureRecordType::ONE_PIXEL;
    }
    return g_textureRecordType;
}

void RSProfiler::SetTextureRecordType(TextureRecordType type)
{
    g_textureRecordType = type;
}

bool RSProfiler::IfNeedToSkipDuringReplay(Parcel& parcel, uint32_t skipBytes)
{
    if (!IsEnabled()) {
        return false;
    }
    if (!IsParcelMock(parcel)) {
        return false;
    }
    if (IsReadEmulationMode() || IsReadMode()) {
        parcel.SkipBytes(skipBytes);
        return true;
    }
    return false;
}

bool RSProfiler::IsFirstFrameParcel(const Parcel& parcel)
{
    if (!IsEnabled()) {
        return false;
    }
    if (!IsBetaRecordEnabled()) {
        return false;
    }
    return IsWriteEmulationMode() || IsReadEmulationMode();
}

std::shared_ptr<ProfilerMarshallingJob>& RSProfiler::GetMarshallingJob()
{
    return g_marshallingJob;
}

void RSProfiler::SetMarshalFirstFrameThreadFlag(bool flag)
{
    g_marshalFirstFrameThread = flag;
}

bool RSProfiler::GetMarshalFirstFrameThreadFlag()
{
    return g_marshalFirstFrameThread;
}

void RSProfiler::SurfaceOnDrawMatchOptimize(bool& useNodeMatchOptimize)
{
    if (!IsEnabled()) {
        return;
    }
    if (IsReadEmulationMode() || IsReadMode()) {
        useNodeMatchOptimize = true;
    }
}

void RSProfiler::MetricRenderNodeInc(bool isOnTree)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }
    if (isOnTree) {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_ONTREE_NODE_COUNT, 1);
    } else {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_OFFTREE_NODE_COUNT, 1);
    }
}

void RSProfiler::MetricRenderNodeDec(bool isOnTree)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }
    if (isOnTree) {
        GetCustomMetrics().SubInt(RSPROFILER_METRIC_ONTREE_NODE_COUNT, 1);
    } else {
        GetCustomMetrics().SubInt(RSPROFILER_METRIC_OFFTREE_NODE_COUNT, 1);
    }
}

void RSProfiler::MetricRenderNodeChange(bool isOnTree)
{
    if (!IsEnabled() || !IsWriteMode()) {
        return;
    }
    if (isOnTree) {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_ONTREE_NODE_COUNT, 1);
        GetCustomMetrics().SubInt(RSPROFILER_METRIC_OFFTREE_NODE_COUNT, 1);
    } else {
        GetCustomMetrics().AddInt(RSPROFILER_METRIC_OFFTREE_NODE_COUNT, 1);
        GetCustomMetrics().SubInt(RSPROFILER_METRIC_ONTREE_NODE_COUNT, 1);
    }
}

void RSProfiler::MetricRenderNodeInit(RSContext* context)
{
    if (!context) {
        return;
    }
    GetCustomMetrics().SetZero(RSPROFILER_METRIC_ONTREE_NODE_COUNT);
    GetCustomMetrics().SetZero(RSPROFILER_METRIC_OFFTREE_NODE_COUNT);
    auto globalRootNodeId = context->GetGlobalRootRenderNode()->GetId();
    auto& nodeMap = context->GetMutableNodeMap();
    nodeMap.TraversalNodes([globalRootNodeId](const std::shared_ptr<RSBaseRenderNode>& node) {
        if (node == nullptr) {
            return;
        }
        auto parentPtr = node->GetParent().lock();
        for (; parentPtr && parentPtr->GetId() != globalRootNodeId; parentPtr = parentPtr->GetParent().lock())
            ;
        if (parentPtr != nullptr) {
            GetCustomMetrics().AddInt(RSPROFILER_METRIC_ONTREE_NODE_COUNT, 1);
        } else {
            GetCustomMetrics().AddInt(RSPROFILER_METRIC_OFFTREE_NODE_COUNT, 1);
        }
    });
}

void RSProfiler::RSLogOutput(RSProfilerLogType type, const char* format, va_list argptr)
{
    if (!IsEnabled() || !(IsWriteMode() || IsReadEmulationMode())) {
        return;
    }

    // no access to vsnprintf_s_p in inner api of hilog - have to write naive code myself
    constexpr int maxSize = 1024;
    char format2[maxSize] = {0}; // zero ending always present
    const char* ptr1 = format;
    char* ptr2 = format2;
    const auto effectiveSize = maxSize - 3; // max 3 chars can be added in one iteration
    constexpr int publicLen = 8; // publicLen = strlen("{public}");
    for (; *ptr1 && ptr2 - format2 < effectiveSize && ptr1 - format < effectiveSize - publicLen;) {
        if (*ptr1 == '%') {
            if (*(ptr1 + 1) == '%') {
                // %% translates to %%
                *ptr2++ = *ptr1++;
                *ptr2++ = *ptr1++;
            } else if (!memcmp(ptr1 + 1, "{public}", publicLen)) {
                // %{public} translates to %
                *ptr2++ = *ptr1++;
                ptr1 += publicLen;
            } else {
                // abcd%{private} translates to abcd{private} - all subsequent vars are skipped
                strcat_s(ptr2, effectiveSize - (ptr2 - format2), "{private}");
                ptr2 = format2 + strlen(format2);
                break;
            }
        } else {
            // other symbols are just copied
            *ptr2++ = *ptr1++;
        }
    }
    *ptr2++ = 0;

    char outStr[maxSize] = {0};
    if (vsprintf_s(outStr, sizeof(outStr), format2, argptr) > 0) {
        SendRSLogBase(type, std::string(outStr));
    }
}

RSProfilerLogMsg RSProfiler::ReceiveRSLogBase()
{
    const std::lock_guard<std::mutex> guard(g_rsLogListMutex);
    if (g_rsLogList.empty()) {
        return RSProfilerLogMsg();
    }
    auto value = g_rsLogList.front();
    g_rsLogList.pop();
    return value;
}

void RSProfiler::SendRSLogBase(RSProfilerLogType type, const std::string& msg)
{
    if (IsReadEmulationMode()) {
        if (type == RSProfilerLogType::WARNING) {
            RSProfiler::SendMessageBase("RS_LOGW: " + msg);
        } else if (type == RSProfilerLogType::ERROR) {
            RSProfiler::SendMessageBase("RS_LOGE: " + msg);
        }
    } else {
        const std::lock_guard<std::mutex> guard(g_rsLogListMutex);
        g_rsLogList.push(RSProfilerLogMsg(type, Utils::Now(), msg));
    }
}

void RSProfiler::ResetCustomMetrics()
{
    RSProfilerCustomMetrics& customMetrics = GetCustomMetrics();
    customMetrics.Reset();
}

RSProfilerCustomMetrics& RSProfiler::GetCustomMetrics()
{
    static RSProfilerCustomMetrics s_customMetrics;
    return s_customMetrics;
}

bool RSProfiler::IsRecordingMode()
{
    return IsEnabled() && IsWriteMode();
}

} // namespace OHOS::Rosen
