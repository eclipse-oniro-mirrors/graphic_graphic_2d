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

#include "rs_render_service_connection.h"
#include "rs_profiler.h"
#include <string>

#include "frame_report.h"
#include "hgm_command.h"
#include "hgm_core.h"
#include "hgm_frame_rate_manager.h"
#include "offscreen_render/rs_offscreen_render_thread.h"
#include "rs_frame_report.h"
#include "rs_main_thread.h"
#include "rs_trace.h"
#include "rs_profiler.h"
//blur predict
#include "rs_frame_blur_predict.h"
#include "system/rs_system_parameters.h"

#include "command/rs_command_verify_helper.h"
#include "command/rs_display_node_command.h"
#include "command/rs_surface_node_command.h"
#include "common/rs_background_thread.h"
#include "dirty_region/rs_gpu_dirty_collector.h"
#include "dirty_region/rs_optimize_canvas_dirty_collector.h"
#include "display_engine/rs_luminance_control.h"
#include "drawable/rs_canvas_drawing_render_node_drawable.h"
#include "feature/capture/rs_ui_capture.h"
#include "feature/capture/rs_uni_ui_capture.h"
#include "feature/capture/rs_surface_capture_task.h"
#include "feature/capture/rs_ui_capture_task_parallel.h"
#include "feature/capture/rs_ui_capture_solo_task_parallel.h"
#include "feature/capture/rs_surface_capture_task_parallel.h"
#include "feature/uifirst/rs_uifirst_frame_rate_control.h"
#include "gfx/fps_info/rs_surface_fps_manager.h"
#include "gfx/first_frame_notifier/rs_first_frame_notifier.h"
#ifdef RS_ENABLE_OVERLAY_DISPLAY
#include "feature/overlay_display/rs_overlay_display_manager.h"
#endif
#include "info_collection/rs_hdr_collection.h"
#ifdef RS_ENABLE_GPU
#include "feature/uifirst/rs_sub_thread_manager.h"
#endif
#include "feature/uifirst/rs_uifirst_manager.h"
#include "memory/rs_memory_manager.h"
#include "monitor/self_drawing_node_monitor.h"
#include "pipeline/rs_canvas_drawing_render_node.h"
#include "pipeline/rs_pointer_window_manager.h"
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
#include "pipeline/magic_pointer_render/rs_magic_pointer_render_manager.h"
#endif
#include "pipeline/hardware_thread/rs_realtime_refresh_rate_manager.h"
#include "feature/hyper_graphic_manager/rs_render_frame_rate_linker_map.h"
#include "pipeline/rs_render_node_gc.h"
#include "pipeline/rs_render_node_map.h"
#include "pipeline/main_thread/rs_render_service_listener.h"
#include "pipeline/rs_surface_buffer_callback_manager.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_task_dispatcher.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "pixel_map_from_surface.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#include "platform/ohos/rs_jank_stats_helper.h"
#include "render/rs_typeface_cache.h"
#include "transaction/rs_unmarshal_thread.h"
#include "transaction/rs_transaction_data_callback_manager.h"
#include "graphic_feature_param_manager.h"

#ifdef TP_FEATURE_ENABLE
#include "screen_manager/touch_screen.h"
#endif

#ifdef RS_ENABLE_VK
#include "platform/ohos/backend/rs_vulkan_context.h"
#endif

#if defined(RS_ENABLE_DVSYNC)
#include "dvsync.h"
#endif

#undef LOG_TAG
#define LOG_TAG "RSRenderServiceConnection"

#include "app_mgr_client.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr int SLEEP_TIME_US = 1000;
const std::string REGISTER_NODE = "RegisterNode";
const std::string APS_SET_VSYNC = "APS_SET_VSYNC";
constexpr uint32_t MEM_BYTE_TO_MB = 1024 * 1024;
constexpr uint32_t PIDLIST_SIZE_MAX = 128;
constexpr uint64_t MAX_TIME_OUT_NS = 1e9;
constexpr int64_t MAX_FREEZE_SCREEN_TIME = 3000;
const std::string UNFREEZE_SCREEN_TASK_NAME = "UNFREEZE_SCREEN_TASK";
}
// we guarantee that when constructing this object,
// all these pointers are valid, so will not check them.
RSRenderServiceConnection::RSRenderServiceConnection(
    pid_t remotePid,
    wptr<RSRenderService> renderService,
    RSMainThread* mainThread,
    sptr<RSScreenManager> screenManager,
    sptr<IRemoteObject> token,
    sptr<VSyncDistributor> distributor)
    : remotePid_(remotePid),
      renderService_(renderService),
      mainThread_(mainThread),
#ifdef RS_ENABLE_GPU
      renderThread_(RSUniRenderThread::Instance()),
#endif
      screenManager_(screenManager),
      token_(token),
      connDeathRecipient_(new RSConnectionDeathRecipient(this)),
      applicationDeathRecipient_(new RSApplicationRenderThreadDeathRecipient(this)),
      appVSyncDistributor_(distributor)
{
    if (token_ == nullptr || !token_->AddDeathRecipient(connDeathRecipient_)) {
        RS_LOGW("RSRenderServiceConnection: Failed to set death recipient.");
    }
    if (renderService_ == nullptr) {
        RS_LOGW("RSRenderServiceConnection: renderService_ is nullptr");
    }
    if (mainThread_ == nullptr) {
        RS_LOGW("RSRenderServiceConnection: mainThread_ is nullptr");
    }
    if (screenManager_ == nullptr) {
        RS_LOGW("RSRenderServiceConnection: screenManager_ is nullptr");
    }
    if (appVSyncDistributor_ == nullptr) {
        RS_LOGW("RSRenderServiceConnection: appVSyncDistributor_ is nullptr");
    }
}

RSRenderServiceConnection::~RSRenderServiceConnection() noexcept
{
    RS_LOGI("~RSRenderServiceConnection remotePid:%{public}d", remotePid_);
    if (token_ && connDeathRecipient_) {
        token_->RemoveDeathRecipient(connDeathRecipient_);
    }
    CleanAll();
}

void RSRenderServiceConnection::CleanVirtualScreens() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (screenManager_ != nullptr) {
        for (const auto id : virtualScreenIds_) {
            screenManager_->RemoveVirtualScreen(id);
        }
    }
    virtualScreenIds_.clear();

    if (screenChangeCallback_ != nullptr && screenManager_ != nullptr) {
        screenManager_->RemoveScreenChangeCallback(screenChangeCallback_);
        screenChangeCallback_ = nullptr;
    }
}

void RSRenderServiceConnection::CleanRenderNodes() noexcept
{
    if (mainThread_ == nullptr) {
        return;
    }
    auto& context = mainThread_->GetContext();
    auto& nodeMap = context.GetMutableNodeMap();
    MemoryTrack::Instance().RemovePidRecord(remotePid_);

    RS_PROFILER_KILL_PID(remotePid_);
    nodeMap.FilterNodeByPid(remotePid_);
    RS_PROFILER_KILL_PID_END();
}

void RSRenderServiceConnection::CleanFrameRateLinkers() noexcept
{
    if (mainThread_ == nullptr) {
        return;
    }
    auto& context = mainThread_->GetContext();
    auto& frameRateLinkerMap = context.GetMutableFrameRateLinkerMap();

    frameRateLinkerMap.FilterFrameRateLinkerByPid(remotePid_);
}

void RSRenderServiceConnection::CleanAll(bool toDelete) noexcept
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cleanDone_) {
            return;
        }
    }
    if (!mainThread_) {
        return;
    }
    RS_LOGD("CleanAll() start.");
    RS_TRACE_NAME("RSRenderServiceConnection CleanAll begin, remotePid: " + std::to_string(remotePid_));
    RsCommandVerifyHelper::GetInstance().RemoveCntWithPid(remotePid_);
    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this)]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (!connection) {
                return;
            }
            RS_TRACE_NAME_FMT("CleanVirtualScreens %d", connection->remotePid_);
            connection->CleanVirtualScreens();
        }).wait();
    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this)]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (!connection) {
                return;
            }
            RS_TRACE_NAME_FMT("CleanRenderNodes %d", connection->remotePid_);
            connection->CleanRenderNodes();
            connection->CleanFrameRateLinkers();
            connection->CleanBrightnessInfoChangeCallbacks();
        }).wait();
    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this)]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return;
            }
            RS_TRACE_NAME_FMT("ClearTransactionDataPidInfo %d", connection->remotePid_);
            connection->mainThread_->ClearTransactionDataPidInfo(connection->remotePid_);
        }).wait();
    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this)]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return;
            }
            RS_TRACE_NAME_FMT("UnRegisterCallback %d", connection->remotePid_);
            connection->mainThread_->UnRegisterOcclusionChangeCallback(connection->remotePid_);
            connection->mainThread_->ClearSurfaceOcclusionChangeCallback(connection->remotePid_);
            connection->mainThread_->UnRegisterUIExtensionCallback(connection->remotePid_);
        }).wait();

    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this)]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return;
            }
            connection->mainThread_->ClearSurfaceWatermark(connection->remotePid_);
        }).wait();
    if (SelfDrawingNodeMonitor::GetInstance().IsListeningEnabled()) {
        mainThread_->ScheduleTask(
            [weakThis = wptr<RSRenderServiceConnection>(this)]() {
                sptr<RSRenderServiceConnection> connection = weakThis.promote();
                if (connection == nullptr) {
                    return;
                }
                auto &monitor = SelfDrawingNodeMonitor::GetInstance();
                monitor.UnRegisterRectChangeCallback(connection->remotePid_);
            }).wait();
    }
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(remotePid_);
    HgmTaskHandleThread::Instance().ScheduleTask([pid = remotePid_] () {
        RS_TRACE_NAME_FMT("CleanHgmEvent %d", pid);
        HgmConfigCallbackManager::GetInstance()->UnRegisterHgmConfigChangeCallback(pid);
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr != nullptr) {
            frameRateMgr->CleanVote(pid);
        }
    }).wait();
    RSTypefaceCache::Instance().RemoveDrawingTypefacesByPid(remotePid_);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanDone_ = true;
    }

    if (toDelete) {
        if (auto renderService = renderService_.promote()) {
            auto token = iface_cast<RSIConnectionToken>(GetToken());
            renderService->RemoveConnection(token);
        } else {
            RS_LOGW("CleanAll() RenderService is dead.");
        }
    }

    {
        std::lock_guard<std::mutex> lock(pidToBundleMutex_);
        pidToBundleName_.clear();
    }

    RS_LOGD("CleanAll() end.");
    RS_TRACE_NAME("RSRenderServiceConnection CleanAll end, remotePid: " + std::to_string(remotePid_));
}

RSRenderServiceConnection::RSConnectionDeathRecipient::RSConnectionDeathRecipient(
    wptr<RSRenderServiceConnection> conn) : conn_(conn)
{
}

void RSRenderServiceConnection::RSConnectionDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& token)
{
    auto tokenSptr = token.promote();
    if (tokenSptr == nullptr) {
        RS_LOGW("RSConnectionDeathRecipient::OnRemoteDied: can't promote remote object.");
        return;
    }

    auto rsConn = conn_.promote();
    if (rsConn == nullptr) {
        RS_LOGW("RSConnectionDeathRecipient::OnRemoteDied: RSRenderServiceConnection was dead, do nothing.");
        return;
    }

    if (rsConn->GetToken() != tokenSptr) {
        RS_LOGI("RSConnectionDeathRecipient::OnRemoteDied: token doesn't match, ignore it.");
        return;
    }

    rsConn->CleanAll(true);
}

RSRenderServiceConnection::RSApplicationRenderThreadDeathRecipient::RSApplicationRenderThreadDeathRecipient(
    wptr<RSRenderServiceConnection> conn) : conn_(conn)
{}

void RSRenderServiceConnection::RSApplicationRenderThreadDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& token)
{
    auto tokenSptr = token.promote();
    if (tokenSptr == nullptr) {
        RS_LOGW("RSApplicationRenderThreadDeathRecipient::OnRemoteDied: can't promote remote object.");
        return;
    }

    auto rsConn = conn_.promote();
    if (rsConn == nullptr) {
        RS_LOGW("RSApplicationRenderThreadDeathRecipient::OnRemoteDied: "
            "RSRenderServiceConnection was dead, do nothing.");
        return;
    }

    RS_LOGD("RSApplicationRenderThreadDeathRecipient::OnRemoteDied: Unregister.");
    auto app = iface_cast<IApplicationAgent>(tokenSptr);
    rsConn->UnRegisterApplicationAgent(app);
}

ErrCode RSRenderServiceConnection::CommitTransaction(std::unique_ptr<RSTransactionData>& transactionData)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    pid_t callingPid = GetCallingPid();
    bool isTokenTypeValid = true;
    bool isNonSystemAppCalling = false;
    RSInterfaceCodeAccessVerifierBase::GetAccessType(isTokenTypeValid, isNonSystemAppCalling);
    bool shouldDrop = RSUnmarshalThread::Instance().ReportTransactionDataStatistics(
        callingPid, transactionData.get(), isNonSystemAppCalling);
    if (shouldDrop) {
        RS_LOGW("CommitTransaction data droped");
        return ERR_INVALID_VALUE;
    }
    if (transactionData && transactionData->GetDVSyncUpdate()) {
        mainThread_->DVSyncUpdate(transactionData->GetDVSyncTime(), transactionData->GetTimestamp());
    }
    bool isProcessBySingleFrame = mainThread_->IsNeedProcessBySingleFrameComposer(transactionData);
    if (isProcessBySingleFrame) {
        mainThread_->ProcessDataBySingleFrameComposer(transactionData);
    } else {
        mainThread_->RecvRSTransactionData(transactionData);
    }
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::ExecuteSynchronousTask(const std::shared_ptr<RSSyncTask>& task)
{
    if (task == nullptr || mainThread_ == nullptr) {
        RS_LOGW("ExecuteSynchronousTask, task or main thread is null!");
        return ERR_INVALID_VALUE;
    }
    // After a synchronous task times out, it will no longer be executed.
    auto isTimeout = std::make_shared<bool>(0);
    std::weak_ptr<bool> isTimeoutWeak = isTimeout;
    std::chrono::nanoseconds span(std::min(task->GetTimeout(), MAX_TIME_OUT_NS));
    mainThread_->ScheduleTask([task, mainThread = mainThread_, isTimeoutWeak] {
        if (task == nullptr || mainThread == nullptr || isTimeoutWeak.expired()) {
            return;
        }
        task->Process(mainThread->GetContext());
    }).wait_for(span);
    isTimeout.reset();
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetUniRenderEnabled(bool& enable)
{
    enable = RSUniRenderJudgement::IsUniRender();
    return  ERR_OK;
}

ErrCode RSRenderServiceConnection::CreateNode(const RSDisplayNodeConfig& displayNodeConfig, NodeId nodeId,
    bool& success)
{
    if (!mainThread_) {
        success = false;
        return ERR_INVALID_VALUE;
    }
    auto node = DisplayNodeCommandHelper::CreateWithConfigInRS(mainThread_->GetContext(), nodeId, displayNodeConfig);
    if (node == nullptr) {
        RS_LOGE("RSRenderService::CreateDisplayNode fail");
        success = false;
        return ERR_INVALID_VALUE;
    }
    std::function<void()> registerNode = [this, nodeId, node, &displayNodeConfig]() {
        if (mainThread_ == nullptr) {
            return;
        }
        RS_LOGI("On registerNode scheduled by mainThread. NodeID: %{public}" PRIu64 ", screenID: %{public}" PRIu64,
                nodeId, displayNodeConfig.screenId);

        auto& context = mainThread_->GetContext();
        auto& nodeMap = context.GetMutableNodeMap();
        nodeMap.RegisterRenderNode(node);
        nodeMap.TraverseScreenNodes([&node, id = node->GetScreenId()](auto& screenNode) {
            if (!screenNode || screenNode->GetScreenId() != id) {
                return;
            }
            screenNode->AddChild(node);
        });

        DisplayNodeCommandHelper::SetDisplayMode(context, nodeId, displayNodeConfig);
    };
    // When the event runner has not started to rotate, synchronous tasks will not be executed,
    // so asynchronous tasks need to be dispatched at this time.
    if (!mainThread_->IsReadyForSyncTask() || !mainThread_->PostSyncTask(registerNode)) {
        RS_LOGW("Post async tasks instead. Sync task processor ready? %{public}d",
                static_cast<int>(mainThread_->IsReadyForSyncTask()));
        mainThread_->PostTask(registerNode);
    }
    success = true;
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::CreateNode(const RSSurfaceRenderNodeConfig& config, bool& success)
{
    if (!mainThread_) {
        success = false;
        return ERR_INVALID_VALUE;
    }
    std::shared_ptr<RSSurfaceRenderNode> node =
        SurfaceNodeCommandHelper::CreateWithConfigInRS(config, mainThread_->GetContext());
    if (node == nullptr) {
        RS_LOGE("RSRenderService::CreateNode fail");
        success = false;
        return ERR_INVALID_VALUE;
    }
    std::function<void()> registerNode = [node, weakThis = wptr<RSRenderServiceConnection>(this)]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        connection->mainThread_->GetContext().GetMutableNodeMap().RegisterRenderNode(node);
    };
    mainThread_->PostTask(registerNode);
    success = true;
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::CreateNodeAndSurface(const RSSurfaceRenderNodeConfig& config,
    sptr<Surface>& sfc, bool unobscured)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    std::shared_ptr<RSSurfaceRenderNode> node =
        SurfaceNodeCommandHelper::CreateWithConfigInRS(config, mainThread_->GetContext(), unobscured);
    if (node == nullptr) {
        RS_LOGE("RSRenderService::CreateNodeAndSurface CreateNode fail");
        return ERR_INVALID_VALUE;
    }
    sptr<IConsumerSurface> surface = IConsumerSurface::Create(config.name);
    if (surface == nullptr) {
        RS_LOGE("RSRenderService::CreateNodeAndSurface get consumer surface fail");
        return ERR_INVALID_VALUE;
    }
    const std::string& surfaceName = surface->GetName();
    RS_LOGI("RsDebug RSRenderService::CreateNodeAndSurface node"
        "id:%{public}" PRIu64 " name:%{public}s surface id:%{public}" PRIu64 " name:%{public}s",
        node->GetId(), node->GetName().c_str(),
        surface->GetUniqueId(), surfaceName.c_str());
    auto defaultUsage = surface->GetDefaultUsage();
    auto nodeId = node->GetId();
    bool isUseSelfDrawBufferUsage = RSSystemProperties::GetSelfDrawingDirtyRegionEnabled() &&
        RSGpuDirtyCollector::GetInstance().IsGpuDirtyEnable(nodeId) &&
        config.nodeType == RSSurfaceNodeType::SELF_DRAWING_NODE;
    if (isUseSelfDrawBufferUsage) {
        defaultUsage |= BUFFER_USAGE_AUXILLARY_BUFFER0;
    }
    surface->SetDefaultUsage(defaultUsage | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_HW_COMPOSER);
    node->GetRSSurfaceHandler()->SetConsumer(surface);
    RSMainThread* mainThread = mainThread_;
    std::function<void()> registerNode = [node, mainThread]() -> void {
        if (auto preNode = mainThread->GetContext().GetNodeMap().GetRenderNode(node->GetId())) {
            if (auto preSurfaceNode = node->ReinterpretCastTo<RSSurfaceRenderNode>()) {
                RS_LOGE("CreateNodeAndSurface same id node:%{public}" PRIu64 ", name:%{public}s, type:%{public}d",
                    node->GetId(), preSurfaceNode->GetName().c_str(), preNode->GetType());
            } else {
                RS_LOGE("CreateNodeAndSurface same id node:%{public}" PRIu64 ", type:%{public}d", node->GetId(),
                    preNode->GetType());
            }
            usleep(SLEEP_TIME_US);
        }
        RS_LOGI("CreateNodeAndSurface RegisterRenderNode id:%{public}" PRIu64 ", name:%{public}s", node->GetId(),
            node->GetName().c_str());
        mainThread->GetContext().GetMutableNodeMap().RegisterRenderNode(node);
    };
    if (config.isSync) {
        mainThread_->PostSyncTask(registerNode);
    } else {
        mainThread_->PostTask(registerNode, REGISTER_NODE, 0, AppExecFwk::EventQueue::Priority::VIP);
    }
    std::weak_ptr<RSSurfaceRenderNode> surfaceRenderNode(node);
    sptr<IBufferConsumerListener> listener = new RSRenderServiceListener(surfaceRenderNode);
    SurfaceError ret = surface->RegisterConsumerListener(listener);
    if (ret != SURFACE_ERROR_OK) {
        RS_LOGE("RSRenderService::CreateNodeAndSurface Register Consumer Listener fail");
        return ERR_INVALID_VALUE;
    }
    sptr<IBufferProducer> producer = surface->GetProducer();
    sfc = Surface::CreateSurfaceAsProducer(producer);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::CreateVSyncConnection(sptr<IVSyncConnection>& vsyncConn,
                                                         const std::string& name,
                                                         const sptr<VSyncIConnectionToken>& token,
                                                         VSyncConnParam vsyncConnParam)
{
    if (mainThread_ == nullptr || appVSyncDistributor_ == nullptr) {
        vsyncConn = nullptr;
        return ERR_INVALID_VALUE;
    }
    uint64_t id = vsyncConnParam.id;
    NodeId windowNodeId = vsyncConnParam.windowNodeId;
    if (vsyncConnParam.fromXcomponent) {
        mainThread_->ScheduleTask([&windowNodeId]() {
            auto& node = RSMainThread::Instance()->GetContext().GetNodeMap()
                        .GetRenderNode<RSRenderNode>(windowNodeId);
            if (node == nullptr) {
                RS_LOGE("CreateVSyncConnection:node is nullptr");
                return;
            }
            windowNodeId = node->GetInstanceRootNodeId();
        }).wait();
    }
    sptr<VSyncConnection> conn = new VSyncConnection(appVSyncDistributor_, name, token->AsObject(), 0, windowNodeId);
    if (ExtractPid(id) == remotePid_) {
        auto observer = [] (const RSRenderFrameRateLinker& linker) {
            if (auto mainThread = RSMainThread::Instance(); mainThread != nullptr) {
                HgmCore::Instance().SetHgmTaskFlag(true);
            }
        };
        mainThread_->ScheduleTask([weakThis = wptr<RSRenderServiceConnection>(this),
            id, observer, name, windowNodeId]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return;
            }
            auto linker = std::make_shared<RSRenderFrameRateLinker>(id, observer);
            linker->SetVsyncName(name);
            linker->SetWindowNodeId(windowNodeId);
            auto& context = connection->mainThread_->GetContext();
            auto& frameRateLinkerMap = context.GetMutableFrameRateLinkerMap();
            frameRateLinkerMap.RegisterFrameRateLinker(linker);
        }).wait();
        conn->id_ = id;
        RS_LOGD("CreateVSyncConnection connect id: %{public}" PRIu64, id);
    }
    auto ret = appVSyncDistributor_->AddConnection(conn, windowNodeId);
    if (ret != VSYNC_ERROR_OK) {
        UnregisterFrameRateLinker(conn->id_);
        vsyncConn = nullptr;
        return ERR_INVALID_VALUE;
    }
    vsyncConn = conn;
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetPixelMapByProcessId(
    std::vector<PixelMapInfo>& pixelMapInfoVector, pid_t pid, int32_t& repCode)
{
    if (mainThread_ == nullptr) {
        repCode = INVALID_ARGUMENTS;
        return ERR_INVALID_VALUE;
    }
    std::vector<std::tuple<sptr<SurfaceBuffer>, std::string, RectI>> sfBufferInfoVector;
    std::function<void()> getSurfaceBufferByPidTask = [weakThis = wptr<RSRenderServiceConnection>(this),
                                                          &sfBufferInfoVector, pid]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        RS_TRACE_NAME_FMT("RSRenderServiceConnection::GetPixelMapByProcessId getSurfaceBufferByPidTask pid: %d", pid);
        auto selfDrawingNodeVector =
            connection->mainThread_->GetContext().GetMutableNodeMap().GetSelfDrawingNodeInProcess(pid);
        for (auto iter = selfDrawingNodeVector.rbegin(); iter != selfDrawingNodeVector.rend(); ++iter) {
            auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(*iter);
            if (auto surfaceNode = node->ReinterpretCastTo<RSSurfaceRenderNode>()) {
                auto surfaceBuffer = surfaceNode->GetRSSurfaceHandler()->GetBuffer();
                auto surfaceBufferInfo = std::make_tuple(surfaceBuffer, surfaceNode->GetName(),
                    surfaceNode->GetRenderProperties().GetBoundsGeometry()->GetAbsRect());
                sfBufferInfoVector.push_back(surfaceBufferInfo);
            }
        }
    };
    mainThread_->PostSyncTask(getSurfaceBufferByPidTask);

    for (uint32_t i = 0; i < sfBufferInfoVector.size(); i++) {
        auto surfaceBuffer = std::get<0>(sfBufferInfoVector[i]);
        const auto surfaceName = std::get<1>(sfBufferInfoVector[i]);
        const auto& absRect = std::get<2>(sfBufferInfoVector[i]);
        if (surfaceBuffer) {
            OHOS::Media::Rect rect = { 0, 0, surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight() };
            std::shared_ptr<Media::PixelMap> pixelmap = nullptr;
            RSBackgroundThread::Instance().PostSyncTask([&surfaceBuffer, rect, &pixelmap]() {
                pixelmap = Rosen::CreatePixelMapFromSurfaceBuffer(surfaceBuffer, rect);
            });
            if (pixelmap) {
                pixelMapInfoVector.emplace_back(PixelMapInfo { pixelmap,
                    { absRect.GetLeft(), absRect.GetTop(), absRect.GetWidth(), absRect.GetHeight(), i },
                    surfaceName,
                    GetRotationInfoFromSurfaceBuffer(surfaceBuffer) });
            } else {
                RS_LOGE("CreatePixelMapFromSurfaceBuffer pixelmap is null, nodeName:%{public}s", surfaceName.c_str());
            }
        } else {
            RS_LOGE("CreatePixelMapFromSurface surfaceBuffer is null, nodeName:%{public}s, rect:%{public}s",
                surfaceName.c_str(), absRect.ToString().c_str());
        }
    }
    repCode = SUCCESS;
    return ERR_OK;
}

float RSRenderServiceConnection::GetRotationInfoFromSurfaceBuffer(const sptr<SurfaceBuffer>& buffer)
{
    if (buffer == nullptr) {
        RS_LOGE("GetRotationInfoFromSurfaceBuffer buffer is null");
        return 0.0f;
    }
    auto transformType = buffer->GetSurfaceBufferTransform();
    if (transformType == GRAPHIC_ROTATE_90) {
        return 90.0f;
    } else if (transformType == GRAPHIC_ROTATE_180) {
        return 180.0f;
    } else if (transformType == GRAPHIC_ROTATE_270) {
        return 270.0f;
    }
    return 0.0f;
}

ErrCode RSRenderServiceConnection::CreatePixelMapFromSurface(sptr<Surface> surface,
    const Rect &srcRect, std::shared_ptr<Media::PixelMap> &pixelMap)
{
    OHOS::Media::Rect rect = {
        .left = srcRect.x,
        .top = srcRect.y,
        .width = srcRect.w,
        .height = srcRect.h,
    };
    RSBackgroundThread::Instance().PostSyncTask([surface, rect, &pixelMap]() {
        pixelMap = Rosen::CreatePixelMapFromSurface(surface, rect);
    });
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetFocusAppInfo(const FocusAppInfo& info, int32_t& repCode)
{
    if (mainThread_ == nullptr) {
        repCode = INVALID_ARGUMENTS;
        return ERR_INVALID_VALUE;
    }
    mainThread_->ScheduleTask(
        [info, mainThread = mainThread_]() {
            // don't use 'this' to get mainThread poninter
            mainThread->SetFocusAppInfo(info);
        }
    );
    repCode = SUCCESS;
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetWatermark(const std::string& name, std::shared_ptr<Media::PixelMap> watermark,
    bool& success)
{
    if (!mainThread_) {
        success = false;
        return ERR_INVALID_VALUE;
    }
    pid_t callingPid = GetCallingPid();
    std::function<void()> task = [weakThis = wptr<RSRenderServiceConnection>(this),
        callingPid, name, watermark]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        connection->mainThread_->SetWatermark(callingPid, name, watermark);
    };
    mainThread_->PostTask(task);
    success = true;
    return ERR_OK;
}

uint32_t RSRenderServiceConnection::SetSurfaceWatermark(pid_t pid, const std::string &name,
    const std::shared_ptr<Media::PixelMap> &watermark,
    const std::vector<NodeId> &nodeIdList, SurfaceWatermarkType watermarkType)
{
    if (!mainThread_) {
        return WATER_MARK_IPC_ERROR;
    }
    auto isSystemCalling = RSInterfaceCodeAccessVerifierBase::IsSystemCalling(
        RSIRenderServiceConnectionInterfaceCodeAccessVerifier::codeEnumTypeName_ +
        "::SET_SURFACE_WATERMARK");
    uint32_t res =  SurfaceWatermarkStatusCode::WATER_MARK_RS_CONNECTION_ERROR;
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), &name, &nodeIdList, &watermark, &watermarkType,
        pid, isSystemCalling, &res]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        res = connection->mainThread_->SetSurfaceWatermark(pid, name, watermark,
            nodeIdList, watermarkType, isSystemCalling);
    };
    mainThread_->PostSyncTask(task);
    return res;
}
    
void RSRenderServiceConnection::ClearSurfaceWatermarkForNodes(pid_t pid, const std::string &name,
    const std::vector<NodeId> &nodeIdList)
{
    if (!mainThread_) {
        return;
    }
    auto isSystemCalling = RSInterfaceCodeAccessVerifierBase::IsSystemCalling(
        RSIRenderServiceConnectionInterfaceCodeAccessVerifier::codeEnumTypeName_ +
        "::CLEAR_SURFACE_WATERMARK_FOR_NODES");
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), &name, pid,
        &nodeIdList, isSystemCalling]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        connection->mainThread_->ClearSurfaceWatermarkForNodes(pid, name, nodeIdList, isSystemCalling);
    };
    mainThread_->PostTask(task);
}
    
void RSRenderServiceConnection::ClearSurfaceWatermark(pid_t pid, const std::string &name)
{
    if (!mainThread_) {
        return;
    }
    auto isSystemCalling = RSInterfaceCodeAccessVerifierBase::IsSystemCalling(
        RSIRenderServiceConnectionInterfaceCodeAccessVerifier::codeEnumTypeName_ +
        "::CLEAR_SURFACE_WATERMARK");
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), &name, pid, isSystemCalling]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        connection->mainThread_->ClearSurfaceWatermark(pid, name, isSystemCalling);
    };
    mainThread_->PostTask(task);
}

ErrCode RSRenderServiceConnection::GetDefaultScreenId(uint64_t& screenId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        screenId = INVALID_SCREEN_ID;
        return ERR_INVALID_VALUE;
    }
    screenId = screenManager_->GetDefaultScreenId();
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetActiveScreenId(uint64_t& screenId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        screenId =  INVALID_SCREEN_ID;
        return ERR_INVALID_VALUE;
    }
    screenId = screenManager_->GetActiveScreenId();
    return ERR_OK;
}

std::vector<ScreenId> RSRenderServiceConnection::GetAllScreenIds()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return std::vector<ScreenId>();
    }
    return screenManager_->GetAllScreenIds();
}

ScreenId RSRenderServiceConnection::CreateVirtualScreen(
    const std::string &name,
    uint32_t width,
    uint32_t height,
    sptr<Surface> surface,
    ScreenId mirrorId,
    int32_t flags,
    std::vector<NodeId> whiteList)
{
    if (whiteList.size() > MAX_WHITE_LIST_NUM) {
        RS_LOGW("%{public}s: white list is over max size!", __func__);
        return INVALID_SCREEN_ID;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto newVirtualScreenId = screenManager_->CreateVirtualScreen(
        name, width, height, surface, mirrorId, flags, whiteList);
    virtualScreenIds_.insert(newVirtualScreenId);
    if (surface != nullptr) {
        EventInfo event = { "VOTER_VIRTUALDISPLAY", ADD_VOTE, OLED_60_HZ, OLED_60_HZ, name };
        NotifyRefreshRateEvent(event);
        ROSEN_LOGI("%{public}s vote 60hz", __func__);
    }
    return newVirtualScreenId;
}

int32_t RSRenderServiceConnection::SetVirtualScreenBlackList(ScreenId id, std::vector<NodeId>& blackListVector)
{
    if (blackListVector.size() > MAX_BLACK_LIST_NUM) {
        RS_LOGW("%{public}s: black list is over max size!", __func__);
        return StatusCode::INVALID_ARGUMENTS;
    }
    if (blackListVector.empty()) {
        RS_LOGW("SetVirtualScreenBlackList blackList is empty.");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->SetVirtualScreenBlackList(id, blackListVector);
}

ErrCode RSRenderServiceConnection::SetVirtualScreenTypeBlackList(
    ScreenId id, std::vector<NodeType>& typeBlackListVector, int32_t& repCode)
{
    if (typeBlackListVector.empty()) {
        RS_LOGW("SetVirtualScreenTypeBlackList typeBlackList is empty.");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        repCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    repCode = screenManager_->SetVirtualScreenTypeBlackList(id, typeBlackListVector);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::AddVirtualScreenBlackList(
    ScreenId id, std::vector<NodeId>& blackListVector, int32_t& repCode)
{
    if (blackListVector.size() > MAX_BLACK_LIST_NUM) {
        RS_LOGW("%{public}s: black list is over max size!", __func__);
        repCode = StatusCode::INVALID_ARGUMENTS;
        return ERR_INVALID_VALUE;
    }
    if (blackListVector.empty()) {
        RS_LOGW("AddVirtualScreenBlackList blackList is empty.");
        repCode = StatusCode::BLACKLIST_IS_EMPTY;
        return ERR_INVALID_VALUE;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        repCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    repCode = screenManager_->AddVirtualScreenBlackList(id, blackListVector);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::RemoveVirtualScreenBlackList(
    ScreenId id, std::vector<NodeId>& blackListVector, int32_t& repCode)
{
    if (blackListVector.empty()) {
        RS_LOGW("RemoveVirtualScreenBlackList blackList is empty.");
        repCode = StatusCode::BLACKLIST_IS_EMPTY;
        return ERR_INVALID_VALUE;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        repCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    repCode = screenManager_->RemoveVirtualScreenBlackList(id, blackListVector);
    return ERR_OK;
}

int32_t RSRenderServiceConnection::SetVirtualScreenSecurityExemptionList(
    ScreenId id,
    const std::vector<NodeId>& securityExemptionList)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->SetVirtualScreenSecurityExemptionList(id, securityExemptionList);
}

int32_t RSRenderServiceConnection::SetScreenSecurityMask(ScreenId id,
    std::shared_ptr<Media::PixelMap> securityMask)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->SetScreenSecurityMask(id, std::move(securityMask));
}

int32_t RSRenderServiceConnection::SetMirrorScreenVisibleRect(ScreenId id, const Rect& mainScreenRect,
    bool supportRotation)
{
    if (screenManager_ == nullptr) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->SetMirrorScreenVisibleRect(id, mainScreenRect, supportRotation);
}

int32_t RSRenderServiceConnection::SetCastScreenEnableSkipWindow(ScreenId id, bool enable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->SetCastScreenEnableSkipWindow(id, enable);
}

int32_t RSRenderServiceConnection::SetVirtualScreenSurface(ScreenId id, sptr<Surface> surface)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->SetVirtualScreenSurface(id, surface);
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
int32_t RSRenderServiceConnection::SetPointerColorInversionConfig(float darkBuffer,
    float brightBuffer, int64_t interval, int32_t rangeSize)
{
    RSMagicPointerRenderManager::GetInstance().SetPointerColorInversionConfig(darkBuffer, brightBuffer,
        interval, rangeSize);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::SetPointerColorInversionEnabled(bool enable)
{
    RSMagicPointerRenderManager::GetInstance().SetPointerColorInversionEnabled(enable);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterPointerLuminanceChangeCallback(
    sptr<RSIPointerLuminanceChangeCallback> callback)
{
    if (!callback) {
        RS_LOGE("RegisterPointerLuminanceChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }
    RSMagicPointerRenderManager::GetInstance().RegisterPointerLuminanceChangeCallback(remotePid_, callback);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::UnRegisterPointerLuminanceChangeCallback()
{
    RSMagicPointerRenderManager::GetInstance().UnRegisterPointerLuminanceChangeCallback(remotePid_);
    return StatusCode::SUCCESS;
}
#endif

void RSRenderServiceConnection::RemoveVirtualScreen(ScreenId id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return;
    }
    screenManager_->RemoveVirtualScreen(id);
    virtualScreenIds_.erase(id);
    EventInfo event = { "VOTER_VIRTUALDISPLAY", REMOVE_VOTE };
    NotifyRefreshRateEvent(event);
}

int32_t RSRenderServiceConnection::SetScreenChangeCallback(sptr<RSIScreenChangeCallback> callback)
{
    if (!callback) {
        RS_LOGE("%{public}s: callback is nullptr", __func__);
        return INVALID_ARGUMENTS;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if (screenChangeCallback_ == callback) {
        RS_LOGE("%{public}s: the callback has been set", __func__);
        return INVALID_ARGUMENTS;
    }
    if (screenManager_ == nullptr) {
        RS_LOGE("%{public}s: screenManager_ is nullptr", __func__);
        return SCREEN_NOT_FOUND;
    }

    if (screenChangeCallback_ != nullptr) {
        // remove the old callback
        RS_LOGW("%{public}s: last screenChangeCallback_ should be removed", __func__);
        screenManager_->RemoveScreenChangeCallback(screenChangeCallback_);
    }

    // update
    int32_t status = screenManager_->AddScreenChangeCallback(callback);
    screenChangeCallback_ = callback;
    return status;
}

int32_t RSRenderServiceConnection::SetScreenSwitchingNotifyCallback(sptr<RSIScreenSwitchingNotifyCallback> callback)
{
    if (screenManager_ == nullptr) {
        RS_LOGE("%{public}s: screenManager_ is nullptr", __func__);
        return SCREEN_NOT_FOUND;
    }

    // update
    int32_t status = screenManager_->SetScreenSwitchingNotifyCallback(callback);
    return status;
}

int32_t RSRenderServiceConnection::SetBrightnessInfoChangeCallback(sptr<RSIBrightnessInfoChangeCallback> callback)
{
    if (mainThread_ == nullptr) {
        return INVALID_ARGUMENTS;
    }
    auto task = [this, &callback]() {
        auto& context = mainThread_->GetContext();
        return context.SetBrightnessInfoChangeCallback(remotePid_, callback);
    };
    return mainThread_->ScheduleTask(task).get();
}

void RSRenderServiceConnection::CleanBrightnessInfoChangeCallbacks() noexcept
{
    if (mainThread_ == nullptr) {
        return;
    }
    auto& context = mainThread_->GetContext();
    context.SetBrightnessInfoChangeCallback(remotePid_, nullptr);
}

int32_t RSRenderServiceConnection::GetBrightnessInfo(ScreenId screenId, BrightnessInfo& brightnessInfo)
{
    brightnessInfo = RSLuminanceControl::Get().GetBrightnessInfo(screenId);
    return StatusCode::SUCCESS;
}

uint32_t RSRenderServiceConnection::SetScreenActiveMode(ScreenId id, uint32_t modeId)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_MANAGER_NULL;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenActiveMode(id, modeId); }).get();
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenActiveMode(id, modeId); }).get();
    }
    return StatusCode::RS_CONNECTION_ERROR;
}

void RSRenderServiceConnection::SetScreenRefreshRate(ScreenId id, int32_t sceneId, int32_t rate)
{
    ROSEN_TRACE_BEGIN(HITRACE_TAG_GRAPHIC_AGP, "RSRenderService::SetScreenRefreshRate");
    HgmTaskHandleThread::Instance().PostTask([id, sceneId, rate] () {
        int32_t setResult = HgmCore::Instance().SetScreenRefreshRate(id, sceneId, rate);
        if (setResult != 0) {
            RS_LOGW("SetScreenRefreshRate request of screen %{public}" PRIu64 " of rate %{public}d is refused",
                id, rate);
            return;
        }
    });
    ROSEN_TRACE_END(HITRACE_TAG_GRAPHIC_AGP);
}

void RSRenderServiceConnection::SetRefreshRateMode(int32_t refreshRateMode)
{
    ROSEN_TRACE_BEGIN(HITRACE_TAG_GRAPHIC_AGP, "RSRenderService::SetRefreshRateMode");
    HgmTaskHandleThread::Instance().PostTask([refreshRateMode] () {
        int32_t setResult = HgmCore::Instance().SetRefreshRateMode(refreshRateMode);
        RSSystemProperties::SetHgmRefreshRateModesEnabled(std::to_string(refreshRateMode));
        if (setResult != 0) {
            RS_LOGW("SetRefreshRateMode mode %{public}d is not supported", refreshRateMode);
        }
    });
    ROSEN_TRACE_END(HITRACE_TAG_GRAPHIC_AGP);
}

void RSRenderServiceConnection::SyncFrameRateRange(FrameRateLinkerId id,
    const FrameRateRange& range, int32_t animatorExpectedFrameRate)
{
    if (!mainThread_) {
        return;
    }
    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this), id, &range, animatorExpectedFrameRate]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return;
            }
            auto& context = connection->mainThread_->GetContext();
            auto& linkerMap = context.GetMutableFrameRateLinkerMap();
            auto linker = linkerMap.GetFrameRateLinker(id);
            if (linker == nullptr) {
                RS_LOGW("SyncFrameRateRange there is no frameRateLinker for id %{public}" PRIu64, id);
                return;
            }
            linker->SetExpectedRange(range);
            linker->SetAnimatorExpectedFrameRate(animatorExpectedFrameRate);
            if (range.type_ != OHOS::Rosen::NATIVE_VSYNC_FRAME_RATE_TYPE) {
                return;
            }
            auto appVSyncDistributor = connection->appVSyncDistributor_;
            if (appVSyncDistributor == nullptr) {
                return;
            }
            auto conn = appVSyncDistributor->GetVSyncConnection(id);
            if (conn == nullptr) {
                return;
            }
            std::weak_ptr<RSRenderFrameRateLinker> weakPtr = linker;
            conn->RegisterRequestNativeVSyncCallback([weakPtr]() {
                RS_TRACE_NAME("NativeVSync request frame, update timepoint");
                auto linker = weakPtr.lock();
                if (linker == nullptr) {
                    return;
                }
                linker->UpdateNativeVSyncTimePoint();
            });
        }).wait();
}

void RSRenderServiceConnection::UnregisterFrameRateLinker(FrameRateLinkerId id)
{
    if (!mainThread_) {
        return;
    }
    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this), id]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return;
            }
            auto& context = connection->mainThread_->GetContext();
            auto& linkerMap = context.GetMutableFrameRateLinkerMap();
            auto linker = linkerMap.GetFrameRateLinker(id);
            if (linker == nullptr) {
                RS_LOGE("UnregisterFrameRateLinker there is no frameRateLinker for id %{public}" PRIu64, id);
                return;
            }
            linkerMap.UnregisterFrameRateLinker(id);
        }).wait();
}

uint32_t RSRenderServiceConnection::GetScreenCurrentRefreshRate(ScreenId id)
{
    uint32_t rate = HgmTaskHandleThread::Instance().ScheduleTask([id] () -> uint32_t {
        return HgmCore::Instance().GetScreenCurrentRefreshRate(id);
    }).get();
    if (rate == 0) {
        RS_LOGW("GetScreenCurrentRefreshRate failed to get current refreshrate of"
            " screen : %{public}" PRIu64, id);
    }
    return rate;
}

std::vector<int32_t> RSRenderServiceConnection::GetScreenSupportedRefreshRates(ScreenId id)
{
    return HgmTaskHandleThread::Instance().ScheduleTask([id] () -> std::vector<int32_t> {
        return HgmCore::Instance().GetScreenComponentRefreshRates(id);
    }).get();
}

ErrCode RSRenderServiceConnection::GetShowRefreshRateEnabled(bool& enable)
{
    enable = RSRealtimeRefreshRateManager::Instance().GetShowRefreshRateEnabled();
    return ERR_OK;
}

void RSRenderServiceConnection::SetShowRefreshRateEnabled(bool enabled, int32_t type)
{
    return RSRealtimeRefreshRateManager::Instance().SetShowRefreshRateEnabled(enabled, type);
}

uint32_t RSRenderServiceConnection::GetRealtimeRefreshRate(ScreenId screenId)
{
    return RSRealtimeRefreshRateManager::Instance().GetRealtimeRefreshRate(screenId);
}

ErrCode RSRenderServiceConnection::GetRefreshInfo(pid_t pid, std::string& enable)
{
    if (!mainThread_) {
        enable = "";
        return ERR_INVALID_VALUE;
    }
    auto& context = mainThread_->GetContext();
    auto& nodeMap = context.GetMutableNodeMap();
    std::string surfaceName = nodeMap.GetSelfDrawSurfaceNameByPid(pid);
    if (surfaceName.empty()) {
        enable = "";
        return ERR_INVALID_VALUE;
    }
    std::string dumpString;
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        RSHardwareThread::Instance().ScheduleTask(
            [weakThis = wptr<RSRenderServiceConnection>(this), &dumpString, &surfaceName]() {
                sptr<RSRenderServiceConnection> connection = weakThis.promote();
                if (connection == nullptr || connection->screenManager_ == nullptr) {
                    return;
                }
                connection->screenManager_->FpsDump(dumpString, surfaceName);
            }).wait();
#endif
    } else {
        mainThread_->ScheduleTask(
            [weakThis = wptr<RSRenderServiceConnection>(this), &dumpString, &surfaceName]() {
                sptr<RSRenderServiceConnection> connection = weakThis.promote();
                if (connection == nullptr || connection->screenManager_ == nullptr) {
                    return;
                }
                connection->screenManager_->FpsDump(dumpString, surfaceName);
            }).wait();
    }
    enable = dumpString;
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetRefreshInfoToSP(NodeId id, std::string& enable)
{
    if (!mainThread_) {
        enable = "";
        return ERR_INVALID_VALUE;
    }
    std::string dumpString;
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    auto dumpTask = [weakThis = wptr<RSRenderServiceConnection>(this), &dumpString, &id]() {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr) {
            RS_LOGE("GetRefreshInfoToSP connection is nullptr");
            return;
        }
        if (connection->screenManager_ == nullptr) {
            RS_LOGE("GetRefreshInfoToSP connection->screenManager_ is nullptr");
            return;
        }
        RSSurfaceFpsManager::GetInstance().Dump(dumpString, id);
    };
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        RSHardwareThread::Instance().ScheduleTask(dumpTask).wait();
#endif
    } else {
        mainThread_->ScheduleTask(dumpTask).wait();
    }
    enable = dumpString;
    return ERR_OK;
}

int32_t RSRenderServiceConnection::GetCurrentRefreshRateMode()
{
    return HgmTaskHandleThread::Instance().ScheduleTask([] () -> int32_t {
        return HgmCore::Instance().GetCurrentRefreshRateMode();
    }).get();
}

int32_t RSRenderServiceConnection::SetPhysicalScreenResolution(ScreenId id, uint32_t width, uint32_t height)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_MANAGER_NULL;
    }
    return screenManager_->SetPhysicalScreenResolution(id, width, height);
}

int32_t RSRenderServiceConnection::SetVirtualScreenResolution(ScreenId id, uint32_t width, uint32_t height)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetVirtualScreenResolution(id, width, height); }).get();
#else
        return StatusCode::SCREEN_NOT_FOUND;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetVirtualScreenResolution(id, width, height); }).get();
    } else {
        return StatusCode::SCREEN_NOT_FOUND;
    }
}

ErrCode RSRenderServiceConnection::MarkPowerOffNeedProcessOneFrame()
{
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType != UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return ERR_INVALID_VALUE;
    }
#ifdef RS_ENABLE_GPU
    renderThread_.PostTask(
        [weakThis = wptr<RSRenderServiceConnection>(this)]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->screenManager_ == nullptr) {
                return;
            }
            connection->screenManager_->MarkPowerOffNeedProcessOneFrame();
        }
    );
#endif
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::RepaintEverything()
{
    if (mainThread_ == nullptr) {
        RS_LOGE("RepaintEverything, mainThread_ is null, return");
        return ERR_INVALID_VALUE;
    }
    auto task = []() -> void {
        RS_LOGI("RepaintEverything, setDirtyflag, forceRefresh in mainThread");
        RSMainThread::Instance()->SetDirtyFlag();
        RSMainThread::Instance()->ForceRefreshForUni();
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::ForceRefreshOneFrameWithNextVSync()
{
    if (!mainThread_) {
        RS_LOGE("%{public}s mainThread_ is nullptr, return", __func__);
        return ERR_INVALID_VALUE;
    }

    auto task = [weakThis = wptr<RSRenderServiceConnection>(this)]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }

        RS_LOGI("ForceRefreshOneFrameWithNextVSync, setDirtyflag, forceRefresh in mainThread");
        connection->mainThread_->SetDirtyFlag();
        connection->mainThread_->RequestNextVSync();
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

void RSRenderServiceConnection::DisablePowerOffRenderControl(ScreenId id)
{
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        renderThread_.PostTask(
            [weakThis = wptr<RSRenderServiceConnection>(this), id]() {
                sptr<RSRenderServiceConnection> connection = weakThis.promote();
                if (connection == nullptr || connection->screenManager_ == nullptr) {
                    return;
                }
                connection->screenManager_->DisablePowerOffRenderControl(id);
            }
        );
#endif
    }
}

void RSRenderServiceConnection::SetScreenPowerStatus(ScreenId id, ScreenPowerStatus status)
{
    if (screenManager_ == nullptr || mainThread_ == nullptr) {
        RS_LOGE("%{public}s screenManager or mainThread is null, id: %{public}" PRIu64, __func__, id);
        return;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        RSHardwareThread::Instance().ScheduleTask([=]() {
            screenManager_->SetScreenPowerStatus(id, status);
        }).wait();
        screenManager_->WaitScreenPowerStatusTask();
        mainThread_->SetDiscardJankFrames(true);
        RSJankStatsRenderFrameHelper::GetInstance().SetDiscardJankFrames(true);
        HgmTaskHandleThread::Instance().PostTask([id, status]() {
            HgmCore::Instance().NotifyScreenPowerStatus(id, status);
        });
#endif
    } else {
        mainThread_->ScheduleTask(
            [=]() { screenManager_->SetScreenPowerStatus(id, status); }).wait();
    }
}

namespace {
void TakeSurfaceCaptureForUiParallel(
    NodeId id, sptr<RSISurfaceCaptureCallback> callback, const RSSurfaceCaptureConfig& captureConfig,
    const Drawing::Rect& specifiedAreaRect)
{
#ifdef RS_ENABLE_GPU
    RS_LOGI("TakeSurfaceCaptureForUiParallel nodeId:[%{public}" PRIu64 "], issync:%{public}s", id,
        captureConfig.isSync ? "true" : "false");
    std::function<void()> captureTask = [id, callback, captureConfig, specifiedAreaRect]() {
        RSUiCaptureTaskParallel::Capture(id, callback, captureConfig, specifiedAreaRect);
    };
    auto& context = RSMainThread::Instance()->GetContext();

    auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode<RSRenderNode>(id);
    if (!node) {
        RS_LOGE("TakeSurfaceCaptureForUiParallel node is nullptr");
        callback->OnSurfaceCapture(id, captureConfig, nullptr);
        return;
    }

    auto surfaceNode = node->ReinterpretCastTo<RSSurfaceRenderNode>();
    if (surfaceNode) {
        std::lock_guard<std::mutex> lock(surfaceNode->GetCaptureUiFirstMutex());
        surfaceNode->SetCaptureEnableUifirst(true);
    }
    bool captureNodeDirty = (node->IsDirty() || node->IsSubTreeDirty() || !node->IsOnTheTree());
    if (captureConfig.isSync || captureNodeDirty) {
        if (captureConfig.isSync) {
            context.GetUiCaptureHelper().InsertUiCaptureCmdsExecutedFlag(id, false);
        }
        RSMainThread::Instance()->AddUiCaptureTask(id, captureTask);
        return;
    }
    RSMainThread::Instance()->PostTask(captureTask);
#endif
}

void TakeSurfaceCaptureForUIWithUni(NodeId id, sptr<RSISurfaceCaptureCallback> callback,
    const RSSurfaceCaptureConfig& captureConfig)
{
#ifdef RS_ENABLE_GPU
    std::function<void()> offscreenRenderTask = [id, callback, captureConfig]() -> void {
        RS_LOGD("RSRenderService::TakeSurfaceCaptureForUIWithUni callback->OnOffscreenRender"
            " nodeId:[%{public}" PRIu64 "]", id);
        ROSEN_TRACE_BEGIN(HITRACE_TAG_GRAPHIC_AGP, "RSRenderService::TakeSurfaceCaptureForUIWithUni");
        std::shared_ptr<RSUniUICapture> rsUniUICapture = std::make_shared<RSUniUICapture>(id, captureConfig);
        std::shared_ptr<Media::PixelMap> pixelmap = rsUniUICapture->TakeLocalCapture();
        callback->OnSurfaceCapture(id, captureConfig, pixelmap.get());
        ROSEN_TRACE_END(HITRACE_TAG_GRAPHIC_AGP);
    };
    if (!captureConfig.isSync) {
        RSOffscreenRenderThread::Instance().PostTask(offscreenRenderTask);
    } else {
        auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode<RSRenderNode>(id);
        if (node == nullptr || !node->GetCommandExecuted()) {
            RSOffscreenRenderThread::Instance().InSertCaptureTask(id, offscreenRenderTask);
            return;
        }
        RSOffscreenRenderThread::Instance().PostTask(offscreenRenderTask);
        node->SetCommandExecuted(false);
    }
#endif
}
}

void RSRenderServiceConnection::TakeSurfaceCapture(NodeId id, sptr<RSISurfaceCaptureCallback> callback,
    const RSSurfaceCaptureConfig& captureConfig, const RSSurfaceCaptureBlurParam& blurParam,
    const Drawing::Rect& specifiedAreaRect, RSSurfaceCapturePermissions permissions)
{
    if (!mainThread_) {
        RS_LOGE("%{public}s mainThread_ is nullptr", __func__);
        return;
    }

    std::function<void()> captureTask = [id, callback, captureConfig, blurParam, specifiedAreaRect,
        screenCapturePermission = permissions.screenCapturePermission,
        isSystemCalling = permissions.isSystemCalling,
        selfCapture = permissions.selfCapture]() -> void {
        RS_TRACE_NAME_FMT("RSRenderServiceConnection::TakeSurfaceCapture captureTask nodeId:[%" PRIu64 "]", id);
        RS_LOGD("TakeSurfaceCapture captureTask begin nodeId:[%{public}" PRIu64 "]", id);
        if (captureConfig.captureType == SurfaceCaptureType::UICAPTURE) {
            // When the isSync flag in captureConfig is true, UI capture processes commands before capture.
            // When the isSync flag in captureConfig is false, UI capture will check null node independently.
            // Therefore, a null node is valid for UI capture.
            auto uiCaptureHasPermission = selfCapture || isSystemCalling;
            if (!uiCaptureHasPermission) {
                RS_LOGE("TakeSurfaceCapture uicapture failed, nodeId:[%{public}" PRIu64
                        "], isSystemCalling: %{public}u, selfCapture: %{public}u",
                    id, isSystemCalling, selfCapture);
                callback->OnSurfaceCapture(id, captureConfig, nullptr);
                return;
            }
            if (RSUniRenderJudgement::IsUniRender()) {
                TakeSurfaceCaptureForUiParallel(id, callback, captureConfig, specifiedAreaRect);
            } else {
                TakeSurfaceCaptureForUIWithUni(id, callback, captureConfig);
            }
            return;
        }
        auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(id);
        if (node == nullptr) {
            RS_LOGE("TakeSurfaceCapture failed, node is nullptr");
            callback->OnSurfaceCapture(id, captureConfig, nullptr);
            return;
        }
        auto displayCaptureHasPermission = screenCapturePermission && isSystemCalling;
        auto surfaceCaptureHasPermission = blurParam.isNeedBlur ? isSystemCalling : (selfCapture || isSystemCalling);
        if ((node->GetType() == RSRenderNodeType::LOGICAL_DISPLAY_NODE && !displayCaptureHasPermission) ||
            (node->GetType() == RSRenderNodeType::SURFACE_NODE && !surfaceCaptureHasPermission)) {
            RS_LOGE("TakeSurfaceCapture failed, node type: %{public}u, "
                "screenCapturePermission: %{public}u, isSystemCalling: %{public}u, selfCapture: %{public}u",
                node->GetType(), screenCapturePermission, isSystemCalling, selfCapture);
            callback->OnSurfaceCapture(id, captureConfig, nullptr);
            return;
        }
        if (RSUniRenderJudgement::GetUniRenderEnabledType() == UniRenderEnabledType::UNI_RENDER_DISABLED) {
            RS_LOGD("RSRenderService::TakeSurfaceCapture captureTaskInner nodeId:[%{public}" PRIu64 "]", id);
            ROSEN_TRACE_BEGIN(HITRACE_TAG_GRAPHIC_AGP, "RSRenderService::TakeSurfaceCapture");
            RSSurfaceCaptureTask task(id, captureConfig);
            if (!task.Run(callback)) {
                callback->OnSurfaceCapture(id, captureConfig, nullptr);
            }
            ROSEN_TRACE_END(HITRACE_TAG_GRAPHIC_AGP);
        } else {
#ifdef RS_ENABLE_GPU
            RSSurfaceCaptureParam captureParam;
            captureParam.id = id;
            captureParam.config = captureConfig;
            captureParam.isSystemCalling = isSystemCalling;
            captureParam.blurParam = blurParam;
            RSSurfaceCaptureTaskParallel::CheckModifiers(id, captureConfig.useCurWindow);
            RSSurfaceCaptureTaskParallel::Capture(callback, captureParam);
#endif
        }
    };
    mainThread_->PostTask(captureTask);
}

std::vector<std::pair<NodeId, std::shared_ptr<Media::PixelMap>>> RSRenderServiceConnection::TakeSurfaceCaptureSoloNode(
    NodeId id, const RSSurfaceCaptureConfig& captureConfig, RSSurfaceCapturePermissions permissions)
{
    RS_LOGI("TakeSurfaceCaptureSoloNode nodeId:[%{public}" PRIu64 "]", id);
    std::vector<std::pair<NodeId, std::shared_ptr<Media::PixelMap>>> pixelMapIdPairVector;
    std::function<void()> captureTask = [id, captureConfig, &pixelMapIdPairVector,
        isSystemCalling = permissions.isSystemCalling,
        selfCapture = permissions.selfCapture]() {
        RS_TRACE_NAME_FMT("RSRenderServiceConnection::TakeSurfaceCaptureSoloNode captureTask"
            " nodeId:[%" PRIu64 "]", id);
        RS_LOGI("TakeSurfaceCaptureSoloNode captureTask begin "
            "nodeId:[%{public}" PRIu64 "]", id);
        auto uiCaptureHasPermission = selfCapture || isSystemCalling;
        if (!uiCaptureHasPermission) {
            RS_LOGE("TakeSurfaceCaptureSoloNode "
                "uicapturesolo failed, nodeId:[%{public}" PRIu64
                "], isSystemCalling: %{public}u, selfCapture: %{public}u", id, isSystemCalling, selfCapture);
            return;
        }
        pixelMapIdPairVector = RSUiCaptureSoloTaskParallel::CaptureSoloNode(id, captureConfig);
    };
    RSMainThread::Instance()->PostSyncTask(captureTask);
    return pixelMapIdPairVector;
}

void RSRenderServiceConnection::TakeSelfSurfaceCapture(
    NodeId id, sptr<RSISurfaceCaptureCallback> callback, const RSSurfaceCaptureConfig& captureConfig)
{
    if (!mainThread_) {
        RS_LOGE("%{public}s mainThread_ is nullptr", __func__);
        return;
    }
    bool isSystemCalling = RSInterfaceCodeAccessVerifierBase::IsSystemCalling(
        RSIRenderServiceConnectionInterfaceCodeAccessVerifier::codeEnumTypeName_ + "::TAKE_SELF_SURFACE_CAPTURE");
    std::function<void()> selfCaptureTask = [id, callback, captureConfig, isSystemCalling]() -> void {
        auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(id);
        if (node == nullptr) {
            RS_LOGE("TakeSelfSurfaceCapture failed, node is nullptr");
            if (callback) {
                callback->OnSurfaceCapture(id, captureConfig, nullptr);
            }
            return;
        }
        RSSurfaceCaptureParam captureParam;
        captureParam.id = id;
        captureParam.config = captureConfig;
        captureParam.isSystemCalling = isSystemCalling;
        captureParam.isSelfCapture = true;
        RSSurfaceCaptureTaskParallel::CheckModifiers(id, captureConfig.useCurWindow);
        RSSurfaceCaptureTaskParallel::Capture(callback, captureParam);
    };
    mainThread_->PostTask(selfCaptureTask);
}

ErrCode RSRenderServiceConnection::TakeSurfaceCaptureWithAllWindows(NodeId id,
    sptr<RSISurfaceCaptureCallback> callback, const RSSurfaceCaptureConfig& captureConfig,
    bool checkDrmAndSurfaceLock, RSSurfaceCapturePermissions permissions)
{
    bool hasPermission = permissions.screenCapturePermission && permissions.isSystemCalling;
    if (!mainThread_ || !hasPermission) {
        if (callback) {
            callback->OnSurfaceCapture(id, captureConfig, nullptr);
        }
        RS_LOGE("%{public}s mainThread_ is nullptr or permission denied", __func__);
        return ERR_PERMISSION_DENIED;
    }
    RS_TRACE_NAME_FMT("TaskSurfaceCaptureWithAllWindows checkDrmAndSurfaceLock: %d", checkDrmAndSurfaceLock);
    std::function<void()> takeSurfaceCaptureTask =
        [id, checkDrmAndSurfaceLock, callback, captureConfig, hasPermission]() -> void {
        auto displayNode = RSBaseRenderNode::ReinterpretCast<RSLogicalDisplayRenderNode>(
            RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(id));
        if (!displayNode) {
            if (callback) {
                callback->OnSurfaceCapture(id, captureConfig, nullptr);
            }
            RS_LOGE("%{public}s failed, displayNode is nullptr", __func__);
            return;
        }
        if (checkDrmAndSurfaceLock && RSMainThread::Instance()->HasDRMOrSurfaceLockLayer()) {
            if (callback) {
                callback->OnSurfaceCapture(id, captureConfig, nullptr);
            }
            RS_LOGE("%{public}s DRM or surfacelock layer exists", __func__);
            return;
        }
        RSSurfaceCaptureParam captureParam;
        captureParam.id = id;
        captureParam.config = captureConfig;
        captureParam.isSystemCalling = hasPermission;
        captureParam.needCaptureSpecialLayer = hasPermission;
        RSSurfaceCaptureTaskParallel::CheckModifiers(id, captureConfig.useCurWindow);
        RSSurfaceCaptureTaskParallel::Capture(callback, captureParam);
    };
    mainThread_->PostTask(takeSurfaceCaptureTask);
    return ERR_OK;
}
 
ErrCode RSRenderServiceConnection::FreezeScreen(NodeId id, bool isFreeze)
{
    if (!mainThread_) {
        RS_LOGE("%{public}s mainThread_ is nullptr", __func__);
        return ERR_INVALID_OPERATION;
    }
    RS_TRACE_NAME_FMT("FreezeScreen isFreeze: %d", isFreeze);
    std::function<void()> setScreenFreezeTask = [id, isFreeze]() -> void {
        auto displayNode = RSBaseRenderNode::ReinterpretCast<RSLogicalDisplayRenderNode>(
            RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(id));
        auto screenNode = displayNode == nullptr ? nullptr :
            std::static_pointer_cast<RSScreenRenderNode>(displayNode->GetParent().lock());
        if (!screenNode) {
            RS_LOGE("%{public}s failed, screenNode is nullptr", __func__);
            return;
        }
        screenNode->SetForceFreeze(isFreeze);

        // cancel previous task, and unfreeze screen after 3 seconds in case unfreeze fail
        std::string taskName(UNFREEZE_SCREEN_TASK_NAME + std::to_string(id));
        RSMainThread::Instance()->RemoveTask(taskName);
        if (!isFreeze) {
            return;
        }
        auto unfreezeScreenTask = [screenId = screenNode->GetId()]() -> void {
            RS_LOGW("unfreeze screen[%{public}" PRIu64 "] by timer", screenId);
            RS_TRACE_NAME_FMT("UnfreezeScreen[%lld]", screenId);
            auto screenNode = RSBaseRenderNode::ReinterpretCast<RSScreenRenderNode>(
                RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(screenId));
            if (screenNode) {
                screenNode->SetForceFreeze(false);
            }
        };
        RSMainThread::Instance()->PostTask(unfreezeScreenTask, taskName, MAX_FREEZE_SCREEN_TIME,
            AppExecFwk::EventQueue::Priority::IMMEDIATE);
    };
    mainThread_->PostTask(setScreenFreezeTask);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetWindowFreezeImmediately(NodeId id, bool isFreeze,
    sptr<RSISurfaceCaptureCallback> callback, const RSSurfaceCaptureConfig& captureConfig,
    const RSSurfaceCaptureBlurParam& blurParam)
{
    if (!mainThread_) {
        RS_LOGE("%{public}s mainThread_ is nullptr", __func__);
        return ERR_INVALID_VALUE;
    }
    bool isSystemCalling = RSInterfaceCodeAccessVerifierBase::IsSystemCalling(
        RSIRenderServiceConnectionInterfaceCodeAccessVerifier::codeEnumTypeName_ + "::SET_WINDOW_FREEZE_IMMEDIATELY");
    std::function<void()> setWindowFreezeTask =
        [id, isFreeze, callback, captureConfig, blurParam, isSystemCalling]() -> void {
        auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(id);
        if (node == nullptr) {
            RS_LOGE("SetWindowFreezeImmediately failed, node is nullptr");
            if (callback) {
                callback->OnSurfaceCapture(id, captureConfig, nullptr);
            }
            return;
        }
        node->SetStaticCached(isFreeze);
        if (isFreeze) {
            RSSurfaceCaptureParam captureParam;
            captureParam.id = id;
            captureParam.config = captureConfig;
            captureParam.isSystemCalling = isSystemCalling;
            captureParam.isFreeze = isFreeze;
            captureParam.blurParam = blurParam;
            RSSurfaceCaptureTaskParallel::CheckModifiers(id, captureConfig.useCurWindow);
            RSSurfaceCaptureTaskParallel::Capture(callback, captureParam);
        } else {
            RSSurfaceCaptureTaskParallel::ClearCacheImageByFreeze(id);
        }
    };
    mainThread_->PostTask(setWindowFreezeTask);
    return ERR_OK;
}

void RSRenderServiceConnection::TakeUICaptureInRange(
    NodeId id, sptr<RSISurfaceCaptureCallback> callback, const RSSurfaceCaptureConfig& captureConfig)
{
    std::function<void()> captureTask = [id, callback, captureConfig]() -> void {
        RS_TRACE_NAME_FMT("RSRenderServiceConnection::TakeUICaptureInRange captureTask nodeId:[%" PRIu64 "]", id);
        RS_LOGD("RSRenderServiceConnection::TakeUICaptureInRange captureTask nodeId:[%{public}" PRIu64 "]", id);
        TakeSurfaceCaptureForUiParallel(id, callback, captureConfig, {});
    };
    RSMainThread::Instance()->PostTask(captureTask);
}

ErrCode RSRenderServiceConnection::SetHwcNodeBounds(int64_t rsNodeId, float positionX, float positionY,
    float positionZ, float positionW)
{
    if (mainThread_ == nullptr || screenManager_ == nullptr) {
        return ERR_INVALID_VALUE;
    }

    // adapt video scene pointer
    if (screenManager_->GetCurrentVirtualScreenNum() > 0 ||
        !RSPointerWindowManager::Instance().GetIsPointerEnableHwc()) {
        // when has virtual screen or pointer is enable hwc, we can't skip
        RSPointerWindowManager::Instance().SetIsPointerCanSkipFrame(false);
        RSMainThread::Instance()->RequestNextVSync();
    } else {
        RSPointerWindowManager::Instance().SetIsPointerCanSkipFrame(true);
    }

    RSPointerWindowManager::Instance().SetHwcNodeBounds(rsNodeId, positionX, positionY,
        positionZ, positionW);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::RegisterApplicationAgent(uint32_t pid, sptr<IApplicationAgent> app)
{
    if (!mainThread_) {
        RS_LOGE("RegisterApplicationAgent mainThread_ is nullptr");
        return ERR_INVALID_VALUE;
    }
    auto captureTask = [weakThis = wptr<RSRenderServiceConnection>(this), pid, app]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            RS_LOGE("RegisterApplicationAgent connection or mainThread_ is nullptr");
            return;
        }
        connection->mainThread_->RegisterApplicationAgent(pid, app);
    };
    mainThread_->PostTask(captureTask);

    app->AsObject()->AddDeathRecipient(applicationDeathRecipient_);
    return ERR_OK;
}

void RSRenderServiceConnection::UnRegisterApplicationAgent(sptr<IApplicationAgent> app)
{
    auto captureTask = [=]() -> void {
        RSMainThread::Instance()->UnRegisterApplicationAgent(app);
    };
    RSMainThread::Instance()->ScheduleTask(captureTask).wait();
}

RSVirtualScreenResolution RSRenderServiceConnection::GetVirtualScreenResolution(ScreenId id)
{
    RSVirtualScreenResolution virtualScreenResolution;
    if (!screenManager_) {
        return virtualScreenResolution;
    }
    screenManager_->GetVirtualScreenResolution(id, virtualScreenResolution);
    return virtualScreenResolution;
}

ErrCode RSRenderServiceConnection::GetScreenActiveMode(uint64_t id, RSScreenModeInfo& screenModeInfo)
{
    if (!screenManager_) {
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        RSHardwareThread::Instance().ScheduleTask(
            [=, &screenModeInfo]() { return screenManager_->GetScreenActiveMode(id, screenModeInfo); }).wait();
#else
        return screenModeInfo;
#endif
    } else if (mainThread_ != nullptr) {
        mainThread_->ScheduleTask(
            [=, &screenModeInfo]() { return screenManager_->GetScreenActiveMode(id, screenModeInfo); }).wait();
    }
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetTotalAppMemSize(float& cpuMemSize, float& gpuMemSize)
{
#ifdef RS_ENABLE_GPU
    RSMainThread::Instance()->GetAppMemoryInMB(cpuMemSize, gpuMemSize);
    gpuMemSize += RSSubThreadManager::Instance()->GetAppGpuMemoryInMB();
#endif
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetMemoryGraphic(int pid, MemoryGraphic& memoryGraphic)
{
    if (pid == 0) {
        return ERR_INVALID_VALUE;
    }
    bool enable;
    if (GetUniRenderEnabled(enable) == ERR_OK && enable) {
        renderThread_.PostSyncTask(
            [weakThis = wptr<RSRenderServiceConnection>(this), &memoryGraphic, &pid] {
                sptr<RSRenderServiceConnection> connection = weakThis.promote();
                if (connection == nullptr) {
                    return;
                }
                memoryGraphic = MemoryManager::CountPidMemory(pid,
                    connection->renderThread_.GetRenderEngine()->GetRenderContext()->GetDrGPUContext());
            });
        return ERR_OK;
    } else {
        return ERR_INVALID_VALUE;
    }
}

ErrCode RSRenderServiceConnection::GetMemoryGraphics(std::vector<MemoryGraphic>& memoryGraphics)
{
    bool res;
    if (!mainThread_ || GetUniRenderEnabled(res) != ERR_OK || !res) {
        return ERR_INVALID_VALUE;
    }
    
    mainThread_->ScheduleTask([mainThread = mainThread_, &memoryGraphics]() {
            mainThread->CountMem(memoryGraphics);
        }).wait();
    return ERR_OK;
}

std::vector<RSScreenModeInfo> RSRenderServiceConnection::GetScreenSupportedModes(ScreenId id)
{
    if (!screenManager_) {
        return std::vector<RSScreenModeInfo>();
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenSupportedModes(id); }).get();
#else
        return std::vector<RSScreenModeInfo>();
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenSupportedModes(id); }).get();
    } else {
        return std::vector<RSScreenModeInfo>();
    }
}

RSScreenCapability RSRenderServiceConnection::GetScreenCapability(ScreenId id)
{
    RSScreenCapability screenCapability;
    if (!screenManager_) {
        return screenCapability;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenCapability(id); }).get();
#else
        return screenCapability;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenCapability(id); }).get();
    } else {
        return screenCapability;
    }
}

ErrCode RSRenderServiceConnection::GetScreenPowerStatus(uint64_t screenId, uint32_t& status)
{
    if (!screenManager_) {
        status = ScreenPowerStatus::INVALID_POWER_STATUS;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        status = RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenPowerStatus(screenId); }).get();
#else
        status = ScreenPowerStatus::INVALID_POWER_STATUS;
#endif
    } else if (mainThread_ != nullptr) {
        status = mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenPowerStatus(screenId); }).get();
    } else {
        status = ScreenPowerStatus::INVALID_POWER_STATUS;
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

RSScreenData RSRenderServiceConnection::GetScreenData(ScreenId id)
{
    RSScreenData screenData;
    if (!screenManager_) {
        return screenData;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenData(id); }).get();
#else
        return screenData;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenData(id); }).get();
    } else {
        return screenData;
    }
}

ErrCode RSRenderServiceConnection::GetScreenBacklight(uint64_t id, int32_t& level)
{
    if (!screenManager_) {
        level = INVALID_BACKLIGHT_VALUE;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        level = RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenBacklight(id); }).get();
#else
        level = INVALID_BACKLIGHT_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        level = mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenBacklight(id); }).get();
    } else {
        level = INVALID_BACKLIGHT_VALUE;
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

void RSRenderServiceConnection::SetScreenBacklight(ScreenId id, uint32_t level)
{
    if (!screenManager_) {
        RS_LOGE("%{public}s screenManager_ is nullptr.", __func__);
        return;
    }
    RSLuminanceControl::Get().SetSdrLuminance(id, level);
    if (RSLuminanceControl::Get().IsHdrOn(id) && level > 0 && mainThread_ != nullptr) {
        auto task = [weakThis = wptr<RSRenderServiceConnection>(this), id]() {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                RS_LOGE("SetScreenBacklight fail");
                return;
            }
            connection->mainThread_->SetLuminanceChangingStatus(id, true);
            connection->mainThread_->SetDirtyFlag();
            connection->mainThread_->RequestNextVSync();
        };
        mainThread_->PostTask(task);
        return;
    }

    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        screenManager_->SetScreenBacklight(id, level);
#endif
    } else if (mainThread_ != nullptr) {
        mainThread_->ScheduleTask(
            [=]() { screenManager_->SetScreenBacklight(id, level); }).wait();
    }
}

ErrCode RSRenderServiceConnection::RegisterBufferClearListener(
    NodeId id, sptr<RSIBufferClearCallback> callback)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    auto registerBufferClearListener =
        [id, callback, weakThis = wptr<RSRenderServiceConnection>(this)]() -> bool {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return false;
            }
            if (auto node = connection->mainThread_->GetContext().GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(id)) {
                node->RegisterBufferClearListener(callback);
                return true;
            }
            return false;
    };
    mainThread_->PostTask(registerBufferClearListener);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::RegisterBufferAvailableListener(
    NodeId id, sptr<RSIBufferAvailableCallback> callback, bool isFromRenderThread)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    auto registerBufferAvailableListener =
        [id, callback, isFromRenderThread, weakThis = wptr<RSRenderServiceConnection>(this)]() -> bool {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return false;
            }
            if (auto node = connection->mainThread_->GetContext().GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(id)) {
                node->RegisterBufferAvailableListener(callback, isFromRenderThread);
                return true;
            }
            return false;
    };
    mainThread_->PostTask(registerBufferAvailableListener);
    return ERR_OK;
}

int32_t RSRenderServiceConnection::GetScreenSupportedColorGamuts(ScreenId id, std::vector<ScreenColorGamut>& mode)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenSupportedColorGamuts(id, mode); }).get();
#else
        return StatusCode::SCREEN_NOT_FOUND;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenSupportedColorGamuts(id, mode); }).get();
    } else {
        return StatusCode::SCREEN_NOT_FOUND;
    }
}

int32_t RSRenderServiceConnection::GetScreenSupportedMetaDataKeys(ScreenId id, std::vector<ScreenHDRMetadataKey>& keys)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &keys]() { return screenManager_->GetScreenSupportedMetaDataKeys(id, keys); }).get();
#else
        return StatusCode::SCREEN_NOT_FOUND;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=, &keys]() { return screenManager_->GetScreenSupportedMetaDataKeys(id, keys); }).get();
    } else {
        return StatusCode::SCREEN_NOT_FOUND;
    }
}

int32_t RSRenderServiceConnection::GetScreenColorGamut(ScreenId id, ScreenColorGamut& mode)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenColorGamut(id, mode); }).get();
#else
        return StatusCode::SCREEN_NOT_FOUND;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenColorGamut(id, mode); }).get();
    } else {
        return StatusCode::SCREEN_NOT_FOUND;
    }
}

int32_t RSRenderServiceConnection::SetScreenColorGamut(ScreenId id, int32_t modeIdx)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenColorGamut(id, modeIdx); }).get();
#else
        return StatusCode::SCREEN_NOT_FOUND;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenColorGamut(id, modeIdx); }).get();
    } else {
        return StatusCode::SCREEN_NOT_FOUND;
    }
}

int32_t RSRenderServiceConnection::SetScreenGamutMap(ScreenId id, ScreenGamutMap mode)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenGamutMap(id, mode); }).get();
#else
        return StatusCode::SCREEN_NOT_FOUND;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenGamutMap(id, mode); }).get();
    } else {
        return StatusCode::SCREEN_NOT_FOUND;
    }
}

int32_t RSRenderServiceConnection::SetScreenCorrection(ScreenId id, ScreenRotation screenRotation)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->SetScreenCorrection(id, screenRotation);
}

bool RSRenderServiceConnection::SetVirtualMirrorScreenCanvasRotation(ScreenId id, bool canvasRotation)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return false;
    }
    return screenManager_->SetVirtualMirrorScreenCanvasRotation(id, canvasRotation);
}

int32_t RSRenderServiceConnection::SetVirtualScreenAutoRotation(ScreenId id, bool isAutoRotation)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_MANAGER_NULL;
    }
    return screenManager_->SetVirtualScreenAutoRotation(id, isAutoRotation);
}

ErrCode RSRenderServiceConnection::SetGlobalDarkColorMode(bool isDark)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), isDark]() {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            RS_LOGE("SetGlobalDarkColorMode fail");
            return;
        }
        connection->mainThread_->SetGlobalDarkColorMode(isDark);
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

bool RSRenderServiceConnection::SetVirtualMirrorScreenScaleMode(ScreenId id, ScreenScaleMode scaleMode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return false;
    }
    return screenManager_->SetVirtualMirrorScreenScaleMode(id, scaleMode);
}

int32_t RSRenderServiceConnection::GetScreenGamutMap(ScreenId id, ScreenGamutMap& mode)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenGamutMap(id, mode); }).get();
#else
        return StatusCode::SCREEN_NOT_FOUND;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenGamutMap(id, mode); }).get();
    } else {
        return StatusCode::SCREEN_NOT_FOUND;
    }
}

int32_t RSRenderServiceConnection::GetScreenHDRCapability(ScreenId id, RSScreenHDRCapability& screenHdrCapability)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->GetScreenHDRCapability(id, screenHdrCapability);
}

ErrCode RSRenderServiceConnection::GetPixelFormat(ScreenId id, GraphicPixelFormat& pixelFormat, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=, &pixelFormat]() { return screenManager_->GetPixelFormat(id, pixelFormat); }).get();
        return ERR_OK;
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        resCode = mainThread_->ScheduleTask(
            [=, &pixelFormat]() { return screenManager_->GetPixelFormat(id, pixelFormat); }).get();
        return ERR_OK;
    } else {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
}

ErrCode RSRenderServiceConnection::SetPixelFormat(ScreenId id, GraphicPixelFormat pixelFormat, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    if (pixelFormat < 0 ||
        (pixelFormat >= GRAPHIC_PIXEL_FMT_END_OF_VALID && pixelFormat != GRAPHIC_PIXEL_FMT_VENDER_MASK)) {
        resCode = StatusCode::INVALID_ARGUMENTS;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetPixelFormat(id, pixelFormat); }).get();
        return ERR_OK;
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        resCode = mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetPixelFormat(id, pixelFormat); }).get();
        return ERR_OK;
    } else {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
}

ErrCode RSRenderServiceConnection::GetScreenSupportedHDRFormats(
    ScreenId id, std::vector<ScreenHDRFormat>& hdrFormats, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=, &hdrFormats]() { return screenManager_->GetScreenSupportedHDRFormats(id, hdrFormats); }).get();
        return ERR_OK;
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        resCode = mainThread_->ScheduleTask(
            [=, &hdrFormats]() { return screenManager_->GetScreenSupportedHDRFormats(id, hdrFormats); }).get();
        return ERR_OK;
    } else {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
}

ErrCode RSRenderServiceConnection::GetScreenHDRFormat(ScreenId id, ScreenHDRFormat& hdrFormat, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=, &hdrFormat]() { return screenManager_->GetScreenHDRFormat(id, hdrFormat); }).get();
        return ERR_OK;
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        resCode = mainThread_->ScheduleTask(
            [=, &hdrFormat]() { return screenManager_->GetScreenHDRFormat(id, hdrFormat); }).get();
        return ERR_OK;
    } else {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
}

ErrCode RSRenderServiceConnection::SetScreenHDRFormat(ScreenId id, int32_t modeIdx, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenHDRFormat(id, modeIdx); }).get();
        return ERR_OK;
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        resCode = mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenHDRFormat(id, modeIdx); }).get();
        return ERR_OK;
    } else {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
}

ErrCode RSRenderServiceConnection::GetScreenHDRStatus(ScreenId id, HdrStatus& hdrStatus, int32_t& resCode)
{
    if (mainThread_ == nullptr) {
        return ERR_INVALID_VALUE;
    }
    HdrStatus hdrStatusRet = HdrStatus::NO_HDR;
    StatusCode resCodeRet = StatusCode::SCREEN_NOT_FOUND;
    auto isTimeout = std::make_shared<bool>(0);
    std::weak_ptr<bool> isTimeoutWeak = isTimeout;
    auto task = [id, mainThread = mainThread_, &resCodeRet, &hdrStatusRet, isTimeoutWeak]() {
        if (isTimeoutWeak.expired()) {
            RS_LOGE("GetScreenHDRStatus time out, ScreenId: [%{public}" PRIu64 "]", id);
            return;
        }
        std::shared_ptr<RSScreenRenderNode> screenNode = nullptr;
        auto& nodeMap = mainThread->GetContext().GetNodeMap();
        nodeMap.TraverseScreenNodes([id, &screenNode](const std::shared_ptr<RSScreenRenderNode>& node) {
            if (node && node->GetScreenId() == id) {
                screenNode = node;
            }
        });
        if (screenNode == nullptr) {
            resCodeRet = StatusCode::SCREEN_NOT_FOUND;
            return;
        }
        hdrStatusRet = screenNode->GetLastDisplayHDRStatus();
        resCodeRet = StatusCode::SUCCESS;
    };
    auto span = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::milliseconds(100)); // timeout 100 ms
    if (mainThread_->ScheduleTask(task).wait_for(span) == std::future_status::timeout) {
        isTimeout.reset();
    }
    if (isTimeoutWeak.expired() && resCodeRet != StatusCode::SUCCESS) {
        return ERR_TIMED_OUT;
    }
    if (resCodeRet == StatusCode::SUCCESS) {
        hdrStatus = hdrStatusRet;
    }
    resCode = resCodeRet;
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetScreenSupportedColorSpaces(
    ScreenId id, std::vector<GraphicCM_ColorSpaceType>& colorSpaces, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=, &colorSpaces]() { return screenManager_->GetScreenSupportedColorSpaces(id, colorSpaces); }).get();
        return ERR_OK;
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        resCode = mainThread_->ScheduleTask(
            [=, &colorSpaces]() { return screenManager_->GetScreenSupportedColorSpaces(id, colorSpaces); }).get();
        return ERR_OK;
    } else {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
}

ErrCode RSRenderServiceConnection::GetScreenColorSpace(
    ScreenId id, GraphicCM_ColorSpaceType& colorSpace, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=, &colorSpace]() { return screenManager_->GetScreenColorSpace(id, colorSpace); }).get();
        return ERR_OK;
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        resCode = mainThread_->ScheduleTask(
            [=, &colorSpace]() { return screenManager_->GetScreenColorSpace(id, colorSpace); }).get();
        return ERR_OK;
    } else {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
}

ErrCode RSRenderServiceConnection::SetScreenColorSpace(
    ScreenId id, GraphicCM_ColorSpaceType colorSpace, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenColorSpace(id, colorSpace); }).get();
        return ERR_OK;
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
#endif
    } else if (mainThread_ != nullptr) {
        resCode = mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenColorSpace(id, colorSpace); }).get();
        return ERR_OK;
    } else {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
}

int32_t RSRenderServiceConnection::GetScreenType(ScreenId id, RSScreenType& screenType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->GetScreenType(id, screenType);
}

ErrCode RSRenderServiceConnection::GetBitmap(NodeId id, Drawing::Bitmap& bitmap, bool& success)
{
    if (!mainThread_) {
        success = false;
        return ERR_INVALID_VALUE;
    }
    std::promise<bool> result;
    std::future<bool> future = result.get_future();
    RSMainThread* mainThread = mainThread_;
#ifdef RS_ENABLE_GPU
    RSUniRenderThread* renderThread = &renderThread_;
    auto getBitmapTask = [id, &bitmap, mainThread, renderThread, &result]() {
        auto node = mainThread->GetContext().GetNodeMap().GetRenderNode<RSCanvasDrawingRenderNode>(id);
        if (node == nullptr) {
            RS_LOGE("GetBitmap cannot find NodeId: [%{public}" PRIu64 "]", id);
            result.set_value(false);
            return;
        }
        if (node->GetType() != RSRenderNodeType::CANVAS_DRAWING_NODE) {
            RS_LOGE("GetBitmap RenderNodeType != RSRenderNodeType::CANVAS_DRAWING_NODE");
            result.set_value(false);
            return;
        }
        auto grContext = renderThread->GetRenderEngine()->GetRenderContext()->GetDrGPUContext();
        auto drawableNode = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
        auto getDrawableBitmapTask = [drawableNode, &bitmap, grContext, &result]() {
            bitmap = std::static_pointer_cast<DrawableV2::RSCanvasDrawingRenderNodeDrawable>(drawableNode)
                ->GetBitmap(grContext);
            result.set_value(!bitmap.IsEmpty());
        };
        renderThread->PostTask(getDrawableBitmapTask);
    };
    mainThread_->PostTask(getBitmapTask);
#endif
    success = future.get();
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetPixelmap(NodeId id, const std::shared_ptr<Media::PixelMap> pixelmap,
    const Drawing::Rect* rect, std::shared_ptr<Drawing::DrawCmdList> drawCmdList, bool& success)
{
    if (!mainThread_) {
        success = false;
        return ERR_INVALID_VALUE;
    }
    std::promise<bool> result;
    std::future<bool> future = result.get_future();
#ifdef RS_ENABLE_GPU
    RSMainThread* mainThread = mainThread_;
    RSUniRenderThread* renderThread = &renderThread_;
    auto getPixelMapTask = [id, pixelmap, rect, drawCmdList, mainThread, renderThread, &result]() {
        auto node = mainThread->GetContext().GetNodeMap().GetRenderNode<RSCanvasDrawingRenderNode>(id);
        if (node == nullptr) {
            RS_LOGD("GetPixelmap: cannot find NodeId: [%{public}" PRIu64 "]", id);
            result.set_value(false);
            return;
        }
        if (node->GetType() != RSRenderNodeType::CANVAS_DRAWING_NODE) {
            RS_LOGE("GetPixelmap: RenderNodeType != RSRenderNodeType::CANVAS_DRAWING_NODE");
            result.set_value(false);
            return;
        }

        auto tid = node->GetTid(); // planning: id may change in subthread
        auto drawableNode = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
        if (drawableNode) {
            tid = std::static_pointer_cast<DrawableV2::RSCanvasDrawingRenderNodeDrawable>(drawableNode)->GetTid();
        }
        auto getDrawablePixelmapTask = [drawableNode, pixelmap, rect, &result, tid, drawCmdList]() {
            result.set_value(std::static_pointer_cast<DrawableV2::RSCanvasDrawingRenderNodeDrawable>(drawableNode)->
                GetPixelmap(pixelmap, rect, tid, drawCmdList));
        };
        if (!node->IsOnTheTree()) {
            node->ClearOp();
        }
        if (tid == UNI_MAIN_THREAD_INDEX) {
            if (!mainThread->IsIdle() && mainThread->GetContext().HasActiveNode(node)) {
                result.set_value(false);
                return;
            }
            result.set_value(node->GetPixelmap(pixelmap, rect, tid, drawCmdList));
        } else if (tid == UNI_RENDER_THREAD_INDEX) {
            renderThread->PostTask(getDrawablePixelmapTask);
        } else {
            const auto& tidMap = RSSubThreadManager::Instance()->GetReThreadIndexMap();
            if (auto found = tidMap.find(tid); found != tidMap.end()) {
                RSTaskDispatcher::GetInstance().PostTask(found->second, getDrawablePixelmapTask, false);
            } else {
                renderThread->PostTask(getDrawablePixelmapTask);
            }
        }
    };
    mainThread_->PostTask(getPixelMapTask);
#endif
    success = future.get();
    return ERR_OK;
}

bool RSRenderServiceConnection::RegisterTypeface(uint64_t globalUniqueId,
    std::shared_ptr<Drawing::Typeface>& typeface)
{
    RS_LOGI("reg typeface, pid[%{public}d], familyname:%{public}s, uniqueid:%{public}u",
        RSTypefaceCache::GetTypefacePid(globalUniqueId), typeface->GetFamilyName().c_str(),
        RSTypefaceCache::GetTypefaceId(globalUniqueId));
    RSTypefaceCache::Instance().CacheDrawingTypeface(globalUniqueId, typeface);
    return true;
}

int32_t RSRenderServiceConnection::RegisterTypeface(uint64_t id, uint32_t size, int32_t fd, int32_t& needUpdate)
{
    auto tf = RSTypefaceCache::Instance().UpdateDrawingTypefaceRef(id);
    if (tf != nullptr) {
        ::close(fd);
        needUpdate = 1;
        return tf->GetFd();
    }
    needUpdate = 0;
    tf = Drawing::Typeface::MakeFromAshmem(fd, size, RSTypefaceCache::GetTypefaceId(id));
    if (tf != nullptr) {
        RSTypefaceCache::Instance().CacheDrawingTypeface(id, tf);
        return tf->GetFd();
    }
    RS_LOGE("RegisterTypeface: failed to register typeface");
    return -1;
}

bool RSRenderServiceConnection::UnRegisterTypeface(uint64_t globalUniqueId)
{
    RS_LOGW("uneg typeface: pid[%{public}d], uniqueid:%{public}u",
        RSTypefaceCache::GetTypefacePid(globalUniqueId), RSTypefaceCache::GetTypefaceId(globalUniqueId));
    auto typeface = RSTypefaceCache::Instance().GetDrawingTypefaceCache(globalUniqueId);
    if (typeface == nullptr) {
        return true;
    }
    uint32_t uniqueId = typeface->GetUniqueID();
    auto task = [uniqueId]() {
        auto context = RSUniRenderThread::Instance().GetRenderEngine()->GetRenderContext()->GetDrGPUContext();
        if (context) {
            context->FreeCpuCache(uniqueId);
            context->PurgeUnlockAndSafeCacheGpuResources();
        }
    };
    RSUniRenderThread::Instance().PostTask(task);
    RSTypefaceCache::Instance().AddDelayDestroyQueue(globalUniqueId);
    return true;
}

int32_t RSRenderServiceConnection::GetDisplayIdentificationData(ScreenId id, uint8_t& outPort,
    std::vector<uint8_t>& edidData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    return screenManager_->GetDisplayIdentificationData(id, outPort, edidData);
}

ErrCode RSRenderServiceConnection::SetScreenSkipFrameInterval(uint64_t id, uint32_t skipFrameInterval, int32_t& resCode)
{
    if (!screenManager_) {
        resCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        resCode = RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenSkipFrameInterval(id, skipFrameInterval); }).get();
#else
        resCode = StatusCode::SCREEN_NOT_FOUND;
#endif
    } else {
        if (!mainThread_) {
            resCode = StatusCode::INVALID_ARGUMENTS;
            return ERR_INVALID_VALUE;
        }
        resCode = mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenSkipFrameInterval(id, skipFrameInterval); }).get();
    }
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetVirtualScreenRefreshRate(
    ScreenId id, uint32_t maxRefreshRate, uint32_t& actualRefreshRate, int32_t& retVal)
{
    if (!screenManager_) {
        retVal = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    retVal = screenManager_->SetVirtualScreenRefreshRate(id, maxRefreshRate, actualRefreshRate);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetScreenActiveRect(ScreenId id, const Rect& activeRect, uint32_t& repCode)
{
    if (!screenManager_) {
        repCode = StatusCode::SCREEN_NOT_FOUND;
        return ERR_INVALID_VALUE;
    }
    GraphicIRect dstActiveRect {
        .x = activeRect.x,
        .y = activeRect.y,
        .w = activeRect.w,
        .h = activeRect.h,
    };
    if (!mainThread_) {
        repCode = StatusCode::INVALID_ARGUMENTS;
        return ERR_INVALID_VALUE;
    }
    auto task = [weakScreenManager = wptr<RSScreenManager>(screenManager_), id, dstActiveRect]() -> void {
        sptr<RSScreenManager> screenManager = weakScreenManager.promote();
        if (!screenManager) {
            return;
        }
        screenManager->SetScreenActiveRect(id, dstActiveRect);
    };
    mainThread_->ScheduleTask(task).wait();

    HgmTaskHandleThread::Instance().PostTask([id, dstActiveRect]() {
        HgmCore::Instance().NotifyScreenRectFrameRateChange(id, dstActiveRect);
    });
    repCode = StatusCode::SUCCESS;
    return ERR_OK;
}

void RSRenderServiceConnection::SetScreenOffset(ScreenId id, int32_t offsetX, int32_t offsetY)
{
    if (!screenManager_) {
        return;
    }
    screenManager_->SetScreenOffset(id, offsetX, offsetY);
}

void RSRenderServiceConnection::SetScreenFrameGravity(ScreenId id, int32_t gravity)
{
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), id, gravity]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        auto& context = connection->mainThread_->GetContext();
        context.GetNodeMap().TraverseScreenNodes([id, gravity](auto& node) {
            if (node && node->GetScreenId() == id) {
                node->GetMutableRenderProperties().SetFrameGravity(static_cast<Gravity>(gravity));
            }
        });
    };
    mainThread_->PostTask(task);
}

ErrCode RSRenderServiceConnection::RegisterOcclusionChangeCallback(
    sptr<RSIOcclusionChangeCallback> callback, int32_t& repCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mainThread_) {
        repCode = StatusCode::INVALID_ARGUMENTS;
        return ERR_INVALID_VALUE;
    }
    if (!callback) {
        RS_LOGD("RegisterOcclusionChangeCallback: callback is nullptr");
        repCode = StatusCode::INVALID_ARGUMENTS;
        return ERR_INVALID_VALUE;
    }
    mainThread_->RegisterOcclusionChangeCallback(remotePid_, callback);
    repCode = StatusCode::SUCCESS;
    return ERR_OK;
}

int32_t RSRenderServiceConnection::RegisterSurfaceOcclusionChangeCallback(
    NodeId id, sptr<RSISurfaceOcclusionChangeCallback> callback, std::vector<float>& partitionPoints)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    if (!callback) {
        RS_LOGD("RegisterSurfaceOcclusionChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }
    mainThread_->RegisterSurfaceOcclusionChangeCallback(id, remotePid_, callback, partitionPoints);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::UnRegisterSurfaceOcclusionChangeCallback(NodeId id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    mainThread_->UnRegisterSurfaceOcclusionChangeCallback(id);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterHgmConfigChangeCallback(sptr<RSIHgmConfigChangeCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback) {
        RS_LOGD("RegisterHgmConfigChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }

    HgmTaskHandleThread::Instance().PostSyncTask([this, &callback] () {
        HgmConfigCallbackManager::GetInstance()->RegisterHgmConfigChangeCallback(remotePid_, callback);
    });
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterHgmRefreshRateModeChangeCallback(
    sptr<RSIHgmConfigChangeCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback) {
        RS_LOGD("RegisterHgmRefreshRateModeChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }

    HgmTaskHandleThread::Instance().PostSyncTask([this, &callback] () {
        HgmConfigCallbackManager::GetInstance()->RegisterHgmRefreshRateModeChangeCallback(remotePid_, callback);
    });
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterHgmRefreshRateUpdateCallback(
    sptr<RSIHgmConfigChangeCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    HgmTaskHandleThread::Instance().PostSyncTask([this, &callback] () {
        HgmConfigCallbackManager::GetInstance()->RegisterHgmRefreshRateUpdateCallback(remotePid_, callback);
    });
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterFirstFrameCommitCallback(
    sptr<RSIFirstFrameCommitCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RSFirstFrameNotifier::GetInstance().RegisterFirstFrameCommitCallback(remotePid_, callback);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterFrameRateLinkerExpectedFpsUpdateCallback(int32_t dstPid,
    sptr<RSIFrameRateLinkerExpectedFpsUpdateCallback> callback)
{
    if (dstPid == 0) {
        return StatusCode::INVALID_ARGUMENTS;
    }

    HgmTaskHandleThread::Instance().PostTask([remotePid = remotePid_, dstPid, callback] () {
        HgmConfigCallbackManager::GetInstance()->RegisterXComponentExpectedFrameRateCallback(
            remotePid, dstPid, callback);
    });

    return StatusCode::SUCCESS;
}

ErrCode RSRenderServiceConnection::SetAppWindowNum(uint32_t num)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), num]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (!connection || !connection->mainThread_) {
            return;
        }
        connection->mainThread_->SetAppWindowNum(num);
    };
    mainThread_->PostTask(task);

    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetSystemAnimatedScenes(
    SystemAnimatedScenes systemAnimatedScenes, bool isRegularAnimation, bool& success)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mainThread_) {
        success = false;
        return ERR_INVALID_VALUE;
    }
#ifdef RS_ENABLE_GPU
    RSUifirstManager::Instance().OnProcessAnimateScene(systemAnimatedScenes);
    success = mainThread_->SetSystemAnimatedScenes(systemAnimatedScenes, isRegularAnimation);
    return ERR_OK;
#else
    success = false;
    return ERR_INVALID_VALUE;
#endif
}

void RSRenderServiceConnection::ShowWatermark(const std::shared_ptr<Media::PixelMap> &watermarkImg, bool isShow)
{
    if (!mainThread_) {
        return;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), watermarkImg, isShow]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        connection->mainThread_->ShowWatermark(watermarkImg, isShow);
    };
    mainThread_->PostTask(task);
}

int32_t RSRenderServiceConnection::ResizeVirtualScreen(ScreenId id, uint32_t width, uint32_t height)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
#ifdef RS_ENABLE_GPU
        return RSHardwareThread::Instance().ScheduleTask(
            [weakThis = wptr<RSRenderServiceConnection>(this), id, width, height]() -> int32_t {
                sptr<RSRenderServiceConnection> connection = weakThis.promote();
                if (connection == nullptr || connection->screenManager_ == nullptr) {
                    return RS_CONNECTION_ERROR;
                }
                return connection->screenManager_->ResizeVirtualScreen(id, width, height);
            }
        ).get();
#else
        return StatusCode::SCREEN_NOT_FOUND;
#endif
    } else if (mainThread_ != nullptr) {
        return mainThread_->ScheduleTask(
            [weakThis = wptr<RSRenderServiceConnection>(this), id, width, height]() -> int32_t {
                sptr<RSRenderServiceConnection> connection = weakThis.promote();
                if (connection == nullptr || connection->screenManager_ == nullptr) {
                    return RS_CONNECTION_ERROR;
                }
                return connection->screenManager_->ResizeVirtualScreen(id, width, height);
            }
        ).get();
    } else {
        return StatusCode::SCREEN_NOT_FOUND;
    }
}

ErrCode RSRenderServiceConnection::ReportJankStats()
{
#ifdef RS_ENABLE_GPU
    auto task = []() -> void { RSJankStats::GetInstance().ReportJankStats(); };
    renderThread_.PostTask(task);
#endif
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::NotifyLightFactorStatus(int32_t lightFactorStatus)
{
    HgmTaskHandleThread::Instance().PostTask([pid = remotePid_, lightFactorStatus]() {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr != nullptr) {
            frameRateMgr->HandleLightFactorStatus(pid, lightFactorStatus);
        }
    });
    return ERR_OK;
}

void RSRenderServiceConnection::NotifyPackageEvent(uint32_t listSize, const std::vector<std::string>& packageList)
{
    if (!mainThread_) {
        return;
    }
    mainThread_->NotifyPackageEvent(packageList);
    HgmTaskHandleThread::Instance().PostTask([pid = remotePid_, listSize, packageList]() {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr != nullptr) {
            frameRateMgr->HandlePackageEvent(pid, packageList);
        }
    });
}

void RSRenderServiceConnection::NotifyAppStrategyConfigChangeEvent(const std::string& pkgName, uint32_t listSize,
    const std::vector<std::pair<std::string, std::string>>& newConfig)
{
    HgmTaskHandleThread::Instance().PostTask([pid = remotePid_, listSize, pkgName, newConfig] () {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr != nullptr) {
            frameRateMgr->HandleAppStrategyConfigEvent(pid, pkgName, newConfig);
        }
    });
}

void RSRenderServiceConnection::NotifyRefreshRateEvent(const EventInfo& eventInfo)
{
    if (VOTER_SCENE_BLUR == eventInfo.eventName) {
        RsFrameBlurPredict::GetInstance().TakeEffectBlurScene(eventInfo);
        return;
    }

    if (VOTER_SCENE_GPU == eventInfo.eventName) {
        RsFrameReport::GetInstance().ReportScbSceneInfo(eventInfo.description, eventInfo.eventStatus);
        return;
    }
    HgmTaskHandleThread::Instance().PostTask([pid = remotePid_, eventInfo]() {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr != nullptr) {
            frameRateMgr->HandleRefreshRateEvent(pid, eventInfo);
        }
    });
}

void RSRenderServiceConnection::SetWindowExpectedRefreshRate(
    const std::unordered_map<uint64_t, EventInfo>& eventInfos
)
{
    HgmTaskHandleThread::Instance().PostTask([pid = remotePid_, eventInfos]() {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr != nullptr) {
            auto& softVsyncMgr = frameRateMgr->SoftVSyncMgrRef();
            softVsyncMgr.SetWindowExpectedRefreshRate(pid, eventInfos);
        }
    });
}

void RSRenderServiceConnection::SetWindowExpectedRefreshRate(
    const std::unordered_map<std::string, EventInfo>& eventInfos
)
{
    HgmTaskHandleThread::Instance().PostTask([pid = remotePid_, eventInfos]() {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr != nullptr) {
            auto& softVsyncMgr = frameRateMgr->SoftVSyncMgrRef();
            softVsyncMgr.SetWindowExpectedRefreshRate(pid, eventInfos);
        }
    });
}

ErrCode RSRenderServiceConnection::NotifySoftVsyncEvent(uint32_t pid, uint32_t rateDiscount)
{
    if (!appVSyncDistributor_) {
        return ERR_INVALID_VALUE;
    }
    appVSyncDistributor_->SetQosVSyncRateByPidPublic(pid, rateDiscount, true);
    return ERR_OK;
}

bool RSRenderServiceConnection::NotifySoftVsyncRateDiscountEvent(uint32_t pid,
    const std::string &name, uint32_t rateDiscount)
{
    if (!appVSyncDistributor_) {
        return false;
    }

    std::vector<uint64_t> linkerIds = appVSyncDistributor_->GetVsyncNameLinkerIds(pid, name);
    if (linkerIds.empty()) {
        RS_LOGW("NotifySoftVsyncRateDiscountEvent: pid=%{public}u linkerIds is nullptr.",
            pid);
        return false;
    }

    auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
    if (frameRateMgr == nullptr) {
        RS_LOGW("NotifySoftVsyncRateDiscountEvent: pid=%{public}u frameRateMgr is nullptr.",
            pid);
        return false;
    }

    if (!frameRateMgr->SetVsyncRateDiscountLTPO(linkerIds, rateDiscount)) {
        RS_LOGW("NotifySoftVsyncRateDiscountEvent: pid=%{public}u Set LTPO fail.",
            pid);
        return false;
    }

    VsyncError ret = appVSyncDistributor_->SetVsyncRateDiscountLTPS(pid, name, rateDiscount);
    if (ret != VSYNC_ERROR_OK) {
        RS_LOGW("NotifySoftVsyncRateDiscountEvent: pid=%{public}u Set LTPS fail.",
            pid);
        return false;
    }

    return true;
}

ErrCode RSRenderServiceConnection::NotifyTouchEvent(int32_t touchStatus, int32_t touchCnt)
{
    if (mainThread_ != nullptr) {
        mainThread_->HandleTouchEvent(touchStatus, touchCnt);
        return ERR_INVALID_VALUE;
    }
    auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
    if (frameRateMgr != nullptr) {
        frameRateMgr->HandleTouchEvent(remotePid_, touchStatus, touchCnt);
    }
    return ERR_OK;
}

void RSRenderServiceConnection::NotifyDynamicModeEvent(bool enableDynamicModeEvent)
{
    HgmTaskHandleThread::Instance().PostTask([enableDynamicModeEvent] () {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr == nullptr) {
            RS_LOGW("NotifyDynamicModeEvent: frameRateMgr is nullptr.");
            return;
        }
        frameRateMgr->HandleDynamicModeEvent(enableDynamicModeEvent);
    });
}

ErrCode RSRenderServiceConnection::NotifyHgmConfigEvent(const std::string &eventName, bool state)
{
    HgmTaskHandleThread::Instance().PostTask([eventName, state] () {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr == nullptr) {
            RS_LOGW("NotifyHgmConfigEvent: frameRateMgr is nullptr.");
            return;
        }
        RS_LOGI("NotifyHgmConfigEvent: recive notify %{public}s, %{public}d",
            eventName.c_str(), state);
        if (eventName == "HGMCONFIG_HIGH_TEMP") {
            frameRateMgr->HandleScreenExtStrategyChange(state, HGM_CONFIG_TYPE_THERMAL_SUFFIX);
        } else if (eventName == "IA_DRAG_SLIDE") {
            frameRateMgr->HandleScreenExtStrategyChange(state, HGM_CONFIG_TYPE_DRAGSLIDE_SUFFIX);
        } else if (eventName == "IL_THROW_SLIDE") {
            frameRateMgr->HandleScreenExtStrategyChange(state, HGM_CONFIG_TYPE_THROWSLIDE_SUFFIX);
        }
    });
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::NotifyXComponentExpectedFrameRate(const std::string& id, int32_t expectedFrameRate)
{
    HgmTaskHandleThread::Instance().PostTask([remotePid = remotePid_, id, expectedFrameRate] () {
        HgmConfigCallbackManager::GetInstance()->SyncXComponentExpectedFrameRateCallback(
            remotePid, id, expectedFrameRate);
    });
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::ReportEventResponse(DataBaseRs info)
{
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), info]() -> void {
        RSJankStats::GetInstance().SetReportEventResponse(info);
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        connection->mainThread_->SetForceRsDVsync(info.sceneId);
    };
#ifdef RS_ENABLE_GPU
    renderThread_.PostTask(task);
    RSUifirstManager::Instance().OnProcessEventResponse(info);
#endif
    RSUifirstFrameRateControl::Instance().SetAnimationStartInfo(info);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::ReportEventComplete(DataBaseRs info)
{
    auto task = [info]() -> void {
        RSJankStats::GetInstance().SetReportEventComplete(info);
    };
#ifdef RS_ENABLE_GPU
    renderThread_.PostTask(task);
    RSUifirstManager::Instance().OnProcessEventComplete(info);
#endif
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::ReportEventJankFrame(DataBaseRs info)
{
#ifdef RS_ENABLE_GPU
    bool isReportTaskDelayed = renderThread_.IsMainLooping();
    auto task = [info, isReportTaskDelayed]() -> void {
        RSJankStats::GetInstance().SetReportEventJankFrame(info, isReportTaskDelayed);
    };
    renderThread_.PostTask(task);
#endif
    RSUifirstFrameRateControl::Instance().SetAnimationEndInfo(info);
    return ERR_OK;
}

void RSRenderServiceConnection::ReportRsSceneJankStart(AppInfo info)
{
    auto task = [info]() -> void {
        RSJankStats::GetInstance().SetReportRsSceneJankStart(info);
    };
    renderThread_.PostTask(task);
}

void RSRenderServiceConnection::ReportRsSceneJankEnd(AppInfo info)
{
    auto task = [info]() -> void {
        RSJankStats::GetInstance().SetReportRsSceneJankEnd(info);
    };
    renderThread_.PostTask(task);
}

ErrCode RSRenderServiceConnection::ReportGameStateData(GameStateData info)
{
    RS_LOGD("ReportGameStateData = %{public}s, uid = %{public}d, state = %{public}d, "
            "pid = %{public}d renderTid = %{public}d ",
        info.bundleName.c_str(), info.uid, info.state, info.pid, info.renderTid);

    FrameReport::GetInstance().SetGameScene(info.pid, info.state);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetHardwareEnabled(NodeId id, bool isEnabled, SelfDrawingNodeType selfDrawingType,
    bool dynamicHardwareEnable)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), id, isEnabled, selfDrawingType,
        dynamicHardwareEnable]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        auto& context = connection->mainThread_->GetContext();
        auto node = context.GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(id);
        if (node) {
            node->SetHardwareEnabled(isEnabled, selfDrawingType, dynamicHardwareEnable);
        }
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetHidePrivacyContent(NodeId id, bool needHidePrivacyContent, uint32_t& resCode)
{
    if (!mainThread_) {
        resCode = static_cast<int32_t>(RSInterfaceErrorCode::UNKNOWN_ERROR);
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), id, needHidePrivacyContent]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        auto& context = connection->mainThread_->GetContext();
        auto node = context.GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(id);
        if (node) {
            node->SetHidePrivacyContent(needHidePrivacyContent);
        }
    };
    mainThread_->PostTask(task);
    resCode = static_cast<uint32_t>(RSInterfaceErrorCode::NO_ERROR);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetCacheEnabledForRotation(bool isEnabled)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    auto task = [isEnabled]() {
        RSSystemProperties::SetCacheEnabledForRotation(isEnabled);
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

std::vector<ActiveDirtyRegionInfo> RSRenderServiceConnection::GetActiveDirtyRegionInfo()
{
#ifdef RS_ENABLE_GPU
    const auto& activeDirtyRegionInfos = GpuDirtyRegionCollection::GetInstance().GetActiveDirtyRegionInfo();
    GpuDirtyRegionCollection::GetInstance().ResetActiveDirtyRegionInfo();
    return activeDirtyRegionInfos;
#else
    return {};
#endif
}

GlobalDirtyRegionInfo RSRenderServiceConnection::GetGlobalDirtyRegionInfo()
{
#ifdef RS_ENABLE_GPU
    const auto& globalDirtyRegionInfo = GpuDirtyRegionCollection::GetInstance().GetGlobalDirtyRegionInfo();
    GpuDirtyRegionCollection::GetInstance().ResetGlobalDirtyRegionInfo();
    return globalDirtyRegionInfo;
#else
    return {};
#endif
}

LayerComposeInfo RSRenderServiceConnection::GetLayerComposeInfo()
{
    const auto& layerComposeInfo = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    LayerComposeCollection::GetInstance().ResetLayerComposeInfo();
    return layerComposeInfo;
}

HwcDisabledReasonInfos RSRenderServiceConnection::GetHwcDisabledReasonInfo()
{
    return HwcDisabledReasonCollection::GetInstance().GetHwcDisabledReasonInfo();
}

ErrCode RSRenderServiceConnection::GetHdrOnDuration(int64_t& hdrOnDuration)
{
    auto rsHdrCollection = RsHdrCollection::GetInstance();
    if (rsHdrCollection == nullptr) {
        return ERR_INVALID_VALUE;
    }
    hdrOnDuration = rsHdrCollection->GetHdrOnDuration();
    rsHdrCollection->ResetHdrOnDuration();
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetVmaCacheStatus(bool flag)
{
#ifdef RS_ENABLE_GPU
    renderThread_.SetVmaCacheStatus(flag);
#endif
    return ERR_OK;
}

#ifdef TP_FEATURE_ENABLE
ErrCode RSRenderServiceConnection::SetTpFeatureConfig(int32_t feature, const char* config,
    TpFeatureConfigType tpFeatureConfigType)
{
    switch (tpFeatureConfigType) {
        case TpFeatureConfigType::DEFAULT_TP_FEATURE: {
            if (!TOUCH_SCREEN->IsSetFeatureConfigHandleValid()) {
                RS_LOGW("SetTpFeatureConfig: SetFeatureConfigHandl is nullptr");
                return ERR_INVALID_VALUE;
            }
            if (TOUCH_SCREEN->SetFeatureConfig(feature, config) < 0) {
                RS_LOGW("SetTpFeatureConfig: SetFeatureConfig failed");
                return ERR_INVALID_VALUE;
            }
            return ERR_OK;
        }
        case TpFeatureConfigType::AFT_TP_FEATURE: {
            if (!TOUCH_SCREEN->IsSetAftConfigHandleValid()) {
                RS_LOGW("SetTpFeatureConfig: SetAftConfigHandl is nullptr");
                return ERR_INVALID_VALUE;
            }
            if (TOUCH_SCREEN->SetAftConfig(config) < 0) {
                RS_LOGW("SetTpFeatureConfig: SetAftConfig failed");
                return ERR_INVALID_VALUE;
            }
            return ERR_OK;
        }
        default: {
            RS_LOGW("SetTpFeatureConfig: unknown TpFeatureConfigType: %" PRIu8"",
                static_cast<uint8_t>(tpFeatureConfigType));
            return ERR_INVALID_VALUE;
        }
    }
}
#endif

void RSRenderServiceConnection::SetVirtualScreenUsingStatus(bool isVirtualScreenUsingStatus)
{
    if (isVirtualScreenUsingStatus) {
        EventInfo event = { "VOTER_VIRTUALDISPLAY", ADD_VOTE, OLED_60_HZ, OLED_60_HZ };
        NotifyRefreshRateEvent(event);
    } else {
        EventInfo event = { "VOTER_VIRTUALDISPLAY", REMOVE_VOTE };
        NotifyRefreshRateEvent(event);
    }
    return;
}

ErrCode RSRenderServiceConnection::SetCurtainScreenUsingStatus(bool isCurtainScreenOn)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), isCurtainScreenOn]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        connection->mainThread_->SetCurtainScreenUsingStatus(isCurtainScreenOn);
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::DropFrameByPid(const std::vector<int32_t> pidList)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this), pidList]() {
            // don't use 'this' directly
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return;
            }
            connection->mainThread_->AddPidNeedDropFrame(pidList);
        }
    );
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetGpuCrcDirtyEnabledPidList(const std::vector<int32_t> pidList)
{
    if (!mainThread_ || pidList.size() > PIDLIST_SIZE_MAX) {
        return ERR_INVALID_VALUE;
    }
    mainThread_->ScheduleTask(
        [weakThis = wptr<RSRenderServiceConnection>(this), pidList]() {
            // don't use 'this' directly
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (connection == nullptr || connection->mainThread_ == nullptr) {
                return;
            }
            RSGpuDirtyCollector::GetInstance().SetSelfDrawingGpuDirtyPidList(pidList);
        }
    );
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetOptimizeCanvasDirtyPidList(const std::vector<int32_t>& pidList)
{
    if (pidList.size() > PIDLIST_SIZE_MAX) {
        return ERR_INVALID_VALUE;
    }
    RSOptimizeCanvasDirtyCollector::GetInstance().SetOptimizeCanvasDirtyPidList(pidList);
    return ERR_OK;
}

int32_t RSRenderServiceConnection::RegisterUIExtensionCallback(uint64_t userId, sptr<RSIUIExtensionCallback> callback,
    bool unobscured)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    if (!callback) {
        RS_LOGE("RegisterUIExtensionCallback register null callback, failed.");
        return StatusCode::INVALID_ARGUMENTS;
    }
    mainThread_->RegisterUIExtensionCallback(remotePid_, userId, callback, unobscured);
    return StatusCode::SUCCESS;
}

ErrCode RSRenderServiceConnection::SetVirtualScreenStatus(ScreenId id,
    VirtualScreenStatus screenStatus, bool& success)
{
    if (!screenManager_) {
        success = false;
        return StatusCode::SCREEN_NOT_FOUND;
    }
    RS_LOGD("SetVirtualScreenStatus ScreenId:%{public}" PRIu64 " screenStatus:%{public}d",
        id, screenStatus);
    success = screenManager_->SetVirtualScreenStatus(id, screenStatus);
    return StatusCode::SUCCESS;
}

ErrCode RSRenderServiceConnection::SetAncoForceDoDirect(bool direct, bool& res)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mainThread_ == nullptr) {
        res = false;
        return ERR_INVALID_VALUE;
    }
    mainThread_->SetAncoForceDoDirect(direct);
    res = true;
    return ERR_OK;
}

void RSRenderServiceConnection::SetFreeMultiWindowStatus(bool enable)
{
#ifdef RS_ENABLE_GPU
    if (mainThread_ == nullptr) {
        return;
    }
    auto task = [enable]() -> void {
        RSUifirstManager::Instance().SetFreeMultiWindowStatus(enable);
    };
    mainThread_->PostTask(task);
#endif
}

ErrCode RSRenderServiceConnection::RegisterSurfaceBufferCallback(pid_t pid, uint64_t uid,
    sptr<RSISurfaceBufferCallback> callback)
{
    RSSurfaceBufferCallbackManager::Instance().RegisterSurfaceBufferCallback(pid, uid, callback);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::UnregisterSurfaceBufferCallback(pid_t pid, uint64_t uid)
{
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(pid, uid);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetLayerTopForHWC(NodeId nodeId, bool isTop, uint32_t zOrder)
{
    if (mainThread_ == nullptr) {
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), nodeId, isTop, zOrder]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        auto& context = connection->mainThread_->GetContext();
        auto surfaceNode = context.GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(nodeId);
        if (surfaceNode == nullptr) {
            return;
        }
        surfaceNode->SetLayerTop(isTop, false);
        surfaceNode->SetTopLayerZOrder(zOrder);
        // It can be displayed immediately after layer-top changed.
        connection->mainThread_->SetDirtyFlag();
        connection->mainThread_->RequestNextVSync();
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetLayerTop(const std::string &nodeIdStr, bool isTop)
{
    if (mainThread_ == nullptr) {
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), nodeIdStr, isTop]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        auto& context = connection->mainThread_->GetContext();
        context.GetNodeMap().TraverseSurfaceNodes(
            [&nodeIdStr, &isTop](const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode) mutable {
            if ((surfaceNode != nullptr) && (surfaceNode->GetName() == nodeIdStr) &&
                (surfaceNode->GetSurfaceNodeType() == RSSurfaceNodeType::SELF_DRAWING_NODE)) {
                surfaceNode->SetLayerTop(isTop);
                return;
            }
        });
        // It can be displayed immediately after layer-top changed.
        connection->mainThread_->SetDirtyFlag();
        connection->mainThread_->RequestNextVSync();
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetForceRefresh(const std::string &nodeIdStr, bool isForceRefresh)
{
    if (mainThread_ == nullptr) {
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), nodeIdStr, isForceRefresh]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        auto& context = connection->mainThread_->GetContext();
        context.GetNodeMap().TraverseSurfaceNodes(
            [&nodeIdStr, &isForceRefresh](const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode) mutable {
            if ((surfaceNode != nullptr) && (surfaceNode->GetName() == nodeIdStr) &&
                (surfaceNode->GetSurfaceNodeType() == RSSurfaceNodeType::SELF_DRAWING_NODE)) {
                surfaceNode->SetForceRefresh(isForceRefresh);
                return;
            }
        });
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

void RSRenderServiceConnection::RegisterTransactionDataCallback(uint64_t token,
    uint64_t timeStamp, sptr<RSITransactionDataCallback> callback)
{
    RSTransactionDataCallbackManager::Instance().RegisterTransactionDataCallback(token, timeStamp, callback);
}

void RSRenderServiceConnection::SetColorFollow(const std::string &nodeIdStr, bool isColorFollow)
{
    if (mainThread_ == nullptr) {
        return;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), nodeIdStr, isColorFollow]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        auto& context = connection->mainThread_->GetContext();
        context.GetNodeMap().TraverseSurfaceNodes(
            [&nodeIdStr, &isColorFollow](const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode) mutable {
            if ((surfaceNode != nullptr) && (surfaceNode->GetName() == nodeIdStr) &&
                (surfaceNode->GetSurfaceNodeType() == RSSurfaceNodeType::SELF_DRAWING_NODE)) {
                surfaceNode->SetColorFollow(isColorFollow);
                return;
            }
        });
        connection->mainThread_->SetDirtyFlag();
        connection->mainThread_->RequestNextVSync();
    };
    mainThread_->PostTask(task);
}

ErrCode RSRenderServiceConnection::NotifyScreenSwitched()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!screenManager_) {
        RS_LOGE("NotifyScreenSwitched screenManager_ is nullptr");
        return ERR_INVALID_VALUE;
    }
    RS_LOGI("NotifyScreenSwitched SetScreenSwitchStatus true");
    RS_TRACE_NAME_FMT("NotifyScreenSwitched");
    screenManager_->SetScreenSwitchStatus(true);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetWindowContainer(NodeId nodeId, bool value)
{
    if (!mainThread_) {
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), nodeId, value]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        auto& nodeMap = connection->mainThread_->GetContext().GetNodeMap();
        if (auto node = nodeMap.GetRenderNode<RSCanvasRenderNode>(nodeId)) {
            auto displayNodeId = node->GetLogicalDisplayNodeId();
            if (auto displayNode = nodeMap.GetRenderNode<RSLogicalDisplayRenderNode>(displayNodeId)) {
                RS_LOGD("SetWindowContainer nodeId: %{public}" PRIu64 ", value: %{public}d",
                    nodeId, value);
                displayNode->SetWindowContainer(value ? node : nullptr);
            } else {
                RS_LOGE("SetWindowContainer displayNode is nullptr, nodeId: %{public}"
                    PRIu64, displayNodeId);
            }
        } else {
            RS_LOGE("SetWindowContainer node is nullptr, nodeId: %{public}" PRIu64,
                nodeId);
        }
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

int32_t RSRenderServiceConnection::RegisterSelfDrawingNodeRectChangeCallback(
    const RectConstraint& constraint, sptr<RSISelfDrawingNodeRectChangeCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    if (!callback) {
        RS_LOGE("RegisterSelfDrawingNodeRectChangeCallback register null callback, failed.");
        return StatusCode::INVALID_ARGUMENTS;
    }

    auto task = [pid = remotePid_, constraint, callback]() {
        SelfDrawingNodeMonitor::GetInstance().RegisterRectChangeCallback(pid, constraint, callback);
    };
    mainThread_->PostTask(task);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::UnRegisterSelfDrawingNodeRectChangeCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    auto task = [pid = remotePid_]() { SelfDrawingNodeMonitor::GetInstance().UnRegisterRectChangeCallback(pid); };
    mainThread_->PostTask(task);
    return StatusCode::SUCCESS;
}

#ifdef RS_ENABLE_OVERLAY_DISPLAY
ErrCode RSRenderServiceConnection::SetOverlayDisplayMode(int32_t mode)
{
    RS_LOGI("SetOverlayDisplayMode: mode: [%{public}d]", mode);
    return RSOverlayDisplayManager::Instance().SetOverlayDisplayMode(mode) == 0 ? ERR_OK : ERR_INVALID_VALUE;
}
#endif

ErrCode RSRenderServiceConnection::NotifyPageName(const std::string &packageName,
    const std::string &pageName, bool isEnter)
{
    HgmTaskHandleThread::Instance().PostTask([pid = remotePid_, packageName, pageName, isEnter]() {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr != nullptr) {
            frameRateMgr->NotifyPageName(pid, packageName, pageName, isEnter);
        }
    });
    return StatusCode::SUCCESS;
}

bool RSRenderServiceConnection::GetHighContrastTextState()
{
    return RSBaseRenderEngine::IsHighContrastEnabled();
}

ErrCode RSRenderServiceConnection::AvcodecVideoStart(const std::vector<uint64_t>& uniqueIdList,
    const std::vector<std::string>& surfaceNameList, uint32_t fps, uint64_t reportTime)
{
    auto task = [uniqueIdList, surfaceNameList, fps, reportTime]() -> void {
        RSJankStats::GetInstance().AvcodecVideoStart(uniqueIdList, surfaceNameList, fps, reportTime);
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::AvcodecVideoStop(const std::vector<uint64_t>& uniqueIdList,
    const std::vector<std::string>& surfaceNameList, uint32_t fps)
{
    auto task = [uniqueIdList, surfaceNameList, fps]() -> void {
        RSJankStats::GetInstance().AvcodecVideoStop(uniqueIdList, surfaceNameList, fps);
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::SetBehindWindowFilterEnabled(bool enabled)
{
    if (!mainThread_) {
        RS_LOGE("SetBehindWindowFilterEnabled mainThread_ is nullptr.");
        return ERR_INVALID_VALUE;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), enabled]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (connection == nullptr || connection->mainThread_ == nullptr) {
            return;
        }
        if (RSSystemProperties::GetBehindWindowFilterEnabled() == enabled) {
            return;
        }
        RSSystemProperties::SetBehindWindowFilterEnabled(enabled);
        auto& nodeMap = connection->mainThread_->GetContext().GetNodeMap();
        bool needRequestNextVSync = false;
        nodeMap.TraverseSurfaceNodes(
            [&needRequestNextVSync](const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode) mutable {
                if (!surfaceNode) {
                    return;
                }
                if (!surfaceNode->NeedUpdateDrawableBehindWindow()) {
                    return;
                }
                surfaceNode->SetContentDirty();
                needRequestNextVSync = true;
            });
        if (needRequestNextVSync) {
            connection->mainThread_->RequestNextVSync();
            connection->mainThread_->SetForceUpdateUniRenderFlag(true);
        }
    };
    mainThread_->PostTask(task);
    return ERR_OK;
}

ErrCode RSRenderServiceConnection::GetBehindWindowFilterEnabled(bool& enabled)
{
    enabled = RSSystemProperties::GetBehindWindowFilterEnabled();
    return ERR_OK;
}

int32_t RSRenderServiceConnection::GetPidGpuMemoryInMB(pid_t pid, float &gpuMemInMB)
{
    MemorySnapshotInfo memorySnapshotInfo;

    bool ret = MemorySnapshot::Instance().GetMemorySnapshotInfoByPid(pid, memorySnapshotInfo);
    if (!ret) {
        RS_LOGD("RSRenderServiceConnection::GetPidGpuMemoryInMB fail to find pid!");
        return ERR_INVALID_VALUE;
    }
    gpuMemInMB = static_cast<float>(memorySnapshotInfo.gpuMemory) / MEM_BYTE_TO_MB;
    RS_LOGD("RSRenderServiceConnection::GetPidGpuMemoryInMB called succ");
    return ERR_OK;
}

RetCodeHrpService RSRenderServiceConnection::ProfilerServiceOpenFile(const HrpServiceDirInfo& dirInfo,
    const std::string& fileName, int32_t flags, int& outFd)
{
#ifdef RS_PROFILER_ENABLED
    if (fileName.length() == 0 || !HrpServiceValidDirOrFileName(fileName)) {
        return RET_HRP_SERVICE_ERR_INVALID_PARAM;
    }

    return RSProfiler::HrpServiceOpenFile(dirInfo, fileName, flags, outFd);
#else
    outFd = -1;
    return RET_HRP_SERVICE_ERR_UNSUPPORTED;
#endif
}

RetCodeHrpService RSRenderServiceConnection::ProfilerServicePopulateFiles(const HrpServiceDirInfo& dirInfo,
    uint32_t firstFileIndex, std::vector<HrpServiceFileInfo>& outFiles)
{
#ifdef RS_PROFILER_ENABLED
    return RSProfiler::HrpServicePopulateFiles(dirInfo, firstFileIndex, outFiles);
#else
    outFiles.clear();
    return RET_HRP_SERVICE_ERR_UNSUPPORTED;
#endif
}

bool RSRenderServiceConnection::ProfilerIsSecureScreen()
{
#ifdef RS_PROFILER_ENABLED
    if (!RSSystemProperties::GetProfilerEnabled()) {
        return false;
    }
    return RSProfiler::IsSecureScreen();
#else
    return false;
#endif
}

void RSRenderServiceConnection::ClearUifirstCache(NodeId id)
{
    if (!mainThread_) {
        return;
    }
    auto task = [id]() -> void {
        RSUifirstManager::Instance().AddMarkedClearCacheNode(id);
    };
    mainThread_->PostTask(task);
}

std::string RSRenderServiceConnection::GetBundleName(pid_t pid)
{
    std::lock_guard<std::mutex> lock(pidToBundleMutex_);
    if (auto it = pidToBundleName_.find(pid); it != pidToBundleName_.end()) {
        return it->second;
    }

    static const auto appMgrClient = std::make_shared<AppExecFwk::AppMgrClient>();
    if (appMgrClient == nullptr) {
        RS_LOGE("GetBundleName get appMgrClient fail.");
        return {};
    }

    std::string bundleName{};
    int32_t uid{0};
    int32_t ret = appMgrClient->GetBundleNameByPid(pid, bundleName, uid);
    if ((ret != ERR_OK) || bundleName.empty()) {
        RS_LOGE("GetBundleName failed, ret=%{public}d.", ret);
        return {};
    }

    pidToBundleName_.emplace(pid, bundleName);
    return bundleName;
}
} // namespace Rosen
} // namespace OHOS
