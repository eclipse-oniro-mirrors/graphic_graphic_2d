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

#ifndef RS_MAIN_THREAD
#define RS_MAIN_THREAD

#include <event_handler.h>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <thread>

#include "refbase.h"
#include "rs_base_render_engine.h"
#include "rs_draw_frame.h"
#include "vsync_distributor.h"
#include "vsync_receiver.h"

#include "command/rs_command.h"
#include "common/rs_common_def.h"
#include "common/rs_thread_handler.h"
#include "common/rs_thread_looper.h"
#include "drawable/rs_render_node_drawable_adapter.h"
#include "ipc_callbacks/iapplication_agent.h"
#include "ipc_callbacks/rs_iocclusion_change_callback.h"
#include "ipc_callbacks/rs_isurface_occlusion_change_callback.h"
#include "ipc_callbacks/rs_iuiextension_callback.h"
#include "memory/rs_app_state_listener.h"
#include "memory/rs_memory_graphic.h"
#include "params/rs_render_thread_params.h"
#include "pipeline/rs_context.h"
#include "pipeline/rs_draw_frame.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "platform/common/rs_event_manager.h"
#include "platform/drawing/rs_vsync_client.h"
#include "transaction/rs_transaction_data.h"
#include "transaction/rs_uiextension_data.h"

#ifdef RES_SCHED_ENABLE
#include "vsync_system_ability_listener.h"
#endif

namespace OHOS::Rosen {
#if defined(ACCESSIBILITY_ENABLE)
class AccessibilityObserver;
#endif
class HgmFrameRateManager;
class RSUniRenderVisitor;
struct FrameRateRangeData;
namespace Detail {
template<typename Task>
class ScheduledTask : public RefBase {
public:
    static auto Create(Task&& task)
    {
        sptr<ScheduledTask<Task>> t(new ScheduledTask(std::forward<Task&&>(task)));
        return std::make_pair(t, t->task_.get_future());
    }

    void Run()
    {
        task_();
    }

private:
    explicit ScheduledTask(Task&& task) : task_(std::move(task)) {}
    ~ScheduledTask() override = default;

    using Return = std::invoke_result_t<Task>;
    std::packaged_task<Return()> task_;
};
} // namespace Detail

class RSMainThread {
public:
    static RSMainThread* Instance();

    void Init();
    void Start();
    bool IsNeedProcessBySingleFrameComposer(std::unique_ptr<RSTransactionData>& rsTransactionData);
    void UpdateFocusNodeId(NodeId focusNodeId);
    void UpdateNeedDrawFocusChange(NodeId id);
    void ProcessDataBySingleFrameComposer(std::unique_ptr<RSTransactionData>& rsTransactionData);
    void RecvAndProcessRSTransactionDataImmediately(std::unique_ptr<RSTransactionData>& rsTransactionData);
    void RecvRSTransactionData(std::unique_ptr<RSTransactionData>& rsTransactionData);
    void RequestNextVSync(const std::string& fromWhom = "unknown", int64_t lastVSyncTS = 0);
    void PostTask(RSTaskMessage::RSTask task);
    void PostTask(RSTaskMessage::RSTask task, const std::string& name, int64_t delayTime,
        AppExecFwk::EventQueue::Priority priority = AppExecFwk::EventQueue::Priority::IDLE);
    void RemoveTask(const std::string& name);
    void PostSyncTask(RSTaskMessage::RSTask task);
    bool IsIdle() const;
    void RenderServiceTreeDump(std::string& dumpString, bool forceDumpSingleFrame = true);
    void RsEventParamDump(std::string& dumpString);
    bool IsUIFirstOn() const;
    void UpdateAnimateNodeFlag();
    void ResetAnimateNodeFlag();
    void GetAppMemoryInMB(float& cpuMemSize, float& gpuMemSize);
    void ClearMemoryCache(ClearMemoryMoment moment, bool deeply = false, pid_t pid = -1);
    static bool CheckIsHdrSurface(const RSSurfaceRenderNode& surfaceNode);

    template<typename Task, typename Return = std::invoke_result_t<Task>>
    std::future<Return> ScheduleTask(Task&& task)
    {
        auto [scheduledTask, taskFuture] = Detail::ScheduledTask<Task>::Create(std::forward<Task&&>(task));
        PostTask([t(std::move(scheduledTask))]() { t->Run(); });
        return std::move(taskFuture);
    }

    const std::shared_ptr<RSBaseRenderEngine> GetRenderEngine() const
    {
        RS_LOGD("You'd better to call GetRenderEngine from RSUniRenderThread directly");
        return isUniRender_ ? std::move(RSUniRenderThread::Instance().GetRenderEngine()) : renderEngine_;
    }

    bool GetClearMemoryFinished() const
    {
        return clearMemoryFinished_;
    }

    RSContext& GetContext()
    {
        return *context_;
    }

    std::thread::id Id() const
    {
        return mainThreadId_;
    }

    bool CheckIsHardwareEnabledBufferUpdated() const
    {
        return isHardwareEnabledBufferUpdated_;
    }

    /* Judge if rootnode has to be prepared based on it corresponding process is active
     * If its pid is in activeProcessPids_ set, return true
     */
    bool CheckNodeHasToBePreparedByPid(NodeId nodeId, bool isClassifyByRoot);
    // check if active app has static drawing cache
    bool IsDrawingGroupChanged(RSRenderNode& cacheRootNode) const;
    // check if active instance only move or scale it's main window surface without rearrangement
    // instanceNodeId should be MainWindowType, or it cannot grep correct app's info
    void CheckAndUpdateInstanceContentStaticStatus(std::shared_ptr<RSSurfaceRenderNode> instanceNode) const;

    void RegisterApplicationAgent(uint32_t pid, sptr<IApplicationAgent> app);
    void UnRegisterApplicationAgent(sptr<IApplicationAgent> app);

    void RegisterOcclusionChangeCallback(pid_t pid, sptr<RSIOcclusionChangeCallback> callback);
    void UnRegisterOcclusionChangeCallback(pid_t pid);

    void RegisterSurfaceOcclusionChangeCallback(
        NodeId id, pid_t pid, sptr<RSISurfaceOcclusionChangeCallback> callback, std::vector<float>& partitionPoints);
    void UnRegisterSurfaceOcclusionChangeCallback(NodeId id);
    void ClearSurfaceOcclusionChangeCallback(pid_t pid);
    bool SurfaceOcclusionCallBackIfOnTreeStateChanged();

    void WaitUtilUniRenderFinished();
    void NotifyUniRenderFinish();

    bool WaitHardwareThreadTaskExecute();
    void NotifyHardwareThreadCanExecuteTask();

    void ClearTransactionDataPidInfo(pid_t remotePid);
    void AddTransactionDataPidInfo(pid_t remotePid);

    void SetFocusAppInfo(
        int32_t pid, int32_t uid, const std::string &bundleName, const std::string &abilityName, uint64_t focusNodeId);
    std::unordered_map<NodeId, bool> GetCacheCmdSkippedNodes() const;

    sptr<VSyncDistributor> rsVSyncDistributor_;
    sptr<VSyncController> rsVSyncController_;
    sptr<VSyncController> appVSyncController_;
    sptr<VSyncGenerator> vsyncGenerator_;

    void ReleaseSurface();
    void AddToReleaseQueue(std::shared_ptr<Drawing::Surface>&& surface);

    void AddUiCaptureTask(NodeId id, std::function<void()> task);
    void ProcessUiCaptureTasks();

    void SetDirtyFlag(bool isDirty = true);
    bool GetDirtyFlag();
    void SetColorPickerForceRequestVsync(bool colorPickerForceRequestVsync);
    void SetNoNeedToPostTask(bool noNeedToPostTask);
    void SetAccessibilityConfigChanged();
    void SetScreenPowerOnChanged(bool val);
    bool GetScreenPowerOnChanged() const;
    bool IsAccessibilityConfigChanged() const;
    bool IsCurtainScreenUsingStatusChanged() const;
    void ForceRefreshForUni();
    void TrimMem(std::unordered_set<std::u16string>& argSets, std::string& result);
    void DumpMem(std::unordered_set<std::u16string>& argSets, std::string& result, std::string& type, int pid = 0);
    void DumpNode(std::string& result, uint64_t nodeId) const;
    void CountMem(int pid, MemoryGraphic& mem);
    void CountMem(std::vector<MemoryGraphic>& mems);
    void SetAppWindowNum(uint32_t num);
    bool SetSystemAnimatedScenes(SystemAnimatedScenes systemAnimatedScenes);
    SystemAnimatedScenes GetSystemAnimatedScenes();
    void ShowWatermark(const std::shared_ptr<Media::PixelMap> &watermarkImg, bool flag);
    void SetIsCachedSurfaceUpdated(bool isCachedSurfaceUpdated);
    pid_t GetDesktopPidForRotationScene() const;
    void SetForceUpdateUniRenderFlag(bool flag)
    {
        forceUpdateUniRenderFlag_ = flag;
    }
    void SetIdleTimerExpiredFlag(bool flag)
    {
        idleTimerExpiredFlag_ = flag;
    }
    void SetRSIdleTimerExpiredFlag(bool flag)
    {
        rsIdleTimerExpiredFlag_ = flag;
    }
    std::shared_ptr<Drawing::Image> GetWatermarkImg();
    bool GetWatermarkFlag();

    bool IsWatermarkFlagChanged() const
    {
        return lastWatermarkFlag_ != watermarkFlag_;
    }

    uint64_t GetFrameCount() const
    {
        return frameCount_;
    }
    std::vector<NodeId>& GetDrawStatusVec()
    {
        return curDrawStatusVec_;
    }
    void SetAppVSyncDistributor(const sptr<VSyncDistributor>& appVSyncDistributor)
    {
        appVSyncDistributor_ = appVSyncDistributor;
    }

    DeviceType GetDeviceType() const;
    bool IsSingleDisplay();
    bool HasMirrorDisplay() const;
    bool GetNoNeedToPostTask();
    uint64_t GetFocusNodeId() const;
    uint64_t GetFocusLeashWindowId() const;
    bool GetClearMemDeeply() const
    {
        return clearMemDeeply_;
    }

    ClearMemoryMoment GetClearMoment() const
    {
        if (!context_) {
            return ClearMemoryMoment::NO_CLEAR;
        }
        return context_->clearMoment_;
    }

    void SetClearMoment(ClearMemoryMoment moment)
    {
        if (!context_) {
            return;
        }
        context_->clearMoment_ = moment;
    }

    bool IsPCThreeFingerScenesListScene() const
    {
        return !threeFingerScenesList_.empty();
    }

    void SurfaceOcclusionChangeCallback(VisibleData& dstCurVisVec);
    void SurfaceOcclusionCallback();
    void SubscribeAppState();
    void HandleOnTrim(Memory::SystemMemoryLevel level);
    void SetCurtainScreenUsingStatus(bool isCurtainScreenOn);
    bool IsCurtainScreenOn() const;
    void NotifySurfaceCapProcFinish();
    void WaitUntilSurfaceCapProcFinished();
    void SetSurfaceCapProcFinished(bool flag);

    bool GetParallelCompositionEnabled();
    std::shared_ptr<HgmFrameRateManager> GetFrameRateMgr() { return frameRateMgr_; };
    void SetFrameIsRender(bool isRender);
    const std::vector<std::shared_ptr<RSSurfaceRenderNode>>& GetSelfDrawingNodes() const;
    bool GetMarkRenderFlag() const
    {
        return markRenderFlag_;
    }
    void ResetMarkRenderFlag()
    {
        markRenderFlag_ = false;
    }

    bool IsOnVsync() const
    {
        return isOnVsync_.load();
    }

    bool GetDiscardJankFrames() const
    {
        return discardJankFrames_.load();
    }

    void SetDiscardJankFrames(bool discardJankFrames)
    {
        if (discardJankFrames_.load() != discardJankFrames) {
            discardJankFrames_.store(discardJankFrames);
        }
    }

    bool GetSkipJankAnimatorFrame() const
    {
        return skipJankAnimatorFrame_.load();
    }

    void SetSkipJankAnimatorFrame(bool skipJankAnimatorFrame)
    {
        skipJankAnimatorFrame_.store(skipJankAnimatorFrame);
    }

    bool IsRequestedNextVSync();

    bool GetNextDVsyncAnimateFlag() const
    {
        return needRequestNextVsyncAnimate_;
    }

    bool IsFirstFrameOfPartialRender() const
    {
        return isFirstFrameOfPartialRender_;
    }

    void CallbackDrawContextStatusToWMS(bool isUniRender = false);
    void SetHardwareTaskNum(uint32_t num);
    void RegisterUIExtensionCallback(pid_t pid, uint64_t userId, sptr<RSIUIExtensionCallback> callback);
    void UnRegisterUIExtensionCallback(pid_t pid);

    bool IsSystemAnimatedScenesListEmpty() const
    {
        return systemAnimatedScenesList_.empty();
    }

private:
    using TransactionDataIndexMap = std::unordered_map<pid_t,
        std::pair<uint64_t, std::vector<std::unique_ptr<RSTransactionData>>>>;

    RSMainThread();
    ~RSMainThread() noexcept;
    RSMainThread(const RSMainThread&) = delete;
    RSMainThread(const RSMainThread&&) = delete;
    RSMainThread& operator=(const RSMainThread&) = delete;
    RSMainThread& operator=(const RSMainThread&&) = delete;

    void OnVsync(uint64_t timestamp, uint64_t frameCount, void* data);
    void ProcessCommand();
    void Animate(uint64_t timestamp);
    void ConsumeAndUpdateAllNodes();
    void CollectInfoForHardwareComposer();
    void ReleaseAllNodesBuffer();
    void Render();
    void OnUniRenderDraw();
    void SetDeviceType();
    void ColorPickerRequestVsyncIfNeed();
    void UniRender(std::shared_ptr<RSBaseRenderNode> rootNode);
    bool CheckSurfaceNeedProcess(OcclusionRectISet& occlusionSurfaces, std::shared_ptr<RSSurfaceRenderNode> curSurface);
    RSVisibleLevel CalcSurfaceNodeVisibleRegion(const std::shared_ptr<RSDisplayRenderNode>& displayNode,
        const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode, Occlusion::Region& accumulatedRegion,
        Occlusion::Region& curRegion, Occlusion::Region& totalRegion);
    void CalcOcclusionImplementation(const std::shared_ptr<RSDisplayRenderNode>& displayNode,
        std::vector<RSBaseRenderNode::SharedPtr>& curAllSurfaces, VisibleData& dstCurVisVec,
        std::map<NodeId, RSVisibleLevel>& dstPidVisMap);
    void CalcOcclusion();
    void SetVSyncRateByVisibleLevel(std::map<NodeId, RSVisibleLevel>& pidVisMap,
        std::vector<RSBaseRenderNode::SharedPtr>& curAllSurfaces);
    void SetUniVSyncRateByVisibleLevel(const std::shared_ptr<RSUniRenderVisitor>& visitor);
    void NotifyVSyncRates(const std::map<NodeId, RSVisibleLevel>& vSyncRates);
    void CallbackToWMS(VisibleData& curVisVec);
    void SendCommands();
    void InitRSEventDetector();
    void RemoveRSEventDetector();
    void SetRSEventDetectorLoopStartTag();
    void SetRSEventDetectorLoopFinishTag();
    void CheckSystemSceneStatus();
    void UpdateUIFirstSwitch();
    // ROG: Resolution Online Government
    void UpdateRogSizeIfNeeded();
    void UpdateDisplayNodeScreenId();
    uint32_t GetRefreshRate() const;
    uint32_t GetDynamicRefreshRate() const;
    void SkipCommandByNodeId(std::vector<std::unique_ptr<RSTransactionData>>& transactionVec, pid_t pid);
    static void OnHideNotchStatusCallback(const char *key, const char *value, void *context);

    bool DoParallelComposition(std::shared_ptr<RSBaseRenderNode> rootNode);

    void ClassifyRSTransactionData(std::unique_ptr<RSTransactionData>& rsTransactionData);
    void ProcessRSTransactionData(std::unique_ptr<RSTransactionData>& rsTransactionData, pid_t pid);
    void ProcessSyncRSTransactionData(std::unique_ptr<RSTransactionData>& rsTransactionData, pid_t pid);
    void ProcessSyncTransactionCount(std::unique_ptr<RSTransactionData>& rsTransactionData);
    void StartSyncTransactionFallbackTask(std::unique_ptr<RSTransactionData>& rsTransactionData);
    void ProcessAllSyncTransactionData();
    void ProcessCommandForDividedRender();
    void ProcessCommandForUniRender();
    void WaitUntilUnmarshallingTaskFinished();
    void MergeToEffectiveTransactionDataMap(TransactionDataMap& cachedTransactionDataMap);

    void ClearDisplayBuffer();
    void PerfAfterAnim(bool needRequestNextVsync);
    void PerfForBlurIfNeeded();
    void PerfMultiWindow();
    void RenderFrameStart(uint64_t timestamp);
    void ResetHardwareEnabledState(bool isUniRender);
    void CheckIfHardwareForcedDisabled();
    void CheckAndUpdateTransactionIndex(
        std::shared_ptr<TransactionDataMap>& transactionDataEffective, std::string& transactionFlags);

    bool IsResidentProcess(pid_t pid) const;
    bool IsNeedSkip(NodeId instanceRootNodeId, pid_t pid);

    // UIFirst
    bool CheckParallelSubThreadNodesStatus();
    void CacheCommands();
    bool CheckSubThreadNodeStatusIsDoing(NodeId appNodeId) const;

    // used for informing hgm the bundle name of SurfaceRenderNodes
    void InformHgmNodeInfo();
    void CheckIfNodeIsBundle(std::shared_ptr<RSSurfaceRenderNode> node);

    void SetFocusLeashWindowId();
    void ProcessHgmFrameRate(uint64_t timestamp);
    bool IsLastFrameUIFirstEnabled(NodeId appNodeId) const;
    RSVisibleLevel GetRegionVisibleLevel(const Occlusion::Region& curRegion,
        const Occlusion::Region& visibleRegion);
    void PrintCurrentStatus();
    void ProcessScreenHotPlugEvents();
    void WaitUntilUploadTextureTaskFinishedForGL();
#ifdef RES_SCHED_ENABLE
    void SubScribeSystemAbility();
#endif
#if defined(RS_ENABLE_CHIPSET_VSYNC)
    void ConnectChipsetVsyncSer();
    void SetVsyncInfo(uint64_t timestamp);
#endif

    bool DoDirectComposition(std::shared_ptr<RSBaseRenderNode> rootNode, bool waitForRT);

    void RSJankStatsOnVsyncStart(int64_t onVsyncStartTime, int64_t onVsyncStartTimeSteady,
                                 float onVsyncStartTimeSteadyFloat);
    void RSJankStatsOnVsyncEnd(int64_t onVsyncStartTime, int64_t onVsyncStartTimeSteady,
                               float onVsyncStartTimeSteadyFloat);
    int64_t GetCurrentSystimeMs() const;
    int64_t GetCurrentSteadyTimeMs() const;
    float GetCurrentSteadyTimeMsFloat() const;
    void RequestNextVsyncForCachedCommand(std::string& transactionFlags, pid_t pid, uint64_t curIndex);
    void UpdateLuminance();
    void DvsyncCheckRequestNextVsync();

    void PrepareUiCaptureTasks(std::shared_ptr<RSUniRenderVisitor> uniVisitor);
    void UIExtensionNodesTraverseAndCallback();
    bool CheckUIExtensionCallbackDataChanged() const;

    std::shared_ptr<AppExecFwk::EventRunner> runner_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    RSTaskMessage::RSTask mainLoop_;
    std::unique_ptr<RSVsyncClient> vsyncClient_ = nullptr;
    std::unordered_map<NodeId, uint64_t> bufferTimestamps_;

    std::mutex transitionDataMutex_;
    std::unordered_map<NodeId, std::map<uint64_t, std::vector<std::unique_ptr<RSCommand>>>> cachedCommands_;
    std::map<uint64_t, std::vector<std::unique_ptr<RSCommand>>> effectiveCommands_;
    std::map<uint64_t, std::vector<std::unique_ptr<RSCommand>>> pendingEffectiveCommands_;
    std::unordered_map<pid_t, std::vector<std::unique_ptr<RSTransactionData>>> syncTransactionData_;
    std::unordered_map<int32_t, int32_t> subSyncTransactionCounts_;

    TransactionDataMap cachedTransactionDataMap_;
    TransactionDataIndexMap effectiveTransactionDataIndexMap_;
    std::map<pid_t, std::vector<std::unique_ptr<RSTransactionData>>> cachedSkipTransactionDataMap_;
    std::unordered_map<pid_t, uint64_t> transactionDataLastWaitTime_;

    uint64_t curTime_ = 0;
    uint64_t timestamp_ = 0;
    uint64_t vsyncId_ = 0;
    uint64_t lastAnimateTimestamp_ = 0;
    uint64_t prePerfTimestamp_ = 0;
    uint64_t lastCleanCacheTimestamp_ = 0;
    pid_t lastCleanCachePid_ = -1;
    int hardwareTid_ = -1;
    std::unordered_map<uint32_t, sptr<IApplicationAgent>> applicationAgentMap_;

    std::shared_ptr<RSContext> context_;
    std::thread::id mainThreadId_;
    std::shared_ptr<VSyncReceiver> receiver_ = nullptr;
    std::map<pid_t, sptr<RSIOcclusionChangeCallback>> occlusionListeners_;
    std::mutex occlusionMutex_;

    bool isUniRender_ = RSUniRenderJudgement::IsUniRender();
    RSTaskMessage::RSTask unmarshalBarrierTask_;
    std::condition_variable unmarshalTaskCond_;
    std::mutex unmarshalMutex_;
    int32_t unmarshalFinishedCount_ = 0;
    bool needWaitUnmarshalFinished_ = true;
    sptr<VSyncDistributor> appVSyncDistributor_ = nullptr;

    std::condition_variable surfaceCapProcTaskCond_;
    std::mutex surfaceCapProcMutex_;
    bool surfaceCapProcFinished_ = true;

#if defined(RS_ENABLE_PARALLEL_UPLOAD) && defined(RS_ENABLE_GL)
    RSTaskMessage::RSTask uploadTextureBarrierTask_;
    std::condition_variable uploadTextureTaskCond_;
    std::mutex uploadTextureMutex_;
    int32_t uploadTextureFinishedCount_ = 0;
    EGLSyncKHR uploadTextureFence;
#endif

    mutable std::mutex uniRenderMutex_;
    bool uniRenderFinished_ = false;
    std::condition_variable uniRenderCond_;

    bool clearMemoryFinished_ = true;
    bool clearMemDeeply_ = false;

    // Used to refresh the whole display when AccessibilityConfig is changed
    bool isAccessibilityConfigChanged_ = false;

    // Used to refresh the whole display when curtain screen status is changed
    bool isCurtainScreenUsingStatusChanged_ = false;

    // used for blocking mainThread when hardwareThread has 2 and more task to Execute
    mutable std::mutex hardwareThreadTaskMutex_;
    std::condition_variable hardwareThreadTaskCond_;

    std::map<NodeId, RSVisibleLevel> lastVisMapForVsyncRate_;
    VisibleData lastVisVec_;
    std::map<NodeId, uint64_t> lastDrawStatusMap_;
    std::vector<NodeId> curDrawStatusVec_;
    bool qosPidCal_ = false;

    std::atomic<bool> isDirty_ = false;
    std::atomic<bool> screenPowerOnChanged_ = false;
    std::atomic_bool doWindowAnimate_ = false;
    std::vector<NodeId> lastSurfaceIds_;
    std::atomic<int32_t> focusAppPid_ = -1;
    std::atomic<int32_t> focusAppUid_ = -1;
    const uint8_t opacity_ = 255;
    std::string focusAppBundleName_ = "";
    std::string focusAppAbilityName_ = "";
    std::atomic<uint64_t> focusNodeId_ = 0;
    uint64_t focusLeashWindowId_ = 0;
    uint64_t lastFocusNodeId_ = 0;
    uint32_t appWindowNum_ = 0;
    std::atomic<uint32_t> requestNextVsyncNum_ = 0;
    bool lastFrameHasFilter_ = false;
    bool vsyncControlEnabled_ = true;
    bool systemAnimatedScenesEnabled_ = false;
    bool isFoldScreenDevice_ = false;

    bool colorPickerForceRequestVsync_ = false;
    std::atomic_bool noNeedToPostTask_ = false;
    std::atomic_int colorPickerRequestFrameNum_ = 15;

    std::shared_ptr<RSBaseRenderEngine> renderEngine_;
    std::shared_ptr<RSBaseRenderEngine> uniRenderEngine_;
    std::shared_ptr<RSBaseEventDetector> rsCompositionTimeoutDetector_;
    RSEventManager rsEventManager_;
#if defined(ACCESSIBILITY_ENABLE)
    std::shared_ptr<AccessibilityObserver> accessibilityObserver_;
#endif

    // used for hardware enabled case
    bool doDirectComposition_ = true;
    bool isLastFrameDirectComposition_ = false;
    bool isHardwareEnabledBufferUpdated_ = false;
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes_;
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> selfDrawingNodes_;
    bool isHardwareForcedDisabled_ = false; // if app node has shadow or filter, disable hardware composer for all
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> hardwareEnabledDrwawables_;

    // used for watermark
    std::mutex watermarkMutex_;
    std::shared_ptr<Drawing::Image> watermarkImg_ = nullptr;
    bool watermarkFlag_ = false;
    bool lastWatermarkFlag_ = false;
    bool doParallelComposition_ = false;
    bool hasProtectedLayer_ = false;

    std::shared_ptr<HgmFrameRateManager> frameRateMgr_ = nullptr;
    std::shared_ptr<RSRenderFrameRateLinker> rsFrameRateLinker_ = nullptr;
    pid_t desktopPidForRotationScene_ = 0;
    FrameRateRange rsCurrRange_;

    // UIFirst
    std::list<std::shared_ptr<RSSurfaceRenderNode>> subThreadNodes_;
    std::unordered_map<NodeId, bool> cacheCmdSkippedNodes_;
    std::unordered_map<pid_t, std::pair<std::vector<NodeId>, bool>> cacheCmdSkippedInfo_;
    std::atomic<uint64_t> frameCount_ = 0;
    std::set<std::shared_ptr<RSBaseRenderNode>> oldDisplayChildren_;
    DeviceType deviceType_ = DeviceType::PHONE;
    bool isCachedSurfaceUpdated_ = false;
    bool isUiFirstOn_ = false;

    // used for informing hgm the bundle name of SurfaceRenderNodes
    bool noBundle_ = false;
    std::string currentBundleName_ = "";
    bool forceUpdateUniRenderFlag_ = false;
    bool idleTimerExpiredFlag_ = false;
    bool rsIdleTimerExpiredFlag_ = false;
    // for ui first
    std::mutex mutex_;
    std::queue<std::shared_ptr<Drawing::Surface>> tmpSurfaces_;

    // for surface occlusion change callback
    std::mutex surfaceOcclusionMutex_;
    std::vector<NodeId> lastRegisteredSurfaceOnTree_;
    std::mutex systemAnimatedScenesMutex_;
    std::list<std::pair<SystemAnimatedScenes, time_t>> systemAnimatedScenesList_;
    std::list<std::pair<SystemAnimatedScenes, time_t>> threeFingerScenesList_;
    bool isReduceVSyncBySystemAnimatedScenes_ = false;
    std::unordered_map<NodeId, // map<node ID, <pid, callback, partition points vector, level>>
        std::tuple<pid_t, sptr<RSISurfaceOcclusionChangeCallback>,
        std::vector<float>, uint8_t>> surfaceOcclusionListeners_;
    std::unordered_map<NodeId, // map<node ID, <surface node, app window node>>
        std::pair<std::shared_ptr<RSSurfaceRenderNode>, std::shared_ptr<RSSurfaceRenderNode>>> savedAppWindowNode_;

    std::shared_ptr<RSAppStateListener> rsAppStateListener_;
    int32_t subscribeFailCount_ = 0;
    SystemAnimatedScenes systemAnimatedScenes_ = SystemAnimatedScenes::OTHERS;
    uint32_t leashWindowCount_ = 0;

    // for ui captures
    std::vector<std::tuple<NodeId, std::function<void()>>> pendingUiCaptureTasks_;
    std::vector<std::tuple<NodeId, std::function<void()>>> uiCaptureTasks_;

    // for dvsync (animate requestNextVSync after mark rsnotrendering)
    bool needRequestNextVsyncAnimate_ = false;
    bool markRenderFlag_ = false;

    bool forceUIFirstChanged_ = false;

    // uiextension
    std::mutex uiExtensionMutex_;
    UIExtensionCallbackData uiExtensionCallbackData_;
    bool lastFrameUIExtensionDataEmpty_ = false;
    // <pid, <uid, callback>>
    std::map<pid_t, std::pair<uint64_t, sptr<RSIUIExtensionCallback>>> uiExtensionListenners_ = {};

#ifdef RS_PROFILER_ENABLED
    friend class RSProfiler;
#endif
#if defined(RS_ENABLE_CHIPSET_VSYNC)
    bool initVsyncServiceFlag_ = true;
#endif
    pid_t exitedPid_ = -1;
    std::set<pid_t> exitedPidSet_;
    RSDrawFrame drawFrame_;
    std::unique_ptr<RSRenderThreadParams> renderThreadParams_ = nullptr; // sync to render thread
    RsParallelType rsParallelType_;
    bool isCurtainScreenOn_ = false;
#ifdef RES_SCHED_ENABLE
    sptr<VSyncSystemAbilityListener> saStatusChangeListener_ = nullptr;
#endif
    // for statistic of jank frames
    std::atomic_bool isOnVsync_ = false;
    std::atomic_bool discardJankFrames_ = false;
    std::atomic_bool skipJankAnimatorFrame_ = false;
    ScreenId displayNodeScreenId_ = 0;

    // partial render
    bool isFirstFrameOfPartialRender_ = false;
    bool isPartialRenderEnabledOfLastFrame_ = false;
    bool isRegionDebugEnabledOfLastFrame_ = false;
};
} // namespace OHOS::Rosen
#endif // RS_MAIN_THREAD
