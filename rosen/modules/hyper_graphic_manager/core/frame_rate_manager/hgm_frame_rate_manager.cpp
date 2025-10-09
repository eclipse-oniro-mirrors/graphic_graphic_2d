/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hgm_frame_rate_manager.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <limits>
#include "common/rs_common_hook.h"
#include "common/rs_optional_trace.h"
#include "common/rs_thread_handler.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "hgm_config_callback_manager.h"
#include "hgm_core.h"
#include "hgm_energy_consumption_policy.h"
#include "hgm_event.h"
#include "hgm_hfbc_config.h"
#include "hgm_log.h"
#include "hgm_screen_info.h"
#include "parameters.h"
#include "rs_trace.h"
#include "sandbox_utils.h"
#include "frame_rate_report.h"
#include "hdi_device.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_hisysevent.h"
#include "vsync_sampler.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr int32_t IDLE_TIMER_EXPIRED = 200; // ms
constexpr int32_t CHANGE_GENERATOR_RATE_VALID_TIMEOUT = 20; // ms
constexpr int64_t UNI_RENDER_VSYNC_OFFSET = 5000000; // ns
constexpr int64_t UNI_RENDER_VSYNC_OFFSET_DELAY_MODE = -3300000; // ns
constexpr uint32_t REPORT_VOTER_INFO_LIMIT = 20;
constexpr int32_t LAST_TOUCH_CNT = 1;

constexpr uint32_t FIRST_FRAME_TIME_OUT = 100; // 100ms
constexpr uint64_t BUFFER_IDLE_TIME_OUT = 200000000; // 200ms
constexpr long DRAG_SCENE_CHANGE_RATE_TIMEOUT = 100; // 100ms
const std::string UP_TIME_OUT_TASK_ID = "UP_TIME_OUT_TASK_ID";
const std::string S_UP_TIMEOUT_MS = "up_timeout_ms";
const std::string S_RS_IDLE_TIMEOUT_MS = "rs_idle_timeout_ms";
const std::string LOW_BRIGHT = "LowBright";
const std::string ANCO_LOW_BRIGHT = "AncoLowBright";
const std::string STYLUS_PEN = "StylusPen";

constexpr int ADAPTIVE_SYNC_PROPERTY = 3;
constexpr int DISPLAY_SUCCESS = 1;
constexpr int32_t VIRTUAL_KEYBOARD_FINGERS_MIN_CNT = 8;
constexpr uint32_t FRAME_RATE_REPORT_MAX_RETRY_TIMES = 3;
constexpr uint32_t FRAME_RATE_REPORT_DELAY_TIME = 20000;
}

HgmFrameRateManager::HgmFrameRateManager()
    : changeGeneratorRateValidTimer_("ChangeGeneratorRateValid",
          std::chrono::milliseconds(CHANGE_GENERATOR_RATE_VALID_TIMEOUT), nullptr, [this]() {
              changeGeneratorRateValid_ = true;
              UpdateSoftVSync(false);
          }),
      rsFrameRateTimer_("rsFrameRate", std::chrono::milliseconds(IDLE_TIMER_EXPIRED), nullptr, [this]() {
          if (rsFrameRateLinker_ != nullptr) {
              rsFrameRateLinker_->SetExpectedRange({});
              UpdateSoftVSync(false);
          }
      }),
      frameVoter_(HgmFrameVoter(multiAppStrategy_))
{
    frameVoter_.SetChangeRangeCallback([this](const std::string& voter) {
        MarkVoteChange(voter);
    });
    softVSyncManager_.SetUpdateSoftVSyncFunc([this](bool followRs) {
        UpdateSoftVSync(followRs);
    });
}

void HgmFrameRateManager::Init(sptr<VSyncController> rsController,
    sptr<VSyncController> appController, sptr<VSyncGenerator> vsyncGenerator, sptr<VSyncDistributor> appDistributor)
{
    auto& hgmCore = HgmCore::Instance();
    curRefreshRateMode_ = hgmCore.GetCurrentRefreshRateMode();
    multiAppStrategy_.UpdateXmlConfigCache();
    UpdateEnergyConsumptionConfig();

    InitConfig();
    RegisterCoreCallbacksAndInitController(rsController, appController, vsyncGenerator, appDistributor);
    multiAppStrategy_.RegisterStrategyChangeCallback([this](const PolicyConfigData::StrategyConfig& strategy) {
        frameVoter_.SetTouchUpLTPOFirstDynamicMode(strategy.dynamicMode);
        DeliverRefreshRateVote({"VOTER_PACKAGES", strategy.min, strategy.max}, ADD_VOTE);
        touchManager_.SetUpTimeout(strategy.upTimeOut);
        idleFps_ = strategy.idleFps;
        HandleIdleEvent(true);
    });
    static std::once_flag createFlag;
    std::call_once(createFlag, [this]() {
        InitTouchManager();
    });
    hgmCore.SetLtpoConfig();
    multiAppStrategy_.CalcVote();
    appPageUrlStrategy_.RegisterPageUrlVoterCallback([this](pid_t pid,
        std::string strategy, const bool isAddVoter) {
        ProcessPageUrlVote(pid, strategy, isAddVoter);
    });
    HgmHfbcConfig& hfbcConfig = hgmCore.GetHfbcConfig();
    hfbcConfig.HandleHfbcConfig({""});
    FrameRateReportTask(FRAME_RATE_REPORT_MAX_RETRY_TIMES);
    userDefine_.Init();
}

void HgmFrameRateManager::InitConfig()
{
    auto& hgmCore = HgmCore::Instance();
    // hgm warning: get non active screenId in non-folding devices（from sceneboard）
    auto screenList = hgmCore.GetScreenIds();
    curScreenId_.store(screenList.empty() ? 0 : screenList.front());
    auto& hgmScreenInfo = HgmScreenInfo::GetInstance();
    isLtpo_ = hgmScreenInfo.IsLtpoType(hgmScreenInfo.GetScreenType(curScreenId_.load()));
    std::string curScreenName = "screen" + std::to_string(curScreenId_.load()) + "_" + (isLtpo_ ? "LTPO" : "LTPS");
    auto configData = hgmCore.GetPolicyConfigData();
    if (configData != nullptr) {
        auto iter = configData->screenStrategyConfigs_.find(curScreenName);
        if (iter != configData->screenStrategyConfigs_.end()) {
            curScreenStrategyId_ = iter->second;
        }
        if (curScreenStrategyId_.empty()) {
            curScreenStrategyId_ = "LTPO-DEFAULT";
        }
        auto configVisitor = hgmCore.GetPolicyConfigVisitor();
        if (configVisitor != nullptr) {
            configVisitor->ChangeScreen(curScreenStrategyId_);
        }
        curScreenDefaultStrategyId_ = curScreenStrategyId_;
        if (configData->xmlCompatibleMode_) {
            curRefreshRateMode_ = configData->SettingModeId2XmlModeId(curRefreshRateMode_);
        }
        multiAppStrategy_.UpdateXmlConfigCache();
        SetTimeoutParamsFromConfig(configData);
        GetLowBrightVec(configData);
        GetAncoLowBrightVec(configData);
        GetStylusVec(configData);
        UpdateEnergyConsumptionConfig();
        multiAppStrategy_.CalcVote();
        HandleIdleEvent(ADD_VOTE);
        UpdateScreenExtStrategyConfig(configData->screenConfigs_);
        softVSyncManager_.GetVRateMiniFPS(configData);
    }
}

void HgmFrameRateManager::RegisterCoreCallbacksAndInitController(sptr<VSyncController> rsController,
    sptr<VSyncController> appController, sptr<VSyncGenerator> vsyncGenerator, sptr<VSyncDistributor> appDistributor)
{
    if (rsController == nullptr || appController == nullptr) {
        HGM_LOGE("HgmFrameRateManager::rsController or appController is nullptr");
        return;
    }
    auto& hgmCore = HgmCore::Instance();
    hgmCore.RegisterRefreshRateModeChangeCallback([rsController, appController](int32_t mode) {
        if (HgmCore::Instance().IsLTPOSwitchOn()) {
            rsController->SetPhaseOffset(0);
            appController->SetPhaseOffset(0);
            CreateVSyncGenerator()->SetVSyncMode(VSYNC_MODE_LTPO);
        } else {
            if (RSUniRenderJudgement::IsUniRender()) {
                int64_t offset = HgmCore::Instance().IsDelayMode() ?
                    UNI_RENDER_VSYNC_OFFSET_DELAY_MODE : UNI_RENDER_VSYNC_OFFSET;
                rsController->SetPhaseOffset(offset);
                appController->SetPhaseOffset(offset);
            }
            CreateVSyncGenerator()->SetVSyncMode(VSYNC_MODE_LTPS);
        }
    });

    hgmCore.RegisterRefreshRateUpdateCallback([](int32_t refreshRate) {
        HgmTaskHandleThread::Instance().PostTask([refreshRate]() {
            HgmConfigCallbackManager::GetInstance()->SyncRefreshRateUpdateCallback(refreshRate);
        });
    });

    controller_ = std::make_shared<HgmVSyncGeneratorController>(rsController, appController, vsyncGenerator);
    std::weak_ptr<HgmVSyncGeneratorController> weakController(controller_);
    softVSyncManager_.InitController(weakController, appDistributor);
}

void HgmFrameRateManager::SetTimeoutParamsFromConfig(const std::shared_ptr<PolicyConfigData>& configData)
{
    if (configData == nullptr || configData->timeoutStrategyConfig_.empty()) {
        return;
    }
    int32_t upTimeoutMs = 0;
    int32_t rsIdleTimeoutMs = 0;
    if (configData->timeoutStrategyConfig_.find(S_UP_TIMEOUT_MS) != configData->timeoutStrategyConfig_.end() &&
        XMLParser::IsNumber(configData->timeoutStrategyConfig_[S_UP_TIMEOUT_MS])) {
        upTimeoutMs = static_cast<int32_t>(std::stoi(configData->timeoutStrategyConfig_[S_UP_TIMEOUT_MS]));
    }
    if (configData->timeoutStrategyConfig_.find(S_RS_IDLE_TIMEOUT_MS) != configData->timeoutStrategyConfig_.end() &&
        XMLParser::IsNumber(configData->timeoutStrategyConfig_[S_RS_IDLE_TIMEOUT_MS])) {
        rsIdleTimeoutMs = static_cast<int32_t>(std::stoi(configData->timeoutStrategyConfig_[S_RS_IDLE_TIMEOUT_MS]));
    }
    if (upTimeoutMs != 0) {
        touchManager_.SetUpTimeout(upTimeoutMs);
        HILOG_COMM_INFO("set upTimeout from Config");
    }
    if (rsIdleTimeoutMs != 0) {
        touchManager_.SetRsIdleTimeout(rsIdleTimeoutMs);
        HILOG_COMM_INFO("set rsIdleTimeout from Config");
    }
}

void HgmFrameRateManager::InitTouchManager()
{
    auto updateTouchToMultiAppStrategy = [this](TouchState newState) {
        HgmMultiAppStrategy::TouchInfo touchInfo = { .pkgName = touchManager_.GetPkgName(), .touchState = newState };
        HgmEnergyConsumptionPolicy::Instance().SetTouchState(newState);
        multiAppStrategy_.HandleTouchInfo(touchInfo);
        UpdateSoftVSync(false);
    };
    touchManager_.RegisterEnterStateCallback(TouchState::DOWN_STATE,
        [this, updateTouchToMultiAppStrategy](TouchState lastState, TouchState newState) {
            needForceUpdateUniRender_ = true;
            updateTouchToMultiAppStrategy(newState);
            startCheck_.store(false);
            voterTouchEffective_.store(true);
            needForceUpdateUniRender_ = false;
        });
    touchManager_.RegisterEnterStateCallback(TouchState::IDLE_STATE,
        [this, updateTouchToMultiAppStrategy](TouchState lastState, TouchState newState) {
            SetSchedulerPreferredFps(OLED_60_HZ);
            startCheck_.store(false);
            softVSyncManager_.ChangePerformanceFirst(false);
            updateTouchToMultiAppStrategy(newState);
            voterTouchEffective_.store(false);
        });
    touchManager_.RegisterEnterStateCallback(TouchState::UP_STATE,
        [this, updateTouchToMultiAppStrategy](TouchState lastState, TouchState newState) {
            frameVoter_.SetIsTouchUpLTPOFirstPeriod(true);
            HgmTaskHandleThread::Instance().PostEvent(UP_TIME_OUT_TASK_ID, [this]() {
                frameVoter_.SetIsTouchUpLTPOFirstPeriod(false);
                startCheck_.store(true);
                UpdateSoftVSync(false);
            }, FIRST_FRAME_TIME_OUT);
            updateTouchToMultiAppStrategy(newState);
        });
    touchManager_.RegisterExitStateCallback(TouchState::UP_STATE,
        [this](TouchState lastState, TouchState newState) {
            frameVoter_.SetIsTouchUpLTPOFirstPeriod(false);
            HgmTaskHandleThread::Instance().RemoveEvent(UP_TIME_OUT_TASK_ID);
            startCheck_.store(false);
        });
    RegisterUpTimeoutAndDownEvent();
}

void HgmFrameRateManager::RegisterUpTimeoutAndDownEvent()
{
    touchManager_.RegisterEventCallback(TouchEvent::DOWN_EVENT, [this](TouchEvent event) {
        SetSchedulerPreferredFps(OLED_120_HZ);
        touchManager_.ChangeState(TouchState::DOWN_STATE);
    });
    touchManager_.RegisterExitStateCallback(TouchState::IDLE_STATE,
        [this](TouchState lastState, TouchState newState) {
            softVSyncManager_.ChangePerformanceFirst(true);
        });
}

void HgmFrameRateManager::ProcessPendingRefreshRate(
    uint64_t timestamp, int64_t vsyncId, uint32_t rsRate, bool isUiDvsyncOn)
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    // ensure that vsync switching takes effect in this frame
    if (vsyncId < vsyncCountOfChangeGeneratorRate_) {
        return;
    }
    auto& hgmCore = HgmCore::Instance();
    hgmCore.SetTimestamp(timestamp);
    if (pendingRefreshRate_ != nullptr) {
        hgmCore.SetPendingConstraintRelativeTime(pendingConstraintRelativeTime_);
        lastPendingConstraintRelativeTime_ = pendingConstraintRelativeTime_;
        pendingConstraintRelativeTime_ = 0;

        hgmCore.SetPendingScreenRefreshRate(*pendingRefreshRate_);
        lastPendingRefreshRate_ = *pendingRefreshRate_;
        pendingRefreshRate_.reset();
        RS_TRACE_NAME_FMT("ProcessHgmFrameRate pendingRefreshRate: %d", lastPendingRefreshRate_);
    } else {
        if (lastPendingConstraintRelativeTime_ != 0) {
            hgmCore.SetPendingConstraintRelativeTime(lastPendingConstraintRelativeTime_);
        }
        if (lastPendingRefreshRate_ != 0) {
            hgmCore.SetPendingScreenRefreshRate(lastPendingRefreshRate_);
            RS_TRACE_NAME_FMT("ProcessHgmFrameRate pendingRefreshRate: %d", lastPendingRefreshRate_);
        }
    }

    if (hgmCore.GetLtpoEnabled() && isLtpo_ && rsRate > OLED_10_HZ &&
        isUiDvsyncOn && GetCurScreenStrategyId().find("LTPO") != std::string::npos) {
        hgmCore.SetPendingScreenRefreshRate(rsRate);
        RS_TRACE_NAME_FMT("ProcessHgmFrameRate pendingRefreshRate: %d ui-dvsync", rsRate);
    }
    SetChangeGeneratorRateValid(true);
}

void HgmFrameRateManager::UpdateSurfaceTime(const std::string& surfaceName, pid_t pid, UIFWKType uiFwkType)
{
    HgmEnergyConsumptionPolicy::Instance().StatisticsVideoCallBufferCount(pid, surfaceName);
    if (!voterTouchEffective_) {
        return;
    }
    surfaceData_.emplace_back(std::tuple<std::string, pid_t, UIFWKType>({surfaceName, pid, uiFwkType}));
}

void HgmFrameRateManager::UpdateAppSupportedState()
{
    PolicyConfigData::StrategyConfig config;
    if (multiAppStrategy_.GetFocusAppStrategyConfig(config) == EXEC_SUCCESS &&
        (config.dynamicMode == DynamicModeType::TOUCH_EXT_ENABLED ||
         config.dynamicMode == DynamicModeType::TOUCH_EXT_ENABLED_LTPO_FIRST)) {
        idleDetector_.SetAppSupportedState(true);
    } else {
        idleDetector_.SetAppSupportedState(false);
    }
    idleDetector_.SetBufferFpsMap(std::move(config.bufferFpsMap));
}

void HgmFrameRateManager::SetAceAnimatorVote(const std::shared_ptr<RSRenderFrameRateLinker>& linker)
{
    if (linker == nullptr) {
        return;
    }
    if (linker->GetAceAnimatorExpectedFrameRate() >= 0) {
        RS_TRACE_NAME_FMT("SetAceAnimatorVote PID = [%d]  linkerId = [%" PRIu64 "]  SetAceAnimatorIdleState[false] "
            "AnimatorExpectedFrameRate = [%d]", ExtractPid(linker->GetId()), linker->GetId(),
            linker->GetAceAnimatorExpectedFrameRate());
        idleDetector_.SetAceAnimatorIdleState(false);
        idleDetector_.UpdateAceAnimatorExpectedFrameRate(linker->GetAceAnimatorExpectedFrameRate());
    }
}

void HgmFrameRateManager::UpdateGuaranteedPlanVote(uint64_t timestamp)
{
    if (!idleDetector_.GetAppSupportedState()) {
        return;
    }
    idleDetector_.UpdateSurfaceState(timestamp);
    RS_TRACE_NAME_FMT("HgmFrameRateManager:: TouchState = [%d]  SurFaceIdleState = [%d]  AceAnimatorIdleState = [%d]",
        touchManager_.GetState(), idleDetector_.GetSurfaceIdleState(), idleDetector_.GetAceAnimatorIdleState());

    // After touch up, wait FIRST_FRAME_TIME_OUT ms
    if (!startCheck_.load() || touchManager_.GetState() == TouchState::IDLE_STATE) {
        lastTouchUpExpectFps_ = 0;
        return;
    }

    // remove the touch vote if third framework idle, otherwise vote the touch up fps
    if (idleDetector_.GetSurfaceIdleState() && idleDetector_.GetAceAnimatorIdleState()) {
        RS_TRACE_NAME_FMT("UpdateGuaranteedPlanVote:: Surface And Animator Idle, remove touch vote");
        DeliverRefreshRateVote({"VOTER_TOUCH"}, REMOVE_VOTE);
        lastTouchUpExpectFps_ = 0;
    } else {
        int32_t currTouchUpExpectedFPS = idleDetector_.GetTouchUpExpectedFPS();
        if (currTouchUpExpectedFPS == lastTouchUpExpectFps_) {
            return;
        }

        lastTouchUpExpectFps_ = currTouchUpExpectedFPS;
        HgmMultiAppStrategy::TouchInfo touchInfo = {
            .touchState = TouchState::UP_STATE,
            .upExpectFps = currTouchUpExpectedFPS,
        };
        multiAppStrategy_.HandleTouchInfo(touchInfo);
    }
}

void HgmFrameRateManager::ProcessLtpoVote(const FrameRateRange& finalRange)
{
    frameVoter_.SetDragScene(finalRange.type_ & ACE_COMPONENT_FRAME_RATE_TYPE);
    if (finalRange.IsValid()) {
        auto refreshRate = UpdateFrameRateWithDelay(CalcRefreshRate(curScreenId_.load(), finalRange));
        HGM_LOGD("ltpo type: %{public}s", finalRange.GetAllTypeDescription().c_str());
        RS_TRACE_NAME_FMT("ltpo type: %s", finalRange.GetAllTypeDescription().c_str());
        RS_TRACE_NAME_FMT("ProcessLtpoVote isDragScene_: [%d], refreshRate: [%d], lastLTPORefreshRate_: [%d]",
            frameVoter_.IsDragScene(), refreshRate, lastLTPORefreshRate_);
        DeliverRefreshRateVote(
            {"VOTER_LTPO", refreshRate, refreshRate, DEFAULT_PID, finalRange.GetExtInfo()}, ADD_VOTE);
    } else {
        DeliverRefreshRateVote({.voterName = "VOTER_LTPO"}, REMOVE_VOTE);
    }
}

uint32_t HgmFrameRateManager::UpdateFrameRateWithDelay(uint32_t refreshRate)
{
    if (!frameVoter_.IsDragScene()) {
        return refreshRate;
    }

    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now()
                    .time_since_epoch()).count();
    if (refreshRate < lastLTPORefreshRate_ && curTime - lastLTPOVoteTime_ < DRAG_SCENE_CHANGE_RATE_TIMEOUT) {
        return lastLTPORefreshRate_;
    }

    lastLTPORefreshRate_ = refreshRate;
    lastLTPOVoteTime_ = curTime;
    return refreshRate;
}

void HgmFrameRateManager::UniProcessDataForLtpo(uint64_t timestamp,
    std::shared_ptr<RSRenderFrameRateLinker> rsFrameRateLinker, const FrameRateLinkerMap& appFrameRateLinkers,
    const std::map<uint64_t, int>& vRatesMap)
{
    RS_TRACE_FUNC();
    timestamp_ = timestamp;
    rsFrameRateLinker_ = rsFrameRateLinker;
    appFrameRateLinkers_ = appFrameRateLinkers;

    softVSyncManager_.UniProcessDataForLtpo(vRatesMap, appFrameRateLinkers_);
    UpdateSoftVSync(true);
}

void HgmFrameRateManager::UpdateSoftVSync(bool followRs)
{
    if (rsFrameRateLinker_ == nullptr) {
        return;
    }
    FrameRateRange rsRange = rsFrameRateLinker_->GetExpectedRange();
    HgmEnergyConsumptionPolicy::Instance().GetAnimationIdleFps(rsRange);
    rsFrameRateLinker_->SetExpectedRange(rsRange);
    FrameRateRange finalRange;
    finalRange.Merge(rsRange);
    idleDetector_.SetAceAnimatorIdleState(true);
    for (auto linker : appFrameRateLinkers_) {
        if (linker.second == nullptr || !multiAppStrategy_.CheckPidValid(ExtractPid(linker.first))) {
            continue;
        }
        SetAceAnimatorVote(linker.second);
        auto expectedRange = linker.second->GetExpectedRange();
        if (expectedRange.type_ == NATIVE_VSYNC_FRAME_RATE_TYPE && linker.second->NativeVSyncIsTimeOut()) {
            continue;
        }
        if (!HgmEnergyConsumptionPolicy::Instance().GetUiIdleFps(expectedRange, ExtractPid(linker.first)) &&
            (expectedRange.type_ & ANIMATION_STATE_FIRST_FRAME) != 0 &&
            expectedRange.preferred_ < static_cast<int32_t>(currRefreshRate_)) {
            expectedRange.Set(currRefreshRate_, currRefreshRate_, currRefreshRate_);
        }
        finalRange.Merge(expectedRange);
    }
    HgmEnergyConsumptionPolicy::Instance().PrintEnergyConsumptionLog(finalRange);
    ProcessLtpoVote(finalRange);

    UpdateGuaranteedPlanVote(timestamp_);
    idleDetector_.ResetAceAnimatorExpectedFrameRate();
    // changeGenerator only once in a single vsync period
    if (!changeGeneratorRateValid_.load()) {
        return;
    }
    // max used here
    finalRange = {lastVoteInfo_.max, lastVoteInfo_.max, lastVoteInfo_.max};
    RS_TRACE_NAME_FMT("VoteRes: %s[%d, %d]", lastVoteInfo_.voterName.c_str(), lastVoteInfo_.min, lastVoteInfo_.max);
    bool needChangeDssRefreshRate = false;
    auto refreshRate = CalcRefreshRate(curScreenId_.load(), finalRange);
    if (currRefreshRate_.load() != refreshRate) {
        currRefreshRate_.store(refreshRate);
        schedulePreferredFpsChange_ = true;
        needChangeDssRefreshRate = true;
        FrameRateReport();
    }
    bool frameRateChanged = softVSyncManager_.CollectFrameRateChange(finalRange, rsFrameRateLinker_,
        appFrameRateLinkers_, currRefreshRate_);
    CheckRefreshRateChange(followRs, frameRateChanged, refreshRate, needChangeDssRefreshRate);
    ReportHiSysEvent(lastVoteInfo_);
}

void HgmFrameRateManager::ReportHiSysEvent(const VoteInfo& frameRateVoteInfo)
{
    if (frameRateVoteInfo.voterName.empty()) {
        return;
    }
    bool needAdd = frameRateVoteInfoVec_.empty() || frameRateVoteInfoVec_.back().second != frameRateVoteInfo;
    if (frameRateVoteInfoVec_.size() >= REPORT_VOTER_INFO_LIMIT) {
        std::string msg;
        for (auto& [timestamp, voteInfo] : frameRateVoteInfoVec_) {
            msg += voteInfo.ToString(timestamp);
        }
        RS_TRACE_NAME("HgmFrameRateManager::ReportHiSysEvent HiSysEventWrite");
        RSHiSysEvent::EventWrite(RSEventName::HGM_VOTER_INFO, RSEventType::RS_STATISTIC, "MSG", msg);
        frameRateVoteInfoVec_.clear();
    }
    if (needAdd) {
        auto currentTime = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now()).time_since_epoch().count();
        frameRateVoteInfoVec_.push_back({currentTime, frameRateVoteInfo});
        HGM_LOGD("ReportHiSysEvent: %{public}s", frameRateVoteInfo.ToString(currentTime).c_str());
    }
}

void HgmFrameRateManager::FrameRateReport()
{
    if (!schedulePreferredFpsChange_ && !slideModeChange) {
        return;
    }
    std::unordered_map<pid_t, uint32_t> rates;
    rates[GetRealPid()] = currRefreshRate_;
    if (curRefreshRateMode_ != HGM_REFRESHRATE_MODE_AUTO) {
        rates[UNI_APP_PID] = currRefreshRate_;
    } else if (schedulePreferredFps_ == OLED_60_HZ && currRefreshRate_ == OLED_60_HZ) {
        rates[UNI_APP_PID] = OLED_60_HZ;
    } else {
        rates[UNI_APP_PID] = OLED_120_HZ;
    }
    if (isLowPowerSlide && currRefreshRate_ == OLED_60_HZ) {
        rates[UNI_APP_PID] = OLED_60_HZ;
        slideModeChange = false;
    }
    HGM_LOGD("FrameRateReport: RS(%{public}d) = %{public}d, APP(%{public}d) = %{public}d",
        GetRealPid(), rates[GetRealPid()], UNI_APP_PID, rates[UNI_APP_PID]);
    RS_TRACE_NAME_FMT("FrameRateReport: RS(%d) = %d, APP(%d) = %d",
        GetRealPid(), rates[GetRealPid()], UNI_APP_PID, rates[UNI_APP_PID]);
    FRAME_TRACE::FrameRateReport::GetInstance().SendFrameRates(rates);
    FRAME_TRACE::FrameRateReport::GetInstance().SendFrameRatesToRss(rates);
    schedulePreferredFpsChange_ = false;
}

void HgmFrameRateManager::HandleFrameRateChangeForLTPO(uint64_t timestamp, bool followRs, bool isNeedDvsyncDelay)
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    auto& hgmCore = HgmCore::Instance();
    auto lastRefreshRate = hgmCore.GetPendingScreenRefreshRate();
    uint64_t targetTime = 0;
    // low refresh rate switch to high refresh rate immediately.
    if (lastRefreshRate < OLED_60_HZ && currRefreshRate_ > lastRefreshRate) {
        hgmCore.SetPendingScreenRefreshRate(currRefreshRate_);
        pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
        hgmCore.SetScreenRefreshRateImme(currRefreshRate_);
        if (hgmCore.IsLowRateToHighQuickEnabled() && controller_) {
            targetTime = controller_->CalcVSyncQuickTriggerTime(timestamp, lastRefreshRate);
            if (targetTime > timestamp && targetTime > 0) {
                pendingConstraintRelativeTime_ = targetTime - timestamp;
            } else {
                pendingConstraintRelativeTime_ = 0;
            }
            hgmCore.SetPendingConstraintRelativeTime(pendingConstraintRelativeTime_);
            pendingConstraintRelativeTime_ = 0;
        }
        // ChangeGeneratorRate delay 1 frame
        if (!followRs) {
            changeGeneratorRateValidTimer_.Start();
            return;
        }
    }

    // Start of DVSync
    auto controllerRate = softVSyncManager_.GetControllerRate();
    int64_t delayTime = 0;
    if (isNeedDvsyncDelay) {
        delayTime = CreateVSyncGenerator()->SetCurrentRefreshRate(controllerRate, lastRefreshRate);
    }
    std::vector<std::pair<FrameRateLinkerId, uint32_t>> appChangeData = softVSyncManager_.GetSoftAppChangeData();
    if (delayTime != 0) {
        DVSyncTaskProcessor(delayTime, targetTime, appChangeData, controllerRate);
    } else if (controller_) {
        vsyncCountOfChangeGeneratorRate_ = controller_->ChangeGeneratorRate(
            controllerRate, appChangeData, targetTime, isNeedUpdateAppOffset_);
    }
    // End of DVSync
    isNeedUpdateAppOffset_ = false;
    pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
    SetChangeGeneratorRateValid(false);
}

void HgmFrameRateManager::DVSyncTaskProcessor(int64_t delayTime, uint64_t targetTime,
    std::vector<std::pair<FrameRateLinkerId, uint32_t>> appChangeData, int64_t controllerRate)
{
    bool needUpdate = isNeedUpdateAppOffset_;
    RSTaskMessage::RSTask task = [this, targetTime, controllerRate, appChangeData, needUpdate]() {
        if (controller_) {
            vsyncCountOfChangeGeneratorRate_ = controller_->ChangeGeneratorRate(controllerRate,
                appChangeData, targetTime, needUpdate);
        }
        CreateVSyncGenerator()->SetCurrentRefreshRate(0, 0);
    };
    HgmTaskHandleThread::Instance().PostTask(task, delayTime);
}

void HgmFrameRateManager::GetSupportedRefreshRates(const std::shared_ptr<PolicyConfigData>& configData,
    const std::string& modeKey, std::vector<uint32_t>& targetVec, bool handleAmbientEffect)
{
    if (configData == nullptr) {
        return;
    }

    // Check if current screen strategy ID exists in supported mode configs
    if (configData->supportedModeConfigs_.find(curScreenStrategyId_) == configData->supportedModeConfigs_.end()) {
        return;
    }
    auto supportedModeConfig = configData->supportedModeConfigs_[curScreenStrategyId_];
    auto iter = supportedModeConfig.find(modeKey);
    if (iter == supportedModeConfig.end() || iter->second.empty()) {
        return;
    }

    // Get supported refresh rates from HgmCore
    auto supportRefreshRateVec = HgmCore::Instance().GetScreenSupportedRefreshRates(curScreenId_.load());
    targetVec.clear();

    // Match supported refresh rates
    for (auto rate : iter->second) {
        auto it = std::find(supportRefreshRateVec.begin(), supportRefreshRateVec.end(), rate);
        if (it != supportRefreshRateVec.end()) {
            targetVec.push_back(*it);
        }
    }

    // Handle ambient effect if needed
    if (!targetVec.empty() && handleAmbientEffect) {
        isAmbientEffect_ = true;
        multiAppStrategy_.HandleLowAmbientStatus(isAmbientEffect_);
    }
}

void HgmFrameRateManager::GetLowBrightVec(const std::shared_ptr<PolicyConfigData>& configData)
{
    isAmbientEffect_ = false;
    multiAppStrategy_.HandleLowAmbientStatus(isAmbientEffect_);
    GetSupportedRefreshRates(configData, LOW_BRIGHT, lowBrightVec_, true);
}

void HgmFrameRateManager::GetAncoLowBrightVec(const std::shared_ptr<PolicyConfigData>& configData)
{
    GetSupportedRefreshRates(configData, ANCO_LOW_BRIGHT, ancoLowBrightVec_, false);
}

void HgmFrameRateManager::GetStylusVec(const std::shared_ptr<PolicyConfigData>& configData)
{
    if (!configData) {
        return;
    }

    // refresh rate for stylus pen
    if (configData->supportedModeConfigs_.find(curScreenStrategyId_) == configData->supportedModeConfigs_.end()) {
        return;
    }
    auto supportedModeConfig = configData->supportedModeConfigs_[curScreenStrategyId_];
    auto iter = supportedModeConfig.find(STYLUS_PEN);
    if (iter == supportedModeConfig.end() || iter->second.empty()) {
        return;
    }
    auto supportRefreshRateVec = HgmCore::Instance().GetScreenSupportedRefreshRates(curScreenId_.load());
    stylusVec_.clear();
    for (auto rate : iter->second) {
        auto it = std::find(supportRefreshRateVec.begin(), supportRefreshRateVec.end(), rate);
        if (it != supportRefreshRateVec.end()) {
            stylusVec_.push_back(rate);
        }
    }
}

uint32_t HgmFrameRateManager::CalcRefreshRate(const ScreenId id, const FrameRateRange& range) const
{
    // Find current refreshRate by FrameRateRange. For example:
    // 1. FrameRateRange[min, max, preferred] is [24, 48, 48], supported refreshRates
    // of current screen are {30, 60, 90}, the result should be 30, not 60.
    // 2. FrameRateRange[min, max, preferred] is [150, 150, 150], supported refreshRates
    // of current screen are {30, 60, 90}, the result will be 90.
    uint32_t refreshRate = currRefreshRate_;
    std::vector<uint32_t> supportRefreshRateVec;
    bool stylusFlag = (isStylusWakeUp_ && !stylusVec_.empty());
    if ((isLtpo_ && isAmbientStatus_ == LightFactorStatus::NORMAL_LOW && isAmbientEffect_) ||
        (!isLtpo_ && isAmbientEffect_ && isAmbientStatus_ != LightFactorStatus::HIGH_LEVEL)) {
        RS_TRACE_NAME_FMT("Replace supported refresh rates from config");
        if (CheckAncoVoterStatus()) {
            supportRefreshRateVec = ancoLowBrightVec_;
        } else {
            supportRefreshRateVec = lowBrightVec_;
        }
    } else if (stylusFlag) {
        supportRefreshRateVec = stylusVec_;
        HGM_LOGD("stylusVec size = %{public}zu", stylusVec_.size());
    } else {
        supportRefreshRateVec = HgmCore::Instance().GetScreenSupportedRefreshRates(id);
    }
    if (supportRefreshRateVec.empty()) {
        return refreshRate;
    }
    std::sort(supportRefreshRateVec.begin(), supportRefreshRateVec.end());
    // In stylus mode, refresh is the first value of less than or equal to preferred in supportRefreshRateVec;
    // supportRefreshRateVec is not empty when stylusFlag is true;
    // The return value of upper_bound is bigger than preferred, so need subtract one;
    if (stylusFlag) {
        auto item = std::upper_bound(supportRefreshRateVec.begin(), supportRefreshRateVec.end(), range.preferred_);
        if ((item - supportRefreshRateVec.begin()) > 0) {
            item--;
        }
        return *item;
    }
    auto iter = std::lower_bound(supportRefreshRateVec.begin(), supportRefreshRateVec.end(), range.preferred_);
    if (iter != supportRefreshRateVec.end()) {
        refreshRate = *iter;
        if (refreshRate > static_cast<uint32_t>(range.max_) &&
            (iter - supportRefreshRateVec.begin()) > 0) {
            iter--;
            if (*iter >= static_cast<uint32_t>(range.min_) &&
                *iter <= static_cast<uint32_t>(range.max_)) {
                refreshRate = *iter;
            }
        }
    } else {
        refreshRate = supportRefreshRateVec.back();
    }
    return refreshRate;
}

int32_t HgmFrameRateManager::GetExpectedFrameRate(const RSPropertyUnit unit, float velocityPx,
    int32_t areaPx, int32_t lengthPx) const
{
    static const std::map<RSPropertyUnit, std::string> typeMap = {
        {RSPropertyUnit::PIXEL_POSITION, "translate"},
        {RSPropertyUnit::PIXEL_SIZE, "scale"},
        {RSPropertyUnit::RATIO_SCALE, "scale"},
        {RSPropertyUnit::ANGLE_ROTATION, "rotation"}
    };
    if (auto it = typeMap.find(unit); it != typeMap.end()) {
        return GetPreferredFps(it->second, PixelToMM(velocityPx), SqrPixelToSqrMM(areaPx), PixelToMM(lengthPx));
    }
    return 0;
}

int32_t HgmFrameRateManager::GetPreferredFps(const std::string& type, float velocityMM,
    float areaSqrMM, float lengthMM) const
{
    auto& configData = HgmCore::Instance().GetPolicyConfigData();
    if (!configData) {
        return 0;
    }
    if (ROSEN_EQ(velocityMM, 0.f)) {
        return 0;
    }
    const auto curScreenStrategyId = curScreenStrategyId_;
    const std::string settingMode = std::to_string(curRefreshRateMode_);
    if (configData->screenConfigs_.find(curScreenStrategyId) == configData->screenConfigs_.end() ||
        configData->screenConfigs_[curScreenStrategyId].find(settingMode) ==
        configData->screenConfigs_[curScreenStrategyId].end()) {
        return 0;
    }
    auto& screenSetting = configData->screenConfigs_[curScreenStrategyId][settingMode];
    auto matchFunc = [velocityMM](const auto& pair) {
        return velocityMM >= pair.second.min && (velocityMM < pair.second.max || pair.second.max == -1);
    };

    // find result if it's small size animation
    bool needCheck = screenSetting.smallSizeArea > 0 && screenSetting.smallSizeLength > 0;
    bool matchArea = areaSqrMM > 0 && areaSqrMM < screenSetting.smallSizeArea;
    bool matchLength = lengthMM > 0 && lengthMM < screenSetting.smallSizeLength;
    if (needCheck && matchArea && matchLength &&
        screenSetting.smallSizeAnimationDynamicSettings.find(type) !=
        screenSetting.smallSizeAnimationDynamicSettings.end()) {
        auto& config = screenSetting.smallSizeAnimationDynamicSettings[type];
        auto iter = std::find_if(config.begin(), config.end(), matchFunc);
        if (iter != config.end()) {
            RS_OPTIONAL_TRACE_NAME_FMT("GetPreferredFps (small size): type: %s, speed: %f, area: %f, length: %f,"
                "rate: %d", type.c_str(), velocityMM, areaSqrMM, lengthMM, iter->second.preferredFps);
            return iter->second.preferredFps;
        }
    }

    // it's not a small size animation or current small size config don't cover it, find result in normal config
    if (screenSetting.animationDynamicSettings.find(type) != screenSetting.animationDynamicSettings.end()) {
        auto& config = screenSetting.animationDynamicSettings[type];
        auto iter = std::find_if(config.begin(), config.end(), matchFunc);
        if (iter != config.end()) {
            RS_OPTIONAL_TRACE_NAME_FMT("GetPreferredFps: type: %s, speed: %f, area: %f, length: %f, rate: %d",
                type.c_str(), velocityMM, areaSqrMM, lengthMM, iter->second.preferredFps);
            return iter->second.preferredFps;
        }
    }
    return 0;
}

template<typename T>
float HgmFrameRateManager::PixelToMM(T pixel)
{
    auto& hgmCore = HgmCore::Instance();
    sptr<HgmScreen> hgmScreen = hgmCore.GetScreen(hgmCore.GetActiveScreenId());
    if (hgmScreen && hgmScreen->GetPpi() > 0.f) {
        return pixel / hgmScreen->GetPpi() * INCH_2_MM;
    }
    return 0.f;
}

template<typename T>
float HgmFrameRateManager::SqrPixelToSqrMM(T sqrPixel)
{
    return PixelToMM(PixelToMM(sqrPixel));
}

void HgmFrameRateManager::HandleLightFactorStatus(pid_t pid, int32_t state)
{
    // based on the light determine whether allowed to reduce the screen refresh rate to avoid screen flicker
    // 1.normal strategy : there are two states {NORMAL_HIGH, NORMAL_LOW}
    // NORMAL_HIGH : allowed to reduce the screen refresh rate; NORMAL_LOW : not allowed
    // 2.brightness level strategy : there are three states {LOW_LEVEL, MIDDLE_LEVEL, HIGH_LEVEL}
    // LOW_LEVEL : not allowed to reduce the screen refresh rate, up to 90Hz;
    // MIDDLE_LEVEL : allowed to reduce the screen refresh rate, up to 90Hz;
    // HIGH_LEVEL : allowed to reduce the screen refresh rate, up to 120Hz
    HILOG_COMM_INFO("HandleLightFactorStatus status:%{public}d", state);
    if (pid != DEFAULT_PID) {
        cleanPidCallback_[pid].insert(CleanPidCallbackType::LIGHT_FACTOR);
    }
    multiAppStrategy_.SetScreenType(isLtpo_);
    multiAppStrategy_.HandleLightFactorStatus(state);
    isAmbientStatus_ = state;
    MarkVoteChange();
}

void HgmFrameRateManager::HandlePackageEvent(pid_t pid, const std::vector<std::string>& packageList)
{
    if (pid != DEFAULT_PID) {
        cleanPidCallback_[pid].insert(CleanPidCallbackType::PACKAGE_EVENT);
    }
    // check whether to enable HFBC
    HgmHfbcConfig& hfbcConfig = HgmCore::Instance().GetHfbcConfig();
    hfbcConfig.HandleHfbcConfig(packageList);
    multiAppStrategy_.HandlePkgsEvent(packageList);
    HgmEventDistributor::Instance()->HandlePackageEvent(packageList);
    MarkVoteChange("VOTER_SCENE");
    UpdateAppSupportedState();
}

void HgmFrameRateManager::HandleRefreshRateEvent(pid_t pid, const EventInfo& eventInfo)
{
    std::string eventName = eventInfo.eventName;
    if (eventName == "VOTER_VIDEO_CALL") {
        HgmEnergyConsumptionPolicy::Instance().SetVideoCallSceneInfo(eventInfo);
        return;
    } else if (eventName == "ENERGY_CONSUMPTION_ASSURANCE") {
        HgmEnergyConsumptionPolicy::Instance().SetEnergyConsumptionAssuranceSceneInfo(eventInfo);
        return;
    } else if (eventName == "VOTER_LOW_POWER_SLIDE") {
        HandleLowPowerSlideSceneEvent(eventInfo.description, eventInfo.eventStatus);
        return;
    }
    auto voters = frameVoter_.GetVoters();
    auto event = std::find(voters.begin(), voters.end(), eventName);
    if (event == voters.end()) {
        HGM_LOGW("HgmFrameRateManager:unknown event, eventName is %{public}s", eventName.c_str());
        return;
    }

    HGM_LOGI("%{public}s(%{public}d) [%{public}d %{public}d] %{public}d %{public}s", eventName.c_str(), pid,
        eventInfo.minRefreshRate, eventInfo.maxRefreshRate, eventInfo.eventStatus, eventInfo.description.c_str());
    if (eventName == "VOTER_SCENE") {
        HandleSceneEvent(pid, eventInfo);
    } else if (eventName == "VOTER_VIRTUALDISPLAY") {
        HandleVirtualDisplayEvent(pid, eventInfo);
    } else if (eventName == "VOTER_GAMES") {
        HandleGamesEvent(pid, eventInfo);
    } else if (eventName == "VOTER_MULTISELFOWNEDSCREEN") {
        HandleMultiSelfOwnedScreenEvent(pid, eventInfo);
    } else {
        DeliverRefreshRateVote({eventName, eventInfo.minRefreshRate, eventInfo.maxRefreshRate, pid},
            eventInfo.eventStatus);
    }
}

void HgmFrameRateManager::HandleTouchEvent(pid_t pid, int32_t touchStatus, int32_t touchCnt)
{
    HGM_LOGD("HandleTouchEvent status:%{public}d", touchStatus);
    if (frameVoter_.GetVoterGamesEffective() && touchManager_.GetState() == TouchState::DOWN_STATE) {
        return;
    }
    if (frameVoter_.GetVoterGamesEffective() &&
        (touchStatus ==  TOUCH_MOVE || touchStatus ==  TOUCH_BUTTON_DOWN || touchStatus ==  TOUCH_BUTTON_UP)) {
        return;
    }
    HgmTaskHandleThread::Instance().PostTask([this, pid, touchStatus, touchCnt]() {
        if (touchStatus ==  TOUCH_MOVE || touchStatus ==  TOUCH_BUTTON_DOWN || touchStatus ==  TOUCH_BUTTON_UP ||
            touchStatus == AXIS_BEGIN || touchStatus == AXIS_UPDATE || touchStatus == AXIS_END) {
            HandlePointerTask(pid, touchStatus, touchCnt);
        } else {
            HandleTouchTask(pid, touchStatus, touchCnt);
        }
    });
}

void HgmFrameRateManager::HandleTouchTask(pid_t pid, int32_t touchStatus, int32_t touchCnt)
{
    if (pid != DEFAULT_PID) {
        cleanPidCallback_[pid].insert(CleanPidCallbackType::TOUCH_EVENT);
    }

    if (touchStatus == TOUCH_DOWN || touchStatus == TOUCH_PULL_DOWN) {
        HGM_LOGD("[touch manager] down");
        PolicyConfigData::StrategyConfig strategyRes;
        touchManager_.HandleTouchEvent(TouchEvent::DOWN_EVENT, "");
    } else if (touchStatus == TOUCH_UP || touchStatus == TOUCH_PULL_UP) {
        if (touchCnt != LAST_TOUCH_CNT) {
            return;
        }
        auto voteRecord = frameVoter_.GetVoteRecord();
        if (frameVoter_.GetVoterGamesEffective()) {
            HGM_LOGD("[touch manager] keep down in games");
            return;
        }
        if (touchCnt == LAST_TOUCH_CNT) {
            HGM_LOGD("[touch manager] up");
            touchManager_.HandleTouchEvent(TouchEvent::UP_EVENT, "");
        }
    } else if (touchStatus == TOUCH_CANCEL && touchCnt >= VIRTUAL_KEYBOARD_FINGERS_MIN_CNT) {
        HGM_LOGD("[touch manager] cancel");
        touchManager_.HandleTouchEvent(TouchEvent::UP_EVENT, "");
    } else {
        HGM_LOGD("[touch manager] other touch status not support");
    }
}

void HgmFrameRateManager::HandlePointerTask(pid_t pid, int32_t pointerStatus, int32_t pointerCnt)
{
    if (pid != DEFAULT_PID) {
        cleanPidCallback_[pid].insert(CleanPidCallbackType::TOUCH_EVENT);
    }

    if (pointerStatus ==  TOUCH_MOVE || pointerStatus ==  TOUCH_BUTTON_DOWN || pointerStatus ==  TOUCH_BUTTON_UP) {
        PolicyConfigData::StrategyConfig strategyRes;
        if (multiAppStrategy_.GetFocusAppStrategyConfig(strategyRes) == EXEC_SUCCESS &&
            strategyRes.pointerMode != PointerModeType::POINTER_DISENABLED) {
            HGM_LOGD("[pointer manager] active");
            pointerManager_.HandleTimerReset();
            pointerManager_.HandlePointerEvent(PointerEvent::POINTER_ACTIVE_EVENT, "");
        }
    }

    if (pointerStatus ==  AXIS_BEGIN || pointerStatus == AXIS_UPDATE || pointerStatus == AXIS_END) {
        PolicyConfigData::StrategyConfig strategyRes;
        if (multiAppStrategy_.GetFocusAppStrategyConfig(strategyRes) == EXEC_SUCCESS &&
            strategyRes.pointerMode != PointerModeType::POINTER_DISENABLED) {
            HGM_LOGD("[pointer axis manager] active");
            if (pointerStatus == AXIS_BEGIN) {
                pointerManager_.HandlePointerEvent(PointerEvent::POINTER_ACTIVE_EVENT, "");
            } else {
                pointerManager_.HandleTimerReset();
            }
        }
    }
}

void HgmFrameRateManager::HandleDynamicModeEvent(bool enableDynamicModeEvent)
{
    HILOG_COMM_INFO("HandleDynamicModeEvent status:%{public}u", enableDynamicModeEvent);
    HgmCore::Instance().SetEnableDynamicMode(enableDynamicModeEvent);
    multiAppStrategy_.CalcVote();
}

void HgmFrameRateManager::HandleIdleEvent(bool isIdle)
{
    if (isIdle) {
        HGM_LOGD("HandleIdleEvent status:%{public}u", isIdle);
        DeliverRefreshRateVote({"VOTER_IDLE", idleFps_, idleFps_}, ADD_VOTE);
    } else {
        DeliverRefreshRateVote({"VOTER_IDLE"}, REMOVE_VOTE);
    }
}

void HgmFrameRateManager::HandleRefreshRateMode(int32_t refreshRateMode)
{
    HILOG_COMM_INFO("HandleRefreshRateMode curMode:%{public}d", refreshRateMode);
    if (curRefreshRateMode_ == refreshRateMode) {
        return;
    }

    curRefreshRateMode_ = refreshRateMode;
    DeliverRefreshRateVote({"VOTER_LTPO"}, REMOVE_VOTE);
    multiAppStrategy_.UpdateXmlConfigCache();
    UpdateEnergyConsumptionConfig();
    HandlePageUrlEvent();
    multiAppStrategy_.CalcVote();
    HgmCore::Instance().SetLtpoConfig();
    HgmConfigCallbackManager::GetInstance()->SyncHgmConfigChangeCallback();
    UpdateAppSupportedState();  // sync app state config when RefreshRateMode changed
}

void HgmFrameRateManager::HandleScreenPowerStatus(ScreenId id, ScreenPowerStatus status)
{
    // hgm warning: strategy for screen off
    HILOG_COMM_INFO("curScreen:%{public}d status:%{public}d", static_cast<int>(id), static_cast<int>(status));
    if (status == ScreenPowerStatus::POWER_STATUS_ON) {
        ReportHiSysEvent({.voterName = "SCREEN_POWER", .extInfo = "ON"});
    } else if (status == ScreenPowerStatus::POWER_STATUS_SUSPEND) {
        ReportHiSysEvent({.voterName = "SCREEN_POWER", .extInfo = "OFF"});
    }
    if (status != ScreenPowerStatus::POWER_STATUS_ON || curScreenId_.load() == id) {
        return;
    }

    auto& hgmCore = HgmCore::Instance();
    auto screen = hgmCore.GetScreen(id);
    if (!screen || !screen->GetSelfOwnedScreenFlag()) {
        return;
    }
    if (hgmCore.GetMultiSelfOwnedScreenEnable()) {
        return;
    }

    auto configData = hgmCore.GetPolicyConfigData();
    if (configData == nullptr) {
        return;
    }
    auto& hgmScreenInfo = HgmScreenInfo::GetInstance();
    auto isLtpo = hgmScreenInfo.IsLtpoType(hgmScreenInfo.GetScreenType(id));
    std::string curScreenName = "screen" + std::to_string(id) + "_" + (isLtpo ? "LTPO" : "LTPS");

    isLtpo_ = isLtpo;
    lastCurScreenId_.store(curScreenId_.load());
    curScreenId_.store(id);
    hgmCore.SetActiveScreenId(curScreenId_.load());
    HGM_LOGD("curScreen change:%{public}d", static_cast<int>(curScreenId_.load()));

    HandleScreenFrameRate(curScreenName);
    HandlePageUrlEvent();
}

void HgmFrameRateManager::HandleScreenRectFrameRate(ScreenId id, const GraphicIRect& activeRect)
{
    RS_TRACE_NAME_FMT("HgmFrameRateManager::HandleScreenRectFrameRate screenId:%d activeRect(%d, %d, %d, %d)",
        id, activeRect.x, activeRect.y, activeRect.w, activeRect.h);
    auto& hgmScreenInfo = HgmScreenInfo::GetInstance();
    auto& hgmCore = HgmCore::Instance();
    auto screen = hgmCore.GetScreen(id);
    if (!screen || !screen->GetSelfOwnedScreenFlag()) {
        return;
    }

    auto isLtpo = hgmScreenInfo.IsLtpoType(hgmScreenInfo.GetScreenType(id));

    std::string curScreenName = "screen" + std::to_string(id) + "_" + (isLtpo ? "LTPO" : "LTPS");
    curScreenName += "_" + std::to_string(activeRect.x);
    curScreenName += "_" + std::to_string(activeRect.y);
    curScreenName += "_" + std::to_string(activeRect.w);
    curScreenName += "_" + std::to_string(activeRect.h);
    
    HandleScreenFrameRate(curScreenName);
}

void HgmFrameRateManager::HandleScreenFrameRate(std::string curScreenName)
{
    auto& hgmCore = HgmCore::Instance();
    auto configData = hgmCore.GetPolicyConfigData();
    auto configVisitor = hgmCore.GetPolicyConfigVisitor();
    if (configData == nullptr || configVisitor == nullptr) {
        return;
    }

    if (configData->screenStrategyConfigs_.find(curScreenName) != configData->screenStrategyConfigs_.end()) {
        curScreenStrategyId_ = configData->screenStrategyConfigs_[curScreenName];
    } else {
        curScreenStrategyId_ = "LTPO-DEFAULT";
    }
    curScreenDefaultStrategyId_ = curScreenStrategyId_;

    curScreenStrategyId_ = GetCurScreenExtStrategyId();
    configVisitor->ChangeScreen(curScreenStrategyId_);
    UpdateScreenFrameRate();
}

void HgmFrameRateManager::HandleScreenExtStrategyChange(bool status, const std::string& suffix)
{
    if (screenExtStrategyMap_.find(suffix) == screenExtStrategyMap_.end()) {
        return;
    }
    screenExtStrategyMap_[suffix].second = status;

    std::string curScreenStrategyId = GetCurScreenExtStrategyId();
    if (curScreenStrategyId != curScreenStrategyId_) {
        RS_TRACE_NAME_FMT("HgmFrameRateManager::HandleScreenExtStrategyChange type:%s, status:%d",
            curScreenStrategyId.c_str(), status);
        HILOG_COMM_INFO("HgmFrameRateManager::HandleScreenExtStrategyChange type:%{public}s, status:%{public}d",
            curScreenStrategyId.c_str(), status);
        curScreenStrategyId_ = curScreenStrategyId;
        auto configVisitor = HgmCore::Instance().GetPolicyConfigVisitor();
        if (configVisitor != nullptr) {
            configVisitor->ChangeScreen(curScreenStrategyId_);
        }
        UpdateScreenFrameRate();
    }
}

std::string HgmFrameRateManager::GetCurScreenExtStrategyId()
{
    auto& hgmCore = HgmCore::Instance();
    auto configData = hgmCore.GetPolicyConfigData();
    if (configData == nullptr) {
        return curScreenDefaultStrategyId_;
    }

    std::string suffix;
    for (const auto& [key, value] : screenExtStrategyMap_) {
        if (value.second && (screenExtStrategyMap_.find(suffix) == screenExtStrategyMap_.end() ||
            value.first > screenExtStrategyMap_[suffix].first)) {
            suffix = key;
        }
    }
    std::string curScreenStrategyId = curScreenDefaultStrategyId_ + suffix;
    if (configData->screenConfigs_.find(curScreenStrategyId) == configData->screenConfigs_.end()) {
        HILOG_COMM_ERROR("HgmFrameRateManager::HandleScreenExtStrategyChange not support %{public}s config",
            suffix.c_str());
        return curScreenDefaultStrategyId_;
    }
    return curScreenStrategyId;
}

void HgmFrameRateManager::UpdateScreenExtStrategyConfig(const PolicyConfigData::ScreenConfigMap& screenConfigs)
{
    std::unordered_set<std::string> screenConfigKeys;
    for (const auto& config : screenConfigs) {
        screenConfigKeys.insert(config.first);
    }

    for (auto it = screenExtStrategyMap_.begin(); it != screenExtStrategyMap_.end();) {
        if (std::find_if(screenConfigKeys.begin(), screenConfigKeys.end(),
            [&](const auto& item) { return item.find(it->first) != std::string::npos; }) == screenConfigKeys.end()) {
            it = screenExtStrategyMap_.erase(it);
        } else {
            ++it;
        }
    }
}

void HgmFrameRateManager::UpdateScreenFrameRate()
{
    auto& hgmCore = HgmCore::Instance();
    auto configData = hgmCore.GetPolicyConfigData();
    if (configData == nullptr) {
        return;
    }

    multiAppStrategy_.UpdateXmlConfigCache();
    GetLowBrightVec(configData);
    GetAncoLowBrightVec(configData);
    GetStylusVec(configData);
    UpdateEnergyConsumptionConfig();

    multiAppStrategy_.CalcVote();
    hgmCore.SetLtpoConfig();
    MarkVoteChange();
    HgmConfigCallbackManager::GetInstance()->SyncHgmConfigChangeCallback();

    // hgm warning: use !isLtpo_ instead after GetDisplaySupportedModes ready
    if (curScreenStrategyId_.find("LTPO") == std::string::npos) {
        DeliverRefreshRateVote({"VOTER_LTPO"}, REMOVE_VOTE);
    }

    if (!IsCurrentScreenSupportAS()) {
        isAdaptive_.store(SupportASStatus::NOT_SUPPORT);
    }
}

void HgmFrameRateManager::HandleRsFrame()
{
    touchManager_.HandleRsFrame();
    pointerManager_.HandleRsFrame();
}

void HgmFrameRateManager::HandleStylusSceneEvent(const std::string& sceneName)
{
    if (sceneName == "STYLUS_SLEEP" || sceneName == "STYLUS_NO_LINK") {
        isStylusWakeUp_ = false;
    } else if (sceneName == "STYLUS_WAKEUP") {
        isStylusWakeUp_ = true;
    }
}

void HgmFrameRateManager::HandleLowPowerSlideSceneEvent(const std::string& sceneName, bool eventStatus)
{
    bool slideMode = isLowPowerSlide;
    if (sceneName == "LOW_POWER_SLIDE_MODE") {
        isLowPowerSlide = eventStatus;
    }
    slideModeChange = (slideMode != isLowPowerSlide);
}

void HgmFrameRateManager::HandleSceneEvent(pid_t pid, const EventInfo& eventInfo)
{
    // control the list of supported frame rates for stylus pen, not control frame rate directly
    HandleStylusSceneEvent(eventInfo.description);
    HgmEventDistributor::Instance()->HandleSceneEvent(pid, eventInfo);
}

void HgmFrameRateManager::HandleVirtualDisplayEvent(pid_t pid, EventInfo eventInfo)
{
    std::string virtualDisplayName = eventInfo.description;
    auto configData = HgmCore::Instance().GetPolicyConfigData();
    if (configData == nullptr || !configData->virtualDisplaySwitch_) {
        // disable vote from virtual display in xml
        return;
    }

    auto virtualDisplayConfig = configData->virtualDisplayConfigs_;
    if (virtualDisplayConfig.count(virtualDisplayName) == 0 ||
        configData->strategyConfigs_.count(virtualDisplayConfig[virtualDisplayName]) == 0) {
        HGM_LOGW("HandleVirtualDisplayEvent:unknow virtual display [%{public}s]", virtualDisplayName.c_str());
        DeliverRefreshRateVote({"VOTER_VIRTUALDISPLAY", OLED_60_HZ, OLED_60_HZ, pid}, eventInfo.eventStatus);
    } else {
        auto curStrategy = configData->strategyConfigs_[virtualDisplayConfig[virtualDisplayName]];
        DeliverRefreshRateVote({"VOTER_VIRTUALDISPLAY", curStrategy.min, curStrategy.max, pid}, ADD_VOTE);
    }
}

void HgmFrameRateManager::HandleGamesEvent(pid_t pid, EventInfo eventInfo)
{
    if (!eventInfo.eventStatus) {
        isGameSupportAS_ = SupportASStatus::NOT_SUPPORT;
        DeliverRefreshRateVote({"VOTER_GAMES"}, false);
        return;
    }
    auto [pkgName, gamePid, appType] = HgmMultiAppStrategy::AnalyzePkgParam(eventInfo.description);
    if (gamePid == DEFAULT_PID) {
        HILOG_COMM_ERROR("unknow game pid: %{public}s, skip", eventInfo.description.c_str());
        return;
    }
    if (pid != DEFAULT_PID) {
        cleanPidCallback_[pid].insert(CleanPidCallbackType::GAMES);
    }
    PolicyConfigData::StrategyConfig config;
    if (multiAppStrategy_.GetAppStrategyConfig(pkgName, config) == EXEC_SUCCESS) {
        isGameSupportAS_ = config.supportAS;
        SetGameNodeName(multiAppStrategy_.GetGameNodeName(pkgName));
    } else {
        isGameSupportAS_ = SupportASStatus::NOT_SUPPORT;
        SetGameNodeName("");
    }
    DeliverRefreshRateVote(
        {"VOTER_GAMES", eventInfo.minRefreshRate, eventInfo.maxRefreshRate, gamePid}, eventInfo.eventStatus);
}

void HgmFrameRateManager::HandleMultiSelfOwnedScreenEvent(pid_t pid, EventInfo eventInfo)
{
    HgmCore::Instance().SetMultiSelfOwnedScreenEnable(eventInfo.eventStatus);
    DeliverRefreshRateVote(
        {"VOTER_MULTISELFOWNEDSCREEN", eventInfo.minRefreshRate, eventInfo.maxRefreshRate, pid},
        eventInfo.eventStatus);
}

void HgmFrameRateManager::MarkVoteChange(const std::string& voter)
{
    auto voteRecord = frameVoter_.GetVoteRecord();
    if (auto iter = voteRecord.find(voter);
        voter != "" && (iter == voteRecord.end() || !iter->second.second) && !voterTouchEffective_) {
        return;
    }

    VoteInfo resultVoteInfo = ProcessRefreshRateVote();
    if (lastVoteInfo_ == resultVoteInfo) {
        if (isAmbientStatus_ < LightFactorStatus::LOW_LEVEL && !voterTouchEffective_) {
            return;
        }
    } else {
        lastVoteInfo_ = resultVoteInfo;
        HGM_LOGI("Strategy:%{public}s Screen:%{public}d Mode:%{public}d -- %{public}s", curScreenStrategyId_.c_str(),
            static_cast<int>(curScreenId_.load()), curRefreshRateMode_, resultVoteInfo.ToSimpleString().c_str());
    }

    // max used here
    FrameRateRange finalRange = {resultVoteInfo.max, resultVoteInfo.max, resultVoteInfo.max};
    auto refreshRate = CalcRefreshRate(curScreenId_.load(), finalRange);
    if (refreshRate == currRefreshRate_ && !voterTouchEffective_) {
        return;
    }

    CheckForceUpdateCallback(refreshRate);

    // changeGenerator only once in a single vsync period
    if (!changeGeneratorRateValid_.load()) {
        return;
    }
    bool needChangeDssRefreshRate = currRefreshRate_.load() != refreshRate;
    RS_TRACE_NAME_FMT("MarkVoteChange: %d %d", currRefreshRate_.load(), refreshRate);
    currRefreshRate_.store(refreshRate);
    schedulePreferredFpsChange_ = needChangeDssRefreshRate;
    FrameRateReport();

    bool frameRateChanged = false;
    if (rsFrameRateLinker_ != nullptr) {
        frameRateChanged = softVSyncManager_.CollectFrameRateChange(finalRange, rsFrameRateLinker_,
            appFrameRateLinkers_, currRefreshRate_);
    }
    CheckRefreshRateChange(false, frameRateChanged, refreshRate, needChangeDssRefreshRate);
    ReportHiSysEvent(resultVoteInfo);
}

void HgmFrameRateManager::DeliverRefreshRateVote(const VoteInfo& voteInfo, bool eventStatus)
{
    frameVoter_.DeliverVote(voteInfo, eventStatus);
}

bool HgmFrameRateManager::IsCurrentScreenSupportAS()
{
    auto hdiDevice = HdiDevice::GetInstance();
    if (hdiDevice == nullptr) {
        return false;
    }
    ScreenId id = HgmCore::Instance().GetActiveScreenId();
    ScreenPhysicalId screenId = static_cast<ScreenPhysicalId>(id);
    uint64_t propertyAS = 0;
    hdiDevice->GetDisplayProperty(screenId, ADAPTIVE_SYNC_PROPERTY, propertyAS);
    return propertyAS == DISPLAY_SUCCESS;
}

void HgmFrameRateManager::ProcessAdaptiveSync(const std::string& voterName)
{
    // VOTER_GAMES wins, enter adaptive vsync mode
    bool isGameVoter = voterName == "VOTER_GAMES";

    if (!isGameVoter) {
        isAdaptive_.store(SupportASStatus::NOT_SUPPORT);
        return;
    }

    if (isGameSupportAS_ == SupportASStatus::GAME_SCENE_SKIP) {
        isAdaptive_.store(isGameSupportAS_);
        return;
    }

    if (!HgmCore::Instance().GetAdaptiveSyncEnabled()) {
        return;
    }

    if (isGameSupportAS_ != SupportASStatus::SUPPORT_AS) {
        HILOG_COMM_INFO("this game does not support adaptive sync mode");
        return;
    }

    if (!IsCurrentScreenSupportAS()) {
        HILOG_COMM_INFO("current screen not support adaptive sync mode");
        return;
    }

    HILOG_COMM_INFO("ProcessHgmFrameRate RSAdaptiveVsync change mode");
    RS_TRACE_BEGIN("ProcessHgmFrameRate RSAdaptiveVsync change mode");
    isAdaptive_.store(SupportASStatus::SUPPORT_AS);
    RS_TRACE_END();
}

bool HgmFrameRateManager::CheckAncoVoterStatus() const
{
    if (isAmbientStatus_ != LightFactorStatus::NORMAL_LOW || !isLtpo_ ||
        !isAmbientEffect_ || ancoLowBrightVec_.empty()) {
        return false;
    }
    auto voteRecord = frameVoter_.GetVoteRecord();
    auto iter = voteRecord.find("VOTER_ANCO");
    if (iter == voteRecord.end() || iter->second.first.empty() || !iter->second.second) {
        return false;
    }
    return true;
}

VoteInfo HgmFrameRateManager::ProcessRefreshRateVote()
{
    auto [resultVoteInfo, voteRange] = frameVoter_.ProcessVote(curScreenStrategyId_,
        curScreenId_.load(), curRefreshRateMode_);
    auto [min, max] = voteRange;
    SetResultVoteInfo(resultVoteInfo, min, max);
    ProcessAdaptiveSync(resultVoteInfo.voterName);

    auto sampler = CreateVSyncSampler();
    sampler->SetAdaptive(isAdaptive_.load() == SupportASStatus::SUPPORT_AS);
    if (controller_ != nullptr) {
        controller_->ChangeAdaptiveStatus(isAdaptive_.load() == SupportASStatus::SUPPORT_AS);
    }
    return resultVoteInfo;
}

void HgmFrameRateManager::CleanVote(pid_t pid)
{
    if (pid == DEFAULT_PID) {
        return;
    }
    multiAppStrategy_.CleanApp(pid);
    if (auto iter = cleanPidCallback_.find(pid); iter != cleanPidCallback_.end()) {
        for (auto cleanPidCallbackType : iter->second) {
            switch (cleanPidCallbackType) {
                case CleanPidCallbackType::LIGHT_FACTOR:
                    HandleLightFactorStatus(DEFAULT_PID, LightFactorStatus::NORMAL_HIGH);
                    break;
                case CleanPidCallbackType::PACKAGE_EVENT:
                    HandlePackageEvent(DEFAULT_PID, {}); // handle empty pkg
                    break;
                case CleanPidCallbackType::TOUCH_EVENT:
                    HandleTouchEvent(DEFAULT_PID, TouchStatus::TOUCH_UP, LAST_TOUCH_CNT);
                    break;
                case CleanPidCallbackType::GAMES:
                    DeliverRefreshRateVote({"VOTER_GAMES"}, false);
                    break;
                case CleanPidCallbackType::PAGE_URL:
                    CleanPageUrlVote(pid);
                    break;
                case CleanPidCallbackType::APP_STRATEGY_CONFIG_EVENT:
                    HandleAppStrategyConfigEvent(DEFAULT_PID, "", {});
                    break;
                default:
                    break;
            }
        }
        iter->second.clear();
    }

    softVSyncManager_.EraseGameRateDiscountMap(pid);
    frameVoter_.CleanVote(pid);
}

void HgmFrameRateManager::SetResultVoteInfo(VoteInfo& voteInfo, uint32_t min, uint32_t max)
{
    voteInfo.min = min;
    voteInfo.max = max;
    if (voteInfo.voterName == "VOTER_PACKAGES" && touchManager_.GetState() != TouchState::IDLE_STATE) {
        voteInfo.extInfo = "ONTOUCH";
    }
    if (auto packages = multiAppStrategy_.GetPackages(); packages.size() > 0) {
        const auto& package = packages.front();
        const auto& pos = package.find(":");
        if (pos != package.npos) {
            voteInfo.bundleName = package.substr(0, pos);
        } else {
            voteInfo.bundleName = packages.front();
        }
    }
}

void HgmFrameRateManager::UpdateEnergyConsumptionConfig()
{
    HgmEnergyConsumptionPolicy::Instance().SetEnergyConsumptionConfig(
        multiAppStrategy_.GetScreenSetting().animationPowerConfig);
    HgmEnergyConsumptionPolicy::Instance().SetUiEnergyConsumptionConfig(
        multiAppStrategy_.GetScreenSetting().uiPowerConfig);
    HgmEnergyConsumptionPolicy::Instance().SetRefreshRateMode(curRefreshRateMode_, curScreenStrategyId_);
}

bool HgmFrameRateManager::UpdateUIFrameworkDirtyNodes(
    std::vector<std::weak_ptr<RSRenderNode>>& uiFwkDirtyNodes, uint64_t timestamp)
{
    timestamp_ = timestamp;
    HgmEnergyConsumptionPolicy::Instance().CheckOnlyVideoCallExist();
    if (!voterTouchEffective_ || frameVoter_.GetVoterGamesEffective()) {
        surfaceData_.clear();
        return false;
    }
    std::unordered_map<std::string, pid_t> uiFrameworkDirtyNodeName;
    for (auto iter = uiFwkDirtyNodes.begin(); iter != uiFwkDirtyNodes.end();) {
        auto renderNode = iter->lock();
        if (renderNode == nullptr) {
            iter = uiFwkDirtyNodes.erase(iter);
        } else {
            if (renderNode->IsDirty()) {
                uiFrameworkDirtyNodeName[renderNode->GetNodeName()] = ExtractPid(renderNode->GetId());
            }
            ++iter;
        }
    }

    if (uiFrameworkDirtyNodeName.empty() && surfaceData_.empty() &&
        (timestamp - lastPostIdleDetectorTaskTimestamp_) < BUFFER_IDLE_TIME_OUT) {
        return false;
    }
    HgmTaskHandleThread::Instance().PostTask([this, uiFrameworkDirtyNodeName, timestamp,
                                              surfaceData = surfaceData_]() {
        for (const auto& [surfaceName, pid, uiFwkType] : surfaceData) {
            if (multiAppStrategy_.CheckPidValid(pid, true)) {
                idleDetector_.UpdateSurfaceTime(surfaceName, timestamp, pid, uiFwkType);
            }
        }
        for (const auto& [uiFwkDirtyNodeName, pid] : uiFrameworkDirtyNodeName) {
            if (multiAppStrategy_.CheckPidValid(pid, true)) {
                idleDetector_.UpdateSurfaceTime(uiFwkDirtyNodeName, timestamp, pid, UIFWKType::FROM_UNKNOWN);
            }
        }
    });
    surfaceData_.clear();
    lastPostIdleDetectorTaskTimestamp_ = timestamp;
    return true;
}

bool HgmFrameRateManager::HandleGameNode(const RSRenderNodeMap& nodeMap)
{
    bool isGameSelfNodeOnTree = false;
    bool isOtherSelfNodeOnTree = false;
    std::string gameNodeName = GetGameNodeName();
    nodeMap.TraverseSurfaceNodes(
        [&isGameSelfNodeOnTree, &gameNodeName, &isOtherSelfNodeOnTree]
        (const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode) mutable {
            if (surfaceNode == nullptr) {
                return;
            }
            if (surfaceNode->IsOnTheTree() &&
                surfaceNode->GetSurfaceNodeType() == RSSurfaceNodeType::SELF_DRAWING_NODE) {
                if (gameNodeName == surfaceNode->GetName()) {
                    isGameSelfNodeOnTree = true;
                } else {
                    isOtherSelfNodeOnTree = true;
                }
            }
        });
    RS_TRACE_NAME_FMT("HgmFrameRateManager::HandleGameNode, game node on tree: %d, other node no tree: %d",
                      isGameSelfNodeOnTree, isOtherSelfNodeOnTree);
    isGameNodeOnTree_.store(isGameSelfNodeOnTree && !isOtherSelfNodeOnTree);
    return isGameSelfNodeOnTree && !isOtherSelfNodeOnTree;
}

void HgmFrameRateManager::HandleAppStrategyConfigEvent(pid_t pid, const std::string& pkgName,
    const std::vector<std::pair<std::string, std::string>>& newConfig)
{
    if (pid != DEFAULT_PID) {
        cleanPidCallback_[pid].insert(CleanPidCallbackType::APP_STRATEGY_CONFIG_EVENT);
    }
    HgmEventDistributor::Instance()->HandleAppStrategyConfigEvent(pkgName, newConfig);
}

void HgmFrameRateManager::SetChangeGeneratorRateValid(bool valid)
{
    if (changeGeneratorRateValid_ == valid) {
        return;
    }
    changeGeneratorRateValid_ = valid;
    if (!valid) {
        changeGeneratorRateValidTimer_.Start();
    }
}

void HgmFrameRateManager::ProcessPageUrlVote(pid_t pid, std::string strategy, const bool isAddVoter)
{
    if (isAddVoter) {
        PolicyConfigData::StrategyConfig strategyConfig;
        if (multiAppStrategy_.GetStrategyConfig(strategy, strategyConfig) == EXEC_SUCCESS) {
            auto min = strategyConfig.min;
            auto max = strategyConfig.max;
            DeliverRefreshRateVote({"VOTER_PAGE_URL", min, max, pid}, ADD_VOTE);
        }
        if (pid != DEFAULT_PID) {
            cleanPidCallback_[pid].insert(CleanPidCallbackType::PAGE_URL);
        }
    } else {
        DeliverRefreshRateVote({"VOTER_PAGE_URL", 0, 0, pid}, REMOVE_VOTE);
    }
}

void HgmFrameRateManager::CleanPageUrlVote(pid_t pid)
{
    DeliverRefreshRateVote({"VOTER_PAGE_URL", 0, 0, pid}, REMOVE_VOTE);
    appPageUrlStrategy_.CleanPageUrlVote(pid);
}

void HgmFrameRateManager::HandlePageUrlEvent()
{
    auto screenSetting = multiAppStrategy_.GetScreenSetting();
    appPageUrlStrategy_.SetPageUrlConfig(screenSetting.pageUrlConfig);
    appPageUrlStrategy_.NotifyScreenSettingChange();
}

void HgmFrameRateManager::NotifyPageName(pid_t pid, const std::string& packageName,
    const std::string& pageName, bool isEnter)
{
    auto screenSetting = multiAppStrategy_.GetScreenSetting();
    appPageUrlStrategy_.SetPageUrlConfig(screenSetting.pageUrlConfig);
    appPageUrlStrategy_.NotifyPageName(pid, packageName, pageName, isEnter);
}

void HgmFrameRateManager::CheckNeedUpdateAppOffset(uint32_t refreshRate, uint32_t controllerRate)
{
    if (controller_ == nullptr || refreshRate > OLED_60_HZ || isNeedUpdateAppOffset_ ||
        !controller_->CheckNeedUpdateAppOffsetRefreshRate(controllerRate)) {
        return;
    }
    if (touchManager_.GetState() == TouchState::IDLE_STATE) {
        isNeedUpdateAppOffset_ = true;
        return;
    }
    if (isLowPowerSlide && refreshRate == OLED_60_HZ) {
        isNeedUpdateAppOffset_ = true;
        return;
    }
    auto voteRecord = frameVoter_.GetVoteRecord();
    if (auto iter = voteRecord.find("VOTER_THERMAL");
        iter != voteRecord.end() && !iter->second.first.empty() &&
        iter->second.first.back().max > 0 && iter->second.first.back().max <= OLED_60_HZ) {
        isNeedUpdateAppOffset_ = true;
        return;
    }
}

void HgmFrameRateManager::CheckRefreshRateChange(
    bool followRs, bool frameRateChanged, uint32_t refreshRate, bool needChangeDssRefreshRate)
{
    // 当dvsync在连续延迟切帧阶段，使用dvsync内记录的刷新率判断是否变化
    auto controllerRate = softVSyncManager_.GetControllerRate();
    bool isNeedDvsyncDelay = CreateVSyncGenerator()->DVSyncRateChanged(controllerRate,
        frameRateChanged, needChangeDssRefreshRate);
    bool appOffsetChange = false;
    if (controller_ != nullptr) {
        CheckNeedUpdateAppOffset(refreshRate, controllerRate);
        appOffsetChange = isNeedUpdateAppOffset_ && controller_->GetPulseNum() != 0;
    }
    if (HgmCore::Instance().GetLtpoEnabled() &&
        (frameRateChanged || (appOffsetChange && !CreateVSyncGenerator()->IsUiDvsyncOn()))) {
        HandleFrameRateChangeForLTPO(timestamp_.load(), followRs, isNeedDvsyncDelay);
        if (needChangeDssRefreshRate && forceUpdateCallback_ != nullptr) {
            forceUpdateCallback_(false, true);
        }
    } else {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
        if (needChangeDssRefreshRate && forceUpdateCallback_ != nullptr) {
            forceUpdateCallback_(false, true);
        }
        if (frameRateChanged) {
            softVSyncManager_.SetQosVSyncRate(currRefreshRate_, appFrameRateLinkers_);
        }
    }
    if (HgmCore::Instance().GetLtpoEnabled() && appOffsetChange && isNeedUpdateAppOffset_) {
        HgmCore::Instance().SetHgmTaskFlag(true);
    }
    isNeedUpdateAppOffset_ = false;
}

void HgmFrameRateManager::FrameRateReportTask(uint32_t leftRetryTimes)
{
    HgmTaskHandleThread::Instance().PostTask(
        [this, leftRetryTimes]() {
            if (leftRetryTimes == 1 || system::GetBoolParameter("bootevent.boot.completed", false)) {
                HGM_LOGI("FrameRateReportTask run and left retry:%{public}d", leftRetryTimes);
                schedulePreferredFpsChange_ = true;
                FrameRateReport();
                return;
            }
            if (leftRetryTimes > 1) {
                FrameRateReportTask(leftRetryTimes - 1);
            }
        },
        FRAME_RATE_REPORT_DELAY_TIME);
}

bool HgmFrameRateManager::SetVsyncRateDiscountLTPO(const std::vector<uint64_t>& linkerIds, uint32_t rateDiscount)
{
    HgmTaskHandleThread::Instance().PostTask([this, linkerIds, rateDiscount]() {
        softVSyncManager_.SetVsyncRateDiscountLTPO(linkerIds, rateDiscount);
        UpdateSoftVSync(false);
    });
    return true;
}
} // namespace Rosen
} // namespace OHOS

