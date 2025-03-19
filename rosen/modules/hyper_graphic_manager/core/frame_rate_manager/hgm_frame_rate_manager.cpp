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
#include "common/rs_common_hook.h"
#include "common/rs_optional_trace.h"
#include "common/rs_thread_handler.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "hgm_config_callback_manager.h"
#include "hgm_core.h"
#include "hgm_energy_consumption_policy.h"
#include "hgm_hfbc_config.h"
#include "hgm_log.h"
#include "hgm_screen_info.h"
#include "parameters.h"
#include "rs_trace.h"
#include "sandbox_utils.h"
#include "frame_rate_report.h"
#include "hisysevent.h"
#include "hdi_device.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_hisysevent.h"

namespace OHOS {
namespace Rosen {
namespace {
    constexpr int32_t IDLE_TIMER_EXPIRED = 200; // ms
    constexpr int32_t CHANGE_GENERATOR_RATE_VALID_TIMEOUT = 20; //ms
    constexpr int64_t UNI_RENDER_VSYNC_OFFSET = 5000000; // ns
    constexpr int64_t UNI_RENDER_VSYNC_OFFSET_DELAY_MODE = -3300000; // ns
    constexpr uint32_t REPORT_VOTER_INFO_LIMIT = 20;
    constexpr int32_t LAST_TOUCH_CNT = 1;

    constexpr uint32_t FIRST_FRAME_TIME_OUT = 100; // 100ms
    constexpr uint32_t DEFAULT_PRIORITY = 0;
    constexpr uint32_t VOTER_SCENE_PRIORITY_BEFORE_PACKAGES = 1;
    constexpr uint32_t VOTER_LTPO_PRIORITY_BEFORE_PACKAGES = 2;
    constexpr uint64_t BUFFER_IDLE_TIME_OUT = 200000000; // 200ms
    const static std::string UP_TIME_OUT_TASK_ID = "UP_TIME_OUT_TASK_ID";
    const static std::string LOW_BRIGHT = "LowBright";
    const static std::string STYLUS_PEN = "StylusPen";
    // CAUTION: with priority
    const std::string VOTER_NAME[] = {
        "VOTER_THERMAL",
        "VOTER_VIRTUALDISPLAY_FOR_CAR",
        "VOTER_VIRTUALDISPLAY",
        "VOTER_MUTIPHYSICALSCREEN",
        "VOTER_MULTISELFOWNEDSCREEN",
        "VOTER_POWER_MODE",
        "VOTER_DISPLAY_ENGINE",
        "VOTER_GAMES",
        "VOTER_ANCO",

        "VOTER_PAGE_URL",
        "VOTER_PACKAGES",
        "VOTER_LTPO",
        "VOTER_TOUCH",
        "VOTER_POINTER",
        "VOTER_SCENE",
        "VOTER_VIDEO",
        "VOTER_IDLE"
    };

    constexpr int ADAPTIVE_SYNC_PROPERTY = 3;
    constexpr int DISPLAY_SUCCESS = 1;

    constexpr int32_t STYLUS_NO_LINK = 0;
    constexpr int32_t STYLUS_LINK_UNUSED = 1;
    constexpr int32_t STYLUS_LINK_WRITE = 2;
    const std::unordered_map<std::string, int32_t> STYLUS_STATUS_MAP = {
        {"STYLUS_NO_LINK", STYLUS_NO_LINK},
        {"STYLUS_LINK_UNUSED", STYLUS_LINK_UNUSED},
        {"STYLUS_LINK_WRITE", STYLUS_LINK_WRITE}};
}

HgmFrameRateManager::HgmFrameRateManager()
    : changeGeneratorRateValidTimer_("ChangeGeneratorRateValid",
        std::chrono::milliseconds(CHANGE_GENERATOR_RATE_VALID_TIMEOUT), nullptr, [this] () {
            changeGeneratorRateValid_ = true;
            UpdateSoftVSync(false);
    }),
    rsFrameRateTimer_("rsFrameRate", std::chrono::milliseconds(IDLE_TIMER_EXPIRED), nullptr, [this] () {
        if (rsFrameRateLinker_ != nullptr) {
            rsFrameRateLinker_->SetExpectedRange({});
            UpdateSoftVSync(false);
        }
    }),
    voters_(std::begin(VOTER_NAME), std::end(VOTER_NAME))
{
    for (auto &voter : VOTER_NAME) {
        voteRecord_[voter] = {{}, true};
    }
}

void HgmFrameRateManager::Init(sptr<VSyncController> rsController,
    sptr<VSyncController> appController, sptr<VSyncGenerator> vsyncGenerator)
{
    auto& hgmCore = HgmCore::Instance();
    curRefreshRateMode_ = hgmCore.GetCurrentRefreshRateMode();
    multiAppStrategy_.UpdateXmlConfigCache();
    UpdateEnergyConsumptionConfig();

    // hgm warning: get non active screenId in non-folding devices（from sceneboard）
    auto screenList = hgmCore.GetScreenIds();
    curScreenId_.store(screenList.empty() ? 0 : screenList.front());
    auto& hgmScreenInfo = HgmScreenInfo::GetInstance();
    isLtpo_ = hgmScreenInfo.IsLtpoType(hgmScreenInfo.GetScreenType(curScreenId_.load()));
    std::string curScreenName = "screen" + std::to_string(curScreenId_.load()) + "_" + (isLtpo_ ? "LTPO" : "LTPS");
    auto configData = hgmCore.GetPolicyConfigData();
    if (configData != nullptr) {
        if (configData->screenStrategyConfigs_.find(curScreenName) != configData->screenStrategyConfigs_.end()) {
            curScreenStrategyId_ = configData->screenStrategyConfigs_[curScreenName];
        }
        if (curScreenStrategyId_.empty()) {
            curScreenStrategyId_ = "LTPO-DEFAULT";
        }
        if (curRefreshRateMode_ != HGM_REFRESHRATE_MODE_AUTO && configData->xmlCompatibleMode_) {
            curRefreshRateMode_ = configData->SettingModeId2XmlModeId(curRefreshRateMode_);
        }
        multiAppStrategy_.UpdateXmlConfigCache();
        GetLowBrightVec(configData);
        GetStylusVec(configData);
        UpdateEnergyConsumptionConfig();
        multiAppStrategy_.CalcVote();
        HandleIdleEvent(ADD_VOTE);
    }

    RegisterCoreCallbacksAndInitController(rsController, appController, vsyncGenerator);
    multiAppStrategy_.RegisterStrategyChangeCallback([this] (const PolicyConfigData::StrategyConfig& strategy) {
        DeliverRefreshRateVote({"VOTER_PACKAGES", strategy.min, strategy.max}, ADD_VOTE);
        idleFps_ = strategy.idleFps;
        HandleIdleEvent(true);
    });
    InitTouchManager();
    hgmCore.SetLtpoConfig();
    multiAppStrategy_.CalcVote();
    appPageUrlStrategy_.RegisterPageUrlVoterCallback([this] (pid_t pid,
        std::string strategy, const bool isAddVoter) {
        ProcessPageUrlVote(pid, strategy, isAddVoter);
    });
}

void HgmFrameRateManager::RegisterCoreCallbacksAndInitController(sptr<VSyncController> rsController,
    sptr<VSyncController> appController, sptr<VSyncGenerator> vsyncGenerator)
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
        HgmTaskHandleThread::Instance().PostTask([refreshRate] () {
            HgmConfigCallbackManager::GetInstance()->SyncRefreshRateUpdateCallback(refreshRate);
        });
    });

    controller_ = std::make_shared<HgmVSyncGeneratorController>(rsController, appController, vsyncGenerator);
}

void HgmFrameRateManager::InitTouchManager()
{
    static std::once_flag createFlag;
    std::call_once(createFlag, [this]() {
        auto updateTouchToMultiAppStrategy = [this](TouchState newState) {
            HgmMultiAppStrategy::TouchInfo touchInfo = {
                .pkgName = touchManager_.GetPkgName(),
                .touchState = newState,
            };
            HgmEnergyConsumptionPolicy::Instance().SetTouchState(newState);
            multiAppStrategy_.HandleTouchInfo(touchInfo);
            UpdateSoftVSync(false);
        };
        touchManager_.RegisterEventCallback(TouchEvent::UP_TIMEOUT_EVENT, [this] (TouchEvent event) {
            SetSchedulerPreferredFps(OLED_60_HZ);
            SetIsNeedUpdateAppOffset(true);
            touchManager_.ChangeState(TouchState::IDLE_STATE);
        });
        touchManager_.RegisterEventCallback(TouchEvent::DOWN_EVENT, [this] (TouchEvent event) {
            SetSchedulerPreferredFps(OLED_120_HZ);
            touchManager_.ChangeState(TouchState::DOWN_STATE);
        });
        touchManager_.RegisterEnterStateCallback(TouchState::DOWN_STATE,
            [this, updateTouchToMultiAppStrategy] (TouchState lastState, TouchState newState) {
            updateTouchToMultiAppStrategy(newState);
            startCheck_.store(false);
            voterTouchEffective_.store(true);
            forceUpdateCallback_(false, true);
        });
        touchManager_.RegisterEnterStateCallback(TouchState::IDLE_STATE,
            [this, updateTouchToMultiAppStrategy] (TouchState lastState, TouchState newState) {
            startCheck_.store(false);
            updateTouchToMultiAppStrategy(newState);
            voterTouchEffective_.store(false);
        });
        touchManager_.RegisterEnterStateCallback(TouchState::UP_STATE,
            [this, updateTouchToMultiAppStrategy] (TouchState lastState, TouchState newState) {
            HgmTaskHandleThread::Instance().PostEvent(UP_TIME_OUT_TASK_ID, [this] () {
                startCheck_.store(true);
                UpdateSoftVSync(false);
            }, FIRST_FRAME_TIME_OUT);
            updateTouchToMultiAppStrategy(newState);
        });
        touchManager_.RegisterExitStateCallback(TouchState::UP_STATE,
            [this] (TouchState lastState, TouchState newState) {
            HgmTaskHandleThread::Instance().RemoveEvent(UP_TIME_OUT_TASK_ID);
            startCheck_.store(false);
        });
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
    auto &hgmCore = HgmCore::Instance();
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
        config.dynamicMode == DynamicModeType::TOUCH_EXT_ENABLED) {
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
    if (finalRange.IsValid()) {
        auto refreshRate = CalcRefreshRate(curScreenId_.load(), finalRange);
        DeliverRefreshRateVote(
            {"VOTER_LTPO", refreshRate, refreshRate, DEFAULT_PID, finalRange.GetExtInfo()}, ADD_VOTE);
    } else {
        DeliverRefreshRateVote({.voterName = "VOTER_LTPO"}, REMOVE_VOTE);
    }
}

void HgmFrameRateManager::UniProcessDataForLtpo(uint64_t timestamp,
    std::shared_ptr<RSRenderFrameRateLinker> rsFrameRateLinker, const FrameRateLinkerMap& appFrameRateLinkers,
    const std::map<uint64_t, int>& vRatesMap)
{
    RS_TRACE_FUNC();
    timestamp_ = timestamp;
    rsFrameRateLinker_ = rsFrameRateLinker;
    appFrameRateLinkers_ = appFrameRateLinkers;

    vRatesMap_ = vRatesMap;
    UpdateSoftVSync(true);
}

void HgmFrameRateManager::UpdateSoftVSync(bool followRs)
{
    if (rsFrameRateLinker_ == nullptr) {
        return;
    }
    Reset();
    FrameRateRange finalRange = rsFrameRateLinker_->GetExpectedRange();
    HgmEnergyConsumptionPolicy::Instance().GetAnimationIdleFps(finalRange);
    rsFrameRateLinker_->SetExpectedRange(finalRange);
    idleDetector_.SetAceAnimatorIdleState(true);
    for (auto linker : appFrameRateLinkers_) {
        if (linker.second == nullptr || !multiAppStrategy_.CheckPidValid(ExtractPid(linker.first))) {
            continue;
        }
        SetAceAnimatorVote(linker.second);
        auto expectedRange = linker.second->GetExpectedRange();
        if (!HgmEnergyConsumptionPolicy::Instance().GetUiIdleFps(expectedRange) &&
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
    auto refreshRate = CalcRefreshRate(curScreenId_.load(), finalRange);
    if (currRefreshRate_.load() != refreshRate) {
        currRefreshRate_.store(refreshRate);
        schedulePreferredFpsChange_ = true;
        FrameRateReport();
    }

    bool frameRateChanged = CollectFrameRateChange(finalRange, rsFrameRateLinker_, appFrameRateLinkers_);
    CheckRefreshRateChange(followRs, frameRateChanged, refreshRate);
    ReportHiSysEvent(lastVoteInfo_);
}

void HgmFrameRateManager::CollectVRateChange(uint64_t linkerId, FrameRateRange& finalRange)
{
    auto iter = vRatesMap_.find(linkerId);
    if (iter == vRatesMap_.end()) {
        RS_OPTIONAL_TRACE_NAME_FMT("CollectVRateChange not find pid = %d linkerId = %" PRIu64 " return",
            ExtractPid(linkerId), linkerId);
        HGM_LOGD("CollectVRateChange not find pid = %{public}d linkerId = %{public}" PRIu64 " return",
            ExtractPid(linkerId), linkerId);
        return;
    }
    if (iter->second == 1 || iter->second == 0) {
        RS_OPTIONAL_TRACE_NAME_FMT("CollectVRateChange pid = %d , linkerId = %" PRIu64 ", vrate = %d return",
            ExtractPid(linkerId), linkerId, iter->second);
        HGM_LOGD("CollectVRateChange linkerId = %{public}" PRIu64 ",vrate = %{public}d return",
                linkerId, iter->second);
        return;
    }
    int32_t& appFrameRate = finalRange.preferred_;
    // finalRange.preferred_ is 0 means that the appframerate want to be changed by self.
    if (appFrameRate != 0) {
        RS_OPTIONAL_TRACE_NAME_FMT("CollectVRateChange pid = %d , linkerId = %" PRIu64 ", vrate = %d "
            "return because changed by self", ExtractPid(linkerId), linkerId, iter->second);
        HGM_LOGD("CollectVRateChange linkerId = %{public}" PRIu64 ",vrate = %{public}d return because changed by self",
                linkerId, iter->second);
        return;
    }

    appFrameRate = static_cast<int>(controllerRate_) / iter->second;
    // vrate is int::max means app need not refreshing
    if (appFrameRate == 0) {
        //appFrameRate value is 1  means that not refreshing.
        appFrameRate = 1;
    }
    finalRange.min_ = OLED_NULL_HZ;
    finalRange.max_ = OLED_144_HZ;
    RS_TRACE_NAME_FMT("CollectVRateChange modification pid = %d , linkerIdS = %" PRIu64 ",appFrameRate = %d,"
        " vrate = %d, rsFrameRate = %u", ExtractPid(linkerId), linkerId, appFrameRate, iter->second, controllerRate_);
    HGM_LOGD("CollectVRateChange modification linkerId = %{public}" PRIu64 ",appFrameRate = %{public}d,"
        " vrate = %{public}d, rsFrameRate = %{public}u", linkerId, appFrameRate, iter->second, controllerRate_);
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
    if (!schedulePreferredFpsChange_) {
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
    HGM_LOGD("FrameRateReport: RS(%{public}d) = %{public}d, APP(%{public}d) = %{public}d",
        GetRealPid(), rates[GetRealPid()], UNI_APP_PID, rates[UNI_APP_PID]);
    RS_TRACE_NAME_FMT("FrameRateReport: RS(%d) = %d, APP(%d) = %d",
        GetRealPid(), rates[GetRealPid()], UNI_APP_PID, rates[UNI_APP_PID]);
    FRAME_TRACE::FrameRateReport::GetInstance().SendFrameRates(rates);
    FRAME_TRACE::FrameRateReport::GetInstance().SendFrameRatesToRss(rates);
    schedulePreferredFpsChange_ = false;
}

bool HgmFrameRateManager::CollectFrameRateChange(FrameRateRange finalRange,
                                                 std::shared_ptr<RSRenderFrameRateLinker> rsFrameRateLinker,
                                                 const FrameRateLinkerMap& appFrameRateLinkers)
{
    if (controller_ == nullptr) {
        HGM_LOGE("no valid controller, cannot work correctly, maybe Init() wasn't executed correctly.");
        return false;
    }
    bool frameRateChanged = false;
    bool controllerRateChanged = false;
    auto rsFrameRate = GetDrawingFrameRate(currRefreshRate_, finalRange);
    controllerRate_ = rsFrameRate > 0 ? rsFrameRate : controller_->GetCurrentRate();
    if (controllerRate_ != controller_->GetCurrentRate()) {
        rsFrameRateLinker->SetFrameRate(controllerRate_);
        controllerRateChanged = true;
        frameRateChanged = true;
    }

    auto& hgmCore = HgmCore::Instance();
    auto screenCurrentRefreshRate = hgmCore.GetScreenCurrentRefreshRate(hgmCore.GetActiveScreenId());
    RS_TRACE_NAME_FMT("CollectFrameRateChange refreshRate: %d, rsFrameRate: %d, finalRange = (%d, %d, %d)",
        screenCurrentRefreshRate, rsFrameRate, finalRange.min_, finalRange.max_, finalRange.preferred_);
    RS_TRACE_INT("PreferredFrameRate", static_cast<int>(finalRange.preferred_));

    appChangeData_.clear();
    for (auto linker : appFrameRateLinkers) {
        if (linker.second == nullptr) {
            continue;
        }
        auto expectedRange = linker.second->GetExpectedRange();
        HgmEnergyConsumptionPolicy::Instance().GetVideoCallFrameRate(
            ExtractPid(linker.first), linker.second->GetVsyncName(), expectedRange);
        CollectVRateChange(linker.first, expectedRange);
        auto appFrameRate = touchManager_.GetState() == TouchState::IDLE_STATE ?
                            GetDrawingFrameRate(currRefreshRate_, expectedRange) : OLED_NULL_HZ;
        if (appFrameRate != linker.second->GetFrameRate() || controllerRateChanged) {
            linker.second->SetFrameRate(appFrameRate);
            appChangeData_.emplace_back(linker.second->GetId(), appFrameRate);
            HGM_LOGD("HgmFrameRateManager: appChangeData linkerId = %{public}" PRIu64 ", %{public}d",
                linker.second->GetId(), appFrameRate);
            frameRateChanged = true;
        }
        if (expectedRange.min_ == OLED_NULL_HZ && expectedRange.preferred_ == OLED_NULL_HZ &&
            (expectedRange.max_ == OLED_144_HZ || expectedRange.max_ == OLED_NULL_HZ)) {
            continue;
        }
        RS_TRACE_NAME_FMT("HgmFrameRateManager::UniProcessData multiAppFrameRate: pid = %d, linkerId = %ld, "\
            "appFrameRate = %d, appRange = (%d, %d, %d)", ExtractPid(linker.first), linker.second->GetId(),
            appFrameRate, expectedRange.min_, expectedRange.max_, expectedRange.preferred_);
    }
    return frameRateChanged;
}

void HgmFrameRateManager::HandleFrameRateChangeForLTPO(uint64_t timestamp, bool followRs)
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
    int64_t delayTime = CreateVSyncGenerator()->SetCurrentRefreshRate(controllerRate_, lastRefreshRate);
    if (delayTime != 0) {
        int64_t controllerRate = controllerRate_;
        std::vector<std::pair<FrameRateLinkerId, uint32_t>> appChangeData = appChangeData_;
        bool needUpdate = isNeedUpdateAppOffset_;
        RSTaskMessage::RSTask task = [this, targetTime, controllerRate, appChangeData, needUpdate]() {
            if (controller_) {
                vsyncCountOfChangeGeneratorRate_ = controller_->ChangeGeneratorRate(controllerRate,
                    appChangeData, targetTime, needUpdate);
            }
            CreateVSyncGenerator()->SetCurrentRefreshRate(0, 0);
        };
        HgmTaskHandleThread::Instance().PostTask(task, delayTime);
    } else if (controller_) {
        vsyncCountOfChangeGeneratorRate_ = controller_->ChangeGeneratorRate(
            controllerRate_, appChangeData_, targetTime, isNeedUpdateAppOffset_);
    }
    // End of DVSync
    isNeedUpdateAppOffset_ = false;
    pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
    SetChangeGeneratorRateValid(false);
}

void HgmFrameRateManager::GetLowBrightVec(const std::shared_ptr<PolicyConfigData>& configData)
{
    isAmbientEffect_ = false;
    multiAppStrategy_.HandleLowAmbientStatus(isAmbientEffect_);
    if (!configData) {
        return;
    }

    // obtain the refresh rate supported in low ambient light
    if (configData->supportedModeConfigs_.find(curScreenStrategyId_) == configData->supportedModeConfigs_.end()) {
        return;
    }
    auto supportedModeConfig = configData->supportedModeConfigs_[curScreenStrategyId_];
    auto iter = supportedModeConfig.find(LOW_BRIGHT);
    if (iter == supportedModeConfig.end() || iter->second.empty()) {
        return;
    }
    auto supportRefreshRateVec = HgmCore::Instance().GetScreenSupportedRefreshRates(curScreenId_.load());
    lowBrightVec_.clear();
    for (auto rate : iter->second) {
        auto it = std::find(supportRefreshRateVec.begin(), supportRefreshRateVec.end(), rate);
        if (it != supportRefreshRateVec.end()) {
            lowBrightVec_.push_back(*it);
        }
    }

    if (lowBrightVec_.empty()) {
        return;
    }
    isAmbientEffect_ = true;
    multiAppStrategy_.HandleLowAmbientStatus(isAmbientEffect_);
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
    bool stylusFlag = (stylusMode_ == STYLUS_LINK_WRITE && !stylusVec_.empty());
    if ((isLtpo_ && isAmbientStatus_ == LightFactorStatus::NORMAL_LOW && isAmbientEffect_) ||
        (!isLtpo_ && isAmbientEffect_ && isAmbientStatus_ != LightFactorStatus::HIGH_LEVEL)) {
        supportRefreshRateVec = lowBrightVec_;
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
    auto iter = std::lower_bound(supportRefreshRateVec.begin(), supportRefreshRateVec.end(), range.preferred_);
    if (iter != supportRefreshRateVec.end()) {
        refreshRate = *iter;
        if (stylusFlag) {
            return refreshRate;
        }
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

uint32_t HgmFrameRateManager::GetDrawingFrameRate(const uint32_t refreshRate, const FrameRateRange& range)
{
    if (refreshRate == 0 || range.preferred_ <= 0) {
        return 0;
    }

    uint32_t preferredFps = static_cast<uint32_t>(range.preferred_);
    if (!range.IsValid() || preferredFps > refreshRate) {
        return refreshRate;
    }

    // find the smallest value in range of [preferredFps, refreshRate], which can exactly divide refreshRate
    uint32_t divisor = refreshRate / preferredFps;
    while (divisor > 1) {
        if (refreshRate % divisor == 0) {
            break;
        }
        divisor--;
    }
    return refreshRate / divisor;
}

void HgmFrameRateManager::Reset()
{
    controllerRate_ = 0;
    appChangeData_.clear();
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
    auto &configData = HgmCore::Instance().GetPolicyConfigData();
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
                "rate: %d", type.c_str(), velocityMM, areaSqrMM, lengthMM, iter->second.preferred_fps);
            return iter->second.preferred_fps;
        }
    }

    // it's not a small size animation or current small size config don't cover it, find result in normal config
    if (screenSetting.animationDynamicSettings.find(type) != screenSetting.animationDynamicSettings.end()) {
        auto& config = screenSetting.animationDynamicSettings[type];
        auto iter = std::find_if(config.begin(), config.end(), matchFunc);
        if (iter != config.end()) {
            RS_OPTIONAL_TRACE_NAME_FMT("GetPreferredFps: type: %s, speed: %f, area: %f, length: %f, rate: %d",
                type.c_str(), velocityMM, areaSqrMM, lengthMM, iter->second.preferred_fps);
            return iter->second.preferred_fps;
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
    HGM_LOGI("HandleLightFactorStatus status:%{public}d", state);
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
    HgmHfbcConfig::HandleHfbcConfig(packageList);
    if (multiAppStrategy_.HandlePkgsEvent(packageList) == EXEC_SUCCESS) {
        auto sceneListConfig = multiAppStrategy_.GetScreenSetting().sceneList;
        for (auto scenePid = sceneStack_.begin(); scenePid != sceneStack_.end();) {
            if (auto iter = sceneListConfig.find(scenePid->first);
                iter != sceneListConfig.end() && iter->second.doNotAutoClear) {
                ++scenePid;
                continue;
            }
            gameScenes_.erase(scenePid->first);
            ancoScenes_.erase(scenePid->first);
            scenePid = sceneStack_.erase(scenePid);
        }
    }
    MarkVoteChange("VOTER_SCENE");
    UpdateAppSupportedState();
}

void HgmFrameRateManager::HandleRefreshRateEvent(pid_t pid, const EventInfo& eventInfo)
{
    std::string eventName = eventInfo.eventName;
    if (eventName == "VOTER_VIDEO_CALL") {
        HgmEnergyConsumptionPolicy::Instance().SetVideoCallSceneInfo(eventInfo);
        return;
    }
    auto event = std::find(voters_.begin(), voters_.end(), eventName);
    if (event == voters_.end()) {
        HGM_LOGW("HgmFrameRateManager:unknown event, eventName is %{public}s", eventName.c_str());
        return;
    }

    HGM_LOGD("%{public}s(%{public}d) %{public}s", eventName.c_str(), pid, eventInfo.description.c_str());
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
    if (voterGamesEffective_ && touchManager_.GetState() == TouchState::DOWN_STATE) {
        return;
    }
    if (voterGamesEffective_ &&
        (touchStatus ==  TOUCH_MOVE || touchStatus ==  TOUCH_BUTTON_DOWN || touchStatus ==  TOUCH_BUTTON_UP)) {
        return;
    }
    HgmTaskHandleThread::Instance().PostTask([this, pid, touchStatus, touchCnt] () {
        if (touchStatus ==  TOUCH_MOVE || touchStatus ==  TOUCH_BUTTON_DOWN || touchStatus ==  TOUCH_BUTTON_UP) {
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
        if (auto iter = voteRecord_.find("VOTER_GAMES"); iter != voteRecord_.end() && !iter->second.first.empty() &&
            gameScenes_.empty() && multiAppStrategy_.CheckPidValid(iter->second.first.front().pid)) {
            HGM_LOGD("[touch manager] keep down in games");
            return;
        }
        if (touchCnt == LAST_TOUCH_CNT) {
            HGM_LOGD("[touch manager] up");
            touchManager_.HandleTouchEvent(TouchEvent::UP_EVENT, "");
        }
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
}

void HgmFrameRateManager::HandleDynamicModeEvent(bool enableDynamicModeEvent)
{
    HGM_LOGE("HandleDynamicModeEvent status:%{public}u", enableDynamicModeEvent);
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
    HGM_LOGI("HandleRefreshRateMode curMode:%{public}d", refreshRateMode);
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
    HGM_LOGI("curScreen:%{public}d status:%{public}d", static_cast<int>(id), static_cast<int>(status));
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
    if (configData == nullptr) {
        return;
    }

    if (configData->screenStrategyConfigs_.find(curScreenName) != configData->screenStrategyConfigs_.end()) {
        curScreenStrategyId_ = configData->screenStrategyConfigs_[curScreenName];
    } else {
        curScreenStrategyId_ = "LTPO-DEFAULT";
    }

    if (isEnableThermalStrategy_ && configData->screenConfigs_.find(
        curScreenStrategyId_ + HGM_CONFIG_TYPE_THERMAL_SUFFIX) != configData->screenConfigs_.end()) {
        curScreenStrategyId_ += HGM_CONFIG_TYPE_THERMAL_SUFFIX;
    }

    UpdateScreenFrameRate();
}

void HgmFrameRateManager::HandleThermalFrameRate(bool status)
{
    auto& hgmCore = HgmCore::Instance();
    auto configData = hgmCore.GetPolicyConfigData();
    if (configData == nullptr) {
        return;
    }

    if (isEnableThermalStrategy_ == status) {
        return;
    }
    isEnableThermalStrategy_ = status;
    std::string curScreenStrategyId;
    if (isEnableThermalStrategy_) {
        curScreenStrategyId = curScreenStrategyId_ + HGM_CONFIG_TYPE_THERMAL_SUFFIX;
    } else {
        curScreenStrategyId = curScreenStrategyId_.substr(
            0, curScreenStrategyId_.length() - std::string(HGM_CONFIG_TYPE_THERMAL_SUFFIX).length());
    }
    if (configData->screenConfigs_.find(curScreenStrategyId) == configData->screenConfigs_.end()) {
        HGM_LOGE("HgmFrameRateManager::HandleThermalFrameRate not support thermal config");
        return;
    }
    RS_TRACE_NAME_FMT("HgmFrameRateManager::HandleThermalFrameRate type:%s, status:%d", curScreenStrategyId.c_str(),
        status);
    curScreenStrategyId_ = curScreenStrategyId;
    UpdateScreenFrameRate();
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

void HgmFrameRateManager::HandleSceneEvent(pid_t pid, EventInfo eventInfo)
{
    std::string sceneName = eventInfo.description;
    auto screenSetting = multiAppStrategy_.GetScreenSetting();
    auto &gameSceneList = screenSetting.gameSceneList;
    auto &ancoSceneList = screenSetting.ancoSceneList;

    // control the list of supported frame rates for stylus pen, not control frame rate directly
    if (STYLUS_STATUS_MAP.find(sceneName) != STYLUS_STATUS_MAP.end()) {
        stylusMode_ = STYLUS_STATUS_MAP.at(sceneName);
        return;
    }

    if (gameSceneList.find(sceneName) != gameSceneList.end()) {
        if (eventInfo.eventStatus == ADD_VOTE) {
            if (gameScenes_.insert(sceneName).second) {
                MarkVoteChange();
            }
        } else {
            if (gameScenes_.erase(sceneName)) {
                MarkVoteChange();
            }
        }
    }
    if (ancoSceneList.find(sceneName) != ancoSceneList.end()) {
        if (eventInfo.eventStatus == ADD_VOTE) {
            if (ancoScenes_.insert(sceneName).second) {
                MarkVoteChange();
            }
        } else {
            if (ancoScenes_.erase(sceneName)) {
                MarkVoteChange();
            }
        }
    }

    std::pair<std::string, pid_t> info = std::make_pair(sceneName, pid);
    auto scenePos = find(sceneStack_.begin(), sceneStack_.end(), info);
    if (eventInfo.eventStatus == ADD_VOTE) {
        if (scenePos == sceneStack_.end()) {
            sceneStack_.push_back(info);
            MarkVoteChange("VOTER_SCENE");
        }
    } else {
        if (scenePos != sceneStack_.end()) {
            sceneStack_.erase(scenePos);
            MarkVoteChange("VOTER_SCENE");
        }
    }
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
        HGM_LOGE("unknow game pid: %{public}s, skip", eventInfo.description.c_str());
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
    if (auto iter = voteRecord_.find(voter);
        voter != "" && (iter == voteRecord_.end() || !iter->second.second) && !voterTouchEffective_) {
        return;
    }
    Reset();

    VoteInfo resultVoteInfo = ProcessRefreshRateVote();
    if (lastVoteInfo_ == resultVoteInfo) {
        if (!voterTouchEffective_) {
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
    if (refreshRate == currRefreshRate_ && isAmbientStatus_ < LightFactorStatus::LOW_LEVEL && !voterTouchEffective_) {
        return;
    }

    // changeGenerator only once in a single vsync period
    if (!changeGeneratorRateValid_.load()) {
        return;
    }
    bool needChangeDssRefreshRate = currRefreshRate_.load() != refreshRate;
    RS_TRACE_NAME_FMT("MarkVoteChange: %d %d", currRefreshRate_.load(), refreshRate);
    currRefreshRate_.store(refreshRate);
    schedulePreferredFpsChange_ = true;
    FrameRateReport();

    bool frameRateChanged = false;
    if (rsFrameRateLinker_ != nullptr) {
        frameRateChanged = CollectFrameRateChange(finalRange, rsFrameRateLinker_, appFrameRateLinkers_);
    }
    // 当dvsync在连续延迟切帧阶段，使用dvsync内记录的刷新率判断是否变化
    CreateVSyncGenerator()->DVSyncRateChanged(controllerRate_, frameRateChanged);
    auto& hgmCore = HgmCore::Instance();
    bool needForceUpdate = currRefreshRate_.load() != hgmCore.GetPendingScreenRefreshRate();
    if (hgmCore.GetLtpoEnabled() && frameRateChanged) {
        HandleFrameRateChangeForLTPO(timestamp_.load(), false);
        if (needChangeDssRefreshRate && changeDssRefreshRateCb_ != nullptr) {
            changeDssRefreshRateCb_(curScreenId_, refreshRate, true);
        }
    } else {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
        if (needChangeDssRefreshRate && changeDssRefreshRateCb_ != nullptr) {
            changeDssRefreshRateCb_(curScreenId_, refreshRate, true);
        }
    }
    ReportHiSysEvent(resultVoteInfo);
}

void HgmFrameRateManager::DeliverRefreshRateVote(const VoteInfo& voteInfo, bool eventStatus)
{
    RS_TRACE_NAME_FMT("Deliver voter:%s(pid:%d extInfo:%s), status:%u, value:[%d-%d]",
        voteInfo.voterName.c_str(), voteInfo.pid, voteInfo.extInfo.c_str(),
        eventStatus, voteInfo.min, voteInfo.max);
    if (voteInfo.min > voteInfo.max) {
        HGM_LOGW("HgmFrameRateManager:invalid vote %{public}s(%{public}d %{public}s):[%{public}d, %{public}d]",
            voteInfo.voterName.c_str(), voteInfo.pid, voteInfo.extInfo.c_str(), voteInfo.min, voteInfo.max);
        return;
    }

    voteRecord_.try_emplace(voteInfo.voterName, std::pair<std::vector<VoteInfo>, bool>({{}, true}));
    auto& vec = voteRecord_[voteInfo.voterName].first;

    auto voter = voteInfo.voterName != "VOTER_PACKAGES" ? voteInfo.voterName : "";

    // clear
    if ((voteInfo.pid == 0) && (eventStatus == REMOVE_VOTE)) {
        if (!vec.empty()) {
            vec.clear();
            MarkVoteChange(voter);
        }
        return;
    }

    for (auto it = vec.begin(); it != vec.end(); it++) {
        if ((*it).pid != voteInfo.pid) {
            continue;
        }

        if (eventStatus == REMOVE_VOTE) {
            // remove
            it = vec.erase(it);
            MarkVoteChange(voter);
            return;
        } else {
            if ((*it).min != voteInfo.min || (*it).max != voteInfo.max) {
                // modify
                vec.erase(it);
                vec.push_back(voteInfo);
                MarkVoteChange(voter);
            } else if (voteInfo.voterName == "VOTER_PACKAGES") {
                // force update cause VOTER_PACKAGES is flag of safe_voter
                MarkVoteChange(voter);
            }
            return;
        }
    }

    // add
    if (eventStatus == ADD_VOTE) {
        pidRecord_.insert(voteInfo.pid);
        vec.push_back(voteInfo);
        MarkVoteChange(voter);
    }
}

std::pair<bool, bool> HgmFrameRateManager::MergeRangeByPriority(VoteRange& rangeRes, const VoteRange& curVoteRange)
{
    auto &[min, max] = rangeRes;
    auto &[minTemp, maxTemp] = curVoteRange;
    bool needMergeVoteInfo = false;
    if (minTemp > min) {
        min = minTemp;
        if (min >= max) {
            min = max;
            return {true, needMergeVoteInfo};
        }
    }
    if (maxTemp < max) {
        max = maxTemp;
        needMergeVoteInfo = true;
        if (min >= max) {
            max = min;
            return {true, needMergeVoteInfo};
        }
    }
    if (min == max) {
        return {true, needMergeVoteInfo};
    }
    return {false, needMergeVoteInfo};
}

bool HgmFrameRateManager::MergeLtpo2IdleVote(
    std::vector<std::string>::iterator &voterIter, VoteInfo& resultVoteInfo, VoteRange &mergedVoteRange)
{
    bool mergeSuccess = false;
    // [VOTER_LTPO, VOTER_IDLE)
    for (; voterIter != voters_.end() - 1; voterIter++) {
        if (voteRecord_.find(*voterIter) == voteRecord_.end()) {
            continue;
        }
        voteRecord_[*voterIter].second = true;
        auto vec = voteRecord_[*voterIter].first;
        if (vec.empty()) {
            continue;
        }

        VoteInfo curVoteInfo = vec.back();
        if (!multiAppStrategy_.CheckPidValid(curVoteInfo.pid)) {
            ProcessVoteLog(curVoteInfo, true);
            continue;
        }
        if (curVoteInfo.voterName == "VOTER_VIDEO") {
            std::string voterPkgName = "";
            auto foregroundPidApp = multiAppStrategy_.GetForegroundPidApp();
            if (foregroundPidApp.find(curVoteInfo.pid) != foregroundPidApp.end()) {
                voterPkgName = foregroundPidApp[curVoteInfo.pid].second;
            } else if (auto pkgs = multiAppStrategy_.GetPackages(); !pkgs.empty()) { // Get the current package name
                voterPkgName = std::get<0>(HgmMultiAppStrategy::AnalyzePkgParam(pkgs.front()));
            }
            auto configData = HgmCore::Instance().GetPolicyConfigData();
            if (configData != nullptr &&
                configData->videoFrameRateList_.find(voterPkgName) == configData->videoFrameRateList_.end()) {
                ProcessVoteLog(curVoteInfo, true);
                continue;
            }
        }
        ProcessVoteLog(curVoteInfo, false);
        if (mergeSuccess) {
            mergedVoteRange.first = mergedVoteRange.first > curVoteInfo.min ? mergedVoteRange.first : curVoteInfo.min;
            if (curVoteInfo.max >= mergedVoteRange.second) {
                mergedVoteRange.second = curVoteInfo.max;
                resultVoteInfo.Merge(curVoteInfo);
            }
        } else {
            resultVoteInfo.Merge(curVoteInfo);
            mergedVoteRange = {curVoteInfo.min, curVoteInfo.max};
        }
        mergeSuccess = true;
    }
    return mergeSuccess;
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
    bool isAdaptiveSyncEnabled = HgmCore::Instance().GetAdaptiveSyncEnabled();

    if (isGameSupportAS_ != SupportASStatus::SUPPORT_AS) {
        isAdaptive_.store(isGameSupportAS_);
        return;
    }

    if (!isAdaptiveSyncEnabled) {
        return;
    }

    // VOTER_GAMES wins, enter adaptive vsync mode
    bool isGameVoter = voterName == "VOTER_GAMES";

    if ((isAdaptive_.load() == SupportASStatus::SUPPORT_AS && isGameVoter) ||
        (isAdaptive_.load() == SupportASStatus::NOT_SUPPORT && !isGameVoter)) {
        return;
    }

    if (isGameVoter && isGameSupportAS_ != SupportASStatus::SUPPORT_AS) {
        HGM_LOGI("this game does not support adaptive sync mode");
        return;
    }

    if (isGameVoter && !IsCurrentScreenSupportAS()) {
        HGM_LOGI("current screen not support adaptive sync mode");
        return;
    }

    HGM_LOGI("ProcessHgmFrameRate RSAdaptiveVsync change mode");
    RS_TRACE_BEGIN("ProcessHgmFrameRate RSAdaptiveVsync change mode");
    isAdaptive_.load() == SupportASStatus::NOT_SUPPORT ? isAdaptive_.store(SupportASStatus::SUPPORT_AS) :
        isAdaptive_.store(SupportASStatus::NOT_SUPPORT);
    RS_TRACE_END();
}

void HgmFrameRateManager::CheckAncoVoter(const std::string& voter, VoteInfo& curVoteInfo)
{
    if (voter == "VOTER_ANCO" && !ancoScenes_.empty()) {
        // Multiple scene are not considered at this time
        auto configData = HgmCore::Instance().GetPolicyConfigData();
        auto screenSetting = multiAppStrategy_.GetScreenSetting();
        auto ancoSceneIt = screenSetting.ancoSceneList.find(*ancoScenes_.begin());
        uint32_t min = OLED_60_HZ;
        uint32_t max = OLED_90_HZ;
        if (configData != nullptr && ancoSceneIt != screenSetting.ancoSceneList.end() &&
            configData->strategyConfigs_.find(ancoSceneIt->second.strategy) != configData->strategyConfigs_.end()) {
            min = static_cast<uint32_t>(configData->strategyConfigs_[ancoSceneIt->second.strategy].min);
            max = static_cast<uint32_t>(configData->strategyConfigs_[ancoSceneIt->second.strategy].max);
        }
        curVoteInfo.SetRange(min, max);
    }
}

bool HgmFrameRateManager::ProcessRefreshRateVote(std::vector<std::string>::iterator& voterIter,
    VoteInfo& resultVoteInfo, VoteRange& voteRange, bool &voterGamesEffective)
{
    VoteRange range;
    VoteInfo info;
    if (*voterIter == "VOTER_LTPO" && MergeLtpo2IdleVote(voterIter, info, range)) {
        auto [mergeVoteRange, mergeVoteInfo] = MergeRangeByPriority(voteRange, range);
        if (mergeVoteInfo) {
            resultVoteInfo.Merge(info);
        }
        if (mergeVoteRange) {
            return true;
        }
    }

    auto &voter = *voterIter;
    if (voteRecord_.find(voter) == voteRecord_.end()) {
        return false;
    }
    voteRecord_[voter].second = true;
    auto& voteInfos = voteRecord_[voter].first;
    auto firstValidVoteInfoIter = std::find_if(voteInfos.begin(), voteInfos.end(), [this] (auto& voteInfo) {
        if (!multiAppStrategy_.CheckPidValid(voteInfo.pid)) {
            ProcessVoteLog(voteInfo, true);
            return false;
        }
        return true;
    });
    if (firstValidVoteInfoIter == voteInfos.end()) {
        return false;
    }
    auto curVoteInfo = *firstValidVoteInfoIter;
    if (voter == "VOTER_GAMES") {
        if (!gameScenes_.empty() || !multiAppStrategy_.CheckPidValid(curVoteInfo.pid, true)) {
            ProcessVoteLog(curVoteInfo, true);
            return false;
        }
        voterGamesEffective = true;
    }
    CheckAncoVoter(voter, curVoteInfo);
    ProcessVoteLog(curVoteInfo, false);
    auto [mergeVoteRange, mergeVoteInfo] = MergeRangeByPriority(voteRange, {curVoteInfo.min, curVoteInfo.max});
    if (mergeVoteInfo) {
        resultVoteInfo.Merge(curVoteInfo);
    }
    if (mergeVoteRange) {
        return true;
    }
    return false;
}

VoteInfo HgmFrameRateManager::ProcessRefreshRateVote()
{
    UpdateVoteRule();

    VoteInfo resultVoteInfo;
    VoteRange voteRange = { OLED_MIN_HZ, OLED_MAX_HZ };
    auto &[min, max] = voteRange;

    bool voterGamesEffective = false;
    auto voterIter = voters_.begin();
    for (; voterIter != voters_.end(); ++voterIter) {
        if (ProcessRefreshRateVote(voterIter, resultVoteInfo, voteRange, voterGamesEffective)) {
            break;
        }
    }
    voterGamesEffective_ = voterGamesEffective;
    // update effective status
    if (voterIter != voters_.end()) {
        ++voterIter;
        for (; voterIter != voters_.end(); ++voterIter) {
            if (auto iter = voteRecord_.find(*voterIter); iter != voteRecord_.end()) {
                iter->second.second = false;
            }
        }
    }
    if (voteRecord_["VOTER_PACKAGES"].second || voteRecord_["VOTER_LTPO"].second) {
        voteRecord_["VOTER_SCENE"].second = true;
    }
    HGM_LOGD("Process: Strategy:%{public}s Screen:%{public}d Mode:%{public}d -- VoteResult:{%{public}d-%{public}d}",
        curScreenStrategyId_.c_str(), static_cast<int>(curScreenId_.load()), curRefreshRateMode_, min, max);
    SetResultVoteInfo(resultVoteInfo, min, max);
    ProcessAdaptiveSync(resultVoteInfo.voterName);
    return resultVoteInfo;
}

void HgmFrameRateManager::ChangePriority(uint32_t curScenePriority)
{
    // restore
    voters_ = std::vector<std::string>(std::begin(VOTER_NAME), std::end(VOTER_NAME));
    switch (curScenePriority) {
        case VOTER_SCENE_PRIORITY_BEFORE_PACKAGES: {
            auto scenePos1 = find(voters_.begin(), voters_.end(), "VOTER_SCENE");
            voters_.erase(scenePos1);
            auto packagesPos1 = find(voters_.begin(), voters_.end(), "VOTER_PACKAGES");
            voters_.insert(packagesPos1, "VOTER_SCENE");
            break;
        }
        case VOTER_LTPO_PRIORITY_BEFORE_PACKAGES: {
            auto scenePos2 = find(voters_.begin(), voters_.end(), "VOTER_SCENE");
            voters_.erase(scenePos2);
            auto packagesPos2 = find(voters_.begin(), voters_.end(), "VOTER_PACKAGES");
            voters_.insert(packagesPos2, "VOTER_SCENE");
            auto ltpoPos2 = find(voters_.begin(), voters_.end(), "VOTER_LTPO");
            voters_.erase(ltpoPos2);
            auto packagesPos3 = find(voters_.begin(), voters_.end(), "VOTER_PACKAGES");
            voters_.insert(packagesPos3, "VOTER_LTPO");
            break;
        }
        default:
            break;
    }
}

void HgmFrameRateManager::UpdateVoteRule()
{
    // restore
    ChangePriority(DEFAULT_PRIORITY);
    multiAppStrategy_.SetDisableSafeVoteValue(false);
    // dynamic priority for scene
    if (sceneStack_.empty()) {
        // no active scene
        DeliverRefreshRateVote({"VOTER_SCENE"}, REMOVE_VOTE);
        return;
    }
    auto configData = HgmCore::Instance().GetPolicyConfigData();
    if (configData == nullptr) {
        return;
    }
    if (configData->screenConfigs_.count(curScreenStrategyId_) == 0 ||
        configData->screenConfigs_[curScreenStrategyId_].count(std::to_string(curRefreshRateMode_)) == 0) {
        return;
    }
    auto curScreenSceneList =
        configData->screenConfigs_[curScreenStrategyId_][std::to_string(curRefreshRateMode_)].sceneList;
    if (curScreenSceneList.empty()) {
        // no scene configed in cur screen
        return;
    }

    std::string lastScene;
    auto scenePos = sceneStack_.rbegin();
    for (; scenePos != sceneStack_.rend(); scenePos++) {
        lastScene = (*scenePos).first;
        if (curScreenSceneList.count(lastScene) != 0) {
            break;
        }
    }
    if (scenePos == sceneStack_.rend()) {
        // no valid scene
        DeliverRefreshRateVote({"VOTER_SCENE"}, REMOVE_VOTE);
        return;
    }
    auto curSceneConfig = curScreenSceneList[lastScene];
    if (!XMLParser::IsNumber(curSceneConfig.priority) ||
        configData->strategyConfigs_.find(curSceneConfig.strategy) == configData->strategyConfigs_.end()) {
        return;
    }
    uint32_t curScenePriority = static_cast<uint32_t>(std::stoi(curSceneConfig.priority));
    uint32_t min = static_cast<uint32_t>(configData->strategyConfigs_[curSceneConfig.strategy].min);
    uint32_t max = static_cast<uint32_t>(configData->strategyConfigs_[curSceneConfig.strategy].max);
    HGM_LOGD("UpdateVoteRule: SceneName:%{public}s", lastScene.c_str());
    DeliverRefreshRateVote({"VOTER_SCENE", min, max, (*scenePos).second, lastScene}, ADD_VOTE);

    ChangePriority(curScenePriority);
    multiAppStrategy_.SetDisableSafeVoteValue(curSceneConfig.disableSafeVote);
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
                case CleanPidCallbackType::APP_STRATEGY_CONFIG_EVENT:
                    HandleAppStrategyConfigEvent(DEFAULT_PID, "", {});
                    break;
                case CleanPidCallbackType::PAGE_URL:
                    CleanPageUrlVote(pid);
                    break;
                default:
                    break;
            }
        }
        iter->second.clear();
    }

    if (pidRecord_.count(pid) == 0) {
        return;
    }
    HGM_LOGW("CleanVote: i am [%{public}d], i died, clean my votes please.", pid);
    pidRecord_.erase(pid);

    for (auto& [voterName, voterInfo] : voteRecord_) {
        for (auto iter = voterInfo.first.begin(); iter != voterInfo.first.end();) {
            if (iter->pid == pid) {
                auto voter = iter->voterName;
                iter = voterInfo.first.erase(iter);
                MarkVoteChange(voter);
                break;
            } else {
                ++iter;
            }
        }
    }
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

void HgmFrameRateManager::ProcessVoteLog(const VoteInfo& curVoteInfo, bool isSkip)
{
    RS_TRACE_NAME_FMT("Process voter:%s(pid:%d), value:[%d-%d]%s",
        curVoteInfo.voterName.c_str(), curVoteInfo.pid, curVoteInfo.min, curVoteInfo.max, isSkip ? " skip" : "");
    HGM_LOGD("Process: %{public}s(%{public}d):[%{public}d, %{public}d]%{public}s",
        curVoteInfo.voterName.c_str(), curVoteInfo.pid, curVoteInfo.min, curVoteInfo.max, isSkip ? " skip" : "");
}

bool HgmFrameRateManager::UpdateUIFrameworkDirtyNodes(
    std::vector<std::weak_ptr<RSRenderNode>>& uiFwkDirtyNodes, uint64_t timestamp)
{
    timestamp_ = timestamp;
    HgmEnergyConsumptionPolicy::Instance().CheckOnlyVideoCallExist();
    if (!voterTouchEffective_ || voterGamesEffective_) {
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
                                              surfaceData = surfaceData_] () {
        for (const auto &[surfaceName, pid, uiFwkType] : surfaceData) {
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

void HgmFrameRateManager::HandleGameNode(const RSRenderNodeMap& nodeMap)
{
    bool isGameSelfNodeOnTree = false;
    std::string gameNodeName = GetGameNodeName();
    nodeMap.TraverseSurfaceNodes(
        [this, &isGameSelfNodeOnTree, &gameNodeName]
        (const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode) mutable {
            if (surfaceNode->IsOnTheTree() && gameNodeName == surfaceNode->GetName()) {
                isGameSelfNodeOnTree = true;
            }
        }
    );
    RS_TRACE_NAME_FMT("HgmFrameRateManager::HandleGameNode, game node on tree: %d", isGameSelfNodeOnTree);
    isGameNodeOnTree_.store(isGameSelfNodeOnTree);
}

void HgmFrameRateManager::HandleAppStrategyConfigEvent(pid_t pid, const std::string& pkgName,
    const std::vector<std::pair<std::string, std::string>>& newConfig)
{
    if (pid != DEFAULT_PID) {
        cleanPidCallback_[pid].insert(CleanPidCallbackType::APP_STRATEGY_CONFIG_EVENT);
    }
    multiAppStrategy_.SetAppStrategyConfig(pkgName, newConfig);
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

void HgmFrameRateManager::NotifyPageName(pid_t pid, const std::string &packageName,
    const std::string &pageName, bool isEnter)
{
    auto screenSetting = multiAppStrategy_.GetScreenSetting();
    appPageUrlStrategy_.SetPageUrlConfig(screenSetting.pageUrlConfig);
    appPageUrlStrategy_.NotifyPageName(pid, packageName, pageName, isEnter);
}

void HgmFrameRateManager::CheckRefreshRateChange(bool followRs, bool frameRateChanged, uint32_t refreshRate)
{
    bool needChangeDssRefreshRate = currRefreshRate_.load() != refreshRate;
    // 当dvsync在连续延迟切帧阶段，使用dvsync内记录的刷新率判断是否变化
    CreateVSyncGenerator()->DVSyncRateChanged(controllerRate_, frameRateChanged);
    if (HgmCore::Instance().GetLtpoEnabled() && frameRateChanged) {
        HandleFrameRateChangeForLTPO(timestamp_.load(), followRs);
        if (needChangeDssRefreshRate && changeDssRefreshRateCb_ != nullptr) {
            changeDssRefreshRateCb_(curScreenId_.load(), refreshRate, true);
        }
    } else {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
        if (needChangeDssRefreshRate && changeDssRefreshRateCb_ != nullptr) {
            changeDssRefreshRateCb_(curScreenId_.load(), refreshRate, true);
        }
    }
}
} // namespace Rosen
} // namespace OHOS

