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
#include "hgm_log.h"
#include "parameters.h"
#include "rs_trace.h"
#include "sandbox_utils.h"
#include "frame_rate_report.h"
#include "hgm_config_callback_manager.h"
#include "hisysevent.h"

namespace OHOS {
namespace Rosen {
namespace {
    constexpr float MARGIN = 0.00001;
    constexpr float MIN_DRAWING_DIVISOR = 10.0f;
    constexpr float DIVISOR_TWO = 2.0f;
    constexpr int32_t IDLE_TIMER_EXPIRED = 200; // ms
    constexpr uint32_t UNI_RENDER_VSYNC_OFFSET = 5000000; // ns
    constexpr uint32_t REPORT_VOTER_INFO_LIMIT = 20;
    constexpr int32_t LAST_TOUCH_CNT = 1;

    constexpr uint32_t FIRST_FRAME_TIME_OUT = 100; // 100ms
    constexpr uint32_t SCENE_BEFORE_XML = 1;
    constexpr uint32_t SCENE_AFTER_TOUCH = 3;
    constexpr uint64_t ENERGY_ASSURANCE_TASK_DELAY_TIME = 1000; //1s
    constexpr uint64_t UI_ENERGY_ASSURANCE_TASK_DELAY_TIME = 3000; // 3s
    const static std::string ENERGY_ASSURANCE_TASK_ID = "ENERGY_ASSURANCE_TASK_ID";
    const static std::string UI_ENERGY_ASSURANCE_TASK_ID = "UI_ENERGY_ASSURANCE_TASK_ID";
    const static std::string UP_TIME_OUT_TASK_ID = "UP_TIME_OUT_TASK_ID";
    // CAUTION: with priority
    const std::string VOTER_NAME[] = {
        "VOTER_THERMAL",
        "VOTER_VIRTUALDISPLAY",
        "VOTER_POWER_MODE",
        "VOTER_DISPLAY_ENGIN",
        "VOTER_GAMES",
        "VOTER_ANCO",

        "VOTER_PACKAGES",
        "VOTER_LTPO",
        "VOTER_SCENE",
        "VOTER_VIDEO",
        "VOTER_IDLE"
    };
}

void HgmFrameRateManager::Init(sptr<VSyncController> rsController,
    sptr<VSyncController> appController, sptr<VSyncGenerator> vsyncGenerator)
{
    voters_ = std::vector<std::string>(std::begin(VOTER_NAME), std::end(VOTER_NAME));
    auto& hgmCore = HgmCore::Instance();
    curRefreshRateMode_ = hgmCore.GetCurrentRefreshRateMode();
    multiAppStrategy_.UpdateXmlConfigCache();
    UpdateEnergyConsumptionConfig();

    // hgm warning: get non active screenId in non-folding devices（from sceneboard）
    auto screenList = hgmCore.GetScreenIds();
    curScreenId_ = screenList.empty() ? 0 : screenList.front();
    isLtpo_ = (GetScreenType(curScreenId_) == "LTPO");
    std::string curScreenName = "screen" + std::to_string(curScreenId_) + "_" + (isLtpo_ ? "LTPO" : "LTPS");
    auto configData = hgmCore.GetPolicyConfigData();
    if (configData != nullptr) {
        curScreenStrategyId_ = configData->screenStrategyConfigs_[curScreenName];
        idleDetector_.UpdateSupportAppBufferList(configData->appBufferList_);
        if (curScreenStrategyId_.empty()) {
            curScreenStrategyId_ = "LTPO-DEFAULT";
        }
        if (curRefreshRateMode_ != HGM_REFRESHRATE_MODE_AUTO && configData->xmlCompatibleMode_) {
            curRefreshRateMode_ = configData->SettingModeId2XmlModeId(curRefreshRateMode_);
        }
        multiAppStrategy_.UpdateXmlConfigCache();
        UpdateEnergyConsumptionConfig();
        multiAppStrategy_.CalcVote();
        HandleIdleEvent(ADD_VOTE);
    }

    hgmCore.RegisterRefreshRateModeChangeCallback([rsController, appController](int32_t mode) {
        if (HgmCore::Instance().IsLTPOSwitchOn()) {
            rsController->SetPhaseOffset(0);
            appController->SetPhaseOffset(0);
            CreateVSyncGenerator()->SetVSyncMode(VSYNC_MODE_LTPO);
        } else {
            if (RSUniRenderJudgement::IsUniRender()) {
                rsController->SetPhaseOffset(UNI_RENDER_VSYNC_OFFSET);
                appController->SetPhaseOffset(UNI_RENDER_VSYNC_OFFSET);
            }
            CreateVSyncGenerator()->SetVSyncMode(VSYNC_MODE_LTPS);
        }
    });

    hgmCore.RegisterRefreshRateUpdateCallback([](int32_t refreshRate) {
        HgmConfigCallbackManager::GetInstance()->SyncRefreshRateUpdateCallback(refreshRate);
    });

    controller_ = std::make_shared<HgmVSyncGeneratorController>(rsController, appController, vsyncGenerator);

    multiAppStrategy_.RegisterStrategyChangeCallback([this] (const PolicyConfigData::StrategyConfig& strategy) {
        DeliverRefreshRateVote({"VOTER_PACKAGES", strategy.min, strategy.max}, ADD_VOTE);
        idleFps_ = std::max(strategy.min, static_cast<int32_t>(OLED_60_HZ));
        HandleIdleEvent(true);
    });
    InitTouchManager();
    multiAppStrategy_.CalcVote();
}

void HgmFrameRateManager::InitTouchManager()
{
    static std::once_flag createFlag;
    std::call_once(createFlag, [this]() {
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
            [this] (TouchState lastState, TouchState newState) {
            if (lastState == TouchState::IDLE_STATE) {
                HgmMultiAppStrategy::TouchInfo touchInfo = {
                    .pkgName = touchManager_.GetPkgName(),
                    .touchState = newState,
                    .upExpectFps = OLED_120_HZ,
                };
                multiAppStrategy_.HandleTouchInfo(touchInfo);
            }
            startCheck_.store(false);
        });
        touchManager_.RegisterEnterStateCallback(TouchState::IDLE_STATE,
            [this] (TouchState lastState, TouchState newState) {
            startCheck_.store(false);
            HgmMultiAppStrategy::TouchInfo touchInfo = {
                .pkgName = touchManager_.GetPkgName(),
                .touchState = newState,
            };
            multiAppStrategy_.HandleTouchInfo(touchInfo);
        });
        touchManager_.RegisterEnterStateCallback(TouchState::UP_STATE,
            [this] (TouchState lastState, TouchState newState) {
            HgmTaskHandleThread::Instance().PostEvent(UP_TIME_OUT_TASK_ID, [this] () { startCheck_.store(true); },
                FIRST_FRAME_TIME_OUT);
        });
        touchManager_.RegisterExitStateCallback(TouchState::UP_STATE,
            [this] (TouchState lastState, TouchState newState) {
            HgmTaskHandleThread::Instance().RemoveEvent(UP_TIME_OUT_TASK_ID);
            startCheck_.store(false);
        });
    });
}

void HgmFrameRateManager::ProcessPendingRefreshRate(uint64_t timestamp, uint32_t rsRate, const DvsyncInfo& dvsyncInfo)
{
    auto &hgmCore = HgmCore::Instance();
    hgmCore.SetTimestamp(timestamp);
    if (pendingRefreshRate_ != nullptr) {
        hgmCore.SetPendingConstraintRelativeTime(pendingConstraintRelativeTime_);
        hgmCore.SetPendingScreenRefreshRate(*pendingRefreshRate_);
        RS_TRACE_NAME_FMT("ProcessHgmFrameRate pendingRefreshRate: %d", *pendingRefreshRate_);
        pendingRefreshRate_.reset();
        pendingConstraintRelativeTime_ = 0;
    }
    if (curRefreshRateMode_ == HGM_REFRESHRATE_MODE_AUTO &&
        dvsyncInfo.isUiDvsyncOn && GetCurScreenStrategyId().find("LTPO") != std::string::npos) {
        RS_TRACE_NAME_FMT("ProcessHgmFrameRate pendingRefreshRate: %d ui-dvsync", rsRate);
        hgmCore.SetPendingScreenRefreshRate(rsRate);
    }
}

void HgmFrameRateManager::UpdateSurfaceTime(const std::string& surfaceName, uint64_t timestamp,
    pid_t pid, UIFWKType uiFwkType)
{
    idleDetector_.UpdateSurfaceTime(surfaceName, timestamp, pid, uiFwkType);
}

void HgmFrameRateManager::ProcessUnknownUIFwkIdleState(const std::unordered_map<NodeId,
    std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>>>& activeNodesInRoot, uint64_t timestamp)
{
    idleDetector_.ProcessUnknownUIFwkIdleState(activeNodesInRoot, timestamp);
}
void HgmFrameRateManager::UpdateAppSupportedState()
{
    bool appNeedHighRefresh = false;
    idleDetector_.ClearAppBufferList();
    idleDetector_.ClearAppBufferBlackList();
    PolicyConfigData::StrategyConfig config;
    if (multiAppStrategy_.GetFocusAppStrategyConfig(config) == EXEC_SUCCESS) {
        if (config.dynamicMode == DynamicModeType::TOUCH_EXT_ENABLED) {
            appNeedHighRefresh = true;
        }
    }
    idleDetector_.UpdateAppBufferList(config.appBufferList);
    idleDetector_.UpdateAppBufferBlackList(config.appBufferBlackList);
    idleDetector_.SetAppSupportedState(appNeedHighRefresh);
}

void HgmFrameRateManager::SetAceAnimatorVote(const std::shared_ptr<RSRenderFrameRateLinker>& linker,
    bool& needCheckAceAnimatorStatus)
{
    if (!needCheckAceAnimatorStatus || linker == nullptr) {
        return;
    }
    if (linker->GetAceAnimatorExpectedFrameRate() >= 0) {
        needCheckAceAnimatorStatus = false;
        RS_TRACE_NAME_FMT("SetAceAnimatorVote PID = [%d]  linkerId = [%" PRIu64 "]  SetAceAnimatorIdleState[false] "
            "AnimatorExpectedFrameRate = [%d]", ExtractPid(linker->GetId()), linker->GetId(),
            linker->GetAceAnimatorExpectedFrameRate());
        idleDetector_.SetAceAnimatorIdleState(false);
        return;
    }
    RS_OPTIONAL_TRACE_NAME_FMT("SetAceAnimatorVote PID = [%d]  linkerId = [%" PRIu64 "] "
        "SetAceAnimatorIdleState[true] AnimatorExpectedFrameRate = [%d]", ExtractPid(linker->GetId()),
        linker->GetId(), linker->GetAceAnimatorExpectedFrameRate());
    idleDetector_.SetAceAnimatorIdleState(true);
}

void HgmFrameRateManager::UpdateGuaranteedPlanVote(uint64_t timestamp)
{
    if (!idleDetector_.GetAppSupportedState()) {
        return;
    }
    RS_TRACE_NAME_FMT("HgmFrameRateManager:: TouchState = [%d]  SurfaceIdleState = [%d]  AceAnimatorIdleState = [%d]",
        touchManager_.GetState(), idleDetector_.GetSurfaceIdleState(timestamp),
        idleDetector_.GetAceAnimatorIdleState());

    // After touch up, wait FIRST_FRAME_TIME_OUT ms
    if (!startCheck_.load() || touchManager_.GetState() == TouchState::IDLE_STATE) {
        needHighRefresh_ = false;
        lastTouchUpExpectFps_ = 0;
        return;
    }

    // Check if third framework need high refresh
    if (!needHighRefresh_) {
        needHighRefresh_ = true;
        if (!idleDetector_.ThirdFrameNeedHighRefresh()) {
            touchManager_.HandleThirdFrameIdle();
            return;
        }
    }

    //Third frame need high refresh vote
    if (idleDetector_.GetSurfaceIdleState(timestamp) && idleDetector_.GetAceAnimatorIdleState()) {
        RS_TRACE_NAME_FMT("UpdateGuaranteedPlanVote:: Surface And Animator Idle, Vote Idle");
        touchManager_.HandleThirdFrameIdle();
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

void HgmFrameRateManager::ProcessLtpoVote(const FrameRateRange& finalRange, bool idleTimerExpired)
{
    if (finalRange.IsValid()) {
        ResetScreenTimer(curScreenId_);
        CalcRefreshRate(curScreenId_, finalRange);
        DeliverRefreshRateVote(
            {"VOTER_LTPO", currRefreshRate_, currRefreshRate_, DEFAULT_PID, finalRange.GetExtInfo()}, ADD_VOTE);
    } else if (idleTimerExpired) {
        // idle in ltpo
        HandleIdleEvent(ADD_VOTE);
        DeliverRefreshRateVote({"VOTER_LTPO"}, REMOVE_VOTE);
    } else {
        StartScreenTimer(curScreenId_, IDLE_TIMER_EXPIRED, nullptr, [this]() {
            if (forceUpdateCallback_ != nullptr) {
                forceUpdateCallback_(true, false);
            }
        });
    }
}

void HgmFrameRateManager::UniProcessDataForLtpo(uint64_t timestamp,
                                                std::shared_ptr<RSRenderFrameRateLinker> rsFrameRateLinker,
                                                const FrameRateLinkerMap& appFrameRateLinkers, bool idleTimerExpired,
                                                const DvsyncInfo& dvsyncInfo)
{
    RS_TRACE_FUNC();
    Reset();

    auto& hgmCore = HgmCore::Instance();
    FrameRateRange finalRange;
    if (curRefreshRateMode_ == HGM_REFRESHRATE_MODE_AUTO) {
        finalRange = rsFrameRateLinker->GetExpectedRange();
        bool needCheckAceAnimatorStatus = true;
        for (auto linker : appFrameRateLinkers) {
            if (!multiAppStrategy_.CheckPidValid(ExtractPid(linker.first))) {
                continue;
            }
            SetAceAnimatorVote(linker.second, needCheckAceAnimatorStatus);
            auto expectedRange = linker.second->GetExpectedRange();
            HgmEnergyConsumptionPolicy::Instance().GetUiIdleFps(expectedRange);
            finalRange.Merge(expectedRange);
        }
        ProcessLtpoVote(finalRange, idleTimerExpired);
    }

    UpdateGuaranteedPlanVote(timestamp);
    VoteInfo resultVoteInfo = ProcessRefreshRateVote();
    // max used here
    finalRange = {resultVoteInfo.max, resultVoteInfo.max, resultVoteInfo.max};
    CalcRefreshRate(curScreenId_, finalRange);

    bool frameRateChanged = CollectFrameRateChange(finalRange, rsFrameRateLinker, appFrameRateLinkers);
    if (hgmCore.GetLtpoEnabled() && frameRateChanged) {
        HandleFrameRateChangeForLTPO(timestamp);
    } else {
        pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
        if (currRefreshRate_ != hgmCore.GetPendingScreenRefreshRate()) {
            if (forceUpdateCallback_ != nullptr) {
                forceUpdateCallback_(false, true);
            }
            schedulePreferredFpsChange_ = true;
        }
        FrameRateReport();
    }
    ReportHiSysEvent(resultVoteInfo);
    lastVoteInfo_ = resultVoteInfo;
}

void HgmFrameRateManager::ReportHiSysEvent(const VoteInfo& frameRateVoteInfo)
{
    if (frameRateVoteInfo.voterName.empty()) {
        return;
    }
    std::lock_guard<std::mutex> locker(frameRateVoteInfoMutex_);
    bool needAdd = frameRateVoteInfoVec_.empty() || frameRateVoteInfoVec_.back().second != frameRateVoteInfo;
    if (frameRateVoteInfoVec_.size() >= REPORT_VOTER_INFO_LIMIT) {
        std::string msg;
        for (auto& [timestamp, voteInfo] : frameRateVoteInfoVec_) {
            msg += voteInfo.ToString(timestamp);
        }
        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC, "HGM_VOTER_INFO",
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, "MSG", msg);
        frameRateVoteInfoVec_.clear();
    }
    if (needAdd) {
        auto currentTime = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now()).time_since_epoch().count();
        frameRateVoteInfoVec_.push_back({currentTime, frameRateVoteInfo});
        HGM_LOGD("ReportHiSysEvent: %{public}s", frameRateVoteInfo.ToString(currentTime).c_str());
    }
}

void HgmFrameRateManager::UniProcessDataForLtps(bool idleTimerExpired)
{
    RS_TRACE_FUNC();
    Reset();

    if (idleTimerExpired) {
        // idle in ltps
        HandleIdleEvent(ADD_VOTE);
    } else {
        StartScreenTimer(curScreenId_, IDLE_TIMER_EXPIRED, nullptr, [this]() {
            if (forceUpdateCallback_ != nullptr) {
                forceUpdateCallback_(true, false);
            }
        });
    }

    FrameRateRange finalRange;
    VoteInfo resultVoteInfo = ProcessRefreshRateVote();
    auto& hgmCore = HgmCore::Instance();
    // max used here
    finalRange = {resultVoteInfo.max, resultVoteInfo.max, resultVoteInfo.max};
    CalcRefreshRate(curScreenId_, finalRange);
    RS_TRACE_INT("PreferredFrameRate", static_cast<int>(currRefreshRate_));
    pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
    if (currRefreshRate_ != hgmCore.GetPendingScreenRefreshRate()) {
        if (forceUpdateCallback_ != nullptr) {
            forceUpdateCallback_(false, true);
        }
        schedulePreferredFpsChange_ = true;
    }
    FrameRateReport();
    ReportHiSysEvent(resultVoteInfo);
    lastVoteInfo_ = resultVoteInfo;
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
    } else {
        rates[UNI_APP_PID] = schedulePreferredFps_;
    }
    HGM_LOGD("FrameRateReport: RS(%{public}d) = %{public}d, APP(%{public}d) = %{public}d",
        GetRealPid(), rates[GetRealPid()], UNI_APP_PID, rates[UNI_APP_PID]);
    FRAME_TRACE::FrameRateReport::GetInstance().SendFrameRates(rates);
    FRAME_TRACE::FrameRateReport::GetInstance().SendFrameRatesToRss(rates);
    schedulePreferredFpsChange_ = false;
}

bool HgmFrameRateManager::CollectFrameRateChange(FrameRateRange finalRange,
                                                 std::shared_ptr<RSRenderFrameRateLinker> rsFrameRateLinker,
                                                 const FrameRateLinkerMap& appFrameRateLinkers)
{
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

    for (auto linker : appFrameRateLinkers) {
        const auto& expectedRange = linker.second->GetExpectedRange();
        auto appFrameRate = GetDrawingFrameRate(currRefreshRate_, expectedRange);
        if (touchManager_.GetState() != TouchState::IDLE_STATE) {
            appFrameRate = OLED_NULL_HZ;
        }
        if (appFrameRate != linker.second->GetFrameRate() || controllerRateChanged) {
            linker.second->SetFrameRate(appFrameRate);
            std::lock_guard<std::mutex> lock(appChangeDataMutex_);
            appChangeData_.emplace_back(linker.second->GetId(), appFrameRate);
            HGM_LOGD("HgmFrameRateManager: appChangeData linkerId = %{public}" PRIu64 ", %{public}d",
                linker.second->GetId(), appFrameRate);
            frameRateChanged = true;
        }
        if (expectedRange.min_ == OLED_NULL_HZ && expectedRange.max_ == OLED_144_HZ &&
            expectedRange.preferred_ == OLED_NULL_HZ) {
            continue;
        }
        RS_TRACE_NAME_FMT("HgmFrameRateManager::UniProcessData multiAppFrameRate: pid = %d, linkerId = %ld, "\
            "appFrameRate = %d, appRange = (%d, %d, %d)", ExtractPid(linker.first), linker.second->GetId(),
            appFrameRate, expectedRange.min_, expectedRange.max_, expectedRange.preferred_);
    }
    return frameRateChanged;
}

void HgmFrameRateManager::HandleFrameRateChangeForLTPO(uint64_t timestamp)
{
    auto& hgmCore = HgmCore::Instance();
    auto lastRefreshRate = hgmCore.GetPendingScreenRefreshRate();
    uint64_t targetTime = 0;
    // low refresh rate switch to high refresh rate immediately.
    if (lastRefreshRate < OLED_60_HZ && currRefreshRate_ > lastRefreshRate) {
        hgmCore.SetPendingScreenRefreshRate(currRefreshRate_);
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
    }

    RSTaskMessage::RSTask task = [this, lastRefreshRate, targetTime]() {
        std::lock_guard<std::mutex> lock(appChangeDataMutex_);
        controller_->ChangeGeneratorRate(controllerRate_, appChangeData_, targetTime, isNeedUpdateAppOffset_);
        isNeedUpdateAppOffset_ = false;
        pendingRefreshRate_ = std::make_shared<uint32_t>(currRefreshRate_);
        if (currRefreshRate_ != lastRefreshRate) {
            if (forceUpdateCallback_ != nullptr) {
                forceUpdateCallback_(false, true);
            }
            schedulePreferredFpsChange_ = true;
        }
        FrameRateReport();
    };
    HgmTaskHandleThread::Instance().PostTask(task);
}

void HgmFrameRateManager::CalcRefreshRate(const ScreenId id, const FrameRateRange& range)
{
    // Find current refreshRate by FrameRateRange. For example:
    // 1. FrameRateRange[min, max, preferred] is [24, 48, 48], supported refreshRates
    // of current screen are {30, 60, 90}, the result should be 30, not 60.
    // 2. FrameRateRange[min, max, preferred] is [150, 150, 150], supported refreshRates
    // of current screen are {30, 60, 90}, the result will be 90.
    auto supportRefreshRateVec = HgmCore::Instance().GetScreenSupportedRefreshRates(id);
    if (supportRefreshRateVec.empty()) {
        return;
    }
    std::sort(supportRefreshRateVec.begin(), supportRefreshRateVec.end());
    auto iter = std::lower_bound(supportRefreshRateVec.begin(), supportRefreshRateVec.end(), range.preferred_);
    if (iter != supportRefreshRateVec.end()) {
        currRefreshRate_ = *iter;
        if (currRefreshRate_ > static_cast<uint32_t>(range.max_) &&
            (iter - supportRefreshRateVec.begin()) > 0) {
            iter--;
            if (*iter >= static_cast<uint32_t>(range.min_) &&
                *iter <= static_cast<uint32_t>(range.max_)) {
                currRefreshRate_ = *iter;
            }
        }
    } else {
        currRefreshRate_ = supportRefreshRateVec.back();
    }
}

uint32_t HgmFrameRateManager::GetDrawingFrameRate(const uint32_t refreshRate, const FrameRateRange& range)
{
    // We will find a drawing fps, which is divisible by refreshRate.
    // If the refreshRate is 60, the options of drawing fps are 60, 30, 15, 12, etc.
    // 1. The preferred fps is divisible by refreshRate.
    const float currRefreshRate = static_cast<float>(refreshRate);
    const float preferredFps = static_cast<float>(range.preferred_);
    if (preferredFps < MARGIN || currRefreshRate < MARGIN) {
        return 0;
    }
    if (std::fmodf(currRefreshRate, range.preferred_) < MARGIN) {
        return static_cast<uint32_t>(preferredFps);
    }
    // 2. FrameRateRange is not dynamic, we will find the closest drawing fps to preferredFps.
    // e.g. If the FrameRateRange of a surfaceNode is [50, 50, 50], the refreshRate is
    // 90, the drawing fps of the surfaceNode should be 45.
    if (!range.IsDynamic()) {
        return static_cast<uint32_t>(currRefreshRate / std::round(refreshRate / preferredFps));
    }
    // 3. FrameRateRange is dynamic. We will find a divisible result in the range if possible.
    // If several divisible options are in the range, the smoother, the better.
    // The KPI of "smooth" is the ratio of lack.
    // e.g. The preferred fps is 58, the refreshRate is 60. When the drawing fps is 60,
    // we lack the least(the ratio is 2/60).
    // The preferred fps is 34, the refreshRate is 60, the drawing fps will be 30(the ratio is 4/30).
    int divisor = 1;
    float drawingFps = currRefreshRate;
    float dividedFps = currRefreshRate;
    float currRatio = std::abs(dividedFps - preferredFps) / preferredFps;
    float ratio = currRatio;
    const float minDrawingFps = currRefreshRate / MIN_DRAWING_DIVISOR;
    while (dividedFps > minDrawingFps - MARGIN) {
        if (dividedFps < range.min_ || dividedFps <= static_cast<float>(range.preferred_) / DIVISOR_TWO) {
            break;
        }
        if (dividedFps > range.max_) {
            divisor++;
            float preDividedFps = dividedFps;
            dividedFps = currRefreshRate / static_cast<float>(divisor);
            // If we cannot find a divisible result, the closer to the preferred, the better.
            // e.g.FrameRateRange is [50, 80, 80], refreshrate is
            // 90, the drawing frame rate is 90.
            if (dividedFps < range.min_ && (preferredFps - dividedFps) > (preDividedFps - preferredFps)) {
                drawingFps = preDividedFps;
                break;
            }
            currRatio = std::abs(dividedFps - preferredFps) / preferredFps;
            if (currRatio < ratio) {
                ratio = currRatio;
                drawingFps = dividedFps;
            }
            continue;
        }
        currRatio = std::min(std::fmodf(preferredFps, dividedFps),
            std::fmodf(std::abs(dividedFps - preferredFps), dividedFps)) / dividedFps;
        // When currRatio is almost zero, dividedFps is the perfect result
        if (currRatio < MARGIN) {
            drawingFps = dividedFps;
            break;
        }
        if (currRatio < ratio) {
            ratio = currRatio;
            drawingFps = dividedFps;
        }
        divisor++;
        dividedFps = currRefreshRate / static_cast<float>(divisor);
    }
    return static_cast<uint32_t>(std::round(drawingFps));
}

std::shared_ptr<uint32_t> HgmFrameRateManager::GetPendingRefreshRate()
{
    return pendingRefreshRate_;
}

void HgmFrameRateManager::ResetPendingRefreshRate()
{
    pendingRefreshRate_.reset();
}

void HgmFrameRateManager::Reset()
{
    currRefreshRate_ = 0;
    controllerRate_ = 0;
    pendingConstraintRelativeTime_ = 0;
    pendingRefreshRate_.reset();

    std::lock_guard<std::mutex> lock(appChangeDataMutex_);
    appChangeData_.clear();
}

int32_t HgmFrameRateManager::GetExpectedFrameRate(const RSPropertyUnit unit, float velocity) const
{
    switch (unit) {
        case RSPropertyUnit::PIXEL_POSITION:
            return GetPreferredFps("translate", PixelToMM(velocity));
        case RSPropertyUnit::PIXEL_SIZE:
        case RSPropertyUnit::RATIO_SCALE:
            return GetPreferredFps("scale", PixelToMM(velocity));
        case RSPropertyUnit::ANGLE_ROTATION:
            return GetPreferredFps("rotation", PixelToMM(velocity));
        default:
            return 0;
    }
}

int32_t HgmFrameRateManager::GetPreferredFps(const std::string& type, float velocity) const
{
    auto &configData = HgmCore::Instance().GetPolicyConfigData();
    if (!configData) {
        return 0;
    }
    if (ROSEN_EQ(velocity, 0.f)) {
        return 0;
    }
    const std::string settingMode = std::to_string(curRefreshRateMode_);
    if (configData->screenConfigs_.count(curScreenStrategyId_) &&
        configData->screenConfigs_[curScreenStrategyId_].count(settingMode) &&
        configData->screenConfigs_[curScreenStrategyId_][settingMode].animationDynamicSettings.count(type)) {
        auto& config = configData->screenConfigs_[curScreenStrategyId_][settingMode].animationDynamicSettings[type];
        auto iter = std::find_if(config.begin(), config.end(), [&velocity](const auto& pair) {
            return velocity >= pair.second.min && (velocity < pair.second.max || pair.second.max == -1);
        });
        if (iter != config.end()) {
            RS_OPTIONAL_TRACE_NAME_FMT("GetPreferredFps: type: %s, speed: %f, rate: %d",
                type.c_str(), velocity, iter->second.preferred_fps);
            return iter->second.preferred_fps;
        }
    }
    return 0;
}

float HgmFrameRateManager::PixelToMM(float velocity)
{
    float velocityMM = 0.0f;
    auto& hgmCore = HgmCore::Instance();
    sptr<HgmScreen> hgmScreen = hgmCore.GetScreen(hgmCore.GetActiveScreenId());
    if (hgmScreen && hgmScreen->GetPpi() > 0.f) {
        velocityMM = velocity / hgmScreen->GetPpi() * INCH_2_MM;
    }
    return velocityMM;
}

std::shared_ptr<HgmOneShotTimer> HgmFrameRateManager::GetScreenTimer(ScreenId screenId) const
{
    if (auto timer = screenTimerMap_.find(screenId); timer != screenTimerMap_.end()) {
        return timer->second;
    }
    return nullptr;
}

void HgmFrameRateManager::StartScreenTimer(ScreenId screenId, int32_t interval,
    std::function<void()> resetCallback, std::function<void()> expiredCallback)
{
    if (auto oldtimer = GetScreenTimer(screenId); oldtimer == nullptr) {
        auto newTimer = std::make_shared<HgmOneShotTimer>("idle_timer" + std::to_string(screenId),
            std::chrono::milliseconds(interval), resetCallback, expiredCallback);
        screenTimerMap_[screenId] = newTimer;
        newTimer->Start();
    }
}

void HgmFrameRateManager::ResetScreenTimer(ScreenId screenId) const
{
    if (auto timer = GetScreenTimer(screenId); timer != nullptr) {
        timer->Reset();
    }
}

void HgmFrameRateManager::StopScreenTimer(ScreenId screenId)
{
    if (auto timer = screenTimerMap_.find(screenId); timer != screenTimerMap_.end()) {
        screenTimerMap_.erase(timer);
    }
}

void HgmFrameRateManager::HandleLightFactorStatus(pid_t pid, bool isSafe)
{
    // based on the light determine whether allowed to reduce the screen refresh rate to avoid screen flicker
    HGM_LOGI("HandleLightFactorStatus status:%{public}u", isSafe);
    if (pid != DEFAULT_PID) {
        std::lock_guard<std::mutex> lock(cleanPidCallbackMutex_);
        cleanPidCallback_[pid].insert(CleanPidCallbackType::LIGHT_FACTOR);
    }
    HgmTaskHandleThread::Instance().PostTask([this, isSafeParam = isSafe] () {
        multiAppStrategy_.HandleLightFactorStatus(isSafeParam);
    });
}

void HgmFrameRateManager::HandlePackageEvent(pid_t pid, uint32_t listSize, const std::vector<std::string>& packageList)
{
    if (pid != DEFAULT_PID) {
        std::lock_guard<std::mutex> lock(cleanPidCallbackMutex_);
        cleanPidCallback_[pid].insert(CleanPidCallbackType::PACKAGE_EVENT);
    }
    HgmTaskHandleThread::Instance().PostTask([this, packageList] () {
        if (multiAppStrategy_.HandlePkgsEvent(packageList) == EXEC_SUCCESS) {
            std::lock_guard<std::mutex> locker(pkgSceneMutex_);
            sceneStack_.clear();
        }
        UpdateAppSupportedState();
    });
}

void HgmFrameRateManager::HandleRefreshRateEvent(pid_t pid, const EventInfo& eventInfo)
{
    std::string eventName = eventInfo.eventName;
    std::lock_guard<std::mutex> lock(voteNameMutex_);
    auto event = std::find(voters_.begin(), voters_.end(), eventName);
    if (event == voters_.end()) {
        HGM_LOGW("HgmFrameRateManager:unknown event, eventName is %{public}s", eventName.c_str());
        return;
    }

    HGM_LOGI("%{public}s(%{public}d) %{public}s", eventName.c_str(), pid, eventInfo.description.c_str());
    if (eventName == "VOTER_SCENE") {
        HandleSceneEvent(pid, eventInfo);
    } else if (eventName == "VOTER_VIRTUALDISPLAY") {
        HandleVirtualDisplayEvent(pid, eventInfo);
    } else if (eventName == "VOTER_GAMES") {
        HandleGamesEvent(pid, eventInfo);
    } else {
        DeliverRefreshRateVote({eventName, eventInfo.minRefreshRate, eventInfo.maxRefreshRate, pid},
            eventInfo.eventStatus);
    }
}

void HgmFrameRateManager::HandleTouchEvent(pid_t pid, int32_t touchStatus, int32_t touchCnt)
{
    HGM_LOGD("HandleTouchEvent status:%{public}d", touchStatus);
    if (pid != DEFAULT_PID) {
        std::lock_guard<std::mutex> lock(cleanPidCallbackMutex_);
        cleanPidCallback_[pid].insert(CleanPidCallbackType::TOUCH_EVENT);
    }

    static std::mutex hgmTouchEventMutex;
    std::unique_lock<std::mutex> eventLock(hgmTouchEventMutex);
    if (touchStatus == TOUCH_DOWN || touchStatus == TOUCH_PULL_DOWN) {
        HGM_LOGI("[touch manager] down");
        PolicyConfigData::StrategyConfig strategyRes;
        ExitEnergyConsumptionAssuranceMode();
        if (multiAppStrategy_.GetFocusAppStrategyConfig(strategyRes) == EXEC_SUCCESS &&
            strategyRes.dynamicMode != DynamicModeType::TOUCH_DISENABLED) {
                touchManager_.HandleTouchEvent(TouchEvent::DOWN_EVENT, "");
        }
    } else if (touchStatus == TOUCH_UP || touchStatus == TOUCH_PULL_UP) {
        if (touchCnt != LAST_TOUCH_CNT) {
            return;
        }
        std::lock_guard<std::mutex> lock(voteMutex_);
        if (auto iter = voteRecord_.find("VOTER_GAMES"); iter != voteRecord_.end() && !iter->second.empty() &&
            gameScenes_.empty() && multiAppStrategy_.CheckPidValid(iter->second.front().pid)) {
            HGM_LOGI("[touch manager] keep down in games");
            return;
        }
        if (touchCnt == LAST_TOUCH_CNT) {
            HGM_LOGI("[touch manager] up");
            EnterEnergyConsumptionAssuranceMode();
            touchManager_.HandleTouchEvent(TouchEvent::UP_EVENT, "");
        }
    } else {
        HGM_LOGD("[touch manager] other touch status not support");
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
    multiAppStrategy_.CalcVote();
    HgmCore::Instance().SetLtpoConfig();
    schedulePreferredFpsChange_ = true;
    FrameRateReport();
    HgmConfigCallbackManager::GetInstance()->SyncHgmConfigChangeCallback();
}

void HgmFrameRateManager::HandleScreenPowerStatus(ScreenId id, ScreenPowerStatus status)
{
    // hgm warning: strategy for screen off
    HGM_LOGI("HandleScreenPowerStatus curScreen:%{public}d status:%{public}d",
        static_cast<int>(curScreenId_), static_cast<int>(status));
    if (status == ScreenPowerStatus::POWER_STATUS_ON) {
        ReportHiSysEvent({.voterName = "SCREEN_POWER", .extInfo = "ON"});
    } else if (status == ScreenPowerStatus::POWER_STATUS_SUSPEND) {
        ReportHiSysEvent({.voterName = "SCREEN_POWER", .extInfo = "OFF"});
    }
    if (status != ScreenPowerStatus::POWER_STATUS_ON) {
        return;
    }
    static std::mutex lastScreenIdMutex;
    std::unique_lock<std::mutex> lock(lastScreenIdMutex);
    static ScreenId lastScreenId = 12345; // init value diff with any real screen id
    if (lastScreenId == id) {
        return;
    }
    lastScreenId = id;

    auto& hgmCore = HgmCore::Instance();
    auto screenList = hgmCore.GetScreenIds();
    auto screenPos = find(screenList.begin(), screenList.end(), id);
    auto lastCurScreenId = curScreenId_;
    curScreenId_ = (screenPos == screenList.end()) ? 0 : id;
    if (lastCurScreenId == curScreenId_) {
        return;
    }
    HGM_LOGI("HandleScreenPowerStatus curScreen:%{public}d", static_cast<int>(curScreenId_));
    isLtpo_ = (GetScreenType(curScreenId_) == "LTPO");
    std::string curScreenName = "screen" + std::to_string(curScreenId_) + "_" + (isLtpo_ ? "LTPO" : "LTPS");

    auto configData = hgmCore.GetPolicyConfigData();
    if (configData != nullptr) {
        curScreenStrategyId_ = configData->screenStrategyConfigs_[curScreenName];
        if (curScreenStrategyId_.empty()) {
            curScreenStrategyId_ = "LTPO-DEFAULT";
        }
        multiAppStrategy_.UpdateXmlConfigCache();
        UpdateEnergyConsumptionConfig();
    }

    multiAppStrategy_.CalcVote();
    hgmCore.SetLtpoConfig();
    MarkVoteChange();
    schedulePreferredFpsChange_ = true;
    FrameRateReport();
    HgmConfigCallbackManager::GetInstance()->SyncHgmConfigChangeCallback();

    // hgm warning: use !isLtpo_ instead after GetDisplaySupportedModes ready
    if (curScreenStrategyId_.find("LTPO") == std::string::npos) {
        DeliverRefreshRateVote({"VOTER_LTPO"}, REMOVE_VOTE);
    }
}

void HgmFrameRateManager::HandleSceneEvent(pid_t pid, EventInfo eventInfo)
{
    std::string sceneName = eventInfo.description;
    auto screenSetting = multiAppStrategy_.GetScreenSetting();
    auto &gameSceneList = screenSetting.gameSceneList;

    std::lock_guard<std::mutex> locker(pkgSceneMutex_);
    std::lock_guard<std::mutex> lock(voteMutex_);
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

    std::pair<std::string, pid_t> info = std::make_pair(sceneName, pid);
    auto scenePos = find(sceneStack_.begin(), sceneStack_.end(), info);
    if (eventInfo.eventStatus == ADD_VOTE) {
        if (scenePos == sceneStack_.end()) {
            sceneStack_.push_back(info);
            MarkVoteChange();
        }
    } else {
        if (scenePos != sceneStack_.end()) {
            sceneStack_.erase(scenePos);
            MarkVoteChange();
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
    if (virtualDisplayConfig.count(virtualDisplayName) == 0) {
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
        DeliverRefreshRateVote({"VOTER_GAMES"}, false);
        return;
    }
    auto [pkgName, gamePid, appType] = HgmMultiAppStrategy::AnalyzePkgParam(eventInfo.description);
    if (gamePid == DEFAULT_PID) {
        HGM_LOGE("unknow game pid: %{public}s, skip", eventInfo.description.c_str());
        return;
    }
    if (pid != DEFAULT_PID) {
        std::lock_guard<std::mutex> lock(cleanPidCallbackMutex_);
        cleanPidCallback_[pid].insert(CleanPidCallbackType::GAMES);
    }
    DeliverRefreshRateVote(
        {"VOTER_GAMES", eventInfo.minRefreshRate, eventInfo.maxRefreshRate, gamePid}, eventInfo.eventStatus);
}

void HgmFrameRateManager::MarkVoteChange()
{
    isRefreshNeed_ = true;
    if (forceUpdateCallback_ != nullptr) {
        forceUpdateCallback_(false, true);
    }
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

    std::lock_guard<std::mutex> lock(voteMutex_);
    voteRecord_.try_emplace(voteInfo.voterName, std::vector<VoteInfo>());
    auto& vec = voteRecord_[voteInfo.voterName];

    // clear
    if ((voteInfo.pid == 0) && (eventStatus == REMOVE_VOTE)) {
        if (!vec.empty()) {
            vec.clear();
            MarkVoteChange();
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
            MarkVoteChange();
            return;
        } else {
            if ((*it).min != voteInfo.min || (*it).max != voteInfo.max) {
                // modify
                vec.erase(it);
                vec.push_back(voteInfo);
                MarkVoteChange();
            } else if (voteInfo.voterName == "VOTER_PACKAGES") {
                // force update cause VOTER_PACKAGES is flag of safe_voter
                MarkVoteChange();
            }
            return;
        }
    }

    // add
    if (eventStatus == ADD_VOTE) {
        pidRecord_.insert(voteInfo.pid);
        vec.push_back(voteInfo);
        MarkVoteChange();
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
        auto vec = voteRecord_[*voterIter];
        if (vec.empty()) {
            continue;
        }

        VoteInfo curVoteInfo = vec.back();
        if (!multiAppStrategy_.CheckPidValid(curVoteInfo.pid)) {
            ProcessVoteLog(curVoteInfo, true);
            continue;
        }
        if (curVoteInfo.voterName == "VOTER_VIDEO") {
            auto foregroundPidApp = multiAppStrategy_.GetForegroundPidApp();
            if (foregroundPidApp.find(curVoteInfo.pid) == foregroundPidApp.end()) {
                ProcessVoteLog(curVoteInfo, true);
                continue;
            }
            auto configData = HgmCore::Instance().GetPolicyConfigData();
            if (configData != nullptr && configData->videoFrameRateList_.find(
                foregroundPidApp[curVoteInfo.pid].second) == configData->videoFrameRateList_.end()) {
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

VoteInfo HgmFrameRateManager::ProcessRefreshRateVote()
{
    if (!isRefreshNeed_) {
        const auto& packages = multiAppStrategy_.GetPackages();
        RS_TRACE_NAME_FMT("Process nothing, lastVoteInfo: %s[%d, %d] curPackage: %s, touchState: %d",
            lastVoteInfo_.voterName.c_str(), lastVoteInfo_.min, lastVoteInfo_.max,
            packages.empty() ? "" : packages.front().c_str(), touchManager_.GetState());
        return lastVoteInfo_;
    }
    UpdateVoteRule();
    std::lock_guard<std::mutex> voteNameLock(voteNameMutex_);
    std::lock_guard<std::mutex> voteLock(voteMutex_);

    VoteInfo resultVoteInfo;
    VoteRange voteRange = { OLED_MIN_HZ, OLED_MAX_HZ };
    auto &[min, max] = voteRange;

    for (auto voterIter = voters_.begin(); voterIter != voters_.end(); voterIter++) {
        VoteRange range;
        VoteInfo info;
        if (*voterIter == "VOTER_LTPO" && MergeLtpo2IdleVote(voterIter, info, range)) {
            auto [mergeVoteRange, mergeVoteInfo] = MergeRangeByPriority(voteRange, range);
            if (mergeVoteInfo) {
                resultVoteInfo.Merge(info);
            }
            if (mergeVoteRange) {
                break;
            }
        }

        auto &voter = *voterIter;
        if (voteRecord_.find(voter) == voteRecord_.end() || voteRecord_[voter].empty()) {
            continue;
        }
        VoteInfo curVoteInfo = voteRecord_[voter].back();
        if ((voter == "VOTER_GAMES" && !gameScenes_.empty()) || !multiAppStrategy_.CheckPidValid(curVoteInfo.pid)) {
            ProcessVoteLog(curVoteInfo, true);
            continue;
        }
        ProcessVoteLog(curVoteInfo, false);
        auto [mergeVoteRange, mergeVoteInfo] = MergeRangeByPriority(voteRange, {curVoteInfo.min, curVoteInfo.max});
        if (mergeVoteInfo) {
            resultVoteInfo.Merge(curVoteInfo);
        }
        if (mergeVoteRange) {
            break;
        }
    }
    isRefreshNeed_ = false;
    HGM_LOGI("Process: Strategy:%{public}s Screen:%{public}d Mode:%{public}d -- VoteResult:{%{public}d-%{public}d}",
        curScreenStrategyId_.c_str(), static_cast<int>(curScreenId_), curRefreshRateMode_, min, max);
    SetResultVoteInfo(resultVoteInfo, min, max);
    return resultVoteInfo;
}

void HgmFrameRateManager::UpdateVoteRule()
{
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
    uint32_t scenePriority = static_cast<uint32_t>(std::stoi(curSceneConfig.priority));
    uint32_t min = static_cast<uint32_t>(configData->strategyConfigs_[curSceneConfig.strategy].min);
    uint32_t max = static_cast<uint32_t>(configData->strategyConfigs_[curSceneConfig.strategy].max);
    HGM_LOGI("UpdateVoteRule: SceneName:%{public}s", lastScene.c_str());
    DeliverRefreshRateVote({"VOTER_SCENE", min, max, (*scenePos).second, lastScene}, ADD_VOTE);

    // restore
    std::lock_guard<std::mutex> lock(voteNameMutex_);
    voters_ = std::vector<std::string>(std::begin(VOTER_NAME), std::end(VOTER_NAME));
    std::string srcScene = "VOTER_SCENE";
    std::string dstScene = (scenePriority == SCENE_BEFORE_XML) ? "VOTER_PACKAGES" : "VOTER_TOUCH";

    // priority 1: VOTER_SCENE > VOTER_PACKAGES
    // priority 2: VOTER_SCENE > VOTER_TOUCH
    // priority 3: VOTER_SCENE < VOTER_TOUCH
    auto srcPos = find(voters_.begin(), voters_.end(), srcScene);
    auto dstPos = find(voters_.begin(), voters_.end(), dstScene);
    
    // resort
    voters_.erase(srcPos);
    if (scenePriority == SCENE_AFTER_TOUCH) {
        voters_.insert(++dstPos, srcScene);
    } else {
        voters_.insert(dstPos, srcScene);
    }
}

std::string HgmFrameRateManager::GetScreenType(ScreenId screenId)
{
    // hgm warning: use GetDisplaySupportedModes instead
    return (screenId == 0) ? "LTPO" : "LTPS";
}

void HgmFrameRateManager::CleanVote(pid_t pid)
{
    if (pid == DEFAULT_PID) {
        return;
    }
    multiAppStrategy_.CleanApp(pid);
    {
        std::lock_guard<std::mutex> lock(cleanPidCallbackMutex_);
        if (auto iter = cleanPidCallback_.find(pid); iter != cleanPidCallback_.end()) {
            for (auto cleanPidCallbackType : iter->second) {
                switch (cleanPidCallbackType) {
                    case CleanPidCallbackType::LIGHT_FACTOR:
                        HandleLightFactorStatus(DEFAULT_PID, false);
                        break;
                    case CleanPidCallbackType::PACKAGE_EVENT:
                        HandlePackageEvent(DEFAULT_PID, 0, {}); // handle empty pkg
                        break;
                    case CleanPidCallbackType::TOUCH_EVENT:
                        HandleTouchEvent(DEFAULT_PID, TouchStatus::TOUCH_UP, LAST_TOUCH_CNT);
                        break;
                    case CleanPidCallbackType::GAMES:
                        DeliverRefreshRateVote({"VOTER_GAMES"}, false);
                        break;
                    default:
                        break;
                }
            }
            iter->second.clear();
        }
    }

    if (pidRecord_.count(pid) == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(voteMutex_);
    HGM_LOGW("CleanVote: i am [%{public}d], i died, clean my votes please.", pid);
    pidRecord_.erase(pid);

    for (auto& [key, value] : voteRecord_) {
        for (auto it = value.begin(); it != value.end(); it++) {
            if ((*it).pid == pid) {
                it = value.erase(it);
                MarkVoteChange();
                break;
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
}

void HgmFrameRateManager::EnterEnergyConsumptionAssuranceMode()
{
    auto task = []() { HgmEnergyConsumptionPolicy::Instance().SetAnimationEnergyConsumptionAssuranceMode(true); };
    HgmTaskHandleThread::Instance().PostEvent(ENERGY_ASSURANCE_TASK_ID, task, ENERGY_ASSURANCE_TASK_DELAY_TIME);
    auto uiTask = []() { HgmEnergyConsumptionPolicy::Instance().SetUiEnergyConsumptionAssuranceMode(true); };
    HgmTaskHandleThread::Instance().PostEvent(UI_ENERGY_ASSURANCE_TASK_ID, uiTask, UI_ENERGY_ASSURANCE_TASK_DELAY_TIME);
}

void HgmFrameRateManager::ExitEnergyConsumptionAssuranceMode()
{
    HgmTaskHandleThread::Instance().RemoveEvent(ENERGY_ASSURANCE_TASK_ID);
    HgmTaskHandleThread::Instance().RemoveEvent(UI_ENERGY_ASSURANCE_TASK_ID);
    HgmEnergyConsumptionPolicy::Instance().SetAnimationEnergyConsumptionAssuranceMode(false);
    HgmEnergyConsumptionPolicy::Instance().SetUiEnergyConsumptionAssuranceMode(false);
}

void HgmFrameRateManager::ProcessVoteLog(const VoteInfo& curVoteInfo, bool isSkip)
{
    RS_TRACE_NAME_FMT("Process voter:%s(pid:%d), value:[%d-%d] skip: %s",
        curVoteInfo.voterName.c_str(), curVoteInfo.pid, curVoteInfo.min, curVoteInfo.max, isSkip ? "true" : "false");
    HGM_LOGI("Process: %{public}s(%{public}d):[%{public}d, %{public}d] skip: %{public}s",
        curVoteInfo.voterName.c_str(), curVoteInfo.pid, curVoteInfo.min, curVoteInfo.max, isSkip ? "true" : "false");
}
} // namespace Rosen
} // namespace OHOS