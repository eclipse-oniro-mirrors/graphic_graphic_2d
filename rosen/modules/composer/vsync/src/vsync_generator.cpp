/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "vsync_generator.h"
#include "vsync_distributor.h"
#include <cstdint>
#include <mutex>
#include <scoped_bytrace.h>
#include <sched.h>
#include <sys/resource.h>
#include <string>
#include <parameters.h>
#include "vsync_log.h"
#include <ctime>
#include <vsync_sampler.h>
#include <rs_trace.h>
#include "scoped_trace_fmt.h"

#ifdef COMPOSER_SCHED_ENABLE
#include "if_system_ability_manager.h"
#include <iservice_registry.h>
#include "system_ability_definition.h"
#endif

namespace OHOS {
namespace Rosen {
namespace impl {
namespace {
static int64_t SystemTime()
{
    timespec t = {};
    clock_gettime(CLOCK_MONOTONIC, &t);
    return int64_t(t.tv_sec) * 1000000000LL + t.tv_nsec; // 1000000000ns == 1s
}

// 1.5ms
constexpr int64_t maxWaleupDelay = 1500000;
constexpr int32_t THREAD_PRIORTY = -6;
constexpr int32_t SCHED_PRIORITY = 2;
constexpr int64_t errorThreshold = 500000;
constexpr int32_t MAX_REFRESHRATE_DEVIATION = 5; // ±5Hz
constexpr int64_t PERIOD_CHECK_THRESHOLD = 1000000; // 1000000ns == 1.0ms
constexpr int64_t DEFAULT_SOFT_VSYNC_PERIOD = 16000000; // 16000000ns == 16ms
constexpr int64_t REFRESH_PERIOD = 16666667; // 16666667ns == 16.666667ms

static void SetThreadHighPriority()
{
    setpriority(PRIO_PROCESS, 0, THREAD_PRIORTY);
    struct sched_param param = {0};
    param.sched_priority = SCHED_PRIORITY;
    sched_setscheduler(0, SCHED_FIFO, &param);
}

static uint32_t CalculateRefreshRate(int64_t period)
{
    if (period > 30000000 && period < 35000000) { // 30000000ns, 35000000ns
        return 30; // 30hz
    } else if (period > 15000000 && period < 18000000) { // 15000000ns, 18000000ns
        return 60; // 60hz
    } else if (period > 10000000 && period < 12000000) { // 10000000ns, 12000000ns
        return 90; // 90hz
    } else if (period > 7500000 && period < 9000000) { // 7500000ns, 9000000ns
        return 120; // 120hz
    }
    return 0;
}

static bool IsPcType()
{
    static bool isPc = (system::GetParameter("const.product.devicetype", "pc") == "pc") ||
                       (system::GetParameter("const.product.devicetype", "pc") == "2in1");
    return isPc;
}

static bool IsPCRefreshRateLock60()
{
    static bool isPCRefreshRateLock60 =
        (std::atoi(system::GetParameter("persist.pc.refreshrate.lock60", "0").c_str()) != 0);
    return isPCRefreshRateLock60;
}
}

std::once_flag VSyncGenerator::createFlag_;
sptr<OHOS::Rosen::VSyncGenerator> VSyncGenerator::instance_ = nullptr;

sptr<OHOS::Rosen::VSyncGenerator> VSyncGenerator::GetInstance() noexcept
{
    std::call_once(createFlag_, []() {
        instance_ = new VSyncGenerator();
    });

    return instance_;
}

void VSyncGenerator::DeleteInstance() noexcept
{
    instance_ = nullptr;
}

VSyncGenerator::VSyncGenerator()
{
    if (IsPcType() && IsPCRefreshRateLock60()) {
        period_ = REFRESH_PERIOD;
    } else {
        period_ = DEFAULT_SOFT_VSYNC_PERIOD;
    }
    vsyncThreadRunning_ = true;
    thread_ = std::thread([this] { this->ThreadLoop(); });
    pthread_setname_np(thread_.native_handle(), "VSyncGenerator");
}

VSyncGenerator::~VSyncGenerator()
{
    {
        std::unique_lock<std::mutex> locker(mutex_);
        vsyncThreadRunning_ = false;
    }
    if (thread_.joinable()) {
        con_.notify_all();
        thread_.join();
    }
}

void VSyncGenerator::ListenerVsyncEventCB(int64_t occurTimestamp, int64_t nextTimeStamp,
    int64_t occurReferenceTime, bool isWakeup)
{
    SCOPED_DEBUG_TRACE_FMT("occurTimestamp:%ld, nextTimeStamp:%ld", occurTimestamp, nextTimeStamp);
    std::vector<Listener> listeners;
    {
        std::unique_lock<std::mutex> locker(mutex_);
        int64_t newOccurTimestamp = SystemTime();
        if (isWakeup) {
            UpdateWakeupDelay(newOccurTimestamp, nextTimeStamp);
        }
        if (vsyncMode_ == VSYNC_MODE_LTPO) {
            listeners = GetListenerTimeoutedLTPO(occurTimestamp, occurReferenceTime);
        } else {
            listeners = GetListenerTimeouted(newOccurTimestamp, occurTimestamp, occurReferenceTime);
        }
        expectTimeFlag_ = false;
    }
    RS_TRACE_NAME_FMT("GenerateVsyncCount:%lu, period:%ld, currRefreshRate_:%u, vsyncMode_:%d",
        listeners.size(), periodRecord_, currRefreshRate_, vsyncMode_);
    for (uint32_t i = 0; i < listeners.size(); i++) {
        RS_TRACE_NAME_FMT("listener phase is %ld", listeners[i].phase_);
        if (listeners[i].callback_ != nullptr) {
            listeners[i].callback_->OnVSyncEvent(listeners[i].lastTime_, periodRecord_, currRefreshRate_, vsyncMode_);
        }
    }
}

void VSyncGenerator::ThreadLoop()
{
#ifdef COMPOSER_SCHED_ENABLE
    SubScribeSystemAbility();
#endif
    // set thread priorty
    SetThreadHighPriority();

    int64_t occurTimestamp = 0;
    int64_t nextTimeStamp = 0;
    int64_t occurReferenceTime = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> locker(mutex_);
            if (vsyncThreadRunning_ == false) {
                break;
            }
            UpdateVSyncModeLocked();
            occurReferenceTime = referenceTime_;
            phaseRecord_ = phase_;
            periodRecord_ = period_;
            if (period_ == 0) {
                ScopedBytrace func("VSyncGenerator: period not valid");
                if (vsyncThreadRunning_ == true) {
                    con_.wait(locker);
                }
                continue;
            }
            occurTimestamp = SystemTime();
            nextTimeStamp = ComputeNextVSyncTimeStamp(occurTimestamp, occurReferenceTime);
            if (nextTimeStamp == INT64_MAX) {
                ScopedBytrace func("VSyncGenerator: there has no listener");
                if (vsyncThreadRunning_ == true) {
                    con_.wait(locker);
                }
                continue;
            } else if (vsyncMode_ == VSYNC_MODE_LTPO) {
                bool modelChanged = UpdateChangeDataLocked(occurTimestamp, occurReferenceTime, nextTimeStamp);
                if (modelChanged) {
                    ScopedBytrace func("VSyncGenerator: LTPO mode change");
                    bool clearAllSamplesFlag = clearAllSamplesFlag_;
                    clearAllSamplesFlag_ = false;
                    locker.unlock();
                    ClearAllSamplesInternal(clearAllSamplesFlag);
                    appVSyncDistributor_->RecordVsyncModeChange(currRefreshRate_, period_);
                    rsVSyncDistributor_->RecordVsyncModeChange(currRefreshRate_, period_);
                    continue;
                }
            }
        }

        WaitForTimeout(occurTimestamp, nextTimeStamp, occurReferenceTime);
    }
}

void VSyncGenerator::WaitForTimeout(int64_t occurTimestamp, int64_t nextTimeStamp, int64_t occurReferenceTime)
{
    bool isWakeup = false;
    if (occurTimestamp < nextTimeStamp) {
        std::unique_lock<std::mutex> lck(waitForTimeoutMtx_);
        auto err = waitForTimeoutCon_.wait_for(lck, std::chrono::nanoseconds(nextTimeStamp - occurTimestamp));
        if (err == std::cv_status::timeout) {
            isWakeup = true;
        } else {
            ScopedBytrace func("VSyncGenerator::ThreadLoop::Continue");
            return;
        }
    }
    ListenerVsyncEventCB(occurTimestamp, nextTimeStamp, occurReferenceTime, isWakeup);
}

bool VSyncGenerator::ChangeListenerOffsetInternal()
{
    if (changingPhaseOffset_.cb == nullptr) {
        return true;
    }
    auto it = listeners_.begin();
    for (; it < listeners_.end(); it++) {
        if (it->callback_ == changingPhaseOffset_.cb) {
            break;
        }
    }
    int64_t phaseOffset = pulse_ * changingPhaseOffset_.phaseByPulseNum;
    if (it != listeners_.end()) {
        it->phase_ = phaseOffset;
    }

    it = listenersRecord_.begin();
    for (; it < listenersRecord_.end(); it++) {
        if (it->callback_ == changingPhaseOffset_.cb) {
            break;
        }
    }
    if (it == listenersRecord_.end()) {
        return false;
    }
    if (it->callback_ != nullptr) {
        it->callback_->OnPhaseOffsetChanged(phaseOffset);
    }
    changingPhaseOffset_ = {}; // reset
    return true;
}

bool VSyncGenerator::ChangeListenerRefreshRatesInternal()
{
    if (changingRefreshRates_.cb == nullptr) {
        return true;
    }
    auto it = listenersRecord_.begin();
    for (; it < listenersRecord_.end(); it++) {
        if (it->callback_ == changingRefreshRates_.cb) {
            break;
        }
    }
    if (it == listenersRecord_.end()) {
        return false;
    }
    if (it->callback_ != nullptr) {
        it->callback_->OnConnsRefreshRateChanged(changingRefreshRates_.refreshRates);
    }
    // reset
    changingRefreshRates_.cb = nullptr;
    changingRefreshRates_.refreshRates.clear();
    changingRefreshRates_ = {};
    return true;
}

void VSyncGenerator::UpdateWakeupDelay(int64_t occurTimestamp, int64_t nextTimeStamp)
{
    // 63, 1 / 64
    wakeupDelay_ = ((wakeupDelay_ * 63) + (occurTimestamp - nextTimeStamp)) / 64;
    wakeupDelay_ = wakeupDelay_ > maxWaleupDelay ? maxWaleupDelay : wakeupDelay_;
}

int64_t VSyncGenerator::ComputeNextVSyncTimeStamp(int64_t now, int64_t referenceTime)
{
    int64_t nextVSyncTime = INT64_MAX;
    for (uint32_t i = 0; i < listeners_.size(); i++) {
        int64_t t = ComputeListenerNextVSyncTimeStamp(listeners_[i], now, referenceTime);
        if (t < nextVSyncTime) {
            nextVSyncTime = t;
        }
    }

    return nextVSyncTime;
}

bool VSyncGenerator::CheckTimingCorrect(int64_t now, int64_t referenceTime, int64_t nextVSyncTime)
{
    bool isTimingCorrect = false;
    for (uint32_t i = 0; i < listeners_.size(); i++) {
        int64_t t = ComputeListenerNextVSyncTimeStamp(listeners_[i], now, referenceTime);
        if ((t - nextVSyncTime < errorThreshold) && (listeners_[i].phase_ == 0)) {
            isTimingCorrect = true;
        }
    }
    return isTimingCorrect;
}

bool VSyncGenerator::UpdateChangeDataLocked(int64_t now, int64_t referenceTime, int64_t nextVSyncTime)
{
    bool modelChanged = false;

    // change referenceTime
    if (expectNextVsyncTime_ > 0) {
        RS_TRACE_NAME_FMT("UpdateChangeDataLocked, expectNextVsyncTime_:%ld", expectNextVsyncTime_);
        nextVSyncTime = expectNextVsyncTime_;
        expectNextVsyncTime_ = 0;
        referenceTime_ = nextVSyncTime;
        modelChanged = true;
        expectTimeFlag_ = true;
    } else {
        if (!CheckTimingCorrect(now, referenceTime, nextVSyncTime)) {
            return false;
        }
    }

    // update generate refreshRate
    if (needChangeGeneratorRefreshRate_) {
        currRefreshRate_ = changingGeneratorRefreshRate_;
        period_ = pulse_ * static_cast<int64_t>(VSYNC_MAX_REFRESHRATE / currRefreshRate_);
        referenceTime_ = nextVSyncTime;
        changingGeneratorRefreshRate_ = 0; // reset
        needChangeGeneratorRefreshRate_ = false;
        refreshRateIsChanged_ = true;
        frameRateChanging_ = true;
        ScopedBytrace trace("frameRateChanging_ = true");
        targetPeriod_ = period_;
        clearAllSamplesFlag_ = true;
        modelChanged = true;
    }

    // update phaseOffset
    if (needChangePhaseOffset_) {
        bool offsetChangedSucceed = ChangeListenerOffsetInternal();
        if (offsetChangedSucceed) {
            needChangePhaseOffset_ = false;
            modelChanged = true;
        }
    }

    // update VSyncConnections refreshRates
    if (needChangeRefreshRates_) {
        bool refreshRatesChangedSucceed = ChangeListenerRefreshRatesInternal();
        if (refreshRatesChangedSucceed) {
            needChangeRefreshRates_ = false;
            modelChanged = true;
        }
    }

    return modelChanged;
}

void VSyncGenerator::ClearAllSamplesInternal(bool clearAllSamplesFlag)
{
    if (clearAllSamplesFlag) {
        CreateVSyncSampler()->ClearAllSamples();
    }
}

void VSyncGenerator::UpdateVSyncModeLocked()
{
    if (pendingVsyncMode_ != VSYNC_MODE_INVALID) {
        vsyncMode_ = pendingVsyncMode_;
        pendingVsyncMode_ = VSYNC_MODE_INVALID;
    }
}

int64_t VSyncGenerator::ComputeListenerNextVSyncTimeStamp(const Listener& listener, int64_t now, int64_t referenceTime)
{
    int64_t lastVSyncTime = listener.lastTime_ + wakeupDelay_;
    if (now < lastVSyncTime) {
        now = lastVSyncTime;
    }

    now -= referenceTime;
    int64_t phase = phaseRecord_ + listener.phase_;
    now -= phase;
    if (now < 0) {
        if (vsyncMode_ == VSYNC_MODE_LTPO) {
            if (expectTimeFlag_ || refreshRateIsChanged_) { // Ensure that nextTime is not earlier than referenceTime.
                now += ((-now) / periodRecord_) * periodRecord_;
            }
            now -= periodRecord_;
        } else {
            now = -periodRecord_;
        }
    }
    int64_t numPeriod = now / periodRecord_;
    int64_t nextTime = (numPeriod + 1) * periodRecord_ + phase;
    nextTime += referenceTime;

    // 3 / 5 and 1 / 10 are just empirical value
    int64_t threshold = refreshRateIsChanged_ ? (1 * periodRecord_ / 10) : (3 * periodRecord_ / 5);
    // between 8000000(8ms) and 8500000(8.5ms)
    if (!refreshRateIsChanged_ && frameRateChanging_ && periodRecord_ > 8000000 && periodRecord_ < 8500000) {
        threshold = 4 * periodRecord_ / 5; // 4 / 5 is an empirical value
    }
    // 3 / 5 just empirical value
    if (((vsyncMode_ == VSYNC_MODE_LTPS) && (nextTime - listener.lastTime_ < (3 * periodRecord_ / 5))) ||
        ((vsyncMode_ == VSYNC_MODE_LTPO) && (nextTime - listener.lastTime_ < threshold))) {
        RS_TRACE_NAME_FMT("ComputeListenerNextVSyncTimeStamp add one more period:%ld, threshold:%ld",
            periodRecord_, threshold);
        nextTime += periodRecord_;
    }

    nextTime -= wakeupDelay_;
    return nextTime;
}

std::vector<VSyncGenerator::Listener> VSyncGenerator::GetListenerTimeouted(
    int64_t now, int64_t occurTimestamp, int64_t referenceTime)
{
    std::vector<VSyncGenerator::Listener> ret;
    for (uint32_t i = 0; i < listeners_.size(); i++) {
        int64_t t = ComputeListenerNextVSyncTimeStamp(listeners_[i], occurTimestamp, referenceTime);
        if (t < now || (t - now < errorThreshold)) {
            listeners_[i].lastTime_ = t;
            ret.push_back(listeners_[i]);
        }
    }
    return ret;
}

std::vector<VSyncGenerator::Listener> VSyncGenerator::GetListenerTimeoutedLTPO(int64_t now, int64_t referenceTime)
{
    std::vector<VSyncGenerator::Listener> ret;
    for (uint32_t i = 0; i < listeners_.size(); i++) {
        int64_t t = ComputeListenerNextVSyncTimeStamp(listeners_[i], now, referenceTime);
        if (t - SystemTime() < errorThreshold) {
            listeners_[i].lastTime_ = t;
            ret.push_back(listeners_[i]);
        }
    }
    refreshRateIsChanged_ = false;
    return ret;
}

VsyncError VSyncGenerator::UpdatePeriodLocked(int64_t period)
{
    VsyncError ret = VSYNC_ERROR_OK;
    uint32_t refreshRate = JudgeRefreshRateLocked(period);
    if ((pendingVsyncMode_ == VSYNC_MODE_LTPO) || (vsyncMode_ == VSYNC_MODE_LTPO)) {
        if ((refreshRate != 0) && ((currRefreshRate_ == refreshRate) || currRefreshRate_ == 0)) {
            period_ = period;
        } else {
            RS_TRACE_NAME_FMT("update period failed, refreshRate:%u, currRefreshRate_:%d",
                refreshRate, currRefreshRate_);
            VLOGE("update period failed, refreshRate:%{public}u, currRefreshRate_:%{public}u, period:" VPUBI64,
                                    refreshRate, currRefreshRate_, period);
            ret = VSYNC_ERROR_API_FAILED;
        }
    } else {
        if (period != 0) {
            period_ = period;
        } else {
            ret = VSYNC_ERROR_API_FAILED;
        }
    }
    return ret;
}

VsyncError VSyncGenerator::UpdateReferenceTimeLocked(int64_t referenceTime)
{
    if ((pendingVsyncMode_ == VSYNC_MODE_LTPO) || (vsyncMode_ == VSYNC_MODE_LTPO)) {
        referenceTime_ = referenceTime - referenceTimeOffsetPulseNum_ * pulse_;
    } else {
        referenceTime_ = referenceTime;
    }
    return VSYNC_ERROR_OK;
}

void VSyncGenerator::SubScribeSystemAbility()
{
    VLOGD("%{public}s", __func__);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        VLOGE("%{public}s failed to get system ability manager client", __func__);
        return;
    }
    std::string threadName = "VSyncGenerator";
    std::string strUid = std::to_string(getuid());
    std::string strPid = std::to_string(getpid());
    std::string strTid = std::to_string(gettid());

    saStatusChangeListener_ = new (std::nothrow)VSyncSystemAbilityListener(threadName, strUid, strPid, strTid);
    int32_t ret = systemAbilityManager->SubscribeSystemAbility(RES_SCHED_SYS_ABILITY_ID, saStatusChangeListener_);
    if (ret != ERR_OK) {
        VLOGE("%{public}s subscribe system ability %{public}d failed.", __func__, RES_SCHED_SYS_ABILITY_ID);
        saStatusChangeListener_ = nullptr;
    }
}

VsyncError VSyncGenerator::UpdateMode(int64_t period, int64_t phase, int64_t referenceTime)
{
    if (IsPcType() && IsPCRefreshRateLock60()) {
        period = REFRESH_PERIOD;
    }
    std::lock_guard<std::mutex> locker(mutex_);
    RS_TRACE_NAME_FMT("UpdateMode, period:%ld, phase:%ld, referenceTime:%ld, referenceTimeOffsetPulseNum_:%d",
        period, phase, referenceTime, referenceTimeOffsetPulseNum_);
    if (period < 0 || referenceTime < 0) {
        VLOGE("wrong parameter, period:" VPUBI64 ", referenceTime:" VPUBI64, period, referenceTime);
        return VSYNC_ERROR_INVALID_ARGUMENTS;
    }
    phase_ = phase;
    if (period != 0) {
        UpdatePeriodLocked(period);
    }
    UpdateReferenceTimeLocked(referenceTime);
    startRefresh_ = false;
    con_.notify_all();
    return VSYNC_ERROR_OK;
}

VsyncError VSyncGenerator::AddListener(int64_t phase, const sptr<OHOS::Rosen::VSyncGenerator::Callback>& cb)
{
    ScopedBytrace func("AddListener");
    std::lock_guard<std::mutex> locker(mutex_);
    if (cb == nullptr) {
        return VSYNC_ERROR_INVALID_ARGUMENTS;
    }
    Listener listener;
    listener.phase_ = phase;
    listener.callback_ = cb;
    listener.lastTime_ = SystemTime() - period_ + phase_;

    listeners_.push_back(listener);

    size_t i = 0;
    for (; i < listenersRecord_.size(); i++) {
        if (listener.callback_ == listenersRecord_[i].callback_) {
            break;
        }
    }
    if (i == listenersRecord_.size()) {
        listenersRecord_.push_back(listener);
    }
    con_.notify_all();
    waitForTimeoutCon_.notify_all();
    return VSYNC_ERROR_OK;
}

uint32_t VSyncGenerator::JudgeRefreshRateLocked(int64_t period)
{
    if (period <= 0) {
        return 0;
    }
    int32_t actualRefreshRate = round(1.0/((double)period/1000000000.0)); // 1.0s == 1000000000.0ns
    int32_t refreshRate = actualRefreshRate;
    int32_t diff = 0;
    // 在actualRefreshRate附近找一个能被VSYNC_MAX_REFRESHRATE整除的刷新率作为训练pulse的参考刷新率
    while ((abs(refreshRate - actualRefreshRate) < MAX_REFRESHRATE_DEVIATION) &&
           (VSYNC_MAX_REFRESHRATE % refreshRate != 0)) {
        if (diff < 0) {
            diff = -diff;
        } else {
            diff = -diff - 1;
        }
        refreshRate = actualRefreshRate + diff;
    }
    if (VSYNC_MAX_REFRESHRATE % refreshRate != 0) {
        VLOGE("Not Support this refresh rate: %{public}d, update pulse failed.", actualRefreshRate);
        return 0;
    }
    pulse_ = period / (VSYNC_MAX_REFRESHRATE / refreshRate);
    return static_cast<uint32_t>(refreshRate);
}

VsyncError VSyncGenerator::SetExpectNextVsyncTimeInternal(int64_t expectNextVsyncTime)
{
    if (expectNextVsyncTime <= 0) {
        return VSYNC_ERROR_OK;
    }
    auto now = SystemTime();
    int64_t expectTime = 0;
    if (expectNextVsyncTime - referenceTime_ > 0) {
        if (((expectNextVsyncTime - referenceTime_) % pulse_) < (pulse_ / 2)) { // check with 1/2 pulse
            expectTime = ((expectNextVsyncTime - referenceTime_) / pulse_) * pulse_ + referenceTime_;
        } else {
            expectTime = ((expectNextVsyncTime - referenceTime_) / pulse_ + 1) * pulse_ + referenceTime_;
        }
    }
    if (expectTime == 0 || expectTime - now > 100000000) { // 100ms == 100000000ns
        RS_TRACE_NAME_FMT("SetExpectNextVsyncTime Failed, expectTime:%ld, now:%ld, expectNextVsyncTime:%ld,"
            " referenceTime_:%ld", expectTime, now, expectNextVsyncTime, referenceTime_);
        return VSYNC_ERROR_INVALID_ARGUMENTS;
    }
    expectNextVsyncTime_ = expectTime;
    RS_TRACE_NAME_FMT("expectNextVsyncTime:%ld, expectNextVsyncTime_:%ld, diff:%ld", expectNextVsyncTime,
        expectNextVsyncTime_, (expectNextVsyncTime_ - expectNextVsyncTime));
    return VSYNC_ERROR_OK;
}

VsyncError VSyncGenerator::ChangeGeneratorRefreshRateModel(const ListenerRefreshRateData &listenerRefreshRates,
                                                           const ListenerPhaseOffsetData &listenerPhaseOffset,
                                                           uint32_t generatorRefreshRate, int64_t expectNextVsyncTime)
{
    std::string refreshrateStr = "refreshRates[";
    for (std::pair<uint64_t, uint32_t> rateVec : listenerRefreshRates.refreshRates) {
        uint64_t linkerId = rateVec.first;
        uint32_t refreshrate = rateVec.second;
        refreshrateStr += "(" + std::to_string(linkerId) + "," + std::to_string(refreshrate) + "),";
    }
    refreshrateStr += "]";
    RS_TRACE_NAME_FMT("ChangeGeneratorRefreshRateModel:%u, phaseByPulseNum:%d, %s, expectNextVsyncTime:%ld",
        generatorRefreshRate, listenerPhaseOffset.phaseByPulseNum, refreshrateStr.c_str(), expectNextVsyncTime);
    std::lock_guard<std::mutex> locker(mutex_);
    if ((vsyncMode_ != VSYNC_MODE_LTPO) && (pendingVsyncMode_ != VSYNC_MODE_LTPO)) {
        ScopedBytrace trace("it's not ltpo mode.");
        return VSYNC_ERROR_NOT_SUPPORT;
    }
    if (pulse_ == 0) {
        ScopedBytrace trace("pulse is not ready!!!");
        VLOGE("pulse is not ready!!!");
        return VSYNC_ERROR_API_FAILED;
    }

    VsyncError ret = SetExpectNextVsyncTimeInternal(expectNextVsyncTime);

    if ((generatorRefreshRate <= 0 || (VSYNC_MAX_REFRESHRATE % generatorRefreshRate != 0))) {
        RS_TRACE_NAME_FMT("Not support this refresh rate: %u", generatorRefreshRate);
        VLOGE("Not support this refresh rate: %{public}u", generatorRefreshRate);
        return VSYNC_ERROR_NOT_SUPPORT;
    }

    if (changingRefreshRates_.cb == nullptr) {
        changingRefreshRates_ = listenerRefreshRates;
    } else {
        UpdateChangeRefreshRatesLocked(listenerRefreshRates);
    }
    needChangeRefreshRates_ = true;

    changingPhaseOffset_ = listenerPhaseOffset;
    needChangePhaseOffset_ = true;

    if (generatorRefreshRate != currRefreshRate_) {
        changingGeneratorRefreshRate_ = generatorRefreshRate;
        needChangeGeneratorRefreshRate_ = true;
    } else {
        RS_TRACE_NAME_FMT("refreshRateNotChanged, generatorRefreshRate:%u, currRefreshRate_:%u",
            generatorRefreshRate, currRefreshRate_);
    }

    waitForTimeoutCon_.notify_all();
    return ret;
}

void VSyncGenerator::UpdateChangeRefreshRatesLocked(const ListenerRefreshRateData &listenerRefreshRates)
{
    for (auto refreshRate : listenerRefreshRates.refreshRates) {
        bool found = false;
        for (auto it = changingRefreshRates_.refreshRates.begin();
             it != changingRefreshRates_.refreshRates.end(); it++) {
            if ((*it).first == refreshRate.first) { // first is linkerId
                (*it).second = refreshRate.second; // second is refreshRate
                found = true;
                break;
            }
        }
        if (!found) {
            changingRefreshRates_.refreshRates.push_back(refreshRate);
        }
    }
}

int64_t VSyncGenerator::GetVSyncPulse()
{
    std::lock_guard<std::mutex> locker(mutex_);
    return pulse_;
}

VsyncError VSyncGenerator::SetVSyncMode(VSyncMode vsyncMode)
{
    RS_TRACE_NAME_FMT("SetVSyncMode:%d", vsyncMode);
    std::lock_guard<std::mutex> locker(mutex_);
    pendingVsyncMode_ = vsyncMode;
    return VSYNC_ERROR_OK;
}

VSyncMode VSyncGenerator::GetVSyncMode()
{
    std::lock_guard<std::mutex> locker(mutex_);
    return vsyncMode_;
}

VsyncError VSyncGenerator::SetVSyncPhaseByPulseNum(int32_t phaseByPulseNum)
{
    std::lock_guard<std::mutex> locker(mutex_);
    referenceTimeOffsetPulseNum_ = phaseByPulseNum;
    defaultReferenceTimeOffsetPulseNum_ = phaseByPulseNum;
    return VSYNC_ERROR_OK;
}

VsyncError VSyncGenerator::SetReferenceTimeOffset(int32_t offsetByPulseNum)
{
    std::lock_guard<std::mutex> locker(mutex_);
    referenceTimeOffsetPulseNum_ = offsetByPulseNum;
    return VSYNC_ERROR_OK;
}

VsyncError VSyncGenerator::StartRefresh()
{
    RS_TRACE_NAME("StartRefresh");
    std::lock_guard<std::mutex> lock(mutex_);
    startRefresh_ = true;
    referenceTimeOffsetPulseNum_ = defaultReferenceTimeOffsetPulseNum_;
    return VSYNC_ERROR_OK;
}

void VSyncGenerator::SetRSDistributor(sptr<VSyncDistributor> &rsVSyncDistributor)
{
    rsVSyncDistributor_ = rsVSyncDistributor;
}

void VSyncGenerator::SetAppDistributor(sptr<VSyncDistributor> &appVSyncDistributor)
{
    appVSyncDistributor_ = appVSyncDistributor;
}

void VSyncGenerator::PeriodCheckLocked(int64_t hardwareVsyncInterval)
{
    if (lastPeriod_ == period_) {
        if (abs(hardwareVsyncInterval - period_) > PERIOD_CHECK_THRESHOLD) {
            // if software period not changed, and hardwareVsyncInterval,
            // and software period is not the same, accumulate counter
            periodCheckCounter_++;
            RS_TRACE_NAME_FMT("CounterAccumulated, lastPeriod_:%ld, period_:%ld, hardwareVsyncInterval:%ld,"
                " periodCheckCounter_:%d", lastPeriod_, period_, hardwareVsyncInterval, periodCheckCounter_);
        }
    } else {
        // if period changed, record this period as lastPeriod_ and clear periodCheckCounter_
        lastPeriod_ = period_;
        periodCheckCounter_ = 0;
        RS_TRACE_NAME("periodCheckCounter_ = 0");
    }
    // exit frameRateChanging status when the frame rate is inconsistent for 10 consecutive times.
    if (periodCheckCounter_ > 10) {
        RS_TRACE_NAME_FMT("samePeriodCounter ERROR, period_:%ld, hardwareVsyncInterval:%ld, pendingReferenceTime_:%ld"
            ", referenceTime_:%ld, referenceTimeDiff:%ld", period_, hardwareVsyncInterval, pendingReferenceTime_,
            referenceTime_, abs(pendingReferenceTime_ - referenceTime_));
        VLOGE("samePeriodCounter ERROR, period_:" VPUBI64 ", hardwareVsyncInterval:" VPUBI64
            ", pendingReferenceTime_:" VPUBI64 ", referenceTime_:" VPUBI64 ", referenceTimeDiff:" VPUBI64,
            period_, hardwareVsyncInterval, pendingReferenceTime_, referenceTime_,
            abs(pendingReferenceTime_ - referenceTime_));
        // end the frameRateChanging status
        frameRateChanging_ = false;
        ScopedBytrace forceEnd("frameRateChanging_ = false, forceEnd");
    }
}

void VSyncGenerator::CalculateReferenceTimeOffsetPulseNumLocked(int64_t referenceTime)
{
    int64_t actualOffset = referenceTime - pendingReferenceTime_;
    int32_t actualOffsetPulseNum = round((double)actualOffset/(double)pulse_);
    if (startRefresh_ || (defaultReferenceTimeOffsetPulseNum_ == 0)) {
        referenceTimeOffsetPulseNum_ = defaultReferenceTimeOffsetPulseNum_;
    } else {
        referenceTimeOffsetPulseNum_ = std::max(actualOffsetPulseNum, defaultReferenceTimeOffsetPulseNum_);
    }
    RS_TRACE_NAME_FMT("UpdateMode, referenceTime:%ld, actualOffsetPulseNum:%d, referenceTimeOffsetPulseNum_:%d"
        ", startRefresh_:%d, period:%ld", referenceTime, actualOffsetPulseNum, referenceTimeOffsetPulseNum_,
        startRefresh_, pendingPeriod_);
}

VsyncError VSyncGenerator::CheckAndUpdateReferenceTime(int64_t hardwareVsyncInterval, int64_t referenceTime)
{
    if (hardwareVsyncInterval < 0 || referenceTime < 0) {
        VLOGE("wrong parameter, hardwareVsyncInterval:" VPUBI64 ", referenceTime:" VPUBI64,
                hardwareVsyncInterval, referenceTime);
        return VSYNC_ERROR_INVALID_ARGUMENTS;
    }
    std::lock_guard<std::mutex> locker(mutex_);
    if ((pendingPeriod_ <= 0 && targetPeriod_ <= 0) || pulse_ == 0) {
        frameRateChanging_ = false;
        VLOGE("[%{public}s] Failed, pendingPeriod_:" VPUBI64 ", targetPeriod_:" VPUBI64 ", pulse_:" VPUBI64,
            __func__, pendingPeriod_, targetPeriod_, pulse_);
        return VSYNC_ERROR_API_FAILED;
    }

    PeriodCheckLocked(hardwareVsyncInterval);

    if (((abs(hardwareVsyncInterval - pendingPeriod_) < PERIOD_CHECK_THRESHOLD) &&
        (abs(hardwareVsyncInterval - targetPeriod_) < PERIOD_CHECK_THRESHOLD || targetPeriod_ == 0))) {
        // framerate has changed
        frameRateChanging_ = false;
        ScopedBytrace changeEnd("frameRateChanging_ = false");
        CalculateReferenceTimeOffsetPulseNumLocked(referenceTime);
        UpdateReferenceTimeLocked(referenceTime);
        bool needNotify = true;
        uint32_t periodRefreshRate = CalculateRefreshRate(period_);
        uint32_t pendingPeriodRefreshRate = CalculateRefreshRate(pendingPeriod_);
        // 120hz, 90hz, 60hz
        if (((periodRefreshRate == 120) || (periodRefreshRate == 90)) && (pendingPeriodRefreshRate == 60)) {
            needNotify = false;
        }
        if ((periodRefreshRate != 0) && (periodRefreshRate == pendingPeriodRefreshRate)) {
            RS_TRACE_NAME_FMT("period not changed, period:%ld", period_);
            needNotify = false;
        } else {
            UpdatePeriodLocked(pendingPeriod_);
        }
        if (needNotify) {
            waitForTimeoutCon_.notify_all();
        }
        pendingPeriod_ = 0;
        targetPeriod_ = 0;
        startRefresh_ = false;
    }
    return VSYNC_ERROR_OK;
}

VsyncError VSyncGenerator::RemoveListener(const sptr<OHOS::Rosen::VSyncGenerator::Callback>& cb)
{
    ScopedBytrace func("RemoveListener");
    std::lock_guard<std::mutex> locker(mutex_);
    if (cb == nullptr) {
        return VSYNC_ERROR_INVALID_ARGUMENTS;
    }
    bool removeFlag = false;
    auto it = listeners_.begin();
    for (; it < listeners_.end(); it++) {
        if (it->callback_ == cb) {
            listeners_.erase(it);
            removeFlag = true;
            break;
        }
    }
    if (!removeFlag) {
        return VSYNC_ERROR_INVALID_ARGUMENTS;
    }
    return VSYNC_ERROR_OK;
}

VsyncError VSyncGenerator::ChangePhaseOffset(const sptr<OHOS::Rosen::VSyncGenerator::Callback>& cb, int64_t offset)
{
    std::lock_guard<std::mutex> locker(mutex_);
    if (cb == nullptr) {
        return VSYNC_ERROR_INVALID_ARGUMENTS;
    }
    auto it = listeners_.begin();
    for (; it < listeners_.end(); it++) {
        if (it->callback_ == cb) {
            break;
        }
    }
    if (it != listeners_.end()) {
        it->phase_ = offset;
    } else {
        return VSYNC_ERROR_INVALID_OPERATING;
    }
    return VSYNC_ERROR_OK;
}

bool VSyncGenerator::IsEnable()
{
    std::lock_guard<std::mutex> locker(mutex_);
    return period_ > 0;
}

bool VSyncGenerator::GetFrameRateChaingStatus()
{
    std::lock_guard<std::mutex> locker(mutex_);
    return frameRateChanging_;
}

void VSyncGenerator::SetFrameRateChangingStatus(bool frameRateChanging)
{
    std::lock_guard<std::mutex> locker(mutex_);
    frameRateChanging_ = frameRateChanging;
}

void VSyncGenerator::SetPendingMode(int64_t period, int64_t timestamp)
{
    if (period <= 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    pendingPeriod_ = period;
    pendingReferenceTime_ = timestamp;
    rsVSyncDistributor_->UpdatePendingReferenceTime(pendingReferenceTime_);
}

void VSyncGenerator::Dump(std::string &result)
{
    std::unique_lock<std::mutex> lock(mutex_);
    result.append("\n-- VSyncGenerator --");
    result += "\nperiod:" + std::to_string(period_);
    result += "\nphase:" + std::to_string(phase_);
    result += "\nreferenceTime:" + std::to_string(referenceTime_);
    result += "\nvsyncMode:" + std::to_string(vsyncMode_);
    result += "\nperiodCheckCounter_:" + std::to_string(periodCheckCounter_);
}
} // namespace impl
sptr<VSyncGenerator> CreateVSyncGenerator()
{
    return impl::VSyncGenerator::GetInstance();
}

void DestroyVSyncGenerator()
{
    impl::VSyncGenerator::DeleteInstance();
}
}
}
