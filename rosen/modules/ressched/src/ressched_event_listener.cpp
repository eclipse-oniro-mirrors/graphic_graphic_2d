
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
#include <limits>

#include "ressched_event_listener.h"
#include "res_sched_client.h"
#include "res_type.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {

constexpr uint32_t DEFAULT_PID = 0;
constexpr uint32_t DEFAULT_TYPE = 0;
constexpr double EPSILON = 0.1;


std::once_flag ResschedEventListener::createFlag_;
sptr<ResschedEventListener> ResschedEventListener::instance_ = nullptr;
std::shared_ptr<ffrt::queue> ResschedEventListener::ffrtQueue_ = nullptr;
constexpr uint64_t SAMPLE_TIME = 100000000;
const std::string RS_RESSCHED_EVENT_LISTENER_QUEUE = "res_ressched_event_listener_queue";
sptr<ResschedEventListener> ResschedEventListener::GetInstance() noexcept
{
    std::call_once(createFlag_, []() {
        instance_ = new ResschedEventListener();
    });
    return instance_;
}

void ResschedEventListener::OnReceiveEvent(uint32_t eventType, uint32_t eventValue,
    std::unordered_map<std::string, std::string> extInfo)
{
    if (eventType == ResourceSchedule::ResType::EventType::EVENT_DRAW_FRAME_REPORT) {
        HandleDrawFrameEventReport(eventValue);
    } else if (eventType == ResourceSchedule::ResType::EventType::EVENT_FRAME_RATE_STATISTICS) {
        HandleFrameRateStatisticsReport(eventValue, extInfo);
    }
}

void ResschedEventListener::HandleDrawFrameEventReport(uint32_t eventValue)
{
    if (eventValue == ResourceSchedule::ResType::EventValue::EVENT_VALUE_DRAW_FRAME_REPORT_START) {
        isNeedReport_ = true;
        isFirstReport_ = true;
    } else if (eventValue == ResourceSchedule::ResType::EventValue::EVENT_VALUE_DRAW_FRAME_REPORT_STOP) {
        isNeedReport_ = false;
        isFirstReport_ = false;
    }
}


void ResschedEventListener::ReportFrameToRSS()
{
    if (GetIsNeedReport()) {
        uint64_t currTime = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        if (GetIsFirstReport() ||
            lastReportTime_ == 0 || currTime - lastReportTime_ >= SAMPLE_TIME) {
            RS_TRACE_BEGIN("ReportFrameToRSS");
            uint32_t type = OHOS::ResourceSchedule::ResType::RES_TYPE_SEND_FRAME_EVENT;
            int64_t value = 0;
            std::unordered_map<std::string, std::string> mapPayload;
            OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, value, mapPayload);
            SetIsFirstReport(false);
            lastReportTime_ = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            RS_TRACE_END();
        }
    }
}

bool ResschedEventListener::GetIsNeedReport() const
{
    return isNeedReport_.load();
}

bool ResschedEventListener::GetIsFirstReport() const
{
    return isFirstReport_.load();
}

void ResschedEventListener::SetIsFirstReport(bool value)
{
    isFirstReport_ = value;
}

void ResschedEventListener::HandleFrameRateStatisticsReport(uint32_t eventValue,
    std::unordered_map<std::string, std::string> extInfo)
{
    uint32_t pid = static_cast<uint32_t>(std::stoul(extInfo["pid"].c_str(), nullptr, 10));
    uint32_t type = static_cast<uint32_t>(std::stoul(extInfo["type"].c_str(), nullptr, 10));
    switch (eventValue) {
        case ResourceSchedule::ResType::EventValue::EVENT_VALUE_FRAME_RATE_STATISTICS_START:
            HandleFrameRateStatisticsBeginAsync(pid, type);
            break;
        case ResourceSchedule::ResType::EventValue::EVENT_VALUE_FRAME_RATE_STATISTICS_BREAK:
            HandleFrameRateStatisticsBreakAsync(pid, type);
            break;
        case ResourceSchedule::ResType::EventValue::EVENT_VALUE_FRAME_RATE_STATISTICS_END:
            HandleFrameRateStatisticsEndAsync(pid, type);
            break;
    }
}

void ResschedEventListener::ReportFrameRateToRSS(const std::unordered_map<std::string, std::string>& mapPayload)
{
    uint32_t type = ResourceSchedule::ResType::RES_TYPE_FRAME_RATE_REPORT_FROM_RS;
    int64_t value = ResourceSchedule::ResType::FrameRateReportState::FRAME_RATE_COMMON_REPORT;
    OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, value, mapPayload);
}

void ResschedEventListener::ReportFrameCountAsync(uint32_t pid)
{
    ffrtQueue_->submit([pid, this]() {
        if (currentType_ == DEFAULT_TYPE) {
            return;
        }
        if (pid != currentPid_.load()) {
            return;
        }
        if (isFrameRateFirstReport_) {
            isFrameRateFirstReport_ = false;
            beginTimeStamp_ = std::chrono::steady_clock::now();
        }
        endTimeStamp_ = std::chrono::steady_clock::now();
        frameCountNum_++;
    });
}

void ResschedEventListener::HandleFrameRateStatisticsBeginAsync(uint32_t pid, uint32_t type)
{
    ffrtQueue_->submit([pid, type, this]() {
        RS_TRACE_BEGIN("HandleFrameRateStatisticsBeginAsync");
        currentPid_.store(pid);
        currentType_ = type;
        frameCountNum_ = 0;
        isFrameRateFirstReport_ = true;
        RS_TRACE_END();
    });
}

void ResschedEventListener::HandleFrameRateStatisticsBreakAsync(uint32_t pid, uint32_t type)
{
    if (pid == currentPid_.load()) {
        ffrtQueue_->submit([this]() {
            RS_TRACE_BEGIN("HandleFrameRateStatisticsBreakAsync");
            currentPid_.store(DEFAULT_PID);
            currentType_ = DEFAULT_TYPE;
            RS_TRACE_END();
        });
    }
}

void ResschedEventListener::HandleFrameRateStatisticsEndAsync(uint32_t pid, uint32_t type)
{
    if (pid == currentPid_.load()) {
        ffrtQueue_->submit([this]() {
            RS_TRACE_BEGIN("HandleFrameRateStatisticsEndAsync");
            std::chrono::duration<double> durationTime = endTimeStamp_ - beginTimeStamp_;
            if (std::fabs(durationTime.count()) > EPSILON) {
                int32_t frameRate = static_cast<int32_t>(std::round(frameCountNum_/durationTime.count()));
                std::unordered_map<std::string, std::string> mapPayload;
                mapPayload["pid"] = std::to_string(currentPid_.load());
                mapPayload["type"] = std::to_string(currentType_);
                mapPayload["frameRate"] = std::to_string(frameRate);
                RS_TRACE_BEGIN("FrameRateStatistics ReportFrameRateToRSS");
                    ReportFrameRateToRSS(mapPayload);
                RS_TRACE_END();
            }
                currentPid_.store(DEFAULT_PID);
                currentType_ = DEFAULT_TYPE;
                RS_TRACE_END();
        });
    }
}

uint32_t ResschedEventListener::GetCurrentPid()
{
    return currentPid_.load();
}
} // namespace Rosen
} // namespace OHOS
