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

#include <thread>

#include "rs_profiler.h"
#include "rs_profiler_archive.h"
#include "rs_profiler_command.h"
#include "rs_profiler_file.h"
#include "rs_profiler_network.h"
#include "rs_profiler_packet.h"
#include "rs_profiler_telemetry.h"

namespace OHOS::Rosen {

static constexpr uint32_t INACTIVITY_THRESHOLD_SECONDS = 5u;
static DeviceInfo g_deviceInfo;
static std::mutex g_deviceInfoMutex;
static bool g_started = false;
static double g_inactiveTimestamp = 0.0;
static double g_recordsTimestamp = 0.0;
static double g_currentFrameDirtyRegion = 0.0;

// implemented in rs_profiler.cpp
void DeviceInfoToCaptureData(double time, const DeviceInfo& in, RSCaptureData& out);

static bool HasInitializationFinished()
{
    constexpr uint32_t maxAttempts = 600u;
    static uint32_t attempt = 0u;
    if (attempt < maxAttempts) {
        attempt++;
    }
    return attempt == maxAttempts;
}

static std::string GetBetaRecordFileName(uint32_t index)
{
    constexpr uint32_t ten = 10u;
    const std::string cacheFile("/data/service/el0/render_service/file");
    return cacheFile + ((index < ten) ? "0" : "") + std::to_string(index) + ".ohr";
}

bool RSProfiler::IsBetaRecordInactive()
{
    return (Now() - g_inactiveTimestamp) > INACTIVITY_THRESHOLD_SECONDS;
}

void RSProfiler::RequestVSyncOnBetaRecordInactivity()
{
    if (IsBetaRecordInactive()) {
        RequestNextVSync();
    }
}

void RSProfiler::LaunchBetaRecordNotificationThread()
{
    std::thread thread([]() {
        while (IsBetaRecordStarted()) {
            RequestVSyncOnBetaRecordInactivity();
            std::this_thread::sleep_for(std::chrono::seconds(INACTIVITY_THRESHOLD_SECONDS));
        }
    });
    thread.detach();
}

void RSProfiler::LaunchBetaRecordMetricsUpdateThread()
{
    if (!IsBetaRecordEnabledWithMetrics()) {
        return;
    }
    std::thread thread([]() {
        while (IsBetaRecordStarted()) {
            const DeviceInfo deviceInfo = RSTelemetry::GetDeviceInfo();

            g_deviceInfoMutex.lock();
            g_deviceInfo = deviceInfo;
            g_deviceInfoMutex.unlock();

            constexpr int32_t sendInterval = 8;
            std::this_thread::sleep_for(std::chrono::milliseconds(sendInterval));
        }
    });
    thread.detach();
}

void RSProfiler::StartBetaRecord()
{
    if (HasInitializationFinished() && !IsBetaRecordStarted() && IsBetaRecordEnabled()) {
        g_inactiveTimestamp = Now();
        g_recordsTimestamp = Now();

        LaunchBetaRecordNotificationThread();
        LaunchBetaRecordMetricsUpdateThread();

        // Start recording for the first file
        RecordStart(ArgList());

        g_started = true;
    }
}

void RSProfiler::StopBetaRecord()
{
    if (IsBetaRecordStarted()) {
        RecordStop(ArgList());
        g_started = false;
        g_inactiveTimestamp = 0;
    }
}

bool RSProfiler::IsBetaRecordStarted()
{
    return g_started;
}

void RSProfiler::SaveBetaRecord()
{
    constexpr double recordMaxLengthSeconds = 30.0;
    const auto recordLength = Now() - g_recordsTimestamp;
    if (!IsBetaRecordSavingTriggered() && (recordLength <= recordMaxLengthSeconds)) {
        return;
    }

    RecordStop(ArgList());
    EnableBetaRecord();
    RecordStart(ArgList());
}

void RSProfiler::UpdateBetaRecord()
{
    if (!IsBetaRecordStarted()) {
        return;
    }
    if (!IsBetaRecordEnabled()) {
        return;
    }

    if (!IsRecording()) {
        return;
    }

    SaveBetaRecord();

    // the last time any rendering is done
    if (g_currentFrameDirtyRegion > 0) {
        g_inactiveTimestamp = Now();
    }
}

bool RSProfiler::OpenBetaRecordFile(RSFile& file)
{
    if (!IsBetaRecordStarted()) {
        return false;
    }

    const auto path = "RECORD_IN_MEMORY";
    file.SetVersion(RSFILE_VERSION_LATEST);
    file.Create(path);

    g_recordsTimestamp = Now();
    return true;
}

bool RSProfiler::SaveBetaRecordFile(RSFile& file)
{
    if (!IsBetaRecordStarted()) {
        return false;
    }

    constexpr uint32_t maxCacheFiles = 10u;
    static uint32_t index = 0u;

    std::vector<uint8_t> data;
    if (!file.GetDataCopy(data)) {
        return false;
    }

    auto out = Utils::FileOpen(GetBetaRecordFileName(index), "wbe");
    if (Utils::IsFileValid(out)) {
        Utils::FileWrite(out, data.data(), data.size());
        Utils::FileClose(out);
    }

    index++;
    if (index >= maxCacheFiles) {
        index = 0u;
    }

    return true;
}

void RSProfiler::WriteBetaRecordMetrics(RSFile& file, double time)
{
    if (!IsBetaRecordStarted() || (time < 0.0) || !IsBetaRecordEnabledWithMetrics()) {
        return;
    }

    g_deviceInfoMutex.lock();
    const DeviceInfo deviceInfo = g_deviceInfo;
    g_deviceInfoMutex.unlock();

    RSCaptureData captureData;
    DeviceInfoToCaptureData(time, deviceInfo, captureData);

    std::vector<char> out;
    DataWriter archive(out);
    char headerType = static_cast<char>(PackageID::RS_PROFILER_GFX_METRICS);
    archive.Serialize(headerType);
    captureData.Serialize(archive);

    file.WriteGFXMetrics(0, time, 0, out.data(), out.size());
}

void RSProfiler::UpdateDirtyRegionBetaRecord(double currentFrameDirtyRegion)
{
    g_currentFrameDirtyRegion = currentFrameDirtyRegion;
}

} // namespace OHOS::Rosen