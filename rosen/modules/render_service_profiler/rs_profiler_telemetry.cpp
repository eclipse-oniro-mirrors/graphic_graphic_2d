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

#include "rs_profiler_telemetry.h"

#include <format>
#include <fstream>

#include "developtools/profiler/host/smartperf/client/client_command/include/CPU.h"
#include "developtools/profiler/host/smartperf/client/client_command/include/sp_utils.h"
#include "rs_profiler_utils.h"

#define ToGHz(X) (X) * 1e-6f
#define ToGB(X) (X) * 1e-6

namespace OHOS::Rosen {

static std::string GetMetric(const std::string& name)
{
    std::string metric("0");
    SmartPerf::SPUtils::LoadFile(name, metric);
    return metric;
}

static float GetMetricFloat(const std::string& name)
{
    return std::stof(GetMetric(name));
}

static std::string GetCPUTemperatureMetric()
{
    std::vector<std::string> directories;
    SmartPerf::SPUtils::ForDirFiles("/sys/class/thermal", directories);

    std::string type;
    for (const std::string& directory : directories) {
        SmartPerf::SPUtils::LoadFile(directory + "/type", type);
        if (type.find("soc_thermal") != std::string::npos) {
            return directory + "/temp";
        }
    }

    return "";
}

static void GetCPUTemperature(CPUInfo& cpu)
{
    static const std::string TEMPERATURE_METRIC = GetCPUTemperatureMetric();
    cpu.temperature_ = GetMetricFloat(TEMPERATURE_METRIC) * 1e-3F;
}

static void GetCPUCurrent(CPUInfo& cpu)
{
    cpu.current_ = GetMetricFloat("/sys/class/power_supply/Battery/current_now") * 1e-6F;
}

static void GetCPUVoltage(CPUInfo& cpu)
{
    cpu.voltage_ = GetMetricFloat("/sys/class/power_supply/Battery/voltage_now") * 1e-6F;
}

static void GetCPUMemory(CPUInfo& cpu)
{
    std::ifstream memoryFile("/proc/meminfo", std::ios::in);
    if (!memoryFile) {
        return;
    }

    struct {
        const char* name_;
        uint64_t& value_;
    } properties[] = {
        { "MemTotal", cpu.ramTotal_ },
        { "MemFree", cpu.ramFree_ },
    };

    const size_t propertyCount = sizeof(properties) / sizeof(properties[0]);

    size_t found = 0U;
    std::string line;
    while (getline(memoryFile, line, '\n') && (found < propertyCount)) {
        if (line.find(properties[found].name_) != std::string::npos) {
            properties[found].value_ = std::stoull(SmartPerf::SPUtils::ExtractNumber(line));
            found++;
        }
    }
}

static void GetCPUCores(CPUInfo& cpu)
{
    SmartPerf::CPU& cpuPerf = SmartPerf::CPU::GetInstance();

    const std::vector<SmartPerf::CpuFreqs> frequency = cpuPerf.GetCpuFreq();
    const std::vector<SmartPerf::CpuUsageInfos> usage = cpuPerf.GetCpuUsage();

    cpu.cores_ = std::min(CPUInfo::MAX_CORE_COUNT, static_cast<uint32_t>(frequency.size()));

    for (uint32_t i = 0; i < cpu.cores_; i++) {
        // Frequency
        const uint32_t frequencyCpuId = std::min(static_cast<uint32_t>(frequency[i].cpuId), cpu.cores_ - 1U);
        cpu.coreFrequency_[frequencyCpuId] = frequency[i].curFreq * 1e-6F;

        // Load
        const uint32_t loadCpuId = std::min(static_cast<uint32_t>(std::atoi(usage[i].cpuId.data())), cpu.cores_ - 1U);
        cpu.coreLoad_[loadCpuId] = usage[i].userUsage + usage[i].niceUsage + usage[i].systemUsage + usage[i].idleUsage +
                                   usage[i].ioWaitUsage + usage[i].irqUsage + usage[i].softIrqUsage;
    }
}

static void GetGPUFrequency(GPUInfo& gpu)
{
    static const std::string PATHS[] = {
        "/sys/class/devfreq/fde60000.gpu/cur_freq",
        "/sys/class/devfreq/gpufreq/cur_freq",
    };

    std::string frequency;
    for (const auto& path : PATHS) {
        if (SmartPerf::SPUtils::LoadFile(path, frequency)) {
            break;
        }
    }

    gpu.frequency_ = std::stof(frequency) * 1e-9F;
}

static void GetGPULoad(GPUInfo& gpu)
{
    static const std::string PATHS[] = {
        "/sys/class/devfreq/gpufreq/gpu_scene_aware/utilisation",
        "/sys/class/devfreq/fde60000.gpu/load",
    };

    std::string load;
    for (const auto& path : PATHS) {
        if (SmartPerf::SPUtils::LoadFile(path, load)) {
            break;
        }
    }

    std::vector<std::string> splits;
    SmartPerf::SPUtils::StrSplit(load, "@", splits);

    gpu.load_ = std::stof(splits.empty() ? load : splits[0]);
}

const DeviceInfo& Telemetry::GetDeviceInfo()
{
    static DeviceInfo info;

    // cpu
    GetCPUTemperature(info.cpu_);
    GetCPUCurrent(info.cpu_);
    GetCPUVoltage(info.cpu_);
    GetCPUMemory(info.cpu_);
    GetCPUCores(info.cpu_);

    // gpu
    GetGPUFrequency(info.gpu_);
    GetGPULoad(info.gpu_);

    return info;
}

static std::string TemperatureToString(float temperature)
{
    return std::to_string(temperature) + " °C";
}

static std::string CurrentToString(float current)
{
    return std::to_string(current) + " mA";
}

static std::string VoltageToString(float voltage)
{
    return std::to_string(voltage) + " V";
}

static std::string MemoryToString(uint64_t memory)
{
    return std::to_string(memory * 1e-6) + " GB";
}

static std::string FrequencyLoadToString(float frequency, float load)
{
    return std::to_string(frequency) + " GHz (" + std::to_string(load) + " %)";
}

std::string Telemetry::GetDeviceInfoString()
{
    const DeviceInfo info = GetDeviceInfo();

    std::string string;
    for (size_t i = 0; i < info.cpu_.cores_; i++) {
        string += +"\nCPU" + std::to_string(i) + ": " +
                  FrequencyLoadToString(info.cpu_.coreFrequency_[i], info.cpu_.coreLoad_[i]);
    }

    string +=
        "\nTemperature: " + TemperatureToString(info.cpu_.temperature_) +
        "\nCurrent: " + CurrentToString(info.cpu_.current_) + "\nVoltage: " + VoltageToString(info.cpu_.voltage_) +
        "\nRAM Total: " + MemoryToString(info.cpu_.ramTotal_) + "\nRAM Free: " + MemoryToString(info.cpu_.ramFree_) +
        "\nGPU: " + FrequencyLoadToString(info.gpu_.frequency_, info.gpu_.load_);

    return string;
}

} // namespace OHOS::Rosen