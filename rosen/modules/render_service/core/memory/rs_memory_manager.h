/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef RS_MEMORY_MANAGER_H
#define RS_MEMORY_MANAGER_H
#include <vector>

#include "image/gpu_context.h"

#include "memory/rs_dfx_string.h"
#include "memory/rs_memory_graphic.h"
#include "memory/rs_memory_snapshot.h"
#include "memory/rs_memory_track.h"
#include "pipeline/rs_surface_render_node.h"

namespace OHOS::Rosen {

class MemoryManager {
public:
    static void DumpMemoryUsage(DfxString& log, std::string& type);
    static void DumpPidMemory(DfxString& log, int pid, const Drawing::GPUContext* gpuContext);
    static void DumpDrawingGpuMemory(DfxString& log, const Drawing::GPUContext* grContext,
        std::vector<std::pair<NodeId, std::string>>& nodeTags);
    // Count memory for hidumper
    static MemoryGraphic CountPidMemory(int pid, const Drawing::GPUContext* gpuContext);
    static void CountMemory(std::vector<pid_t> pids,
        const Drawing::GPUContext* gpuContext, std::vector<MemoryGraphic>& mems);
    static void ReleaseUnlockGpuResource(Drawing::GPUContext* gpuContext, NodeId surfaceNodeId);
    static void ReleaseUnlockGpuResource(Drawing::GPUContext* gpuContext, pid_t pid);
    static void ReleaseUnlockGpuResource(Drawing::GPUContext* gpuContext, Drawing::GPUResourceTag& tag);
    static void ReleaseUnlockGpuResource(Drawing::GPUContext* gpuContext, std::set<pid_t> exitedPidSet);
    static void PurgeCacheBetweenFrames(Drawing::GPUContext* gpuContext, bool scratchResourceOnly,
        std::set<pid_t>& exitedPidSet, std::set<pid_t>& protectedPidSet);
    static void ReleaseAllGpuResource(Drawing::GPUContext* gpuContext, pid_t pid);
    static void ReleaseAllGpuResource(Drawing::GPUContext* gpuContext, Drawing::GPUResourceTag& tag);
    static void ReleaseUnlockGpuResource(Drawing::GPUContext* grContext, bool scratchResourcesOnly = true);
    static void ReleaseUnlockAndSafeCacheGpuResource(Drawing::GPUContext* grContext);
    static float GetAppGpuMemoryInMB(Drawing::GPUContext* gpuContext);
    static void InitMemoryLimit(Drawing::GPUContext* gpuContext);
    static void MemoryOverCheck(Drawing::GPUContext* gpuContext);
    static void MemoryOverflow(pid_t pid, size_t overflowMemory, bool isGpu);
    static void VmaDefragment(Drawing::GPUContext* gpuContext);

private:
    // rs memory = rs + skia cpu + skia gpu
    static void DumpRenderServiceMemory(DfxString& log);
    static void DumpDrawingCpuMemory(DfxString& log);
    static void DumpGpuCache(DfxString& log, const Drawing::GPUContext* gpuContext,
        Drawing::GPUResourceTag* tag, std::string& name);
    static void DumpAllGpuInfo(DfxString& log, const Drawing::GPUContext* grContext,
        std::vector<std::pair<NodeId, std::string>>& nodeTags);
    //jemalloc info
    static void DumpMallocStat(std::string& log);
    static void MemoryOverReport(const pid_t pid, const MemorySnapshotInfo& info, const std::string& bundleName,
        const std::string& reportName);
    static void TotalMemoryOverReport(const std::unordered_map<pid_t, MemorySnapshotInfo>& infoMap);
    static void ErasePidInfo(const std::set<pid_t>& exitedPidSet);

    static std::mutex mutex_;
    static std::unordered_map<pid_t, std::pair<std::string, uint64_t>> pidInfo_;
    static uint32_t frameCount_;
    static uint64_t memoryWarning_;
    static uint64_t totalMemoryReportTime_;
};
} // namespace OHOS::Rosen
#endif