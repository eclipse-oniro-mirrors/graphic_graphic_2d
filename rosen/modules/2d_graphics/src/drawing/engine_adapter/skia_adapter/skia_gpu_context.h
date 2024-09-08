/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.. All rights reserved.
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

#ifndef SKIA_GPUCONTEXT_H
#define SKIA_GPUCONTEXT_H

#include <unordered_map>
#include <array>

#include "include/core/SkExecutor.h"
#include "include/gpu/GrContextOptions.h"
#include "include/gpu/GrDirectContext.h"

#include "image/gpu_context.h"
#include "impl_interface/gpu_context_impl.h"


namespace OHOS {
namespace Rosen {
namespace Drawing {
class SkiaPersistentCache : public GrContextOptions::PersistentCache {
public:
    explicit SkiaPersistentCache(GPUContextOptions::PersistentCache* cache);
    ~SkiaPersistentCache() {}

    sk_sp<SkData> load(const SkData& key) override;
    void store(const SkData& key, const SkData& data) override;
private:
    GPUContextOptions::PersistentCache* cache_;
};

class SkiaGPUContext : public GPUContextImpl {
public:
    static inline constexpr AdapterType TYPE = AdapterType::SKIA_ADAPTER;

    SkiaGPUContext();
    ~SkiaGPUContext() override = default;

    AdapterType GetType() const override
    {
        return AdapterType::SKIA_ADAPTER;
    }

    bool BuildFromGL(const GPUContextOptions& options) override;

    static std::unique_ptr<SkExecutor> threadPool;
    void InitSkExecutor();

#ifdef RS_ENABLE_VK
    bool BuildFromVK(const GrVkBackendContext& context) override;
    bool BuildFromVK(const GrVkBackendContext& context, const GPUContextOptions& options) override;
#endif

    void Flush() override;
    void FlushAndSubmit(bool syncCpu) override;
    void Submit() override;
    void PerformDeferredCleanup(std::chrono::milliseconds msNotUsed) override;

    void GetResourceCacheLimits(int* maxResource, size_t* maxResourceBytes) const override;
    void SetResourceCacheLimits(int maxResource, size_t maxResourceBytes) override;

    void GetResourceCacheUsage(int* resourceCount, size_t* resourceBytes) const override;

    void FreeGpuResources() override;

    void DumpGpuStats(std::string& out) override;

    void ReleaseResourcesAndAbandonContext() override;

    void PurgeUnlockedResources(bool scratchResourcesOnly) override;

    void PurgeUnlockedResourcesByTag(bool scratchResourcesOnly, const GPUResourceTag &tag) override;

    void PurgeUnlockedResourcesByPid(bool scratchResourcesOnly, const std::set<pid_t>& exitedPidSet) override;

    void PurgeUnlockAndSafeCacheGpuResources() override;

    void ReleaseByTag(const GPUResourceTag &tag) override;

    void PurgeCacheBetweenFrames(bool scratchResourcesOnly, const std::set<pid_t>& exitedPidSet,
        const std::set<pid_t>& protectedPidSet) override;

    void ResetContext() override;

    void DumpMemoryStatisticsByTag(TraceMemoryDump* traceMemoryDump, GPUResourceTag &tag) override;

    void DumpMemoryStatistics(TraceMemoryDump* traceMemoryDump) override;

    void SetCurrentGpuResourceTag(const GPUResourceTag &tag) override;

#ifdef RS_ENABLE_VK
    void StoreVkPipelineCacheData() override;
#endif

    sk_sp<GrDirectContext> GetGrContext() const;
    void SetGrContext(const sk_sp<GrDirectContext>& grContext);
    const sk_sp<GrDirectContext> ExportSkiaContext() const
    {
        return grContext_;
    }
    void RegisterPostFunc(const std::function<void(const std::function<void()>& task)>& func) override;

    static std::function<void(const std::function<void()>& task)> GetPostFunc(sk_sp<GrDirectContext> grContext);

    void VmaDefragment() override;
private:
    sk_sp<GrDirectContext> grContext_;
    std::shared_ptr<SkiaPersistentCache> skiaPersistentCache_;
    static std::unordered_map<uintptr_t, std::function<void(const std::function<void()>& task)>> contextPostMap_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif // SKIA_GPUCONTEXT_H
