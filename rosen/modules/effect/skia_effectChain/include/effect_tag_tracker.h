/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef EFFECT_TAG_TRACKER_H
#define EFFECT_TAG_TRACKER_H

#include <cstdint>
#include <memory>
#include <string>

#include "image/gpu_context.h"
#include "image/trace_memory_dump.h"

namespace OHOS::Rosen {

// fSid value identifying GPU resources allocated by the effect module.
static constexpr uint32_t EFFECT_MODULE_TAG = 1001;

class EffectTagTracker {
public:
    explicit EffectTagTracker(const std::shared_ptr<Drawing::GPUContext>& gpuContext);
    EffectTagTracker(const std::shared_ptr<Drawing::GPUContext>& gpuContext,
        uint32_t customTagId, const std::string& customTagName);
    ~EffectTagTracker();

    void SetTagEnd();

    static void SetEnabled(bool enabled);

    static Drawing::GPUResourceTag GetCurrentGpuResourceTag(Drawing::GPUContext* gpuContext);

    Drawing::GPUResourceTag GetCurrentGpuResourceTag() const;

    std::shared_ptr<Drawing::GPUContext> GetGpuContext() const;

    void DumpMemoryStatisticsByTag(Drawing::TraceMemoryDump* traceMemoryDump, Drawing::GPUResourceTag& tag) const;

    static void DumpMemoryStatisticsByTag(Drawing::GPUContext* gpuContext,
        Drawing::TraceMemoryDump* traceMemoryDump, Drawing::GPUResourceTag& tag);

    Drawing::GPUResourceTag GetTag() const;

    bool GetGpuMemoryStatistics(std::string& result) const;

private:
    bool isSetTagEnd_ = false;
    std::shared_ptr<Drawing::GPUContext> gpuContext_ = nullptr;
    Drawing::GPUResourceTag tag_{};
};

} // namespace OHOS::Rosen

#endif // EFFECT_TAG_TRACKER_H