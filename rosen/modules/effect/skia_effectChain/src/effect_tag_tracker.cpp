/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "effect_tag_tracker.h"

#include <atomic>
#include <string>
#include <unistd.h>

#include "memory/rs_dfx_string.h"

namespace OHOS::Rosen {
namespace {
static std::atomic<bool> g_enabled = true;
}

EffectTagTracker::EffectTagTracker(const std::shared_ptr<Drawing::GPUContext>& gpuContext)
    : gpuContext_(gpuContext)
{
    Drawing::GPUResourceTag tag(static_cast<uint32_t>(getpid()),
        static_cast<uint32_t>(gettid()), 0, 0, "");
    tag.fSid = EFFECT_MODULE_TAG;
    tag_ = tag;
    if (!gpuContext_ || !g_enabled.load()) {
        return;
    }
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    gpuContext_->SetCurrentGpuResourceTag(tag);
#endif
}

EffectTagTracker::EffectTagTracker(const std::shared_ptr<Drawing::GPUContext>& gpuContext,
    uint32_t customTagId, const std::string& customTagName)
    : gpuContext_(gpuContext)
{
    Drawing::GPUResourceTag tag(static_cast<uint32_t>(getpid()),
        static_cast<uint32_t>(gettid()), 0, customTagId, customTagName);
    tag.fSid = EFFECT_MODULE_TAG;
    tag_ = tag;
    if (!gpuContext_ || !g_enabled.load()) {
        return;
    }
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    gpuContext_->SetCurrentGpuResourceTag(tag);
#endif
}

void EffectTagTracker::SetTagEnd()
{
    if (!gpuContext_ || !g_enabled.load()) {
        return;
    }
    isSetTagEnd_ = true;
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    Drawing::GPUResourceTag tagEnd(0, 0, 0, 0, "SetTagEnd");
    gpuContext_->SetCurrentGpuResourceTag(tagEnd);
#endif
}

EffectTagTracker::~EffectTagTracker()
{
    if (!g_enabled.load()) {
        return;
    }
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    if (!isSetTagEnd_ && gpuContext_) {
        Drawing::GPUResourceTag tagEnd(0, 0, 0, 0, "~EffectTagTracker");
        gpuContext_->SetCurrentGpuResourceTag(tagEnd);
    }
#endif
}

void EffectTagTracker::SetEnabled(bool enabled)
{
    g_enabled.store(enabled);
}

Drawing::GPUResourceTag EffectTagTracker::GetCurrentGpuResourceTag(Drawing::GPUContext* gpuContext)
{
    Drawing::GPUResourceTag tag;
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    if (gpuContext != nullptr) {
        tag = gpuContext->GetCurrentGpuResourceTag();
    }
#endif
    return tag;
}

std::shared_ptr<Drawing::GPUContext> EffectTagTracker::GetGpuContext() const
{
    return gpuContext_;
}

void EffectTagTracker::DumpMemoryStatisticsByTag(Drawing::GPUContext* gpuContext,
    Drawing::TraceMemoryDump* traceMemoryDump, Drawing::GPUResourceTag& tag)
{
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    if (gpuContext == nullptr || traceMemoryDump == nullptr) {
        return;
    }
    gpuContext->DumpMemoryStatisticsByTag(traceMemoryDump, tag);
#endif
}

Drawing::GPUResourceTag EffectTagTracker::GetCurrentGpuResourceTag() const
{
    Drawing::GPUResourceTag tag;
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    if (gpuContext_) {
        tag = gpuContext_->GetCurrentGpuResourceTag();
    }
#endif
    return tag;
}

Drawing::GPUResourceTag EffectTagTracker::GetTag() const
{
    return tag_;
}

void EffectTagTracker::DumpMemoryStatisticsByTag(
    Drawing::TraceMemoryDump* traceMemoryDump, Drawing::GPUResourceTag& tag) const
{
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    if (!gpuContext_ || traceMemoryDump == nullptr) {
        return;
    }
    gpuContext_->DumpMemoryStatisticsByTag(traceMemoryDump, tag);
#endif
}

bool EffectTagTracker::GetGpuMemoryStatistics(std::string& result) const
{
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    if (!gpuContext_) {
        return false;
    }
    Drawing::TraceMemoryDump gpuTracer("category", true);
    Drawing::GPUResourceTag tag = tag_;
    gpuContext_->DumpMemoryStatisticsByTag(&gpuTracer, tag);

    DfxString log;
    log.AppendFormat("=== EffectTagTracker GPU memory statistics ===\n");
    log.AppendFormat("  tagId=%u, tagName=%s\n", tag_.fFid, tag_.fName.c_str());
    log.AppendFormat("  pid=%u, tid=%u\n", tag_.fPid, tag_.fTid);
    gpuTracer.LogOutput(log);
    log.AppendFormat("Total GPU memory usage:\n");
    gpuTracer.LogTotals(log);

    result = log.GetString();
    return true;
#else
    return false;
#endif
}
} // namespace OHOS::Rosen