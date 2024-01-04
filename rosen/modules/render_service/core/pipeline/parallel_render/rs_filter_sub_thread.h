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

#ifndef RENDER_SERVICE_CORE_PIPELINE_PARALLEL_RENDER_RS_FILTER_SUB_THREAD_H
#define RENDER_SERVICE_CORE_PIPELINE_PARALLEL_RENDER_RS_FILTER_SUB_THREAD_H

#include <cstdint>

#include "EGL/egl.h"
#include "EGL/eglext.h"
#include "include/core/SkSurface.h"
#if defined(NEW_SKIA)
#include "include/gpu/GrDirectContext.h"
#else
#include "include/gpu/GrContext.h"
#endif
#include "event_handler.h"

#include "pipeline/parallel_render/rs_render_task.h"
#include "render_context/render_context.h"
#include "property/rs_color_picker_cache_task.h"

namespace OHOS::Rosen {
class RSFilterSubThread {
public:
    explicit RSFilterSubThread(RenderContext* context) : renderContext_(context) {}
    ~RSFilterSubThread();

    void Start();
    void StartColorPicker();
    void PostTask(const std::function<void()>& task);
    void PostSyncTask(const std::function<void()>& task);
    void RenderCache(std::vector<std::weak_ptr<RSFilter::RSFilterTask>>& filterTaskList);
    void FlushAndSubmit();
    void SetFence(sptr<SyncFence> fence);
    void ColorPickerRenderCache(std::weak_ptr<RSColorPickerCacheTask> colorPickerTask);

    void ResetGrContext();
    void DumpMem(DfxString& log);
    float GetAppGpuMemoryInMB();

private:
    const uint32_t SYNC_TIME_OUT = 1000;
    void CreateShareEglContext();
    void DestroyShareEglContext();
#ifndef USE_ROSEN_DRAWING
#ifdef NEW_SKIA
    sk_sp<GrDirectContext> CreateShareGrContext();
#else
    sk_sp<GrContext> CreateShareGrContext();
#endif
#else
    std::shared_ptr<Drawing::GPUContext> CreateShareGrContext();
#endif
    std::atomic<bool> isWorking_ = false;
    sptr<SyncFence> fence_ = nullptr;
    std::vector<std::weak_ptr<RSFilter::RSFilterTask>> filterTaskList_;
    std::vector<std::weak_ptr<RSFilter::RSFilterTask>> filterReadyTaskList_;
    uint32_t threadIndex_ = 0;
    std::shared_ptr<AppExecFwk::EventRunner> runner_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    RenderContext* renderContext_ = nullptr;
#ifdef RS_ENABLE_GL
    EGLContext eglShareContext_ = EGL_NO_CONTEXT;
#endif
#ifndef USE_ROSEN_DRAWING
#ifdef NEW_SKIA
    sk_sp<GrDirectContext> grContext_ = nullptr;
#else
    sk_sp<GrContext> grContext_ = nullptr;
#endif
#else
    std::shared_ptr<Drawing::GPUContext> grContext_ = nullptr;
#endif
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_CORE_PIPELINE_PARALLEL_RENDER_RS_FILTER_SUB_THREAD_H