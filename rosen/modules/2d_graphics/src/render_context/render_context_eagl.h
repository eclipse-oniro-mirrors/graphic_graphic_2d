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

#ifndef RENDER_CONTEXT_EAGL_H
#define RENDER_CONTEXT_EAGL_H

#include <memory>
#include <mutex>
#include "common/rs_rect.h"

#include "OpenGLES/EAGL.h"
#include "OpenGLES/ES2/gl.h"
#include "OpenGLES/ES2/glext.h"
#include "QuartzCore/CAEAGLLayer.h"

#include "include/core/SkCanvas.h"
#include "include/core/SkColorSpace.h"
#include "include/core/SkImageInfo.h"
#include "include/core/SkSurface.h"
#include "include/gpu/GrBackendSurface.h"
#include "include/gpu/GrContext.h"
#include "include/gpu/gl/GrGLInterface.h"

#include "render_context/render_context.h"
#include "render_context_egl_defines.h"
#ifndef ROSEN_CROSS_PLATFORM
#include "surface_type.h"
#endif

namespace OHOS {
namespace Rosen {
class RenderContextEAGL : public RenderContext {
public:
    RenderContextEAGL();
    ~RenderContextEAGL();

    sk_sp<SkSurface> AcquireSurface(int width, int height) override;
    void MakeCurrent(void* surface = nullptr, void* context = EGL_NO_CONTEXT) override;
    void InitializeEglContext() override;
    bool SetUpGrContext() override;
    GrContext* GetGrContext() const override;
    void RenderFrame() override;
    EGLSurface CreateEGLSurface(EGLNativeWindowType eglNativeWindow) override;
    sk_sp<SkSurface> GetSurface() const override {
        return skSurface_;
    };

    bool ResourceMakeCurrent();
    void SwapBuffers(EGLSurface surface = nullptr) const override;

    bool UpdateStorageSizeIfNecessary();
    sk_sp<SkColorSpace> ColorSpace() const { return color_space_; }

private:
    sk_sp<SkSurface> skSurface_ = nullptr;
    sk_sp<GrContext> grContext_ = nullptr;
    sk_sp<SkColorSpace> color_space_ = nullptr;

    EAGLContext *context_ = nullptr;
    EAGLContext *resource_context_ = nullptr;

    void *layer_ = nullptr;

    GLuint framebuffer_ = 0;
    GLuint colorbuffer_ = 0;
    GLint storage_size_width_ = 0;
    GLint storage_size_height_ = 0;
    bool valid_ = false;
};
} // namespace Rosen
} // namespace OHOS
#endif
