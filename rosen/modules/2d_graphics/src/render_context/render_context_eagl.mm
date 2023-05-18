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

#include "render_context_eagl.h"

#include <sstream>

#import <UIKit/UIKit.h>

#include "third_party/skia/include/gpu/gl/GrGLAssembleInterface.h"
#include "third_party/skia/include/gpu/GrContextOptions.h"

#include "rs_trace.h"
#include "memory/rs_tag_tracker.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
RenderContextEAGL::RenderContextEAGL()
{
    resource_context_ = [[EAGLContext alloc] initWithAPI:kEAGLRenderingAPIOpenGLES3];
    if (resource_context_ != nullptr) {
        context_ = [[EAGLContext alloc] initWithAPI:kEAGLRenderingAPIOpenGLES3
                                         sharegroup:resource_context_.sharegroup];
    } else {
        resource_context_ = [[EAGLContext alloc] initWithAPI:kEAGLRenderingAPIOpenGLES2];
        context_ = [[EAGLContext alloc] initWithAPI:kEAGLRenderingAPIOpenGLES2
                                         sharegroup:resource_context_.sharegroup];
    }

    if (resource_context_ == nullptr || context_ == nullptr) {
        ROSEN_LOGE("context_ is null");
        return;
    }
    color_space_ = SkColorSpace::MakeSRGB();
    if (@available(iOS 10, *)) {
        UIDisplayGamut displayGamut = [UIScreen mainScreen].traitCollection.displayGamut;
        switch (displayGamut) {
            case UIDisplayGamutP3:
                color_space_ = SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kDCIP3);
                break;
            default:
                break;
        }
    }
    InitializeEglContext();
}

RenderContextEAGL::~RenderContextEAGL()
{
    EAGLContext* context = EAGLContext.currentContext;
    [EAGLContext setCurrentContext:context_];

    glDeleteFramebuffers(1, &framebuffer_);
    glDeleteRenderbuffers(1, &colorbuffer_);

    [EAGLContext setCurrentContext:context];
}

EGLSurface RenderContextEAGL::CreateEGLSurface(EGLNativeWindowType eglNativeWindow)
{
    layer_ = eglNativeWindow;
    if (static_cast<CAEAGLLayer*>(layer_) == nullptr) {
       ROSEN_LOGE("RenderContextEAGL layer_ is null");
    }

    NSString* drawableColorFormat = kEAGLColorFormatRGBA8;

    static_cast<CAEAGLLayer*>(layer_).drawableProperties = @{
            kEAGLDrawablePropertyColorFormat : drawableColorFormat,
            kEAGLDrawablePropertyRetainedBacking : @(NO),
    };
    return layer_;
}

void RenderContextEAGL::InitializeEglContext()
{
    if (valid_) {
        return;
    }

    bool isContentCurrent = [EAGLContext setCurrentContext:context_];
    if (!isContentCurrent){
        ROSEN_LOGE("Failed to set current OpenGL context");
    }

    glGenFramebuffers(1, &framebuffer_);
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer_);
    glGenRenderbuffers(1, &colorbuffer_);
    glBindRenderbuffer(GL_RENDERBUFFER, colorbuffer_);
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_RENDERBUFFER, colorbuffer_);
    if (!SetUpGrContext()) {
        ROSEN_LOGE("GrContext is not ready!!!");
        return;
    }
    valid_ = true;
}

bool RenderContextEAGL::UpdateStorageSizeIfNecessary()
{
    const CGSize layer_size = [static_cast<CAEAGLLayer*>(layer_)bounds].size;
    const CGFloat contents_scale = static_cast<CAEAGLLayer*>(layer_).contentsScale;
    const GLint size_width = layer_size.width * contents_scale;
    const GLint size_height = layer_size.height * contents_scale;

    if (size_width == storage_size_width_ && size_height == storage_size_height_) {
        ROSEN_LOGE("size_width == storage_size_width_ && size_height == storage_size_height_");
        /* Nothing to since the stoage size is already consistent with the layer. */
        return true;
    }

    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer_);
    glBindRenderbuffer(GL_RENDERBUFFER, colorbuffer_);

    if (![context_ renderbufferStorage:GL_RENDERBUFFER fromDrawable:static_cast<CAEAGLLayer *>(layer_)]) {
        ROSEN_LOGE("context_ renderbufferStorage:GL_RENDERBUFFER Failed");
        return false;
    }

    glGetRenderbufferParameteriv(GL_RENDERBUFFER, GL_RENDERBUFFER_WIDTH, &storage_size_width_);
    glGetRenderbufferParameteriv(GL_RENDERBUFFER, GL_RENDERBUFFER_HEIGHT, &storage_size_height_);
    return true;
}

void RenderContextEAGL::MakeCurrent(void* surface, void* context)
{
    [EAGLContext setCurrentContext:context_];
    UpdateStorageSizeIfNecessary();
}

bool RenderContextEAGL::ResourceMakeCurrent()
{
    return [EAGLContext setCurrentContext:resource_context_];
}

void RenderContextEAGL::SwapBuffers(EGLSurface surface) const
{
    const GLenum discards[] = {
        GL_DEPTH_ATTACHMENT,
        GL_STENCIL_ATTACHMENT,
    };

    glDiscardFramebufferEXT(GL_FRAMEBUFFER, sizeof(discards) / sizeof(GLenum), discards);
    glBindRenderbuffer(GL_RENDERBUFFER, colorbuffer_);
    [[EAGLContext currentContext] presentRenderbuffer:GL_RENDERBUFFER];
    [CATransaction flush];
}

bool RenderContextEAGL::SetUpGrContext()
{
    if (grContext_ != nullptr) {
        ROSEN_LOGD("grContext has already created!!");
        return true;
    }

    sk_sp<const GrGLInterface> glInterface(GrGLMakeNativeInterface());
    if (glInterface.get() == nullptr) {
        ROSEN_LOGE("SetUpGrContext failed to make native interface");
        return false;
    }

    GrContextOptions options;
    options.fAvoidStencilBuffers = true;
    options.fPreferExternalImagesOverES3 = true;
    options.fDisableGpuYUVConversion = true;
    sk_sp<GrContext> grContext(GrContext::MakeGL(std::move(glInterface), options));
    if (grContext == nullptr) {
        ROSEN_LOGE("SetUpGrContext grContext is null");
        return false;
    }
    grContext_ = std::move(grContext);
    return true;
}

sk_sp<SkSurface> RenderContextEAGL::AcquireSurface(int width, int height)
{
    if (width != storage_size_width_ && storage_size_width_ > 0) {
        static_cast<CAEAGLLayer*>(layer_).contentsScale = width * 1.0 / storage_size_width_;
    }

    GrGLFramebufferInfo framebufferInfo;
    framebufferInfo.fFBOID = framebuffer_;
    framebufferInfo.fFormat = 0x8058;

    SkColorType colorType = kRGBA_8888_SkColorType;

    GrBackendRenderTarget backendRenderTarget(width, height, 0, 0, framebufferInfo);
    SkSurfaceProps surfaceProps = SkSurfaceProps::kLegacyFontHost_InitType;
    sk_sp<SkColorSpace> skColorSpace = nullptr;

    skSurface_ = SkSurface::MakeFromBackendRenderTarget(
        grContext_.get(), backendRenderTarget, kBottomLeft_GrSurfaceOrigin, colorType, skColorSpace, &surfaceProps);
    if (skSurface_ == nullptr) {
        ROSEN_LOGW("skSurface is nullptr");
        return nullptr;
    }

    return skSurface_;
}

void RenderContextEAGL::RenderFrame()
{
    if (skSurface_ == nullptr) {
        ROSEN_LOGE("skSurface_ is nullptr!!!");
        return;
    }
    if (skSurface_->getCanvas() != nullptr) {
        skSurface_->getCanvas()->flush();
    } else {
        ROSEN_LOGE("canvas is nullptr!!!");
    }
}

GrContext* RenderContextEAGL::GetGrContext() const
{
    return grContext_.get();
}
} // namespace Rosen
} // namespace OHOS