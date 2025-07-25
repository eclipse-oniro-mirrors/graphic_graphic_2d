/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "egl_wrapper_display.h"

#include "egl_defs.h"
#if USE_IGRAPHICS_EXTENDS_HOOKS
#include "egl_wrapper_hook.h"
#endif
#include "egl_wrapper_context.h"
#include "egl_wrapper_surface.h"
#include "thread_private_data_ctl.h"
#include "wrapper_log.h"
#include "egl_blob_cache.h"
#include "external_window.h"
#include "surface.h"
#include "window.h"
#include <parameter.h>
#include <parameters.h>

namespace OHOS {
static constexpr const char *VENDOR_VALUE = "OpenHarmony";
static constexpr const char *VERSION_VALUE_1_4 = "1.4 OpenHarmony EGL";
static constexpr const char *VERSION_VALUE_1_5 = "1.5 OpenHarmony EGL";
static constexpr const char *CLIENT_API_VALUE = "OpenGL_ES";
static constexpr const char *EXTENSION_VALUE =
    "EGL_KHR_mutable_render_buffer "
    "EGL_KHR_config_attribs "
    "EGL_KHR_image_base "
    "EGL_KHR_gl_colorspace "
    "EGL_KHR_get_all_proc_addresses "
    "EGL_KHR_no_config_context "
    "EGL_IMG_context_priority "
    "EGL_EXT_pixel_format_float "
    "EGL_ARM_pixmap_multisample_discard "
    "EGL_EXT_protected_content "
    "EGL_ARM_implicit_external_sync "
    "EGL_KHR_gl_texture_2D_image "
    "EGL_KHR_gl_renderbuffer_image "
    "EGL_KHR_create_context "
    "EGL_KHR_surfaceless_context "
    "EGL_KHR_gl_texture_cubemap_image "
    "EGL_EXT_create_context_robustness "
    "EGL_EXT_image_gl_colorspace "
    "EGL_EXT_platform_base "
    "EGL_ANDROID_presentation_time "
    "EGL_ANDROID_get_native_client_buffer "
    "EGL_ANDROID_native_fence_sync "
    "EGL_KHR_partial_update "
    "EGL_KHR_image "
    "EGL_KHR_fence_sync "
    "EGL_KHR_wait_sync "
    "EGL_EXT_protected_surface "
;
static constexpr const char *WIDE_COLOR_AND_HDR_EXTENSIONS =
   // wide color support
   "EGL_EXT_gl_colorspace_display_p3_linear "
   "EGL_EXT_gl_colorspace_display_p3 "
   "EGL_EXT_gl_colorspace_display_p3_passthrough "
   // hdr color space support
   "EGL_EXT_gl_colorspace_bt2020_linear "
   "EGL_EXT_gl_colorspace_bt2020_hlg "
   "EGL_EXT_gl_colorspace_bt2020_pq "
;

// Todo: remove after EGL api upgrade
#ifndef EGL_EXT_gl_colorspace_bt2020_hlg
#define EGL_EXT_gl_colorspace_bt2020_hlg 1
#define EGL_GL_COLORSPACE_BT2020_HLG_EXT  0x3540
#endif /* EGL_EXT_gl_colorspace_bt2020_hlg */

static OH_NativeBuffer_ColorSpace TranslateEglColorSpaceToNative(EGLint colorspace)
{
    switch (colorspace) {
        case EGL_GL_COLORSPACE_DISPLAY_P3_LINEAR_EXT:
            return OH_COLORSPACE_LINEAR_P3;
        case EGL_GL_COLORSPACE_DISPLAY_P3_EXT:
            return OH_COLORSPACE_P3_FULL;
        case EGL_GL_COLORSPACE_DISPLAY_P3_PASSTHROUGH_EXT:
            return OH_COLORSPACE_DISPLAY_P3_SRGB;
        case EGL_GL_COLORSPACE_BT2020_LINEAR_EXT:
            return OH_COLORSPACE_LINEAR_BT2020;
        case EGL_GL_COLORSPACE_BT2020_PQ_EXT:
            return OH_COLORSPACE_BT2020_PQ_FULL;
        case EGL_GL_COLORSPACE_BT2020_HLG_EXT:
            return OH_COLORSPACE_BT2020_HLG_FULL;
        default:
            return OH_COLORSPACE_SRGB_FULL;
    }
}

static std::vector<EGLint> ExtractNonColorspaceInfoFromAttribs(const EGLint *attribList)
{
    std::vector<EGLint> attribVec {};
    for (const EGLint* attr = attribList; attr && attr[0] != EGL_NONE; attr += 2) {
        if (attr[0] == EGL_GL_COLORSPACE_KHR) {
            continue;
        }
        attribVec.push_back(attr[0]); // key
        attribVec.push_back(attr[1]); // value
    }
    attribVec.push_back(EGL_NONE); // end
    return attribVec;
}
    
static constexpr const char *SWAP_BUFFER_EXTENSIONS =
    "EGL_KHR_swap_buffers_with_damage "
;

EglWrapperDisplay EglWrapperDisplay::wrapperDisp_;

EglWrapperDisplay::EglWrapperDisplay() noexcept : disp_(EGL_NO_DISPLAY), refCnt_(0)
{
    WLOGD("");
}

EglWrapperDisplay::~EglWrapperDisplay()
{
    WLOGD("");
}

void EglWrapperDisplay::UpdateQueryValue(EGLint *major, EGLint *minor)
{
    if (minor != nullptr && major != nullptr) {
        // 1 is major version, 5 is minor version.
        versionValue_ = (*major == 1 && *minor == 5) ? VERSION_VALUE_1_5 : VERSION_VALUE_1_4;
    }
    vendorValue_ = VENDOR_VALUE;
    clientApiValue_ = CLIENT_API_VALUE;
    extensionValue_ = EXTENSION_VALUE;
    auto isPartialFlushSupport = system::GetParameter("debug.swap.buffer.with.damage", "1");
    if (isPartialFlushSupport == "1") {
        extensionValue_ = std::string(EXTENSION_VALUE) + std::string(SWAP_BUFFER_EXTENSIONS);
        WLOGI("GetParameter debug.swap.buffer.with.damage 1");
    } else {
        WLOGI("GetParameter debug.swap.buffer.with.damage 0");
    }
    if (strstr(EXTENSION_VALUE, "EGL_KHR_gl_colorspace") != nullptr) {
        hasColorSpaceSupport_ = true;
    }
#ifdef USE_VIDEO_PROCESSING_ENGINE
    hasWideColorAndHdrSupport_ = true;
#endif
    if (hasColorSpaceSupport_ && hasWideColorAndHdrSupport_) {
        extensionValue_ = extensionValue_ +
            std::string(EXTENSION_VALUE) + std::string(WIDE_COLOR_AND_HDR_EXTENSIONS);
    }
    WLOGI("UpdateQueryValue extensions: %{public}s", extensionValue_.c_str());
}

EGLBoolean EglWrapperDisplay::Init(EGLint *major, EGLint *minor)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);
    if (refCnt_ > 0) { // wait other thread init.
        EglWrapperDispatchTablePtr table = &gWrapperHook;
        if (major != nullptr) {
            *major = table->major;
        }
        if (minor != nullptr) {
            *minor = table->minor;
        }
        refCnt_++;
        UpdateQueryValue(&table->major, &table->minor);
        return EGL_TRUE;
    }

    ThreadPrivateDataCtl::SetGlHookTable(&gGlHookNoContext);
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    table->major = -1;
    table->minor = -1;
    if (table->isLoad && table->egl.eglInitialize) {
        if (table->egl.eglInitialize(disp_, &table->major, &table->minor)) {
            WLOGD("initialized ver=%{public}d.%{public}d", table->major, table->minor);
            if (major != nullptr) {
                *major = table->major;
            }
            if (minor != nullptr) {
                *minor = table->minor;
            }
            refCnt_++;
            BlobCache::Get()->Init(this);
            UpdateQueryValue(&table->major, &table->minor);
            return EGL_TRUE;
        } else {
            WLOGE("eglInitialize Error.");
        }
    } else {
        WLOGE("eglInitialize is invalid.");
    }
    return EGL_FALSE;
}

EGLBoolean EglWrapperDisplay::Terminate()
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);
    if (refCnt_ == 0) {
        WLOGI("display is not Init.");
        return EGL_TRUE;
    }
    
    refCnt_--;
    if (refCnt_ > 0) {
        return EGL_TRUE;
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad) {
        if (table->egl.eglTerminate) {
            BlobCache::Get()->Terminate();
            ClearObjects();
            return table->egl.eglTerminate(disp_);
        }
    }

    WLOGE("eglTerminate is invalid.");
    return EGL_FALSE;
}

EGLBoolean EglWrapperDisplay::InternalMakeCurrent(
    EglWrapperSurface *draw, EglWrapperSurface *read, EglWrapperContext *ctx,
    bool isAfterHook, EglWrapperContext *curCtx)
{
    WLOGD("");
    EGLContext actualCtx  = EGL_NO_CONTEXT;
    EGLSurface actualDraw = EGL_NO_SURFACE;
    EGLSurface actualRead = EGL_NO_SURFACE;
    if (draw != nullptr) {
        actualDraw = draw->GetEglSurface();
    }

    if (read != nullptr) {
        actualRead = read->GetEglSurface();
    }

    if (ctx != nullptr) {
        actualCtx = ctx->GetEglContext();
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglMakeCurrent) {
        ret = table->egl.eglMakeCurrent(disp_, actualDraw, actualRead, actualCtx);
        if (ret == EGL_TRUE) {
            GlHookTable *hookTable = &gGlHookNoContext;
            if (ctx != nullptr) {
                hookTable = &gWrapperHook.gl;
                ctx->SetCurrentSurface(draw, read);
            }
#if USE_IGRAPHICS_EXTENDS_HOOKS
            ChooseHookTable(isAfterHook, ctx, curCtx, &hookTable);
#endif
            ThreadPrivateDataCtl::SetGlHookTable(hookTable);
            ThreadPrivateDataCtl::SetContext(ctx);
        } else {
            WLOGE("eglMakeCurrent error.");
        }
    } else {
        WLOGE("eglMakeCurrent is invalid.");
    }
    return ret;
}

#if USE_IGRAPHICS_EXTENDS_HOOKS
void EglWrapperDisplay::ChooseHookTable(bool isAfterHook,
    const EglWrapperContext *ctx, const EglWrapperContext *curCtx,
    GlHookTable **ppHookTable)
{
    if (ppHookTable == nullptr) {
        return;
    }

    if (isAfterHook) {
        if (ctx == nullptr && curCtx != nullptr) {
            *ppHookTable = &g_glHookCSDR;
        }
    } else {
        EglWrapperHook& hookLayer(EglWrapperHook::GetInstance());
        if (hookLayer.IsInit() && hookLayer.gtx.gtxGetSingleThreadStatus()) {
            *ppHookTable = &g_glHookSingle;
        }
    }
}
#endif

EGLBoolean EglWrapperDisplay::MakeCurrent(EGLSurface draw, EGLSurface read, EGLContext ctx)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperContext *ctxPtr = nullptr;
    EglWrapperSurface *surDrawPtr = nullptr;
    EglWrapperSurface *surReadPtr = nullptr;

    if (ctx != EGL_NO_CONTEXT) {
        ctxPtr = EglWrapperContext::GetWrapperContext(ctx);
        if (!CheckObject(ctxPtr)) {
            WLOGE("EGLContext is invalid.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_CONTEXT);
            return EGL_FALSE;
        }
    } else {
        if (draw != EGL_NO_SURFACE || read != EGL_NO_SURFACE) {
            WLOGE("EGLContext and EGLSurface is bad match.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_MATCH);
            return EGL_FALSE;
        }
        if (ThreadPrivateDataCtl::GetContext() == EGL_NO_CONTEXT) {
            WLOGI("There is just no current context. skip");
            return EGL_TRUE;
        }
    }

    if (draw != EGL_NO_SURFACE) {
        surDrawPtr = EglWrapperSurface::GetWrapperSurface(draw);
        if (!CheckObject(surDrawPtr)) {
            WLOGE("EGLSurface is invalid.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
            return EGL_FALSE;
        }
    }

    if (read != EGL_NO_SURFACE) {
        surReadPtr = EglWrapperSurface::GetWrapperSurface(read);
        if (!CheckObject(surReadPtr)) {
            WLOGE("EGLSurface is invalid.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
            return EGL_FALSE;
        }
    }

    return InternalMakeCurrent(surDrawPtr, surReadPtr, ctxPtr);
}

#if USE_IGRAPHICS_EXTENDS_HOOKS
EGLBoolean EglWrapperDisplay::MakeCurrentAfterHook(EGLSurface draw, EGLSurface read, EGLContext ctx)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperContext *ctxPtr = nullptr;
    EglWrapperSurface *surDrawPtr = nullptr;
    EglWrapperSurface *surReadPtr = nullptr;

    EGLContext curC = ThreadPrivateDataCtl::GetContext();
    EglWrapperContext *curCtx = EglWrapperContext::GetWrapperContext(curC);

    if (ctx != EGL_NO_CONTEXT) {
        ctxPtr = EglWrapperContext::GetWrapperContext(ctx);
        if (!CheckObject(ctxPtr)) {
            WLOGE("EGLContext is invalid.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_CONTEXT);
            return EGL_FALSE;
        }
    } else {
        if (draw != EGL_NO_SURFACE || read != EGL_NO_SURFACE) {
            WLOGE("EGLContext and EGLSurface is bad match.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_MATCH);
            return EGL_FALSE;
        }
        if (ThreadPrivateDataCtl::GetContext() == EGL_NO_CONTEXT) {
            WLOGI("There is just no current context. skip");
            return EGL_TRUE;
        }
    }

    if (draw != EGL_NO_SURFACE) {
        surDrawPtr = EglWrapperSurface::GetWrapperSurface(draw);
        if (!CheckObject(surDrawPtr)) {
            WLOGE("EGLSurface is invalid.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
            return EGL_FALSE;
        }
    }

    if (read != EGL_NO_SURFACE) {
        surReadPtr = EglWrapperSurface::GetWrapperSurface(read);
        if (!CheckObject(surReadPtr)) {
            WLOGE("EGLSurface is invalid.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
            return EGL_FALSE;
        }
    }
    return InternalMakeCurrent(surDrawPtr, surReadPtr, ctxPtr, true, curCtx);
}
#endif

EglWrapperDisplay *EglWrapperDisplay::GetWrapperDisplay(EGLDisplay display)
{
    WLOGD("");
    EglWrapperDisplay *disp = reinterpret_cast<EglWrapperDisplay *>(display);
    if (disp == &wrapperDisp_) {
        return disp;
    }
    WLOGE("invalid display pointer.");
    return nullptr;
}

EGLDisplay EglWrapperDisplay::GetEglNativeDisplay(EGLenum platform,
    EGLNativeDisplayType disp, const EGLAttrib *attribList)
{
    WLOGD("");
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad) {
        if (table->egl.eglGetPlatformDisplay) {
            disp_ = table->egl.eglGetPlatformDisplay(platform, disp, attribList);
        }

        if (disp_ == EGL_NO_DISPLAY) {
            if (attribList) {
                WLOGW("attribList ignored.");
            }

            if (table->egl.eglGetDisplay) {
                disp_ = table->egl.eglGetDisplay(disp);
            } else {
                WLOGE("eglGetDisplay is invalid.");
            }
        }
    } else {
        WLOGE("EglWrapperDispatchTable is not load.");
    }

    WLOGD("");

    return (disp_ == EGL_NO_DISPLAY) ? disp_ : (EGLDisplay)&wrapperDisp_;
}

EGLDisplay EglWrapperDisplay::GetEglNativeDisplayExt(EGLenum platform,
    void *disp, const EGLint *attribList)
{
    WLOGD("");
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglGetPlatformDisplayEXT) {
        disp_ = table->egl.eglGetPlatformDisplayEXT(platform, disp, attribList);
    } else {
        WLOGE("eglGetPlatformDisplayEXT is invalid.");
    }

    return (disp_ == EGL_NO_DISPLAY) ? disp_ : (EGLDisplay)&wrapperDisp_;
}

EGLDisplay EglWrapperDisplay::GetEglDisplay(EGLenum platform,
    EGLNativeDisplayType disp, const EGLAttrib *attribList)
{
    WLOGD("");
    return wrapperDisp_.GetEglNativeDisplay(platform, disp, attribList);
}

EGLDisplay EglWrapperDisplay::GetEglDisplayExt(EGLenum platform,
    void *disp, const EGLint *attribList)
{
    return wrapperDisp_.GetEglNativeDisplayExt(platform, disp, attribList);
}

bool EglWrapperDisplay::ValidateEglContext(EGLContext ctx)
{
    WLOGD("");
    return false;
}

bool EglWrapperDisplay::ValidateEglSurface(EGLSurface surf)
{
    WLOGD("");
    return false;
}

#if USE_IGRAPHICS_EXTENDS_HOOKS
int EglWrapperDisplay::ChooseGlesVersion(const EGLint *attribList)
{
    int version = EglWrapperDispatchTable::GLESV1_INDEX;
    if (attribList) {
        while (*attribList != EGL_NONE) {
            GLint attr = *attribList++;
            GLint value = *attribList++;
            if (attr == EGL_CONTEXT_CLIENT_VERSION && (value == 2 || value == 3)) { // 2:version 3:version
                version = EglWrapperDispatchTable::GLESV2_INDEX;
            }
        }
    }
    return version;
}
#endif

EGLContext EglWrapperDisplay::CreateEglContext(EGLConfig config, EGLContext shareList, const EGLint *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EGLContext shareCtx = EGL_NO_CONTEXT;
    if (shareList != EGL_NO_CONTEXT) {
        EglWrapperContext *ctxPtr = EglWrapperContext::GetWrapperContext(shareList);
        if (!CheckObject(ctxPtr)) {
            WLOGE("EGLContext is invalid.");
            ThreadPrivateDataCtl::SetError(EGL_BAD_CONTEXT);
            return EGL_NO_CONTEXT;
        }
        shareCtx = ctxPtr->GetEglContext();
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreateContext) {
        EGLContext context = table->egl.eglCreateContext(disp_, config, shareCtx, attribList);
        if (context != EGL_NO_CONTEXT) {
#if USE_IGRAPHICS_EXTENDS_HOOKS
            return new EglWrapperContext(this, context, ChooseGlesVersion(attribList));
#else
            return new EglWrapperContext(this, context);
#endif
        } else {
            WLOGE("egl.eglCreateContext error.");
        }
    } else {
        WLOGE("eglCreateContext is invalid.");
    }

    return EGL_NO_CONTEXT;
}

EGLBoolean EglWrapperDisplay::DestroyEglContext(EGLContext context)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperContext *ctxPtr = EglWrapperContext::GetWrapperContext(context);
    if (!CheckObject(ctxPtr)) {
        WLOGE("EGLContext is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_CONTEXT);
        return EGL_FALSE;
    }
    EGLContext ctx = ctxPtr->GetEglContext();

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglDestroyContext) {
        ret = table->egl.eglDestroyContext(disp_, ctx);
        if (ret == EGL_TRUE) {
            ctxPtr->Destroy();
        } else {
            WLOGE("eglDestroyContext error.");
        }
    } else {
        WLOGE("eglDestroyContext is invalid.");
    }

    return ret;
}

// Get the colorspace value that should be reported from queries.
// When the colorspace is unknown (no attribute passed), default to reporting LINEAR.
static EGLint GetReportedColorSpace(EGLint colorSpace)
{
    return colorSpace == EGL_UNKNOWN ? EGL_GL_COLORSPACE_LINEAR_KHR : colorSpace;
}

EGLSurface EglWrapperDisplay::CreateEglSurface(EGLConfig config,
    NativeWindowType window, const EGLint *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    if (!window) {
        WLOGE("NativeWindowType window is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_NATIVE_WINDOW);
        return EGL_NO_SURFACE;
    }

    // select correct colorspace and dataspace based on user's attribute list.
    EGLint colorSpace = EGL_UNKNOWN;
    EGLSurface surf = EGL_NO_SURFACE;
    bool requestWideColor = false;
    auto nativeWindow = static_cast<OHNativeWindow*>(window);
    for (const EGLint* attr = attribList; attr && attr[0] != EGL_NONE; attr += 2) {
        if (attr[0] == EGL_GL_COLORSPACE_KHR &&
            (attr[1] == EGL_GL_COLORSPACE_LINEAR_KHR || attr[1] == EGL_GL_COLORSPACE_SRGB_KHR)) {
            colorSpace = static_cast<EGLint>(attr[1]);
        }
        if (attr[0] == EGL_GL_COLORSPACE_KHR && attr[1] != EGL_GL_COLORSPACE_LINEAR_KHR) {
            requestWideColor = true;
            colorSpace = attr[1];
            WLOGI("attrib colorspace: %{public}d", colorSpace);
        }
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreateWindowSurface) {
        WLOGI("CreateEglSurface hasColorSpaceSupport_: %{public}d,"
            "hasWideColorAndHdrSupport_ %{public}d , requestWideColor %{public}d",
            hasColorSpaceSupport_, hasWideColorAndHdrSupport_, requestWideColor);
        if (hasColorSpaceSupport_ && hasWideColorAndHdrSupport_ && requestWideColor) {
            OH_NativeWindow_SetColorSpace(nativeWindow, TranslateEglColorSpaceToNative(colorSpace));
            std::vector<EGLint> attribVec = ExtractNonColorspaceInfoFromAttribs(attribList);
            surf = table->egl.eglCreateWindowSurface(disp_, config, window, attribVec.data());
        } else {
            surf = table->egl.eglCreateWindowSurface(disp_, config, window, attribList);
        }
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf, window, GetReportedColorSpace(colorSpace));
        } else {
            WLOGE("egl.eglCreateWindowSurface error.");
        }
    } else {
        WLOGE("eglCreateWindowSurface is invalid.");
    }

    return EGL_NO_SURFACE;
}

EGLBoolean EglWrapperDisplay::DestroyEglSurface(EGLSurface surf)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }
    EGLSurface sur = surfPtr->GetEglSurface();

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglDestroySurface) {
        ret = table->egl.eglDestroySurface(disp_, sur);
        if (ret == EGL_TRUE) {
            surfPtr->Destroy();
        } else {
            WLOGE("eglDestroySurface error.");
        }
    } else {
        WLOGE("eglDestroySurface is invalid.");
    }

    return ret;
}

void EglWrapperDisplay::AddObject(EglWrapperObject *obj)
{
    std::lock_guard<std::mutex> lock(lockMutex_);
    objects_.insert(obj);
}

void EglWrapperDisplay::RemoveObject(EglWrapperObject *obj)
{
    std::lock_guard<std::mutex> lock(lockMutex_);
    objects_.erase(obj);
}

void EglWrapperDisplay::ClearObjects()
{
    std::lock_guard<std::mutex> lock(lockMutex_);
    for (auto obj : objects_) {
        obj->Release();
    }
    objects_.clear();
}

bool EglWrapperDisplay::CheckObject(EglWrapperObject *obj)
{
    std::lock_guard<std::mutex> lock(lockMutex_);
    if (objects_.find(obj) != objects_.end()) {
        if (obj->GetDisplay() == this) {
            return true;
        }
    }
    return false;
}

EGLBoolean EglWrapperDisplay::CopyBuffers(EGLSurface surf, NativePixmapType target)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCopyBuffers) {
        ret = table->egl.eglCopyBuffers(disp_, surfPtr->GetEglSurface(), target);
    } else {
        WLOGE("eglCopyBuffers is invalid.");
    }

    return ret;
}

EGLSurface EglWrapperDisplay::CreatePbufferSurface(EGLConfig config, const EGLint *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreatePbufferSurface) {
        EGLSurface surf = table->egl.eglCreatePbufferSurface(disp_, config, attribList);
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf);
        } else {
            WLOGE("egl.eglCreatePbufferSurface error.");
        }
    } else {
        WLOGE("eglCreatePbufferSurface is invalid.");
    }

    return EGL_NO_SURFACE;
}

EGLSurface EglWrapperDisplay::CreatePixmapSurface(EGLConfig config,
    EGLNativePixmapType pixmap, const EGLint* attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreatePixmapSurface) {
        EGLSurface surf = table->egl.eglCreatePixmapSurface(disp_, config, pixmap, attribList);
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf);
        } else {
            WLOGE("egl.eglCreatePixmapSurface error.");
        }
    } else {
        WLOGE("eglCreatePixmapSurface is invalid.");
    }

    return EGL_NO_SURFACE;
}

EGLBoolean EglWrapperDisplay::QueryContext(EGLContext ctx, EGLint attribute, EGLint *value)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperContext *ctxPtr = EglWrapperContext::GetWrapperContext(ctx);
    if (!CheckObject(ctxPtr)) {
        WLOGE("EGLContext is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_CONTEXT);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglQueryContext) {
        ret = table->egl.eglQueryContext(disp_,
            ctxPtr->GetEglContext(), attribute, value);
    } else {
        WLOGE("eglQueryContext is invalid.");
    }

    return ret;
}

EGLBoolean EglWrapperDisplay::QuerySurface(EGLSurface surf, EGLint attribute, EGLint *value)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    if (surfPtr->GetColorSpaceAttribute(attribute, value)) {
        return EGL_TRUE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglQuerySurface) {
        ret = table->egl.eglQuerySurface(disp_,
            surfPtr->GetEglSurface(), attribute, value);
    } else {
        WLOGE("eglQuerySurface is invalid.");
    }

    return ret;
}

EGLBoolean EglWrapperDisplay::SwapBuffers(EGLSurface surf)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        if (surfPtr->GetEglSurface() == nullptr) {
            WLOGE("INparament is invalid.");
            return EGL_FALSE;
        }
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglSwapBuffers) {
        ret = table->egl.eglSwapBuffers(disp_, surfPtr->GetEglSurface());
    } else {
        WLOGE("eglSwapBuffers is invalid.");
    }

    return ret;
}

EGLBoolean EglWrapperDisplay::BindTexImage(EGLSurface surf, EGLint buffer)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglBindTexImage) {
        ret = table->egl.eglBindTexImage(disp_, surfPtr->GetEglSurface(), buffer);
    } else {
        WLOGE("eglBindTexImage is invalid.");
    }

    return ret;
}

EGLBoolean EglWrapperDisplay::ReleaseTexImage(EGLSurface surf, EGLint buffer)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglReleaseTexImage) {
        ret = table->egl.eglReleaseTexImage(disp_, surfPtr->GetEglSurface(), buffer);
    } else {
        WLOGE("eglReleaseTexImage is invalid.");
    }

    return ret;
}

EGLBoolean EglWrapperDisplay::SurfaceAttrib(EGLSurface surf, EGLint attribute, EGLint value)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglSurfaceAttrib) {
        ret = table->egl.eglSurfaceAttrib(disp_,
            surfPtr->GetEglSurface(), attribute, value);
    } else {
        WLOGE("eglSurfaceAttrib is invalid.");
    }

    return ret;
}

EGLSurface EglWrapperDisplay::CreatePbufferFromClientBuffer(
    EGLenum buftype, EGLClientBuffer buffer,
    EGLConfig config, const EGLint *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreatePbufferFromClientBuffer) {
        EGLSurface surf = table->egl.eglCreatePbufferFromClientBuffer(
            disp_, buftype, buffer, config, attribList);
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf);
        } else {
            WLOGE("egl.eglCreatePbufferFromClientBuffer error.");
        }
    } else {
        WLOGE("eglCreatePbufferFromClientBuffer is invalid.");
    }

    return EGL_NO_SURFACE;
}

EGLImage EglWrapperDisplay::CreateImage(EGLContext ctx, EGLenum target,
    EGLClientBuffer buffer, const EGLAttrib *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EGLContext actualCtx  = EGL_NO_CONTEXT;
    if (ctx != EGL_NO_CONTEXT) {
        EglWrapperContext *ctxPtr = EglWrapperContext::GetWrapperContext(ctx);
        if (CheckObject(ctxPtr)) {
            actualCtx = ctxPtr->GetEglContext();
        }
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreateImage) {
        return table->egl.eglCreateImage(disp_, actualCtx, target, buffer, attribList);
    } else {
        WLOGE("eglCreateImage is invalid.");
    }

    return EGL_NO_IMAGE_KHR;
}

EGLBoolean EglWrapperDisplay::DestroyImage(EGLImage img)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglDestroyImage) {
        ret = table->egl.eglDestroyImage(disp_, img);
    } else {
        WLOGE("eglDestroyImage is invalid.");
    }

    return ret;
}

EGLSurface EglWrapperDisplay::CreatePlatformWindowSurface(EGLConfig config,
    void *nativeWindow, const EGLAttrib *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    if (!nativeWindow) {
        WLOGE("nativeWindow is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_NATIVE_WINDOW);
        return EGL_NO_SURFACE;
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreatePlatformWindowSurface) {
        EGLSurface surf = table->egl.eglCreatePlatformWindowSurface(disp_,
            config, nativeWindow, attribList);
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf);
        } else {
            WLOGE("egl.eglCreatePlatformWindowSurface error.");
        }
    } else {
        WLOGE("eglCreatePlatformWindowSurface is invalid.");
    }

    return EGL_NO_SURFACE;
}

EGLSurface EglWrapperDisplay::CreatePlatformPixmapSurface(EGLConfig config,
    void *nativePixmap, const EGLAttrib *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    if (!nativePixmap) {
        WLOGE("nativePixmap is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_NATIVE_WINDOW);
        return EGL_NO_SURFACE;
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreatePlatformPixmapSurface) {
        EGLSurface surf = table->egl.eglCreatePlatformPixmapSurface(disp_,
            config, nativePixmap, attribList);
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf);
        } else {
            WLOGE("egl.eglCreatePlatformPixmapSurface error.");
        }
    } else {
        WLOGE("eglCreatePlatformPixmapSurface is invalid.");
    }

    return EGL_NO_SURFACE;
}

EGLBoolean EglWrapperDisplay::LockSurfaceKHR(EGLSurface surf, const EGLint *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglLockSurfaceKHR) {
        ret = table->egl.eglLockSurfaceKHR(disp_,
            surfPtr->GetEglSurface(), attribList);
    } else {
        WLOGE("eglLockSurfaceKHR is invalid.");
    }

    return ret;
}

EGLBoolean EglWrapperDisplay::UnlockSurfaceKHR(EGLSurface surf)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglUnlockSurfaceKHR) {
        ret = table->egl.eglUnlockSurfaceKHR(disp_, surfPtr->GetEglSurface());
    } else {
        WLOGE("eglUnlockSurfaceKHR is invalid.");
    }

    return ret;
}

EGLImageKHR EglWrapperDisplay::CreateImageKHR(EGLContext ctx, EGLenum target,
    EGLClientBuffer buffer, const EGLint *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EGLContext actualCtx  = EGL_NO_CONTEXT;
    if (ctx != EGL_NO_CONTEXT) {
        EglWrapperContext *ctxPtr = EglWrapperContext::GetWrapperContext(ctx);
        if (CheckObject(ctxPtr)) {
            actualCtx = ctxPtr->GetEglContext();
        }
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreateImageKHR) {
        return table->egl.eglCreateImageKHR(disp_, actualCtx, target, buffer, attribList);
    } else {
        WLOGE("eglCreateImageKHR is invalid.");
    }

    return EGL_NO_IMAGE_KHR;
}

EGLBoolean EglWrapperDisplay::DestroyImageKHR(EGLImageKHR img)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglDestroyImageKHR) {
        ret = table->egl.eglDestroyImageKHR(disp_, img);
    } else {
        WLOGE("eglDestroyImageKHR is invalid.");
    }

    return ret;
}

EGLSurface EglWrapperDisplay::CreateStreamProducerSurfaceKHR(EGLConfig config,
    EGLStreamKHR stream, const EGLint *attribList)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreateStreamProducerSurfaceKHR) {
        EGLSurface surf = table->egl.eglCreateStreamProducerSurfaceKHR(
            disp_, config, stream, attribList);
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf);
        } else {
            WLOGE("egl.eglCreateStreamProducerSurfaceKHR error.");
        }
    } else {
        WLOGE("eglCreateStreamProducerSurfaceKHR is invalid.");
    }

    return EGL_NO_SURFACE;
}

EGLBoolean EglWrapperDisplay::SwapBuffersWithDamageKHR(EGLSurface draw, EGLint *rects, EGLint nRects)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfacePtr = EglWrapperSurface::GetWrapperSurface(draw);
    if (!CheckObject(surfacePtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    if (nRects < 0 || (nRects > 0 && rects == NULL)) {
        WLOGE("Paramter error.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_PARAMETER);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglSwapBuffersWithDamageKHR) {
        ret = table->egl.eglSwapBuffersWithDamageKHR(
            disp_, surfacePtr->GetEglSurface(), rects, nRects);
    } else {
        WLOGE("eglSwapBuffersWithDamageKHR is invalid.");
    }

    return ret;
}

EGLBoolean EglWrapperDisplay::SetDamageRegionKHR(EGLSurface surf, EGLint *rects, EGLint nRects)
{
    WLOGD("");
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surf);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    if (nRects < 0 || (nRects > 0 && rects == nullptr)) {
        WLOGE("Paramter error.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_PARAMETER);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglSetDamageRegionKHR) {
        ret = table->egl.eglSetDamageRegionKHR(
            disp_, surfPtr->GetEglSurface(), rects, nRects);
    } else {
        WLOGE("eglSetDamageRegionKHR is invalid.");
    }

    return ret;
}

EGLBoolean EglWrapperDisplay::GetCompositorTimingSupportedANDROID(EGLSurface surface, EGLint name)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surface);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    if (surfPtr->GetNativeWindow() == nullptr) {
        WLOGE("GetCompositorTimingSupportedANDROID native window is nullptr.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    switch (name) {
        case EGL_COMPOSITE_DEADLINE_ANDROID:
        case EGL_COMPOSITE_INTERVAL_ANDROID:
        case EGL_COMPOSITE_TO_PRESENT_LATENCY_ANDROID:
            return EGL_TRUE;
        default:
            return EGL_FALSE;
    }
}

EGLBoolean EglWrapperDisplay::GetFrameTimestampSupportedANDROID(EGLSurface surface, EGLint timestamp)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surface);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    if (surfPtr->GetNativeWindow() == nullptr) {
        WLOGE("GetFrameTimestampSupportedANDROID native window is nullptr.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }
    switch (timestamp) {
        case EGL_COMPOSITE_DEADLINE_ANDROID:
        case EGL_COMPOSITE_INTERVAL_ANDROID:
        case EGL_COMPOSITE_TO_PRESENT_LATENCY_ANDROID:
        case EGL_REQUESTED_PRESENT_TIME_ANDROID:
        case EGL_RENDERING_COMPLETE_TIME_ANDROID:
        case EGL_COMPOSITION_LATCH_TIME_ANDROID:
        case EGL_FIRST_COMPOSITION_START_TIME_ANDROID:
        case EGL_LAST_COMPOSITION_START_TIME_ANDROID:
        case EGL_FIRST_COMPOSITION_GPU_FINISHED_TIME_ANDROID:
        case EGL_DEQUEUE_READY_TIME_ANDROID:
        case EGL_READS_DONE_TIME_ANDROID:
            return EGL_TRUE;
        default:
            return EGL_FALSE;
    }
}

EGLBoolean EglWrapperDisplay::PresentationTimeANDROID(EGLSurface surface, EGLnsecsANDROID time)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surface);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }
    if (surfPtr->GetNativeWindow() == nullptr) {
        WLOGE("PresentationTimeANDROID native window is nullptr.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    if (NativeWindowHandleOpt(reinterpret_cast<OHNativeWindow*>(surfPtr->GetNativeWindow()),
        SET_UI_TIMESTAMP, time) != 0) {
        WLOGE("NativeWindowHandleOpt SET_UI_TIMESTAMP failed.");
        return EGL_FALSE;
    }
    return EGL_TRUE;
}

EGLSurface EglWrapperDisplay::CreatePlatformWindowSurfaceEXT(EGLConfig config, void *nativeWindow,
    const EGLint *attribList)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    if (nativeWindow == nullptr) {
        WLOGE("CreatePlatformWindowSurfaceEXT nativeWindow is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_NATIVE_WINDOW);
        return EGL_NO_SURFACE;
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreatePlatformWindowSurfaceEXT) {
        EGLSurface surf = table->egl.eglCreatePlatformWindowSurfaceEXT(
            disp_, config, nativeWindow, attribList);
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf);
        } else {
            WLOGE("egl.eglCreatePlatformWindowSurfaceEXT error.");
        }
    } else {
        WLOGE("eglCreatePlatformWindowSurfaceEXT is invalid.");
    }

    return EGL_NO_SURFACE;
}

EGLSurface EglWrapperDisplay::CreatePlatformPixmapSurfaceEXT(EGLConfig config, void *nativePixmap,
    const EGLint *attribList)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    if (nativePixmap == nullptr) {
        WLOGE("CreatePlatformPixmapSurfaceEXT nativePixmap is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_NATIVE_WINDOW);
        return EGL_NO_SURFACE;
    }

    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglCreatePlatformPixmapSurfaceEXT) {
        EGLSurface surf = table->egl.eglCreatePlatformPixmapSurfaceEXT(
            disp_, config, nativePixmap, attribList);
        if (surf != EGL_NO_SURFACE) {
            return new EglWrapperSurface(this, surf);
        } else {
            WLOGE("egl.eglCreatePlatformPixmapSurfaceEXT error.");
        }
    } else {
        WLOGE("eglCreatePlatformPixmapSurfaceEXT is invalid.");
    }
    return EGL_NO_SURFACE;
}

EGLBoolean EglWrapperDisplay::SwapBuffersWithDamageEXT(EGLSurface surface, const EGLint *rects, EGLint nRects)
{
    std::lock_guard<std::recursive_mutex> lock(refLockMutex_);

    EglWrapperSurface *surfPtr = EglWrapperSurface::GetWrapperSurface(surface);
    if (!CheckObject(surfPtr)) {
        WLOGE("EGLSurface is invalid.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }

    if (nRects < 0 || (nRects > 0 && rects == nullptr)) {
        WLOGE("Paramter error.");
        ThreadPrivateDataCtl::SetError(EGL_BAD_PARAMETER);
        return EGL_FALSE;
    }

    EGLBoolean ret = EGL_FALSE;
    EglWrapperDispatchTablePtr table = &gWrapperHook;
    if (table->isLoad && table->egl.eglSwapBuffersWithDamageEXT) {
        ret = table->egl.eglSwapBuffersWithDamageEXT(
            disp_, surfPtr->GetEglSurface(), rects, nRects);
    } else {
        WLOGE("eglSwapBuffersWithDamageEXT is invalid.");
    }
    return ret;
}
} // namespace OHOS
