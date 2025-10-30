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
#ifndef FRAMEWORKS_OPENGL_WRAPPER_EGL_DEFS_H
#define FRAMEWORKS_OPENGL_WRAPPER_EGL_DEFS_H

#include <map>

#include <EGL/egl.h>
#include "egl_wrapper_entry.h"
#include "hook.h"
namespace OHOS {
struct EglWrapperDispatchTable {
    enum { GLESV1_INDEX = 0, GLESV2_INDEX = 1 };
    inline EglWrapperDispatchTable() noexcept : isLoad(false), useMesa(false) {}
    WrapperHookTable    wrapper;
    EglHookTable        egl;
    GlHookTable         gl;
    bool                isLoad;
    bool                useMesa;
    EGLint              major;
    EGLint              minor;
};

extern char const * const gWrapperApiNames[EGL_API_NUM];
extern char const * const gEglApiNames[EGL_API_NUM];
extern char const * const gGlApiNames1[GLES_API_NUM];
extern char const * const gGlApiNames2[GLES_API_NUM];
extern char const * const gGlApiNames3[GLES_API_NUM];
#ifdef OPENGL_WRAPPER_ENABLE_GL4
constexpr const char *SUPPORT_GL_TO_VK = "const.graphic.gl_to_vk_support";
extern char const * const gGlApiNames4[OPENGL_API_NUM];
extern const std::map<std::string, EglWrapperFuncPointer> gCustomMap;
extern PENEGLGETPROCADDRESSPROC gGetProcAddress;
#endif
extern const std::map<std::string, EglWrapperFuncPointer> gExtensionMap;

extern GlHookTable gGlHookNoContext;
extern EglWrapperDispatchTable gWrapperHook;
#if USE_IGRAPHICS_EXTENDS_HOOKS
extern GlHookTable g_glHookCSDR;
extern GlHookTable g_glHookSingle;
#endif

using EglWrapperDispatchTablePtr = EglWrapperDispatchTable *;
}; // namespace OHOS

#endif // FRAMEWORKS_OPENGL_WRAPPER_EGL_DEFS_H
