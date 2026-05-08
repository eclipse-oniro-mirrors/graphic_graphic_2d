/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <EGL/egl.h>
#include "parameters.h"
#include "EGL/egl_wrapper_custom.h"
#include "EGL/egl_wrapper_display.h"
#include "egl_defs.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class EglWrapperCustomTest : public testing::Test {
protected:
    static std::shared_ptr<OHOS::system::ParameterMock> mockParameter;
};

std::shared_ptr<OHOS::system::ParameterMock> EglWrapperCustomTest::mockParameter = nullptr;
} // namespace OHOS

#ifdef OPENGL_WRAPPER_ENABLE_GL4
/**
 * @tc.name: EglGetProcAddressCustomImplTest001
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglGetProcAddressCustomImplTest001, Level1)
{
    mockParameter = std::make_shared<OHOS::system::ParameterMock>();
    EXPECT_CALL(*mockParameter, GetBoolParameter(OHOS::SUPPORT_GL_TO_VK, _))
        .WillOnce(testing::Return(true));
    EXPECT_EQ(OHOS::OHGraphicsQueryGLImpl(), EGL_TRUE);
}

/**
 * @tc.name: OHGraphicsQueryGLImplTest002
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, OHGraphicsQueryGLImplTest002, Level1)
{
    mockParameter = std::make_shared<OHOS::system::ParameterMock>();
    EXPECT_CALL(*mockParameter, GetBoolParameter(_, _)).WillOnce(testing::Return(false));
    EXPECT_EQ(OHOS::OHGraphicsQueryGLImpl(), EGL_FALSE);
}
#endif

namespace {
typedef EGLBoolean (*SetEngineNameFunc)(EGLDisplay dpy, const char* name);
} // namespace

/**
 * @tc.name: EglSetEngineNameImplTest001
 * @tc.desc: Test EglSetEngineNameImpl with nullptr display
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglSetEngineNameImplTest001, Level1)
{
    auto func = reinterpret_cast<SetEngineNameFunc>(eglGetProcAddress("eglSetEngineName"));
    ASSERT_NE(nullptr, func);

    auto result = func(EGL_NO_DISPLAY, "test_engine");
    EXPECT_EQ(result, EGL_FALSE);
}

/**
 * @tc.name: EglSetEngineNameImplTest002
 * @tc.desc: Test EglSetEngineNameImpl with invalid display (not initialized)
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglSetEngineNameImplTest002, Level1)
{
    auto func = reinterpret_cast<SetEngineNameFunc>(eglGetProcAddress("eglSetEngineName"));
    ASSERT_NE(nullptr, func);

    auto eglWrapperDisplay = EglWrapperDisplay::GetWrapperDisplay(
        (EGLDisplay)&EglWrapperDisplay::wrapperDisp_);
    ASSERT_NE(nullptr, eglWrapperDisplay);
    auto tmp = eglWrapperDisplay->refCnt_;
    eglWrapperDisplay->refCnt_ = 0;

    auto result = func((EGLDisplay)eglWrapperDisplay, "test_engine");
    EXPECT_EQ(result, EGL_FALSE);

    eglWrapperDisplay->refCnt_ = tmp;
}

/**
 * @tc.name: EglSetEngineNameImplTest003
 * @tc.desc: Test EglSetEngineNameImpl when driver not loaded
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglSetEngineNameImplTest003, Level1)
{
    auto func = reinterpret_cast<SetEngineNameFunc>(eglGetProcAddress("eglSetEngineName"));
    ASSERT_NE(nullptr, func);

    EGLDisplay dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major, minor;
    EGLBoolean ret = eglInitialize(dpy, &major, &minor);
    ASSERT_EQ(ret, EGL_TRUE);

    auto eglWrapperDisplay = OHOS::EglWrapperDisplay::GetWrapperDisplay(dpy);
    ASSERT_NE(nullptr, eglWrapperDisplay);

    auto temp = OHOS::gWrapperHook.isLoad;
    OHOS::gWrapperHook.isLoad = false;

    auto result = func(dpy, "test_engine");
    EXPECT_EQ(result, EGL_FALSE);

    OHOS::gWrapperHook.isLoad = temp;
    eglTerminate(dpy);
}

/**
 * @tc.name: EglSetEngineNameImplTest004
 * @tc.desc: Test EglSetEngineNameImpl when eglGetProcAddress is null
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglSetEngineNameImplTest004, Level1)
{
    auto func = reinterpret_cast<SetEngineNameFunc>(eglGetProcAddress("eglSetEngineName"));
    ASSERT_NE(nullptr, func);

    EGLDisplay dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major, minor;
    EGLBoolean ret = eglInitialize(dpy, &major, &minor);
    ASSERT_EQ(ret, EGL_TRUE);

    auto temp = OHOS::gWrapperHook.egl.eglGetProcAddress;
    OHOS::gWrapperHook.egl.eglGetProcAddress = nullptr;

    auto result = func(dpy, "test_engine");
    EXPECT_EQ(result, EGL_FALSE);

    OHOS::gWrapperHook.egl.eglGetProcAddress = temp;
    eglTerminate(dpy);
}

/**
 * @tc.name: EglSetEngineNameImplTest005
 * @tc.desc: Test EglSetEngineNameImpl when driver not support eglSetEngineName
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglSetEngineNameImplTest005, Level1)
{
    auto func = reinterpret_cast<SetEngineNameFunc>(eglGetProcAddress("eglSetEngineName"));
    ASSERT_NE(nullptr, func);

    EGLDisplay dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major, minor;
    EGLBoolean ret = eglInitialize(dpy, &major, &minor);
    ASSERT_EQ(ret, EGL_TRUE);

    auto tempIsLoad = OHOS::gWrapperHook.isLoad;
    auto tempGetProcAddr = OHOS::gWrapperHook.egl.eglGetProcAddress;

    OHOS::gWrapperHook.isLoad = true;
    OHOS::gWrapperHook.egl.eglGetProcAddress = +[](const char*)
        -> __eglMustCastToProperFunctionPointerType { return nullptr; };

    auto result = func(dpy, "test_engine");
    EXPECT_EQ(result, EGL_FALSE);

    OHOS::gWrapperHook.isLoad = tempIsLoad;
    OHOS::gWrapperHook.egl.eglGetProcAddress = tempGetProcAddr;
    eglTerminate(dpy);
}

/**
 * @tc.name: EglSetEngineNameImplTest006
 * @tc.desc: Test EglSetEngineNameImpl success path
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglSetEngineNameImplTest006, Level1)
{
    auto func = reinterpret_cast<SetEngineNameFunc>(eglGetProcAddress("eglSetEngineName"));
    ASSERT_NE(nullptr, func);

    EGLDisplay dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major, minor;
    EGLBoolean ret = eglInitialize(dpy, &major, &minor);
    ASSERT_EQ(ret, EGL_TRUE);

    auto tempIsLoad = OHOS::gWrapperHook.isLoad;
    auto tempGetProcAddr = OHOS::gWrapperHook.egl.eglGetProcAddress;

    OHOS::gWrapperHook.isLoad = true;
    OHOS::gWrapperHook.egl.eglGetProcAddress = +[](const char*)
        -> __eglMustCastToProperFunctionPointerType {
        return reinterpret_cast<__eglMustCastToProperFunctionPointerType>(
            +[]() -> EGLBoolean { return EGL_TRUE; });
    };

    auto result = func(dpy, "test_engine");
    EXPECT_EQ(result, EGL_TRUE);

    OHOS::gWrapperHook.isLoad = tempIsLoad;
    OHOS::gWrapperHook.egl.eglGetProcAddress = tempGetProcAddr;
    eglTerminate(dpy);
}

/**
 * @tc.name: EglSetEngineNameImplTest007
 * @tc.desc: Test EglSetEngineNameImpl when name is null
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglSetEngineNameImplTest007, Level1)
{
    auto func = reinterpret_cast<SetEngineNameFunc>(eglGetProcAddress("eglSetEngineName"));
    ASSERT_NE(nullptr, func);

    EGLDisplay dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major, minor;
    EGLBoolean ret = eglInitialize(dpy, &major, &minor);
    ASSERT_EQ(ret, EGL_TRUE);

    auto tempIsLoad = OHOS::gWrapperHook.isLoad;
    auto tempGetProcAddr = OHOS::gWrapperHook.egl.eglGetProcAddress;

    OHOS::gWrapperHook.isLoad = true;
    OHOS::gWrapperHook.egl.eglGetProcAddress = +[](const char*)
        -> __eglMustCastToProperFunctionPointerType {
        return reinterpret_cast<__eglMustCastToProperFunctionPointerType>(
            +[]() -> EGLBoolean { return EGL_FALSE; });
    };

    auto result = func(dpy, nullptr);
    EXPECT_EQ(result, EGL_FALSE);

    OHOS::gWrapperHook.isLoad = tempIsLoad;
    OHOS::gWrapperHook.egl.eglGetProcAddress = tempGetProcAddr;
    eglTerminate(dpy);
}

/**
 * @tc.name: EglSetEngineNameImplTest008
 * @tc.desc: Test EglSetEngineNameImpl with empty string name
 * @tc.type: FUNC
 */
HWTEST_F(OHOS::EglWrapperCustomTest, EglSetEngineNameImplTest008, Level1)
{
    auto func = reinterpret_cast<SetEngineNameFunc>(eglGetProcAddress("eglSetEngineName"));
    ASSERT_NE(nullptr, func);

    EGLDisplay dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major, minor;
    EGLBoolean ret = eglInitialize(dpy, &major, &minor);
    ASSERT_EQ(ret, EGL_TRUE);

    auto tempIsLoad = OHOS::gWrapperHook.isLoad;
    auto tempGetProcAddr = OHOS::gWrapperHook.egl.eglGetProcAddress;

    OHOS::gWrapperHook.isLoad = true;
    OHOS::gWrapperHook.egl.eglGetProcAddress = +[](const char*)
        -> __eglMustCastToProperFunctionPointerType {
        return reinterpret_cast<__eglMustCastToProperFunctionPointerType>(
            +[]() -> EGLBoolean { return EGL_TRUE; });
    };

    auto result = func(dpy, "");
    EXPECT_EQ(result, EGL_TRUE);

    OHOS::gWrapperHook.isLoad = tempIsLoad;
    OHOS::gWrapperHook.egl.eglGetProcAddress = tempGetProcAddr;
    eglTerminate(dpy);
}
} // OHOS::Rosen