/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "rs_graphic_test_capture.h"

#include <chrono>
#include <iostream>
#include <mutex>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Rosen {
namespace {

std::mutex g_captureConfigMutex;
EmulatorCaptureConfig g_captureConfig;

bool IsValidOutputDirectory(const std::string& path)
{
    if (path.size() < 2 || path.front() != '/') {
        return false;
    }
    if (path.find('\n') != std::string::npos || path.find('\r') != std::string::npos ||
        path.find('\0') != std::string::npos || path.find("/../") != std::string::npos ||
        (path.size() >= 3 && path.compare(path.size() - 3, 3, "/..") == 0)) {
        return false;
    }
    return true;
}

} // namespace

void SetGraphicTestCaptureNativeToken()
{
    const char* permissions[2];
    permissions[0] = "ohos.permission.CAPTURE_SCREEN";
    permissions[1] = "ohos.permission.MANAGE_DISPLAY_MANAGER";
    const char* acls[1];
    acls[0] = "ohos.permission.CAPTURE_SCREEN";
    NativeTokenInfoParams info = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 1,
        .dcaps = NULL,
        .perms = permissions,
        .acls = acls,
        .processName = "foundation",
        .aplStr = "system_basic",
    };
    const uint64_t tokenId = GetAccessTokenId(&info);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

bool ConfigureEmulatorCapture(const EmulatorCaptureConfig& config, std::string& error)
{
    if (!config.enabled || !IsValidOutputDirectory(config.outputDirectory)) {
        error = "emulator capture requires an enabled configuration and safe absolute output directory";
        return false;
    }
    if (config.readyMaxRetries == 0) {
        error = "readyMaxRetries must be positive";
        return false;
    }
    std::lock_guard lock(g_captureConfigMutex);
    g_captureConfig = config;
    return true;
}

EmulatorCaptureConfig GetEmulatorCaptureConfig()
{
    std::lock_guard lock(g_captureConfigMutex);
    return g_captureConfig;
}

bool IsEmulatorCaptureModeEnabled()
{
    std::lock_guard lock(g_captureConfigMutex);
    return g_captureConfig.enabled;
}

bool IsDisplayCaptureFallbackEnabled()
{
    std::lock_guard lock(g_captureConfigMutex);
    return g_captureConfig.enabled && g_captureConfig.displayFallback;
}

uint32_t GetEmulatorFlushSettleMs()
{
    std::lock_guard lock(g_captureConfigMutex);
    return g_captureConfig.enabled ? g_captureConfig.flushSettleMs : 0;
}

void ResetEmulatorCaptureConfigForTest()
{
    std::lock_guard lock(g_captureConfigMutex);
    g_captureConfig = EmulatorCaptureConfig {};
}

int64_t EmulatorMonotonicTimeMs()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

void LogEmulatorTiming(const char* phase, int64_t startMs)
{
    if (IsEmulatorCaptureModeEnabled()) {
        std::cout << "RS_GRAPHIC_TEST_TIMING " << phase << "_ms=" << EmulatorMonotonicTimeMs() - startMs << std::endl;
    }
}

} // namespace Rosen
} // namespace OHOS
