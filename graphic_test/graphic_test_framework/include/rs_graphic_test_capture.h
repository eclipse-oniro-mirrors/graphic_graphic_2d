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

#ifndef RS_GRAPHIC_TEST_CAPTURE_H
#define RS_GRAPHIC_TEST_CAPTURE_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Rosen {

struct EmulatorCaptureConfig {
    bool enabled = false;
    bool displayFallback = false;
    std::string outputDirectory;
    uint32_t readyMaxRetries = 3;
    uint32_t readyDelayMs = 0;
    uint32_t flushSettleMs = 0;
};

bool ConfigureEmulatorCapture(const EmulatorCaptureConfig& config, std::string& error);
EmulatorCaptureConfig GetEmulatorCaptureConfig();
bool IsEmulatorCaptureModeEnabled();
bool IsDisplayCaptureFallbackEnabled();
uint32_t GetEmulatorFlushSettleMs();
void ResetEmulatorCaptureConfigForTest();

void SetGraphicTestCaptureNativeToken();
int64_t EmulatorMonotonicTimeMs();
void LogEmulatorTiming(const char* phase, int64_t startMs);

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_CAPTURE_H
