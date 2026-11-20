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

#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>

#include "effect_filter.h"
#include "effect_types.h"

#include "image_source.h"
#include "pixel_map.h"
#include "pixelmap_native_impl.h"

using namespace OHOS;
using namespace OHOS::Media;

namespace {
const std::string DEFAULT_IMAGE_PATH = "/data/local/tmp/backgroundImage.jpg";
const std::string DEFAULT_IMAGE_PATH_2 = "/data/local/tmp/backgroundImage2.jpg";
const std::string DEFAULT_IMAGE_PATH_3 = "/data/local/tmp/backgroundImage3.jpg";

constexpr float BLUR_RADIUS_SMALL = 15.0f;
constexpr float BLUR_RADIUS_MEDIUM = 25.0f;
constexpr float BLUR_RADIUS_LARGE = 40.0f;

constexpr uint32_t TAG_ID_BLUR_BACKGROUND = 1001;
constexpr uint32_t TAG_ID_BLUR_DIALOG = 1002;
constexpr uint32_t TAG_ID_BLUR_AVATAR = 1003;

const char* TAG_NAME_BLUR_BACKGROUND = "blur_background";
const char* TAG_NAME_BLUR_DIALOG = "blur_dialog";
const char* TAG_NAME_BLUR_AVATAR = "blur_avatar";

const char* EffectErrorCodeToString(EffectErrorCode code)
{
    switch (code) {
        case EFFECT_SUCCESS: return "EFFECT_SUCCESS";
        case EFFECT_BAD_PARAMETER: return "EFFECT_BAD_PARAMETER";
        default: return "UNKNOWN";
    }
}

void PrintTag(const char* scenario, uint32_t tagId, const char* tagName)
{
    std::cout << "[Tracker] scenario=" << scenario <<
        ", tagId=" << tagId <<
        ", tagName=" << (tagName ? tagName : "(null)") <<
        ", pid=" << getpid() <<
        ", tid=" << gettid() <<
        std::endl;
}
} // namespace

std::shared_ptr<PixelMap> DecodePixelMap(const std::string& pathName)
{
    uint32_t errCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(pathName, SourceOptions(), errCode);
    if (imageSource == nullptr || errCode != 0) {
        std::cout << "DecodePixelMap: create image source failed, errCode=" << errCode << std::endl;
        return nullptr;
    }

    DecodeOptions decodeOpt;
    decodeOpt.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(decodeOpt, errCode);
    if (pixelmap == nullptr || errCode != 0) {
        std::cout << "DecodePixelMap: create pixel map failed, errCode=" << errCode << std::endl;
        return nullptr;
    }
    std::cout << "DecodePixelMap: success, width=" << pixelmap->GetWidth() <<
        ", height=" << pixelmap->GetHeight() << std::endl;
    return pixelmap;
}

void RunBlurScenario(OH_PixelmapNative* srcPixelmap, float radius,
    uint32_t tagId, const char* tagName, const char* scenarioName)
{
    std::cout << "\n  [" << scenarioName << "] radius=" << radius << std::endl;

    OH_Filter* filter = nullptr;
    EffectErrorCode ret = OH_Filter_CreateEffect(srcPixelmap, &filter);
    if (ret != EFFECT_SUCCESS || filter == nullptr) {
        std::cout << "  " << scenarioName << ": CreateEffect failed, ret=" <<
            EffectErrorCodeToString(ret) << std::endl;
        return;
    }

    PrintTag(scenarioName, tagId, tagName);
    ret = OH_Filter_SetGpuResourceTag(filter, tagId, tagName);
    if (ret != EFFECT_SUCCESS) {
        std::cout << "  " << scenarioName << ": SetGpuResourceTag failed, ret=" <<
            EffectErrorCodeToString(ret) << std::endl;
        OH_Filter_Release(filter);
        return;
    }

    ret = OH_Filter_Blur(filter, radius);
    if (ret != EFFECT_SUCCESS) {
        std::cout << "  " << scenarioName << ": Blur failed, ret=" <<
            EffectErrorCodeToString(ret) << std::endl;
        OH_Filter_Release(filter);
        return;
    }

    OH_PixelmapNative* result = nullptr;
    ret = OH_Filter_GetEffectPixelMap(filter, &result);
    std::cout << "  " << scenarioName << ": " << EffectErrorCodeToString(ret) << std::endl;

    char* statistics = nullptr;
    ret = OH_Filter_GetGpuMemoryStatistics(filter, &statistics);
    if (ret == EFFECT_SUCCESS && statistics != nullptr) {
        std::cout << "  [Statistics] tagId=" << tagId << " (" << tagName << "):\n" <<
            statistics << std::endl;
        free(statistics);
    } else {
        std::cout << "  [Statistics] query failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
    }

    if (result != nullptr) {
        OH_PixelmapNative_Release(result);
    }
    OH_Filter_Release(filter);
}

void DemoBlurWithoutCustomTag(OH_PixelmapNative* srcPixelmap)
{
    std::cout << "\n=== Demo 1: Blur without custom tag ===" << std::endl;

    OH_Filter* filter = nullptr;
    EffectErrorCode ret = OH_Filter_CreateEffect(srcPixelmap, &filter);
    if (ret != EFFECT_SUCCESS || filter == nullptr) {
        std::cout << "Demo1: CreateEffect failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
        return;
    }

    PrintTag("blur_no_custom", 0, nullptr);
    ret = OH_Filter_SetGpuResourceTag(filter, 0, nullptr);
    if (ret != EFFECT_SUCCESS) {
        std::cout << "Demo1: SetGpuResourceTag failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
        OH_Filter_Release(filter);
        return;
    }

    ret = OH_Filter_Blur(filter, BLUR_RADIUS_MEDIUM);
    if (ret != EFFECT_SUCCESS) {
        std::cout << "Demo1: Blur failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
        OH_Filter_Release(filter);
        return;
    }

    OH_PixelmapNative* result = nullptr;
    ret = OH_Filter_GetEffectPixelMap(filter, &result);
    if (ret != EFFECT_SUCCESS || result == nullptr) {
        std::cout << "Demo1: GetEffectPixelMap failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
        OH_Filter_Release(filter);
        return;
    }

    char* statistics = nullptr;
    ret = OH_Filter_GetGpuMemoryStatistics(filter, &statistics);
    if (ret == EFFECT_SUCCESS && statistics != nullptr) {
        std::cout << "Demo1: Blur without custom tag completed successfully." << std::endl;
        std::cout << "       (Default tag: filter type \"blur\".)" << std::endl;
        std::cout << "       [Statistics]:" << std::endl << statistics << std::endl;
        free(statistics);
    } else {
        std::cout << "Demo1: GetGpuMemoryStatistics failed, ret=" <<
            EffectErrorCodeToString(ret) << std::endl;
    }

    OH_PixelmapNative_Release(result);
    OH_Filter_Release(filter);
}

void DemoBlurWithCustomTag(OH_PixelmapNative* srcPixelmap)
{
    std::cout << "\n=== Demo 2: Blur with custom tag ===" << std::endl;

    OH_Filter* filter = nullptr;
    EffectErrorCode ret = OH_Filter_CreateEffect(srcPixelmap, &filter);
    if (ret != EFFECT_SUCCESS || filter == nullptr) {
        std::cout << "Demo2: CreateEffect failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
        return;
    }

    PrintTag("blur_background", TAG_ID_BLUR_BACKGROUND, TAG_NAME_BLUR_BACKGROUND);
    ret = OH_Filter_SetGpuResourceTag(filter, TAG_ID_BLUR_BACKGROUND, TAG_NAME_BLUR_BACKGROUND);
    if (ret != EFFECT_SUCCESS) {
        std::cout << "Demo2: SetGpuResourceTag failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
        OH_Filter_Release(filter);
        return;
    }

    ret = OH_Filter_Blur(filter, BLUR_RADIUS_LARGE);
    if (ret != EFFECT_SUCCESS) {
        std::cout << "Demo2: Blur failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
        OH_Filter_Release(filter);
        return;
    }

    OH_PixelmapNative* result = nullptr;
    ret = OH_Filter_GetEffectPixelMap(filter, &result);
    if (ret != EFFECT_SUCCESS || result == nullptr) {
        std::cout << "Demo2: GetEffectPixelMap failed, ret=" << EffectErrorCodeToString(ret) << std::endl;
        OH_Filter_Release(filter);
        return;
    }

    std::cout << "Demo2: Blur with custom tag completed successfully." << std::endl;
    std::cout << "         GPU resources are tagged with tagId=" << TAG_ID_BLUR_BACKGROUND <<
        " (" << TAG_NAME_BLUR_BACKGROUND << ")" << std::endl;

    char* statistics = nullptr;
    ret = OH_Filter_GetGpuMemoryStatistics(filter, &statistics);
    if (ret == EFFECT_SUCCESS && statistics != nullptr) {
        std::cout << "         [Statistics]:" << std::endl << statistics << std::endl;
        free(statistics);
    } else {
        std::cout << "         GetGpuMemoryStatistics failed, ret=" <<
            EffectErrorCodeToString(ret) << std::endl;
    }

    OH_PixelmapNative_Release(result);
    OH_Filter_Release(filter);
}

void DemoMultiScenarioBlur(OH_PixelmapNative* srcPixelmap)
{
    std::cout << "\n=== Demo 3: Multi-scenario blur (different images + tags) ===" << std::endl;

    auto decodeOrFallback = [](const std::string& path,
            OH_PixelmapNative* fallback) -> OH_PixelmapNative* {
        std::shared_ptr<PixelMap> pm = DecodePixelMap(path);
        if (pm == nullptr) {
            std::cout << "  (fallback: " << path << " not found, using source image)" << std::endl;
            return fallback;
        }
        return new OH_PixelmapNative(pm);
    };

    OH_PixelmapNative* imgBackground = decodeOrFallback(DEFAULT_IMAGE_PATH_2, srcPixelmap);
    OH_PixelmapNative* imgDialog = decodeOrFallback(DEFAULT_IMAGE_PATH_3, srcPixelmap);

    RunBlurScenario(imgBackground, BLUR_RADIUS_LARGE,
        TAG_ID_BLUR_BACKGROUND, TAG_NAME_BLUR_BACKGROUND, "Scenario1: background blur (image2)");

    RunBlurScenario(imgDialog, BLUR_RADIUS_MEDIUM,
        TAG_ID_BLUR_DIALOG, TAG_NAME_BLUR_DIALOG, "Scenario2: dialog blur (image3)");

    RunBlurScenario(srcPixelmap, BLUR_RADIUS_SMALL,
        TAG_ID_BLUR_AVATAR, TAG_NAME_BLUR_AVATAR, "Scenario3: avatar blur (image1)");

    if (imgBackground != srcPixelmap) {
        delete imgBackground;
    }
    if (imgDialog != srcPixelmap) {
        delete imgDialog;
    }

    std::cout << "\nDemo3: Multi-scenario blur completed." << std::endl;
    std::cout << "       Each scenario printed its own GPU memory statistics," << std::endl;
    std::cout << "       queried via OH_Filter_GetGpuMemoryStatistics (string returned to app)." << std::endl;
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << "  Effect GPU Tracker - Blur Demo" << std::endl;
    std::cout << "  pid=" << getpid() << ", tid=" << gettid() << std::endl;
    std::cout << "========================================" << std::endl;

    std::shared_ptr<PixelMap> srcPixelMap = DecodePixelMap(DEFAULT_IMAGE_PATH);
    if (srcPixelMap == nullptr) {
        std::cout << "Failed to decode source image from " << DEFAULT_IMAGE_PATH << std::endl;
        std::cout << "Please push a test image to " << DEFAULT_IMAGE_PATH << " first." << std::endl;
        std::cout << "For Demo3, optionally push additional images to:" << std::endl;
        std::cout << "  " << DEFAULT_IMAGE_PATH_2 << std::endl;
        std::cout << "  " << DEFAULT_IMAGE_PATH_3 << std::endl;
        return 1;
    }

    OH_PixelmapNative* srcPixelmap = new OH_PixelmapNative(srcPixelMap);
    if (srcPixelmap == nullptr) {
        std::cout << "Failed to create OH_PixelmapNative" << std::endl;
        return 1;
    }

    DemoBlurWithoutCustomTag(srcPixelmap);
    DemoBlurWithCustomTag(srcPixelmap);
    DemoMultiScenarioBlur(srcPixelmap);

    delete srcPixelmap;

    std::cout << "\n========================================" << std::endl;
    std::cout << "  All demos completed." << std::endl;
    std::cout << "  GPU memory statistics were queried via" << std::endl;
    std::cout << "  OH_Filter_GetGpuMemoryStatistics and printed by the demo itself" << std::endl;
    std::cout << "  (no automatic hilog dumping)." << std::endl;
    std::cout << "========================================" << std::endl;
    return 0;
}