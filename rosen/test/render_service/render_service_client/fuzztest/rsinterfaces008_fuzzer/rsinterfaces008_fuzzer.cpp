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

#include "rsinterfaces008_fuzzer.h"

#include <securec.h>

#include "transaction/rs_interfaces.h"

namespace OHOS {
namespace Rosen {
namespace {
const uint8_t DO_CREATE_PIXEL_MAP_FROM_SURFACE = 0;
const uint8_t DO_GET_SCREEN_HDR_CAPABILITY = 1;
const uint8_t DO_SET_PIXEL_FORMAT = 2;
const uint8_t DO_GET_PIXEL_FORMAT = 3;
const uint8_t DO_GET_SCREEN_SUPPORTED_HDR_FORMATS = 4;
const uint8_t DO_GET_SCREEN_HDR_FORMAT = 5;
const uint8_t DO_SET_SCREEN_HDR_FORMAT = 6;
const uint8_t DO_GET_SCREEN_SUPPORTED_COLORSPACES = 7;
const uint8_t DO_GET_SCREEN_COLORSPACE = 8;
const uint8_t DO_SET_SCREEN_COLORSPACE = 9;
const uint8_t DO_GET_SCREEN_TYPE = 10;
const uint8_t DO_SET_SCREEN_SKIP_FRAME_INTERVAL = 11;
const uint8_t DO_GET_BITMAP = 12;
const uint8_t DO_GET_PIXELMAP = 13;
const uint8_t TARGET_SIZE = 14;
const uint8_t DO_GET_SCREEN_HDR_STATUS = 15;

const uint8_t* DATA = nullptr;
size_t g_size = 0;
size_t g_pos;
constexpr uint8_t GRPAHIC_PIXEL_FORMAT_SIZE = 43;
constexpr uint8_t SCREEN_HDR_FORMAT_SIZE = 8;
constexpr uint8_t GRPAHIC_CM_COLOR_SPACE_TPYE_SIZE = 32;
constexpr uint8_t SCREEN_TYPE_SIZE = 4;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (DATA == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

bool Init(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    DATA = data;
    g_size = size;
    g_pos = 0;
    return true;
}
} // namespace

namespace Mock {

} // namespace Mock

void DoCreatePixelMapFromSurface()
{
    uint64_t surfaceId = GetData<uint64_t>();
    Rect srcRect = {0, 0, 100, 100};
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.CreatePixelMapFromSurfaceId(surfaceId, srcRect);
}

void DoGetScreenHDRCapability()
{
    ScreenId id = GetData<ScreenId>();
    RSScreenHDRCapability screenHdrCapability;
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.GetScreenHDRCapability(id, screenHdrCapability);
}

void DoSetPixelFormat()
{
    ScreenId id = GetData<ScreenId>();
    GraphicPixelFormat format = static_cast<GraphicPixelFormat>(GetData<uint8_t>() % GRPAHIC_PIXEL_FORMAT_SIZE);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.SetPixelFormat(id, format);
}

void DoGetPixelFormat()
{
    ScreenId id = GetData<ScreenId>();
    GraphicPixelFormat format = static_cast<GraphicPixelFormat>(GetData<uint8_t>() % GRPAHIC_PIXEL_FORMAT_SIZE);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.GetPixelFormat(id, format);
}

void DoGetScreenSupportedHDRFormats()
{
    ScreenId id = GetData<ScreenId>();
    ScreenHDRFormat hdrFormat = static_cast<ScreenHDRFormat>(GetData<uint8_t>() % SCREEN_HDR_FORMAT_SIZE);
    std::vector<ScreenHDRFormat> hdrFormats = { hdrFormat };
    client->GetScreenSupportedHDRFormats(id, hdrFormats);
}

void DoGetScreenHDRFormat()
{
    ScreenId id = GetData<ScreenId>();
    ScreenHDRFormat format = static_cast<ScreenHDRFormat>(GetData<uint8_t>() % SCREEN_HDR_FORMAT_SIZE);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.GetScreenHDRFormat(id, format);
}

void DoSetScreenHDRFormat()
{
    ScreenId id = GetData<uint64_t>();
    int32_t modeIdx = GetData<int32_t>();
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.SetScreenHDRFormat(id, modeIdx);
}

void DoGetScreenSupportedColorSpaces()
{
    ScreenId id = GetData<ScreenId>();
    GraphicCM_ColorSpaceType colorSpace =
        static_cast<GraphicCM_ColorSpaceType>(GetData<uint8_t>() % GRPAHIC_CM_COLOR_SPACE_TPYE_SIZE);
    std::vector<GraphicCM_ColorSpaceType> colorSpaces = { colorSpace };
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.GetScreenSupportedColorSpaces(id, colorSpaces);
}

void DoGetScreenColorSpace()
{
    ScreenId id = GetData<ScreenId>();
    GraphicCM_ColorSpaceType colorSpace =
        static_cast<GraphicCM_ColorSpaceType>(GetData<uint8_t>() % GRPAHIC_CM_COLOR_SPACE_TPYE_SIZE);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.GetScreenColorSpace(id, colorSpace);
}

void DoSetScreenColorSpace()
{
    ScreenId id = GetData<ScreenId>();
    GraphicCM_ColorSpaceType colorSpace =
        static_cast<GraphicCM_ColorSpaceType>(GetData<uint8_t>() % GRPAHIC_CM_COLOR_SPACE_TPYE_SIZE);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.SetScreenColorSpace(id, colorSpace);
}

void DoGetScreenType()
{
    ScreenId id = GetData<ScreenId>();
    RSScreenType screenType = static_cast<RSScreenType>(GetData<uint8_t>() % SCREEN_TYPE_SIZE);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.GetScreenType(id, screenType);
}

void DoSetScreenSkipFrameInterval()
{
    ScreenId id = GetData<uint64_t>();
    uint32_t skipFrameInterval = GetData<uint32_t>();
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.SetScreenSkipFrameInterval(id, skipFrameInterval);
}

void DoGetScreenHDRStatus()
{
    static std::vector<HdrStatus> statusVec = { HdrStatus::NO_HDR, HdrStatus::HDR_PHOTO, HdrStatus::HDR_VIDEO,
        HdrStatus::AI_HDR_VIDEO_GTM, HdrStatus::HDR_EFFECT };
    ScreenId screenId = GetData<ScreenId>();
    HdrStatus hdrStatus = statusVec[GetData<uint8_t>() % statusVec.size()];
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.GetScreenHDRStatus(screenId, hdrStatus);
}
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!OHOS::Rosen::Init(data, size)) {
        return -1;
    }
    /* Run your code on data */
    uint8_t tarPos = OHOS::Rosen::GetData<uint8_t>() % OHOS::Rosen::TARGET_SIZE;
    switch (tarPos) {
        case OHOS::Rosen::DO_CREATE_PIXEL_MAP_FROM_SURFACE:
            OHOS::Rosen::DoCreatePixelMapFromSurface();
            break;
        case OHOS::Rosen::DO_GET_SCREEN_HDR_CAPABILITY:
            OHOS::Rosen::DoGetScreenHDRCapability();
            break;
        case OHOS::Rosen::DO_SET_PIXEL_FORMAT:
            OHOS::Rosen::DoSetPixelFormat();
            break;
        case OHOS::Rosen::DO_GET_PIXEL_FORMAT:
            OHOS::Rosen::DoGetPixelFormat();
            break;
        case OHOS::Rosen::DO_GET_SCREEN_SUPPORTED_HDR_FORMATS:
            OHOS::Rosen::DoGetScreenSupportedHDRFormats();
            break;
        case OHOS::Rosen::DO_GET_SCREEN_HDR_FORMAT:
            OHOS::Rosen::DoGetScreenHDRFormat();
            break;
        case OHOS::Rosen::DO_SET_SCREEN_HDR_FORMAT:
            OHOS::Rosen::DoSetScreenHDRFormat();
            break;
        case OHOS::Rosen::DO_GET_SCREEN_SUPPORTED_COLORSPACES:
            OHOS::Rosen::DoGetScreenSupportedColorSpaces();
            break;
        case OHOS::Rosen::DO_GET_SCREEN_COLORSPACE:
            OHOS::Rosen::DoGetScreenColorSpace();
            break;
        case OHOS::Rosen::DO_SET_SCREEN_COLORSPACE:
            OHOS::Rosen::DoSetScreenColorSpace();
            break;
        case OHOS::Rosen::DO_GET_SCREEN_TYPE:
            OHOS::Rosen::DoGetScreenType();
            break;
        case OHOS::Rosen::DO_SET_SCREEN_SKIP_FRAME_INTERVAL:
            OHOS::Rosen::DoSetScreenSkipFrameInterval();
            break;
        case OHOS::Rosen::DO_GET_SCREEN_HDR_STATUS:
            OHOS::Rosen::DoGetScreenHDRStatus();
            break;
        default:
            return -1;
    }
    return 0;
}
