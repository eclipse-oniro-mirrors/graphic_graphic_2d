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

#include "rsinterfaces009_fuzzer.h"

#include <securec.h>

#include "transaction/rs_interfaces.h"

namespace OHOS {
namespace Rosen {
namespace {
const uint8_t DO_SHOW_WATERMARK = 0;
const uint8_t DO_SET_WATERMARK = 1;
const uint8_t DO_SET_SURFACE_WATERMARK = 2;
const uint8_t DO_CLEAR_SURFACE_WATERMARK_FOR_NODES = 3;
const uint8_t DO_CLEAR_SURFACE_WATERMARK = 4;
const uint8_t TARGET_SIZE = 5;

const uint8_t* DATA = nullptr;
size_t g_size = 0;
size_t g_pos;
constexpr size_t STR_LEN = 10;

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

/*
 * get a string from g_data
 */
std::string GetStringFromData(int strlen)
{
    if (strlen <= 0) {
        return "fuzz";
    }
    char cstr[strlen];
    cstr[strlen - 1] = '\0';
    for (int i = 0; i < strlen - 1; i++) {
        char tmp = GetData<char>();
        if (tmp == '\0') {
            tmp = '1';
        }
        cstr[i] = tmp;
    }
    std::string str(cstr);
    return str;
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

void DoShowWatermark()
{
    Media::InitializationOptions opts;
    opts.size.width = GetData<int32_t>();
    opts.size.height = GetData<int32_t>();
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    opts.pixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>());
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>());
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    std::shared_ptr<Media::PixelMap>  watermarkImg = Media::PixelMap::Create(opts);
    bool isShow = GetData<bool>();
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.ShowWatermark(watermarkImg, isShow);
}

void DoSetWatermark()
{
    std::string name = GetStringFromData(STR_LEN);
    Media::InitializationOptions opts;
    opts.size.width = GetData<int32_t>();
    opts.size.height = GetData<int32_t>();
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    opts.pixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>());
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>());
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    std::shared_ptr<Media::PixelMap>  watermark = Media::PixelMap::Create(opts);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterfaces.SetWatermark(name, watermark);
}

void DoSetSurfaceWatermark()
{
    std::string name = GetStringFromData(STR_LEN);
    opts.size.width = GetData<int32_t>();
    opts.size.height = GetData<int32_t>();
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    opts.pixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>());
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>());
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    std::shared_ptr<Media::PixelMap>  watermark = Media::PixelMap::Create(opts);

    auto& rsInterfaces = RSInterfaces::GetInstance();
    auto watermarkType = GetData<uint8_t>() % static_cast<uint8_t>(SurfaceWatermarkType::INVALID_WATER_MARK);
    rsInterface.SetSurfaceWatermark(0, name, watermark, {GetData<uint64_t>(), GetData<uint64_t>()},
        static_cast<SurfaceCaptureType>(watermarkType));
}

void DoClearSurfaceWatermarkForNodes()
{
    std::string name = GetStringFromData(STR_LEN);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterface.ClearSurfaceWatermarkForNodes(0, name, {GetData<uint64_t>(), GetData<uint64_t>()});
}

void DoClearSurfaceWatermark()
{
    std::string name = GetStringFromData(STR_LEN);
    auto& rsInterfaces = RSInterfaces::GetInstance();
    rsInterface.ClearSurfaceWatermarkForNodes(0, name);
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
        case OHOS::Rosen::DO_SHOW_WATERMARK:
            OHOS::Rosen::DoShowWatermark();
            break;
        case OHOS::Rosen::DO_SET_WATERMARK:
            OHOS::Rosen::DoSetWatermark();
            break;
        case OHOS::Rosen::DO_SET_SURFACE_WATERMARK:
            OHOS::Rosen::DoSetSurfaceWatermark();
        case OHOS::Rosen::DO_CLEAR_SURFACE_WATERMARK:
            OHOS::Rosen::DoClearSurfaceWatermarkForNodes();
        case OHOS::Rosen::DO_CLEAR_SURFACE_WATERMARK:
            OHOS::Rosen::DoClearSurfaceWatermark();
        default:
            return -1;
    }
    return 0;
}
