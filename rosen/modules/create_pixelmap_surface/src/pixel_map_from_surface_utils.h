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

#ifndef PIXEL_MAP_FROM_SURFACE_UTILS_H
#define PIXEL_MAP_FROM_SURFACE_UTILS_H

#include <cstdint>
#include <unistd.h>
#include "surface_type.h"

namespace OHOS {
namespace Rosen {
struct BufferLayoutInfo {
    int32_t format = GRAPHIC_PIXEL_FMT_BUTT;
    int32_t width = 0;
    int32_t height = 0;
    int32_t stride = 0; // bytes per row of the first plane
    int32_t size = 0;
};

struct PixelFormatLayout {
    int32_t bytesPerPixel = 0; // 0 means the format is not supported
    bool hasHalfHeightChroma = false; // YUV420: chroma adds ceil(height / 2) rows of stride bytes
};

constexpr int32_t BYTES_8BIT = 1;
constexpr int32_t BYTES_16BIT = 2;
constexpr int32_t BYTES_32BIT = 4;
constexpr int32_t BYTES_64BIT = 8;
constexpr int64_t YUV420_CHROMA_ROW_DIVISOR = 2;

// Supported formats are those RS composition renders (see GetColorTypeFromBufferFormat), the
// YUV420 formats of camera and video, and FP16. Other formats have no layout rule here and are
// rejected rather than imported with an unchecked size.
inline PixelFormatLayout GetPixelFormatLayout(int32_t format)
{
    switch (format) {
        case GRAPHIC_PIXEL_FMT_RGBA_8888:
        case GRAPHIC_PIXEL_FMT_RGBX_8888:
        case GRAPHIC_PIXEL_FMT_BGRA_8888:
        case GRAPHIC_PIXEL_FMT_BGRX_8888:
        case GRAPHIC_PIXEL_FMT_RGBA_1010102:
        // 38 bits of data per pixel, so at least 4 bytes; replace with the display HDI pixel size once confirmed
        case GRAPHIC_PIXEL_FMT_RGBA_1010108:
            return { BYTES_32BIT, false };
        case GRAPHIC_PIXEL_FMT_RGBA16_FLOAT:
            return { BYTES_64BIT, false };
        case GRAPHIC_PIXEL_FMT_RGB_565:
        // single-channel half float: image_framework allocates PixelFormat::ALPHA_F16 with this format
        case GRAPHIC_PIXEL_FMT_FP16:
            return { BYTES_16BIT, false };
        case GRAPHIC_PIXEL_FMT_YCBCR_420_SP:
        case GRAPHIC_PIXEL_FMT_YCRCB_420_SP:
        case GRAPHIC_PIXEL_FMT_YCBCR_420_P:
        case GRAPHIC_PIXEL_FMT_YCRCB_420_P:
            return { BYTES_8BIT, true };
        case GRAPHIC_PIXEL_FMT_YCBCR_P010:
        case GRAPHIC_PIXEL_FMT_YCRCB_P010:
            return { BYTES_16BIT, true };
        default:
            return {};
    }
}

// Returns the real size of the memory behind fd, or -1 on failure. lseek(SEEK_END) is used
// instead of fstat because it works for dma-buf and needs no getattr permission; the file
// offset it moves is not used by dma-buf consumers.
inline int64_t GetFdAllocationSize(int fd)
{
    if (fd < 0) {
        return -1;
    }
    off_t size = ::lseek(fd, 0, SEEK_END);
    return size > 0 ? static_cast<int64_t>(size) : -1;
}

// BufferHandle geometry and format come from the buffer producer, which may run in another
// process. The GPU sizes the imported image from width, height and format, so the minimum
// layout of that format must fit in size, and size must fit in the real allocation.
inline bool IsBufferLayoutWithinSize(const BufferLayoutInfo& info, int64_t allocationSize)
{
    const PixelFormatLayout layout = GetPixelFormatLayout(info.format);
    if (layout.bytesPerPixel == 0 || info.width <= 0 || info.height <= 0 || info.stride <= 0 ||
        info.size <= 0 || allocationSize <= 0) {
        return false;
    }
    const int64_t minStride = static_cast<int64_t>(info.width) * static_cast<int64_t>(layout.bytesPerPixel);
    const int64_t firstPlaneSize = static_cast<int64_t>(info.height) * static_cast<int64_t>(info.stride);
    if (info.stride < minStride || firstPlaneSize > info.size || info.size > allocationSize) {
        return false;
    }
    if (!layout.hasHalfHeightChroma) {
        return true;
    }
    // firstPlaneSize <= size <= INT32_MAX here, so the sum below cannot overflow int64_t
    const int64_t chromaRows =
        (static_cast<int64_t>(info.height) + YUV420_CHROMA_ROW_DIVISOR - 1) / YUV420_CHROMA_ROW_DIVISOR;
    return firstPlaneSize + chromaRows * static_cast<int64_t>(info.stride) <= info.size;
}

template<typename RectType>
inline bool IsSrcRectValid(int32_t bufferWidth, int32_t bufferHeight, const RectType& srcRect)
{
    if (bufferWidth <= 0 || bufferHeight <= 0 || srcRect.left < 0 || srcRect.top < 0 ||
        srcRect.width <= 0 || srcRect.height <= 0) {
        return false;
    }
    const int64_t right = static_cast<int64_t>(srcRect.left) + static_cast<int64_t>(srcRect.width);
    const int64_t bottom = static_cast<int64_t>(srcRect.top) + static_cast<int64_t>(srcRect.height);
    return right <= static_cast<int64_t>(bufferWidth) && bottom <= static_cast<int64_t>(bufferHeight);
}
} // namespace Rosen
} // namespace OHOS

#endif // PIXEL_MAP_FROM_SURFACE_UTILS_H
