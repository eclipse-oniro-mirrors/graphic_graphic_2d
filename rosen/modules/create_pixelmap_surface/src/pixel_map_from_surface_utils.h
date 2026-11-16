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

// Minimum layout of a format: a row of the first plane holds at least width * bytesPerPixel
// bytes, and the other planes add ceil(height * extraRowsNum / extraRowsDen) rows of stride bytes.
struct PixelFormatLayout {
    int32_t format;
    int32_t bytesPerPixel;
    int32_t extraRowsNum;
    int32_t extraRowsDen;
};

constexpr int32_t BYTES_8BIT = 1;
constexpr int32_t BYTES_16BIT = 2;
constexpr int32_t BYTES_24BIT = 3;
constexpr int32_t BYTES_32BIT = 4;
constexpr int32_t BYTES_64BIT = 8;
constexpr int32_t SINGLE_PLANE_NUM = 0;
constexpr int32_t SINGLE_PLANE_DEN = 1;
constexpr int32_t YUV420_EXTRA_NUM = 1; // chroma takes half as many rows as luma
constexpr int32_t YUV420_EXTRA_DEN = 2;
constexpr int32_t YUV422_EXTRA_NUM = 1; // chroma takes as many rows as luma
constexpr int32_t YUV422_EXTRA_DEN = 1;

// Formats missing here (CLUT, RAW10, BLOB, vendor private) have no layout rule this module
// can verify, so they are rejected rather than imported with an unchecked size.
inline constexpr PixelFormatLayout PIXEL_FORMAT_LAYOUTS[] = {
    { GRAPHIC_PIXEL_FMT_RGBX_8888, BYTES_32BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBA_8888, BYTES_32BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_BGRX_8888, BYTES_32BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_BGRA_8888, BYTES_32BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBA_1010102, BYTES_32BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    // 38 bits of data per pixel, so at least 4 bytes; the exact pixel size is defined by the display
    // HDI and should replace this lower bound once confirmed
    { GRAPHIC_PIXEL_FMT_RGBA_1010108, BYTES_32BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBA_R16G16, BYTES_32BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBA16_FLOAT, BYTES_64BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGB_888, BYTES_24BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBA_5658, BYTES_24BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGB_565, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_BGR_565, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBX_4444, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBA_4444, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_BGRX_4444, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_BGRA_4444, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGB_444, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBX_5551, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGBA_5551, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_BGRX_5551, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_BGRA_5551, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_RGB_555, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_YUV_422_I, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_YUYV_422_PKG, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_UYVY_422_PKG, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_YVYU_422_PKG, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_VYUY_422_PKG, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_Y16, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    // single-channel half float: image_framework allocates PixelFormat::ALPHA_F16 with this format
    { GRAPHIC_PIXEL_FMT_FP16, BYTES_16BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_Y8, BYTES_8BIT, SINGLE_PLANE_NUM, SINGLE_PLANE_DEN },
    { GRAPHIC_PIXEL_FMT_YCBCR_420_SP, BYTES_8BIT, YUV420_EXTRA_NUM, YUV420_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCRCB_420_SP, BYTES_8BIT, YUV420_EXTRA_NUM, YUV420_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCBCR_420_P, BYTES_8BIT, YUV420_EXTRA_NUM, YUV420_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCRCB_420_P, BYTES_8BIT, YUV420_EXTRA_NUM, YUV420_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCBCR_P010, BYTES_16BIT, YUV420_EXTRA_NUM, YUV420_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCRCB_P010, BYTES_16BIT, YUV420_EXTRA_NUM, YUV420_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCBCR_422_SP, BYTES_8BIT, YUV422_EXTRA_NUM, YUV422_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCRCB_422_SP, BYTES_8BIT, YUV422_EXTRA_NUM, YUV422_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCBCR_422_P, BYTES_8BIT, YUV422_EXTRA_NUM, YUV422_EXTRA_DEN },
    { GRAPHIC_PIXEL_FMT_YCRCB_422_P, BYTES_8BIT, YUV422_EXTRA_NUM, YUV422_EXTRA_DEN },
};

inline const PixelFormatLayout* FindPixelFormatLayout(int32_t format)
{
    for (const auto& layout : PIXEL_FORMAT_LAYOUTS) {
        if (layout.format == format) {
            return &layout;
        }
    }
    return nullptr;
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
    const PixelFormatLayout* layout = FindPixelFormatLayout(info.format);
    if (layout == nullptr || info.width <= 0 || info.height <= 0 || info.stride <= 0 || info.size <= 0 ||
        allocationSize <= 0) {
        return false;
    }
    const int64_t minStride = static_cast<int64_t>(info.width) * static_cast<int64_t>(layout->bytesPerPixel);
    const int64_t firstPlaneSize = static_cast<int64_t>(info.height) * static_cast<int64_t>(info.stride);
    if (info.stride < minStride || firstPlaneSize > info.size || info.size > allocationSize) {
        return false;
    }
    // firstPlaneSize <= size <= INT32_MAX here, so the products below cannot overflow int64_t
    const int64_t extraRows = (static_cast<int64_t>(info.height) * layout->extraRowsNum +
        layout->extraRowsDen - 1) / layout->extraRowsDen;
    const int64_t layoutSize = firstPlaneSize + extraRows * static_cast<int64_t>(info.stride);
    return layoutSize <= info.size;
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
