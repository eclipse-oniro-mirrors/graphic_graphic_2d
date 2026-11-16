/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "pixel_map_from_surface.h"
#include "pixel_map_from_surface_utils.h"
#include "iconsumer_surface.h"
#include "ibuffer_consumer_listener.h"
#include <gtest/gtest.h>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class BufferConsumerListener : public ::OHOS::IBufferConsumerListener {
public:
    void OnBufferAvailable() override
    {
    }
};
class PixelMapFromSurfaceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    static inline GSError OnBufferRelease(sptr<SurfaceBuffer> &buffer)
    {
        return GSERROR_OK;
    }
};

void PixelMapFromSurfaceTest::SetUpTestCase() {}

void PixelMapFromSurfaceTest::TearDownTestCase() {}

namespace {
/*
* Function: CreatePixelMapFromSurface001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription:
    1. call CreatePixelMapFromSurface with nullptr suface and should return nullptr
    2. call CreatePixelMapFromSurface with incorrect rect.left and should return nullptr
    3. call CreatePixelMapFromSurface with incorrect rect.top and should return nullptr
    4. call CreatePixelMapFromSurface with incorrect rect.width and should return nullptr
    5. call CreatePixelMapFromSurface with incorrect rect.height and should return nullptr
 */
HWTEST_F(PixelMapFromSurfaceTest, CreatePixelMapFromSurface001, Function | MediumTest| Level3)
{
    OHOS::Media::Rect srcRect = {0, 0, 100, 100};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurface(nullptr, srcRect), nullptr);
    auto cSurface = IConsumerSurface::Create();
    ASSERT_NE(cSurface, nullptr);
    auto producer = cSurface->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);
    srcRect = {-1, 0, 100, 100};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurface(pSurface, srcRect), nullptr);
    srcRect = {0, -1, 100, 100};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurface(pSurface, srcRect), nullptr);
    srcRect = {0, 0, 0, 100};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurface(pSurface, srcRect), nullptr);
    srcRect = {0, 0, 100, 0};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurface(pSurface, srcRect), nullptr);
}

/*
* Function: CreatePixelMapFromSurface002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription:
    1. call CreatePixelMapFromSurface should fail because this Process is not render_service
 */
HWTEST_F(PixelMapFromSurfaceTest, CreatePixelMapFromSurface002, Function | MediumTest| Level3)
{
    BufferRequestConfig requestConfig = {
        .width = 100,
        .height = 100,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
    };
    BufferFlushConfig flushConfig = {
        .damage = {
            .w = 100,
            .h = 100,
        },
    };

    auto csurf = IConsumerSurface::Create();
    sptr<IBufferConsumerListener> listener = new BufferConsumerListener();
    csurf->RegisterConsumerListener(listener);
    auto producer = csurf->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    pSurface->RegisterReleaseListener(OnBufferRelease);

    sptr<SurfaceBuffer> buffer = nullptr;
    int releaseFence = -1;
    GSError ret = pSurface->RequestBuffer(buffer, releaseFence, requestConfig);
    ASSERT_EQ(ret, OHOS::GSERROR_OK);
    ASSERT_NE(buffer, nullptr);
    ret = pSurface->FlushBuffer(buffer, -1, flushConfig);
    ASSERT_EQ(ret, OHOS::GSERROR_OK);

    // CreatePixelMapFromSurface should fail because this Process is not render_service
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurface(pSurface, {0, 0, 100, 100}), nullptr);
}

/*
* Function: CreatePixelMapFromSurfaceBuffer001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription:
    1. call CreatePixelMapFromSurfaceBuffer with nullptr suface and should return nullptr
    2. call CreatePixelMapFromSurfaceBuffer with incorrect rect.left and should return nullptr
    3. call CreatePixelMapFromSurfaceBuffer with incorrect rect.top and should return nullptr
    4. call CreatePixelMapFromSurfaceBuffer with incorrect rect.width and should return nullptr
    5. call CreatePixelMapFromSurfaceBuffer with incorrect rect.height and should return nullptr
    6. call CreatePixelMapFromSurfaceBuffer without GPUContext and should return nullptr
 */
HWTEST_F(PixelMapFromSurfaceTest, CreatePixelMapFromSurfaceBuffer001, Function | MediumTest| Level3)
{
    OHOS::Media::Rect srcRect = {0, 0, 100, 100};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurfaceBuffer(nullptr, srcRect), nullptr);
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    ASSERT_EQ(surfaceBuffer, nullptr);
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurfaceBuffer(surfaceBuffer, srcRect), nullptr);
    surfaceBuffer = SurfaceBuffer::Create().GetRefPtr();
    ASSERT_NE(surfaceBuffer, nullptr);
    srcRect = {-1, 0, 100, 100};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurfaceBuffer(surfaceBuffer, srcRect), nullptr);
    srcRect = {0, -1, 100, 100};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurfaceBuffer(surfaceBuffer, srcRect), nullptr);
    srcRect = {0, 0, 0, 100};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurfaceBuffer(surfaceBuffer, srcRect), nullptr);
    srcRect = {0, 0, 100, 0};
    ASSERT_EQ(OHOS::Rosen::CreatePixelMapFromSurfaceBuffer(surfaceBuffer, srcRect), nullptr);
}

/*
* Function: IsSrcRectValid
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription:
    1. accept a rect that exactly matches the SurfaceBuffer bounds
    2. reject rects that cross the right or bottom bounds
    3. reject invalid SurfaceBuffer dimensions and invalid rect dimensions
 */
HWTEST_F(PixelMapFromSurfaceTest, IsSrcRectValid001, Function | MediumTest| Level3)
{
    constexpr int32_t bufferWidth = 100;
    constexpr int32_t bufferHeight = 100;

    ASSERT_TRUE(IsSrcRectValid(
        bufferWidth, bufferHeight, OHOS::Media::Rect {0, 0, bufferWidth, bufferHeight}));
    ASSERT_FALSE(IsSrcRectValid(
        bufferWidth, bufferHeight, OHOS::Media::Rect {1, 0, bufferWidth, bufferHeight}));
    ASSERT_FALSE(IsSrcRectValid(
        bufferWidth, bufferHeight, OHOS::Media::Rect {0, 1, bufferWidth, bufferHeight}));
    ASSERT_FALSE(IsSrcRectValid(0, bufferHeight, OHOS::Media::Rect {0, 0, 1, 1}));
    ASSERT_FALSE(IsSrcRectValid(bufferWidth, bufferHeight, OHOS::Media::Rect {0, 0, 0, 1}));
    ASSERT_FALSE(IsSrcRectValid(bufferWidth, bufferHeight,
        OHOS::Media::Rect {std::numeric_limits<int32_t>::max(), 0, 1, 1}));
}

/*
* Function: GetFdAllocationSize
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription:
    1. return -1 for an invalid fd
    2. return the real size of a memfd, independent of the current file offset
    3. return -1 for an empty memfd
 */
HWTEST_F(PixelMapFromSurfaceTest, GetFdAllocationSize001, Function | MediumTest| Level3)
{
    constexpr off_t memfdSize = 4096 * 4;
    ASSERT_EQ(GetFdAllocationSize(-1), -1);

    int fd = memfd_create("pixel_map_from_surface_test", MFD_CLOEXEC);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(GetFdAllocationSize(fd), -1);
    ASSERT_EQ(ftruncate(fd, memfdSize), 0);
    ASSERT_EQ(GetFdAllocationSize(fd), static_cast<int64_t>(memfdSize));
    ASSERT_EQ(GetFdAllocationSize(fd), static_cast<int64_t>(memfdSize));
    close(fd);
}

/*
* Function: IsBufferLayoutWithinSize
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription:
    1. accept a genuine RGBA_8888 layout, a padded stride and a larger real allocation
    2. reject a handle whose height was raised while size was left unchanged
    3. reject a handle whose height and size were both raised consistently
    4. reject an RGBA stride counted in pixels instead of bytes
    5. reject a layout larger than size even when both fit in the real allocation
    6. reject invalid geometry, unknown allocation size and 32-bit overflow inputs
 */
HWTEST_F(PixelMapFromSurfaceTest, IsBufferLayoutWithinSize001, Function | MediumTest| Level3)
{
    constexpr int32_t fmt = GRAPHIC_PIXEL_FMT_RGBA_8888;
    constexpr int32_t width = 1024;
    constexpr int32_t height = 1024;
    constexpr int32_t forgedHeight = 1536;
    constexpr int32_t stride = width * 4;
    constexpr int32_t paddedStride = stride + 64;
    constexpr int32_t size = stride * height;
    constexpr int32_t forgedSize = stride * forgedHeight;
    constexpr int64_t allocation = size;
    constexpr int64_t largeAllocation = static_cast<int64_t>(size) * 2;
    constexpr int32_t maxInt = std::numeric_limits<int32_t>::max();

    ASSERT_TRUE(IsBufferLayoutWithinSize({ fmt, width, height, stride, size }, allocation));
    ASSERT_TRUE(IsBufferLayoutWithinSize({ fmt, width, height, stride, size }, largeAllocation));
    ASSERT_TRUE(IsBufferLayoutWithinSize({ fmt, width, height, paddedStride, paddedStride * height },
        static_cast<int64_t>(paddedStride) * height));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, forgedHeight, stride, size }, allocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, forgedHeight, stride, forgedSize }, allocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, forgedHeight, width, size }, allocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, forgedHeight, stride, size }, largeAllocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, height, stride, size }, allocation - 1));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, height, stride - 1, size }, allocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, 0, height, stride, size }, allocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, -1, stride, size }, allocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, height, stride, 0 }, allocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, height, stride, size }, -1));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, width, maxInt, maxInt, maxInt }, allocation));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fmt, maxInt, height, maxInt, maxInt }, allocation));
}

/*
* Function: IsBufferLayoutWithinSize
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription:
    1. accept genuine NV12, odd-height NV12 and P010 layouts
    2. reject an RGBA-sized buffer whose format was changed to NV12
    3. reject NV12 when size does not cover the rounded-up chroma rows
    4. reject unsupported formats even when their geometry would fit
 */
HWTEST_F(PixelMapFromSurfaceTest, IsBufferLayoutWithinSize002, Function | MediumTest| Level3)
{
    constexpr int32_t nv12 = GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
    constexpr int32_t width = 1024;
    constexpr int32_t height = 1024;
    constexpr int32_t oddHeight = 1025;
    constexpr int32_t chromaRowsOdd = 513;
    constexpr int32_t nv12Size = width * height * 3 / 2;
    constexpr int32_t nv12OddSize = width * (oddHeight + chromaRowsOdd);
    constexpr int32_t p010Stride = width * 2;
    constexpr int32_t p010Size = p010Stride * height * 3 / 2;
    constexpr int32_t rgbaStride = width * 4;
    constexpr int32_t rgbaSize = rgbaStride * height;

    ASSERT_TRUE(IsBufferLayoutWithinSize({ nv12, width, height, width, nv12Size }, nv12Size));
    ASSERT_TRUE(IsBufferLayoutWithinSize({ nv12, width, oddHeight, width, nv12OddSize }, nv12OddSize));
    ASSERT_TRUE(IsBufferLayoutWithinSize(
        { GRAPHIC_PIXEL_FMT_YCBCR_P010, width, height, p010Stride, p010Size }, p010Size));
    ASSERT_FALSE(IsBufferLayoutWithinSize(
        { GRAPHIC_PIXEL_FMT_YCBCR_422_SP, width, height, rgbaStride, rgbaSize }, rgbaSize));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ GRAPHIC_PIXEL_FMT_RGB_888, width, height, rgbaStride, rgbaSize },
        rgbaSize));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ GRAPHIC_PIXEL_FMT_Y8, width, height, rgbaStride, rgbaSize }, rgbaSize));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ nv12, width, height, rgbaStride, rgbaSize }, rgbaSize));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ nv12, width, oddHeight, width, nv12OddSize - 1 }, nv12OddSize));
    ASSERT_FALSE(IsBufferLayoutWithinSize(
        { GRAPHIC_PIXEL_FMT_YCBCR_P010, width, height, width, p010Size }, p010Size));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ GRAPHIC_PIXEL_FMT_BLOB, width, 1, width, width }, width));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ GRAPHIC_PIXEL_FMT_VENDER_PRIVATE1, width, height, width, rgbaSize },
        rgbaSize));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ GRAPHIC_PIXEL_FMT_BUTT, width, height, rgbaStride, rgbaSize }, rgbaSize));
}

/*
* Function: IsBufferLayoutWithinSize
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription:
    1. accept FP16 with a 2-byte stride per pixel and reject a 1-byte stride
    2. accept RGBA_1010108 with a 4-byte stride per pixel and reject a smaller stride
    3. reject either format when the layout exceeds size or the real allocation
 */
HWTEST_F(PixelMapFromSurfaceTest, IsBufferLayoutWithinSize003, Function | MediumTest| Level3)
{
    constexpr int32_t fp16 = GRAPHIC_PIXEL_FMT_FP16;
    constexpr int32_t rgba1010108 = GRAPHIC_PIXEL_FMT_RGBA_1010108;
    constexpr int32_t width = 1024;
    constexpr int32_t height = 1024;
    constexpr int32_t fp16Stride = width * 2;
    constexpr int32_t fp16Size = fp16Stride * height;
    constexpr int32_t rgbaStride = width * 4;
    constexpr int32_t rgbaSize = rgbaStride * height;

    ASSERT_TRUE(IsBufferLayoutWithinSize({ fp16, width, height, fp16Stride, fp16Size }, fp16Size));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fp16, width, height, width, fp16Size }, fp16Size));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ fp16, width, height * 2, fp16Stride, fp16Size }, fp16Size));
    ASSERT_TRUE(IsBufferLayoutWithinSize({ rgba1010108, width, height, rgbaStride, rgbaSize }, rgbaSize));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ rgba1010108, width, height, rgbaStride - 1, rgbaSize }, rgbaSize));
    ASSERT_FALSE(IsBufferLayoutWithinSize({ rgba1010108, width, height, rgbaStride, rgbaSize }, rgbaSize - 1));
}

/*
* Function: SurfaceBufferIntegrity
* Type: Function
* Rank: Important(2)
* EnvConditions: DMA SurfaceBuffer allocation is available
* CaseDescription:
    1. a freshly allocated SurfaceBuffer passes both the field check and the allocation size check
    2. after raising height and size through the raw BufferHandle, both checks fail
 */
HWTEST_F(PixelMapFromSurfaceTest, SurfaceBufferIntegrity001, Function | MediumTest| Level3)
{
    constexpr int32_t bufferSide = 100;
    constexpr int32_t forgedHeightFactor = 2;
    BufferRequestConfig requestConfig = {
        .width = bufferSide,
        .height = bufferSide,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
    };
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    ASSERT_EQ(buffer->Alloc(requestConfig), GSERROR_OK);
    BufferHandle* handle = buffer->GetBufferHandle();
    ASSERT_NE(handle, nullptr);
    auto layoutOf = [](const BufferHandle* h) {
        return BufferLayoutInfo { h->format, h->width, h->height, h->stride, h->size };
    };
    ASSERT_TRUE(buffer->CheckBufferHandleFields());
    ASSERT_TRUE(IsBufferLayoutWithinSize(layoutOf(handle), GetFdAllocationSize(handle->fd)));

    const int32_t originalHeight = handle->height;
    const int32_t originalSize = handle->size;
    handle->height = originalHeight * forgedHeightFactor;
    handle->size = handle->height * handle->stride;
    EXPECT_FALSE(buffer->CheckBufferHandleFields());
    EXPECT_FALSE(IsBufferLayoutWithinSize(layoutOf(handle), GetFdAllocationSize(handle->fd)));
    handle->height = originalHeight;
    handle->size = originalSize;
}
} // namespace
} // namespace Rosen
} // namespace OHOS
