/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef SKIAIMAGE_H
#define SKIAIMAGE_H

#include "include/core/SkBitmap.h"
#ifdef USE_M133_SKIA
#include "include/gpu/ganesh/SkImageGanesh.h"
#include "include/gpu/ganesh/SkSurfaceGanesh.h"
#endif
#include "include/core/SkImage.h"
#include "include/core/SkPaint.h"
#include "include/core/SkPicture.h"
#ifdef RS_ENABLE_GPU
#ifdef USE_M133_SKIA
#include "include/gpu/ganesh/GrDirectContext.h"
#else
#include "include/gpu/GrDirectContext.h"
#endif
#endif
#include "skia_bitmap.h"
#include "skia_color_space.h"
#include "skia_matrix.h"
#include "skia_paint.h"
#include "skia_picture.h"
#include "skia_yuv_info.h"
#ifdef USE_M133_SKIA
#include "include/gpu/ganesh/GrBackendSurface.h"
#else
#include "include/gpu/GrBackendSurface.h"
#endif

#include "impl_interface/image_impl.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class DRAWING_API SkiaImage : public ImageImpl {
public:
    static inline constexpr AdapterType TYPE = AdapterType::SKIA_ADAPTER;

    SkiaImage() noexcept;
    explicit SkiaImage(sk_sp<SkImage> skImg) noexcept;
    ~SkiaImage() override;

    AdapterType GetType() const override
    {
        return AdapterType::SKIA_ADAPTER;
    }

    static std::shared_ptr<Image> MakeFromRaster(const Pixmap& pixmap,
        RasterReleaseProc rasterReleaseProc, ReleaseContext releaseContext);
    static std::shared_ptr<Image> MakeRasterData(const ImageInfo& info, std::shared_ptr<Data> pixels,
        size_t rowBytes);
    bool BuildFromBitmap(const Bitmap& bitmap) override;
#ifdef RS_ENABLE_GPU
    static std::shared_ptr<Image> MakeFromYUVAPixmaps(GPUContext& gpuContext, const YUVInfo& info, void* memory);
    bool BuildFromSurface(GPUContext& gpuContext, Surface& surface, TextureOrigin origin,
        BitmapFormat bitmapFormat, const std::shared_ptr<ColorSpace>& colorSpace) override;
    bool BuildFromBitmap(GPUContext& gpuContext, const Bitmap& bitmap) override;
    bool MakeFromEncoded(const std::shared_ptr<Data>& data) override;
    bool BuildSubset(const std::shared_ptr<Image> image, const RectI& rect, GPUContext& gpuContext) override;
    bool BuildFromCompressed(GPUContext& gpuContext, const std::shared_ptr<Data>& data, int width, int height,
        CompressedType type, const std::shared_ptr<ColorSpace>& colorSpace = nullptr) override;
    bool BuildFromTexture(GPUContext& gpuContext, const TextureInfo& info, TextureOrigin origin,
        BitmapFormat bitmapFormat, const std::shared_ptr<ColorSpace>& colorSpace,
        void (*deleteFunc)(void*) = nullptr, void* cleanupHelper = nullptr) override;
    void DeleteCleanupHelper(void (*deleteFunc)(void*), void* cleanupHelper);
    BackendTexture GetBackendTexture(bool flushPendingGrContextIO, TextureOrigin* origin) override;
    void SetGrBackendTexture(const GrBackendTexture& grBackendTexture);
    bool IsValid(GPUContext* context) const override;
#endif
    bool AsLegacyBitmap(Bitmap& bitmap) const override;
    int GetWidth() const override;
    int GetHeight() const override;
    ColorType GetColorType() const override;
    AlphaType GetAlphaType() const override;
    std::shared_ptr<ColorSpace> GetColorSpace() const override;
    uint32_t GetUniqueID() const override;
    ImageInfo GetImageInfo() override;
    bool ReadPixels(Bitmap& bitmap, int x, int y) override;
    bool ReadPixels(Pixmap& pixmap, int x, int y) override;
    bool ReadPixels(const ImageInfo& dstInfo, void* dstPixels, size_t dstRowBytes,
                    int32_t srcX, int32_t srcY) const override;
    bool IsTextureBacked() const override;

    bool ScalePixels(const Bitmap& bitmap, const SamplingOptions& sampling,
        bool allowCachingHint = true) const override;
    std::shared_ptr<Data> EncodeToData(EncodedImageFormat encodedImageFormat, int quality) const override;
    bool IsLazyGenerated() const override;
    bool GetROPixels(Bitmap& bitmap) const override;
    std::shared_ptr<Image> MakeRasterImage() const override;
    bool CanPeekPixels() const override;
    bool IsOpaque() const override;
    void HintCacheGpuResource() const override;

    const sk_sp<SkImage> GetImage() const;

    /*
     * @brief  Update the member variable to skImage, adaptation layer calls.
     */
    void SetSkImage(const sk_sp<SkImage>& skImage);
#ifdef RS_ENABLE_GPU
    /*
     * @brief  Export Skia member variables for use by the adaptation layer.
     */
    sk_sp<GrDirectContext> GetGrContext() const;
#endif
    std::shared_ptr<Data> Serialize() const override;
    bool Deserialize(std::shared_ptr<Data> data) override;

    void PostSkImgToTargetThread();

    void SetHeadroom(float headroom) override;
    float GetHeadroom() const override;
private:
#ifdef RS_ENABLE_GPU
    sk_sp<GrDirectContext> grContext_ = nullptr;
#endif
    sk_sp<SkImage> skiaImage_;
    GrBackendTexture grBackendTexture_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif
