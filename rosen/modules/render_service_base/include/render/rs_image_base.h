/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_CLIENT_CORE_RENDER_RS_IMAGE_BASE_H
#define RENDER_SERVICE_CLIENT_CORE_RENDER_RS_IMAGE_BASE_H

#include <cstdint>
#include <mutex>
#include "common/rs_macros.h"
#include "common/rs_rect.h"
#include <memory>
#include "draw/canvas.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "transaction/rs_marshalling_helper.h"

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
#include "external_window.h"
#include "surface_buffer.h"
#endif

namespace OHOS {
namespace Media {
class PixelMap;
}
namespace Rosen {
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
namespace NativeBufferUtils {
class VulkanCleanupHelper;
}
#endif
class RSB_EXPORT RSImageBase {
public:
    RSImageBase() = default;
    virtual ~RSImageBase();

    virtual void DrawImage(Drawing::Canvas& canvas, const Drawing::SamplingOptions& samplingOptions,
        Drawing::SrcRectConstraint constraint = Drawing::SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT);
    void SetImage(const std::shared_ptr<Drawing::Image> image);
#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
    void SetDmaImage(const std::shared_ptr<Drawing::Image> image);
    void MarkYUVImage();
#endif
    void SetPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap);
    void SetSrcRect(const RectF& dstRect);
    void SetDstRect(const RectF& dstRect);
    void SetImagePixelAddr(void* addr);
    void UpdateNodeIdToPicture(NodeId nodeId);
    void MarkRenderServiceImage();
    std::shared_ptr<Media::PixelMap> GetPixelMap() const;
#ifdef ROSEN_OHOS
    virtual bool Marshalling(Parcel& parcel) const;
    [[nodiscard]] static RSImageBase* Unmarshalling(Parcel& parcel);
#endif

    void ConvertPixelMapToDrawingImage(bool parallelUpload = false);

    void Purge();
    enum class CanPurgeFlag : int8_t {
        UNINITED = -1,
        DISABLED = 0,
        ENABLED = 1,
    };
    CanPurgeFlag canPurgeShareMemFlag_ = CanPurgeFlag::UNINITED;

protected:
    void GenUniqueId(uint32_t id);
#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
    void ProcessYUVImage(std::shared_ptr<Drawing::GPUContext> gpuContext);
#if defined(RS_ENABLE_VK)
    void BindPixelMapToDrawingImage(Drawing::Canvas& canvas);
    std::shared_ptr<Drawing::Image> MakeFromTextureForVK(Drawing::Canvas& canvas, SurfaceBuffer* surfaceBuffer);
#endif
#endif
    static bool UnmarshallingDrawingImageAndPixelMap(Parcel& parcel, uint64_t uniqueId, bool& useDrawingImage,
        std::shared_ptr<Drawing::Image>& img, std::shared_ptr<Media::PixelMap>& pixelMap, void*& imagepixelAddr);
    static void IncreaseCacheRefCount(uint64_t uniqueId,
            bool useSkImage = true, std::shared_ptr<Media::PixelMap> pixelMap = nullptr);

    mutable std::mutex mutex_;
    std::shared_ptr<Drawing::Image> image_;
    void* imagePixelAddr_ = nullptr;
    std::shared_ptr<Media::PixelMap> pixelMap_;

    RectF srcRect_;
    RectF dstRect_;
    Drawing::Rect src_;
    Drawing::Rect dst_;
    Drawing::Rect lastRect_;
    bool isDrawn_ = false;
    uint64_t uniqueId_ = 0;
    bool renderServiceImage_ = false;
    bool isYUVImage_ = false;

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
    mutable OHNativeWindowBuffer* nativeWindowBuffer_ = nullptr;
    mutable pid_t tid_ = 0;
    mutable Drawing::BackendTexture backendTexture_ = {};
    mutable NativeBufferUtils::VulkanCleanupHelper* cleanUpHelper_ = nullptr;
#endif
};
} // namespace Rosen
} // namespace OHOS
#endif // RENDER_SERVICE_CLIENT_CORE_RENDER_RS_IMAGE_BASE_H
