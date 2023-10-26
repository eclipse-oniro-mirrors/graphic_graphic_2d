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

#ifndef DRAWING_SURFACE_IMPL_H
#define DRAWING_SURFACE_IMPL_H

#include "base_impl.h"
#include "utils/rect.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class Bitmap;
class Canvas;
class Image;
class Surface;
#ifdef ACE_ENABLE_GPU
struct FrameBuffer;
class ImageInfo;
class GPUContext;
#endif

class SurfaceImpl : public BaseImpl {
public:
    static inline constexpr AdapterType TYPE = AdapterType::BASE_INTERFACE;
    SurfaceImpl() {};
    ~SurfaceImpl() override {};

    AdapterType GetType() const override
    {
        return AdapterType::BASE_INTERFACE;
    }

    virtual bool Bind(const Bitmap& bitmap) = 0;
#ifdef ACE_ENABLE_GPU
    virtual bool Bind(const Image& image) = 0;
    virtual bool Bind(const FrameBuffer& frameBuffer) = 0;
    virtual bool MakeRenderTarget(GPUContext& gpuContext, bool Budgeted, const ImageInfo& imageInfo) = 0;
    virtual bool MakeRasterN32Premul(int32_t width, int32_t height) = 0;
#endif

    virtual std::shared_ptr<Canvas> GetCanvas() const = 0;
    virtual std::shared_ptr<Image> GetImageSnapshot() const = 0;
    virtual std::shared_ptr<Image> GetImageSnapshot(const RectI& bounds) const = 0;
    virtual std::shared_ptr<Surface> MakeSurface(int width, int height) const = 0;
    virtual void FlushAndSubmit(bool syncCpu) = 0;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif // DRAWING_SURFACE_IMPL_H
