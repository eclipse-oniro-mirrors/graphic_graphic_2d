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

#ifndef DRAWING_SURFACE_H
#define DRAWING_SURFACE_H

#include "impl_interface/surface_impl.h"

#include "draw/canvas.h"
#include "image/bitmap.h"
#include "image/image.h"
#include "utils/drawing_macros.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

#ifdef ACE_ENABLE_GPU
struct FrameBuffer {
    int width;
    int height;
    int FBOID;
    int Format;
    std::shared_ptr<GPUContext> gpuContext;
    std::shared_ptr<ColorSpace> colorSpace;
};
#endif

struct FlushInfo {
    bool backendSurfaceAccess = false;
    size_t numSemaphores = 0;
    void *backendSemaphore = nullptr;
};

class DRAWING_API Surface {
public:
    Surface();
    ~Surface() {}

    /*
     * @brief         Bind raster Surface.
     * @param bitmap  Raster pixel array.
     */
    bool Bind(const Bitmap& bitmap);

#ifdef ACE_ENABLE_GPU
    /*
     * @brief         Bind GPU texture Surface.
     * @param image   In GPU memory as a GPU texture.
     */
    bool Bind(const Image& image);

    /*
     * @brief       Bind
     * @param info  FrameBuffer object info.
     */
    bool Bind(const FrameBuffer& frameBuffer);

#ifdef RS_ENABLE_VK
    static std::shared_ptr<Surface> MakeFromBackendRenderTarget(GPUContext* gpuContext, const VKTextureInfo& info,
        TextureOrigin origin, void (*deleteVkImage)(void *), void* cleanHelper);
#endif

    /*
     * @brief              Create Surface from gpuContext and imageInfo.
     * @param gpuContext   GPU texture.
     * @param budgeted     Texture count.
     * @param imageInfo    image Info.
     * @return             A shared point to Surface.
     */
    static std::shared_ptr<Surface> MakeRenderTarget(GPUContext* gpuContext, bool budgeted, const ImageInfo& imageInfo);
#endif

    /*
     * @brief              Allocates raster Surface.
     * @param imageInfo    image info.
     * @return             A shared point to Surface.
     */
    static std::shared_ptr<Surface> MakeRaster(const ImageInfo& imageInfo);

    /*
     * @brief              Allocates raster direct Surface.
     * @param imageInfo    image info.
     * @param pixels       Pointer to destination pixels buffer.
     * @param rowBytes     Interval from one Surface row to the next.
     * @return             A shared point to Surface.
     */
    static std::shared_ptr<Surface> MakeRasterDirect(const ImageInfo& imageInfo, void* pixels, size_t rowBytes);

    /*
     * @brief          Create Surface using width and height.
     * @param width    Pixel column count.
     * @param height   Pixel row count.
     * @return         A shared point to Surface.
     */
    static std::shared_ptr<Surface> MakeRasterN32Premul(int32_t width, int32_t height);

    /*
     * @brief   Gets Canvas that draws into Surface.
     */
    std::shared_ptr<Canvas> GetCanvas();

    /*
     * @brief   Gets Image capturing Surface contents.
     */
    std::shared_ptr<Image> GetImageSnapshot() const;

    /*
     * @brief         Gets Image capturing Surface contents.
     * @param bounds  Bounds.
     *                If bounds extends beyond the Surface, it will be trimmed to just the intersection of it
     *                and the Surface.
     *                If bounds does not intersect the surface, then this returns nullptr.
     *                If bounds == the surface, then this is the same as calling the no-parameter variant.
     */
    std::shared_ptr<Image> GetImageSnapshot(const RectI& bounds) const;

    /*
     * @brief   Returns a compatible Surface, with the specified widht and height
     */
    std::shared_ptr<Surface> MakeSurface(int width, int height) const;

    /*
     * @brief   Gets ImageInfo of Surface
     */
    ImageInfo GetImageInfo();

    /*
     * @brief   Call to ensure all reads/writes of surface have been issue to the underlying 3D API.
     */
    void FlushAndSubmit(bool syncCpu = false);

    /*
     * @brief   Call to ensure all reads/writes of surface have been issue to the underlying 3D API.
     */
    void Flush(FlushInfo *drawingflushInfo = nullptr);

    template<typename T>
    const std::shared_ptr<T> GetImpl() const
    {
        return impl_->DowncastingTo<T>();
    }

#ifdef RS_ENABLE_VK
    void Wait(int32_t time, const VkSemaphore& semaphore);
    void SetDrawingArea(const std::vector<RectI>& rects);
#endif

private:
    std::shared_ptr<SurfaceImpl> impl_;
    std::shared_ptr<Canvas> cachedCanvas_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif
