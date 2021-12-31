/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HDI_BACKEND_HDI_LAYER_INFO_H
#define HDI_BACKEND_HDI_LAYER_INFO_H

#include <surface.h>
#include <surface_buffer.h>
#include <sync_fence.h>

#include "surface_type.h"
#include "display_type.h"

namespace OHOS {
namespace Rosen {

class HdiLayerInfo {
public:
    HdiLayerInfo() = default;
    virtual ~HdiLayerInfo() = default;

    /* rs create and set layer info begin */
    static std::shared_ptr<HdiLayerInfo> CreateHdiLayerInfo()
    {
        return std::make_shared<HdiLayerInfo>();
    }

    void SetSurface(const sptr<Surface> &surface)
    {
        cSurface_ = surface;
    }

    void SetBuffer(const sptr<SurfaceBuffer> &sbuffer, int32_t acquireFence)
    {
        sbuffer_ = sbuffer;
        acquireFence_ = new SyncFence(acquireFence);
    }

    void SetZorder(int32_t zOrder)
    {
        zOrder_ = zOrder;
    }

    void SetAlpha(const LayerAlpha &alpha)
    {
        layerAlpha_ = alpha;
    }

    void SetTransform(TransformType type)
    {
        transformType_ = type;
    }

    void SetCompositionType(CompositionType type)
    {
        compositionType_ = type;
    }

    void SetVisibleRegion(uint32_t num, const IRect &visibleRegion)
    {
        visibleNum_ = num;
        visibleRegion_ = visibleRegion;
    }

    void SetDirtyRegion(const IRect &dirtyRegion)
    {
        dirtyRegion_ = dirtyRegion;
    }

    void SetBlendType(BlendType type)
    {
        blendType_ = type;
    }

    void SetCropRect(const IRect &crop)
    {
        cropRect_ = crop;
    }

    void SetPreMulti(bool preMulti)
    {
        preMulti_ = preMulti;
    }

    void SetLayerSize(const IRect &layerRect)
    {
        layerRect_ = layerRect;
    }
    /* rs create and set layer info end */

    /* hdiLayer get layer info begin */
    sptr<Surface> GetSurface() const
    {
        return cSurface_;
    }

    sptr<SurfaceBuffer> GetBuffer() const
    {
        return sbuffer_;
    }

    uint32_t GetZorder() const
    {
        return zOrder_;
    }

    sptr<SyncFence> GetAcquireFence() const
    {
        return acquireFence_;
    }

    /* const */ LayerAlpha& GetAlpha()
    {
        return layerAlpha_;
    }

    TransformType GetTransformType() const
    {
        return transformType_;
    }

    CompositionType GetCompositionType() const
    {
        return compositionType_;
    }

    uint32_t GetVisibleNum() const
    {
        return visibleNum_;
    }

    /* const */ IRect& GetVisibleRegion()
    {
        return visibleRegion_;
    }

    /* const */ IRect& GetDirtyRegion()
    {
        return dirtyRegion_;
    }

    BlendType GetBlendType() const
    {
        return blendType_;
    }

    /* const */ IRect& GetCropRect()
    {
        return cropRect_;
    }

    /* const */ IRect& GetLayerSize()
    {
        return layerRect_;
    }

    bool IsPreMulti() const
    {
        return preMulti_;
    }
    /* hdiLayer get layer info end */

private:
    uint32_t zOrder_ = 0;
    uint32_t visibleNum_ = 0;
    sptr<SyncFence> acquireFence_ = SyncFence::INVALID_FENCE;
    IRect layerRect_;
    IRect visibleRegion_;
    IRect dirtyRegion_;
    IRect cropRect_;
    LayerAlpha layerAlpha_;
    TransformType transformType_;
    CompositionType compositionType_;
    BlendType blendType_;

    sptr<Surface> cSurface_ = nullptr;
    sptr<SurfaceBuffer> sbuffer_ = nullptr;

    bool preMulti_ = false;
};
} // namespace Rosen
} // namespace OHOS

#endif // HDI_BACKEND_HDI_LAYER_INFO_H