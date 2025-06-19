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
#ifndef RENDER_SERVICE_BASE_RENDER_RENDER_SKIA_RS_SKIA_FILTER_H
#define RENDER_SERVICE_BASE_RENDER_RENDER_SKIA_RS_SKIA_FILTER_H

#include <optional>

#include "common/rs_vector2.h"
#include "draw/brush.h"
#include "draw/canvas.h"
#include "effect/image_filter.h"
#include "render/rs_filter.h"

namespace OHOS {
namespace Rosen {
class RSPaintFilterCanvas;
class RSDrawingFilterOriginal : public RSFilter {
public:
    RSDrawingFilterOriginal(std::shared_ptr<Drawing::ImageFilter> imagefilter);
    ~RSDrawingFilterOriginal() override;
    Drawing::Brush GetBrush() const;
    virtual void DrawImageRect(Drawing::Canvas& canvas, const std::shared_ptr<Drawing::Image>& image,
        const Drawing::Rect& src, const Drawing::Rect& dst) const;
    std::shared_ptr<Drawing::ImageFilter> GetImageFilter() const;
    virtual std::shared_ptr<RSDrawingFilterOriginal> Compose(
        const std::shared_ptr<RSDrawingFilterOriginal>& other) const = 0;
    virtual void PreProcess(std::shared_ptr<Drawing::Image> image) {};
    virtual void PostProcess(Drawing::Canvas& canvas) {};
    virtual void SetGreyCoef(const std::optional<Vector2f>& greyCoef) {};
    virtual bool CanSkipFrame() const { return false; };
    virtual void SetGeometry(Drawing::Canvas& canvas, float geoWidth, float geoHeight) {};
    virtual void IsOffscreenCanvas(bool isOffscreenCanvas) {};
    virtual void DisableMotionBlur(bool isDisableMotionBlur) {};

protected:
    std::shared_ptr<Drawing::ImageFilter> imageFilter_ = nullptr;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_RENDER_RENDER_SKIA_RS_SKIA_FILTER_H