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

#ifndef RENDER_SERVICE_CLIENT_CORE_RENDER_RS_HPS_BLUR_H
#define RENDER_SERVICE_CLIENT_CORE_RENDER_RS_HPS_BLUR_H

#include "draw/canvas.h"
#include "effect/color_filter.h"
#include "effect/runtime_effect.h"
#include "image/image.h"
#include "utils/matrix.h"
#include "utils/rect.h"

namespace OHOS {
namespace Rosen {
class HpsBlurFilter {
public:
    ~HpsBlurFilter() = default;
    bool ApplyHpsBlur(Drawing::Canvas& canvas, const std::shared_ptr<Drawing::Image>& image,
        const Drawing::HpsBlurParameter& param, Drawing::Brush& brush) const;
    const static HpsBlurFilter& GetHpsBlurFilter()
    {
        static HpsBlurFilter filter;
        return filter;
    }

private:
    HpsBlurFilter() = default;
    static Drawing::Matrix GetShaderTransform(const Drawing::Rect& blurRect, float scaleW = 1.0f, float scaleH = 1.0f);
};
} // namespace Rosen
} // namespace OHOS
#endif // RENDER_SERVICE_CLIENT_CORE_RENDER_RS_HPS_BLUR_H