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
#ifndef RENDER_SERVICE_CLIENT_CORE_RENDER_RS_MASKCOLOR_SHADER_FILTER_H
#define RENDER_SERVICE_CLIENT_CORE_RENDER_RS_MASKCOLOR_SHADER_FILTER_H

#include "common/rs_color.h"
#include "draw/color.h"
#include "effect/color_filter.h"
#include "effect/color_matrix.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "render/rs_render_filter_base.h"

namespace OHOS {
namespace Rosen {
class RSB_EXPORT RSMaskColorShaderFilter : public RSRenderFilterParaBase {
public:
    RSMaskColorShaderFilter(int colorMode, RSColor maskColor);
    RSMaskColorShaderFilter(const RSMaskColorShaderFilter&) = delete;
    RSMaskColorShaderFilter operator=(const RSMaskColorShaderFilter&) = delete;
    ~RSMaskColorShaderFilter() override;

    int GetColorMode() const;
    RSColor GetMaskColor() const;
    void CaclMaskColor(std::shared_ptr<Drawing::Image>& image);
    float GetPostProcessAlpha() const;
    virtual void PreProcess(std::shared_ptr<Drawing::Image>& image) override;
    virtual void PostProcess(Drawing::Canvas& canvas) override;
    static Drawing::ColorQuad CalcAverageColor(std::shared_ptr<Drawing::Image> image);
private:
    int colorMode_;
    RSColor maskColor_ = RSColor();
    friend class RSMarshallingHelper;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_RENDER_RS_MASKCOLOR_SHADER_FILTER_H
