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

#ifndef ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_PAINT_H
#define ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_PAINT_H

#include <memory>

#include <include/core/SkPaint.h>
#include <include/core/SkBlendMode.h>

#include "texgine_mask_filter.h"
#include "texgine_path_effect.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
class TexginePaint {
public:
    enum Style : uint8_t {
        FILL,
        STROKE,
        STROKEANDFILL,
    };

    enum TexgineBlendMode : uint8_t {
        CLEAR,
        SRC,
        DST,
        SRC_OVER,
        DST_OVER,
        SRC_IN,
        DST_IN,
        SRC_OUT,
        DST_OUT,
        SRC_ATOP,
        DST_ATOP,
        XOR,
        PLUS,
        MODULATE,
        SCREEN,
        OVERLAY,
        DARKEN,
        LIGHTEN,
        COLOR_DODGE,
        COLOR_BURN,
        HARD_LIGHT,
        SOFT_LIGHT,
        DIFFERENCE,
        EXCLUSION,
        MULTIPLY,
        HUE,
        STATURATION,
        COLOR,
        LUMINOSITY,
    };

    TexginePaint();
    SkPaint GetPaint() const;
    void SetPaint(SkPaint paint);
    void SetColor(uint32_t color);
    void SetAlphaf(float alpha);
    void SetStrokeWidth(double width);
    void SetAntiAlias(bool aa);
    void SetARGB(unsigned int a, unsigned int r, unsigned int g, unsigned int b);
    void SetStyle(Style style);
    void SetPathEffect(std::shared_ptr<TexginePathEffect> pathEffect);
    void SetMaskFilter(std::shared_ptr<TexgineMaskFilter> maskFilter);
    void SetAlpha(unsigned int alpha);
    void SetBlendMode(TexgineBlendMode mode);
    bool operator ==(const TexginePaint &rhs) const;

private:
    std::shared_ptr<SkPaint> paint_ = nullptr;
};
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_PAINT_H
