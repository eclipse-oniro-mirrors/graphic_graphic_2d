/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FONT_IMPL_H
#define FONT_IMPL_H

#include <cstdint>

#include "draw/path.h"
#include "impl_interface/base_impl.h"
#include "text/font_metrics.h"
#include "text/font_types.h"
#include "text/typeface.h"
#include "utils/rect.h"
#include "utils/scalar.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
enum class FontEdging;

class FontImpl : public BaseImpl {
public:
    ~FontImpl() override = default;

    virtual void SetEdging(FontEdging edging) = 0;
    virtual void SetBaselineSnap(bool baselineSnap) = 0;
    virtual void SetForceAutoHinting(bool isForceAutoHinting) = 0;
    virtual void SetSubpixel(bool isSubpixel) = 0;
    virtual void SetHinting(FontHinting hintingLevel) = 0;
    virtual void SetEmbeddedBitmaps(bool embeddedBitmaps) = 0;
    virtual void SetTypeface(std::shared_ptr<Typeface> typeface) = 0;
    virtual void SetSize(scalar textSize) = 0;
    virtual void SetEmbolden(bool isEmbolden) = 0;
    virtual void SetScaleX(scalar scaleX) = 0;
    virtual void SetSkewX(scalar skewX) = 0;
    virtual void SetLinearMetrics(bool isLinearMetrics) = 0;

    virtual scalar GetMetrics(FontMetrics* metrics) const = 0;
    virtual void GetWidths(const uint16_t glyphs[], int count, scalar widths[]) const = 0;
    virtual void GetWidths(const uint16_t glyphs[], int count, scalar widths[], Rect bounds[]) const = 0;
    virtual scalar GetSize() const = 0;
    virtual std::shared_ptr<Typeface> GetTypeface() const = 0;

    virtual FontEdging GetEdging() const = 0;
    virtual FontHinting GetHinting() const = 0;
    virtual scalar GetScaleX() const = 0;
    virtual scalar GetSkewX() const = 0;
    virtual bool IsBaselineSnap() const = 0;
    virtual bool IsEmbeddedBitmaps() const = 0;
    virtual bool IsEmbolden() const = 0;
    virtual bool IsForceAutoHinting() const = 0;
    virtual bool IsLinearMetrics() const = 0;
    virtual bool IsSubpixel() const = 0;

    virtual uint16_t UnicharToGlyph(int32_t uni) const = 0;
    virtual int TextToGlyphs(const void* text, size_t byteLength, TextEncoding encoding,
        uint16_t glyphs[], int maxGlyphCount) const = 0;
    virtual bool GetPathForGlyph(uint16_t glyph, Path* path) const = 0;

    virtual scalar MeasureText(const void* text, size_t byteLength, TextEncoding encoding,
        Rect* bounds = nullptr) const = 0;
    virtual int CountText(const void* text, size_t byteLength, TextEncoding encoding) const = 0;

protected:
    FontImpl() noexcept = default;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif