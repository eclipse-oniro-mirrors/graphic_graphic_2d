/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.. All rights reserved.
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

#ifndef ROSEN_TEXT_EXPORT_ROSEN_TEXT_RUN_H
#define ROSEN_TEXT_EXPORT_ROSEN_TEXT_RUN_H

#include "typography_types.h"
#include "draw/canvas.h"
#include "text/font.h"
#include "utils/point.h"

namespace OHOS {
namespace Rosen {
class Run {
public:
    virtual ~Run() = default;

    virtual Drawing::Font GetFont() const = 0;
    virtual size_t GetGlyphCount() const = 0;
    virtual std::vector<uint16_t> GetGlyphs() const = 0;
    virtual std::vector<Drawing::Point> GetPositions() = 0;
    virtual std::vector<Drawing::Point> GetOffsets() = 0;
    virtual std::vector<uint16_t> GetGlyphs(int64_t start, int64_t length) const = 0;
    virtual std::vector<Drawing::Point> GetPositions(int64_t start, int64_t length) const = 0;
    virtual std::vector<Drawing::Point> GetAdvances(uint32_t start, uint32_t length) const = 0;
    virtual TextDirection GetTextDirection() const = 0;
    virtual void GetStringRange(uint64_t* location, uint64_t* length) const = 0;
    virtual std::vector<uint64_t> GetStringIndices(int64_t start, int64_t length) const = 0;
    virtual Drawing::Rect GetImageBounds() const = 0;
    virtual float GetTypographicBounds(float* ascent, float* descent, float* leading) const = 0;
    virtual void Paint(Drawing::Canvas *canvas, double x, double y) = 0;
};
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_TEXT_EXPORT_ROSEN_TEXT_RUN_H
