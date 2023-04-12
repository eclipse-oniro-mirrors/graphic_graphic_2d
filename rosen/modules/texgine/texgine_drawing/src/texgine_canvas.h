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

#ifndef ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_CANVAS_H
#define ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_CANVAS_H

#include <memory>

#include <include/core/SkCanvas.h>

#include "texgine_rect.h"
#include "texgine_paint.h"
#include "texgine_text_blob.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
class TexgineCanvas {
public:
    void DrawLine(double x0, double y0, double x1, double y1, TexginePaint &paint);
    void DrawRect(TexgineRect &rect, const TexginePaint &paint) const;
    void DrawTextBlob(std::shared_ptr<TexgineTextBlob> &blob, float x, float y, TexginePaint &paint);
    void Clear(uint32_t clolor);
    int Save();
    void Translate(float dx, float dy);
    SkCanvas *GetCanvas();
    void Restore();
    void SetCanvas(SkCanvas *canvas);

private:
    SkCanvas *canvas_;
};
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_CANVAS_H
