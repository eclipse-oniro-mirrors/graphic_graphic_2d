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

#include "skia_text_blob.h"

#include <map>
#include "include/core/SkFontTypes.h"
#include "include/core/SkRSXform.h"
#include "include/core/SkSerialProcs.h"

#include "skia_adapter/skia_convert_utils.h"
#include "skia_adapter/skia_data.h"
#include "skia_adapter/skia_font.h"
#include "skia_adapter/skia_path.h"
#include "skia_adapter/skia_typeface.h"
#include "utils/log.h"
#include "skia_adapter/skia_path_effect.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
static const std::map<Drawing::Paint::PaintStyle, SkPaint::Style> PAINT_STYLE = {
    {Drawing::Paint::PaintStyle::PAINT_FILL, SkPaint::kFill_Style},
    {Drawing::Paint::PaintStyle::PAINT_STROKE, SkPaint::kStroke_Style},
    {Drawing::Paint::PaintStyle::PAINT_FILL_STROKE, SkPaint::kStrokeAndFill_Style},
};

SkiaTextBlob::SkiaTextBlob(sk_sp<SkTextBlob> skTextBlob) : skTextBlob_(skTextBlob) {}

sk_sp<SkTextBlob> SkiaTextBlob::GetTextBlob() const
{
    return skTextBlob_;
}

std::shared_ptr<TextBlob> SkiaTextBlob::MakeFromText(const void* text, size_t byteLength,
    const Font& font, TextEncoding encoding)
{
    auto skiaFont = font.GetImpl<SkiaFont>();
    if (!skiaFont) {
        LOGD("skiaFont nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    SkTextEncoding skEncoding = static_cast<SkTextEncoding>(encoding);
    sk_sp<SkTextBlob> skTextBlob = SkTextBlob::MakeFromText(text, byteLength, skiaFont->GetFont(), skEncoding);
    if (!skTextBlob) {
        LOGD("skTextBlob nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    std::shared_ptr<TextBlobImpl> textBlobImpl = std::make_shared<SkiaTextBlob>(skTextBlob);
    return std::make_shared<TextBlob>(textBlobImpl);
}

std::shared_ptr<TextBlob> SkiaTextBlob::MakeFromPosText(const void* text, size_t byteLength,
    const Point pos[], const Font& font, TextEncoding encoding)
{
    auto skiaFont = font.GetImpl<SkiaFont>();
    if (!skiaFont) {
        LOGD("skiaFont nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }

    SkTextEncoding skEncoding = static_cast<SkTextEncoding>(encoding);
    auto skFont = skiaFont->GetFont();
    const int count = skFont.countText(text, byteLength, skEncoding);
    SkPoint skPts[count];
    for (int i = 0; i < count; ++i) {
        skPts[i] = {pos[i].GetX(), pos[i].GetY()};
    }
    sk_sp<SkTextBlob> skTextBlob = SkTextBlob::MakeFromPosText(text, byteLength, skPts, skFont, skEncoding);
    if (!skTextBlob) {
        LOGD("skTextBlob nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    std::shared_ptr<TextBlobImpl> textBlobImpl = std::make_shared<SkiaTextBlob>(skTextBlob);
    return std::make_shared<TextBlob>(textBlobImpl);
}

std::shared_ptr<TextBlob> SkiaTextBlob::MakeFromRSXform(const void* text, size_t byteLength,
    const RSXform xform[], const Font& font, TextEncoding encoding)
{
    auto skiaFont = font.GetImpl<SkiaFont>();
    if (!skiaFont) {
        LOGD("skiaFont nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    SkTextEncoding skEncoding = static_cast<SkTextEncoding>(encoding);
    SkRSXform skXform;
    if (xform) {
        SkiaConvertUtils::DrawingRSXformCastToSkXform(*xform, skXform);
    }
    sk_sp<SkTextBlob> skTextBlob =
        SkTextBlob::MakeFromRSXform(text, byteLength, xform ? &skXform : nullptr, skiaFont->GetFont(), skEncoding);
    if (!skTextBlob) {
        LOGD("skTextBlob nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    std::shared_ptr<TextBlobImpl> textBlobImpl = std::make_shared<SkiaTextBlob>(skTextBlob);
    return std::make_shared<TextBlob>(textBlobImpl);
}

std::shared_ptr<Data> SkiaTextBlob::Serialize(void* ctx) const
{
    if (!skTextBlob_) {
        LOGD("skTextBlob nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    SkSerialProcs procs;
    procs.fTypefaceProc = &SkiaTypeface::SerializeTypeface;
    procs.fTypefaceCtx = ctx;
    auto skData = skTextBlob_->serialize(procs);
    auto data = std::make_shared<Data>();
    auto skiaData = data->GetImpl<SkiaData>();
    if (!skiaData) {
        LOGD("skiaData nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    skiaData->SetSkData(skData);
    return data;
}

std::shared_ptr<TextBlob> SkiaTextBlob::Deserialize(const void* data, size_t size, void* ctx)
{
    SkDeserialProcs procs;
    procs.fTypefaceProc = &SkiaTypeface::DeserializeTypeface;
    procs.fTypefaceCtx = ctx;
    sk_sp<SkTextBlob> skTextBlob = SkTextBlob::Deserialize(data, size, procs);
    if (!skTextBlob) {
        LOGD("skTextBlob nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    std::shared_ptr<TextBlobImpl> textBlobImpl = std::make_shared<SkiaTextBlob>(skTextBlob);
    return std::make_shared<TextBlob>(textBlobImpl);
}

static SkPaint::Style ConvertSkStyle(Paint::PaintStyle style)
{
    if (PAINT_STYLE.find(style) != PAINT_STYLE.end()) {
        return PAINT_STYLE.at(style);
    } else {
        return SkPaint::kStrokeAndFill_Style;
    }
}

static void ConvertSkPaint(const Paint* drawingPaint, SkPaint &skPaint)
{
    if (drawingPaint == nullptr) {
        return;
    }
    skPaint.setStyle(ConvertSkStyle(drawingPaint->GetStyle()));
    skPaint.setAntiAlias(drawingPaint->IsAntiAlias());
    Color color = drawingPaint->GetColor();
    skPaint.setColor(Color::ColorQuadSetARGB(color.GetAlpha(), color.GetRed(), color.GetGreen(), color.GetGreen()));
    skPaint.setStrokeWidth(drawingPaint->GetWidth());
    const std::shared_ptr<PathEffect> effect = drawingPaint->GetPathEffect();
    if (effect != nullptr) {
        SkiaPathEffect *skiaEffect = effect->GetImpl<SkiaPathEffect>();
        if (skiaEffect != nullptr) {
            skPaint.setPathEffect(skiaEffect->GetPathEffect());
        }
    }
}

int SkiaTextBlob::GetIntercepts(const float bounds[], float intervals[], const Paint* paint) const
{
    if (skTextBlob_ && paint != nullptr) {
        SkPaint skPaint;
        ConvertSkPaint(paint, skPaint);
        return skTextBlob_->getIntercepts(bounds, intervals, &skPaint);
    }
    return 0;
}

void SkiaTextBlob::GetDrawingGlyphIDforTextBlob(const TextBlob* blob, std::vector<uint16_t>& glyphIds)
{
    SkTextBlob* skTextBlob = nullptr;
    if (blob) {
        auto skiaBlobImpl = blob->GetImpl<SkiaTextBlob>();
        if (skiaBlobImpl != nullptr) {
            skTextBlob = skiaBlobImpl->GetTextBlob().get();
        }
    }
    GetGlyphIDforTextBlob(skTextBlob, glyphIds);
}

Path SkiaTextBlob::GetDrawingPathforTextBlob(uint16_t glyphId, const TextBlob* blob)
{
    SkTextBlob* skTextBlob = nullptr;
    if (blob) {
        auto skiaBlobImpl = blob->GetImpl<SkiaTextBlob>();
        if (skiaBlobImpl != nullptr) {
            skTextBlob = skiaBlobImpl->GetTextBlob().get();
        }
    }
    SkPath skPath = GetPathforTextBlob(glyphId, skTextBlob);
    Path path;
    path.GetImpl<SkiaPath>()->SetPath(skPath);
    return path;
}

void SkiaTextBlob::GetDrawingPointsForTextBlob(const TextBlob* blob, std::vector<Point>& points)
{
    if (blob == nullptr) {
        return;
    }
    SkTextBlob* skTextBlob = nullptr;
    if (blob) {
        auto skiaBlobImpl = blob->GetImpl<SkiaTextBlob>();
        if (skiaBlobImpl != nullptr) {
            skTextBlob = skiaBlobImpl->GetTextBlob().get();
        }
    }
    std::vector<SkPoint> skPoints;
    GetPointsForTextBlob(skTextBlob, skPoints);

    points.reserve(skPoints.size());
    for (const auto& p : skPoints) {
        points.emplace_back(p.x(), p.y());
    }
}

std::shared_ptr<Rect> SkiaTextBlob::Bounds() const
{
    if (skTextBlob_) {
        auto bounds = skTextBlob_->bounds();
        return std::make_shared<Rect>(bounds.left(), bounds.top(), bounds.right(), bounds.bottom());
    }
    return nullptr;
}

uint32_t SkiaTextBlob::UniqueID() const
{
    if (skTextBlob_) {
        return skTextBlob_->uniqueID();
    }
    return 0;
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS