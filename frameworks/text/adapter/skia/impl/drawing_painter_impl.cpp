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

#include "drawing_painter_impl.h"

#include <array>
#include <memory>

#include "include/core/SkBlurTypes.h"
#include "include/core/SkMaskFilter.h"
#include "include/effects/SkDashPathEffect.h"
#include "include/effects/SkDiscretePathEffect.h"
#include "modules/skparagraph/include/drawing.h"
#include "paint_record.h"
#include "skia_adapter/skia_paint.h"
#include "skia_adapter/skia_path.h"
#include "skia_adapter/skia_text_blob.h"
#include "symbol_engine/hm_symbol_run.h"
#include "utils/text_trace.h"

#ifdef HM_SYMBOL_TXT_ENABLE
#include <parameters.h>

const bool G_IS_HM_SYMBOL_TXT_ENABLE =
    (std::atoi(OHOS::system::GetParameter("persist.sys.graphic.hmsymboltxt.enable", "1").c_str()) != 0);
#else
const bool G_IS_HM_SYMBOL_TXT_ENABLE = true;
#endif


namespace OHOS {
namespace Rosen {
namespace SPText {
static Drawing::Paint ConvertDecorStyle(const ParagraphPainter::DecorationStyle& decorStyle,
    Drawing::Paint::PaintStyle drawStyle = Drawing::Paint::PAINT_STROKE)
{
    Drawing::Paint paint;
    paint.SetStyle(drawStyle);
    paint.SetAntiAlias(true);
    paint.SetColor(PaintRecord::ToRSColor(decorStyle.getColor()));
    paint.SetWidth(decorStyle.getStrokeWidth());
    if (decorStyle.getDashPathEffect().has_value()) {
        auto dashPathEffect = decorStyle.getDashPathEffect().value();
        Drawing::scalar intervals[] = {dashPathEffect.fOnLength, dashPathEffect.fOffLength,
            dashPathEffect.fOnLength, dashPathEffect.fOffLength};
        size_t count = sizeof(intervals) / sizeof(intervals[0]);
        auto pathEffect1 = Drawing::PathEffect::CreateDashPathEffect(intervals, count, 0.0f);
        auto pathEffect2 = Drawing::PathEffect::CreateDiscretePathEffect(0, 0);
        auto pathEffect = Drawing::PathEffect::CreateComposePathEffect(*pathEffect1.get(), *pathEffect2.get());
        paint.SetPathEffect(pathEffect);
    }
    return paint;
}

static Drawing::Rect ToDrawingRect(const SkRect& skRect)
{
    Drawing::Rect rect;
    rect.SetLeft(skRect.fLeft);
    rect.SetTop(skRect.fTop);
    rect.SetRight(skRect.fRight);
    rect.SetBottom(skRect.fBottom);
    return rect;
}

static Drawing::RoundRect ToDrawingRoundRect(const SkRRect& skRRect)
{
    Drawing::Rect rect;
    rect.SetLeft(skRRect.rect().fLeft);
    rect.SetTop(skRRect.rect().fTop);
    rect.SetRight(skRRect.rect().fRight);
    rect.SetBottom(skRRect.rect().fBottom);
    Drawing::scalar ltRadius = skRRect.radii(SkRRect::Corner::kUpperLeft_Corner).x();
    Drawing::scalar rtRadius = skRRect.radii(SkRRect::Corner::kUpperRight_Corner).x();
    Drawing::scalar rbRadius = skRRect.radii(SkRRect::Corner::kLowerRight_Corner).x();
    Drawing::scalar lbRadius = skRRect.radii(SkRRect::Corner::kLowerLeft_Corner).x();
    Drawing::Point leftTop = {ltRadius, ltRadius};
    Drawing::Point rightTop = {rtRadius, rtRadius};
    Drawing::Point rightBottom = {rbRadius, rbRadius};
    Drawing::Point leftBottom = {lbRadius, lbRadius};
    Drawing::RoundRect roundRect(rect, {leftTop, rightTop, rightBottom, leftBottom});
    return roundRect;
}

RSCanvasParagraphPainter::RSCanvasParagraphPainter(Drawing::Canvas* canvas, const std::vector<PaintRecord>& paints)
    : canvas_(canvas), paints_(paints)
{}

void RSCanvasParagraphPainter::DrawSymbolSkiaTxt(const std::shared_ptr<RSTextBlob>& blob, const RSPoint& offset,
    const PaintRecord &pr)
{
    std::shared_ptr<HMSymbolRun> hmSymbolRun = generateSymbolRun(blob, pr);
    if (hmSymbolRun == nullptr) {
        return;
    }

    if (pr.pen.has_value() && pr.brush.has_value()) {
        canvas_->AttachBrush(pr.brush.value());
        canvas_->AttachPen(pr.pen.value());
        hmSymbolRun->DrawSymbol(canvas_, offset);
        canvas_->DetachPen();
        canvas_->DetachBrush();
    } else if (pr.pen.has_value() && !pr.brush.has_value()) {
        canvas_->AttachPen(pr.pen.value());
        hmSymbolRun->DrawSymbol(canvas_, offset);
        canvas_->DetachPen();
    } else if (!pr.pen.has_value() && pr.brush.has_value()) {
        canvas_->AttachBrush(pr.brush.value());
        hmSymbolRun->DrawSymbol(canvas_, offset);
        canvas_->DetachBrush();
    } else {
        Drawing::Brush brush;
        brush.SetColor(pr.color);
        brush.SetAntiAlias(true);
        canvas_->AttachBrush(brush);
        hmSymbolRun->DrawSymbol(canvas_, offset);
        canvas_->DetachBrush();
    }
}

void RSCanvasParagraphPainter::drawTextBlob(const std::shared_ptr<RSTextBlob>& blob, SkScalar x, SkScalar y,
    const SkPaintOrID& paint)
{
    TEXT_TRACE_FUNC();
    SkASSERT(!std::holds_alternative<SkPaint>(paint));
    const PaintRecord& pr = paints_[std::get<PaintID>(paint)];

    if (pr.isSymbolGlyph && G_IS_HM_SYMBOL_TXT_ENABLE) {
        std::vector<RSPoint> points;
        RSTextBlob::GetDrawingPointsForTextBlob(blob.get(), points);
        RSPoint offset;
        if (points.size() > 0) {
            offset = RSPoint{ x + points[0].GetX(), y + points[0].GetY() };
        } else {
            offset = RSPoint{ x, y };
        }
        DrawSymbolSkiaTxt(blob, offset, pr);
    } else if (pr.pen.has_value() && pr.brush.has_value()) {
        canvas_->AttachPen(pr.pen.value());
        canvas_->DrawTextBlob(blob.get(), x, y);
        canvas_->DetachPen();
        canvas_->AttachBrush(pr.brush.value());
        canvas_->DrawTextBlob(blob.get(), x, y);
        canvas_->DetachBrush();
    } else if (pr.pen.has_value() && !pr.brush.has_value()) {
        canvas_->AttachPen(pr.pen.value());
        canvas_->DrawTextBlob(blob.get(), x, y);
        canvas_->DetachPen();
    } else if (!pr.pen.has_value() && pr.brush.has_value()) {
        canvas_->AttachBrush(pr.brush.value());
        canvas_->DrawTextBlob(blob.get(), x, y);
        canvas_->DetachBrush();
    } else {
        Drawing::Brush brush;
        if (blob != nullptr && blob->IsEmoji()) {
            brush.SetBlenderEnabled(false);
        }
        brush.SetColor(pr.color);
        canvas_->AttachBrush(brush);
        canvas_->DrawTextBlob(blob.get(), x, y);
        canvas_->DetachBrush();
    }
}

void RSCanvasParagraphPainter::SymbolAnimation(const PaintRecord &pr)
{
    auto painterSymbolAnimationConfig = std::make_shared<TextEngine::SymbolAnimationConfig>();
    if (painterSymbolAnimationConfig == nullptr) {
        return;
    }
    painterSymbolAnimationConfig->effectStrategy = pr.symbol.GetEffectStrategy();
    if (animationFunc_ != nullptr) {
        animationFunc_(painterSymbolAnimationConfig);
    }
}

void RSCanvasParagraphPainter::drawTextShadow(const std::shared_ptr<RSTextBlob>& blob, SkScalar x, SkScalar y,
    SkColor color, SkScalar blurSigma)
{
    Drawing::Filter filter;
    filter.SetMaskFilter(Drawing::MaskFilter::CreateBlurMaskFilter(Drawing::BlurType::NORMAL, blurSigma, false));

    Drawing::Brush brush;
    brush.SetColor(PaintRecord::ToRSColor(color));
    brush.SetAntiAlias(true);
    brush.SetFilter(filter);

    canvas_->AttachBrush(brush);
    canvas_->DrawTextBlob(blob.get(), x, y);
    canvas_->DetachBrush();
}

void RSCanvasParagraphPainter::drawRect(const SkRect& rect, const SkPaintOrID& paint)
{
    SkASSERT(!std::holds_alternative<SkPaint>(paint));
    const PaintRecord& pr = paints_[std::get<PaintID>(paint)];
    Drawing::Rect rsRect = ToDrawingRect(rect);

    if (pr.pen.has_value()) {
        canvas_->AttachPen(pr.pen.value());
        canvas_->DrawRect(rsRect);
        canvas_->DetachPen();
    }
    if (pr.brush.has_value()) {
        canvas_->AttachBrush(pr.brush.value());
        canvas_->DrawRect(rsRect);
        canvas_->DetachBrush();
    }
}

void RSCanvasParagraphPainter::drawRRect(const SkRRect& rrect, const SkColor color)
{
    Drawing::RoundRect rsRRect = ToDrawingRoundRect(rrect);
    Drawing::Brush brush;
    brush.SetColor(PaintRecord::ToRSColor(color));
    brush.SetAntiAlias(false);
    canvas_->AttachBrush(brush);
    canvas_->DrawRoundRect(rsRRect);
    canvas_->DetachBrush();
}

void RSCanvasParagraphPainter::drawFilledRect(const SkRect& rect, const DecorationStyle& decorStyle)
{
    Drawing::Paint paint = ConvertDecorStyle(decorStyle, Drawing::Paint::PAINT_FILL);
    Drawing::Rect rsRect = ToDrawingRect(rect);

    canvas_->AttachPaint(paint);
    canvas_->DrawRect(rsRect);
    canvas_->DetachPaint();
}

void RSCanvasParagraphPainter::drawPath(const RSPath& path, const DecorationStyle& decorStyle)
{
    Drawing::Paint paint = ConvertDecorStyle(decorStyle);

    canvas_->AttachPaint(paint);
    canvas_->DrawPath(path);
    canvas_->DetachPaint();
}

void RSCanvasParagraphPainter::drawLine(
    SkScalar x0, SkScalar y0, SkScalar x1, SkScalar y1, const DecorationStyle& decorStyle)
{
    Drawing::Paint paint = ConvertDecorStyle(decorStyle);
    Drawing::Point point0(x0, y0);
    Drawing::Point point1(x1, y1);

    canvas_->AttachPaint(paint);
    canvas_->DrawLine(point0, point1);
    canvas_->DetachPaint();
}

void RSCanvasParagraphPainter::clipRect(const SkRect& rect)
{
    Drawing::Rect rsRect = ToDrawingRect(rect);
    canvas_->ClipRect(rsRect);
}

void RSCanvasParagraphPainter::translate(SkScalar dx, SkScalar dy)
{
    canvas_->Translate(dx, dy);
}

void RSCanvasParagraphPainter::save()
{
    canvas_->Save();
}

void RSCanvasParagraphPainter::restore()
{
    canvas_->Restore();
}

std::shared_ptr<HMSymbolRun> RSCanvasParagraphPainter::generateSymbolRun(
    const std::shared_ptr<RSTextBlob>& blob, const PaintRecord& pr)
{
    for (const std::shared_ptr<HMSymbolRun>& hmSymbol : hmSymbols_) {
        if (hmSymbol->GetSymbolUid() != pr.symbol.GetSymbolUid()) {
            continue;
        }

        hmSymbol->SetTextBlob(blob);
        hmSymbol->SetSymbolTxt(pr.symbol);
        return hmSymbol;
    }
    return nullptr;
}
} // namespace SPText
} // namespace Rosen
} // namespace OHOS
