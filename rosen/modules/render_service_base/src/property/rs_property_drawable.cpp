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

#include "property/rs_property_drawable.h"

#include "common/rs_obj_abs_geometry.h"
#include "platform/common/rs_log.h"
#include "property/rs_properties.h"
#include "property/rs_properties_painter.h"

namespace {
constexpr int PARAM_DOUBLE = 2;
}
namespace OHOS::Rosen {

RSPropertyDrawable::SaveRestorePair RSPropertyDrawable::GenerateSaveRestore(RSPaintFilterCanvas::SaveType type)
{
    if (type == RSPaintFilterCanvas::kNone) {
        return {};
    } else if (type == RSPaintFilterCanvas::kCanvas) {
        auto count = std::make_shared<int>(-1);
        return { std::make_unique<RSSaveDrawable>(count), std::make_unique<RSRestoreDrawable>(count) };
    } else {
        auto status = std::make_shared<RSPaintFilterCanvas::SaveStatus>();
        return { std::make_unique<RSCustomSaveDrawable>(status, type),
            std::make_unique<RSCustomRestoreDrawable>(status) };
    }
}

// ============================================================================
// Save and Restore
RSSaveDrawable::RSSaveDrawable(std::shared_ptr<int> content) : content_(std::move(content)) {}
void RSSaveDrawable::Draw(RSModifierContext& context)
{
    *content_ = context.canvas_->save();
}

RSRestoreDrawable::RSRestoreDrawable(std::shared_ptr<int> content) : content_(std::move(content)) {}
void RSRestoreDrawable::Draw(RSModifierContext& context)
{
    context.canvas_->restoreToCount(*content_);
}

RSCustomSaveDrawable::RSCustomSaveDrawable(std::shared_ptr<RSPaintFilterCanvas::SaveStatus> content, RSPaintFilterCanvas::SaveType type)
    : content_(std::move(content)), type_(type)
{}
void RSCustomSaveDrawable::Draw(RSModifierContext& context)
{
    *content_ = context.canvas_->Save(type_);
}

RSCustomRestoreDrawable::RSCustomRestoreDrawable(std::shared_ptr<RSPaintFilterCanvas::SaveStatus> content)
    : content_(std::move(content))
{}
void RSCustomRestoreDrawable::Draw(RSModifierContext& context)
{
    context.canvas_->RestoreStatus(*content_);
}

// ============================================================================
// Adapter for DrawCmdList
RSDrawCmdListDrawable::RSDrawCmdListDrawable(std::shared_ptr<DrawCmdList> content) : content_(std::move(content)) {}
void RSDrawCmdListDrawable::Draw(RSModifierContext& context)
{
    // PLANNING: pass correct rect into DrawCmdList
    content_->Playback(*context.canvas_, nullptr);
}

// Adapter for RSRenderModifier
RSModifierDrawable::RSModifierDrawable(std::list<std::shared_ptr<RSRenderModifier>> content)
    : content_(std::move(content))
{}
void RSModifierDrawable::Draw(RSModifierContext& context)
{
    for (const auto& modifier : content_) {
        modifier->Apply(context);
    }
}

// ============================================================================
// Bounds and frame geometry
RSBoundsGeometryDrawable::RSBoundsGeometryDrawable(const SkMatrix& boundsMatrix) : boundsMatrix_(boundsMatrix) {}

void RSBoundsGeometryDrawable::Draw(RSModifierContext& context)
{
    context.canvas_->concat(boundsMatrix_);
}
std::unique_ptr<RSPropertyDrawable> RSBoundsGeometryDrawable::Generate(const RSProperties& properties)
{
    auto& matrix = properties.GetBoundsGeometry()->GetMatrix();
    if (matrix.isIdentity()) {
        return nullptr;
    }
    return std::make_unique<RSBoundsGeometryDrawable>(matrix);
}

RSFrameGeometryDrawable::RSFrameGeometryDrawable(float frameOffsetX, float frameOffsetY)
    : frameOffsetX_(frameOffsetX), frameOffsetY_(frameOffsetY)
{}
void RSFrameGeometryDrawable::Draw(RSModifierContext& context)
{
    context.canvas_->translate(frameOffsetX_, frameOffsetY_);
}
std::unique_ptr<RSPropertyDrawable> RSFrameGeometryDrawable::Generate(const RSProperties& properties)
{
    auto frameOffsetX = properties.GetFrameOffsetX();
    auto frameOffsetY = properties.GetFrameOffsetY();
    if (frameOffsetX == 0 && frameOffsetY == 0) {
        return nullptr;
    }
    return std::make_unique<RSFrameGeometryDrawable>(frameOffsetX, frameOffsetY);
}

// ============================================================================
// Alpha
RSAlphaDrawable::RSAlphaDrawable(float alpha) : RSPropertyDrawable(), alpha_(alpha) {}
void RSAlphaDrawable::Draw(RSModifierContext& context)
{
    context.canvas_->MultiplyAlpha(alpha_);
}
std::unique_ptr<RSPropertyDrawable> RSAlphaDrawable::Generate(const RSProperties& properties)
{
    auto alpha = properties.GetAlpha();
    if (alpha == 1) {
        return nullptr;
    }
    return properties.GetAlphaOffscreen() ? std::make_unique<RSAlphaOffscreenDrawable>(alpha)
                                          : std::make_unique<RSAlphaDrawable>(alpha);
}

RSAlphaOffscreenDrawable::RSAlphaOffscreenDrawable(float alpha) : RSAlphaDrawable(alpha)
{
    OnGeometryChange(RSProperties());
}
void RSAlphaOffscreenDrawable::OnGeometryChange(const RSProperties& properties)
{
#ifndef USE_ROSEN_DRAWING
    rect_ = RSPropertiesPainter::Rect2SkRect(properties.GetBoundsRect());
#else
    rect_ = RSPropertiesPainter::Rect2DrawingRect(properties.GetBoundsRect());
#endif
}
void RSAlphaOffscreenDrawable::Draw(RSModifierContext& context)
{
#ifndef USE_ROSEN_DRAWING
    context.canvas_->saveLayerAlpha(&rect_, std::clamp(alpha_, 0.f, 1.f) * UINT8_MAX);
#else
    Drawing::Brush brush;
    brush.SetAlphaF(std::clamp(alpha, 0.f, 1.f) * UINT8_MAX);
    Drawing::SaveLayerOps slr(&rect, &brush);
    canvas.SaveLayer(slr);
#endif
}

// ============================================================================
// Clip to bounds and frame

// ============================================================================
// Border
std::unique_ptr<RSPropertyDrawable> RSBorderDrawable::Generate(const RSProperties& properties)
{
    auto& border = properties.GetBorder();
    if (!border || !border->HasBorder()) {
        return nullptr;
    }
    SkPaint paint;
    paint.setAntiAlias(true);
    if (border->ApplyFillStyle(paint)) {
        return std::make_unique<RSBorderDRRectDrawable>(std::move(paint), properties);
    } else if (properties.GetCornerRadius().IsZero() && border->ApplyFourLine(paint)) {
        return std::make_unique<RSBorderFourLineDrawable>(std::move(paint), properties);
    } else if (border->ApplyPathStyle(paint)) {
        return std::make_unique<RSBorderPathDrawable>(std::move(paint), properties);
    } else {
        return std::make_unique<RSBorderFourLineRoundCornerDrawable>(std::move(paint), properties);
    }
}
RSBorderDRRectDrawable::RSBorderDRRectDrawable(SkPaint&& paint, const RSProperties& properties)
    : RSBorderDrawable(std::move(paint))
{
    OnGeometryChange(properties);
}
void RSBorderDRRectDrawable::OnGeometryChange(const RSProperties& properties)
{
    inner_ = RSPropertiesPainter::RRect2SkRRect(properties.GetInnerRRect());
    outer_ = RSPropertiesPainter::RRect2SkRRect(properties.GetRRect());
}
void RSBorderDRRectDrawable::Draw(RSModifierContext& context)
{
    context.canvas_->drawDRRect(outer_, inner_, paint_);
}

RSBorderFourLineDrawable::RSBorderFourLineDrawable(SkPaint&& paint, const RSProperties& properties)
    : RSBorderDrawable(std::move(paint))
{
    OnGeometryChange(properties);
}
void RSBorderFourLineDrawable::OnGeometryChange(const RSProperties& properties)
{
    rect_ = properties.GetBoundsRect();
}
void RSBorderFourLineDrawable::Draw(RSModifierContext& context)
{
    context.property_.GetBorder()->PaintFourLine(*context.canvas_, paint_, rect_);
}

RSBorderPathDrawable::RSBorderPathDrawable(SkPaint&& paint, const RSProperties& properties)
    : RSBorderDrawable(std::move(paint))
{
    OnGeometryChange(properties);
}
void RSBorderPathDrawable::OnGeometryChange(const RSProperties& properties)
{
    auto borderWidth = properties.GetBorder()->GetWidth();
    RRect rrect = properties.GetRRect();
    rrect.rect_.width_ -= borderWidth;
    rrect.rect_.height_ -= borderWidth;
    rrect.rect_.Move(borderWidth / PARAM_DOUBLE, borderWidth / PARAM_DOUBLE);
    borderPath_.reset();
    borderPath_.addRRect(RSPropertiesPainter::RRect2SkRRect(rrect));
}
void RSBorderPathDrawable::Draw(RSModifierContext& context)
{
    context.canvas_->drawPath(borderPath_, paint_);
}

RSBorderFourLineRoundCornerDrawable::RSBorderFourLineRoundCornerDrawable(
    SkPaint&& paint, const RSProperties& properties)
    : RSBorderDrawable(std::move(paint))
{
    paint_.setStyle(SkPaint::Style::kStroke_Style);
    OnGeometryChange(properties);
}
void RSBorderFourLineRoundCornerDrawable::OnGeometryChange(const RSProperties& properties)
{
    innerRrect_ = RSPropertiesPainter::RRect2SkRRect(properties.GetInnerRRect());
    rrect_ = RSPropertiesPainter::RRect2SkRRect(properties.GetRRect());
}
void RSBorderFourLineRoundCornerDrawable::Draw(RSModifierContext& context)
{
    SkAutoCanvasRestore acr(context.canvas_, true);
    context.canvas_->clipRRect(innerRrect_, SkClipOp::kDifference, true);
    context.property_.GetBorder()->PaintTopPath(*context.canvas_, paint_, rrect_);
    context.property_.GetBorder()->PaintRightPath(*context.canvas_, paint_, rrect_);
    context.property_.GetBorder()->PaintBottomPath(*context.canvas_, paint_, rrect_);
    context.property_.GetBorder()->PaintLeftPath(*context.canvas_, paint_, rrect_);
}

} // namespace OHOS::Rosen
