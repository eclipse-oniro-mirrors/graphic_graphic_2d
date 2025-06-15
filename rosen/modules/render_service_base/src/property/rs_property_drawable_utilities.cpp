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

#include "feature/single_frame_composer/rs_single_frame_composer.h"
#include "property/rs_property_drawable_utilities.h"
#include "pipeline/rs_render_node.h"
#include "property/rs_properties.h"
#include "property/rs_properties_painter.h"
#include "platform/common/rs_log.h"

namespace OHOS::Rosen {
// ============================================================================
// alias (reference or soft link) of another drawable
RSAliasDrawable::RSAliasDrawable(RSPropertyDrawableSlot slot) : slot_(slot) {}
void RSAliasDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    content.DrawPropertyDrawable(slot_, canvas);
}

// ============================================================================
// Save and Restore
RSSaveDrawable::RSSaveDrawable(std::shared_ptr<uint32_t> content) : content_(std::move(content)) {}
void RSSaveDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    *content_ = canvas.Save();
}

RSRestoreDrawable::RSRestoreDrawable(std::shared_ptr<uint32_t> content) : content_(std::move(content)) {}
void RSRestoreDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    canvas.RestoreToCount(*content_);
}

RSCustomSaveDrawable::RSCustomSaveDrawable(
    std::shared_ptr<RSPaintFilterCanvas::SaveStatus> content, RSPaintFilterCanvas::SaveType type)
    : content_(std::move(content)), type_(type)
{}
void RSCustomSaveDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    *content_ = canvas.SaveAllStatus(type_);
}

RSCustomRestoreDrawable::RSCustomRestoreDrawable(std::shared_ptr<RSPaintFilterCanvas::SaveStatus> content)
    : content_(std::move(content))
{}
void RSCustomRestoreDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    canvas.RestoreStatus(*content_);
}

// ============================================================================
// Adapter for RSRenderModifier
void RSModifierDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    // single-frame-compose needs to access render node & mutable draw cmd list during the render process
    // PLANNING: this is a temporarily workaround, should refactor later
    auto nodePtr = content.GetRenderProperties().backref_.lock();
    if (nodePtr == nullptr) {
        ROSEN_LOGE("RSModifierDrawable::Draw nodePtr is nullptr");
        return;
    }
#ifdef MODIFIER_NG
        auto modifiers = nodePtr->modifiersNG_[static_cast<uint8_t>(modifierTypeNG_)];
        if (modifiers.empty()) {
            return;
        }
        if (RSSystemProperties::GetSingleFrameComposerEnabled()) {
            bool needSkip = false;
            if (nodePtr->GetNodeIsSingleFrameComposer() && nodePtr->singleFrameComposer_ != nullptr) {
                needSkip = nodePtr->singleFrameComposer_->SingleFrameModifierAddToListNG(modifierTypeNG_, modifiers);
            }
            for (const auto& modifier : modifiers) {
                if (nodePtr->singleFrameComposer_ != nullptr &&
                    nodePtr->singleFrameComposer_->SingleFrameIsNeedSkipNG(needSkip, modifier)) {
                    continue;
                }
                modifier->Apply(&canvas, const_cast<RSRenderContent&>(content).renderProperties_);
            }
        } else {
            for (const auto& modifier : modifiers) {
                modifier->Apply(&canvas, const_cast<RSRenderContent&>(content).renderProperties_);
            }
        }
        return;
#endif
    auto& drawCmdModifiers = const_cast<RSRenderContent::DrawCmdContainer&>(content.drawCmdModifiers_);
    auto itr = drawCmdModifiers.find(modifierType_);
    if (itr == drawCmdModifiers.end() || itr->second.empty()) {
        return;
    }
    // temporary fix, will refactor RSRenderModifier::Apply to workaround this issue
    RSModifierContext context = { const_cast<RSRenderContent&>(content).renderProperties_, &canvas };
    if (RSSystemProperties::GetSingleFrameComposerEnabled()) {
        bool needSkip = false;
        if (nodePtr->GetNodeIsSingleFrameComposer() && nodePtr->singleFrameComposer_ != nullptr) {
            needSkip = nodePtr->singleFrameComposer_->SingleFrameModifierAddToList(modifierType_, itr->second);
        }
        for (const auto& modifier : itr->second) {
            if (nodePtr->singleFrameComposer_ != nullptr &&
                nodePtr->singleFrameComposer_->SingleFrameIsNeedSkip(needSkip, modifier)) {
                continue;
            }
            modifier->Apply(context);
        }
    } else {
        for (const auto& modifier : itr->second) {
            if (modifier) {
                modifier->Apply(context);
            }
        }
    }
}

// ============================================================================
// Alpha
RSAlphaDrawable::RSAlphaDrawable(float alpha) : RSPropertyDrawable(), alpha_(alpha) {}
void RSAlphaDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    canvas.MultiplyAlpha(alpha_);
}
RSPropertyDrawable::DrawablePtr RSAlphaDrawable::Generate(const RSRenderContent& content)
{
    auto alpha = content.GetRenderProperties().GetAlpha();
    if (alpha == 1) {
        return nullptr;
    }
    return content.GetRenderProperties().GetAlphaOffscreen() ? std::make_unique<RSAlphaOffscreenDrawable>(alpha)
                                                   : std::make_unique<RSAlphaDrawable>(alpha);
}

RSAlphaOffscreenDrawable::RSAlphaOffscreenDrawable(float alpha) : RSAlphaDrawable(alpha) {}
void RSAlphaOffscreenDrawable::Draw(const RSRenderContent& content, RSPaintFilterCanvas& canvas) const
{
    auto rect = RSPropertiesPainter::Rect2DrawingRect(content.GetRenderProperties().GetBoundsRect());
    Drawing::Brush brush;
    brush.SetAlpha(std::clamp(alpha_, 0.f, 1.f) * UINT8_MAX);
    Drawing::SaveLayerOps slr(&rect, &brush);
    canvas.SaveLayer(slr);
}
} // namespace OHOS::Rosen
