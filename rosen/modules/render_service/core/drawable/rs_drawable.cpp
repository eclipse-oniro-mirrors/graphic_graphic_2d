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

#include "drawable/rs_drawable.h"

#include "drawable/rs_render_node_drawable.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_recording_canvas.h"
#include "pipeline/rs_render_node.h"

namespace OHOS::Rosen {

// ==================== RSChildrenDrawable =====================
std::shared_ptr<RSDrawable> RSChildrenDrawable::OnGenerate(const RSRenderNode& node)
{
    if (auto ret = std::make_shared<RSChildrenDrawable>(); ret->OnUpdate(node)) {
        return ret;
    }
    return nullptr;
}

bool RSChildrenDrawable::OnUpdate(const RSRenderNode& node)
{
    needSync_ = true;
    stagingChildrenDrawables_.clear();

    auto children = node.GetSortedChildren();
    if (children == nullptr || children->empty()) {
        return false;
    }
    stagingChildrenDrawables_.clear();
    for (auto& child : *children) {
        stagingChildrenDrawables_.push_back(RSRenderNodeDrawable::OnGenerate(child));
    }
    return true;
}

void RSChildrenDrawable::OnSync()
{
    if (!needSync_) {
        return;
    }
    childrenDrawables_ = std::move(stagingChildrenDrawables_);
    needSync_ = false;
}

void RSChildrenDrawable::OnDraw(RSPaintFilterCanvas& canvas) const
{
    for (auto& drawable : childrenDrawables_) {
        drawable->OnDraw(canvas);
    }
}

// ==================== RSCustomModifierDrawable ===================
RSDrawable::Ptr RSCustomModifierDrawable::OnGenerate(const RSRenderNode& node, RSModifierType type)
{
    const auto& drawCmdModifiers = node.GetDrawCmdModifiers();
    auto itr = drawCmdModifiers.find(type);
    if (itr == drawCmdModifiers.end() || itr->second.empty()) {
        return nullptr;
    }
    if (auto ret = std::make_shared<RSCustomModifierDrawable>(type); ret->OnUpdate(node)) {
        return ret;
    }
    return nullptr;
}

bool RSCustomModifierDrawable::OnUpdate(const RSRenderNode& node)
{
    stagingDrawCmdList_.clear();
    needSync_ = true;

    const auto& drawCmdModifiers = node.GetDrawCmdModifiers();
    auto itr = drawCmdModifiers.find(type_);
    if (itr == drawCmdModifiers.end() || itr->second.empty()) {
        return false;
    }
    // regenerate stagingDrawCmdList_
    for (const auto& modifier : itr->second) {
        auto property = std::static_pointer_cast<RSRenderProperty<Drawing::DrawCmdListPtr>>(modifier->GetProperty());
        if (property == nullptr) {
            continue;
        }
        if (auto& drawCmdList = property->GetRef()) {
            stagingDrawCmdList_.push_back(drawCmdList);
        }
    }
    return true;
}

void RSCustomModifierDrawable::OnSync()
{
    if (!needSync_) {
        return;
    }
    drawCmdList_ = std::move(stagingDrawCmdList_);
    needSync_ = false;
}

void RSCustomModifierDrawable::OnDraw(RSPaintFilterCanvas& canvas) const
{
    for (auto& drawCmdList : drawCmdList_) {
        drawCmdList->Playback(canvas);
    }
}
} // namespace OHOS::Rosen
