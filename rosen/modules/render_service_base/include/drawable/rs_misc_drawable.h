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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_MISC_DRAWABLE_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_MISC_DRAWABLE_H

#include <bitset>
#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <unordered_set>

#include "drawable/rs_drawable.h"
#include "modifier/rs_modifier_type.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "property/rs_properties_def.h"

namespace OHOS::Rosen {
enum class RSModifierType : int16_t;
namespace Drawing {
class DrawCmdList;
}

namespace DrawableV2 {
class RSRenderNodeDrawableAdapter;
// RSChildrenDrawable, for drawing children of RSRenderNode, updates on child add/remove
class RSChildrenDrawable : public RSDrawable {
public:
    RSChildrenDrawable() = default;
    ~RSChildrenDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& content) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    std::vector<std::shared_ptr<RSRenderNodeDrawableAdapter>> childrenDrawableVec_;
    std::vector<std::shared_ptr<RSRenderNodeDrawableAdapter>> stagingChildrenDrawableVec_;

    // Shared Transition related
    bool childrenHasSharedTransition_ = false;
    bool OnSharedTransition(const std::shared_ptr<RSRenderNode>& node);
    friend class RSRenderNode;
    friend class RSRenderNodeDrawableAdapter;
};

// RSCustomModifierDrawable, for drawing custom modifiers
class RSCustomModifierDrawable : public RSDrawable {
public:
    RSCustomModifierDrawable(RSModifierType type) : type_(type) {}
    static RSDrawable::Ptr OnGenerate(const RSRenderNode& content, RSModifierType type);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    RSModifierType type_;
    bool needClearOp_ = false;
    bool needSync_ = false;
    Gravity gravity_ = Gravity::DEFAULT;
    Gravity stagingGravity_ = Gravity::DEFAULT;
    bool isCanvasNode_ = false;
    bool stagingIsCanvasNode_ = false;
    std::vector<std::shared_ptr<Drawing::DrawCmdList>> drawCmdListVec_;
    std::vector<std::shared_ptr<Drawing::DrawCmdList>> stagingDrawCmdListVec_;
};

// ============================================================================
// Save and Restore
class RSSaveDrawable : public RSDrawable {
public:
    explicit RSSaveDrawable(std::shared_ptr<uint32_t> content);
    ~RSSaveDrawable() override = default;

    // no need to sync, content_ only used in render thread
    void OnSync() override {};
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    std::shared_ptr<uint32_t> content_;
};

class RSRestoreDrawable : public RSDrawable {
public:
    explicit RSRestoreDrawable(std::shared_ptr<uint32_t> content);
    ~RSRestoreDrawable() override = default;

    // no need to sync, content_ only used in render thread
    void OnSync() override {};
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    std::shared_ptr<uint32_t> content_;
};

class RSCustomSaveDrawable : public RSDrawable {
public:
    explicit RSCustomSaveDrawable(
        std::shared_ptr<RSPaintFilterCanvas::SaveStatus> content, RSPaintFilterCanvas::SaveType type);
    ~RSCustomSaveDrawable() override = default;

    // no need to sync, content_ only used in render thread
    void OnSync() override {};
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    std::shared_ptr<RSPaintFilterCanvas::SaveStatus> content_;
    RSPaintFilterCanvas::SaveType type_;
};

class RSCustomRestoreDrawable : public RSDrawable {
public:
    explicit RSCustomRestoreDrawable(std::shared_ptr<RSPaintFilterCanvas::SaveStatus> content);
    ~RSCustomRestoreDrawable() override = default;

    // no need to sync, content_ only used in render thread
    void OnSync() override {};
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    std::shared_ptr<RSPaintFilterCanvas::SaveStatus> content_;
};

// ============================================================================
// EnvFGColor
class RSEnvFGColorDrawable : public RSDrawable {
public:
    explicit RSEnvFGColorDrawable() = default;
    ~RSEnvFGColorDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;

    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

protected:
    bool needSync_ = false;
    Color envFGColor_;
    Color stagingEnvFGColor_;
};

// ============================================================================
// EnvFGColorStrategy
class RSEnvFGColorStrategyDrawable : public RSDrawable {
public:
    explicit RSEnvFGColorStrategyDrawable() = default;
    ~RSEnvFGColorStrategyDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;

    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

protected:
    bool needSync_ = false;
    ForegroundColorStrategyType envFGColorStrategy_;
    bool needClipToBounds_;
    Color backgroundColor_;
    Vector4f boundsRect_;

    ForegroundColorStrategyType stagingEnvFGColorStrategy_;
    bool stagingNeedClipToBounds_;
    Color stagingBackgroundColor_;
    Vector4f stagingBoundsRect_;
};

// ============================================================================
// Blender & BlendMode
class RSBeginBlenderDrawable : public RSDrawable {
public:
    RSBeginBlenderDrawable() = default;
    ~RSBeginBlenderDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    std::shared_ptr<Drawing::Blender> blender_ = nullptr;
    int blendApplyType_ = 0;
    bool isDangerous_ = false;
    std::string propertyDescription_;

    std::shared_ptr<Drawing::Blender> stagingBlender_ = nullptr;
    int stagingBlendApplyType_ = 0;
    bool stagingIsDangerous_ = false;
    std::string stagingPropertyDescription_;
};

class RSEndBlenderDrawable : public RSDrawable {
public:
    RSEndBlenderDrawable() = default;
    ~RSEndBlenderDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    int blendApplyType_ = 0;
    int stagingBlendApplyType_ = 0;
};
} // namespace DrawableV2
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_MISC_DRAWABLE_H
