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

#ifndef RENDER_SERVICE_BASE_PROPERTY_RS_PROPERTY_DRAWABLE_H
#define RENDER_SERVICE_BASE_PROPERTY_RS_PROPERTY_DRAWABLE_H

#include <list>
#include <map>
#include <unordered_set>
#include <utility>

#include "modifier/rs_render_modifier.h"

namespace OHOS::Rosen {
class RSPaintFilterCanvas;
class RSProperties;
class RSPropertyDrawableGenerateContext;
class RSPropertyDrawableRenderContext;
class RSRenderModifier;
class RSRenderNode;

enum class RSPropertyDrawableSlot : unsigned char {
    INVALID = 0,

    SAVE_ALL,

    // Bounds Geometry
    BOUNDS_MATRIX,
    ALPHA,
    MASK,
    TRANSITION,
    ENV_FOREGROUND_COLOR,
    SHADOW,

    // In Bounds Clip
    SAVE_BOUNDS,
    CLIP_TO_BOUNDS,
    BACKGROUND,
    BACKGROUND_FILTER,
    USE_EFFECT,
    CUSTOM_BACKGROUND_MODIFIER,
    DYNAMIC_LIGHT_UP,
    ENV_FOREGROUND_COLOR_STRATEGY,
    RESTORE_BOUNDS_BEFORE_FRAME,

    // Frame Geometry
    SAVE_FRAME,
    FRAME_OFFSET,
    CLIP_TO_FRAME,
    CONTENT_STYLE,
    CHILDREN,
    FOREGROUND_STYLE,
    COLOR_FILTER,
    RESTORE_FRAME,

    // In Bounds clip (again)
    SAVE_BOUNDS_AFTER_CHILDREN,
    CLIP_TO_BOUNDS_AFTER_CHILDREN,
    LIGHT_UP_EFFECT,
    FOREGROUND_FILTER,
    LINEAR_GRADIENT_BLUR_FILTER,
    BORDER,
    OVERLAY,
    FOREGROUND_COLOR,
    PARTICLE_EFFECT,
    PIXEL_STRETCH,
    RESTORE_BOUNDS,

    RESTORE_ALL,
};

// Pure virtual base class
class RSPropertyDrawable {
public:
    RSPropertyDrawable() = default;
    virtual ~RSPropertyDrawable() = default;

    // not copyable and moveable
    RSPropertyDrawable(const RSPropertyDrawable&) = delete;
    RSPropertyDrawable(const RSPropertyDrawable&&) = delete;
    RSPropertyDrawable& operator=(const RSPropertyDrawable&) = delete;
    RSPropertyDrawable& operator=(const RSPropertyDrawable&&) = delete;

    using DrawablePtr = std::unique_ptr<RSPropertyDrawable>;

    //
    virtual void Draw(RSPropertyDrawableRenderContext& context) = 0;
    virtual void OnGeometryChange(const RSProperties& properties) {}

    // Generator
    using DrawableMap = std::map<RSPropertyDrawableSlot, RSPropertyDrawable::DrawablePtr>;
    static void UpdateDrawableMap(RSPropertyDrawableGenerateContext& context, DrawableMap& drawableMap,
        const std::unordered_set<RSModifierType>& dirtyTypes);

private:
    // index = RSModifierType value = RSPropertyDrawableType
    static const std::vector<RSPropertyDrawableSlot> PropertyToDrawableLut;
    // index = RSPropertyDrawableType value = DrawableGenerator
    using DrawableGenerator = std::function<RSPropertyDrawable::DrawablePtr(const RSPropertyDrawableGenerateContext&)>;
    static const std::vector<DrawableGenerator> DrawableGeneratorLut;

    static void OptimizeSaveRestore(RSPropertyDrawableGenerateContext& context, DrawableMap& drawableMap);
};

class RSPropertyDrawableGenerateContext {
public:
    explicit RSPropertyDrawableGenerateContext(RSRenderNode& node);
    virtual ~RSPropertyDrawableGenerateContext() = default;

    // disable copy and move
    RSPropertyDrawableGenerateContext(const RSPropertyDrawableGenerateContext&) = delete;
    RSPropertyDrawableGenerateContext(const RSPropertyDrawableGenerateContext&&) = delete;
    RSPropertyDrawableGenerateContext& operator=(const RSPropertyDrawableGenerateContext&) = delete;
    RSPropertyDrawableGenerateContext& operator=(const RSPropertyDrawableGenerateContext&&) = delete;

    // member variable
    const std::shared_ptr<RSRenderNode> node_;
    const RSProperties& properties_;
    bool hasChildren_;
};

class RSPropertyDrawableRenderContext : public RSModifierContext {
public:
    explicit RSPropertyDrawableRenderContext(RSRenderNode& node, RSPaintFilterCanvas* canvas);
    virtual ~RSPropertyDrawableRenderContext() = default;

    // disable copy and move
    RSPropertyDrawableRenderContext(const RSPropertyDrawableRenderContext&) = delete;
    RSPropertyDrawableRenderContext(const RSPropertyDrawableRenderContext&&) = delete;
    RSPropertyDrawableRenderContext& operator=(const RSPropertyDrawableRenderContext&) = delete;
    RSPropertyDrawableRenderContext& operator=(const RSPropertyDrawableRenderContext&&) = delete;

    // member variable
    const std::shared_ptr<RSRenderNode> node_;
    const std::list<std::shared_ptr<RSRenderNode>>& children_;
    RSPropertyDrawable::DrawableMap& drawableMap_;
    std::map<RSModifierType, std::list<std::shared_ptr<RSRenderModifier>>>& drawCmdModifiers_;
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_PROPERTY_RS_PROPERTY_DRAWABLE_H
