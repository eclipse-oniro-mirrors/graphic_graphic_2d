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
#include <utility>

#include "modifier/rs_render_modifier.h"

namespace OHOS::Rosen {
class RSPaintFilterCanvas;
class RSDrawCmdList;

// Pure virtual base class
class RSPropertyDrawable {
public:
    RSPropertyDrawable() = default;
    virtual ~RSPropertyDrawable() = default;
    virtual void Draw(RSModifierContext& context) = 0;
    virtual void OnGeometryChange(const RSProperties& properties) {}

    static std::pair<std::unique_ptr<RSPropertyDrawable>, std::unique_ptr<RSPropertyDrawable>> GenerateSaveRestore();

    // not copyable and moveable
    RSPropertyDrawable(const RSPropertyDrawable&) = delete;
    RSPropertyDrawable(const RSPropertyDrawable&&) = delete;
    RSPropertyDrawable& operator=(const RSPropertyDrawable&) = delete;
    RSPropertyDrawable& operator=(const RSPropertyDrawable&&) = delete;
};

// ============================================================================
// Save and Restore
class RSSaveDrawable : public RSPropertyDrawable {
public:
    explicit RSSaveDrawable(std::shared_ptr<int> content);
    ~RSSaveDrawable() override = default;
    void Draw(RSModifierContext& context) override;

private:
    std::shared_ptr<int> content_;
};

class RSRestoreDrawable : public RSPropertyDrawable {
public:
    explicit RSRestoreDrawable(std::shared_ptr<int> content);
    ~RSRestoreDrawable() override = default;
    void Draw(RSModifierContext& context) override;

private:
    std::shared_ptr<int> content_;
};

// ============================================================================
// Adapter for DrawCmdList
class RSDrawCmdListDrawable : public RSPropertyDrawable {
public:
    explicit RSDrawCmdListDrawable(std::shared_ptr<DrawCmdList> content);
    ~RSDrawCmdListDrawable() override = default;
    void Draw(RSModifierContext& context) override;

private:
    std::shared_ptr<DrawCmdList> content_;
};

// Adapter for RSRenderModifier
class RSModifierDrawable : public RSPropertyDrawable {
public:
    explicit RSModifierDrawable(std::list<std::shared_ptr<RSRenderModifier>> content);
    ~RSModifierDrawable() override = default;

    void Draw(RSModifierContext& context) override;

private:
    std::list<std::shared_ptr<RSRenderModifier>> content_;
};

// ============================================================================
// Bounds and frame geometry
class RSBoundsGeometryDrawable : public RSPropertyDrawable {
public:
    explicit RSBoundsGeometryDrawable(const SkMatrix& boundsMatrix);
    ~RSBoundsGeometryDrawable() override = default;
    void Draw(RSModifierContext& context) override;

    static std::unique_ptr<RSPropertyDrawable> Generate(const RSProperties& properties);

private:
    SkMatrix boundsMatrix_;
};

class RSFrameGeometryDrawable : public RSPropertyDrawable {
public:
    explicit RSFrameGeometryDrawable(float frameOffsetX, float frameOffsetY);
    ~RSFrameGeometryDrawable() override = default;
    void Draw(RSModifierContext& context) override;

    static std::unique_ptr<RSPropertyDrawable> Generate(const RSProperties& properties);

private:
    float frameOffsetX_;
    float frameOffsetY_;
};

// ============================================================================
// Alpha
class RSAlphaDrawable : public RSPropertyDrawable {
public:
    explicit RSAlphaDrawable(float alpha);
    ~RSAlphaDrawable() override = default;
    void Draw(RSModifierContext& context) override;

    static std::unique_ptr<RSPropertyDrawable> Generate(const RSProperties& properties);

protected:
    float alpha_;
};

class RSAlphaOffscreenDrawable : public RSAlphaDrawable {
public:
    explicit RSAlphaOffscreenDrawable(float alpha);

    void Draw(RSModifierContext& context) override;
    void OnGeometryChange(const RSProperties& properties) override;

private:
#ifndef USE_ROSEN_DRAWING
    SkRect rect_;
#else
    Drawing::Brush brush_;
#endif
};

// ============================================================================
// Clip to bounds and frame
class RSClipBoundsDrawable : public RSPropertyDrawable {
public:
    explicit RSClipBoundsDrawable(const SkRect& content) : content_(content) {}
    ~RSClipBoundsDrawable() override = default;
    void Draw(RSModifierContext& context) override;

    static std::unique_ptr<RSPropertyDrawable> Generate(const RSProperties& properties);

private:
    SkRect content_;
};

class RSClipFrameDrawable : public RSPropertyDrawable {
public:
    explicit RSClipFrameDrawable(const SkRect& content) : content_(content) {}
    ~RSClipFrameDrawable() override = default;
    void Draw(RSModifierContext& context) override;

private:
    SkRect content_;
};

// ============================================================================
// Border
class RSBorderDrawable : public RSPropertyDrawable {
public:
    explicit RSBorderDrawable(SkPaint&& paint) : RSPropertyDrawable(), paint_(std::move(paint)) {}
    ~RSBorderDrawable() override = default;
    static std::unique_ptr<RSPropertyDrawable> Generate(const RSProperties& properties);

protected:
    SkPaint paint_;
};

class RSBorderDRRectDrawable : public RSBorderDrawable {
public:
    explicit RSBorderDRRectDrawable(SkPaint&& paint, const RSProperties& properties);
    ~RSBorderDRRectDrawable() override = default;
    void OnGeometryChange(const RSProperties& properties) override;
    void Draw(RSModifierContext& context) override;

private:
    SkRRect inner_;
    SkRRect outer_;
};

class RSBorderFourLineDrawable : public RSBorderDrawable {
public:
    explicit RSBorderFourLineDrawable(SkPaint&& paint, const RSProperties& properties);
    ~RSBorderFourLineDrawable() override = default;
    void OnGeometryChange(const RSProperties& properties) override;
    void Draw(RSModifierContext& context) override;

private:
    RectF rect_;
};

class RSBorderPathDrawable : public RSBorderDrawable {
public:
    explicit RSBorderPathDrawable(SkPaint&& paint, const RSProperties& properties);
    ~RSBorderPathDrawable() override = default;
    void OnGeometryChange(const RSProperties& properties) override;
    void Draw(RSModifierContext& context) override;

private:
    SkPath borderPath_;
};

class RSBorderFourLineRoundCornerDrawable : public RSBorderDrawable {
public:
    explicit RSBorderFourLineRoundCornerDrawable(SkPaint&& paint, const RSProperties& properties);
    ~RSBorderFourLineRoundCornerDrawable() override = default;
    void OnGeometryChange(const RSProperties& properties) override;
    void Draw(RSModifierContext& context) override;

private:
    SkRRect innerRrect_;
    SkRRect rrect_;
};
// ============================================================================

}; // namespace OHOS::Rosen

#endif