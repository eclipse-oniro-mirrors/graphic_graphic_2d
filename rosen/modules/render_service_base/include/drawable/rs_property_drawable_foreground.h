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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_FOREGROUND_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_FOREGROUND_H

#include "common/rs_rect.h"
#include "common/rs_vector4.h"
#include "drawable/rs_property_drawable.h"
#include "property/rs_properties.h"
#include "property/rs_properties_def.h"

namespace OHOS::Rosen {
class RSFilter;
class RSBorder;
class RSNGRenderShaderBase;
class RSProperties;
namespace Drawing {
class GEShader;
class RuntimeEffect;
class RuntimeShaderBuilder;
} // namespace Drawing

namespace DrawableV2 {
namespace {
constexpr int MAX_LIGHT_SOURCES = 12;
}
class RSBinarizationDrawable : public RSDrawable {
public:
    RSBinarizationDrawable() = default;
    ~RSBinarizationDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    std::optional<Vector4f> aiInvert_;
    std::optional<Vector4f> stagingAiInvert_;
};

class RSColorFilterDrawable : public RSDrawable {
public:
    RSColorFilterDrawable() = default;
    ~RSColorFilterDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    std::shared_ptr<Drawing::ColorFilter> filter_;
    std::shared_ptr<Drawing::ColorFilter> stagingFilter_;
};

class RSLightUpEffectDrawable : public RSDrawable {
public:
    RSLightUpEffectDrawable() = default;
    ~RSLightUpEffectDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    float lightUpEffectDegree_ = 1.0f;
    float stagingLightUpEffectDegree_ = 1.0f;
};

class RSDynamicDimDrawable : public RSDrawable {
public:
    RSDynamicDimDrawable() = default;
    ~RSDynamicDimDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    float dynamicDimDegree_ = 1.0f;
    float stagingDynamicDimDegree_ = 1.0f;
};

class RSCompositingFilterDrawable : public RSFilterDrawable {
public:
    RSCompositingFilterDrawable() = default;
    ~RSCompositingFilterDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    bool IsForeground() const override
    {
        return true;
    }
};

// foregroundFilter
class RSForegroundFilterDrawable : public RSDrawable {
public:
    RSForegroundFilterDrawable() = default;
    ~RSForegroundFilterDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    RectF boundsRect_;
    RectF stagingBoundsRect_;
};

class RSForegroundFilterRestoreDrawable : public RSDrawable {
public:
    RSForegroundFilterRestoreDrawable() = default;
    ~RSForegroundFilterRestoreDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    bool needSync_ = false;
    std::shared_ptr<RSFilter> foregroundFilter_;
    std::shared_ptr<RSFilter> stagingForegroundFilter_;
};

class RSForegroundColorDrawable : public RSPropertyDrawable {
public:
    RSForegroundColorDrawable(std::shared_ptr<Drawing::DrawCmdList>&& drawCmdList)
        : RSPropertyDrawable(std::move(drawCmdList))
    {}
    RSForegroundColorDrawable() = default;
    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;

private:
};

class RSForegroundShaderDrawable : public RSDrawable {
public:
    RSForegroundShaderDrawable() = default;
    ~RSForegroundShaderDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;
private:
    bool needSync_ = false;
    std::shared_ptr<Drawing::GEShader> geShader_;
    std::shared_ptr<RSNGRenderShaderBase> stagingShader_;
};

class RSPointLightDrawable : public RSDrawable {
public:
    RSPointLightDrawable(const RSProperties &properties) : properties_(properties) {}
    ~RSPointLightDrawable() override = default;
    void OnSync() override;
    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;

private:
    const RSProperties &properties_;
    std::vector<std::pair<std::shared_ptr<RSLightSource>, Vector4f>> lightSourcesAndPosVec_;
    RectI rect_  = {};
    IlluminatedType illuminatedType_ = IlluminatedType::INVALID;
    Drawing::RoundRect borderRRect_ = {};
    Drawing::RoundRect contentRRect_ = {};
    float borderWidth_ = 0.0f;
    void DrawLight(Drawing::Canvas* canvas) const;
    static const std::shared_ptr<Drawing::RuntimeShaderBuilder>& GetPhongShaderBuilder();
    static const std::shared_ptr<Drawing::RuntimeShaderBuilder>& GetFeatheringBoardLightShaderBuilder();
    void DrawContentLight(Drawing::Canvas& canvas, std::shared_ptr<Drawing::RuntimeShaderBuilder>& lightBuilder,
        Drawing::Brush& brush, const std::array<float, MAX_LIGHT_SOURCES>& lightIntensityArray) const;
    void DrawBorderLight(Drawing::Canvas& canvas, std::shared_ptr<Drawing::RuntimeShaderBuilder>& lightBuilder,
        Drawing::Pen& pen, const std::array<float, MAX_LIGHT_SOURCES>& lightIntensityArray) const;
};

// ============================================================================
// Border & Outline
class RSBorderDrawable : public RSPropertyDrawable {
    friend class RSOutlineDrawable;

public:
    RSBorderDrawable(std::shared_ptr<Drawing::DrawCmdList>&& drawCmdList) : RSPropertyDrawable(std::move(drawCmdList))
    {}
    RSBorderDrawable() = default;
    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;

private:
    static void DrawBorder(const RSProperties& properties, Drawing::Canvas& canvas,
        const std::shared_ptr<RSBorder>& border, const bool& isOutline);
};

class RSOutlineDrawable : public RSPropertyDrawable {
public:
    RSOutlineDrawable(std::shared_ptr<Drawing::DrawCmdList>&& drawCmdList) : RSPropertyDrawable(std::move(drawCmdList))
    {}
    RSOutlineDrawable() = default;
    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;

private:
};

class RSParticleDrawable : public RSPropertyDrawable {
public:
    RSParticleDrawable(std::shared_ptr<Drawing::DrawCmdList>&& drawCmdList) : RSPropertyDrawable(std::move(drawCmdList))
    {}
    RSParticleDrawable() = default;
    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;

private:
};

class RSPixelStretchDrawable : public RSDrawable {
public:
    RSPixelStretchDrawable() = default;
    ~RSPixelStretchDrawable() override = default;

    static RSDrawable::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
    void OnSync() override;
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override;
    void SetPixelStretch(const std::optional<Vector4f>& pixelStretch);

private:
    bool needSync_ = false;
    NodeId stagingNodeId_ = INVALID_NODEID;
    NodeId renderNodeId_ = INVALID_NODEID;
    std::optional<Vector4f> pixelStretch_;
    std::optional<Vector4f> stagingPixelStretch_;
    int pixelStretchTileMode_ = 0;
    int stagePixelStretchTileMode_ = 0;
    bool boundsGeoValid_ = false;
    bool stagingBoundsGeoValid_ = false;
    RectF boundsRect_;
    RectF stagingBoundsRect_;
};
} // namespace DrawableV2
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_FOREGROUND_H
