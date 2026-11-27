/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_BASE_EFFECT_RS_RENDER_SHADER_BASE_H
#define RENDER_SERVICE_BASE_EFFECT_RS_RENDER_SHADER_BASE_H

#include "effect/rs_frame_cache_level.h"
#include "effect/rs_render_effect_template.h"
#include "effect/rs_render_property_tag.h"

namespace OHOS {
namespace Rosen {

namespace Drawing {
    class GEVisualEffectContainer;
    class GEVisualEffect;
    class GEShader;
} // namespace Drawing

class RSB_EXPORT RSNGRenderShaderBase : public RSNGRenderEffectBase<RSNGRenderShaderBase> {
public:
    ~RSNGRenderShaderBase() override = default;

    static std::shared_ptr<RSNGRenderShaderBase> Create(RSNGEffectType type);
    virtual void GenerateGEVisualEffect() {}

    virtual void AppendToGEContainer(std::shared_ptr<Drawing::GEVisualEffectContainer>& ge) {};

    void ApplyCacheConfigToGEContainer(std::shared_ptr<Drawing::GEVisualEffectContainer>& ge) const;

    [[nodiscard]] static bool Unmarshalling(Parcel& parcel, std::shared_ptr<RSNGRenderShaderBase>& val);

    void SetCachePolicy(RSFrameCacheLevel level, const RSFrameSkipPolicy& skipPolicy)
    {
        cacheLevel_ = level;
        skipPolicy_ = skipPolicy;
    }

    RSFrameCacheLevel GetFrameCacheLevel() const { return cacheLevel_; }

    const RSFrameSkipPolicy& GetFrameSkipPolicy() const { return skipPolicy_; }

    // Shader-specific trailer: cache policy
    uint32_t GetTrailerFlags() const override
    {
        return cacheLevel_ != RSFrameCacheLevel::NONE ? TRAILER_FLAG_CACHE_POLICY : 0;
    }

    bool OnMarshalTrailerData(Parcel& parcel, uint32_t flags) const override
    {
        if (flags & TRAILER_FLAG_CACHE_POLICY) {
            return OnMarshalCachePolicy(parcel);
        }
        return true;
    }

    [[nodiscard]] bool OnUnmarshalTrailerData(Parcel& parcel, uint32_t flags) override
    {
        if (flags & TRAILER_FLAG_CACHE_POLICY) {
            return OnUnmarshalCachePolicy(parcel);
        }
        return true;
    }

private:
    bool OnMarshalCachePolicy(Parcel& parcel) const
    {
        if (!RSMarshallingHelper::Marshalling(parcel, static_cast<int32_t>(cacheLevel_))) {
            return false;
        }
        if (!RSMarshallingHelper::Marshalling(parcel, static_cast<int32_t>(skipPolicy_.mode))) {
            return false;
        }
        return RSMarshallingHelper::Marshalling(parcel, skipPolicy_.skipInterval);
    }

    [[nodiscard]] bool OnUnmarshalCachePolicy(Parcel& parcel)
    {
        int32_t cacheLevelInt = 0;
        int32_t skipModeInt = 0;
        uint32_t skipInterval = 0;
        if (!RSMarshallingHelper::Unmarshalling(parcel, cacheLevelInt)) {
            return false;
        }
        if (!RSMarshallingHelper::Unmarshalling(parcel, skipModeInt)) {
            return false;
        }
        if (!RSMarshallingHelper::Unmarshalling(parcel, skipInterval)) {
            return false;
        }
        constexpr int32_t CACHE_LEVEL_MAX = static_cast<int32_t>(RSFrameCacheLevel::CONTAINER);
        constexpr int32_t SKIP_MODE_MAX = static_cast<int32_t>(RSFrameSkipMode::FIXED_INTERVAL);
        if (cacheLevelInt < 0 || cacheLevelInt > CACHE_LEVEL_MAX) {
            cacheLevelInt = static_cast<int32_t>(RSFrameCacheLevel::NONE);
        }
        if (skipModeInt < 0 || skipModeInt > SKIP_MODE_MAX) {
            skipModeInt = static_cast<int32_t>(RSFrameSkipMode::NONE);
        }
        cacheLevel_ = static_cast<RSFrameCacheLevel>(cacheLevelInt);
        skipPolicy_ = { static_cast<RSFrameSkipMode>(skipModeInt), skipInterval };
        return true;
    }

protected:
    RSFrameCacheLevel cacheLevel_ = RSFrameCacheLevel::NONE;
    RSFrameSkipPolicy skipPolicy_ {};

private:
    friend class RSNGRenderShaderHelper;
};

template<RSNGEffectType Type, typename... PropertyTags>
class RSNGRenderShaderTemplate : public RSNGRenderEffectTemplate<RSNGRenderShaderBase, Type, PropertyTags...> {
public:
    using EffectTemplateBase = RSNGRenderEffectTemplate<RSNGRenderShaderBase, Type, PropertyTags...>;

    RSNGRenderShaderTemplate() : EffectTemplateBase() {}
    ~RSNGRenderShaderTemplate() override = default;
    RSNGRenderShaderTemplate(const std::tuple<PropertyTags...>& properties) noexcept
        : EffectTemplateBase(properties) {}

    void AppendToGEContainer(std::shared_ptr<Drawing::GEVisualEffectContainer>& ge) override
    {
        if (ge == nullptr) {
            return;
        }
        RS_OPTIONAL_TRACE_FMT("RSRenderShader, Type: %s paramStr: %s",
            RSNGRenderEffectHelper::GetEffectTypeString(Type).c_str(),
            EffectTemplateBase::DumpProperties().c_str());
        auto geShader = RSNGRenderEffectHelper::CreateGEVisualEffect(Type);
        std::apply([&geShader](const auto&... propTag) {
            (RSNGRenderEffectHelper::UpdateVisualEffectParam<std::decay_t<decltype(propTag)>>(geShader, propTag), ...);
            },
            EffectTemplateBase::properties_);
        RSNGRenderEffectHelper::AppendToGEContainer(ge, geShader);
        if (EffectTemplateBase::nextEffect_) {
            EffectTemplateBase::nextEffect_->AppendToGEContainer(ge);
        }
    }

protected:
    virtual void OnGenerateGEVisualEffect(std::shared_ptr<Drawing::GEVisualEffect>) {}
};

class RSNGRenderShaderHelper {
public:
    static bool CheckEnableEDR(std::shared_ptr<RSNGRenderShaderBase>& shader);

    static void SetRotationAngle(const std::shared_ptr<RSNGRenderShaderBase>& shader,
        const Vector3f& rotationAngle);

    static void SetCornerRadius(const std::shared_ptr<RSNGRenderShaderBase>& shader,
        float cornerRadius);
    
    static void SetSDFShape(const std::shared_ptr<RSNGRenderShaderBase>& shader,
        const std::shared_ptr<RSNGRenderShapeBase>& sdfShape);

    static std::shared_ptr<RSPaintFilterCanvas::CachedEffectData> GetCachedBlurImage(Drawing::Canvas* canvas);

    static RectF CalcRect(const std::shared_ptr<RSNGRenderShaderBase>& shader, const RectF& bound);
};

#define ADD_PROPERTY_TAG(Effect, Prop) Effect##Prop##RenderTag
#define DECLARE_SHADER(ShaderName, ShaderType, ...) \
    using RSNGRender##ShaderName = RSNGRenderShaderTemplate<RSNGEffectType::ShaderType, __VA_ARGS__>

#include "effect/rs_render_shader_def.in"

#undef ADD_PROPERTY_TAG
#undef DECLARE_SHADER

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_RENDER_MASK_BASE_H
