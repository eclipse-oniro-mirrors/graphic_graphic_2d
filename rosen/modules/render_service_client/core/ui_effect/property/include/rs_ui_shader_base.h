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

#ifndef ROSEN_ENGINE_CORE_RENDER_UI_SHADER_BASE_H
#define ROSEN_ENGINE_CORE_RENDER_UI_SHADER_BASE_H

#include "effect/rs_frame_cache_level.h"
#include "effect/rs_render_shader_base.h"
#include "ui_effect/property/include/rs_ui_property_tag.h"
#include "ui_effect/property/include/rs_ui_template.h"

namespace OHOS {
namespace Rosen {

class RSNGShaderBase : public RSNGEffectBase<RSNGShaderBase, RSNGRenderShaderBase> {
public:
    virtual ~RSNGShaderBase() = default;

    RSC_EXPORT static std::shared_ptr<RSNGShaderBase> Create(RSNGEffectType type);
    RSC_EXPORT static std::shared_ptr<RSNGShaderBase> Create(std::shared_ptr<VisualEffectPara> effectPara);

    void EnableCache(RSFrameCacheLevel level, const RSFrameSkipPolicy& skipPolicy)
    {
        stagingCacheLevel_ = level;
        stagingSkipPolicy_ = skipPolicy;
        auto current = nextEffect_;
        while (current) {
            current->stagingCacheLevel_ = level;
            current->stagingSkipPolicy_ = skipPolicy;
            current = current->nextEffect_;
        }
    }

    RSFrameCacheLevel GetFrameCacheLevel() const { return stagingCacheLevel_; }

    const RSFrameSkipPolicy& GetFrameSkipPolicy() const { return stagingSkipPolicy_; }

    void OnCopyCachePolicyTo(RSNGRenderShaderBase& server) override
    {
        server.SetCachePolicy(stagingCacheLevel_, stagingSkipPolicy_);
        cacheLevel_ = stagingCacheLevel_;
        skipPolicy_ = stagingSkipPolicy_;
    }

    void OnCopyCachePolicyFrom(const RSNGShaderBase& other) override
    {
        stagingCacheLevel_ = other.stagingCacheLevel_;
        stagingSkipPolicy_ = other.stagingSkipPolicy_;
    }

    bool CachePolicyNeedsSync(const RSNGShaderBase& other) const override
    {
        return other.stagingCacheLevel_ != cacheLevel_ ||
            other.stagingSkipPolicy_.mode != skipPolicy_.mode ||
            other.stagingSkipPolicy_.skipInterval != skipPolicy_.skipInterval;
    }

protected:
    RSFrameCacheLevel stagingCacheLevel_ = RSFrameCacheLevel::NONE;
    RSFrameSkipPolicy stagingSkipPolicy_ {};
    RSFrameCacheLevel cacheLevel_ = RSFrameCacheLevel::NONE;
    RSFrameSkipPolicy skipPolicy_ {};
};

template<RSNGEffectType Type, typename... PropertyTags>
using RSNGShaderTemplate = RSNGEffectTemplate<RSNGShaderBase,
        RSNGRenderShaderTemplate<Type, typename PropertyTags::RenderPropertyTagType...>, Type, PropertyTags...>;


#define ADD_PROPERTY_TAG(Effect, Prop) Effect##Prop##Tag

#define DECLARE_SHADER(ShaderName, ShaderType, ...) \
    using RSNG##ShaderName = RSNGShaderTemplate<RSNGEffectType::ShaderType, __VA_ARGS__>

#include "effect/rs_render_shader_def.in"

#undef ADD_PROPERTY_TAG
#undef DECLARE_SHADER

} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_ENGINE_CORE_RENDER_UI_SHADER_BASE_H
