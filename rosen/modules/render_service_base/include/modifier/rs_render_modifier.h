/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_BASE_MODIFIER_RS_RENDER_MODIFIER_H
#define RENDER_SERVICE_BASE_MODIFIER_RS_RENDER_MODIFIER_H

#include <memory>

#include "parcel.h"
#include "recording/draw_cmd_list.h"
#include "rs_modifier_type.h"

#include "common/rs_color.h"
#include "common/rs_macros.h"
#include "common/rs_rect.h"
#include "modifier/rs_modifier_type.h"
#include "modifier/rs_render_property.h"
#include "utils/matrix.h"

namespace OHOS {
namespace Rosen {
class RSProperties;
class RSPaintFilterCanvas;
class RSRenderNode;
class RSRenderParticleVector;

class RSModifierContext {
public:
    RSModifierContext(RSProperties& property) : properties_(property), canvas_(nullptr) {}
    RSModifierContext(RSProperties& property, RSPaintFilterCanvas* canvas) : properties_(property), canvas_(canvas) {}
    RSProperties& properties_;
    RSPaintFilterCanvas* canvas_;
};

class RSB_EXPORT RSRenderModifier {
public:
    RSRenderModifier() = default;
    RSRenderModifier(const RSRenderModifier&) = delete;
    RSRenderModifier(const RSRenderModifier&&) = delete;
    RSRenderModifier& operator=(const RSRenderModifier&) = delete;
    RSRenderModifier& operator=(const RSRenderModifier&&) = delete;
    virtual ~RSRenderModifier() = default;

    virtual void Apply(RSModifierContext& context) const = 0;

    virtual PropertyId GetPropertyId() = 0;
    virtual std::shared_ptr<RSRenderPropertyBase> GetProperty() const = 0;
    void Dump(std::string& out) const
    {
        auto property = GetProperty();
        if (property != nullptr) {
            property->Dump(out);
        }
    }

    // LCOV_EXCL_START
    size_t GetSize()
    {
        auto property = GetProperty();
        if (property != nullptr) {
            return property->GetSize();
        }
        return 0;
    }
    // LCOV_EXCL_STOP

    // LCOV_EXCL_START
    virtual RSModifierType GetType()
    {
        return RSModifierType::INVALID;
    }
    // LCOV_EXCL_STOP

    virtual std::string GetModifierTypeString()
    {
        auto modifierTypeString = std::make_shared<RSModifierTypeString>();
        return modifierTypeString->GetModifierTypeString(GetType());
    }

    virtual void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) = 0;

    virtual bool Marshalling(Parcel& parcel) = 0;
    [[nodiscard]] static RSRenderModifier* Unmarshalling(Parcel& parcel);

    virtual std::shared_ptr<Drawing::DrawCmdList> GetPropertyDrawCmdList() const
    {
        return nullptr;
    }

    virtual void SetPropertyDrawCmdList(std::shared_ptr<Drawing::DrawCmdList> ptr) const
    {
    }

    // LCOV_EXCL_START
    virtual uint64_t GetDrawCmdListId() const
    {
        return 0;
    }
    // LCOV_EXCL_STOP
    virtual void SetSingleFrameModifier(bool value)
    {
        (void)value;
    }
    // LCOV_EXCL_START
    virtual bool GetSingleFrameModifier() const
    {
        return false;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSGeometryTransRenderModifier : public RSRenderModifier {
public:
    RSGeometryTransRenderModifier(const std::shared_ptr<RSRenderProperty<Drawing::Matrix>>& property)
        : property_(property ? property : std::make_shared<RSRenderProperty<Drawing::Matrix>>())
    {}
    ~RSGeometryTransRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    PropertyId GetPropertyId() override
    {
        return property_->GetId();
    }
    // LCOV_EXCL_STOP

    std::shared_ptr<RSRenderPropertyBase> GetProperty() const override
    {
        return property_;
    }

    void SetType(RSModifierType type)
    {
        drawStyle_ = type;
    }

    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return drawStyle_;
    }
    // LCOV_EXCL_STOP

protected:
    RSModifierType drawStyle_ = RSModifierType::GEOMETRYTRANS;
    std::shared_ptr<RSRenderProperty<Drawing::Matrix>> property_;
};

class RSB_EXPORT RSDrawCmdListRenderModifier : public RSRenderModifier {
public:
    RSDrawCmdListRenderModifier(const std::shared_ptr<RSRenderProperty<Drawing::DrawCmdListPtr>>& property)
        : property_(property ? property : std::make_shared<RSRenderProperty<Drawing::DrawCmdListPtr>>())
    {}
    ~RSDrawCmdListRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;

    // LCOV_EXCL_START
    PropertyId GetPropertyId() override
    {
        return property_->GetId();
    }
    // LCOV_EXCL_STOP

    std::shared_ptr<RSRenderPropertyBase> GetProperty() const override
    {
        return property_;
    }

    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return drawStyle_;
    }
    // LCOV_EXCL_STOP
    void SetType(RSModifierType type)
    {
        drawStyle_ = type;
        if (property_) {
            property_->SetModifierType(type);
        }
    }

    // LCOV_EXCL_START
    int16_t GetIndex() const
    {
        return index_;
    }
    // LCOV_EXCL_STOP

    void SetIndex(int16_t index)
    {
        index_ = index;
    }

    std::shared_ptr<Drawing::DrawCmdList> GetPropertyDrawCmdList() const override
    {
        return property_->Get();
    }

    void SetPropertyDrawCmdList(std::shared_ptr<Drawing::DrawCmdList> ptr) const override
    {
        return property_->Set(ptr);
    }

    // LCOV_EXCL_START
    uint64_t GetDrawCmdListId() const override
    {
        Drawing::DrawCmdListPtr drawCmd = property_->Get();
        return reinterpret_cast<uint64_t>(drawCmd.get());
    }
    // LCOV_EXCL_STOP
    void SetSingleFrameModifier(bool value) override
    {
        isSingleFrameModifier_ = value;
    }
    // LCOV_EXCL_START
    bool GetSingleFrameModifier() const override
    {
        return isSingleFrameModifier_;
    }
    // LCOV_EXCL_STOP
protected:
    RSModifierType drawStyle_ = RSModifierType::EXTENDED;
    std::shared_ptr<RSRenderProperty<Drawing::DrawCmdListPtr>> property_;
    bool isSingleFrameModifier_ = false;
    int16_t index_ = 0;
};

class RSAnimatableRenderModifier : public RSRenderModifier {
public:
    RSAnimatableRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : property_(property ? property : std::make_shared<RSRenderAnimatableProperty<float>>())
    {}

    ~RSAnimatableRenderModifier() override = default;

    // LCOV_EXCL_START
    PropertyId GetPropertyId() override
    {
        return property_->GetId();
    }
    // LCOV_EXCL_STOP

    std::shared_ptr<RSRenderPropertyBase> GetProperty() const override
    {
        return property_;
    }

protected:
    std::shared_ptr<RSRenderPropertyBase> property_;

    friend class RSRenderPropertyAnimation;
};

class RSGeometryRenderModifier : public RSAnimatableRenderModifier {
public:
    RSGeometryRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSAnimatableRenderModifier(property)
    {}

    ~RSGeometryRenderModifier() override = default;
};

class RSBackgroundRenderModifier : public RSAnimatableRenderModifier {
public:
    RSBackgroundRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSAnimatableRenderModifier(property)
    {}

    ~RSBackgroundRenderModifier() override = default;
};

class RSContentRenderModifier : public RSAnimatableRenderModifier {
public:
    RSContentRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSAnimatableRenderModifier(property)
    {}

    ~RSContentRenderModifier() override = default;
};

class RSForegroundRenderModifier : public RSAnimatableRenderModifier {
public:
    RSForegroundRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSAnimatableRenderModifier(property)
    {}

    ~RSForegroundRenderModifier() override = default;
};

class RSOverlayRenderModifier : public RSAnimatableRenderModifier {
public:
    RSOverlayRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSAnimatableRenderModifier(property)
    {}

    ~RSOverlayRenderModifier() override = default;
};

class RSAppearanceRenderModifier : public RSAnimatableRenderModifier {
public:
    RSAppearanceRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSAnimatableRenderModifier(property)
    {}

    ~RSAppearanceRenderModifier() override = default;
};

class RSB_EXPORT RSHDRBrightnessRenderModifier : public RSAnimatableRenderModifier {
public:
    RSHDRBrightnessRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSAnimatableRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::HDR_BRIGHTNESS);
    }
    ~RSHDRBrightnessRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::HDR_BRIGHTNESS;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSEnvForegroundColorRenderModifier : public RSForegroundRenderModifier {
public:
    RSEnvForegroundColorRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSForegroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::ENV_FOREGROUND_COLOR);
    }
    ~RSEnvForegroundColorRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::ENV_FOREGROUND_COLOR;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSEnvForegroundColorStrategyRenderModifier : public RSForegroundRenderModifier {
public:
    RSEnvForegroundColorStrategyRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSForegroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::ENV_FOREGROUND_COLOR_STRATEGY);
    }
    ~RSEnvForegroundColorStrategyRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::ENV_FOREGROUND_COLOR_STRATEGY;
    }
    // LCOV_EXCL_STOP
    Color GetInvertBackgroundColor(RSModifierContext& context) const;
    Color CalculateInvertColor(Color backgroundColor) const;
};

class RSB_EXPORT RSCustomClipToFrameRenderModifier : public RSForegroundRenderModifier {
public:
    RSCustomClipToFrameRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSForegroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::CUSTOM_CLIP_TO_FRAME);
    }
    ~RSCustomClipToFrameRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::CUSTOM_CLIP_TO_FRAME;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSBehindWindowFilterRadiusRenderModifier : public RSBackgroundRenderModifier {
public:
    RSBehindWindowFilterRadiusRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSBackgroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::BEHIND_WINDOW_FILTER_RADIUS);
    }
    ~RSBehindWindowFilterRadiusRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override {}
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::BEHIND_WINDOW_FILTER_RADIUS;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSBehindWindowFilterSaturationRenderModifier : public RSBackgroundRenderModifier {
public:
    RSBehindWindowFilterSaturationRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSBackgroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::BEHIND_WINDOW_FILTER_SATURATION);
    }
    ~RSBehindWindowFilterSaturationRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override {}
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::BEHIND_WINDOW_FILTER_SATURATION;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSBehindWindowFilterBrightnessRenderModifier : public RSBackgroundRenderModifier {
public:
    RSBehindWindowFilterBrightnessRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSBackgroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::BEHIND_WINDOW_FILTER_BRIGHTNESS);
    }
    ~RSBehindWindowFilterBrightnessRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override {}
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::BEHIND_WINDOW_FILTER_BRIGHTNESS;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSBehindWindowFilterMaskColorRenderModifier : public RSBackgroundRenderModifier {
public:
    RSBehindWindowFilterMaskColorRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSBackgroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::BEHIND_WINDOW_FILTER_MASK_COLOR);
    }
    ~RSBehindWindowFilterMaskColorRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override {}
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::BEHIND_WINDOW_FILTER_MASK_COLOR;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSComplexShaderParamRenderModifier : public RSBackgroundRenderModifier {
public:
    RSComplexShaderParamRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSBackgroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::COMPLEX_SHADER_PARAM);
    }
    ~RSComplexShaderParamRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::COMPLEX_SHADER_PARAM;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSForegroundNGFilterRenderModifier : public RSForegroundRenderModifier {
public:
    RSForegroundNGFilterRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSForegroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::FOREGROUND_NG_FILTER);
    }
    ~RSForegroundNGFilterRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::FOREGROUND_NG_FILTER;
    }
    // LCOV_EXCL_STOP
};

class RSB_EXPORT RSBackgroundNGFilterRenderModifier : public RSBackgroundRenderModifier {
public:
    RSBackgroundNGFilterRenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)
        : RSBackgroundRenderModifier(property)
    {
        property->SetModifierType(RSModifierType::BACKGROUND_NG_FILTER);
    }
    ~RSBackgroundNGFilterRenderModifier() override = default;
    void Apply(RSModifierContext& context) const override;
    void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;
    bool Marshalling(Parcel& parcel) override;
    // LCOV_EXCL_START
    RSModifierType GetType() override
    {
        return RSModifierType::BACKGROUND_NG_FILTER;
    }
    // LCOV_EXCL_STOP
};

// declare RenderModifiers like RSBoundsRenderModifier
#define DECLARE_ANIMATABLE_MODIFIER(MODIFIER_NAME, TYPE, MODIFIER_TYPE, DELTA_OP, MODIFIER_TIER, THRESHOLD_TYPE) \
    class RSB_EXPORT RS##MODIFIER_NAME##RenderModifier : public RS##MODIFIER_TIER##RenderModifier {              \
    public:                                                                                                      \
        RS##MODIFIER_NAME##RenderModifier(const std::shared_ptr<RSRenderPropertyBase>& property)                 \
            : RS##MODIFIER_TIER##RenderModifier(property)                                                        \
        {                                                                                                        \
            property->SetModifierType(RSModifierType::MODIFIER_TYPE);                                            \
        }                                                                                                        \
        virtual ~RS##MODIFIER_NAME##RenderModifier() = default;                                                  \
        void Apply(RSModifierContext& context) const override;                                                   \
        void Update(const std::shared_ptr<RSRenderPropertyBase>& prop, bool isDelta) override;                   \
        bool Marshalling(Parcel& parcel) override;                                                               \
        RSModifierType GetType() override                                                                        \
        {                                                                                                        \
            return (RSModifierType::MODIFIER_TYPE);                                                              \
        }                                                                                                        \
        virtual std::string GetModifierTypeString() override                                                     \
        {                                                                                                        \
            return #MODIFIER_NAME;                                                                               \
        }                                                                                                        \
    };

#define DECLARE_NOANIMATABLE_MODIFIER(MODIFIER_NAME, TYPE, MODIFIER_TYPE, MODIFIER_TIER) \
    DECLARE_ANIMATABLE_MODIFIER(MODIFIER_NAME, TYPE, MODIFIER_TYPE, Add, MODIFIER_TIER, ZERO)

DECLARE_NOANIMATABLE_MODIFIER(Particles, RSRenderParticleVector, PARTICLE, Foreground)

#include "modifier/rs_modifiers_def.in"

#undef DECLARE_ANIMATABLE_MODIFIER
#undef DECLARE_NOANIMATABLE_MODIFIER
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_MODIFIER_RS_RENDER_MODIFIER_H
