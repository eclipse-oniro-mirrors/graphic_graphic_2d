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

#ifndef RENDER_SERVICE_CLIENT_CORE_MODIFIER_NG_RS_MODIFIER_NG_H
#define RENDER_SERVICE_CLIENT_CORE_MODIFIER_NG_RS_MODIFIER_NG_H

#include <map>
#include <memory>

#include "common/rs_common_def.h"
#include "common/rs_macros.h"
#include "modifier/rs_property.h"
#include "modifier_ng/rs_modifier_ng_type.h"

namespace OHOS::Rosen {
class RSNode;

namespace ModifierNG {
class RSRenderModifier;

class RSC_EXPORT RSModifier : public std::enable_shared_from_this<RSModifier> {
public:
    ModifierId GetId() const
    {
        return id_;
    }

    void OnAttach(RSNode& node);
    void OnDetach();

    void AttachProperty(ModifierNG::RSPropertyType type, std::shared_ptr<RSPropertyBase> property);
    void DetachProperty(ModifierNG::RSPropertyType type);

    void SetDirty(bool isDirty);

    virtual RSModifierType GetType() const = 0;

    std::shared_ptr<RSPropertyBase> GetProperty(RSPropertyType type)
    {
        auto it = properties_.find(type);
        if (it == properties_.end()) {
            return nullptr;
        }
        return it->second;
    }

protected:
    RSModifier() = default;
    virtual ~RSModifier() = default;

    // only accept properties on white list ?
    std::map<RSPropertyType, std::shared_ptr<RSPropertyBase>> properties_;
    ModifierId id_;
    std::weak_ptr<RSNode> node_;

    virtual std::shared_ptr<RSRenderModifier> CreateRenderModifier();
    virtual void UpdateToRender() {}

    template<typename T>
    inline T Getter(RSPropertyType type, const T& defaultValue) const
    {
        auto it = properties_.find(type);
        if (it == properties_.end()) {
            return defaultValue;
        }
        auto property = std::static_pointer_cast<RSProperty<T>>(it->second);
        return property->Get();
    }

    template<template<typename> class PropertyType = RSAnimatableProperty, typename T>
    inline void Setter(RSPropertyType type, const T& value)
    {
        auto it = properties_.find(type);
        if (it != properties_.end()) {
            auto property = std::static_pointer_cast<PropertyType<T>>(it->second);
            property->Set(value);
        } else {
            std::shared_ptr<RSPropertyBase> property = std::make_shared<PropertyType<T>>(value);
            AttachProperty(type, property);
        }
    }

    template<typename T>
    inline std::optional<T> GetterOptional(RSPropertyType type) const
    {
        auto it = properties_.find(type);
        if (it == properties_.end()) {
            return std::nullopt;
        }
        auto property = std::static_pointer_cast<RSProperty<T>>(it->second);
        return property->Get();
    }

    template<template<typename> class PropertyType = RSProperty, typename T>
    inline void SetterOptional(RSPropertyType type, const std::optional<T>& value)
    {
        if (!value.has_value()) {
            DetachProperty(type);
            return;
        }
        auto it = properties_.find(type);
        if (it != properties_.end()) {
            auto property = std::static_pointer_cast<PropertyType<T>>(it->second);
            property->Set(value.value());
        } else {
            std::shared_ptr<RSPropertyBase> property = std::make_shared<PropertyType<T>>(value.value());
            AttachProperty(type, property);
        }
    }

    // TODO: used in the original code, but do we need this?
    std::string GetModifierTypeString() const
    {
        return RSModifierTypeString::GetModifierTypeString(GetType());
    }

    using Constructor = std::function<RSModifier*()>;

private:
    static std::array<Constructor, ModifierNG::MODIFIER_TYPE_COUNT> ConstructorLUT_;

    friend class OHOS::Rosen::RSNode;
};
} // namespace ModifierNG
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_CLIENT_CORE_MODIFIER_NG_RS_MODIFIER_NG_H
