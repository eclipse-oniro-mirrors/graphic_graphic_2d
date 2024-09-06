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

#include "foundation/graphic/graphic_2d/utils/log/rs_trace.h"
#include "rs_profiler.h"
#include "rs_profiler_json.h"
#include "rs_profiler_network.h"

#include "common/rs_obj_geometry.h"
#include "pipeline/rs_context.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_root_render_node.h"
#include "pipeline/rs_surface_handler.h"
#include "pipeline/rs_surface_render_node.h"

namespace OHOS::Rosen {

void RSProfiler::DumpNode(const RSRenderNode& node, JsonWriter& out)
{
    out.PushObject();
    DumpNodeBaseInfo(node, out);
    DumpNodeProperties(node.GetRenderProperties(), out);
    DumpNodeOptionalFlags(node, out);
    DumpNodeDrawCmdModifiers(node, out);
    DumpNodeAnimations(node.animationManager_, out);
    DumpNodeChildrenListUpdate(node, out);

    auto& children = out["children"];
    children.PushArray();
    if (node.GetSortedChildren()) {
        for (auto& child : *node.GetSortedChildren()) {
            if (child) {
                DumpNode(*child, children);
            }
        }
    }
    children.PopArray();
    out.PopObject();
}

void RSProfiler::DumpNodeBaseInfo(const RSRenderNode& node, JsonWriter& out)
{
    std::string type;
    node.DumpNodeType(node.GetType(), type);
    out["type"] = type;
    out["id"] = node.GetId();
    out["instanceRootNodeId"] = node.GetInstanceRootNodeId();
    DumpNodeSubsurfaces(node, out);
    auto sharedTrans = node.GetSharedTransitionParam();
    if (sharedTrans) {
        out["SharedTransitionParam"] =
            std::to_string(sharedTrans->inNodeId_) + " -> " + std::to_string(sharedTrans->outNodeId_);
    }
    if (node.IsSuggestedDrawInGroup()) {
        out["nodeGroup"] = static_cast<int>(node.nodeGroupType_);
    }
    if (node.GetUifirstRootNodeId() != INVALID_NODEID) {
        out["uifirstRootNodeId"] = node.GetUifirstRootNodeId();
    }
    DumpNodeSubClassNode(node, out);
}

void RSProfiler::DumpNodeSubsurfaces(const RSRenderNode& node, JsonWriter& out)
{
    if (auto surface = node.ReinterpretCastTo<RSSurfaceRenderNode>(); surface && surface->HasSubSurfaceNodes()) {
        auto& subsurface = out["subsurface"];
        subsurface.PushArray();
        for (auto [id, _] : surface->GetChildSubSurfaceNodes()) {
            subsurface.Append(id);
        }
        subsurface.PopArray();
    }
}

void RSProfiler::DumpNodeSubClassNode(const RSRenderNode& node, JsonWriter& out)
{
    auto& subclass = out["subclass"];
    subclass.PushObject();
    if (node.GetType() == RSRenderNodeType::SURFACE_NODE) {
        auto& surfaceNode = static_cast<const RSSurfaceRenderNode&>(node);
        auto p = node.parent_.lock();
        subclass["Parent"] = p ? p->GetId() : uint64_t(0);
        subclass["Name"] = surfaceNode.GetName();
        out["hasConsumer"] = surfaceNode.GetRSSurfaceHandler()->HasConsumer();
        std::string contextAlpha = std::to_string(surfaceNode.contextAlpha_);
        std::string propertyAlpha = std::to_string(surfaceNode.GetRenderProperties().GetAlpha());
        subclass["Alpha"] = propertyAlpha + " (include ContextAlpha: " + contextAlpha + ")";
        subclass["Visible"] = std::to_string(surfaceNode.GetRenderProperties().GetVisible()) + " " +
                              surfaceNode.GetVisibleRegion().GetRegionInfo();
        subclass["Opaque"] = surfaceNode.GetOpaqueRegion().GetRegionInfo();
        subclass["OcclusionBg"] = std::to_string((surfaceNode.GetAbilityBgAlpha()));
        subclass["SecurityLayer"] = surfaceNode.GetSecurityLayer();
        subclass["skipLayer"] = surfaceNode.GetSkipLayer();
    } else if (node.GetType() == RSRenderNodeType::ROOT_NODE) {
        auto& rootNode = static_cast<const RSRootRenderNode&>(node);
        subclass["Visible"] = rootNode.GetRenderProperties().GetVisible();
        subclass["Size"] = { rootNode.GetRenderProperties().GetFrameWidth(),
            rootNode.GetRenderProperties().GetFrameHeight() };
        subclass["EnableRender"] = rootNode.GetEnableRender();
    } else if (node.GetType() == RSRenderNodeType::DISPLAY_NODE) {
        auto& displayNode = static_cast<const RSDisplayRenderNode&>(node);
        subclass["skipLayer"] = displayNode.GetSecurityDisplay();
    }
    subclass.PopObject();
}

void RSProfiler::DumpNodeOptionalFlags(const RSRenderNode& node, JsonWriter& out)
{
    if (node.GetBootAnimation()) {
        out["GetBootAnimation"] = true;
    }
    if (node.isContainBootAnimation_) {
        out["isContainBootAnimation_"] = true;
    }
    if (node.dirtyStatus_ != RSRenderNode::NodeDirty::CLEAN) {
        out["isNodeDirty"] = static_cast<int>(node.dirtyStatus_);
    }
    if (node.GetRenderProperties().IsDirty()) {
        out["isPropertyDirty"] = true;
    }
    if (node.isSubTreeDirty_) {
        out["isSubTreeDirty"] = true;
    }
    if (node.IsPureContainer()) {
        out["IsPureContainer"] = true;
    }
}

void RSProfiler::DumpNodeDrawCmdModifiers(const RSRenderNode& node, JsonWriter& out)
{
    if (!node.renderContent_) {
        return;
    }

    auto& modifiersJson = out["DrawCmdModifiers"];
    modifiersJson.PushArray();
    for (auto& [type, modifiers] : node.renderContent_->drawCmdModifiers_) {
        modifiersJson.PushObject();
        modifiersJson["type"] = static_cast<int>(type);
        auto& modifierDesc = modifiersJson["modifiers"];
        modifierDesc.PushArray();
        for (const auto& modifier : modifiers) {
            if (modifier) {
                DumpNodeDrawCmdModifier(node, modifierDesc, static_cast<int>(type), *modifier);
            }
        }
        modifiersJson.PopArray();
        modifiersJson.PopObject();
    }
    modifiersJson.PopArray();
}

static std::string Hex(uint32_t value)
{
    std::stringstream sstream;
    sstream << std::hex << value;
    return sstream.str();
}

void RSProfiler::DumpNodeDrawCmdModifier(
    const RSRenderNode& node, JsonWriter& out, int type, RSRenderModifier& modifier)
{
    auto modType = static_cast<RSModifierType>(type);

    if (modType < RSModifierType::ENV_FOREGROUND_COLOR) {
        auto propertyPtr = std::static_pointer_cast<RSRenderProperty<Drawing::DrawCmdListPtr>>(modifier.GetProperty());
        auto drawCmdListPtr = propertyPtr ? propertyPtr->Get() : nullptr;
        auto propertyStr = drawCmdListPtr ? drawCmdListPtr->GetOpsWithDesc() : "";
        size_t pos = 0;
        size_t oldpos = 0;

        out.PushObject();
        auto& property = out["drawCmdList"];
        property.PushArray();
        while ((pos = propertyStr.find('\n', oldpos)) != std::string::npos) {
            property.Append(propertyStr.substr(oldpos, pos - oldpos));
            oldpos = pos + 1;
        }
        property.PopArray();
        out.PopObject();
    } else if (modType == RSModifierType::ENV_FOREGROUND_COLOR) {
        auto propertyPtr = std::static_pointer_cast<RSRenderAnimatableProperty<Color>>(modifier.GetProperty());
        if (propertyPtr) {
            out.PushObject();
            out["ENV_FOREGROUND_COLOR"] = "#" + Hex(propertyPtr->Get().AsRgbaInt()) + " (RGBA)";
            out.PopObject();
        }
    } else if (modType == RSModifierType::ENV_FOREGROUND_COLOR_STRATEGY) {
        auto propertyPtr =
            std::static_pointer_cast<RSRenderProperty<ForegroundColorStrategyType>>(modifier.GetProperty());
        if (propertyPtr) {
            out.PushObject();
            out["ENV_FOREGROUND_COLOR_STRATEGY"] = static_cast<int>(propertyPtr->Get());
            out.PopObject();
        }
    } else if (modType == RSModifierType::GEOMETRYTRANS) {
        auto propertyPtr = std::static_pointer_cast<RSRenderProperty<SkMatrix>>(modifier.GetProperty());
        if (propertyPtr) {
            std::string str;
            propertyPtr->Get().dump(str, 0);
            out.PushObject();
            out["GEOMETRYTRANS"] = str;
            out.PopObject();
        }
    }
}

void RSProfiler::DumpNodeProperties(const RSProperties& properties, JsonWriter& out)
{
    auto& json = out["Properties"];
    json.PushObject();
    json["Bounds"] = { properties.GetBoundsPositionX(), properties.GetBoundsPositionY(), properties.GetBoundsWidth(),
        properties.GetBoundsHeight() };
    json["Frame"] = { properties.GetFramePositionX(), properties.GetFramePositionY(), properties.GetFrameWidth(),
        properties.GetFrameHeight() };

    if (!properties.GetVisible()) {
        json["IsVisible"] = false;
    }
    DumpNodePropertiesClip(properties, json);
    DumpNodePropertiesTransform(properties, json);
    DumpNodePropertiesDecoration(properties, json);
    DumpNodePropertiesShadow(properties, json);
    DumpNodePropertiesEffects(properties, json);
    DumpNodePropertiesColor(properties, json);
    json.PopObject();
}

void RSProfiler::DumpNodePropertiesClip(const RSProperties& properties, JsonWriter& out)
{
    if (properties.clipToBounds_) {
        out["ClipToBounds"] = true;
    }
    if (properties.clipToFrame_) {
        out["ClipToFrame"] = true;
    }
}

void RSProfiler::DumpNodePropertiesTransform(const RSProperties& properties, JsonWriter& out)
{
    if (!ROSEN_EQ(properties.GetPositionZ(), 0.f)) {
        out["PositionZ"] = properties.GetPositionZ();
    }
    Transform defaultTransform;
    Vector2f pivot = properties.GetPivot();
    if ((!ROSEN_EQ(pivot[0], defaultTransform.pivotX_) || !ROSEN_EQ(pivot[1], defaultTransform.pivotY_))) {
        out["Pivot"] = { pivot[0], pivot[1] };
    }
    if (!ROSEN_EQ(properties.GetRotation(), defaultTransform.rotation_)) {
        out["Rotation"] = properties.GetRotation();
    }
    if (!ROSEN_EQ(properties.GetRotationX(), defaultTransform.rotationX_)) {
        out["RotationX"] = properties.GetRotationX();
    }
    if (!ROSEN_EQ(properties.GetRotationY(), defaultTransform.rotationY_)) {
        out["RotationY"] = properties.GetRotationY();
    }
    if (!ROSEN_EQ(properties.GetTranslateX(), defaultTransform.translateX_)) {
        out["TranslateX"] = properties.GetTranslateX();
    }
    if (!ROSEN_EQ(properties.GetTranslateY(), defaultTransform.translateY_)) {
        out["TranslateY"] = properties.GetTranslateY();
    }
    if (!ROSEN_EQ(properties.GetTranslateZ(), defaultTransform.translateZ_)) {
        out["TranslateZ"] = properties.GetTranslateZ();
    }
    if (!ROSEN_EQ(properties.GetScaleX(), defaultTransform.scaleX_)) {
        out["ScaleX"] = properties.GetScaleX();
    }
    if (!ROSEN_EQ(properties.GetScaleY(), defaultTransform.scaleY_)) {
        out["ScaleY"] = properties.GetScaleY();
    }
}

void RSProfiler::DumpNodePropertiesDecoration(const RSProperties& properties, JsonWriter& out)
{
    if (!properties.GetCornerRadius().IsZero()) {
        out["CornerRadius"] = { properties.GetCornerRadius().x_, properties.GetCornerRadius().y_,
            properties.GetCornerRadius().z_, properties.GetCornerRadius().w_ };
    }
    if (properties.pixelStretch_.has_value()) {
        auto& pixelStretch = out["PixelStretch"];
        pixelStretch.PushObject();
        pixelStretch["left"] = properties.pixelStretch_->z_;
        pixelStretch["top"] = properties.pixelStretch_->y_;
        pixelStretch["right"] = properties.pixelStretch_->z_;
        pixelStretch["bottom"] = properties.pixelStretch_->w_;
        pixelStretch.PopObject();
    }
    if (!ROSEN_EQ(properties.GetAlpha(), 1.f)) {
        out["Alpha"] = properties.GetAlpha();
    }
    if (!ROSEN_EQ(properties.GetSpherize(), 0.f)) {
        out["Spherize"] = properties.GetSpherize();
    }
    if (!ROSEN_EQ(properties.GetAttractionFraction(), 0.f)) {
        out["AttractFraction"] = properties.GetAttractionFraction();
    }
    Vector2f attractionDstpoint = properties.GetAttractionDstPoint();
    if ((!ROSEN_EQ(attractionDstpoint[0], 0.f) || !ROSEN_EQ(attractionDstpoint[1], 0.f))) {
        out["AttractionDstPoint"] = { attractionDstpoint[0], attractionDstpoint[1] };
    }
    
    if (!ROSEN_EQ(properties.GetForegroundColor(), RgbPalette::Transparent())) {
        out["ForegroundColor"] = "#" + Hex(properties.GetForegroundColor().AsArgbInt()) + " (ARGB)";
    }
    if (!ROSEN_EQ(properties.GetBackgroundColor(), RgbPalette::Transparent())) {
        out["BackgroundColor"] = "#" + Hex(properties.GetBackgroundColor().AsArgbInt()) + " (ARGB)";
    }
    Decoration defaultDecoration;
    if ((!ROSEN_EQ(properties.GetBgImagePositionX(), defaultDecoration.bgImageRect_.left_) ||
        !ROSEN_EQ(properties.GetBgImagePositionY(), defaultDecoration.bgImageRect_.top_) ||
        !ROSEN_EQ(properties.GetBgImageWidth(), defaultDecoration.bgImageRect_.width_) ||
        !ROSEN_EQ(properties.GetBgImageHeight(), defaultDecoration.bgImageRect_.height_))) {
        out["BgImage"] = { properties.GetBgImagePositionX(), properties.GetBgImagePositionY(),
            properties.GetBgImageWidth(), properties.GetBgImageHeight() };
    }
}

void RSProfiler::DumpNodePropertiesShadow(const RSProperties& properties, JsonWriter& out)
{
    if (!ROSEN_EQ(properties.GetShadowColor(), Color(DEFAULT_SPOT_COLOR))) {
        out["ShadowColor"] = "#" + Hex(properties.GetShadowColor().AsArgbInt()) + " (ARGB)";
    }
    if (!ROSEN_EQ(properties.GetShadowOffsetX(), DEFAULT_SHADOW_OFFSET_X)) {
        out["ShadowOffsetX"] = properties.GetShadowOffsetX();
    }
    if (!ROSEN_EQ(properties.GetShadowOffsetY(), DEFAULT_SHADOW_OFFSET_Y)) {
        out["ShadowOffsetY"] = properties.GetShadowOffsetY();
    }
    if (!ROSEN_EQ(properties.GetShadowAlpha(), 0.f)) {
        out["ShadowAlpha"] = properties.GetShadowAlpha();
    }
    if (!ROSEN_EQ(properties.GetShadowElevation(), 0.f)) {
        out["ShadowElevation"] = properties.GetShadowElevation();
    }
    if (!ROSEN_EQ(properties.GetShadowRadius(), 0.f)) {
        out["ShadowRadius"] = properties.GetShadowRadius();
    }
    if (!ROSEN_EQ(properties.GetShadowIsFilled(), false)) {
        out["ShadowIsFilled"] = properties.GetShadowIsFilled();
    }
}

void RSProfiler::DumpNodePropertiesEffects(const RSProperties& properties, JsonWriter& out)
{
    if (properties.border_ && properties.border_->HasBorder()) {
        out["Border"] = properties.border_->ToString();
    }
    auto filter = properties.GetFilter();
    if (filter && filter->IsValid()) {
        out["Filter"] = filter->GetDescription();
    }
    auto backgroundFilter = properties.GetBackgroundFilter();
    if (backgroundFilter && backgroundFilter->IsValid()) {
        out["BackgroundFilter"] = backgroundFilter->GetDescription();
    }
    auto foregroundFilterCache = properties.GetForegroundFilterCache();
    if (foregroundFilterCache && foregroundFilterCache->IsValid()) {
        out["ForegroundFilter"] = foregroundFilterCache->GetDescription();
    }
    if (properties.outline_ && properties.outline_->HasBorder()) {
        out["Outline"] = properties.outline_->ToString();
    }
    if (!ROSEN_EQ(properties.GetFrameGravity(), Gravity::DEFAULT)) {
        out["FrameGravity"] = static_cast<int>(properties.GetFrameGravity());
    }
    if (properties.GetUseEffect()) {
        out["GetUseEffect"] = true;
    }
    auto grayScale = properties.GetGrayScale();
    if (grayScale.has_value() && !ROSEN_EQ(*grayScale, 0.f)) {
        out["GrayScale"] = *grayScale;
    }
    if (!ROSEN_EQ(properties.GetLightUpEffect(), 1.f)) {
        out["LightUpEffect"] = properties.GetLightUpEffect();
    }
    auto dynamicLightUpRate = properties.GetDynamicLightUpRate();
    if (dynamicLightUpRate.has_value() && !ROSEN_EQ(*dynamicLightUpRate, 0.f)) {
        out["DynamicLightUpRate"] = *dynamicLightUpRate;
    }
    auto dynamicLightUpDegree = properties.GetDynamicLightUpDegree();
    if (dynamicLightUpDegree.has_value() && !ROSEN_EQ(*dynamicLightUpDegree, 0.f)) {
        out["DynamicLightUpDegree"] = *dynamicLightUpDegree;
    }
}

void RSProfiler::DumpNodePropertiesColor(const RSProperties& properties, JsonWriter& out)
{
    auto brightness = properties.GetBrightness();
    if (brightness.has_value() && !ROSEN_EQ(*brightness, 1.f)) {
        out["Brightness"] = *brightness;
    }
    auto contrast = properties.GetContrast();
    if (contrast.has_value() && !ROSEN_EQ(*contrast, 1.f)) {
        out["Contrast"] = *contrast;
    }
    auto saturate = properties.GetSaturate();
    if (saturate.has_value() && !ROSEN_EQ(*saturate, 1.f)) {
        out["Saturate"] = *saturate;
    }
    auto sepia = properties.GetSepia();
    if (sepia.has_value() && !ROSEN_EQ(*sepia, 0.f)) {
        out["Sepia"] = *sepia;
    }
    auto invert = properties.GetInvert();
    if (invert.has_value() && !ROSEN_EQ(*invert, 0.f)) {
        out["Invert"] = *invert;
    }
    auto hueRotate = properties.GetHueRotate();
    if (hueRotate.has_value() && !ROSEN_EQ(*hueRotate, 0.f)) {
        out["HueRotate"] = *hueRotate;
    }
    auto colorBlend = properties.GetColorBlend();
    if (colorBlend.has_value() && !ROSEN_EQ(*colorBlend, RgbPalette::Transparent())) {
        out["ColorBlend"] = "#" + Hex(colorBlend->AsArgbInt()) + " (ARGB)";
    }
    if (!ROSEN_EQ(properties.GetColorBlendMode(), 0)) {
        out["skblendmode"] = properties.GetColorBlendMode() - 1;
        out["blendType"] = properties.GetColorBlendApplyType();
    }
}

void RSProfiler::DumpNodeAnimations(const RSAnimationManager& animationManager, JsonWriter& out)
{
    if (animationManager.animations_.empty()) {
        return;
    }
    auto& animations = out["RSAnimationManager"];
    animations.PushArray();
    for (auto [id, animation] : animationManager.animations_) {
        if (animation) {
            DumpNodeAnimation(*animation, animations);
        }
    }
    animations.PopArray();
}

void RSProfiler::DumpNodeAnimation(const RSRenderAnimation& animation, JsonWriter& out)
{
    out.PushObject();
    out["id"] = animation.id_;
    std::string type;
    animation.DumpAnimationType(type);
    out["type"] = type;
    out["AnimationState"] = static_cast<int>(animation.state_);
    out["StartDelay"] = animation.animationFraction_.GetDuration();
    out["Duration"] = animation.animationFraction_.GetStartDelay();
    out["Speed"] = animation.animationFraction_.GetSpeed();
    out["RepeatCount"] = animation.animationFraction_.GetRepeatCount();
    out["AutoReverse"] = animation.animationFraction_.GetAutoReverse();
    out["Direction"] = animation.animationFraction_.GetDirection();
    out["FillMode"] = static_cast<int>(animation.animationFraction_.GetFillMode());
    out["RepeatCallbackEnable"] = animation.animationFraction_.GetRepeatCallbackEnable();
    out["FrameRateRange_min"] = animation.animationFraction_.GetFrameRateRange().min_;
    out["FrameRateRange_max"] = animation.animationFraction_.GetFrameRateRange().max_;
    out["FrameRateRange_prefered"] = animation.animationFraction_.GetFrameRateRange().preferred_;
    out.PopObject();
}

void RSProfiler::DumpNodeChildrenListUpdate(const RSRenderNode& node, JsonWriter& out)
{
    if (!node.isFullChildrenListValid_) {
        auto& childrenUpdate = out["children update"];
        childrenUpdate.PushObject();
        childrenUpdate["current count"] = node.fullChildrenList_->size();
        std::string expected = std::to_string(node.GetSortedChildren()->size());
        if (!node.disappearingChildren_.empty()) {
            childrenUpdate["disappearing count"] = node.disappearingChildren_.size();
            expected += " + " + std::to_string(node.disappearingChildren_.size());
        }
        childrenUpdate["expected count"] = expected;
        childrenUpdate.PopObject();
    }
}

} // namespace OHOS::Rosen