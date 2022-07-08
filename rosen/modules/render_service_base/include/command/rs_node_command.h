/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ROSEN_RENDER_SERVICE_BASE_COMMAND_RS_NODE_COMMAND_H
#define ROSEN_RENDER_SERVICE_BASE_COMMAND_RS_NODE_COMMAND_H

#include "command/rs_command_templates.h"
#include "pipeline/rs_render_node.h"
#include "property/rs_properties.h"

namespace OHOS {
namespace Rosen {

enum RSNodeCommandType : uint16_t {
    SET_BOUNDS,
    SET_BOUNDS_SIZE,
    SET_BOUNDS_WIDTH,
    SET_BOUNDS_HEIGHT,
    SET_BOUNDS_POSITION,
    SET_BOUNDS_POSITION_X,
    SET_BOUNDS_POSITION_Y,
    SET_FRAME,
    SET_FRAME_SIZE,
    SET_FRAME_WIDTH,
    SET_FRAME_HEIGHT,
    SET_FRAME_POSITION,
    SET_FRAME_POSITION_X,
    SET_FRAME_POSITION_Y,
    SET_POSITION_Z,
    SET_PIVOT,
    SET_PIVOT_X,
    SET_PIVOT_Y,
    SET_CORNER_RADIUS,
    SET_QUATERNION,
    SET_ROTATION,
    SET_ROTATION_X,
    SET_ROTATION_Y,
    SET_SCALE,
    SET_SCALE_X,
    SET_SCALE_Y,
    SET_TRANSLATE,
    SET_TRANSLATE_X,
    SET_TRANSLATE_Y,
    SET_TRANSLATE_Z,
    SET_ALPHA,
    SET_FG_COLOR,
    SET_BG_COLOR,
    SET_BG_SHADER,
    SET_BG_IMAGE,
    SET_BG_IMAGE_WIDTH,
    SET_BG_IMAGE_HEIGHT,
    SET_BG_IMAGE_POSITION_X,
    SET_BG_IMAGE_POSITION_Y,
    SET_BORDER_COLOR,
    SET_BORDER_WIDTH,
    SET_BORDER_STYLE,
    SET_SUBLAYER_TRANSFORM,
    SET_BG_FILTER,
    SET_FILTER,
    SET_COMPOSITING_FILTER,
    SET_FRAME_GRAVITY,
    SET_CLIP_BOUNDS,
    SET_CLIP_TO_BOUNDS,
    SET_CLIP_TO_FRAME,
    SET_VISIBLE,
    SET_SHADOW_COLOR,
    SET_SHADOW_OFFSET_X,
    SET_SHADOW_OFFSET_Y,
    SET_SHADOW_ALPHA,
    SET_SHADOW_ELEVATION,
    SET_SHADOW_RADIUS,
    SET_SHADOW_PATH,
    SET_MASK,
    SET_SURFACE_BG_COLOR,

    SET_BOUNDS_DELTA,
    SET_BOUNDS_SIZE_DELTA,
    SET_BOUNDS_WIDTH_DELTA,
    SET_BOUNDS_HEIGHT_DELTA,
    SET_BOUNDS_POSITION_DELTA,
    SET_BOUNDS_POSITION_X_DELTA,
    SET_BOUNDS_POSITION_Y_DELTA,
    SET_FRAME_DELTA,
    SET_FRAME_SIZE_DELTA,
    SET_FRAME_WIDTH_DELTA,
    SET_FRAME_HEIGHT_DELTA,
    SET_FRAME_POSITION_DELTA,
    SET_FRAME_POSITION_X_DELTA,
    SET_FRAME_POSITION_Y_DELTA,
    SET_POSITION_Z_DELTA,
    SET_PIVOT_DELTA,
    SET_PIVOT_X_DELTA,
    SET_PIVOT_Y_DELTA,
    SET_CORNER_RADIUS_DELTA,
    SET_QUATERNION_DELTA,
    SET_ROTATION_DELTA,
    SET_ROTATION_X_DELTA,
    SET_ROTATION_Y_DELTA,
    SET_SCALE_DELTA,
    SET_SCALE_X_DELTA,
    SET_SCALE_Y_DELTA,
    SET_TRANSLATE_DELTA,
    SET_TRANSLATE_X_DELTA,
    SET_TRANSLATE_Y_DELTA,
    SET_TRANSLATE_Z_DELTA,
    SET_ALPHA_DELTA,
    SET_FG_COLOR_DELTA,
    SET_BG_COLOR_DELTA,
    SET_BG_SHADER_DELTA,
    SET_BG_IMAGE_WIDTH_DELTA,
    SET_BG_IMAGE_HEIGHT_DELTA,
    SET_BG_IMAGE_POSITION_X_DELTA,
    SET_BG_IMAGE_POSITION_Y_DELTA,
    SET_BORDER_COLOR_DELTA,
    SET_BORDER_WIDTH_DELTA,
    SET_SUBLAYER_TRANSFORM_DELTA,
    SET_BG_FILTER_DELTA,
    SET_FILTER_DELTA,
    SET_COMPOSITING_FILTER_DELTA,
    SET_FRAME_GRAVITY_DELTA,
    SET_SHADOW_COLOR_DELTA,
    SET_SHADOW_OFFSET_X_DELTA,
    SET_SHADOW_OFFSET_Y_DELTA,
    SET_SHADOW_ALPHA_DELTA,
    SET_SHADOW_ELEVATION_DELTA,
    SET_SHADOW_RADIUS_DELTA,

    CLEAR_MODIFIER,
    ADD_MODIFIER,
    REMOVE_MODIFIER,

    UPDATE_MODIFIER_BOOL,
    UPDATE_MODIFIER_FLOAT,
    UPDATE_MODIFIER_INT,
    UPDATE_MODIFIER_COLOR,
    UPDATE_MODIFIER_GRAVITY,
    UPDATE_MODIFIER_MATRIX3F,
    UPDATE_MODIFIER_QUATERNION,
    UPDATE_MODIFIER_FILTER_PTR,
    UPDATE_MODIFIER_IMAGE_PTR,
    UPDATE_MODIFIER_MASK_PTR,
    UPDATE_MODIFIER_PATH_PTR,
    UPDATE_MODIFIER_SHADER_PTR,
    UPDATE_MODIFIER_VECTOR2F,
    UPDATE_MODIFIER_VECTOR4_BORDER_STYLE,
    UPDATE_MODIFIER_VECTOR4_COLOR,
    UPDATE_MODIFIER_VECTOR4F,
    UPDATE_MODIFIER_DRAW_CMD_LIST,
};

class RSRenderNodeCommandHelper {
public:
    // second parameter of SETTER is useless, should be removed
    template<typename T, auto setter>
    static void SetProperty(RSContext& context, NodeId nodeId, const T& value)
    {
        if (auto node = context.GetNodeMap().GetRenderNode<RSRenderNode>(nodeId)) {
            (node->GetMutableRenderProperties().*setter)(value);
        }
    }

    template<typename T, auto setter, auto getter>
    static void SetPropertyDelta(RSContext& context, NodeId nodeId, const T& value)
    {
        if (auto node = context.GetNodeMap().GetRenderNode<RSRenderNode>(nodeId)) {
            T newValue = (node->GetRenderProperties().*getter)() + value;
            (node->GetMutableRenderProperties().*setter)(newValue);
        }
    }
};

// declare commands like RSPropertyRenderNodeAlphaChanged and RSPropertyRenderNodeAlphaDelta
#define DECLARE_SET_COMMAND(COMMAND_NAME, SUBCOMMAND, TYPE, SETTER) \
    ADD_COMMAND(COMMAND_NAME,                                       \
        ARG(RS_NODE, SUBCOMMAND, RSRenderNodeCommandHelper::SetProperty<TYPE, &RSProperties::SETTER>, NodeId, TYPE))
#define DECLARE_DELTA_COMMAND(COMMAND_NAME, SUBCOMMAND, TYPE, SETTER, GETTER)                                        \
    ADD_COMMAND(COMMAND_NAME,                                                                                        \
        ARG(RS_NODE, SUBCOMMAND,                                                                                     \
            RSRenderNodeCommandHelper::SetPropertyDelta<TYPE, &RSProperties::SETTER, &RSProperties::GETTER>, NodeId, \
            TYPE))

#include "rs_node_command.in"

#undef DECLARE_SET_COMMAND
#undef DECLARE_DELTA_COMMAND

class RSNodeCommandHelper {
public:
    static void ClearModifiers(RSContext& context, NodeId nodeId);
    static void AddModifier(RSContext& context, NodeId nodeId, const std::shared_ptr<RSRenderModifier>& modifier);
    static void RemoveModifier(RSContext& context, NodeId nodeId, PropertyId propertyId);
    static void UpdateModifier(RSContext& context, NodeId nodeId, std::shared_ptr<RSRenderProperty> prop, bool isDelta);
};

ADD_COMMAND(RSClearModifiers, ARG(RS_NODE, CLEAR_MODIFIER, RSNodeCommandHelper::ClearModifiers, NodeId))
ADD_COMMAND(RSAddModifier,
    ARG(RS_NODE, ADD_MODIFIER, RSNodeCommandHelper::AddModifier, NodeId, std::shared_ptr<RSRenderModifier>))
ADD_COMMAND(RSRemoveModifier,
    ARG(RS_NODE, REMOVE_MODIFIER, RSNodeCommandHelper::RemoveModifier, NodeId, PropertyId))

ADD_COMMAND(RSUpdatePropertyBool,
    ARG(RS_NODE, UPDATE_MODIFIER_BOOL, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<bool>>, bool))
ADD_COMMAND(RSUpdatePropertyFloat,
    ARG(RS_NODE, UPDATE_MODIFIER_FLOAT, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<float>>, bool))
ADD_COMMAND(RSUpdatePropertyInt,
    ARG(RS_NODE, UPDATE_MODIFIER_INT, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<int>>, bool))
ADD_COMMAND(RSUpdatePropertyColor,
    ARG(RS_NODE, UPDATE_MODIFIER_COLOR, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<Color>>, bool))
ADD_COMMAND(RSUpdatePropertyGravity,
    ARG(RS_NODE, UPDATE_MODIFIER_GRAVITY, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<Gravity>>, bool))
ADD_COMMAND(RSUpdatePropertyMatrix3f,
    ARG(RS_NODE, UPDATE_MODIFIER_MATRIX3F, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<Matrix3f>>, bool))
ADD_COMMAND(RSUpdatePropertyQuaternion,
    ARG(RS_NODE, UPDATE_MODIFIER_QUATERNION, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<Quaternion>>, bool))
ADD_COMMAND(RSUpdatePropertyFilter,
    ARG(RS_NODE, UPDATE_MODIFIER_FILTER_PTR, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<std::shared_ptr<RSFilter>>>, bool))
ADD_COMMAND(RSUpdatePropertyImage,
    ARG(RS_NODE, UPDATE_MODIFIER_IMAGE_PTR, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<std::shared_ptr<RSImage>>>, bool))
ADD_COMMAND(RSUpdatePropertyMask,
    ARG(RS_NODE, UPDATE_MODIFIER_MASK_PTR, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<std::shared_ptr<RSMask>>>, bool))
ADD_COMMAND(RSUpdatePropertyPath,
    ARG(RS_NODE, UPDATE_MODIFIER_PATH_PTR, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<std::shared_ptr<RSPath>>>, bool))
ADD_COMMAND(RSUpdatePropertyShader,
    ARG(RS_NODE, UPDATE_MODIFIER_SHADER_PTR, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<std::shared_ptr<RSShader>>>, bool))
ADD_COMMAND(RSUpdatePropertyVector2f,
    ARG(RS_NODE, UPDATE_MODIFIER_VECTOR2F, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<Vector2f>>, bool))
ADD_COMMAND(RSUpdatePropertyBorderStyle,
    ARG(RS_NODE, UPDATE_MODIFIER_VECTOR4_BORDER_STYLE, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<Vector4<uint32_t>>>, bool))
ADD_COMMAND(RSUpdatePropertyVector4Color,
    ARG(RS_NODE, UPDATE_MODIFIER_VECTOR4_COLOR, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<Vector4<Color>>>, bool))
ADD_COMMAND(RSUpdatePropertyVector4f,
    ARG(RS_NODE, UPDATE_MODIFIER_VECTOR4F, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<Vector4f>>, bool))
ADD_COMMAND(RSUpdatePropertyDrawCmdList,
    ARG(RS_NODE, UPDATE_MODIFIER_DRAW_CMD_LIST, RSNodeCommandHelper::UpdateModifier,
        NodeId, std::shared_ptr<RSAnimatableRenderProperty<DrawCmdListPtr>>, bool))

} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_BASE_COMMAND_RS_NODE_COMMAND_H
