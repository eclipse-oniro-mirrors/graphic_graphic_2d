/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_TYPE_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_TYPE_H

namespace OHOS {
namespace Rosen {
enum class RSModifierType : int16_t {
    INVALID = 0,

    BOUNDS,
    BOUNDS_SIZE,
    BOUNDS_WIDTH,
    BOUNDS_HEIGHT,
    BOUNDS_POSITION,
    BOUNDS_POSITION_X,
    BOUNDS_POSITION_Y,
    FRAME,
    FRAME_SIZE,
    FRAME_WIDTH,
    FRAME_HEIGHT,
    FRAME_POSITION,
    FRAME_POSITION_X,
    FRAME_POSITION_Y,
    POSITION_Z,

    PIVOT,
    PIVOT_X,
    PIVOT_Y,
    QUATERNION,
    ROTATION,
    ROTATION_X,
    ROTATION_Y,
    SCALE,
    SCALE_X,
    SCALE_Y,
    TRANSLATE,
    TRANSLATE_X,
    TRANSLATE_Y,
    TRANSLATE_Z,
    SUBLAYER_TRANSFORM,

    CORNER_RADIUS,
    ALPHA,

    FOREGROUND_COLOR,
    BACKGROUND_COLOR,
    BACKGROUND_SHADER,
    BG_IMAGE,
    BG_IMAGE_WIDTH,
    BG_IMAGE_HEIGHT,
    BG_IMAGE_POSITION_X,
    BG_IMAGE_POSITION_Y,

    BORDER_COLOR,
    BORDER_WIDTH,
    BORDER_STYLE,

    FILTER,
    BACKGROUND_FILTER,

    FRAME_GRAVITY,

    CLIP_BOUNDS,
    CLIP_TO_BOUNDS,
    CLIP_TO_FRAME,
    VISIBLE,

    SHADOW_COLOR,
    SHADOW_OFFSET_X,
    SHADOW_OFFSET_Y,
    SHADOW_ALPHA,
    SHADOW_ELEVATION,
    SHADOW_RADIUS,
    SHADOW_PATH,
    MASK,

    CUSTOM,
    EXTENDED,
    CONTENT_STYLE,
    OVERLAY_STYLE,
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_TYPE_H
