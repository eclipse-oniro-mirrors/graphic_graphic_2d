/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef ROSEN_RENDER_SERVICE_BASE_COMMAND_RS_SURFACE_NODE_COMMAND_H
#define ROSEN_RENDER_SERVICE_BASE_COMMAND_RS_SURFACE_NODE_COMMAND_H

#include "command/rs_command_templates.h"
#include "common/rs_macros.h"
#include "common/rs_vector4.h"
#include "platform/common/rs_surface_ext.h"
#include "surface_type.h"

#include "utils/matrix.h"
#include "utils/rect.h"

namespace OHOS {
namespace Rosen {

enum RSSurfaceNodeCommandType : uint16_t {
    SURFACE_NODE_CREATE,
    SURFACE_NODE_CREATE_WITH_CONFIG,
    SURFACE_NODE_SET_CONTEXT_MATRIX,
    SURFACE_NODE_SET_CONTEXT_ALPHA,
    SURFACE_NODE_SET_CONTEXT_CLIP_REGION,
    SURFACE_NODE_SET_SECURITY_LAYER,
    SURFACE_NODE_SET_SKIP_LAYER,
    SURFACE_NODE_SET_FINGERPRINT,
    SURFACE_NODE_SET_COLOR_SPACE,
    SURFACE_NODE_UPDATE_SURFACE_SIZE,
    SURFACE_NODE_CONNECT_TO_NODE_IN_RENDER_SERVICE,
    SURFACE_NODE_SET_CALLBACK_FOR_RENDER_THREAD,
    SURFACE_NODE_SET_CONTEXT_BOUNDS,
    SURFACE_NODE_SET_ABILITY_BG_ALPHA,
    SURFACE_NODE_SET_IS_NOTIFY_BUFFER_AVAILABLE,
    SURFACE_NODE_SET_SURFACE_NODE_TYPE,
    SURFACE_NODE_SET_CONTAINER_WINDOW,
    SURFACE_NODE_SET_ANIMATION_FINISHED,
    SURFACE_NODE_MARK_UIHIDDEN,
    SURFACE_NODE_SET_IS_TEXTURE_EXPORT_NODE,
    SURFACE_NODE_ATTACH_TO_DISPLAY,
    SURFACE_NODE_DETACH_TO_DISPLAY,
    SURFACE_NODE_SET_FORCE_HARDWARE_AND_FIX_ROTATION,
    SURFACE_NODE_SET_BOOT_ANIMATION,
    SURFACE_NODE_CREATE_SURFACE_EXT,
    SURFACE_NODE_SET_FOREGROUND,
    SURFACE_NODE_SET_SURFACE_ID,
    SURFACE_NODE_SET_FORCE_UIFIRST,
    SURFACE_NODE_SET_ANCO_FLAGS,
    SURFACE_NODE_SET_HDR_PRESENT,
    SURFACE_NODE_SET_SKIP_DRAW,
    SURFACE_NODE_SET_WATERMARK,
    SURFACE_NODE_SET_WATERMARK_ENABLED,
    SURFACE_NODE_SET_LAYER_TOP,
};

class RSB_EXPORT SurfaceNodeCommandHelper {
public:
    static void Create(RSContext& context, NodeId nodeId,
        RSSurfaceNodeType surfaceNodeType = RSSurfaceNodeType::DEFAULT, bool isTextureExportNode = false);
    static void CreateWithConfig(
        RSContext& context, NodeId nodeId, std::string name, uint8_t type, enum SurfaceWindowType surfaceWindowType);
    static std::shared_ptr<RSSurfaceRenderNode> CreateWithConfigInRS(
        const RSSurfaceRenderNodeConfig& config, RSContext& context);
    static void SetContextMatrix(RSContext& context, NodeId nodeId, const std::optional<Drawing::Matrix>& matrix);
    static void SetContextAlpha(RSContext& context, NodeId nodeId, float alpha);
    static void SetContextClipRegion(RSContext& context, NodeId nodeId, const std::optional<Drawing::Rect>& clipRect);
    static void SetSecurityLayer(RSContext& context, NodeId nodeId, bool isSecurityLayer);
    static void SetSkipLayer(RSContext& context, NodeId nodeId, bool isSkipLayer);
    static void SetFingerprint(RSContext& context, NodeId nodeId, bool hasFingerprint);
    static void SetColorSpace(RSContext& context, NodeId nodeId, GraphicColorGamut colorSpace);
    static void UpdateSurfaceDefaultSize(RSContext& context, NodeId nodeId, float width, float height);
    static void ConnectToNodeInRenderService(RSContext& context, NodeId id);
    static void SetCallbackForRenderThreadRefresh(RSContext& context, NodeId id, bool isRefresh);
    static void SetContextBounds(RSContext& context, NodeId id, Vector4f bounds);
    static void SetIsTextureExportNode(RSContext& context, NodeId id, bool isTextureExportNode);
    static void SetAbilityBGAlpha(RSContext& context, NodeId id, uint8_t alpha);
    static void SetIsNotifyUIBufferAvailable(RSContext& context, NodeId nodeId, bool available);
    static void MarkUIHidden(RSContext& context, NodeId nodeId, bool isHidden);
    static void SetLayerTop(RSContext& context, NodeId nodeId, std::string nodeIdStr, bool isTop);
    static void SetSurfaceNodeType(RSContext& context, NodeId nodeId, uint8_t surfaceNodeType);
    static void SetContainerWindow(RSContext& context, NodeId nodeId, bool hasContainerWindow, float density);
    static void SetAnimationFinished(RSContext& context, NodeId nodeId);
    static void AttachToDisplay(RSContext& context, NodeId nodeId, uint64_t screenId);
    static void DetachToDisplay(RSContext& context, NodeId nodeId, uint64_t screenId);
    static void SetBootAnimation(RSContext& context, NodeId nodeId, bool isBootAnimation);
    static void SetForceHardwareAndFixRotation(RSContext& context, NodeId nodeId, bool flag);
#ifdef USE_SURFACE_TEXTURE
    static void CreateSurfaceExt(RSContext& context, NodeId id, const std::shared_ptr<RSSurfaceTexture>& surfaceExt);
#endif
    static void SetForeground(RSContext& context, NodeId nodeId, bool isForeground);
    static void SetSurfaceId(RSContext& context, NodeId nodeId, SurfaceId surfaceId);
    static void SetForceUIFirst(RSContext& context, NodeId nodeId, bool forceUIFirst);
    static void SetAncoFlags(RSContext& context, NodeId nodeId, uint32_t flags);
    static void SetHDRPresent(RSContext& context, NodeId nodeId, bool hdrPresent);
    static void SetSkipDraw(RSContext& context, NodeId nodeId, bool skip);
    static void SetWatermark(RSContext& context, NodeId nodeId, const std::string& name,
            std::shared_ptr<Media::PixelMap> watermark);
    static void SetWatermarkEnabled(RSContext& context, NodeId nodeId, const std::string& name, bool isEnabled);
};

ADD_COMMAND(RSSurfaceNodeCreate,
    ARG(SURFACE_NODE, SURFACE_NODE_CREATE, SurfaceNodeCommandHelper::Create, NodeId, RSSurfaceNodeType, bool))
ADD_COMMAND(RSSurfaceNodeCreateWithConfig,
    ARG(SURFACE_NODE, SURFACE_NODE_CREATE_WITH_CONFIG, SurfaceNodeCommandHelper::CreateWithConfig, NodeId, std::string,
        uint8_t, enum SurfaceWindowType))
ADD_COMMAND(RSSurfaceNodeSetContextMatrix, ARG(SURFACE_NODE, SURFACE_NODE_SET_CONTEXT_MATRIX,
    SurfaceNodeCommandHelper::SetContextMatrix, NodeId, std::optional<Drawing::Matrix>))
ADD_COMMAND(RSSurfaceNodeSetContextAlpha,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_CONTEXT_ALPHA, SurfaceNodeCommandHelper::SetContextAlpha, NodeId, float))
ADD_COMMAND(RSSurfaceNodeSetContextClipRegion, ARG(SURFACE_NODE, SURFACE_NODE_SET_CONTEXT_CLIP_REGION,
    SurfaceNodeCommandHelper::SetContextClipRegion, NodeId, std::optional<Drawing::Rect>))
ADD_COMMAND(RSSurfaceNodeSetHardwareAndFixRotation, ARG(SURFACE_NODE, SURFACE_NODE_SET_FORCE_HARDWARE_AND_FIX_ROTATION,
    SurfaceNodeCommandHelper::SetForceHardwareAndFixRotation, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetBootAnimation,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_BOOT_ANIMATION, SurfaceNodeCommandHelper::SetBootAnimation, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetSecurityLayer,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_SECURITY_LAYER, SurfaceNodeCommandHelper::SetSecurityLayer, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetSkipLayer,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_SKIP_LAYER, SurfaceNodeCommandHelper::SetSkipLayer, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetFingerprint,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_FINGERPRINT, SurfaceNodeCommandHelper::SetFingerprint, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeUpdateSurfaceDefaultSize, ARG(SURFACE_NODE, SURFACE_NODE_UPDATE_SURFACE_SIZE,
    SurfaceNodeCommandHelper::UpdateSurfaceDefaultSize, NodeId, float, float))
ADD_COMMAND(RSSurfaceNodeConnectToNodeInRenderService,
    ARG(SURFACE_NODE, SURFACE_NODE_CONNECT_TO_NODE_IN_RENDER_SERVICE,
    SurfaceNodeCommandHelper::ConnectToNodeInRenderService, NodeId))
ADD_COMMAND(RSSurfaceNodeSetCallbackForRenderThreadRefresh,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_CALLBACK_FOR_RENDER_THREAD,
    SurfaceNodeCommandHelper::SetCallbackForRenderThreadRefresh, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetBounds,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_CONTEXT_BOUNDS, SurfaceNodeCommandHelper::SetContextBounds, NodeId, Vector4f))
ADD_COMMAND(RSSurfaceNodeSetAbilityBGAlpha,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_ABILITY_BG_ALPHA, SurfaceNodeCommandHelper::SetAbilityBGAlpha, NodeId, uint8_t))
ADD_COMMAND(RSSurfaceNodeSetIsNotifyUIBufferAvailable,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_IS_NOTIFY_BUFFER_AVAILABLE,
    SurfaceNodeCommandHelper::SetIsNotifyUIBufferAvailable, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeMarkUIHidden,
    ARG(SURFACE_NODE, SURFACE_NODE_MARK_UIHIDDEN, SurfaceNodeCommandHelper::MarkUIHidden, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetIsTextureExportNode,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_IS_TEXTURE_EXPORT_NODE,
    SurfaceNodeCommandHelper::SetIsTextureExportNode, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetSurfaceNodeType,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_SURFACE_NODE_TYPE,
    SurfaceNodeCommandHelper::SetSurfaceNodeType, NodeId, uint8_t))
ADD_COMMAND(RSSurfaceNodeSetContainerWindow,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_CONTAINER_WINDOW, SurfaceNodeCommandHelper::SetContainerWindow,
    NodeId, bool, float))
ADD_COMMAND(RSSurfaceNodeSetAnimationFinished,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_ANIMATION_FINISHED, SurfaceNodeCommandHelper::SetAnimationFinished, NodeId))
ADD_COMMAND(RSSurfaceNodeAttachToDisplay,
    ARG(SURFACE_NODE, SURFACE_NODE_ATTACH_TO_DISPLAY, SurfaceNodeCommandHelper::AttachToDisplay, NodeId, uint64_t))
ADD_COMMAND(RSSurfaceNodeDetachToDisplay,
    ARG(SURFACE_NODE, SURFACE_NODE_DETACH_TO_DISPLAY, SurfaceNodeCommandHelper::DetachToDisplay, NodeId, uint64_t))
ADD_COMMAND(RSSurfaceNodeSetColorSpace,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_COLOR_SPACE, SurfaceNodeCommandHelper::SetColorSpace, NodeId, GraphicColorGamut))
ADD_COMMAND(RSurfaceNodeSetSurfaceId,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_SURFACE_ID, SurfaceNodeCommandHelper::SetSurfaceId, NodeId, SurfaceId))

#ifdef USE_SURFACE_TEXTURE
ADD_COMMAND(RSSurfaceNodeCreateSurfaceExt,
    ARG(SURFACE_NODE, SURFACE_NODE_CREATE_SURFACE_EXT,
    SurfaceNodeCommandHelper::CreateSurfaceExt, NodeId, std::shared_ptr<RSSurfaceTexture>))
#endif
ADD_COMMAND(RSSurfaceNodeSetForeground,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_FOREGROUND, SurfaceNodeCommandHelper::SetForeground, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetForceUIFirst,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_FORCE_UIFIRST, SurfaceNodeCommandHelper::SetForceUIFirst, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetAncoFlags,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_ANCO_FLAGS, SurfaceNodeCommandHelper::SetAncoFlags, NodeId, uint32_t))
ADD_COMMAND(RSSurfaceNodeSetHDRPresent,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_HDR_PRESENT, SurfaceNodeCommandHelper::SetHDRPresent, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetSkipDraw,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_SKIP_DRAW, SurfaceNodeCommandHelper::SetSkipDraw, NodeId, bool))
ADD_COMMAND(RSSurfaceNodeSetWatermark,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_WATERMARK, SurfaceNodeCommandHelper::SetWatermark,
    NodeId, std::string, std::shared_ptr<Media::PixelMap>))
ADD_COMMAND(RSSurfaceNodeSetWatermarkEnabled,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_WATERMARK_ENABLED, SurfaceNodeCommandHelper::SetWatermarkEnabled,
    NodeId, std::string, bool))
ADD_COMMAND(RSSurfaceNodeSetLayerTop,
    ARG(SURFACE_NODE, SURFACE_NODE_SET_LAYER_TOP, SurfaceNodeCommandHelper::SetLayerTop, NodeId, std::string, bool))
} // namespace Rosen
} // namespace OHOS
#endif // ROSEN_RENDER_SERVICE_BASE_COMMAND_RS_SURFACE_NODE_COMMAND_H
