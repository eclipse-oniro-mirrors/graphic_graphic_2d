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

#ifndef RENDER_SERVICE_BASE_PARAMS_RS_DISPLAY_RENDER_PARAMS_H
#define RENDER_SERVICE_BASE_PARAMS_RS_DISPLAY_RENDER_PARAMS_H

#include <memory>

#include "common/rs_macros.h"
#include "params/rs_render_params.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_render_node.h"
#include "screen_manager/rs_screen_info.h"
#include "pipeline/rs_surface_render_node.h"
namespace OHOS::Rosen {
class RSB_EXPORT RSDisplayRenderParams : public RSRenderParams {
public:
    explicit RSDisplayRenderParams(NodeId id);
    ~RSDisplayRenderParams() override = default;

    void OnSync(const std::unique_ptr<RSRenderParams>& target) override;

    std::vector<RSBaseRenderNode::SharedPtr>& GetAllMainAndLeashSurfaces();
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& GetAllMainAndLeashSurfaceDrawables() override;
    void SetAllMainAndLeashSurfaces(std::vector<RSBaseRenderNode::SharedPtr>& allMainAndLeashSurfaces);
    void SetAllMainAndLeashSurfaceDrawables(
        std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& allMainAndLeashSurfaces);
    int32_t GetDisplayOffsetX() const
    {
        return offsetX_;
    }
    int32_t GetDisplayOffsetY() const
    {
        return offsetY_;
    }
    uint64_t GetScreenId() const override
    {
        return screenId_;
    }
    uint64_t GetMirroredId() const
    {
        return mirroredId_;
    }
    const ScreenInfo& GetScreenInfo() const override
    {
        return screenInfo_;
    }
    NodeId GetMirrorSourceId() const
    {
        return mirrorSourceId_;
    }
    RSDisplayRenderNode::CompositeType GetCompositeType() const
    {
        return compositeType_;
    };
    ScreenRotation GetScreenRotation() const override
    {
        return screenRotation_;
    }
    ScreenRotation GetNodeRotation() const
    {
        return nodeRotation_;
    }
    const std::map<ScreenId, bool>& GetDisplayHasSecSurface() const
    {
        return displayHasSecSurface_;
    }
    const std::map<ScreenId, bool>& GetDisplayHasSkipSurface() const
    {
        return displayHasSkipSurface_;
    }
    const std::map<ScreenId, bool>& GetDisplayHasProtectedSurface() const
    {
        return displayHasProtectedSurface_;
    }
    const std::map<ScreenId, bool>& GethasCaptureWindow() const
    {
        return hasCaptureWindow_;
    }

    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& GetHardwareEnabledDrawables()
    {
        return hardwareEnabledDrawables_;
    }

    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& GetHardwareEnabledTopDrawables()
    {
        return hardwareEnabledTopDrawables_;
    }

    void SetSecurityDisplay(bool isSecurityDisplay);
    bool GetSecurityDisplay() const override
    {
        return isSecurityDisplay_;
    }
    void SetIsMouseDirty(bool mouseDirty)
    {
        isMouseDirty_ = mouseDirty;
    }
    bool GetIsMouseDirty() const
    {
        return isMouseDirty_;
    }
    void SetGlobalZOrder(float zOrder);
    float GetGlobalZOrder() const;
    void SetMainAndLeashSurfaceDirty(bool isDirty);
    bool GetMainAndLeashSurfaceDirty() const;
    bool HasSecurityLayer() const;
    bool HasSkipLayer() const;
    bool HasProtectedLayer() const;
    bool HasCaptureWindow() const;
    void SetNeedOffscreen(bool needOffscreen);
    bool GetNeedOffscreen() const;

    void SetRotationChanged(bool changed) override;
    bool IsRotationChanged() const override;

    void SetHDRPresent(bool hasHdrPresent);
    bool GetHDRPresent() const;

    void SetBrightnessRatio (bool brightnessRatio);
    float GetBrightnessRatio() const;

    void SetNewColorSpace(const GraphicColorGamut& newColorSpace);
    GraphicColorGamut GetNewColorSpace() const;
    void SetNewPixelFormat(const GraphicPixelFormat& newPixelFormat);
    GraphicPixelFormat GetNewPixelFormat() const;

    bool IsSpecialLayerChanged() const
    {
        auto iter = displaySpecailSurfaceChanged_.find(screenId_);
        return iter == displaySpecailSurfaceChanged_.end() ? false : iter->second;
    }

    // dfx
    std::string ToString() const override;

    DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr GetMirrorSourceDrawable() override;
private:
    std::map<ScreenId, bool> displayHasSecSurface_;
    std::map<ScreenId, bool> displayHasSkipSurface_;
    std::map<ScreenId, bool> displayHasProtectedSurface_;
    std::map<ScreenId, bool> displaySpecailSurfaceChanged_;
    std::map<ScreenId, bool> hasCaptureWindow_;
    std::vector<RSBaseRenderNode::SharedPtr> allMainAndLeashSurfaces_;
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> allMainAndLeashSurfaceDrawables_;
    int32_t offsetX_ = -1;
    int32_t offsetY_ = -1;
    ScreenRotation nodeRotation_ = ScreenRotation::INVALID_SCREEN_ROTATION;
    ScreenRotation screenRotation_ = ScreenRotation::INVALID_SCREEN_ROTATION;
    uint64_t screenId_ = 0;
    bool isSecurityDisplay_ = false;
    std::weak_ptr<RSDisplayRenderNode> mirrorSource_;
    std::shared_ptr<DrawableV2::RSRenderNodeDrawableAdapter> mirrorSourceDrawable_ = nullptr;
    NodeId mirrorSourceId_ = INVALID_NODEID;
    ScreenInfo screenInfo_;
    ScreenId mirroredId_ = INVALID_SCREEN_ID;
    RSDisplayRenderNode::CompositeType compositeType_ = RSDisplayRenderNode::CompositeType::HARDWARE_COMPOSITE;
    bool isMainAndLeashSurfaceDirty_ = false;
    bool needOffscreen_ = false;
    bool isRotationChanged_ = false;
    bool hasHdrPresent_ = false;
    bool brightnessRatio_ = 1.0f;
    bool isMouseDirty_ = false;
    float zOrder_ = 0.0f;
    friend class RSUniRenderVisitor;
    friend class RSDisplayRenderNode;
    
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes_;
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> hardwareEnabledDrawables_;
    // vector of hardwareEnabled nodes above displayNodeSurface like pointer window
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledTopNodes_;
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> hardwareEnabledTopDrawables_;
    GraphicColorGamut newColorSpace_ = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    GraphicPixelFormat newPixelFormat_ = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_8888;
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_PARAMS_RS_DISPLAY_RENDER_PARAMS_H
