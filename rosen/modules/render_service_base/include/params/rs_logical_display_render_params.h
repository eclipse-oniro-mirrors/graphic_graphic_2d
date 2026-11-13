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

#ifndef RENDER_SERVICE_BASE_PARAMS_RS_LOGICAL_DISPLAY_RENDER_PARAMS_H
#define RENDER_SERVICE_BASE_PARAMS_RS_LOGICAL_DISPLAY_RENDER_PARAMS_H

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "common/rs_macros.h"
#include "params/rs_render_params.h"
#include "params/rs_screen_render_params.h"
namespace OHOS::Rosen {
class RSSurfaceRenderNode;
class RSB_EXPORT RSLogicalDisplayRenderParams : public RSRenderParams {
public:
    explicit RSLogicalDisplayRenderParams(NodeId nodeId);
    ~RSLogicalDisplayRenderParams() override = default;

    void OnSync(const std::unique_ptr<RSRenderParams>& target) override;

    std::string ToString() const override;

    void SetScreenRotation(ScreenRotation screenRotation);
    ScreenRotation GetScreenRotation() const override;
    ScreenRotation GetNodeRotation() const;
    void SetRotationChanged(bool changed) override;
    bool IsRotationChanged() const override;

    void SetScreenId(uint64_t screenId);
    uint64_t GetScreenId() const;

    void SetDisplayContentRect(const Rect& contentRect);
    const Rect& GetDisplayContentRect() const;

    void SetNeedOffscreen(bool needOffscreen);
    bool GetNeedOffscreen() const;

    void SetHasDstAlphaBlendModeNode(bool hasDstAlphaBlendModeNode)
    {
        if (hasDstAlphaBlendModeNode_ == hasDstAlphaBlendModeNode) {
            return;
        }
        hasDstAlphaBlendModeNode_ = hasDstAlphaBlendModeNode;
        needSync_ = true;
    }

    bool GetHasDstAlphaBlendModeNode() const
    {
        return hasDstAlphaBlendModeNode_;
    }

    bool IsMirrorDisplay() const;
    DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr GetMirrorSourceDrawable() override;
    bool GetVirtualScreenMuteStatus() const;
    bool IsSecurityDisplay() const;
    bool HasCaptureWindow() const;
    CompositeType GetCompositeType() const
    {
        return compositeType_;
    }
    bool GetSecurityExemption() const
    {
        return isSecurityExemption_;
    }

    void SetSecurityExemption(bool isSecurityExemption)
    {
        isSecurityExemption_ = isSecurityExemption;
    }

    const std::vector<Occlusion::Rect>& GetTopSurfaceOpaqueRects() const
    {
        return topSurfaceOpaqueRects_;
    }

    void SetTopSurfaceOpaqueRects(const std::vector<Occlusion::Rect>& topSurfaceOpaqueRects)
    {
        topSurfaceOpaqueRects_ = topSurfaceOpaqueRects;
    }

    void SetTopSurfaceOpaqueRects(std::vector<Occlusion::Rect>&& topSurfaceOpaqueRects)
    {
        topSurfaceOpaqueRects_ = std::move(topSurfaceOpaqueRects);
    }

    const RSSpecialLayerManager& GetSpecialLayerMgr() const
    {
        return specialLayerManager_;
    }

    bool HasSecLayerInVisibleRect() const
    {
        return hasSecLayerInVisibleRect_;
    }

    bool IsSpecialLayerChanged() const
    {
        return displaySpecialSurfaceChanged_;
    }

    bool HasSecLayerInVisibleRectChanged() const
    {
        return hasSecLayerInVisibleRectChanged_;
    }

    void SetAncestorScreenDrawable(const DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr& ancestorScreenDrawable)
    {
        ancestorScreenDrawable_ = ancestorScreenDrawable;
    }

    DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr GetAncestorScreenDrawable() const
    {
        return ancestorScreenDrawable_;
    }

    float GetOffsetX() const
    {
        return offsetX_;
    }

    float GetOffsetY() const
    {
        return offsetY_;
    }

    ScreenRotation GetMirrorSourceRotation() const
    {
        return mirrorSourceRotation_;
    }

    void SetMirrorSourceRotation(ScreenRotation rotation)
    {
        if (mirrorSourceRotation_ == rotation) {
            return;
        }
        mirrorSourceRotation_ = rotation;
        needSync_ = true;
    }

    float GetFixedWidth() const
    {
        return fixedWidth_;
    }

    float GetFixedHeight() const
    {
        return fixedHeight_;
    }

    // A record session is only active on a virtual screen: consumers gate on this instead of the
    // raw config, so a display re-parented to a physical screen falls back to normal drawing.
    bool IsRecordSessionActive() const
    {
        return !windowRecordConfig_.surfaceNodeIds.empty() && isOnVirtualScreen_;
    }
    void SetOnVirtualScreen(bool onVirtualScreen)
    {
        isOnVirtualScreen_ = onVirtualScreen;
        needSync_ = true;
    }
    const RSWindowRecordConfig& GetWindowRecordConfig() const { return windowRecordConfig_; }
    // Window-record snapshots, resolved per frame on the RS main thread (see
    // RSLogicalDisplayRenderNode::ResolveWindowRecordSnapshot). The render thread consumes only
    // these: drawables are the render-thread side representation, so locking them and reading
    // their params is safe. It must never touch RSRenderNodeMap or RSRenderNode, whose state
    // (node map containers, parent chain, node members) is main-thread exclusive and unlocked.
    const std::vector<DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr>& GetRecordSurfaceDrawables() const
    {
        return recordSurfaceDrawables_;
    }
    const std::unordered_set<NodeId>& GetRecordWhiteListIds() const
    {
        return recordWhiteListIds_;
    }
    DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr GetRecordSourceDisplayDrawable() const
    {
        return recordSourceDisplayDrawable_;
    }
    // Called by RSLogicalDisplayRenderNode after writing the record snapshot fields (friend
    // access).
    void MarkWindowRecordSnapshotSynced() { needSync_ = true; }

    void SetWindowRecordConfig(const RSWindowRecordConfig& config) { windowRecordConfig_ = config; needSync_ = true; }

private:
    DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr ancestorScreenDrawable_;
    std::vector<Occlusion::Rect> topSurfaceOpaqueRects_;
    bool hasSecLayerInVisibleRect_ = false;
    RSSpecialLayerManager specialLayerManager_;
    bool isSecurityExemption_ = false;
    uint64_t screenId_ = INVALID_SCREEN_ID;
    Rect contentRect_ = {0, 0, 0, 0};
    bool needOffscreen_ = false;
    ScreenRotation screenRotation_ = ScreenRotation::ROTATION_0;
    ScreenRotation nodeRotation_ = ScreenRotation::INVALID_SCREEN_ROTATION;
    ScreenRotation mirrorSourceRotation_ = ScreenRotation::INVALID_SCREEN_ROTATION;
    bool isRotationChanged_ = false;
    bool hasDstAlphaBlendModeNode_ = false;

    DisplayMode displayMode_ = DisplayMode::INVALID;
    DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr mirrorSourceDrawable_;
    bool virtualScreenMuteStatus_ = false;
    bool isSecurityDisplay_ = false;
    bool hasCaptureWindow_ = false;
    CompositeType compositeType_ = CompositeType::HARDWARE_COMPOSITE;

    bool displaySpecialSurfaceChanged_ = false;
    bool hasSecLayerInVisibleRectChanged_ = false;

    float offsetX_ = 0.f;
    float offsetY_ = 0.f;
    float fixedWidth_ = 0;
    float fixedHeight_ = 0;

    RSWindowRecordConfig windowRecordConfig_;
    bool isOnVirtualScreen_ = false;
    // Main-thread resolved window-record snapshots (see GetRecordSurfaceDrawables() for the
    // thread contract). recordSurfaceDrawables_ holds only main-window-type surfaces, so the
    // render thread needs no node type check; recordWhiteListIds_ contains both persistent ids
    // and surface node ids for record-only capture matching; recordSourceDisplayDrawable_
    // replaces the per-frame parent-chain walk.
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr> recordSurfaceDrawables_;
    std::unordered_set<NodeId> recordWhiteListIds_;
    DrawableV2::RSRenderNodeDrawableAdapter::WeakPtr recordSourceDisplayDrawable_;

    friend class RSLogicalDisplayRenderNode;
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_PARAMS_RS_LOGICAL_DISPLAY_RENDER_PARAMS_H
