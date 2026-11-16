/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef RS_DRM_UTIL_H
#define RS_DRM_UTIL_H

#include "pipeline/rs_processor.h"

namespace OHOS {
namespace Rosen {

class RSDrmUtil {
public:
    RSDrmUtil() = default;
    ~RSDrmUtil() = default;
    using DrawablesVec = std::vector<std::tuple<NodeId, NodeId, DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>>;

    static void ClearDrmNodes();
    static void AddDrmCloneCrossNode(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode,
        DrawablesVec& hardwareEnabledDrawables);
    // Conversion of the drm layers of a cross node from the frame of the display owning the cross node into the frame
    // of screenNode, where the clone of the cross node is composed. Returns false when the cross node has no drm node.
    static bool CalcCrossNodeLayerConversion(const RSSurfaceRenderNode& sourceNode,
        const RSSurfaceRenderNode& cloneNode, const RSScreenRenderNode& screenNode, Drawing::Matrix& conversion);
    static void UpdateDrmCrossNodeConversion(const RSSurfaceRenderNode& crossNode, NodeId screenNodeId,
        const Drawing::Matrix& conversion);
    // Records the display whose frame the dst rect of a drm node of a cross node is in, so the render thread can move
    // it back before converting it. Only the drm nodes record it, a null screenNode or any other node records none.
    static void RecordDstRectDisplay(RSSurfaceRenderNode& node,
        const std::shared_ptr<RSScreenRenderNode>& screenNode);
    // Converts the layer info of a drm cross node composed on screenNodeId with the conversion recorded for that
    // screen. Returns false when there is no such conversion, then the layer info is left unchanged.
    static bool ConvertCrossNodeLayerInfo(const RSSurfaceRenderParams& params, NodeId screenNodeId,
        RSLayerInfo& layerInfo);
    static void ApplyCrossNodeLayerConversion(const Drawing::Matrix& conversion, RSLayerInfo& layerInfo,
        bool convertDstRect = true);
    // The layer info of a cross node keeps the geometry of the whole surface, which may cross the screen boundary, so
    // the source rect is cropped by the same proportion as the destination rect, following its transform.
    static void CropCrossNodeLayerInfo(const Drawing::Rect& composedDstRect, const Drawing::Rect& screenRect,
        RSLayerInfo& layerInfo);
    static void DRMCreateLayer(std::shared_ptr<RSProcessor> processor, Drawing::Matrix hwcMatrix);
    static void MarkBlurIntersectWithDRM(const std::shared_ptr<RSRenderNode>& node,
        const std::vector<std::weak_ptr<RSSurfaceRenderNode>>& drmNodes,
        const std::shared_ptr<RSScreenRenderNode>& curScreenNode);
    static bool IsDRMNodesOnTheTree();
    static void DealWithDRMNodes(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode,
        const sptr<SurfaceBuffer>& buffer, const std::shared_ptr<RSComposerClientManager>& clientManager);
    static bool HasDRMInVirtualScreen(RSPaintFilterCanvas& canvas, RSSurfaceRenderParams& surfaceParams);
private:
    static void MarkAllBlurIntersectWithDRM(const std::shared_ptr<RSRenderNode>& node,
        const std::vector<std::weak_ptr<RSSurfaceRenderNode>>& drmNodes,
        const std::shared_ptr<RSScreenRenderNode>& curScreenNode);
    static void MarkBlurIntersectWithDRM(const std::shared_ptr<RSRenderNode>& node,
        const std::vector<std::weak_ptr<RSSurfaceRenderNode>>& drmNodes);
    static bool IsDRMBelowFilter(const std::shared_ptr<RSScreenRenderNode>& curScreenNode,
        const std::shared_ptr<RSSurfaceRenderNode>& appWindowNode,
        const std::shared_ptr<RSSurfaceRenderNode>& drmNode);
    static bool GetDarkColorMode(const std::shared_ptr<RSRenderNode>& node,
        const std::shared_ptr<RSSurfaceRenderNode>& appWindowNode);
    static void CollectDrmNodes(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode);
    // Whether the node is one of the drm nodes collected for this frame, only those take part in the layer conversion.
    static bool IsDrmNode(const RSRenderNode& node);
    static void PreAllocProtectedFrameBuffers(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode,
        const sptr<SurfaceBuffer>& buffer, const std::shared_ptr<RSComposerClientManager>& clientManager);
    // Moves the dstRect back into the frame the conversions start from, and returns true when it already is in the
    // local frame of screenNodeId, so it must not be converted again.
    static bool RestoreCrossNodeDstRect(const RSSurfaceRenderParams& params, NodeId screenNodeId,
        RSLayerInfo& layerInfo);
    inline static std::unordered_map<NodeId, // map<first level node ID, drm surface node>
        std::vector<std::shared_ptr<RSSurfaceRenderNode>>> drmNodes_ = {};
};

} // namespace Rosen
} // namespace OHOS
#endif // RS_DRM_UTIL_H