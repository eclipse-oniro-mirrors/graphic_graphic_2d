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
    // 从真实父链累计坐标系转换到 screenNode 的局部坐标系；跨屏节点未收集 DRM 时不计算。
    static bool CalcCrossNodeLayerConversion(const RSSurfaceRenderNode& sourceNode,
        const RSSurfaceRenderNode& cloneNode, const RSScreenRenderNode& screenNode, Drawing::Matrix& conversion);
    static void UpdateDrmCrossNodeConversion(const RSSurfaceRenderNode& crossNode, NodeId screenNodeId,
        const Drawing::Matrix& conversion);
    // 将 DRM 全局定位节点的局部 dst 与本次 prepare 屏及其转换配对，主屏也记录，offset 字段清零。
    // 无屏幕、非 DRM、非全局定位或矩阵不可逆时使记录失效。
    static void RecordDstRectDisplay(RSSurfaceRenderNode& node,
        const std::shared_ptr<RSScreenRenderNode>& screenNode);
    // matrix 从真实父链累计坐标系转换，dst 从产生屏的 prepare 局部坐标系转换，不加减 offset。
    // 产生屏或目标屏记录缺失、矩阵不可逆时返回 false，且不修改 layerInfo。
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
    // 将 dst 直接转换到 screenNodeId 的局部坐标系，返回转换是否成功；失败时不修改 layerInfo。
    static bool RestoreCrossNodeDstRect(const RSSurfaceRenderParams& params, NodeId screenNodeId,
        RSLayerInfo& layerInfo);
    inline static std::unordered_map<NodeId, // map<first level node ID, drm surface node>
        std::vector<std::shared_ptr<RSSurfaceRenderNode>>> drmNodes_ = {};
};

} // namespace Rosen
} // namespace OHOS
#endif // RS_DRM_UTIL_H