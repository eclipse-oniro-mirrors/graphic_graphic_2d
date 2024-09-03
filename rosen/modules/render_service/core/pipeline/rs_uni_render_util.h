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

#ifndef RENDER_SERVICE_CORE_PIPELINE_RS_UNI_RENDER_UTIL_H
#define RENDER_SERVICE_CORE_PIPELINE_RS_UNI_RENDER_UTIL_H

#include <list>
#include <mutex>
#include <set>
#include <unordered_map>

#include "surface.h"
#include "surface_type.h"
#include "sync_fence.h"

#include "common/rs_obj_abs_geometry.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_display_render_params.h"
#include "pipeline/rs_base_render_engine.h"
#include "pipeline/rs_base_render_util.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_render_node_map.h"
#include "pipeline/rs_surface_render_node.h"
#include "transaction/rs_uiextension_data.h"
#include "utils/matrix.h"

namespace OHOS {
namespace Rosen {
class RSUniRenderUtil {
public:
    // merge history dirty region of current display node and its child surfacenode(app windows)
    // for mirror display, call this function twice will introduce additional dirtyhistory in dirtymanager
    static void MergeDirtyHistoryForDrawable(DrawableV2::RSDisplayRenderNodeDrawable& drawable, int32_t bufferAge,
        RSDisplayRenderParams& params, bool useAlignedDirtyRegion = false);
    static void SetAllSurfaceDrawableGlobalDityRegion(
        std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& allSurfaceDrawables,
        const RectI& globalDirtyRegion);
    /* we want to set visible dirty region of each surfacenode into DamageRegionKHR interface, hence
     * occlusion is calculated.
     * make sure this function is called after merge dirty history
     */
    static Occlusion::Region MergeVisibleDirtyRegion(
        std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& allSurfaceNodeDrawables,
        std::vector<NodeId>& hasVisibleDirtyRegionSurfaceVec, bool useAlignedDirtyRegion = false);
    static void MergeDirtyHistoryInVirtual(
        DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable, int32_t bufferAge, bool renderParallel = false);
    static Occlusion::Region MergeVisibleDirtyRegionInVirtual(
        std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& allSurfaceNodeDrawables);
    static std::vector<RectI> ScreenIntersectDirtyRects(const Occlusion::Region &region, ScreenInfo& screenInfo);
    static std::vector<RectI> GetFilpDirtyRects(const std::vector<RectI>& srcRects, const ScreenInfo& screenInfo);
    static std::vector<RectI> FilpRects(const std::vector<RectI>& srcRects, const ScreenInfo& screenInfo);
    static bool HandleSubThreadNode(RSSurfaceRenderNode& node, RSPaintFilterCanvas& canvas);
    static bool HandleCaptureNode(RSRenderNode& node, RSPaintFilterCanvas& canvas);
    // This is used for calculate matrix from buffer coordinate to window's relative coordinate
    static Drawing::Matrix GetMatrixOfBufferToRelRect(const RSSurfaceRenderNode& node);
    static void SrcRectScaleDown(BufferDrawParam& params, const sptr<SurfaceBuffer>& buffer,
        const sptr<IConsumerSurface>& surface, RectF& localBounds);
    static void SrcRectScaleFit(BufferDrawParam& params, const sptr<SurfaceBuffer>& buffer,
        const sptr<IConsumerSurface>& surface, RectF& localBounds);
    static BufferDrawParam CreateBufferDrawParam(const RSSurfaceRenderNode& node,
        bool forceCPU, uint32_t threadIndex = UNI_RENDER_THREAD_INDEX, bool useRenderParams = false);
    static BufferDrawParam CreateBufferDrawParam(const RSDisplayRenderNode& node, bool forceCPU);
    static BufferDrawParam CreateBufferDrawParam(const RSSurfaceHandler& surfaceHandler, bool forceCPU);
    static BufferDrawParam CreateBufferDrawParam(
        const DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable, bool forceCPU, uint32_t threadIndex);
    static BufferDrawParam CreateBufferDrawParamForRotationFixed(
        const DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable, RSSurfaceRenderParams& renderParams);
    static BufferDrawParam CreateLayerBufferDrawParam(const LayerInfoPtr& layer, bool forceCPU);
    static void DealWithRotationAndGravityForRotationFixed(GraphicTransformType transform, Gravity gravity,
        RectF localBounds, BufferDrawParam& params);
    static bool IsNeedClient(RSSurfaceRenderNode& node, const ComposeInfo& info);
    static void DrawRectForDfx(RSPaintFilterCanvas& canvas, const RectI& rect, Drawing::Color color,
        float alpha, const std::string& extraInfo = "");
    static Occlusion::Region AlignedDirtyRegion(const Occlusion::Region& dirtyRegion, int32_t alignedBits = 32);
    static int GetRotationFromMatrix(Drawing::Matrix matrix);
    static int GetRotationDegreeFromMatrix(Drawing::Matrix matrix);
    static bool Is3DRotation(Drawing::Matrix matrix);

    static void AssignWindowNodes(const std::shared_ptr<RSDisplayRenderNode>& displayNode,
        std::list<std::shared_ptr<RSSurfaceRenderNode>>& mainThreadNodes,
        std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes);
    static void ClearSurfaceIfNeed(const RSRenderNodeMap& map, const std::shared_ptr<RSDisplayRenderNode>& displayNode,
        std::set<std::shared_ptr<RSBaseRenderNode>>& oldChildren, DeviceType deviceType = DeviceType::PHONE);
    static void ClearCacheSurface(RSRenderNode& node, uint32_t threadIndex, bool isClearCompletedCacheSurface = true);
    static void ClearNodeCacheSurface(std::shared_ptr<Drawing::Surface>&& cacheSurface,
        std::shared_ptr<Drawing::Surface>&& cacheCompletedSurface,
        uint32_t cacheSurfaceThreadIndex, uint32_t completedSurfaceThreadIndex);
    static void CacheSubThreadNodes(std::list<std::shared_ptr<RSSurfaceRenderNode>>& oldSubThreadNodes,
        std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes);
    static bool IsNodeAssignSubThread(std::shared_ptr<RSSurfaceRenderNode> node, bool isDisplayRotation);
#ifdef RS_ENABLE_VK
    static uint32_t FindMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties);
    static void SetVkImageInfo(std::shared_ptr<OHOS::Rosen::Drawing::VKTextureInfo> vkImageInfo,
        const VkImageCreateInfo& imageInfo);
    static Drawing::BackendTexture MakeBackendTexture(uint32_t width, uint32_t height,
        VkFormat format = VK_FORMAT_R8G8B8A8_UNORM);
#endif
    static void UpdateRealSrcRect(RSSurfaceRenderNode& node, const RectI& absRect);
    static void DealWithNodeGravity(RSSurfaceRenderNode& node, const ScreenInfo& screenInfo);
    static void DealWithScalingMode(RSSurfaceRenderNode& node);
    static void CheckForceHardwareAndUpdateDstRect(RSSurfaceRenderNode& node);
    static void LayerRotate(RSSurfaceRenderNode& node, const ScreenInfo& screenInfo);
    static void LayerCrop(RSSurfaceRenderNode& node, const ScreenInfo& screenInfo);
    static void LayerScaleDown(RSSurfaceRenderNode& node);
    static void LayerScaleFit(RSSurfaceRenderNode& node);
    static GraphicTransformType GetLayerTransform(RSSurfaceRenderNode& node, const ScreenInfo& screenInfo);
    static void OptimizedFlushAndSubmit(std::shared_ptr<Drawing::Surface>& surface,
        Drawing::GPUContext* const grContext, bool optFenceWait = true);
    static void AccumulateMatrixAndAlpha(std::shared_ptr<RSSurfaceRenderNode>& hwcNode,
        Drawing::Matrix& matrix, float& alpha);
    static SecRectInfo GenerateSecRectInfoFromNode(RSRenderNode& node, RectI rect);
    static SecSurfaceInfo GenerateSecSurfaceInfoFromNode(
        NodeId uiExtensionId, NodeId hostId, SecRectInfo uiExtensionRectInfo);
    static void UIExtensionFindAndTraverseAncestor(
        const RSRenderNodeMap& nodeMap, UIExtensionCallbackData& callbackData);
    static void TraverseAndCollectUIExtensionInfo(std::shared_ptr<RSRenderNode> node,
        Drawing::Matrix parentMatrix, NodeId hostId, UIExtensionCallbackData& callbackData);
    static void ProcessCacheImage(RSPaintFilterCanvas& canvas, Drawing::Image& cacheImageProcessed);
    static void FlushDmaSurfaceBuffer(Media::PixelMap* pixelMap);
    template<typename... Callbacks>
    static void TraverseParentNodeAndReduce(std::shared_ptr<RSSurfaceRenderNode> hwcNode, Callbacks&&... callbacks)
    {
        static_assert((std::is_invocable<Callbacks, std::shared_ptr<RSRenderNode>>::value && ...),
                    "uninvocable callback");
        if (!hwcNode) {
            return;
        }
        auto parent = std::static_pointer_cast<RSRenderNode>(hwcNode);
        while (static_cast<bool>(parent = parent->GetParent().lock())) {
            (std::invoke(callbacks, parent), ...);
            if (parent->GetType() == RSRenderNodeType::DISPLAY_NODE) {
                break;
            }
        }
    }
private:
    static RectI SrcRectRotateTransform(RSSurfaceRenderNode& node, GraphicTransformType transformType);
    static void AssignMainThreadNode(std::list<std::shared_ptr<RSSurfaceRenderNode>>& mainThreadNodes,
        const std::shared_ptr<RSSurfaceRenderNode>& node);
    static void AssignSubThreadNode(std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes,
        const std::shared_ptr<RSSurfaceRenderNode>& node);
    static void SortSubThreadNodes(std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes);
    static void HandleHardwareNode(const std::shared_ptr<RSSurfaceRenderNode>& node);
    static void PostReleaseSurfaceTask(std::shared_ptr<Drawing::Surface>&& surface, uint32_t threadIndex);
    static GraphicTransformType GetRotateTransformForRotationFixed(RSSurfaceRenderNode& node,
        sptr<IConsumerSurface> consumer);
    static inline int currentUIExtensionIndex_ = -1;
};
}
}
#endif // RENDER_SERVICE_CORE_PIPELINE_RS_UNI_RENDER_UTIL_H
