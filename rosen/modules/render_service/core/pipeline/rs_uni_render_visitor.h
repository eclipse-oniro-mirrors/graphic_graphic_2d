/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#ifndef RENDER_SERVICE_CORE_PIPELINE_RS_UNI_RENDER_VISITOR_H
#define RENDER_SERVICE_CORE_PIPELINE_RS_UNI_RENDER_VISITOR_H

#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <parameters.h>
#include <set>

#include "rs_base_render_engine.h"

#include "pipeline/driven_render/rs_driven_render_manager.h"
#include "pipeline/round_corner_display/rs_rcd_render_manager.h"
#include "pipeline/rs_dirty_region_manager.h"
#include "pipeline/rs_processor.h"
#include "platform/ohos/overdraw/rs_cpu_overdraw_canvas_listener.h"
#include "platform/ohos/overdraw/rs_gpu_overdraw_canvas_listener.h"
#include "platform/ohos/overdraw/rs_overdraw_controller.h"
#include "screen_manager/rs_screen_manager.h"
#include "system/rs_system_parameters.h"
#include "visitor/rs_node_visitor.h"
#include "pipeline/rs_recording_canvas.h"
#ifdef DDGR_ENABLE_FEATURE_OPINC
#include "rs_auto_cache.h"
#endif

class SkPicture;
namespace OHOS {
namespace Rosen {
class RSPaintFilterCanvas;
class RSUniRenderVisitor : public RSNodeVisitor {
public:
    using SurfaceDirtyMgrPair = std::pair<std::shared_ptr<RSSurfaceRenderNode>, std::shared_ptr<RSSurfaceRenderNode>>;
    RSUniRenderVisitor();
    RSUniRenderVisitor(std::shared_ptr<RSPaintFilterCanvas> canvas, uint32_t surfaceIndex);
    explicit RSUniRenderVisitor(const RSUniRenderVisitor& visitor);
    ~RSUniRenderVisitor() override;

    void PrepareChildren(RSRenderNode& node) override;
    void PrepareCanvasRenderNode(RSCanvasRenderNode& node) override;
    void PrepareDisplayRenderNode(RSDisplayRenderNode& node) override;
    void PrepareProxyRenderNode(RSProxyRenderNode& node) override;
    void PrepareRootRenderNode(RSRootRenderNode& node) override;
    void PrepareSurfaceRenderNode(RSSurfaceRenderNode& node) override;
    void PrepareEffectRenderNode(RSEffectRenderNode& node) override;

    void ProcessChildren(RSRenderNode& node) override;
    void ProcessChildInner(RSRenderNode& node, const RSRenderNode::SharedPtr& child);
    void ProcessCanvasRenderNode(RSCanvasRenderNode& node) override;
    void ProcessDisplayRenderNode(RSDisplayRenderNode& node) override;
    void ProcessProxyRenderNode(RSProxyRenderNode& node) override;
    void ProcessRootRenderNode(RSRootRenderNode& node) override;
    void ProcessSurfaceRenderNode(RSSurfaceRenderNode& node) override;
    void ProcessEffectRenderNode(RSEffectRenderNode& node) override;

    bool DoDirectComposition(std::shared_ptr<RSBaseRenderNode> rootNode);
    bool ParallelComposition(const std::shared_ptr<RSBaseRenderNode> rootNode);
    void ChangeCacheRenderNodeMap(RSRenderNode& node, const uint32_t count = 0);
    void UpdateCacheRenderNodeMap(RSRenderNode& node);
    bool GenerateNodeContentCache(RSRenderNode& node);
    bool InitNodeCache(RSRenderNode& node);
    void CopyVisitorInfos(std::shared_ptr<RSUniRenderVisitor> visitor);
    void CheckSkipRepeatShadow(RSRenderNode& node, const bool resetStatus);
    void SetProcessorRenderEngine(std::shared_ptr<RSBaseRenderEngine> renderEngine)
    {
        renderEngine_ = renderEngine;
    }

    void SetAnimateState(bool doAnimate)
    {
        doAnimate_ = doAnimate;
    }

    void SetDirtyFlag(bool isDirty)
    {
        isDirty_ = isDirty;
    }

    void SetFocusedNodeId(uint64_t nodeId, uint64_t leashId)
    {
        currentFocusedNodeId_ = nodeId;
        focusedLeashWindowId_ = leashId;
    }

    void SetSubThreadConfig(uint32_t threadIndex)
    {
        isSubThread_ = true;
        isHardwareForcedDisabled_ = true;
        threadIndex_ = threadIndex;
    }

    void DrawSurfaceLayer(const std::shared_ptr<RSDisplayRenderNode>& displayNode,
        const std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes) const;

    bool GetAnimateState() const
    {
        return doAnimate_;
    }

    void MarkHardwareForcedDisabled()
    {
        isHardwareForcedDisabled_ = true;
    }

    void SetDrivenRenderFlag(bool hasDrivenNodeOnUniTree, bool hasDrivenNodeMarkRender)
    {
        if (!drivenInfo_) {
            return;
        }
        drivenInfo_->prepareInfo.hasDrivenNodeOnUniTree = hasDrivenNodeOnUniTree;
        drivenInfo_->hasDrivenNodeMarkRender = hasDrivenNodeMarkRender;
    }

#ifdef DDGR_ENABLE_FEATURE_OPINC
    void OpincSetRectChangeState(RSCanvasRenderNode& node, RectI& boundsRect);
#endif

    void UpdateHardwareEnabledInfoBeforeCreateLayer();
    void SetHardwareEnabledNodes(const std::vector<std::shared_ptr<RSSurfaceRenderNode>>& hardwareEnabledNodes);
    void AssignGlobalZOrderAndCreateLayer(std::vector<std::shared_ptr<RSSurfaceRenderNode>>& nodesInZOrder);
    void ScaleMirrorIfNeed(RSDisplayRenderNode& node);

    void CopyForParallelPrepare(std::shared_ptr<RSUniRenderVisitor> visitor);
    // Some properties defined before ProcessSurfaceRenderNode() may be used in
    // ProcessSurfaceRenderNode() method. We should copy these properties in parallel render.
    void CopyPropertyForParallelVisitor(RSUniRenderVisitor *mainVisitor);
    bool GetIsPartialRenderEnabled() const
    {
        return isPartialRenderEnabled_;
    }
    bool GetIsOpDropped() const
    {
        return isOpDropped_;
    }
    // Use in vulkan parallel rendering
    GraphicColorGamut GetColorGamut() const
    {
        return newColorSpace_;
    }

    std::shared_ptr<RSProcessor> GetProcessor() const
    {
        return processor_;
    }

    void SetRenderFrame(std::unique_ptr<RSRenderFrame> renderFrame)
    {
        renderFrame_ = std::move(renderFrame);
    }
    void SetAppWindowNum(uint32_t num);

    void SetForceUpdateFlag(bool flag)
    {
        forceUpdateFlag_ = flag;
    }

    using RenderParam = std::tuple<std::shared_ptr<RSRenderNode>, RSPaintFilterCanvas::CanvasStatus>;
private:
    void PartialRenderOptionInit();
    void CalcChildFilterNodeDirtyRegion(std::shared_ptr<RSSurfaceRenderNode>& currentSurfaceNode,
        std::shared_ptr<RSDisplayRenderNode>& displayNode);
    void CalcSurfaceFilterNodeDirtyRegion(std::shared_ptr<RSSurfaceRenderNode>& currentSurfaceNode,
        std::shared_ptr<RSDisplayRenderNode>& displayNode);
    void DrawWatermarkIfNeed(RSDisplayRenderNode& node, bool isMirror = false);
#ifndef USE_ROSEN_DRAWING
    void DrawDirtyRectForDFX(const RectI& dirtyRect, const SkColor color,
        const SkPaint::Style fillType, float alpha, int edgeWidth);
#else
    enum class RSPaintStyle {
        FILL,
        STROKE
    };
    void DrawDirtyRectForDFX(const RectI& dirtyRect, const Drawing::Color color,
        const RSPaintStyle fillType, float alpha, int edgeWidth);
#endif
    void DrawDirtyRegionForDFX(std::vector<RectI> dirtyRects);
    void DrawCacheRegionForDFX(std::vector<RectI> cacheRects);
#ifdef DDGR_ENABLE_FEATURE_OPINC
    void DrawAutoCacheRegionForDFX(std::vector<RectI, std::string> cacheRegionInfo);
#endif
    void DrawAllSurfaceDirtyRegionForDFX(RSDisplayRenderNode& node, const Occlusion::Region& region);
    void DrawTargetSurfaceDirtyRegionForDFX(RSDisplayRenderNode& node);
    void DrawAllSurfaceOpaqueRegionForDFX(RSDisplayRenderNode& node);
    void DrawSurfaceOpaqueRegionForDFX(RSSurfaceRenderNode& node);
    void DrawTargetSurfaceVisibleRegionForDFX(RSDisplayRenderNode& node);
    void DrawCurrentRefreshRate(uint32_t currentRefreshRate, uint32_t realtimeRefreshRate);
    // check if surface name is in dfx target list
    inline bool CheckIfSurfaceTargetedForDFX(std::string nodeName)
    {
        return (std::find(dfxTargetSurfaceNames_.begin(), dfxTargetSurfaceNames_.end(),
            nodeName) != dfxTargetSurfaceNames_.end());
    }

    bool DrawDetailedTypesOfDirtyRegionForDFX(RSSurfaceRenderNode& node);
    void DrawAndTraceSingleDirtyRegionTypeForDFX(RSSurfaceRenderNode& node,
        DirtyRegionType dirtyType, bool isDrawn = true);

    bool IsNotDirtyHardwareEnabledTopSurface(std::shared_ptr<RSSurfaceRenderNode>& node) const;
    std::vector<RectI> GetDirtyRects(const Occlusion::Region &region);
    /* calculate display/global (between windows) level dirty region, current include:
     * 1. window move/add/remove 2. transparent dirty region
     * when process canvas culling, canvas intersect with surface's visibledirty region or
     * global dirty region will be skipped
     */
    void CalcDirtyDisplayRegion(std::shared_ptr<RSDisplayRenderNode>& node);
    void CalcDirtyRegionForFilterNode(const RectI& filterRect,
        std::shared_ptr<RSSurfaceRenderNode>& currentSurfaceNode,
        std::shared_ptr<RSDisplayRenderNode>& displayNode);

    // remove functions below when dirty region is enabled for foldable device
    void UpdateHardwareNodeStatusBasedOnFilterRegion(RSDisplayRenderNode& displayNode);
    void UpdateHardwareNodeStatusBasedOnFilter(std::shared_ptr<RSSurfaceRenderNode>& node,
        std::vector<std::shared_ptr<RSSurfaceRenderNode>>& prevHwcEnabledNodes);
    void UpdateHardwareEnableList(std::vector<RectI>& filterRects,
        std::vector<std::shared_ptr<RSSurfaceRenderNode>>& validHwcNodes);
    // remove functions above when dirty region is enabled for foldable device

    void CalcDirtyFilterRegion(std::shared_ptr<RSDisplayRenderNode>& node);
    /* Disable visible hwc surface if it intersects with filter region
     * Save rest validNodes in prevHwcEnabledNodes
     * [planning] Update hwc surface dirty status at the same time
     */
    void UpdateHardwareNodeStatusBasedOnFilter(std::shared_ptr<RSSurfaceRenderNode>& node,
        std::vector<SurfaceDirtyMgrPair>& prevHwcEnabledNodes,
        std::shared_ptr<RSDirtyRegionManager>& displayDirtyManager);
    /* Disable hwc surface intersect with filter rects and merge dirty filter region
     * [planning] If invisible filterRects could be removed
     */
    RectI UpdateHardwareEnableList(std::vector<RectI>& filterRects,
        std::vector<SurfaceDirtyMgrPair>& validHwcNodes);
    void MergeDirtyRectIfNeed(std::shared_ptr<RSSurfaceRenderNode> appNode,
        std::shared_ptr<RSSurfaceRenderNode> hwcNode);
    void AddContainerDirtyToGlobalDirty(std::shared_ptr<RSDisplayRenderNode>& node) const;
    // merge last childRect as dirty if any child has been removed
    void MergeRemovedChildDirtyRegion(RSRenderNode& node);
    // Reset curSurface info as upper surfaceParent in case surfaceParent has multi children
    void ResetCurSurfaceInfoAsUpperSurfaceParent(RSSurfaceRenderNode& node);

    // set global dirty region to each surface node
    void SetSurfaceGlobalDirtyRegion(std::shared_ptr<RSDisplayRenderNode>& node);
    void SetSurfaceGlobalAlignedDirtyRegion(std::shared_ptr<RSDisplayRenderNode>& node,
        const Occlusion::Region alignedDirtyRegion);
    void AlignGlobalAndSurfaceDirtyRegions(std::shared_ptr<RSDisplayRenderNode>& node);

    void CheckAndSetNodeCacheType(RSRenderNode& node);
    bool UpdateCacheSurface(RSRenderNode& node);
    void DrawSpherize(RSRenderNode& node);
    void DrawChildRenderNode(RSRenderNode& node);
    void DrawChildCanvasRenderNode(RSRenderNode& node);

    void CheckColorSpace(RSSurfaceRenderNode& node);
    void HandleColorGamuts(RSDisplayRenderNode& node, const sptr<RSScreenManager>& screenManager);
    void CheckPixelFormat(RSSurfaceRenderNode& node);
    void HandlePixelFormat(RSDisplayRenderNode& node, const sptr<RSScreenManager>& screenManager);
    void AddOverDrawListener(std::unique_ptr<RSRenderFrame>& renderFrame,
        std::shared_ptr<RSCanvasListener>& overdrawListener);
    /* Judge if surface render node could skip preparation:
     * 1. not leash window
     * 2. parent not dirty
     * 3. no processWithCommands_ of node's corresponding pid
     * If so, reset status flag and stop traversal
     */
    bool CheckIfSurfaceRenderNodeStatic(RSSurfaceRenderNode& node);
    /* Judge if uifirst surface render node could skip subtree preparation:
     * mainwindow check if it has leashwindow parent
     * If so, check parent or check itself
     */
    bool CheckIfUIFirstSurfaceContentReusable(std::shared_ptr<RSSurfaceRenderNode>& node);

    void PrepareTypesOfSurfaceRenderNodeBeforeUpdate(RSSurfaceRenderNode& node);
    void PrepareTypesOfSurfaceRenderNodeAfterUpdate(RSSurfaceRenderNode& node);
    // judge if node's cache changes
    // return false if cache static and simplify its subtree traversal
    bool UpdateCacheChangeStatus(RSRenderNode& node);
    bool IsDrawingCacheStatic(RSRenderNode& node);
    // if cache root reuses, update its subtree
    // [attention] check curSurfaceDirtyManager_ before function calls
    void UpdateStaticCacheSubTree(const std::shared_ptr<RSRenderNode>& cacheRootNode,
        const std::list<RSRenderNode::SharedPtr>& children);
    void UpdateStaticCacheSubTreeSetState(const std::shared_ptr<RSRenderNode>& child);
    void UpdateStaticCacheSubTreeFilter(const std::shared_ptr<RSRenderNode>& child);
    // set node cacheable animation after checking whold child tree
    void SetNodeCacheChangeStatus(RSRenderNode& node);
    void DisableNodeCacheInSetting(RSRenderNode& node);
    // update rendernode's cache status and collect valid cache rect
    void UpdateForegroundFilterCacheWithDirty(RSRenderNode& node, RSDirtyRegionManager& dirtyManager);

    bool IsHardwareComposerEnabled();

    // choose to keep filter cache if node is filter occluded
    bool CheckIfSurfaceRenderNodeNeedProcess(RSSurfaceRenderNode& node, bool& keepFilterCache);

    void ClearTransparentBeforeSaveLayer();
    // mark surfaceNode's child surfaceView nodes hardware forced disabled
    void MarkSubHardwareEnableNodeState(RSSurfaceRenderNode& surfaceNode);
    void CollectAppNodeForHwc(std::shared_ptr<RSSurfaceRenderNode> surfaceNode);
    void UpdateSecurityAndSkipLayerRecord(RSSurfaceRenderNode& node);
    void PrepareEffectNodeIfCacheReuse(const std::shared_ptr<RSRenderNode>& cacheRootNode,
        std::shared_ptr<RSEffectRenderNode> effectNode);

    // offscreen render related
    void PrepareOffscreenRender(RSRenderNode& node);
    void FinishOffscreenRender(bool isMirror = false);
    void ParallelPrepareDisplayRenderNodeChildrens(RSDisplayRenderNode& node);
    bool AdaptiveSubRenderThreadMode(bool doParallel);
    void ParallelRenderEnableHardwareComposer(RSSurfaceRenderNode& node);
    // close partialrender when perform window animation
    void ClosePartialRenderWhenAnimatingWindows(std::shared_ptr<RSDisplayRenderNode>& node);
    bool DrawBlurInCache(RSRenderNode& node);
    void UpdateCacheRenderNodeMapWithBlur(RSRenderNode& node);
    bool IsFirstVisitedCacheForced() const;
    bool IsRosenWebHardwareDisabled(RSSurfaceRenderNode& node, int rotation) const;
#ifndef USE_ROSEN_DRAWING
    sk_sp<SkImage> GetCacheImageFromMirrorNode(std::shared_ptr<RSDisplayRenderNode> mirrorNode);
#else
    std::shared_ptr<Drawing::Image> GetCacheImageFromMirrorNode(std::shared_ptr<RSDisplayRenderNode> mirrorNode);
#endif

    void SwitchColorFilterDrawing(int currentSaveCount);
    void ProcessShadowFirst(RSRenderNode& node, bool inSubThread);
    void SaveCurSurface(std::shared_ptr<RSDirtyRegionManager> dirtyManager,
        std::shared_ptr<RSSurfaceRenderNode> surfaceNode);
    void RestoreCurSurface(std::shared_ptr<RSDirtyRegionManager> &dirtyManager,
        std::shared_ptr<RSSurfaceRenderNode> &surfaceNode);
    void PrepareSubSurfaceNodes(RSSurfaceRenderNode& node);
    void ProcessSubSurfaceNodes(RSSurfaceRenderNode& node);

#ifndef USE_ROSEN_DRAWING
    sk_sp<SkSurface> offscreenSurface_;                 // temporary holds offscreen surface
#else
    std::shared_ptr<Drawing::Surface> offscreenSurface_;                 // temporary holds offscreen surface
#endif
    std::shared_ptr<RSPaintFilterCanvas> canvasBackup_; // backup current canvas before offscreen render

    // Use in vulkan parallel rendering
    void ProcessParallelDisplayRenderNode(RSDisplayRenderNode& node);

    ScreenInfo screenInfo_;
    std::shared_ptr<RSDirtyRegionManager> curSurfaceDirtyManager_;
    std::shared_ptr<RSSurfaceRenderNode> curSurfaceNode_;
    std::stack<std::shared_ptr<RSDirtyRegionManager>> surfaceDirtyManager_;
    std::stack<std::shared_ptr<RSSurfaceRenderNode>> surfaceNode_;
    float curAlpha_ = 1.f;
    Vector4f curCornerRadius_{ 0.f, 0.f, 0.f, 0.f };
    bool dirtyFlag_ { false };
    std::unique_ptr<RSRenderFrame> renderFrame_;
    std::shared_ptr<RSPaintFilterCanvas> canvas_;
    std::map<NodeId, std::shared_ptr<RSSurfaceRenderNode>> dirtySurfaceNodeMap_;
    std::vector<RectI> cacheRenderNodeMapRects_;
#ifndef USE_ROSEN_DRAWING
    SkRect boundsRect_ {};
#else
    Drawing::Rect boundsRect_ {};
#endif
    Gravity frameGravity_ = Gravity::DEFAULT;

    int32_t offsetX_ { 0 };
    int32_t offsetY_ { 0 };
    std::shared_ptr<RSProcessor> processor_;
#ifndef USE_ROSEN_DRAWING
    SkMatrix parentSurfaceNodeMatrix_;
#else
    Drawing::Matrix parentSurfaceNodeMatrix_;
#endif

    ScreenId currentVisitDisplay_ = INVALID_SCREEN_ID;
    std::map<ScreenId, bool> displayHasSecSurface_;
    std::map<ScreenId, bool> displayHasSkipSurface_;
    std::map<ScreenId, bool> hasCaptureWindow_;
    std::set<ScreenId> mirroredDisplays_;
    bool isSecurityDisplay_ = false;

    bool hasFingerprint_ = false;

    std::shared_ptr<RSBaseRenderEngine> renderEngine_;

    std::shared_ptr<RSDirtyRegionManager> curDisplayDirtyManager_;
    std::shared_ptr<RSDisplayRenderNode> curDisplayNode_;
    bool doAnimate_ = false;
    bool isSurfaceRotationChanged_ = false;
    bool isPartialRenderEnabled_ = false;
    bool isOpDropped_ = false;
    bool isDirtyRegionDfxEnabled_ = false; // dirtyRegion DFX visualization
    bool isTargetDirtyRegionDfxEnabled_ = false;
    bool isOpaqueRegionDfxEnabled_ = false;
    bool isVisibleRegionDfxEnabled_ = false;
    bool isDisplayDirtyDfxEnabled_ = false;
    bool isCanvasNodeSkipDfxEnabled_ = false;
    bool isQuickSkipPreparationEnabled_ = false;
    bool isOcclusionEnabled_ = false;
    bool isScreenRotationAnimating_ = false;
    bool isTextNeedCached_ = false;
    std::vector<std::string> dfxTargetSurfaceNames_;
    PartialRenderType partialRenderType_;
    QuickSkipPrepareType quickSkipPrepareType_;
    DirtyRegionDebugType dirtyRegionDebugType_;
    SurfaceRegionDebugType surfaceRegionDebugType_;
    bool isRegionDebugEnabled_ = false;
    bool isDirty_ = false;
    // added for judge if drawing cache changes
    bool isDrawingCacheEnabled_ = false;
    std::stack<bool> isDrawingCacheChanged_ = {};
    std::vector<RectI> accumulatedDirtyRegions_ = {};
    bool isSubSurfaceEnabled_ = false;
#ifdef DDGR_ENABLE_FEATURE_OPINC
    bool autoCacheEnable_ = false;
    bool autoCacheChildDisable_ = false;
    bool autoCacheDrawingEnable_ = false;
    RSRenderNode::RSAutoCache::NodeStragyType nodeCacheType_ = RSRenderNode::RSAutoCache::CACHE_NONE;
    bool unchangeMark_ = false;
    bool isDiscardSurface_ = true;
    std::vector<std::pair<RectI, std::string>> autoCacheRenderNodeInfos_;
    int opNodeDepth_ = 0;
    bool opIncSubtreePropDirty_ = false;
    Drawing::Rect opincRootRect_;
#endif

    bool needFilter_ = false;
    GraphicColorGamut newColorSpace_ = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    GraphicPixelFormat newPixelFormat_ = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_8888;
    std::vector<ScreenColorGamut> colorGamutModes_;
    uint64_t currentFocusedNodeId_ = 0;
    uint64_t focusedLeashWindowId_ = 0;

    bool isSubThread_ = false;
    bool isUIFirst_ = false;
    uint32_t threadIndex_ = UNI_MAIN_THREAD_INDEX;
    // check each surface could be reused per frame
    // currently available to uiFirst
    bool isCachedSurfaceReuse_ = false;
    uint32_t effectNodeNum_ = 0;

    bool isDirtyRegionAlignedEnable_ = false;
    std::shared_ptr<std::mutex> surfaceNodePrepareMutex_;
#if defined(RS_ENABLE_PARALLEL_RENDER)
    uint32_t parallelRenderVisitorIndex_ = 0;
#endif
    ParallelRenderingType parallelRenderType_;

    RectI prepareClipRect_{0, 0, 0, 0}; // renderNode clip rect used in Prepare

    // count prepared and processed canvasnode numbers per app
    // unirender visitor resets every frame, no overflow risk here
    unsigned int preparedCanvasNodeInCurrentSurface_ = 0;
    unsigned int processedCanvasNodeInCurrentSurface_ = 0;
    unsigned int processedPureContainerNode_ = 0;

    float globalZOrder_ = 0.0f;
    bool isUpdateCachedSurface_ = false;
    bool isHardwareForcedDisabled_ = false; // indicates if hardware composer is totally disabled
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledNodes_;
    // vector of all app window nodes with surfaceView, sorted by zOrder
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> appWindowNodesInZOrder_;
    // vector of hardwareEnabled nodes above displayNodeSurface like pointer window
    std::vector<std::shared_ptr<RSSurfaceRenderNode>> hardwareEnabledTopNodes_;
    float localZOrder_ = 0.0f; // local zOrder for surfaceView under same app window node

    // driven render
    std::unique_ptr<DrivenInfo> drivenInfo_ = nullptr;
    std::unique_ptr<RcdInfo> rcdInfo_ = nullptr;

    std::unordered_map<NodeId, RenderParam> unpairedTransitionNodes_;
    std::stack<RenderParam> curGroupedNodes_;
    // return true if we should prepare/process, false if we should skip.
    void PrepareSharedTransitionNode(RSBaseRenderNode& node);
    bool ProcessSharedTransitionNode(RSBaseRenderNode& node);
    void ProcessUnpairedSharedTransitionNode();

    std::weak_ptr<RSBaseRenderNode> logicParentNode_;

#if defined(RS_ENABLE_PARALLEL_RENDER)
    bool isCalcCostEnable_ = false;
#endif
    // adapt to sceneboard, mark if the canvasNode within the scope of surfaceNode
    bool isSubNodeOfSurfaceInPrepare_ = false;
    bool isSubNodeOfSurfaceInProcess_ = false;

    uint32_t appWindowNum_ = 0;

    bool isParallel_ = false;
#if defined(RS_ENABLE_PARALLEL_RENDER)
    bool doParallelRender_ = false;
#endif
    // displayNodeMatrix only used in offScreen render case to ensure correct composer layer info when with rotation,
    // displayNodeMatrix indicates display node's matrix info
#ifndef USE_ROSEN_DRAWING
    std::optional<SkMatrix> displayNodeMatrix_;
#else
    std::optional<Drawing::Matrix> displayNodeMatrix_;
#endif
    mutable std::mutex copyVisitorInfosMutex_;
    bool resetRotate_ = false;
#ifndef USE_ROSEN_DRAWING
    std::optional<SkPath> effectRegion_ = std::nullopt;
#else
    std::optional<Drawing::Path> effectRegion_ = std::nullopt;
#endif
    bool curDirty_ = false;
    bool curContentDirty_ = false;
    bool isPhone_ = false;
    bool isCacheBlurPartialRenderEnabled_ = false;
    bool drawCacheWithBlur_ = false;
    bool noNeedTodrawShadowAgain_ = false;
    bool notRunCheckAndSetNodeCacheType_ = false;
    int updateCacheProcessCnt_ = 0;

    NodeId firstVisitedCache_ = INVALID_NODEID;
    std::unordered_set<NodeId> visitedCacheNodeIds_ = {};
    std::unordered_map<NodeId, std::unordered_set<NodeId>> allCacheFilterRects_ = {};
    std::stack<std::unordered_set<NodeId>> curCacheFilterRects_ = {};
    bool forceUpdateFlag_ = false;
#ifdef ENABLE_RECORDING_DCL
#ifndef USE_ROSEN_DRAWING
    void tryCapture(float width, float height);
    void endCapture() const;
    std::shared_ptr<RSRecordingCanvas> recordingCanvas_;
#else
    void tryCapture(float width, float height);
    void endCapture() const;
    std::shared_ptr<Drawing::RecordingCanvas> recordingCanvas_;
#endif
#endif
    bool isNodeSingleFrameComposer_ = false;

    // use for screen recording optimization
#ifndef USE_ROSEN_DRAWING
    sk_sp<SkImage> cacheImgForCapture_ = nullptr;
#else
    std::shared_ptr<Drawing::Image> cacheImgForCapture_ = nullptr;
#endif
    // attention: please synchronize the change of RSUniRenderVisitor::ProcessChildren to this func
    void ProcessChildrenForScreenRecordingOptimization(RSDisplayRenderNode& node, NodeId rootIdOfCaptureWindow);
    NodeId FindInstanceChildOfDisplay(std::shared_ptr<RSRenderNode> node);
    bool CheckIfNeedResetRotate();
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CORE_PIPELINE_RS_UNI_RENDER_VISITOR_H
