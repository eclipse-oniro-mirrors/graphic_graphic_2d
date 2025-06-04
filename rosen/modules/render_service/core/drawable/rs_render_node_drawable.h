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

#ifndef RENDER_SERVICE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_H
#define RENDER_SERVICE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_H

#include <memory>
#include <vector>

#include "common/rs_common_def.h"
#include "draw/canvas.h"
#include "draw/surface.h"
#include "drawable/rs_render_node_drawable_adapter.h"
#include "feature/opinc/rs_opinc_draw_cache.h"
#include "image/gpu_context.h"
#include "pipeline/rs_render_node.h"

#ifdef RS_ENABLE_VK
#include "platform/ohos/backend/native_buffer_utils.h"
#endif
#include "pipeline/rs_paint_filter_canvas.h"

namespace OHOS::Rosen {
class RSRenderNode;
class RSRenderParams;
class RSPaintFilterCanvas;
namespace NativeBufferUtils {
class VulkanCleanupHelper;
}
namespace DrawableV2 {
// Used by RSUniRenderThread and RSChildrenDrawable
class RSRenderNodeDrawable : public RSRenderNodeDrawableAdapter {
public:
    ~RSRenderNodeDrawable() override;

    static RSRenderNodeDrawable::Ptr OnGenerate(std::shared_ptr<const RSRenderNode> node);

    void Draw(Drawing::Canvas& canvas) override;
    virtual void OnDraw(Drawing::Canvas& canvas);
    virtual void OnCapture(Drawing::Canvas& canvas);

    // deprecated
    inline std::shared_ptr<const RSRenderNode> GetRenderNode()
    {
        return renderNode_.lock();
    }

    inline bool GetOpDropped() const
    {
        return isOpDropped_;
    }

    inline bool IsOcclusionCullingEnabled() const
    {
        return occlusionCullingEnabled_;
    }

    inline void SetOcclusionCullingEnabled(bool enabled)
    {
        occlusionCullingEnabled_ = enabled;
    }

    bool ShouldPaint() const;

    static int GetTotalProcessedNodeCount();
    static void TotalProcessedNodeCountInc();
    static void ClearTotalProcessedNodeCount();
    static int GetSnapshotProcessedNodeCount();
    static void SnapshotProcessedNodeCountInc();
    static void ClearSnapshotProcessedNodeCount();

    // opinc dfx
    std::string GetNodeDebugInfo();

    void SetCacheImageByCapture(std::shared_ptr<Drawing::Image> image);

    std::shared_ptr<Drawing::Image> GetCacheImageByCapture() const;

    // dfx
    static void InitDfxForCacheInfo();
    static void DrawDfxForCacheInfo(RSPaintFilterCanvas& canvas, const std::unique_ptr<RSRenderParams>& params);

    RSOpincDrawCache& GetOpincDrawCache()
    {
        return opincDrawCache_;
    }
protected:
    explicit RSRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node);
    using Registrar = RenderNodeDrawableRegistrar<RSRenderNodeType::RS_NODE, OnGenerate>;
    static Registrar instance_;

    // Only use in RSRenderNode::DrawCacheSurface to calculate scale factor
    float boundsWidth_ = 0.0f;
    float boundsHeight_ = 0.0f;

    void GenerateCacheIfNeed(Drawing::Canvas& canvas, RSRenderParams& params);
    void CheckCacheTypeAndDraw(Drawing::Canvas& canvas, const RSRenderParams& params, bool isInCapture = false);

    static inline bool isDrawingCacheEnabled_ = false;
    static inline bool isDrawingCacheDfxEnabled_ = false;
    static inline std::mutex drawingCacheInfoMutex_;
    static inline std::unordered_map<NodeId, std::pair<RectI, int32_t>> drawingCacheInfos_; // (id, <rect, updateTimes>)
    static inline std::unordered_map<NodeId, bool> cacheUpdatedNodeMap_;

    static inline bool autoCacheDrawingEnable_ = false;
    static inline std::vector<std::pair<RectI, std::string>> autoCacheRenderNodeInfos_;
    thread_local static inline bool isOpincDropNodeExt_ = true;
    thread_local static inline int opincRootTotalCount_ = 0;

    static inline int32_t offsetX_ = 0;
    static inline int32_t offsetY_ = 0;
    static inline ScreenId curDisplayScreenId_ = INVALID_SCREEN_ID;

    // used for render group cache
    void SetCacheType(DrawableCacheType cacheType);
    DrawableCacheType GetCacheType() const;
    void UpdateCacheInfoForDfx(Drawing::Canvas& canvas, const Drawing::Rect& rect, NodeId id);

    std::shared_ptr<Drawing::Surface> GetCachedSurface(pid_t threadId) const;
    void InitCachedSurface(Drawing::GPUContext* gpuContext, const Vector2f& cacheSize, pid_t threadId,
        bool isNeedFP16 = false, GraphicColorGamut colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB);
    bool NeedInitCachedSurface(const Vector2f& newSize);
    std::shared_ptr<Drawing::Image> GetCachedImage(RSPaintFilterCanvas& canvas);
    void DrawCachedImage(RSPaintFilterCanvas& canvas, const Vector2f& boundSize,
    const std::shared_ptr<RSFilter>& rsFilter = nullptr);
    void ClearCachedSurface();

    bool CheckIfNeedUpdateCache(RSRenderParams& params, int32_t& updateTimes);
    void UpdateCacheSurface(Drawing::Canvas& canvas, const RSRenderParams& params);
    void TraverseSubTreeAndDrawFilterWithClip(Drawing::Canvas& canvas, const RSRenderParams& params);

    static int GetProcessedNodeCount();
    static void ProcessedNodeCountInc();
    static void ClearProcessedNodeCount();
    static thread_local bool drawBlurForCache_;

private:
    std::atomic<DrawableCacheType> cacheType_ = DrawableCacheType::NONE;
    mutable std::recursive_mutex cacheMutex_;
    mutable std::mutex freezeByCaptureMutex_;
    std::shared_ptr<Drawing::Surface> cachedSurface_ = nullptr;
    std::shared_ptr<Drawing::Image> cachedImage_ = nullptr;
    std::shared_ptr<Drawing::Image> cachedImageByCapture_ = nullptr;
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    Drawing::BackendTexture cachedBackendTexture_;
#ifdef RS_ENABLE_VK
    NativeBufferUtils::VulkanCleanupHelper* vulkanCleanupHelper_ = nullptr;
#endif
#endif
    // surface thread id, cachedImage_ will update context when image can be reused.
    std::atomic<pid_t> cacheThreadId_;

    static inline std::mutex drawingCacheMapMutex_;
    static inline std::unordered_map<NodeId, int32_t> drawingCacheUpdateTimeMap_;
    static inline std::mutex drawingCacheContiUpdateTimeMapMutex_;
    static inline std::unordered_map<NodeId, int32_t> drawingCacheContinuousUpdateTimeMap_;

    static thread_local bool isOpDropped_;
    static thread_local bool occlusionCullingEnabled_;
    static thread_local bool isOffScreenWithClipHole_;
    static inline std::atomic<int> totalProcessedNodeCount_ = 0;
    static inline int snapshotProcessedNodeCount_ = 0;
    static thread_local inline int processedNodeCount_ = 0;
    // used foe render group cache

    void DrawWithoutNodeGroupCache(
        Drawing::Canvas& canvas, const RSRenderParams& params, DrawableCacheType originalCacheType);
    void DrawWithNodeGroupCache(Drawing::Canvas& canvas, const RSRenderParams& params);

    void CheckRegionAndDrawWithoutFilter(
        const std::vector<FilterNodeInfo>& filterInfoVec, Drawing::Canvas& canvas, const RSRenderParams& params);
    void CheckRegionAndDrawWithFilter(std::vector<FilterNodeInfo>::const_iterator& begin,
        const std::vector<FilterNodeInfo>& filterInfoVec, Drawing::Canvas& canvas, const RSRenderParams& params);
    bool IsIntersectedWithFilter(std::vector<FilterNodeInfo>::const_iterator& begin,
        const std::vector<FilterNodeInfo>& filterInfoVec,
        Drawing::RectI& dstRect);
    void ClearDrawingCacheDataMap();
    void ClearDrawingCacheContiUpdateTimeMap();
    friend class RsSubThreadCache;
    RSOpincDrawCache opincDrawCache_;

    // Used to skip nodes or entire subtree that were culled by the control-level occlusion.
    bool SkipCulledNodeOrEntireSubtree(Drawing::Canvas& canvas, Drawing::Rect& bounds);
};
} // namespace DrawableV2
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_H
