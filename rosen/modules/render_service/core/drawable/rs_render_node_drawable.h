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

#include "draw/canvas.h"
#include "drawable/rs_render_node_drawable_adapter.h"
#include "common/rs_rect.h"

namespace OHOS::Rosen {
class RSRenderNode;
class RSRenderParams;
class RSPaintFilterCanvas;
namespace NativeBufferUtils {
class VulkanCleanupHelper;
}
enum class ReplayType : uint8_t {
    // Default
    REPLAY_ALL,
    // Shadow batching
    REPLAY_ONLY_SHADOW,
    REPLAY_ALL_EXCEPT_SHADOW,
    // For surface render node
    REPLAY_BG_ONLY,
    REPLAY_FG_ONLY,
    REPLAY_ONLY_CONTENT,
};

// Used by RSUniRenderThread and RSChildrenDrawable
class RSRenderNodeDrawable : public RSRenderNodeDrawableAdapter {
public:
    explicit RSRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node);
    ~RSRenderNodeDrawable() override;

    static RSRenderNodeDrawable::Ptr OnGenerate(std::shared_ptr<const RSRenderNode> node);
    void Draw(Drawing::Canvas& canvas) override;

    virtual void OnDraw(Drawing::Canvas& canvas);
    virtual void OnCapture(Drawing::Canvas& canvas);

    void DrawWithoutShadow(Drawing::Canvas& canvas) override;
    void DrawShadow(Drawing::Canvas& canvas) override;
    void DumpDrawableTree(int32_t depth, std::string& out) const override;

protected:
    using Registrar = RenderNodeDrawableRegistrar<RSRenderNodeType::RS_NODE, OnGenerate>;
    static Registrar instance_;

    void DrawBackground(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawContent(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawChildren(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawForeground(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;

    void GenerateCacheIfNeed(Drawing::Canvas& canvas, RSRenderParams& params);
    void CheckCacheTypeAndDraw(Drawing::Canvas& canvas, const RSRenderParams& params);
    bool HasFilterOrEffect() const;

    static inline bool isDrawingCacheEnabled_ = false;
    static inline bool isDrawingCacheDfxEnabled_ = false;
    static inline std::vector<RectI> drawingCacheRects_;
private:
    std::string DumpDrawableVec() const;
    void DrawRangeImpl(Drawing::Canvas& canvas, const Drawing::Rect& rect, int8_t start, int8_t end) const;

    // used foe render group cache
    void SetCacheType(DrawableCacheType cacheType);
    DrawableCacheType GetCacheType() const;
    void DrawBackgroundWithoutFilterAndEffect(Drawing::Canvas& canvas, const RSRenderParams& params) const;
    void DrawDfxForCache(Drawing::Canvas& canvas, const Drawing::Rect& rect);

    std::shared_ptr<Drawing::Surface> GetCachedSurface(pid_t threadId) const;
    void InitCachedSurface(Drawing::GPUContext* gpuContext, const Vector2f& cacheSize, pid_t threadId);
    bool NeedInitCachedSurface(const Vector2f& newSize);
    std::shared_ptr<Drawing::Image> GetCachedImage(RSPaintFilterCanvas& canvas, pid_t threadId);
    void DrawCachedSurface(RSPaintFilterCanvas& canvas, const Vector2f& boundSize, pid_t threadId);
    void ClearCachedSurface();

    bool CheckIfNeedUpdateCache(RSRenderParams& params);
    void UpdateCacheSurface(Drawing::Canvas& canvas, const RSRenderParams& params);

    DrawableCacheType cacheType_ = DrawableCacheType::NONE;
    mutable std::recursive_mutex cacheMutex_;
    std::shared_ptr<Drawing::Surface> cachedSurface_ = nullptr;
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    Drawing::BackendTexture cachedBackendTexture_;
#ifdef RS_ENABLE_VK
    NativeBufferUtils::VulkanCleanupHelper* vulkanCleanupHelper_ = nullptr;
#endif
#endif
    std::atomic<pid_t> cacheThreadId_;

    static inline std::mutex drawingCacheMapMutex_;
    static inline std::unordered_map<NodeId, int32_t> drawingCacheUpdateTimeMap_;

    static inline bool isOpDropped_ = true;
    static inline bool drawBlurForCache_ = false;
    // used foe render group cache
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_H
