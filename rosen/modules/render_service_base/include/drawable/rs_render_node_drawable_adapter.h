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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_ADAPTER_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_ADAPTER_H

#include <map>
#include <memory>
#include <mutex>

#include "common/rs_common_def.h"
#include "common/rs_macros.h"
#include "common/rs_rect.h"
#include "recording/recording_canvas.h"
#include "pipeline/rs_render_content.h"
#include "utils/rect.h"

#ifndef ROSEN_CROSS_PLATFORM
#include <iconsumer_surface.h>
#endif

namespace OHOS::Rosen {
class RSRenderNode;
class RSRenderParams;
class RSDisplayRenderNode;
class RSSurfaceRenderNode;
class RSSurfaceHandler;
namespace Drawing {
class Canvas;
}

struct DrawCmdIndex {
    int8_t shadowIndex_                = -1;
    int8_t renderGroupBeginIndex_      = -1;
    int8_t foregroundFilterBeginIndex_ = -1;
    int8_t backgroundColorIndex_       = -1;
    int8_t backgroundImageIndex_       = -1;
    int8_t backgroundFilterIndex_      = -1;
    int8_t useEffectIndex_             = -1;
    int8_t backgroundEndIndex_         = -1;
    int8_t childrenIndex_              = -1;
    int8_t contentIndex_               = -1;
    int8_t foregroundBeginIndex_       = -1;
    int8_t renderGroupEndIndex_        = -1;
    int8_t foregroundFilterEndIndex_   = -1;
    int8_t endIndex_                   = -1;
};
namespace DrawableV2 {
enum class SkipType : uint8_t {
    NONE = 0,
    SKIP_SHADOW = 1,
    SKIP_BACKGROUND_COLOR = 2
};

class RSB_EXPORT RSRenderNodeDrawableAdapter : public std::enable_shared_from_this<RSRenderNodeDrawableAdapter> {
public:
    explicit RSRenderNodeDrawableAdapter(std::shared_ptr<const RSRenderNode>&& node);
    virtual ~RSRenderNodeDrawableAdapter();

    // delete
    RSRenderNodeDrawableAdapter(const RSRenderNodeDrawableAdapter&) = delete;
    RSRenderNodeDrawableAdapter(const RSRenderNodeDrawableAdapter&&) = delete;
    RSRenderNodeDrawableAdapter& operator=(const RSRenderNodeDrawableAdapter&) = delete;
    RSRenderNodeDrawableAdapter& operator=(const RSRenderNodeDrawableAdapter&&) = delete;

    using Ptr = RSRenderNodeDrawableAdapter*;
    using SharedPtr = std::shared_ptr<RSRenderNodeDrawableAdapter>;
    using WeakPtr = std::weak_ptr<RSRenderNodeDrawableAdapter>;

    virtual void Draw(Drawing::Canvas& canvas) = 0;

    static SharedPtr OnGenerate(const std::shared_ptr<const RSRenderNode>& node);
    static SharedPtr GetDrawableById(NodeId id);
    static SharedPtr OnGenerateShadowDrawable(
        const std::shared_ptr<const RSRenderNode>& node, const std::shared_ptr<RSRenderNodeDrawableAdapter>& drawable);

    inline const std::unique_ptr<RSRenderParams>& GetRenderParams() const
    {
        return renderParams_;
    }

    inline const std::unique_ptr<RSRenderParams>& GetUifirstRenderParams() const
    {
        return uifirstRenderParams_;
    }

    inline NodeId GetId() const
    {
        return nodeId_;
    }
    inline RSRenderNodeType GetNodeType() const
    {
        return nodeType_;
    }
    virtual std::shared_ptr<RSDirtyRegionManager> GetSyncDirtyManager() const
    {
        return nullptr;
    }

    using ClearSurfaceTask = std::function<void()>;
    void RegisterClearSurfaceFunc(ClearSurfaceTask task);
    void ResetClearSurfaceFunc();
    void TryClearSurfaceOnSync();

#ifndef ROSEN_CROSS_PLATFORM
    virtual void RegisterDeleteBufferListenerOnSync(sptr<IConsumerSurface> consumer) {}
#endif

    virtual bool IsDrawCmdListsVisited() const
    {
        return true;
    }
    virtual void SetDrawCmdListsVisited(bool flag) {}
    void SetSkip(SkipType type) { skipType_ = type; }
    SkipType GetSkipType() { return skipType_; }
protected:
    // Util functions
    bool QuickReject(Drawing::Canvas& canvas, const RectF& localDrawRect);
    bool HasFilterOrEffect() const;

    // Draw functions
    void DrawAll(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawUifirstContentChildren(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawBackground(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawContent(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawChildren(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawForeground(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;

    // used for foreground filter
    void DrawBeforeCacheWithForegroundFilter(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawCacheWithForegroundFilter(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawAfterCacheWithForegroundFilter(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;

    // used for render group
    void DrawBackgroundWithoutFilterAndEffect(Drawing::Canvas& canvas, const RSRenderParams& params);
    void DrawCacheWithProperty(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawBeforeCacheWithProperty(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;
    void DrawAfterCacheWithProperty(Drawing::Canvas& canvas, const Drawing::Rect& rect) const;

    // Note, the start is included, the end is excluded, so the range is [start, end)
    void DrawRangeImpl(Drawing::Canvas& canvas, const Drawing::Rect& rect, int8_t start, int8_t end) const;
    void DrawImpl(Drawing::Canvas& canvas, const Drawing::Rect& rect, int8_t index) const;

    // Register utils
    using Generator = Ptr (*)(std::shared_ptr<const RSRenderNode>);
    template<RSRenderNodeType type, Generator generator>
    class RenderNodeDrawableRegistrar {
    public:
        RenderNodeDrawableRegistrar()
        {
            RSRenderNodeDrawableAdapter::GeneratorMap.emplace(type, generator);
        }
    };

    const RSRenderNodeType nodeType_;
    // deprecated
    std::weak_ptr<const RSRenderNode> renderNode_;
    NodeId nodeId_;

    DrawCmdIndex uifirstDrawCmdIndex_;
    DrawCmdIndex drawCmdIndex_;
    std::unique_ptr<RSRenderParams> renderParams_;
    std::unique_ptr<RSRenderParams> uifirstRenderParams_;
    std::vector<Drawing::RecordingCanvas::DrawFunc> uifirstDrawCmdList_;
    std::vector<Drawing::RecordingCanvas::DrawFunc> drawCmdList_;
    std::vector<Drawing::RectI> filterRects_;
#ifdef ROSEN_OHOS
    static thread_local RSRenderNodeDrawableAdapter* curDrawingCacheRoot_;
#else
    static RSRenderNodeDrawableAdapter* curDrawingCacheRoot_;
#endif
    ClearSurfaceTask clearSurfaceTask_ = nullptr;
private:
    static void InitRenderParams(const std::shared_ptr<const RSRenderNode>& node,
                            std::shared_ptr<RSRenderNodeDrawableAdapter>& sharedPtr);
    static std::map<RSRenderNodeType, Generator> GeneratorMap;
    static std::map<NodeId, WeakPtr> RenderNodeDrawableCache_;
    static inline std::mutex cacheMapMutex_;
    SkipType skipType_ = SkipType::NONE;
    int8_t GetSkipIndex() const;

    friend class OHOS::Rosen::RSRenderNode;
    friend class OHOS::Rosen::RSDisplayRenderNode;
    friend class OHOS::Rosen::RSSurfaceRenderNode;
    friend class RSRenderNodeShadowDrawable;
    friend class RSUseEffectDrawable;
};

} // namespace DrawableV2
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_ADAPTER_H