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

#ifndef ROSEN_RENDER_SERVICE_BASE_PIPELINE_RS_CONTEXT_H
#define ROSEN_RENDER_SERVICE_BASE_PIPELINE_RS_CONTEXT_H

#include <cstdint>
#include "common/rs_macros.h"
#ifndef ROSEN_CROSS_PLATFORM
#include "iconsumer_surface.h"
#include "surface_buffer.h"
#include "sync_fence.h"
#endif
#include "animation/rs_render_interactive_implict_animator_map.h"
#include "pipeline/rs_render_node_map.h"
#include "pipeline/rs_render_frame_rate_linker_map.h"

namespace OHOS {
namespace Rosen {
enum ClearMemoryMoment : uint32_t {
    FILTER_INVALID = 0,
    PROCESS_EXIT,
    COMMON_SURFACE_NODE_HIDE,
    SCENEBOARD_SURFACE_NODE_HIDE,
    LOW_MEMORY,
    NO_CLEAR,
    DEFAULT_CLEAN,
};

class RSB_EXPORT RSContext : public std::enable_shared_from_this<RSContext> {
public:
    RSContext() = default;
    ~RSContext() = default;
    RSContext(const RSContext&) = delete;
    RSContext(const RSContext&&) = delete;
    RSContext& operator=(const RSContext&) = delete;
    RSContext& operator=(const RSContext&&) = delete;

#ifndef ROSEN_CROSS_PLATFORM
    struct BufferInfo {
        const sptr<SurfaceBuffer> buffer;
        const sptr<IConsumerSurface> consumer;
        bool useFence = false;
    };
#endif

    enum PurgeType {
        NONE,
        GENTLY,
        STRONGLY
    };

    RSRenderNodeMap& GetMutableNodeMap()
    {
        return nodeMap;
    }

    const RSRenderNodeMap& GetNodeMap() const
    {
        return nodeMap;
    }

    RSRenderFrameRateLinkerMap& GetMutableFrameRateLinkerMap()
    {
        return frameRateLinkerMap;
    }

    const RSRenderFrameRateLinkerMap& GetFrameRateLinkerMap() const
    {
        return frameRateLinkerMap;
    }

    const std::shared_ptr<RSBaseRenderNode>& GetGlobalRootRenderNode() const
    {
        return globalRootRenderNode_;
    }

    RSRenderInteractiveImplictAnimatorMap& GetInteractiveImplictAnimatorMap()
    {
        return interactiveImplictAnimatorMap_;
    }

#ifndef ROSEN_CROSS_PLATFORM
    std::vector<BufferInfo>& GetMutableSkipSyncBuffer()
    {
        return skipSyncBuffer_;
    }
#endif

    void RegisterAnimatingRenderNode(const std::shared_ptr<RSRenderNode>& nodePtr);
    void UnregisterAnimatingRenderNode(NodeId id);

    uint64_t GetTransactionTimestamp() const
    {
        return transactionTimestamp_;
    }

    uint64_t GetCurrentTimestamp() const
    {
        return currentTimestamp_;
    }
    // add node info after cmd data process
    void AddActiveNode(const std::shared_ptr<RSRenderNode>& node);
    bool HasActiveNode(const std::shared_ptr<RSRenderNode>& node);

    void AddPendingSyncNode(const std::shared_ptr<RSRenderNode> node);

    void MarkNeedPurge(ClearMemoryMoment moment, PurgeType purgeType);

    void SetVsyncRequestFunc(const std::function<void()>& taskRunner)
    {
        vsyncRequestFunc_ = taskRunner;
    }

    void RequestVsync() const
    {
        if (vsyncRequestFunc_) {
            vsyncRequestFunc_();
        }
    }

    void SetTaskRunner(const std::function<void(const std::function<void()>&, bool)>& taskRunner)
    {
        taskRunner_ = taskRunner;
    }
    void PostTask(const std::function<void()>& task, bool isSyncTask = false) const
    {
        if (taskRunner_) {
            taskRunner_(task, isSyncTask);
        }
    }

    void SetRTTaskRunner(const std::function<void(const std::function<void()>&)>& taskRunner)
    {
        rttaskRunner_ = taskRunner;
    }

    void PostRTTask(const std::function<void()>& task) const
    {
        if (rttaskRunner_) {
            rttaskRunner_(task);
        }
    }

    void SetClearMoment(ClearMemoryMoment moment);
    ClearMemoryMoment GetClearMoment() const;

    void SetRequestedNextVsyncAnimate(bool requestedNextVsyncAnimate)
    {
        requestedNextVsyncAnimate_ = requestedNextVsyncAnimate;
    }

    bool IsRequestedNextVsyncAnimate() const
    {
        return requestedNextVsyncAnimate_;
    }

    // save some need sync finish to client animations in list
    void AddSyncFinishAnimationList(NodeId nodeId, AnimationId animationId);
private:
    // This function is used for initialization, should be called once after constructor.
    void Initialize();
    RSRenderNodeMap nodeMap;
    RSRenderFrameRateLinkerMap frameRateLinkerMap;
    RSRenderInteractiveImplictAnimatorMap interactiveImplictAnimatorMap_;
    // The root of render node tree, Note: this node is not the animation fallback node.
    std::shared_ptr<RSBaseRenderNode> globalRootRenderNode_ = std::make_shared<RSRenderNode>(0, true);
    // The list of animating nodes in this frame.
    std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>> animatingNodeList_;
    std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>> curFrameAnimatingNodeList_;
    std::vector<std::pair<NodeId, AnimationId>> needSyncFinishAnimationList_;
    // This flag indicates that a request for the next Vsync is needed when moving to the animation fallback node.
    bool requestedNextVsyncAnimate_ = false;
    PurgeType purgeType_ = PurgeType::NONE;
    ClearMemoryMoment clearMoment_ = ClearMemoryMoment::NO_CLEAR;

    uint64_t transactionTimestamp_ = 0;
    uint64_t currentTimestamp_ = 0;
    std::function<void(const std::function<void()>&, bool)> taskRunner_;
    std::function<void(const std::function<void()>&)> rttaskRunner_;
    std::function<void()> vsyncRequestFunc_;
    // Collect all active Nodes sorted by root node id in this frame.
    std::unordered_map<NodeId, std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>>> activeNodesInRoot_;
    std::mutex activeNodesInRootMutex_;

    std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>> pendingSyncNodes_;
#ifndef ROSEN_CROSS_PLATFORM
    std::vector<BufferInfo> skipSyncBuffer_;
#endif

    friend class RSRenderThread;
    friend class RSMainThread;
    friend class RSDrawFrame;
    friend class RSSurfaceCaptureTaskParallel;
#ifdef RS_PROFILER_ENABLED
    friend class RSProfiler;
#endif
};

} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_BASE_PIPELINE_RS_CONTEXT_H
