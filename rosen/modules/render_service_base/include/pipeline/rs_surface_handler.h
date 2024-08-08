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
#ifndef RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_SURFACE_HANDLER_H
#define RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_SURFACE_HANDLER_H

#include <atomic>
#include <map>
#include <mutex>

#include "common/rs_common_def.h"
#include "common/rs_macros.h"
#include "platform/common/rs_log.h"
#ifndef ROSEN_CROSS_PLATFORM
#include <iconsumer_surface.h>
#include <surface.h>
#include "sync_fence.h"
#endif

namespace OHOS {
namespace Rosen {
using OnDeleteBufferFunc = std::function<void(int32_t)>;
class RSB_EXPORT RSSurfaceHandler {
public:
    // indicates which node this handler belongs to.
    explicit RSSurfaceHandler(NodeId id) : id_(id) {}
    virtual ~RSSurfaceHandler() noexcept;

    struct SurfaceBufferEntry {
#ifndef ROSEN_CROSS_PLATFORM
        ~SurfaceBufferEntry() noexcept
        {
            if (buffer != nullptr && bufferDeleteCb_ != nullptr) {
                bufferDeleteCb_(buffer->GetSeqNum());
            }
        }

        void RegisterDeleteBufferListener(OnDeleteBufferFunc bufferDeleteCb)
        {
            if (bufferDeleteCb_ == nullptr) {
                bufferDeleteCb_ = bufferDeleteCb;
            }
        }
#endif
        void Reset()
        {
#ifndef ROSEN_CROSS_PLATFORM
            if (buffer == nullptr) {
                return;
            }
            if (bufferDeleteCb_) {
                bufferDeleteCb_(buffer->GetSeqNum());
            }
            buffer = nullptr;
            acquireFence = SyncFence::INVALID_FENCE;
            releaseFence = SyncFence::INVALID_FENCE;
            damageRect = Rect {0, 0, 0, 0};
#endif
            timestamp = 0;
        }
#ifndef ROSEN_CROSS_PLATFORM
        sptr<SurfaceBuffer> buffer = nullptr;
        sptr<SyncFence> acquireFence = SyncFence::INVALID_FENCE;
        sptr<SyncFence> releaseFence = SyncFence::INVALID_FENCE;
        Rect damageRect = {0, 0, 0, 0};
        OnDeleteBufferFunc bufferDeleteCb_ = nullptr;
#endif
        int64_t timestamp = 0;
    };

    void IncreaseAvailableBuffer();
    void ReduceAvailableBuffer();

    NodeId GetNodeId() const
    {
        return id_;
    }

    void SetDefaultWidthAndHeight(int32_t width, int32_t height)
    {
#ifndef ROSEN_CROSS_PLATFORM
        if (consumer_ != nullptr) {
            consumer_->SetDefaultWidthAndHeight(width, height);
        }
#endif
    }

#ifndef ROSEN_CROSS_PLATFORM
    void SetConsumer(sptr<IConsumerSurface> consumer);

    sptr<IConsumerSurface> GetConsumer() const
    {
        return consumer_;
    }

    void SetHoldBuffer(std::shared_ptr<SurfaceBufferEntry> buffer)
    {
        holdBuffer_ = buffer;
    }

    inline std::shared_ptr<SurfaceBufferEntry> GetHoldBuffer()
    {
        return holdBuffer_;
    }

    void SetBuffer(
        const sptr<SurfaceBuffer>& buffer,
        const sptr<SyncFence>& acquireFence,
        const Rect& damage,
        const int64_t timestamp)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        preBuffer_.Reset();
        preBuffer_ = buffer_;
        buffer_.buffer = buffer;
        buffer_.acquireFence = acquireFence;
        buffer_.damageRect = damage;
        buffer_.timestamp = timestamp;
    }

    const sptr<SurfaceBuffer> GetBuffer() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return buffer_.buffer;
    }

    uint64_t GetBufferUsage() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!buffer_.buffer) {
            return 0;
        }
        return buffer_.buffer->GetUsage();
    }

    const sptr<SyncFence> GetAcquireFence() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return buffer_.acquireFence;
    }

    const Rect GetDamageRegion() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return buffer_.damageRect;
    }

    void SetCurrentReleaseFence(sptr<SyncFence> fence)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        buffer_.releaseFence = fence;
    }

    void SetReleaseFence(sptr<SyncFence> fence)
    {
        // The fence which get from hdi is preBuffer's releaseFence now.
        std::lock_guard<std::mutex> lock(mutex_);
        preBuffer_.releaseFence = std::move(fence);
    }

    void SetBufferSizeChanged(const sptr<SurfaceBuffer>& buffer)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (preBuffer_.buffer == nullptr) {
            return;
        }
        bufferSizeChanged_ = buffer->GetWidth() != preBuffer_.buffer->GetWidth() ||
                             buffer->GetHeight() != preBuffer_.buffer->GetHeight();
    }

    bool CheckScalingModeChanged()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (consumer_ == nullptr || buffer_.buffer == nullptr) {
            return false;
        }

        ScalingMode scalingMode = ScalingMode::SCALING_MODE_SCALE_TO_WINDOW;
        consumer_->GetScalingMode(buffer_.buffer->GetSeqNum(), scalingMode);
        bool ScalingModeChanged_ = scalingMode != scalingModePre;
        scalingModePre = scalingMode;
        return ScalingModeChanged_;
    }

    sptr<SurfaceBuffer> GetPreBuffer()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return preBuffer_.buffer;
    }

    sptr<SyncFence> GetPreBufferAcquireFence()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return preBuffer_.acquireFence;
    }

    sptr<SyncFence> GetPreBufferReleaseFence()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return preBuffer_.releaseFence;
    }
#endif

    void ResetPreBuffer()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        preBuffer_.Reset();
    }

    int32_t GetAvailableBufferCount() const
    {
        return bufferAvailableCount_;
    }

    int64_t GetTimestamp() const
    {
        return buffer_.timestamp;
    }

    void CleanCache()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        buffer_.Reset();
        preBuffer_.Reset();
    }

    void ResetBufferAvailableCount()
    {
        bufferAvailableCount_ = 0;
    }

    void SetGlobalZOrder(float globalZOrder);
    float GetGlobalZOrder() const;

    bool GetBufferSizeChanged()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return bufferSizeChanged_;
    }

    bool HasConsumer() const
    {
#ifndef ROSEN_CROSS_PLATFORM
        return consumer_ != nullptr;
#else
        return false;
#endif
    }
    inline bool IsCurrentFrameBufferConsumed() const
    {
        return isCurrentFrameBufferConsumed_;
    }
    inline void ResetCurrentFrameBufferConsumed()
    {
        isCurrentFrameBufferConsumed_ = false;
    }
    inline void SetCurrentFrameBufferConsumed()
    {
        isCurrentFrameBufferConsumed_ = true;
    }

#ifndef ROSEN_CROSS_PLATFORM
    void RegisterDeleteBufferListener(OnDeleteBufferFunc bufferDeleteCb)
    {
        if (bufferDeleteCb != nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            buffer_.RegisterDeleteBufferListener(bufferDeleteCb);
            preBuffer_.RegisterDeleteBufferListener(bufferDeleteCb);
        }
    }
    void ConsumeAndUpdateBuffer(SurfaceBufferEntry buffer);
    void CacheBuffer(SurfaceBufferEntry buffer);
    RSSurfaceHandler::SurfaceBufferEntry GetBufferFromCache(uint64_t vsyncTimestamp);
    bool HasBufferCache() const;
    void ClearBufferCache();
#endif

protected:
#ifndef ROSEN_CROSS_PLATFORM
    sptr<IConsumerSurface> consumer_ = nullptr;
#endif
    bool isCurrentFrameBufferConsumed_ = false;

private:
    void ReleaseBuffer(SurfaceBufferEntry& buffer);

#ifndef ROSEN_CROSS_PLATFORM
    ScalingMode scalingModePre = ScalingMode::SCALING_MODE_SCALE_TO_WINDOW;
#endif
    NodeId id_ = 0;
    // mutex buffer_ & preBuffer_ & bufferCache_
    mutable std::mutex mutex_;
    SurfaceBufferEntry buffer_;
    SurfaceBufferEntry preBuffer_;
    float globalZOrder_ = 0.0f;
    std::atomic<int> bufferAvailableCount_ = 0;
    bool bufferSizeChanged_ = false;
    std::map<uint64_t, SurfaceBufferEntry> bufferCache_;
    std::shared_ptr<SurfaceBufferEntry> holdBuffer_ = nullptr;
};
}
}
#endif // RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_SURFACE_HANDLER_H
