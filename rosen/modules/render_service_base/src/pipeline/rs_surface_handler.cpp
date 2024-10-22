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

#include "pipeline/rs_surface_handler.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {
RSSurfaceHandler::~RSSurfaceHandler() noexcept
{
}
#ifndef ROSEN_CROSS_PLATFORM
void RSSurfaceHandler::SetConsumer(sptr<IConsumerSurface> consumer)
{
    consumer_ = consumer;
}
#endif

void RSSurfaceHandler::IncreaseAvailableBuffer()
{
    bufferAvailableCount_++;
}

void RSSurfaceHandler::ReduceAvailableBuffer()
{
    --bufferAvailableCount_;
}

void RSSurfaceHandler::SetGlobalZOrder(float globalZOrder)
{
    globalZOrder_ = globalZOrder;
}

float RSSurfaceHandler::GetGlobalZOrder() const
{
    return globalZOrder_;
}

#ifndef ROSEN_CROSS_PLATFORM
void RSSurfaceHandler::ConsumeAndUpdateBuffer(SurfaceBufferEntry buffer)
{
    ConsumeAndUpdateBufferInner(buffer);
}

void RSSurfaceHandler::ConsumeAndUpdateBufferInner(SurfaceBufferEntry& buffer)
{
    if (!buffer.buffer) {
        return;
    }
    SetBuffer(buffer.buffer, buffer.acquireFence, buffer.damageRect, buffer.timestamp);
    SetBufferSizeChanged(buffer.buffer);
    SetCurrentFrameBufferConsumed();
    RS_LOGD("RsDebug surfaceHandler(id: %{public}" PRIu64 ") buffer update, "\
        "buffer[timestamp:%{public}" PRId64 ", seq:%{public}" PRIu32 "]",
        GetNodeId(), buffer.timestamp, buffer.buffer->GetSeqNum());
}
#endif
}
}
