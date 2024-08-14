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

#include "pipeline/rs_render_node_gc.h"

#include "params/rs_render_params.h"
#include "pipeline/rs_render_node.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {
RSRenderNodeGC& RSRenderNodeGC::Instance()
{
    static RSRenderNodeGC instance;
    return instance;
}

void RSRenderNodeGC::NodeDestructor(RSRenderNode* ptr)
{
    RSRenderNodeGC::Instance().NodeDestructorInner(ptr);
}

void RSRenderNodeGC::NodeDestructorInner(RSRenderNode* ptr)
{
    std::lock_guard<std::mutex> lock(nodeMutex_);
    if (nodeBucket_.size() > 0) {
        auto& bucket = nodeBucket_.back();
        if (bucket.size() < BUCKET_MAX_SIZE) {
            bucket.push_back(ptr);
        } else {
            nodeBucket_.push({ptr});
        }
    } else {
        nodeBucket_.push({ptr});
    }
}

void RSRenderNodeGC::ReleaseNodeBucket()
{
    std::vector<RSRenderNode*> toDele;
    {
        std::lock_guard<std::mutex> lock(nodeMutex_);
        if (nodeBucket_.empty()) {
            return;
        }
        toDele.swap(nodeBucket_.front());
        nodeBucket_.pop();
    }
    RS_TRACE_NAME_FMT("ReleaseNodeMemory %zu", toDele.size());
    for (auto ptr : toDele) {
        if (ptr) {
            delete ptr;
            ptr = nullptr;
        }
    }
}

void RSRenderNodeGC::ReleaseNodeMemory()
{
    {
        std::lock_guard<std::mutex> lock(nodeMutex_);
        if (nodeBucket_.empty()) {
            return;
        }
    }
    if (mainTask_) {
        auto task = []() {
            RSRenderNodeGC::Instance().ReleaseNodeBucket();
            RSRenderNodeGC::Instance().ReleaseNodeMemory();
        };
        mainTask_(task, DELETE_NODE_TASK, 0, AppExecFwk::EventQueue::Priority::IDLE);
    } else {
        ReleaseNodeBucket();
    }
}

void RSRenderNodeGC::DrawableDestructor(DrawableV2::RSRenderNodeDrawableAdapter* ptr)
{
    RSRenderNodeGC::Instance().DrawableDestructorInner(ptr);
}

void RSRenderNodeGC::DrawableDestructorInner(DrawableV2::RSRenderNodeDrawableAdapter* ptr)
{
    std::lock_guard<std::mutex> lock(drawableMutex_);
    if (drawableBucket_.size() > 0) {
        auto& bucket = drawableBucket_.back();
        if (bucket.size() < BUCKET_MAX_SIZE) {
            bucket.push_back(ptr);
        } else {
            drawableBucket_.push({ptr});
        }
    } else {
        drawableBucket_.push({ptr});
    }
}

void RSRenderNodeGC::ReleaseDrawableBucket()
{
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter*> toDele;
    {
        std::lock_guard<std::mutex> lock(drawableMutex_);
        if (drawableBucket_.empty()) {
            return;
        }
        toDele.swap(drawableBucket_.front());
        drawableBucket_.pop();
    }
    RS_TRACE_NAME_FMT("ReleaseDrawableMemory %zu", toDele.size());
    for (auto ptr : toDele) {
        if (ptr) {
            delete ptr;
            ptr = nullptr;
        }
    }
}

void RSRenderNodeGC::ReleaseDrawableMemory()
{
    {
        std::lock_guard<std::mutex> lock(drawableMutex_);
        if (drawableBucket_.empty()) {
            return;
        }
    }
    if (renderTask_) {
        auto task = []() {
            RSRenderNodeGC::Instance().ReleaseDrawableBucket();
            RSRenderNodeGC::Instance().ReleaseDrawableMemory();
        };
        renderTask_(task, DELETE_DRAWABLE_TASK, 0, AppExecFwk::EventQueue::Priority::IDLE);
    } else {
        ReleaseDrawableBucket();
    }
}
} // namespace Rosen
} // namespace OHOS
