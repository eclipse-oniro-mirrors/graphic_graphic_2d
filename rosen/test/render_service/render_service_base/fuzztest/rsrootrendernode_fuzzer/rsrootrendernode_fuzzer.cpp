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

#include "rsrootrendernode_fuzzer.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <hilog/log.h>
#include <memory>
#include <securec.h>
#include <unistd.h>

#include "render_thread/rs_render_thread_visitor.h"
#include "pipeline/rs_root_render_node.h"
namespace OHOS {
namespace Rosen {
namespace {
const uint8_t* g_data = nullptr;
size_t g_size = 0;
size_t g_pos;
} // namespace

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_data == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_data + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    uint64_t id = GetData<uint64_t>();
    float width = GetData<float>();
    float height = GetData<float>();
    auto rsRenderThreadVisitor = std::make_shared<RSRenderThreadVisitor>();
    RSRootRenderNode rsRootRenderNode(id);
    rsRootRenderNode.QuickPrepare(rsRenderThreadVisitor);
    rsRootRenderNode.Prepare(rsRenderThreadVisitor);
    rsRootRenderNode.Process(rsRenderThreadVisitor);
    rsRootRenderNode.AttachRSSurfaceNode(id);
    rsRootRenderNode.GetDirtyManager();
    rsRootRenderNode.GetSurface();
    rsRootRenderNode.GetRSSurfaceNodeId();
    rsRootRenderNode.GetSuggestedBufferWidth();
    rsRootRenderNode.GetSuggestedBufferHeight();
    rsRootRenderNode.UpdateSuggestedBufferSize(width, height);
    rsRootRenderNode.SetEnableRender(true);
    rsRootRenderNode.GetEnableRender();

    rsRootRenderNode.InitRenderParams();
    rsRootRenderNode.UpdateRenderParams();
    bool enable = GetData<bool>();
    rsRootRenderNode.EnableWindowKeyFrame(enable);
    rsRootRenderNode.IsWindowKeyFrameEnabled();
    return true;
}
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Rosen::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
