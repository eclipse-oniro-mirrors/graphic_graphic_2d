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

#include "rsrendernodemap_fuzzer.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <hilog/log.h>
#include <securec.h>
#include <unistd.h>

#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_render_node_map.h"
#include "pipeline/rs_surface_render_node.h"

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
    int pid = GetData<int>();
    RSDisplayNodeConfig config;
    auto node = std::make_shared<OHOS::Rosen::RSRenderNode>(id);
    RSDisplayRenderNode* rsDisplayRenderNode = new RSDisplayRenderNode(id, config);
    std::shared_ptr<RSDisplayRenderNode> nodePtr(rsDisplayRenderNode);
    std::shared_ptr<std::unordered_map<NodeId, std::shared_ptr<RSBaseRenderNode>>> subRenderNodeMap;
    auto func = [](const std::shared_ptr<RSBaseRenderNode>& node) {};
    auto surfaceNode = std::make_shared<OHOS::Rosen::RSSurfaceRenderNode>(id);
    RSRenderNodeMap rsRenderNodeMap;
    rsRenderNodeMap.RegisterRenderNode(node);
    rsRenderNodeMap.RegisterDisplayRenderNode(nodePtr);
    rsRenderNodeMap.UnregisterRenderNode(id);
    rsRenderNodeMap.GetRenderNode(id);
    rsRenderNodeMap.GetAnimationFallbackNode();
    rsRenderNodeMap.ContainPid(pid);
    rsRenderNodeMap.FilterNodeByPid(pid);
    rsRenderNodeMap.TraversalNodes(func);
    rsRenderNodeMap.GetResidentSurfaceNodeMap();
    rsRenderNodeMap.IsResidentProcessNode(id);
    rsRenderNodeMap.GetEntryViewNodeId();
    rsRenderNodeMap.GetWallPaperViewNodeId();
    rsRenderNodeMap.GetScreenLockWindowNodeId();
    rsRenderNodeMap.GetNegativeScreenNodeId();
    rsRenderNodeMap.ObtainScreenLockWindowNodeId(surfaceNode);
    rsRenderNodeMap.ObtainLauncherNodeId(surfaceNode);
    rsRenderNodeMap.GetVisibleLeashWindowCount();
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
