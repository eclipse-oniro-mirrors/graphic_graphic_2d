/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_NODE_MAP_V2_H
#define RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_NODE_MAP_V2_H

#include <mutex>
#include <unordered_map>

#include "common/rs_common_def.h"
#include "common/rs_macros.h"
#include "ui/rs_base_node.h"

namespace OHOS {
namespace Rosen {
class RSNode;
class RSC_EXPORT RSNodeMapV2 final {
public:
    bool RegisterNode(const std::shared_ptr<RSBaseNode>& nodePtr);
    bool RegisterNodeInstanceId(NodeId id, int32_t instanceId);
    void UnregisterNode(NodeId id);
    // Get RSNode with type T, return nullptr if not found or type mismatch
    template<typename T = RSBaseNode>
    const std::shared_ptr<T> GetNode(NodeId id) const
    {
        return RSBaseNode::ReinterpretCast<T>(GetNode<RSBaseNode>(id));
    }
    template<>
    const std::shared_ptr<RSBaseNode> GetNode(NodeId id) const;

private:
    RSNodeMapV2();
    ~RSNodeMapV2() noexcept;
    std::unordered_map<NodeId, std::weak_ptr<RSBaseNode>> nodeMapNew_;
    mutable std::mutex mutex_;

    friend class RSUIContext;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_NODE_MAP_V2_H