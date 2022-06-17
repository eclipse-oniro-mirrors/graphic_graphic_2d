/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "pipeline/rs_context.h"

#include "platform/common/rs_log.h"

namespace OHOS::Rosen {
void RSContext::RegisterAnimatingRenderNode(const std::shared_ptr<RSBaseRenderNode>& nodePtr)
{
    NodeId id = nodePtr->GetId();
    animatingNodeList_.emplace(id, nodePtr);
    ROSEN_LOGD("RSContext::RegisterAnimatingRenderNode, register node id: %d", id);
}
} // namespace OHOS::Rosen
