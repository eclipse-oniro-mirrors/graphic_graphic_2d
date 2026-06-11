/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "command_modifier/rs_canvas_drawing_node_command_modifier.h"

#include "command/rs_canvas_drawing_node_command.h"
#include "ui/rs_canvas_drawing_node.h"

namespace OHOS {
namespace Rosen {

void ResetSurfaceCmdModifier::UpdateToRender()
{
    auto node = std::static_pointer_cast<RSCanvasDrawingNode>(GetNode());
    if (!node) return;
    std::unique_ptr<RSCommand> command = std::make_unique<RSCanvasDrawingNodeResetSurface>(
        node->GetId(), param_.width_, param_.height_, param_.resetSurfaceIndex_);
    AddCommand(command, node->IsRenderServiceNode());
}

RSCmdModifier::UpdateResult ResetSurfaceCmdModifier::UpdateToRenderWithResult()
{
    auto node = std::static_pointer_cast<RSCanvasDrawingNode>(GetNode());
    if (!node) return false;
    std::unique_ptr<RSCommand> command = std::make_unique<RSCanvasDrawingNodeResetSurface>(
        node->GetId(), param_.width_, param_.height_, param_.resetSurfaceIndex_);
    return AddCommand(command, node->IsRenderServiceNode());
}

void ResetSurfaceCmdModifier::DumpParam(std::string& out) const
{
    out += "{width:" + std::to_string(param_.width_) +
           ", height:" + std::to_string(param_.height_) +
           ", resetSurfaceIndex:" + std::to_string(param_.resetSurfaceIndex_) + "}";
}

} // namespace Rosen
} // namespace OHOS
