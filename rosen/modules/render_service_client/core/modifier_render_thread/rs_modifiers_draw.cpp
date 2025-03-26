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

#include "modifier_render_thread/rs_modifiers_draw.h"

#include "command/rs_canvas_node_command.h"
#include "command/rs_command.h"
#include "command/rs_node_command.h"
#include "render_context/memory_handler.h"

namespace OHOS {
namespace Rosen {
std::mutex RSModifiersDraw::surfaceEntryMutex_;
std::unordered_map<NodeId, RSModifiersDraw::SurfaceEntry> RSModifiersDraw::surfaceEntryMap_;
std::mutex RSModifiersDraw::dirtyNodeMutex_;
std::unordered_set<NodeId> RSModifiersDraw::dirtyNodes_;
std::unordered_set<NodeId> RSModifiersDraw::offTreeNodes_;
std::mutex RSModifiersDraw::nodeStatusMutex_;

sptr<SurfaceBuffer> RSModifiersDraw::DmaMemAlloc(
    int32_t width, int32_t height, const std::unique_ptr<Media::PixelMap>& pixelMap)
{
    return nullptr;
}

std::shared_ptr<Drawing::Surface> RSModifiersDraw::CreateSurfaceFromGpuContext(
    const std::unique_ptr<Media::PixelMap>& pixelMap, int32_t width, int32_t height)
{
    return nullptr;
}

std::shared_ptr<Drawing::Surface> RSModifiersDraw::CreateSurfaceFromCpuContext(
    const std::unique_ptr<Media::PixelMap>& pixelMap)
{
    return nullptr;
}

std::shared_ptr<Drawing::Surface> RSModifiersDraw::CreateSurface(std::unique_ptr<Media::PixelMap>& pixelMap,
    int32_t width, int32_t height)
{
    return nullptr;
}

std::unique_ptr<Media::PixelMap> RSModifiersDraw::CreatePixelMap(int32_t width, int32_t height, bool useDMA)
{
    return nullptr;
}

RSModifiersDraw::SurfaceEntry RSModifiersDraw::GetSurfaceEntryByNodeId(NodeId nodeId)
{
    return SurfaceEntry {};
}

bool RSModifiersDraw::Playback(const std::shared_ptr<Drawing::Surface>& surface,
    const std::shared_ptr<Drawing::DrawCmdList>& cmdList, bool isCanvasType)
{
    return false;
}

void RSModifiersDraw::AddPixelMapDrawOp(const std::shared_ptr<Drawing::DrawCmdList>& cmdList,
    const std::shared_ptr<Media::PixelMap>& pixelMap, int32_t width, int32_t height, bool isRenderWithForegroundColor)
{
    return;
}

void RSModifiersDraw::InvalidateSurfaceCache(const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    return;
}

void RSModifiersDraw::ConvertCmdListForCanvas(const std::shared_ptr<Drawing::DrawCmdList>& cmdList, NodeId nodeId)
{
    return;
}

void RSModifiersDraw::ConvertCmdList(const std::shared_ptr<Drawing::DrawCmdList>& cmdList)
{
    return;
}

void RSModifiersDraw::ClearOffTreeNodeMemory(NodeId nodeId)
{
    return;
}

void RSModifiersDraw::InsertOffTreeNode(NodeId nodeId)
{
    return;
}

void RSModifiersDraw::EraseOffTreeNode(NodeId nodeId)
{
    return;
}

std::unique_ptr<Media::PixelMap> RSModifiersDraw::GetPixelMapByNodeId(NodeId nodeId, bool useDMA)
{
    return nullptr;
}

void RSModifiersDraw::RemoveSurfaceByNodeId(NodeId nodeId, bool postTask)
{
    return;
}

bool RSModifiersDraw::ResetSurfaceByNodeId(int32_t width, int32_t height, NodeId nodeId, bool postTask)
{
    return false;
}

bool RSModifiersDraw::CheckNodeIsOffTree(NodeId nodeId)
{
    return false;
}

void RSModifiersDraw::CreateNextFrameSurface()
{
    return;
}
} // namespace Rosen
} // namespace OHOS