/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DRAW_CMD_H
#define DRAW_CMD_H

#include <unordered_map>

#include "draw/canvas.h"
#include "draw/pen.h"
#include "recording/op_item.h"
#include "recording/mem_allocator.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

struct BrushSiteInfo {
    CmdListSiteInfo colorSpaceCmdListInfo;
    LargeObjectInfo colorSpaceLargeObjectInfo;
    CmdListSiteInfo shaderEffectCmdListInfo;
    LargeObjectInfo shaderEffectLargeObjectInfo;
    CmdListSiteInfo colorFilterCmdListInfo;
    CmdListSiteInfo imageFilterCmdListInfo;
    CmdListSiteInfo maskFilterCmdListInfo;
};

struct PenSiteInfo {
    CmdListSiteInfo pathEffectCmdListInfo;
    CmdListSiteInfo colorSpaceCmdListInfo;
    LargeObjectInfo colorSpaceLargeObjectInfo;
    CmdListSiteInfo shaderEffectCmdListInfo;
    LargeObjectInfo shaderEffectLargeObjectInfo;
    CmdListSiteInfo colorFilterCmdListInfo;
    CmdListSiteInfo imageFilterCmdListInfo;
    CmdListSiteInfo maskFilterCmdListInfo;
};

class CanvasPlayer {
public:
    CanvasPlayer(Canvas& canvas, const MemAllocator& opAllocator, const MemAllocator& largeObjectAllocator);
    ~CanvasPlayer() = default;

    bool Playback(uint32_t type, const void* opItem);

    Canvas& canvas_;
    const MemAllocator& opAllocator_;
    const MemAllocator& largeObjectAllocator_;

    using PlaybackFunc = void(*)(CanvasPlayer& palyer, const void* opItem);
private:
    static std::unordered_map<uint32_t, PlaybackFunc> opPlaybackFuncLUT_;
};

class DrawOpItem : public OpItem {
public:
    DrawOpItem(uint32_t type) : OpItem(type) {}
    ~DrawOpItem() = default;

    enum Type : uint32_t {
        OPITEM_HEAD,
        POINT_OPITEM,
        LINE_OPITEM,
        RECT_OPITEM,
        ROUND_RECT_OPITEM,
        NESTED_ROUND_RECT_OPITEM,
        ARC_OPITEM,
        PIE_OPITEM,
        OVAL_OPITEM,
        CIRCLE_OPITEM,
        PATH_OPITEM,
        BACKGROUND_OPITEM,
        SHADOW_OPITEM,
        BITMAP_OPITEM,
        IMAGE_OPITEM,
        IMAGE_RECT_OPITEM,
        PICTURE_OPITEM,
        CLIP_RECT_OPITEM,
        CLIP_ROUND_RECT_OPITEM,
        CLIP_PATH_OPITEM,
        SET_MATRIX_OPITEM,
        RESET_MATRIX_OPITEM,
        CONCAT_MATRIX_OPITEM,
        TRANSLATE_OPITEM,
        SCALE_OPITEM,
        ROTATE_OPITEM,
        SHEAR_OPITEM,
        FLUSH_OPITEM,
        CLEAR_OPITEM,
        SAVE_OPITEM,
        SAVE_LAYER_OPITEM,
        RESTORE_OPITEM,
        ATTACH_PEN_OPITEM,
        ATTACH_BRUSH_OPITEM,
        DETACH_PEN_OPITEM,
        DETACH_BRUSH_OPITEM,
    };
};

class DrawPointOpItem : public DrawOpItem {
public:
    DrawPointOpItem(const Point& point);
    ~DrawPointOpItem() = default;

    static void Playback(CanvasPlayer& player, const void* opItem);
    void Playback(Canvas& canvas) const;

private:
    Point point_;
};

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS

#endif // DRAW_CMD_H
