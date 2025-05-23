/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "drawing_round_rect.h"

#include "drawing_canvas_utils.h"

#include "utils/round_rect.h"

using namespace OHOS;
using namespace Rosen;
using namespace Drawing;

static const Rect& CastToRect(const OH_Drawing_Rect& cRect)
{
    return reinterpret_cast<const Rect&>(cRect);
}

static RoundRect* CastToRoundRect(OH_Drawing_RoundRect* cRoundRect)
{
    return reinterpret_cast<RoundRect*>(cRoundRect);
}

OH_Drawing_RoundRect* OH_Drawing_RoundRectCreate(const OH_Drawing_Rect* cRect, float xRad, float yRad)
{
    if (cRect == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return nullptr;
    }
    return (OH_Drawing_RoundRect*)new RoundRect(CastToRect(*cRect), xRad, yRad);
}

OH_Drawing_RoundRect* OH_Drawing_RoundRectCopy(const OH_Drawing_RoundRect* roundRect)
{
    if (roundRect == nullptr) {
        return nullptr;
    }
    const RoundRect* rect = reinterpret_cast<const RoundRect*>(roundRect);
    return (OH_Drawing_RoundRect*)new RoundRect(*rect);
}

static RoundRect::CornerPos CCornerPosCastToCornerPos(OH_Drawing_CornerPos pos)
{
    RoundRect::CornerPos roundPos = RoundRect::CornerPos::TOP_LEFT_POS;
    switch (pos) {
        case CORNER_POS_TOP_LEFT:
            roundPos = RoundRect::CornerPos::TOP_LEFT_POS;
            break;
        case CORNER_POS_TOP_RIGHT:
            roundPos = RoundRect::CornerPos::TOP_RIGHT_POS;
            break;
        case CORNER_POS_BOTTOM_RIGHT:
            roundPos = RoundRect::CornerPos::BOTTOM_RIGHT_POS;
            break;
        case CORNER_POS_BOTTOM_LEFT:
            roundPos = RoundRect::CornerPos::BOTTOM_LEFT_POS;
            break;
        default:
            break;
    }
    return roundPos;
}

void OH_Drawing_RoundRectSetCorner(OH_Drawing_RoundRect* cRoundRect, OH_Drawing_CornerPos pos,
    OH_Drawing_Corner_Radii radiusXY)
{
    RoundRect* rounRect = CastToRoundRect(cRoundRect);
    if (rounRect == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (pos < CORNER_POS_TOP_LEFT || pos > CORNER_POS_BOTTOM_LEFT) {
        g_drawingErrorCode = OH_DRAWING_ERROR_PARAMETER_OUT_OF_RANGE;
        return;
    }
    rounRect->SetCornerRadius(CCornerPosCastToCornerPos(pos), radiusXY.x, radiusXY.y);
}

OH_Drawing_Corner_Radii OH_Drawing_RoundRectGetCorner(OH_Drawing_RoundRect* cRoundRect, OH_Drawing_CornerPos pos)
{
    RoundRect* rounRect = CastToRoundRect(cRoundRect);
    if (rounRect == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return {0, 0};
    }
    if (pos < CORNER_POS_TOP_LEFT || pos > CORNER_POS_BOTTOM_LEFT) {
        g_drawingErrorCode = OH_DRAWING_ERROR_PARAMETER_OUT_OF_RANGE;
        return {0, 0};
    }
    Point radiusXY = rounRect->GetCornerRadius(CCornerPosCastToCornerPos(pos));
    return {radiusXY.GetX(), radiusXY.GetY()};
}

void OH_Drawing_RoundRectDestroy(OH_Drawing_RoundRect* cRoundRect)
{
    if (!cRoundRect) {
        return;
    }
    delete CastToRoundRect(cRoundRect);
}

OH_Drawing_ErrorCode OH_Drawing_RoundRectOffset(OH_Drawing_RoundRect* cRoundRect, float dx, float dy)
{
    RoundRect* rounRect = CastToRoundRect(cRoundRect);
    if (rounRect == nullptr) {
        return OH_DRAWING_ERROR_INVALID_PARAMETER;
    }
    rounRect->Offset(dx, dy);
    return OH_DRAWING_SUCCESS;
}