/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "drawing_pen.h"

#include "drawing_canvas_utils.h"
#include "drawing_helper.h"

#include "draw/pen.h"

using namespace OHOS;
using namespace Rosen;
using namespace Drawing;

static const Matrix* CastToMatrix(const OH_Drawing_Matrix* cMatrix)
{
    return reinterpret_cast<const Matrix*>(cMatrix);
}

static const Path* CastToPath(const OH_Drawing_Path* cPath)
{
    return reinterpret_cast<const Path*>(cPath);
}

static Path* CastToPath(OH_Drawing_Path* cPath)
{
    return reinterpret_cast<Path*>(cPath);
}

static Pen* CastToPen(OH_Drawing_Pen* cPen)
{
    return reinterpret_cast<Pen*>(cPen);
}

static const Pen& CastToPen(const OH_Drawing_Pen& cPen)
{
    return reinterpret_cast<const Pen&>(cPen);
}

static const Rect* CastToRect(const OH_Drawing_Rect* cRect)
{
    return reinterpret_cast<const Rect*>(cRect);
}

static const Filter& CastToFilter(const OH_Drawing_Filter& cFilter)
{
    return reinterpret_cast<const Filter&>(cFilter);
}

static const Filter* CastToFilter(const OH_Drawing_Filter* cFilter)
{
    return reinterpret_cast<const Filter*>(cFilter);
}

static OH_Drawing_PenLineCapStyle CapCastToCCap(Pen::CapStyle cap)
{
    OH_Drawing_PenLineCapStyle cCap = LINE_FLAT_CAP;
    switch (cap) {
        case Pen::CapStyle::FLAT_CAP:
            cCap = LINE_FLAT_CAP;
            break;
        case Pen::CapStyle::SQUARE_CAP:
            cCap = LINE_SQUARE_CAP;
            break;
        case Pen::CapStyle::ROUND_CAP:
            cCap = LINE_ROUND_CAP;
            break;
        default:
            break;
    }
    return cCap;
}

static Pen::CapStyle CCapCastToCap(OH_Drawing_PenLineCapStyle cCap)
{
    Pen::CapStyle cap = Pen::CapStyle::FLAT_CAP;
    switch (cCap) {
        case LINE_FLAT_CAP:
            cap = Pen::CapStyle::FLAT_CAP;
            break;
        case LINE_SQUARE_CAP:
            cap = Pen::CapStyle::SQUARE_CAP;
            break;
        case LINE_ROUND_CAP:
            cap = Pen::CapStyle::ROUND_CAP;
            break;
        default:
            break;
    }
    return cap;
}

OH_Drawing_Pen* OH_Drawing_PenCreate()
{
    return (OH_Drawing_Pen*)new Pen;
}

OH_Drawing_Pen* OH_Drawing_PenCopy(OH_Drawing_Pen* cPen)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return nullptr;
    }
    return (OH_Drawing_Pen*)new Pen(*pen);
}

void OH_Drawing_PenDestroy(OH_Drawing_Pen* cPen)
{
    if (!cPen) {
        return;
    }
    delete CastToPen(cPen);
}

bool OH_Drawing_PenIsAntiAlias(const OH_Drawing_Pen* cPen)
{
    if (cPen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }
    return CastToPen(*cPen).IsAntiAlias();
}

void OH_Drawing_PenSetAntiAlias(OH_Drawing_Pen* cPen, bool aa)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    pen->SetAntiAlias(aa);
}

uint32_t OH_Drawing_PenGetColor(const OH_Drawing_Pen* cPen)
{
    if (cPen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return 0;
    }
    return CastToPen(*cPen).GetColor().CastToColorQuad();
}

void OH_Drawing_PenSetColor(OH_Drawing_Pen* cPen, uint32_t color)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    pen->SetColor(color);
}

uint8_t OH_Drawing_PenGetAlpha(const OH_Drawing_Pen* cPen)
{
    if (cPen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return 0;
    }
    return CastToPen(*cPen).GetAlpha();
}

void OH_Drawing_PenSetAlpha(OH_Drawing_Pen* cPen, uint8_t alpha)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    pen->SetAlpha(alpha);
}

float OH_Drawing_PenGetWidth(const OH_Drawing_Pen* cPen)
{
    if (cPen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return 0.f;
    }
    return CastToPen(*cPen).GetWidth();
}

void OH_Drawing_PenSetWidth(OH_Drawing_Pen* cPen, float width)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    pen->SetWidth(width);
}

float OH_Drawing_PenGetMiterLimit(const OH_Drawing_Pen* cPen)
{
    if (cPen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return 0.f;
    }
    return CastToPen(*cPen).GetMiterLimit();
}

void OH_Drawing_PenSetMiterLimit(OH_Drawing_Pen* cPen, float miter)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    pen->SetMiterLimit(miter);
}

OH_Drawing_PenLineCapStyle OH_Drawing_PenGetCap(const OH_Drawing_Pen* cPen)
{
    if (cPen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return LINE_FLAT_CAP;
    }
    Pen::CapStyle cap = CastToPen(*cPen).GetCapStyle();
    OH_Drawing_PenLineCapStyle cCap = CapCastToCCap(cap);
    return cCap;
}

void OH_Drawing_PenSetCap(OH_Drawing_Pen* cPen, OH_Drawing_PenLineCapStyle cCap)
{
    if (cCap < LINE_FLAT_CAP || cCap > LINE_ROUND_CAP) {
        g_drawingErrorCode = OH_DRAWING_ERROR_PARAMETER_OUT_OF_RANGE;
        return;
    }
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    Pen::CapStyle cap = CCapCastToCap(cCap);
    pen->SetCapStyle(cap);
}

OH_Drawing_PenLineJoinStyle OH_Drawing_PenGetJoin(const OH_Drawing_Pen* cPen)
{
    if (cPen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return LINE_MITER_JOIN;
    }
    Pen::JoinStyle join = CastToPen(*cPen).GetJoinStyle();
    OH_Drawing_PenLineJoinStyle cJoin = static_cast<OH_Drawing_PenLineJoinStyle>(join);
    return cJoin;
}

void OH_Drawing_PenSetJoin(OH_Drawing_Pen* cPen, OH_Drawing_PenLineJoinStyle cJoin)
{
    if (cJoin < LINE_MITER_JOIN || cJoin > LINE_BEVEL_JOIN) {
        g_drawingErrorCode = OH_DRAWING_ERROR_PARAMETER_OUT_OF_RANGE;
        return;
    }
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    Pen::JoinStyle join = static_cast<Pen::JoinStyle>(cJoin);
    pen->SetJoinStyle(join);
}

void OH_Drawing_PenSetShaderEffect(OH_Drawing_Pen* cPen, OH_Drawing_ShaderEffect* cShaderEffect)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cShaderEffect == nullptr) {
        pen->SetShaderEffect(nullptr);
        return;
    }
    auto shaderEffectHandle = Helper::CastTo<OH_Drawing_ShaderEffect*, NativeHandle<ShaderEffect>*>(cShaderEffect);
    pen->SetShaderEffect(shaderEffectHandle->value);
}

void OH_Drawing_PenSetPathEffect(OH_Drawing_Pen* cPen, OH_Drawing_PathEffect* cPathEffect)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cPathEffect == nullptr) {
        pen->SetPathEffect(nullptr);
        return;
    }
    auto pathEffectHandle = Helper::CastTo<OH_Drawing_PathEffect*, NativeHandle<PathEffect>*>(cPathEffect);
    pen->SetPathEffect(pathEffectHandle->value);
}

void OH_Drawing_PenSetShadowLayer(OH_Drawing_Pen* cPen, OH_Drawing_ShadowLayer* cShadowlayer)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cShadowlayer == nullptr) {
        pen->SetLooper(nullptr);
        return;
    }
    auto blurDrawLooperHandle = Helper::CastTo<OH_Drawing_ShadowLayer*, NativeHandle<BlurDrawLooper>*>(cShadowlayer);
    pen->SetLooper(blurDrawLooperHandle->value);
}

void OH_Drawing_PenSetFilter(OH_Drawing_Pen* cPen, OH_Drawing_Filter* cFilter)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cFilter == nullptr) {
        Filter filter;
        pen->SetFilter(filter);
        return;
    }
    pen->SetFilter(CastToFilter(*cFilter));
}

void OH_Drawing_PenGetFilter(OH_Drawing_Pen* cPen, OH_Drawing_Filter* cFilter)
{
    Pen* pen = CastToPen(cPen);
    Filter* filter = const_cast<Filter*>(CastToFilter(cFilter));
    if (pen == nullptr || filter == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    *filter = pen->GetFilter();
}

void OH_Drawing_PenSetBlendMode(OH_Drawing_Pen* cPen, OH_Drawing_BlendMode cBlendMode)
{
    if (cBlendMode < BLEND_MODE_CLEAR || cBlendMode > BLEND_MODE_LUMINOSITY) {
        g_drawingErrorCode = OH_DRAWING_ERROR_PARAMETER_OUT_OF_RANGE;
        return;
    }
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    pen->SetBlendMode(static_cast<BlendMode>(cBlendMode));
}

bool OH_Drawing_PenGetFillPath(OH_Drawing_Pen* cPen, const OH_Drawing_Path* src, OH_Drawing_Path* dst,
    const OH_Drawing_Rect* cRect, const OH_Drawing_Matrix* cMatrix)
{
    Pen* pen = CastToPen(cPen);
    const Path* srcPath = CastToPath(src);
    Path* dstPath = CastToPath(dst);
    if (!pen || !srcPath || !dstPath) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }
    return pen->GetFillPath(*srcPath, *dstPath, cRect ? CastToRect(cRect): nullptr,
        cMatrix ? *CastToMatrix(cMatrix) : Matrix());
}

void OH_Drawing_PenReset(OH_Drawing_Pen* cPen)
{
    Pen* pen = CastToPen(cPen);
    if (pen == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    pen->Reset();
}