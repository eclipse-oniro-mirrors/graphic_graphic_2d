/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "pen_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "get_object.h"

#include "drawing_filter.h"
#include "drawing_matrix.h"
#include "drawing_path.h"
#include "drawing_path_effect.h"
#include "drawing_pen.h"
#include "drawing_rect.h"
#include "drawing_shader_effect.h"
#include "drawing_shadow_layer.h"
#include "drawing_types.h"
#include "draw/pen.h"
#include "native_color_space_manager.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
namespace {
    constexpr uint32_t MAX_ARRAY_SIZE = 5000;
    constexpr uint32_t PATH_CONST = 2;
    constexpr uint32_t PATH_THREE = 3;
    constexpr uint32_t PATH_TWENTY_NINE = 29;
} // namespace

void PenFuzzTest000(const uint8_t* data, size_t size)
{
    uint32_t aa = GetObject<uint32_t>();
    uint32_t color = GetObject<uint32_t>();
    uint8_t alpha = GetObject<uint8_t>();
    float width = GetObject<float>();
    float miter = GetObject<float>();

    OH_Drawing_Pen* pen = OH_Drawing_PenCreate();

    OH_Drawing_PenSetAntiAlias(nullptr, static_cast<bool>(aa % PATH_CONST));
    OH_Drawing_PenSetAntiAlias(pen, static_cast<bool>(aa % PATH_CONST));
    OH_Drawing_PenIsAntiAlias(nullptr);
    OH_Drawing_PenIsAntiAlias(pen);

    OH_Drawing_PenSetColor(nullptr, color);
    OH_Drawing_PenSetColor(pen, color);
    OH_Drawing_PenGetColor(nullptr);
    OH_Drawing_PenGetColor(pen);

    OH_Drawing_PenSetAlpha(nullptr, alpha);
    OH_Drawing_PenSetAlpha(pen, alpha);
    OH_Drawing_PenGetAlpha(nullptr);
    OH_Drawing_PenGetAlpha(pen);

    OH_Drawing_PenSetWidth(nullptr, width);
    OH_Drawing_PenSetWidth(pen, width);
    OH_Drawing_PenGetWidth(nullptr);
    OH_Drawing_PenGetWidth(pen);

    OH_Drawing_PenSetMiterLimit(nullptr, miter);
    OH_Drawing_PenSetMiterLimit(pen, miter);
    OH_Drawing_PenGetMiterLimit(nullptr);
    OH_Drawing_PenGetMiterLimit(pen);

    OH_Drawing_PenReset(nullptr);
    OH_Drawing_PenReset(pen);

    OH_Drawing_PenDestroy(pen);
}

void PenFuzzTest001(const uint8_t* data, size_t size)
{
    uint32_t enum_1 = GetObject<uint32_t>();
    uint32_t color = GetObject<uint32_t>();

    OH_Drawing_Pen* pen = OH_Drawing_PenCreate();

    OH_Drawing_PenSetCap(nullptr, static_cast<OH_Drawing_PenLineCapStyle>(enum_1 % PATH_THREE));
    OH_Drawing_PenSetCap(pen, static_cast<OH_Drawing_PenLineCapStyle>(enum_1 % PATH_THREE));
    OH_Drawing_PenGetCap(nullptr);
    OH_Drawing_PenGetCap(pen);

    OH_Drawing_PenSetJoin(nullptr, static_cast<OH_Drawing_PenLineJoinStyle>(enum_1 % PATH_THREE));
    OH_Drawing_PenSetJoin(pen, static_cast<OH_Drawing_PenLineJoinStyle>(enum_1 % PATH_THREE));
    OH_Drawing_PenGetJoin(nullptr);
    OH_Drawing_PenGetJoin(pen);

    OH_Drawing_ShaderEffect* cShaderEffect = OH_Drawing_ShaderEffectCreateColorShader(color);
    OH_Drawing_PenSetShaderEffect(nullptr, cShaderEffect);
    OH_Drawing_PenSetShaderEffect(pen, nullptr);
    OH_Drawing_PenSetShaderEffect(pen, cShaderEffect);
        
    OH_Drawing_ShaderEffectDestroy(cShaderEffect);
    OH_Drawing_PenDestroy(pen);
}

void PenFuzzTest002(const uint8_t* data, size_t size)
{
    float blurRadius = GetObject<float>();
    float x = GetObject<float>();
    float y = GetObject<float>();
    uint32_t color = GetObject<uint32_t>();
    uint32_t cBlendMode = GetObject<uint32_t>();
    float left = GetObject<float>();
    float top = GetObject<float>();
    float right = GetObject<float>();
    float bottom = GetObject<float>();

    OH_Drawing_Pen* pen = OH_Drawing_PenCreate();
    OH_Drawing_ShadowLayer* cShadowlayer = OH_Drawing_ShadowLayerCreate(blurRadius, x, y, color);
    OH_Drawing_PenSetShadowLayer(nullptr, cShadowlayer);
    OH_Drawing_PenSetShadowLayer(pen, nullptr);
    OH_Drawing_PenSetShadowLayer(pen, cShadowlayer);

    OH_Drawing_Filter* cFilter = OH_Drawing_FilterCreate();
    OH_Drawing_PenSetFilter(nullptr, cFilter);
    OH_Drawing_PenSetFilter(pen, nullptr);
    OH_Drawing_PenSetFilter(pen, cFilter);
    OH_Drawing_PenGetFilter(nullptr, cFilter);
    OH_Drawing_PenGetFilter(pen, nullptr);
    OH_Drawing_PenGetFilter(pen, cFilter);

    OH_Drawing_PenSetBlendMode(nullptr,  static_cast<OH_Drawing_BlendMode>(cBlendMode % PATH_TWENTY_NINE));
    OH_Drawing_PenSetBlendMode(pen,  static_cast<OH_Drawing_BlendMode>(cBlendMode % PATH_TWENTY_NINE));

    OH_Drawing_Path* src = OH_Drawing_PathCreate();
    OH_Drawing_Path* dst = OH_Drawing_PathCreate();
    OH_Drawing_Rect* cRect = OH_Drawing_RectCreate(left, top, right, bottom);
    OH_Drawing_Matrix* cMatrix = OH_Drawing_MatrixCreate();
    OH_Drawing_PenGetFillPath(nullptr, src, dst, cRect, cMatrix);
    OH_Drawing_PenGetFillPath(pen, nullptr, dst, cRect, cMatrix);
    OH_Drawing_PenGetFillPath(pen, src, nullptr, cRect, cMatrix);
    OH_Drawing_PenGetFillPath(pen, src, dst, cRect, cMatrix);

    OH_Drawing_RectDestroy(cRect);
    OH_Drawing_MatrixDestroy(cMatrix);
    OH_Drawing_PathDestroy(src);
    OH_Drawing_PathDestroy(dst);
    OH_Drawing_FilterDestroy(cFilter);
    OH_Drawing_ShadowLayerDestroy(cShadowlayer);
    OH_Drawing_PenDestroy(pen);
}

void PenFuzzTest003(const uint8_t* data, size_t size)
{
    float phase = GetObject<float>();

    OH_Drawing_Pen* pen = OH_Drawing_PenCreate();
    OH_Drawing_Pen* pen1 = OH_Drawing_PenCopy(nullptr);
    pen1 = OH_Drawing_PenCopy(pen);

    uint32_t sizeTemp = GetObject<uint32_t>() % MAX_ARRAY_SIZE;
    uint32_t sizePath = sizeTemp - (sizeTemp % PATH_CONST) + PATH_CONST;
    float* intervals = new float[sizePath];
    for (size_t i = 0; i < sizePath; i++) {
        intervals[i] = GetObject<float>();
    }
    OH_Drawing_PathEffect* PathEffect = OH_Drawing_CreateDashPathEffect(intervals, sizePath, phase);
    OH_Drawing_PenSetPathEffect(nullptr, PathEffect);
    OH_Drawing_PenSetPathEffect(pen, nullptr);
    OH_Drawing_PenSetPathEffect(pen, PathEffect);
    if (intervals != nullptr) {
        delete[] intervals;
        intervals = nullptr;
    }
    OH_Drawing_PathEffectDestroy(PathEffect);
    OH_Drawing_PenDestroy(pen);
    OH_Drawing_PenDestroy(pen1);
}

void PenFuzzTest004(const uint8_t* data, size_t size)
{
    OH_Drawing_Pen* pen = OH_Drawing_PenCreate();
    float a = GetObject<float>();
    float r = GetObject<float>();
    float b = GetObject<float>();
    float g = GetObject<float>();
    OH_NativeColorSpaceManager* colorSpaceManager =
        OH_NativeColorSpaceManager_CreateFromName(ColorSpaceName::ADOBE_RGB);
    OH_Drawing_PenSetColor4f(pen, a, r, g, b, colorSpaceManager);
    OH_Drawing_PenSetColor4f(nullptr, a, r, g, b, colorSpaceManager);
    OH_Drawing_PenSetColor4f(pen, a, r, g, b, nullptr);
    OH_Drawing_PenGetAlphaFloat(pen, &a);
    OH_Drawing_PenGetAlphaFloat(nullptr, &a);
    OH_Drawing_PenGetAlphaFloat(nullptr, nullptr);
    OH_Drawing_PenGetAlphaFloat(pen, nullptr);
    OH_Drawing_PenGetRedFloat(pen, &r);
    OH_Drawing_PenGetRedFloat(nullptr, &r);
    OH_Drawing_PenGetRedFloat(nullptr, nullptr);
    OH_Drawing_PenGetRedFloat(pen, nullptr);
    OH_Drawing_PenGetGreenFloat(nullptr, nullptr);
    OH_Drawing_PenGetGreenFloat(pen, nullptr);
    OH_Drawing_PenGetGreenFloat(pen, &g);
    OH_Drawing_PenGetGreenFloat(nullptr, &g);
    OH_Drawing_PenGetBlueFloat(nullptr, nullptr);
    OH_Drawing_PenGetBlueFloat(pen, &b);
    OH_Drawing_PenGetBlueFloat(nullptr, &b);
    OH_Drawing_PenGetBlueFloat(pen, nullptr);
    OH_Drawing_PenDestroy(pen);
    OH_NativeColorSpaceManager_Destroy(colorSpaceManager);
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // initialize
    OHOS::Rosen::Drawing::g_data = data;
    OHOS::Rosen::Drawing::g_size = size;
    OHOS::Rosen::Drawing::g_pos = 0;

    /* Run your code on data */
    OHOS::Rosen::Drawing::PenFuzzTest000(data, size);
    OHOS::Rosen::Drawing::PenFuzzTest001(data, size);
    OHOS::Rosen::Drawing::PenFuzzTest002(data, size);
    OHOS::Rosen::Drawing::PenFuzzTest003(data, size);
    OHOS::Rosen::Drawing::PenFuzzTest004(data, size);
    return 0;
}
