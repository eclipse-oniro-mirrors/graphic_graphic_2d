/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "brush_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "get_object.h"
#include "draw/brush.h"
#include "effect/blender.h"
#include "effect/shader_effect.h"
#include "utils/rect.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

void BrushFuzzTestInner01(Brush& brush)
{
    float redF = GetObject<float>();
    float greeF = GetObject<float>();
    float blueF = GetObject<float>();
    float alphaF = GetObject<float>();
    uint32_t alpha1 = GetObject<uint32_t>();

    Color4f color4f {
        redF,
        greeF,
        blueF,
        alphaF,
    };
    brush.GetColor4f();
    brush.GetColorSpace();

    std::shared_ptr<ColorSpace> colorSpace = ColorSpace::CreateSRGB();
    brush.SetColor(color4f, colorSpace);
    brush.SetAlpha(alpha1);
    brush.GetAlpha();
    scalar scalarG = GetObject<scalar>();
    brush.SetAlphaF(scalarG);
    brush.GetAlphaF();
    brush.GetBlendMode();
}

void BrushFuzzTestInner02(Brush& brush)
{
    BlendMode mode = GetObject<BlendMode>();
    brush.SetBlendMode(mode);
    Filter filter;
    brush.SetFilter(filter);
    brush.GetFilter();
    brush.IsAntiAlias();
    bool isAntiAlias = GetObject<bool>();
    brush.SetAntiAlias(isAntiAlias);
    brush.Reset();
}

void BrushFuzzTestInner03(Brush& brush)
{
    Brush brushOne = Brush(brush);
    Color color;
    Brush brushTwo = Brush(color);
    ColorQuad colorQuad = GetObject<ColorQuad>();
    std::shared_ptr<ShaderEffect> shaderEffect = ShaderEffect::CreateColorShader(colorQuad);
    brushTwo.SetShaderEffect(shaderEffect);
    brushTwo.GetShaderEffect();
    Brush brushThree = Brush(shaderEffect);
    int rgba = GetObject<int>();
    Brush brushFour = Brush(rgba);
    if (brushOne == brushTwo) {}
    if (brushOne != brushTwo) {}
}

void BrushFuzzTestInner04(Brush& brush)
{
    brush.HasFilter();
    BlendMode mode = GetObject<BlendMode>();
    std::shared_ptr<Blender> blender = Blender::CreateWithBlendMode(mode);
    brush.SetBlender(blender);
    brush.GetBlender();
    brush.CanComputeFastBounds();
    float left = GetObject<float>();
    float top = GetObject<float>();
    float right = GetObject<float>();
    float bottom = GetObject<float>();
    RectF rect {
        left,
        top,
        right,
        bottom,
    };
    RectF rect2 {GetObject<float>(), GetObject<float>(), GetObject<float>(), GetObject<float>()};
    brush.ComputeFastBounds(rect, &rect2);
}

void BrushFuzzTestInner05(Brush& brush)
{
    brush.AsBlendMode();
    brush.Reset();
    float blurRadius = GetObject<float>();
    float dx = GetObject<float>();
    float dy = GetObject<float>();
    Color color;
    std::shared_ptr<BlurDrawLooper> blurDrawLooper = BlurDrawLooper::CreateBlurDrawLooper(blurRadius, dx, dy, color);
    brush.SetLooper(blurDrawLooper);
    brush.GetLooper();
}

bool BrushFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    Brush brush;
    Color color;
    int colorF = GetObject<int>();
    int red = GetObject<int>();
    int gree = GetObject<int>();
    int blue = GetObject<int>();
    int alpha = GetObject<int>();

    brush.SetColor(color);
    brush.SetColor(colorF);
    brush.GetColor();
    brush.SetARGB(red, gree, blue, alpha);

    BrushFuzzTestInner01(brush);
    BrushFuzzTestInner02(brush);
    BrushFuzzTestInner03(brush);
    BrushFuzzTestInner04(brush);
    BrushFuzzTestInner05(brush);

    return true;
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Rosen::Drawing::BrushFuzzTest(data, size);
    return 0;
}
