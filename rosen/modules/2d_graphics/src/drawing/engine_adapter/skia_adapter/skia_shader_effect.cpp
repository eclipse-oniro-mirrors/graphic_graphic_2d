/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "skia_shader_effect.h"

#include <vector>

#include "include/core/SkMatrix.h"
#include "include/core/SkSamplingOptions.h"
#include "include/core/SkTileMode.h"
#include "include/effects/SkGradientShader.h"
#include "include/effects/SkRuntimeEffect.h"
#include "src/core/SkReadBuffer.h"
#include "src/core/SkWriteBuffer.h"
#include "src/shaders/SkShaderBase.h"

#include "skia_helper.h"
#include "skia_image.h"
#include "skia_matrix.h"
#include "skia_picture.h"

#include "effect/shader_effect.h"
#include "image/image.h"
#include "image/picture.h"
#include "utils/matrix.h"
#include "utils/data.h"
#include "utils/log.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
SkiaShaderEffect::SkiaShaderEffect() noexcept : shader_(nullptr) {}

void SkiaShaderEffect::InitWithColor(ColorQuad color)
{
    shader_ = SkShaders::Color(color);
}

void SkiaShaderEffect::InitWithColorSpace(const Color4f& color, std::shared_ptr<ColorSpace> colorSpace)
{
    const SkColor4f& skC4f = { .fR = color.redF_, .fG = color.greenF_, .fB = color.blueF_, .fA = color.alphaF_ };
    shader_ = SkShaders::Color(skC4f, colorSpace->GetSkColorSpace());
}

void SkiaShaderEffect::InitWithBlend(const ShaderEffect& s1, const ShaderEffect& s2, BlendMode mode)
{
    auto dst = s1.GetImpl<SkiaShaderEffect>();
    auto src = s2.GetImpl<SkiaShaderEffect>();
    if (dst != nullptr && src != nullptr) {
        shader_ = SkShaders::Blend(static_cast<SkBlendMode>(mode), dst->GetShader(), src->GetShader());
    }
}

void SkiaShaderEffect::InitWithImage(
    const Image& image, TileMode tileX, TileMode tileY, const SamplingOptions& sampling, const Matrix& matrix)
{
    SkTileMode modeX = static_cast<SkTileMode>(tileX);
    SkTileMode modeY = static_cast<SkTileMode>(tileY);

    auto m = matrix.GetImpl<SkiaMatrix>();
    auto i = image.GetImpl<SkiaImage>();
    SkMatrix skiaMatrix;
    sk_sp<SkImage> skiaImage;
    if (m != nullptr && i != nullptr) {
        skiaMatrix = m->ExportSkiaMatrix();
        skiaImage = i->GetImage();
        if (skiaImage != nullptr) {
            SkSamplingOptions samplingOptions;
            if (sampling.GetUseCubic()) {
                samplingOptions = SkSamplingOptions({ sampling.GetCubicCoffB(), sampling.GetCubicCoffC() });
            } else {
                samplingOptions = SkSamplingOptions(static_cast<SkFilterMode>(sampling.GetFilterMode()),
                    static_cast<SkMipmapMode>(sampling.GetMipmapMode()));
            }
            shader_ = skiaImage->makeShader(modeX, modeY, samplingOptions, &skiaMatrix);
        }
    }
}

void SkiaShaderEffect::InitWithPicture(
    const Picture& picture, TileMode tileX, TileMode tileY, FilterMode mode, const Matrix& matrix, const Rect& rect)
{
    SkTileMode modeX = static_cast<SkTileMode>(tileX);
    SkTileMode modeY = static_cast<SkTileMode>(tileY);
    SkRect r = SkRect::MakeLTRB(rect.GetLeft(), rect.GetTop(), rect.GetRight(), rect.GetBottom());

    auto p = picture.GetImpl<SkiaPicture>();
    auto m = matrix.GetImpl<SkiaMatrix>();
    sk_sp<SkPicture> skiaPicture;
    SkMatrix skiaMatrix;
    if (p != nullptr && m != nullptr) {
        skiaPicture = p->GetPicture();
        skiaMatrix = m->ExportSkiaMatrix();
        if (skiaPicture != nullptr) {
            SkFilterMode skFilterMode = static_cast<SkFilterMode>(mode);
            shader_ = skiaPicture->makeShader(modeX, modeY, skFilterMode, &skiaMatrix, &r);
        }
    }
}

void SkiaShaderEffect::InitWithLinearGradient(const Point& startPt, const Point& endPt,
    const std::vector<ColorQuad>& colors, const std::vector<scalar>& pos, TileMode mode, const Matrix *matrix)
{
    SkPoint pts[2];
    pts[0].set(startPt.GetX(), startPt.GetY());
    pts[1].set(endPt.GetX(), endPt.GetY());

    if (colors.empty()) {
        return;
    }
    size_t colorsCount = colors.size();

    std::vector<SkColor> c;
    std::vector<SkScalar> p;
    for (size_t i = 0; i < colorsCount; ++i) {
        c.emplace_back(colors[i]);
    }
    for (size_t i = 0; i < pos.size(); ++i) {
        p.emplace_back(pos[i]);
    }
    const SkMatrix *skMatrix = nullptr;
    if (matrix != nullptr) {
        skMatrix = &matrix->GetImpl<SkiaMatrix>()->ExportSkiaMatrix();
    }
    shader_ = SkGradientShader::MakeLinear(pts, &c[0], pos.empty() ? nullptr : &p[0],
        colorsCount, static_cast<SkTileMode>(mode), 0, skMatrix);
}

void SkiaShaderEffect::InitWithRadialGradient(const Point& centerPt, scalar radius,
    const std::vector<ColorQuad>& colors, const std::vector<scalar>& pos, TileMode mode, const Matrix *matrix)
{
    SkPoint center;
    center.set(centerPt.GetX(), centerPt.GetY());

    if (colors.empty()) {
        return;
    }
    size_t colorsCount = colors.size();

    std::vector<SkColor> c;
    std::vector<SkScalar> p;
    for (size_t i = 0; i < colorsCount; ++i) {
        c.emplace_back(colors[i]);
    }
    for (size_t i = 0; i < pos.size(); ++i) {
        p.emplace_back(pos[i]);
    }
    const SkMatrix *skMatrix = nullptr;
    if (matrix != nullptr) {
        skMatrix = &matrix->GetImpl<SkiaMatrix>()->ExportSkiaMatrix();
    }
    shader_ = SkGradientShader::MakeRadial(center, radius, &c[0],
        pos.empty() ? nullptr : &p[0], colorsCount, static_cast<SkTileMode>(mode), 0, skMatrix);
}

void SkiaShaderEffect::InitWithTwoPointConical(const Point& startPt, scalar startRadius, const Point& endPt,
    scalar endRadius, const std::vector<ColorQuad>& colors, const std::vector<scalar>& pos, TileMode mode,
    const Matrix *matrix)
{
    SkPoint start;
    SkPoint end;
    start.set(startPt.GetX(), startPt.GetY());
    end.set(endPt.GetX(), endPt.GetY());

    if (colors.empty()) {
        return;
    }
    size_t colorsCount = colors.size();

    std::vector<SkColor> c;
    std::vector<SkScalar> p;
    for (size_t i = 0; i < colorsCount; ++i) {
        c.emplace_back(colors[i]);
    }
    for (size_t i = 0; i < pos.size(); ++i) {
        p.emplace_back(pos[i]);
    }
    const SkMatrix *skMatrix = nullptr;
    if (matrix != nullptr) {
        skMatrix = &matrix->GetImpl<SkiaMatrix>()->ExportSkiaMatrix();
    }

    shader_ = SkGradientShader::MakeTwoPointConical(start, startRadius, end, endRadius,
        &c[0], pos.empty() ? nullptr : &p[0], colorsCount, static_cast<SkTileMode>(mode), 0, skMatrix);
}

void SkiaShaderEffect::InitWithSweepGradient(const Point& centerPt, const std::vector<ColorQuad>& colors,
    const std::vector<scalar>& pos, TileMode mode, scalar startAngle, scalar endAngle, const Matrix *matrix)
{
    if (colors.empty()) {
        return;
    }
    size_t colorsCount = colors.size();

    std::vector<SkColor> c;
    std::vector<SkScalar> p;
    for (size_t i = 0; i < colorsCount; ++i) {
        c.emplace_back(colors[i]);
    }
    for (size_t i = 0; i < pos.size(); ++i) {
        p.emplace_back(pos[i]);
    }
    const SkMatrix *skMatrix = nullptr;
    if (matrix != nullptr) {
        skMatrix = &matrix->GetImpl<SkiaMatrix>()->ExportSkiaMatrix();
    }
    shader_ = SkGradientShader::MakeSweep(centerPt.GetX(), centerPt.GetY(), &c[0],
        pos.empty() ? nullptr : &p[0], colorsCount,
        static_cast<SkTileMode>(mode), startAngle, endAngle, 0, skMatrix);
}

sk_sp<SkShader> SkiaShaderEffect::GetShader() const
{
    return shader_;
}

void SkiaShaderEffect::SetSkShader(const sk_sp<SkShader>& skShader)
{
    shader_ = skShader;
}

std::shared_ptr<Data> SkiaShaderEffect::Serialize() const
{
    if (shader_ == nullptr) {
        LOGD("SkiaShaderEffect::Serialize, shader_ is nullptr!");
        return nullptr;
    }

    SkBinaryWriteBuffer writer;
    writer.writeFlattenable(shader_.get());
    size_t length = writer.bytesWritten();
    std::shared_ptr<Data> data = std::make_shared<Data>();
    data->BuildUninitialized(length);
    writer.writeToMemory(data->WritableData());
    return data;
}

bool SkiaShaderEffect::Deserialize(std::shared_ptr<Data> data)
{
    if (data == nullptr) {
        LOGD("SkiaShaderEffect::Deserialize, data is invalid!");
        return false;
    }
    SkReadBuffer reader(data->GetData(), data->GetSize());
    shader_ = reader.readShader();
    return true;
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS