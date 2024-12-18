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
#include <unordered_map>
#ifdef RS_ENABLE_SDF
#include "cache/sdf_cache_manager.h"
#endif

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
#include "securec.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

std::unordered_map<int, SkRuntimeEffect::Result> SkiaShaderEffect::shaderEffectCaches_;

SkiaShaderEffect::SkiaShaderEffect() noexcept : shader_(nullptr) {}

void SkiaShaderEffect::InitWithColor(ColorQuad color)
{
    shader_ = SkShaders::Color(color);
}

void SkiaShaderEffect::InitWithColorSpace(const Color4f& color, std::shared_ptr<ColorSpace> colorSpace)
{
    const SkColor4f& skC4f = { .fR = color.redF_, .fG = color.greenF_, .fB = color.blueF_, .fA = color.alphaF_ };
    if (colorSpace == nullptr) {
        shader_ = SkShaders::Color(skC4f, nullptr);
        return;
    }
    auto skiaColorSpace = colorSpace->GetImpl<SkiaColorSpace>();
    shader_ = SkShaders::Color(skC4f, skiaColorSpace ? skiaColorSpace->GetColorSpace() : nullptr);
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

void SkiaShaderEffect::InitWithLightUp(const float& lightUpDeg, const ShaderEffect& imageShader)
{
    auto imageShaderImpl_ = imageShader.GetImpl<SkiaShaderEffect>();
    if (imageShaderImpl_ != nullptr) {
        static constexpr char prog[] = R"(
            uniform half lightUpDeg;
            uniform shader imageShader;
            vec3 rgb2hsv(in vec3 c)
            {
                vec4 K = vec4(0.0, -1.0 / 3.0, 2.0 / 3.0, -1.0);
                vec4 p = mix(vec4(c.bg, K.wz), vec4(c.gb, K.xy), step(c.b, c.g));
                vec4 q = mix(vec4(p.xyw, c.r), vec4(c.r, p.yzx), step(p.x, c.r));
                float d = q.x - min(q.w, q.y);
                float e = 1.0e-10;
                return vec3(abs(q.z + (q.w - q.y) / (6.0 * d + e)), d / (q.x + e), q.x);
            }
            vec3 hsv2rgb(in vec3 c)
            {
                vec3 rgb = clamp(abs(mod(c.x * 6.0 + vec3(0.0, 4.0, 2.0), 6.0) - 3.0) - 1.0, 0.0, 1.0);
                return c.z * mix(vec3(1.0), rgb, c.y);
            }
            half4 main(float2 coord)
            {
                vec3 hsv = rgb2hsv(imageShader.eval(coord).rgb);
                float satUpper = clamp(hsv.y * 1.2, 0.0, 1.0);
                hsv.y = mix(satUpper, hsv.y, lightUpDeg);
                hsv.z += lightUpDeg - 1.0;
                return vec4(hsv2rgb(hsv), imageShader.eval(coord).a);
            }
        )";
        auto [effect, err] = SkRuntimeEffect::MakeForShader(SkString(prog));
        sk_sp<SkShader> children[] = {imageShaderImpl_->GetShader()};
        size_t childCount = 1;
        shader_ = effect->makeShader(SkData::MakeWithCopy(
            &lightUpDeg, sizeof(lightUpDeg)), children, childCount, nullptr, false);
    } else {
        LOGE("SkiaShaderEffect::InitWithLightUp: imageShader is nullptr");
    }
}


SkRuntimeEffect::Result SkiaShaderEffect::GetShaderResultInstance(int shapeId, std::string shaderStr)
{
    auto shaderIterator = shaderEffectCaches_.find(shapeId);
    if (shaderIterator != shaderEffectCaches_.end()) {
        LOGE("SCP cache first enter");
        return shaderIterator->second;
    }
    LOGE("SCP cache second enter");
    auto result = SkRuntimeEffect::MakeForShader(static_cast<SkString>(shaderStr));
    shaderEffectCaches_.insert({shapeId, result});
    return result;
}

#ifdef RS_ENABLE_SDF
SkRuntimeEffect::Result GetShaderResultFromCache(int shapeId, const std::string& shaderStr)
{
    SkRuntimeEffect::Result result;
    std::shared_ptr<SDFCacheManager<SkRuntimeEffect::Result>> mgr = SDFCacheManager<SkRuntimeEffect::Result>::GetInstance();
    bool succ = mgr->GetCache(shapeId, result);
    if (succ) {
        LOGE("SCP new cache first enter");
        return result;
    }
    LOGE("SCP new cache second enter");
    auto shaderResult = SkRuntimeEffect::MakeForShader(static_cast<SkString>(shaderStr));
    mgr->SetCache(shapeId, shaderResult);
    return shaderResult;
}
#endif
 
void SkiaShaderEffect::InitWithSdf(const SDFShapeBase& shape)
{
    std::string shaderString = shape.Getshader();
    if (shaderString.size() == 0) {
        LOGE("sdf shape is empty. return on line %{public}d", __LINE__);
        return;
    }

    #ifdef RS_ENABLE_SDF
    auto [effect, err] = GetShaderResultFromCache(shape.GetShapeId(), shaderString);
    #else
    auto [effect, err] = SkRuntimeEffect::MakeForShader(static_cast<SkString>(shaderString));
    #endif
    if (effect == nullptr) {
        LOGE("sdf make shader fail : %{public}s", err.c_str());
        return;
    }
    SkRuntimeShaderBuilder builder(effect);
 
    std::vector<float> para = shape.GetPara();
    std::vector<float> transPara = shape.GetTransPara();
    std::vector<float> paintPara = shape.GetPaintPara();
    std::vector<float> colorParam = shape.GetPointAndColorPara();
    uint64_t transCount = transPara.size();
    uint64_t paraCount = para.size();
    uint64_t paintParaCount = paintPara.size();
    uint64_t pointAndColorParaCount = colorParam.size();
 
    for (uint64_t i = 0; i < pointAndColorParaCount; i++) {
        char buf[15] = {0}; // maximum length of string needed is 10.
        if (sprintf_s(buf, sizeof(buf), "pColorPara%lu", i) != -1) {
            builder.uniform(buf) = colorParam[i];
        } else {
            LOGE("sdf splicing pColorPara error.");
            return;
        }
    }
 
    for (uint64_t i = 1; i <= paraCount; i++) {
        char buf[15] = {0}; // maximum length of string needed is 10.
        if (sprintf_s(buf, sizeof(buf), "para%lu", i) != -1) {
            builder.uniform(buf) = para[i-1];
        } else {
            LOGE("sdf splicing para error.");
            return;
        }
    }
 
    for (uint64_t i = 0; i < paintParaCount; i++) {
        char buf[15] = {0}; // maximum length of string needed is 10.
        if (sprintf_s(buf, sizeof(buf), "paintPara%lu", i) != -1) {
            builder.uniform(buf) = paintPara[i];
        } else {
            LOGE("sdf splicing para error.");
            return;
        }
    }
 
    for (uint64_t i = 1; i <= transCount; i++) {
        char buf[15] = {0}; // maximum length of string needed is 15.
        if (sprintf_s(buf, sizeof(buf), "transpara%lu", i) != -1) {
            builder.uniform(buf) = transPara[i-1];
        } else {
            LOGE("sdf splicing para error.");
            return;
        }
    }

    std::vector<float> color = shape.GetColorPara();
    builder.uniform("sdfalpha") = color[0]; // color_[0] is color alpha channel.
    for (uint64_t i = 1; i < color.size(); i++) {
        char buf[15] = {0}; // maximum length of string needed is 15.
        if (sprintf_s(buf, sizeof(buf), "colpara%lu", i) != -1) {
            builder.uniform(buf) = color[i];
        } else {
            LOGE("sdf splicing para error.");
            return;
        }
    }
    
    SkV2 size = SkV2{shape.GetBoundsRect().GetWidth(), shape.GetBoundsRect().GetHeight()};
    builder.uniform("size") = size;
    builder.uniform("sdfsize") = shape.GetSize();
    builder.uniform("filltype") = shape.GetFillType();
    builder.uniform("translatex") = shape.GetTranslateX();
    builder.uniform("translatey") = shape.GetTranslateY();
    builder.uniform("width") = shape.GetBoundsRect().GetWidth();
    builder.uniform("transparent") = shape.GetTransparent();
    shader_ = builder.makeShader(nullptr, false);
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