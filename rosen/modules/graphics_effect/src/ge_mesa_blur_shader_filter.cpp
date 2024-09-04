/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ge_mesa_blur_shader_filter.h"

#include "ge_log.h"
#include "ge_system_properties.h"
#include "src/core/SkOpts.h"

#include "effect/color_matrix.h"
#include <vector>

namespace OHOS {
namespace Rosen {
#define PROPERTY_KAWASE_ORIGINAL_IMAGE "persist.sys.graphic.kawaseOriginalEnable"

namespace {
static constexpr float BASE_BLUR_SCALE = 0.5f; // 0.5: base downSample radio
static constexpr float BLUR_SCALE_1 = 0.25f; // 0.25 : downSample scale for step1
static constexpr float BLUR_SCALE_2 = 0.125f; // 0.125 : downSample scale for step1p5
static constexpr float BLUR_SCALE_3 = 0.0625f; // 0.0625 : downSample scale for step2
static constexpr float BLUR_SCALE_4 = 0.03125f; // 0.03125 : downSample scale for step3
static constexpr int BLUR_RADIUS_1 = 8; // 8 : radius step1
static constexpr int BLUR_RADIUS_1P5 = 20; // 20 : radius step1.5
static constexpr int BLUR_RADIUS_20 = 24; // 24 : radius step2-0
static constexpr int BLUR_RADIUS_21 = 80; // 80 : radius step2-1
static constexpr int BLUR_RADIUS_2 = 100; // 100 : radius step2
static constexpr int BLUR_RADIUS_3 = 200; // 200 : radius step3
static std::shared_ptr<Drawing::RuntimeEffect> g_blurEffect;
static std::shared_ptr<Drawing::RuntimeEffect> g_mixEffect;
static std::shared_ptr<Drawing::RuntimeEffect> g_simpleFilter;
static std::shared_ptr<Drawing::RuntimeEffect> g_greyAdjustEffect;

static const std::vector<std::vector<float>> offsetTableFourPasses = {
    {{1.421365322425756, 1.421365322425756, 2.52888420687976, 1.6983888474288191,
      0.5060327516701945, 2.477687296510791, 2.645538868459866, 0.4675865935441517}},
    {{1.5532466535764577, 1.5532466535764577, 3.260647277662576, 2.6149639458271343,
      1.492416795484721, 3.3432890011050254, 2.559487807195717, 0.362113179598861}}
};

static const std::vector<std::vector<float>> offsetTableFivePasses = {
    {{1.29351593, 1.29351593, 0.53793921, 1.5822416, 1.58224067,
      0.53794761, 1.58223699, 0.5379565, 0.53795194, 1.58223997}},
    {{1.4925693309454728, 1.4925693309454728, 1.248431515423821, 2.1609475057344536, 2.3006446212434306,
      0.38158524446502357, 2.160947472355003, 1.248431447998051, 0.3815852898151447, 2.300644665028775}},
    {{2.461169146598135, 2.461169146598135, 1.5094283743591717, 1.5185693547666796, 3.2470361889434103,
      0.5465662643903497, 2.6710526969877204, 1.456340654010302, 0.47564642926095513, 2.5790346948641893}},
    {{2.7877137008630277, 2.7877137008630277, 1.368781571748399, 1.3779906041976446, 4.275711858457529,
      1.5175122219974202, 2.779896417187395, 1.5946441694737459, 0.6545369425231907, 3.5714310651049317}},
    {{3.409158646436388, 3.409158646436388, 1.3807194929023436, 1.6494765647589356, 4.638321454662683,
      2.304041644534522, 2.6625386778188735, 1.554841535232042, 0.5313373875839217, 4.660706115409412}},
    {{4.425333740948246, 4.425333740948246, 1.1845267031766928, 1.4500896889624584, 5.313559133773294,
      2.4323499776778643, 2.606322065282447, 1.2553675953527443, 1.1729490480100304, 5.166409017496668}},
    {{4.710484187853573, 4.710484187853573, 1.4007370136555897, 1.2562595222759485, 6.5684867433401495,
      2.4384921005985807, 3.2541990928397246, 1.4465647404038315, 1.436550871193364, 5.52173166041527}},
    {{5.561630104245352, 5.561630104245352, 1.419409904905922, 1.556544555489513, 6.592301531601723,
      3.277577833641203, 3.3151278290421873, 1.573561193200789, 1.3588630736274054, 6.361664806350875}},
};

} // namespace

static bool GetKawaseOriginalEnabled()
{
#ifdef GE_OHOS
    static bool kawaseOriginalEnabled =
        (std::atoi(GESystemProperties::GetEventProperty(PROPERTY_KAWASE_ORIGINAL_IMAGE).c_str()) != 0);
    return kawaseOriginalEnabled;
#else
    return false;
#endif
}

GEMESABlurShaderFilter::GEMESABlurShaderFilter(const Drawing::GEMESABlurShaderFilterParams& params)
    : radius_(params.radius), greyCoef1_(params.greyCoef1), greyCoef2_(params.greyCoef2),
      stretchOffsetX_(params.offsetX), stretchOffsetY_(params.offsetY),
      stretchOffsetZ_(params.offsetZ), stretchOffsetW_(params.offsetW),
      tileMode_(static_cast<Drawing::TileMode>(params.tileMode)), width_(params.width), height_(params.height)
{
    if (!InitBlurEffect() || !InitMixEffect() || !InitSimpleFilter()) {
        return;
    }

    if (radius_ < 1) {
        LOGI("GEMESABlurShaderFilter radius(%{public}d) should be [1, 8k], ignore blur.", radius_);
        radius_ = 0;
    }

    if (radius_ > 8000) { // 8000 experienced value
        LOGI("GEMESABlurShaderFilter radius(%{public}d) should be [1, 8k], change to 8k.", radius_);
        radius_ = 8000; // 8000 experienced value
    }

    if (greyCoef1_ > 1e-6 || greyCoef2_ > 1e-6) {
        isGreyX_ = 1;
        LOGD("GEMESABlurShaderFilter::GreyAdjustment fuzed with blur:greycoef1 = %{public}f, greycoef2 = %{public}f",
            greyCoef1_, greyCoef2_);
        if (!InitGreyAdjustmentEffect()) {
            return;
        }
    }
}

void GEMESABlurShaderFilter::SetBlurParamsFivePassSmall(NewBlurParams& bParam)
{
    int stride = 2;     // 2: stride
    // 5: five passes
    int numberOfPasses = 5;
    int index;
    // 1.f: initial scaling rate
    float scale = 1.f;
    float w1;
    if (blurRadius_ < BLUR_RADIUS_20) {
        scale = blurRadius_ / static_cast<float>(BLUR_RADIUS_20);
        index = 0;
        w1 = 0;
    } else if (blurRadius_ > BLUR_RADIUS_21) {
        scale = blurRadius_ / static_cast<float>(BLUR_RADIUS_21);
        // 8: blur param
        index = (BLUR_RADIUS_21 - BLUR_RADIUS_20) / 8;
        w1 = 0;
    } else {
        // 0.125: blur param
        float findex = (blurRadius_ - BLUR_RADIUS_20) * 0.125;
        index = floor(findex);
        w1 = findex - index;
    }
    if (fabs(w1) < 1e-6) {
        for (int i = 0; i < numberOfPasses; i++) {
            bParam.offsets[stride * i] = scale * offsetTableFivePasses[index][stride * i];
            bParam.offsets[stride * i + 1] = scale * offsetTableFivePasses[index][stride * i + 1];
        }
    } else {
        float w2 = 1 - w1;
        for (int i = 0; i < numberOfPasses; i++) {
            bParam.offsets[stride * i] = w2 * offsetTableFivePasses[index][stride * i] +
                                            w1 * offsetTableFivePasses[index + 1][stride * i];
            bParam.offsets[stride * i + 1] = w2 * offsetTableFivePasses[index][stride * i + 1] +
                                                w1 * offsetTableFivePasses[index + 1][stride * i + 1];
        }
    }
    bParam.numberOfPasses = numberOfPasses;
    return;
}

void GEMESABlurShaderFilter::SetBlurParamsFivePassLarge(NewBlurParams& bParam)
{
    int stride = 2;     // 2: stride
    // 5: five passes
    int numberOfPasses = 5;
    float scale;
    if (blurRadius_ < BLUR_RADIUS_3) {
        // 0.5: scaling rate
        scale = blurRadius_ / static_cast<float>(BLUR_RADIUS_21) * 0.5;
    } else {
        // 0.25: scaling rate
        scale = blurRadius_ / static_cast<float>(BLUR_RADIUS_21) * 0.25;
    }
    int index = (BLUR_RADIUS_21 - BLUR_RADIUS_20) / 8;
    for (int i = 0; i < numberOfPasses; i++) {
        bParam.offsets[stride * i] = scale * offsetTableFivePasses[index][stride * i];
        bParam.offsets[stride * i + 1] = scale * offsetTableFivePasses[index][stride * i + 1];
    }
    bParam.numberOfPasses = numberOfPasses;
    return;
}

void GEMESABlurShaderFilter::SetBlurParams(NewBlurParams& bParam)
{
    int stride = 2;     // 2: stride
    int numberOfPasses;
    if (blurRadius_ < BLUR_RADIUS_1) {
        // 2: min number of pass, 4: fixed four passes
        numberOfPasses = std::max(2, std::min(4, static_cast<int>(blurRadius_)));
        float mys = blurRadius_ * 0.125;    // 0.125: scaling rate
        for (int i = 0; i < numberOfPasses; i++) {
            bParam.offsets[stride * i] = offsetTableFourPasses[0][stride * i] * mys;
            bParam.offsets[stride * i + 1] = offsetTableFourPasses[0][stride * i + 1] * mys;
        }
        if (blurRadius_ >= BLUR_RADIUS_1 - stride) {
            // 3: pre-filtering when the radius is larger than the calculated value
            // 0.33333333: scaling rate.
            // 1.8: blur param
            float blurParam = 1.8;
            float perf = (blurRadius_ - BLUR_RADIUS_1) * 0.33333333 + 1;
            bParam.offsets[stride * numberOfPasses] = blurParam * perf;
            bParam.offsets[stride * numberOfPasses + 1] = blurParam * perf;
            numberOfPasses++;
        }
        bParam.numberOfPasses = numberOfPasses;
        return;
    }
    if (blurRadius_ < BLUR_RADIUS_1P5) {
        // 4: four passes
        numberOfPasses = 4;
        // 16.0: scaling rate
        float scale = blurRadius_ / 16.0;
        for (int i = 0; i < numberOfPasses; i++) {
            bParam.offsets[stride * i] = scale * offsetTableFourPasses[0][stride * i];
            bParam.offsets[stride * i + 1] = scale * offsetTableFourPasses[0][stride * i + 1];
        }

        int newStride = 3;
        if (blurRadius_ >= BLUR_RADIUS_1P5 - newStride) {
            // 4: pre-filtering when the radius is larger than the calculated value
            // 0.4, 0.35: blur param
            float blurParamA = 0.4;
            float blurParamB = 0.35;
            float perf = (blurRadius_ - BLUR_RADIUS_1P5 + newStride + 1);
            bParam.offsets[stride * numberOfPasses] = blurParamA * perf + blurParamB;
            bParam.offsets[stride * numberOfPasses + 1] = blurParamA * perf + blurParamB;
            numberOfPasses++;
        }
        bParam.numberOfPasses = numberOfPasses;
        return;
    }
    if (blurRadius_ < BLUR_RADIUS_2) {
        SetBlurParamsFivePassSmall(bParam);
    } else {
        SetBlurParamsFivePassLarge(bParam);
    }
    return;
}

int GEMESABlurShaderFilter::GetRadius() const
{
    return radius_;
}

std::shared_ptr<Drawing::ShaderEffect> GEMESABlurShaderFilter::ApplyGreyAdjustmentFilter(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image>& input, const std::shared_ptr<Drawing::ShaderEffect>& prevShader,
    const Drawing::ImageInfo& scaledInfo, const Drawing::SamplingOptions& linear) const
{
    Drawing::RuntimeShaderBuilder builder(g_greyAdjustEffect);
    builder.SetChild("imageShader", prevShader);
    builder.SetUniform("coefficient1", greyCoef1_);
    builder.SetUniform("coefficient2", greyCoef2_);
    std::shared_ptr<Drawing::Image> tmpBlur(builder.MakeImage(
        canvas.GetGPUContext().get(), nullptr, scaledInfo, false));
    return GetShaderEffect(tmpBlur, linear, Drawing::Matrix());
}

std::shared_ptr<Drawing::ShaderEffect> GEMESABlurShaderFilter::GetShaderEffect(
    const std::shared_ptr<Drawing::Image>& image, const Drawing::SamplingOptions& linear,
    const Drawing::Matrix& matrix) const
{
    if (!image) {
        return nullptr;
    }
    return Drawing::ShaderEffect::CreateImageShader(*image, Drawing::TileMode::CLAMP,
        Drawing::TileMode::CLAMP, linear, matrix);
}

std::shared_ptr<Drawing::Image> GEMESABlurShaderFilter::DownSampling2X(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image>& input, const Drawing::Rect& src, const Drawing::ImageInfo& scaledInfo,
    const Drawing::SamplingOptions& linear, const NewBlurParams& blur) const
{
    Drawing::RuntimeShaderBuilder blurBuilder(g_blurEffect);
    const auto& blurMatrix = BuildMatrix(src, scaledInfo, input);
    auto tmpShader = Drawing::ShaderEffect::CreateImageShader(*input, Drawing::TileMode::CLAMP,
        Drawing::TileMode::CLAMP, linear, blurMatrix);
    if (isGreyX_) {
        tmpShader = ApplyGreyAdjustmentFilter(canvas, input, tmpShader, scaledInfo, linear);
        if (!tmpShader) {
            return nullptr;
        }
    }
    blurBuilder.SetChild("imageInput", tmpShader);
    blurBuilder.SetUniform("in_blurOffset", blur.offsets[0], blur.offsets[1]);
    return blurBuilder.MakeImage(canvas.GetGPUContext().get(), nullptr, scaledInfo, false);
}

std::shared_ptr<Drawing::Image> GEMESABlurShaderFilter::DownSampling4X(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image>& input, const Drawing::Rect& src, const Drawing::ImageInfo& scaledInfo,
    const Drawing::SamplingOptions& linear, const NewBlurParams& blur) const
{
    Drawing::RuntimeShaderBuilder blurBuilder(g_blurEffect);
    const auto& blurMatrix = BuildMatrix(src, scaledInfo, input);
    blurBuilder.SetChild("imageInput", Drawing::ShaderEffect::CreateImageShader(*input,
        Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP, linear, blurMatrix));
    blurBuilder.SetUniform("in_blurOffset", BLUR_SCALE_1, BLUR_SCALE_1);
    if (isGreyX_) {
        auto tmpShader = blurBuilder.MakeShader(nullptr, input->IsOpaque());
        tmpShader = ApplyGreyAdjustmentFilter(canvas, input, tmpShader, scaledInfo, linear);
        if (!tmpShader) {
            return nullptr;
        }
        blurBuilder.SetChild("imageInput", tmpShader);
        blurBuilder.SetUniform("in_blurOffset", blur.offsets[0], blur.offsets[1]);
    }
    return blurBuilder.MakeImage(canvas.GetGPUContext().get(), nullptr, scaledInfo, false);
}

std::shared_ptr<Drawing::Image> GEMESABlurShaderFilter::DownSampling8X(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image>& input, const Drawing::Rect& src,
    const Drawing::ImageInfo& scaledInfo, const Drawing::ImageInfo& middleInfo,
    const Drawing::SamplingOptions& linear, const NewBlurParams& blur) const
{
    Drawing::RuntimeShaderBuilder blurBuilder(g_blurEffect);
    Drawing::Matrix blurMatrix = BuildMiddleMatrix(middleInfo, input->GetImageInfo());
    Drawing::Matrix inputMatrix = BuildStretchMatrix(src, input->GetWidth(), input->GetHeight());
    inputMatrix.PostConcat(blurMatrix);
    blurBuilder.SetChild("imageInput", Drawing::ShaderEffect::CreateImageShader(*input,
        tileMode_, tileMode_, linear, inputMatrix));
    blurBuilder.SetUniform("in_blurOffset", BLUR_SCALE_1, BLUR_SCALE_1);
    std::shared_ptr<Drawing::Image> tmpBlur_pre(blurBuilder.MakeImage(canvas.GetGPUContext().get(),
        nullptr, middleInfo, false));
    if (!tmpBlur_pre) {
        return nullptr;
    }
    Drawing::Matrix blurMatrixA = BuildMiddleMatrix(scaledInfo, middleInfo);
    Drawing::RuntimeShaderBuilder simpleBlurBuilder(g_simpleFilter);
    simpleBlurBuilder.SetChild("imageInput", Drawing::ShaderEffect::CreateImageShader(*tmpBlur_pre,
        Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP, linear, blurMatrixA));
    if (isGreyX_) {
        auto tmpShader = simpleBlurBuilder.MakeShader(nullptr, input->IsOpaque());
        tmpShader = ApplyGreyAdjustmentFilter(canvas, input, tmpShader, scaledInfo, linear);
        if (!tmpShader) {
            return nullptr;
        }
        blurBuilder.SetChild("imageInput", tmpShader);
        blurBuilder.SetUniform("in_blurOffset", blur.offsets[0], blur.offsets[1]);
    } else {
        tmpBlur_pre = simpleBlurBuilder.MakeImage(canvas.GetGPUContext().get(), nullptr, scaledInfo, false);
        if (!tmpBlur_pre) {
            return nullptr;
        }
        blurBuilder.SetChild("imageInput", Drawing::ShaderEffect::CreateImageShader(*tmpBlur_pre,
            Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP, linear, Drawing::Matrix()));
        blurBuilder.SetUniform("in_blurOffset", blur.offsets[0], blur.offsets[1]);
    }
    return blurBuilder.MakeImage(canvas.GetGPUContext().get(), nullptr, scaledInfo, false);
}

std::shared_ptr<Drawing::Image> GEMESABlurShaderFilter::DownSamplingMoreX(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image>& input, const Drawing::Rect& src,
    const Drawing::ImageInfo& scaledInfo, const Drawing::ImageInfo& middleInfo, const Drawing::ImageInfo& middleInfo2,
    const Drawing::SamplingOptions& linear, const NewBlurParams& blur) const
{
    Drawing::RuntimeShaderBuilder blurBuilder(g_blurEffect);
    Drawing::Matrix blurMatrix = BuildMiddleMatrix(middleInfo, input->GetImageInfo());
    Drawing::Matrix inputMatrix = BuildStretchMatrix(src, input->GetWidth(), input->GetHeight());
    inputMatrix.PostConcat(blurMatrix);
    blurBuilder.SetChild("imageInput", Drawing::ShaderEffect::CreateImageShader(*input,
        tileMode_, tileMode_, linear, inputMatrix));
    blurBuilder.SetUniform("in_blurOffset", BLUR_SCALE_1, BLUR_SCALE_1);
    std::shared_ptr<Drawing::Image> tmpBlur_pre(blurBuilder.MakeImage(canvas.GetGPUContext().get(),
        nullptr, middleInfo, false));
    if (!tmpBlur_pre) {
        return nullptr;
    }
    Drawing::Matrix blurMatrixA = BuildMiddleMatrix(middleInfo2, middleInfo);
    blurBuilder.SetChild("imageInput", Drawing::ShaderEffect::CreateImageShader(*tmpBlur_pre,
        Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP, linear, blurMatrixA));
    blurBuilder.SetUniform("in_blurOffset", BLUR_SCALE_1, BLUR_SCALE_1);
    if (isGreyX_) {
        Drawing::RuntimeShaderBuilder builder(g_greyAdjustEffect);
        builder.SetChild("imageShader", blurBuilder.MakeShader(nullptr, input->IsOpaque()));
        builder.SetUniform("coefficient1", greyCoef1_);
        builder.SetUniform("coefficient2", greyCoef2_);
        tmpBlur_pre = builder.MakeImage(canvas.GetGPUContext().get(), nullptr, middleInfo2, false);
    } else {
        tmpBlur_pre = blurBuilder.MakeImage(canvas.GetGPUContext().get(), nullptr, middleInfo2, false);
    }
    Drawing::Matrix blurMatrix2 = BuildMiddleMatrix(scaledInfo, middleInfo2);
    blurBuilder.SetChild("imageInput", Drawing::ShaderEffect::CreateImageShader(*tmpBlur_pre,
        Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP, linear, blurMatrix2));
    blurBuilder.SetUniform("in_blurOffset", blur.offsets[0], blur.offsets[1]);
    return blurBuilder.MakeImage(canvas.GetGPUContext().get(), nullptr, scaledInfo, false);
}

std::shared_ptr<Drawing::Image> GEMESABlurShaderFilter::DownSampling(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image>& input, const Drawing::Rect& src,
    const Drawing::ImageInfo& scaledInfo, int& width, int& height,
    const Drawing::SamplingOptions& linear, const NewBlurParams& blur) const
{
    auto originImageInfo = input->GetImageInfo();
    auto middleInfo = Drawing::ImageInfo(std::ceil(width * BLUR_SCALE_1), std::ceil(height * BLUR_SCALE_1),
        originImageInfo.GetColorType(), originImageInfo.GetAlphaType(), originImageInfo.GetColorSpace());
    if (blurScale_ > BLUR_SCALE_1 + 1e-4) {
        return DownSampling2X(canvas, input, src, scaledInfo, linear, blur);
    } else if (blurScale_ > BLUR_SCALE_2 + 1e-4) {
        return DownSampling4X(canvas, input, src, scaledInfo, linear, blur);
    } else if (blurScale_ > BLUR_SCALE_3 + 1e-4) {
        return DownSampling8X(canvas, input, src, scaledInfo, middleInfo, linear, blur);
    } else {
        auto middleInfo2 = Drawing::ImageInfo(std::ceil(width * BLUR_SCALE_3), std::ceil(height * BLUR_SCALE_3),
            originImageInfo.GetColorType(), originImageInfo.GetAlphaType(), originImageInfo.GetColorSpace());
        return DownSamplingMoreX(canvas, input, src, scaledInfo, middleInfo, middleInfo2, linear, blur);
    }
}

std::shared_ptr<Drawing::Image> GEMESABlurShaderFilter::ProcessImage(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image> image, const Drawing::Rect& src, const Drawing::Rect& dst)
{
    if (!IsInputValid(canvas, image, src, dst)) {
        return image;
    }
    CalculatePixelStretch(image->GetWidth(), image->GetHeight());

    // Even so there is no blur, we may need to make greyadjustment and pixel stretch.
    if (radius_ <= 0 || radius_ >= 8000 || GetKawaseOriginalEnabled()) {  // 8000 experienced value
        return OutputImageWithoutBlur(canvas, image, src, dst);
    }

    auto input = image;
    CheckInputImage(canvas, image, input, src);
    ComputeRadiusAndScale(radius_);
    NewBlurParams blur;
    SetBlurParams(blur);
    auto originImageInfo = input->GetImageInfo();
    auto width = std::max(static_cast<int>(std::ceil(dst.GetWidth())), input->GetWidth());
    auto height = std::max(static_cast<int>(std::ceil(dst.GetHeight())), input->GetHeight());
    auto scaledInfo = Drawing::ImageInfo(std::ceil(width * blurScale_), std::ceil(height * blurScale_),
        originImageInfo.GetColorType(), originImageInfo.GetAlphaType(), originImageInfo.GetColorSpace());
    Drawing::RuntimeShaderBuilder blurBuilder(g_blurEffect);
    Drawing::SamplingOptions linear(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NONE);
    LOGD("GEMESABlurShaderFilter:: sigma = %{public}f, numberOfPasses = %{public}f",
        blurRadius_, 1.0 * blur.numberOfPasses);

    std::shared_ptr<Drawing::Image> tmpBlur = DownSampling(canvas, input, src, scaledInfo,
        width, height, linear, blur);
    if (!tmpBlur) {
        LOGE("GEMESABlurShaderFilter::ProcessImage make image error when downsampling");
        return image;
    }

    int stride = 2;     // 2: stride
    int i_start = 1;
    if (fabs(blurScale_ - BLUR_SCALE_1) < 1e-4 && (!isGreyX_)) {
        // 0: staring from zero when blurScale_ = 0.25 and isGreyX_ = false
        i_start = 0;
    }
    for (auto i = i_start; i < blur.numberOfPasses; i++) {
        blurBuilder.SetChild("imageInput", Drawing::ShaderEffect::CreateImageShader(*tmpBlur,
            Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP, linear, Drawing::Matrix()));
        blurBuilder.SetUniform("in_blurOffset", blur.offsets[stride * i], blur.offsets[stride * i + 1]);
        tmpBlur = blurBuilder.MakeImage(canvas.GetGPUContext().get(), nullptr, scaledInfo, false);
    }

    auto output = ScaleAndAddRandomColor(canvas, input, tmpBlur, src, dst, width, height);
    return output;
}

bool GEMESABlurShaderFilter::IsInputValid(Drawing::Canvas& canvas, const std::shared_ptr<Drawing::Image>& image,
    const Drawing::Rect& src, const Drawing::Rect& dst)
{
    if (!g_blurEffect || !g_mixEffect || !image || !g_simpleFilter || (isGreyX_ && !g_greyAdjustEffect)) {
        LOGE("GEMESABlurShaderFilter::IsInputValid invalid shader or image");
        return false;
    }
    return true;
}

Drawing::Matrix GEMESABlurShaderFilter::BuildMatrix(
    const Drawing::Rect& src, const Drawing::ImageInfo& scaledInfo, const std::shared_ptr<Drawing::Image>& input) const
{
    Drawing::Matrix blurMatrix;
    blurMatrix.Translate(-src.GetLeft(), -src.GetTop());
    int scaleWidth = scaledInfo.GetWidth();
    int width = input->GetWidth();
    float scaleW = static_cast<float>(scaleWidth) / (width > 0 ? width : 1);

    int scaleHeight = scaledInfo.GetHeight();
    int height = input->GetHeight();
    float scaleH = static_cast<float>(scaleHeight) / (height > 0 ? height : 1);
    blurMatrix.PostScale(scaleW, scaleH);
    return blurMatrix;
}

Drawing::Matrix GEMESABlurShaderFilter::BuildMiddleMatrix(
    const Drawing::ImageInfo& scaledInfo, const Drawing::ImageInfo& middleInfo) const
{
    Drawing::Matrix blurMatrixA;
    int width = middleInfo.GetWidth();
    auto scaleW = static_cast<float>(scaledInfo.GetWidth()) / (width > 0 ? width : 1);
    int height = middleInfo.GetHeight();
    auto scaleH = static_cast<float>(scaledInfo.GetHeight()) / (height > 0 ? height : 1);
    blurMatrixA.SetScale(scaleW, scaleH);
    return blurMatrixA;
}

Drawing::Matrix GEMESABlurShaderFilter::BuildStretchMatrixFull(const Drawing::Rect& src,
    const Drawing::Rect& dst, int imageWidth, int imageHeight) const
{
    Drawing::Matrix matrix;
    float scaleW = static_cast<float>((dst.GetWidth() - offsetX_ - offsetZ_)) / (imageWidth > 0 ? imageWidth : 1);
    float scaleH = static_cast<float>((dst.GetHeight() - offsetY_ - offsetW_)) / (imageHeight > 0 ? imageHeight : 1);
    matrix.Translate(-src.GetLeft(), -src.GetTop());
    matrix.PostScale(scaleW, scaleH);

    Drawing::Matrix translateMatrix;
    translateMatrix.Translate(dst.GetLeft() + offsetX_, dst.GetTop() + offsetY_);
    matrix.PostConcat(translateMatrix);

    return matrix;
}

Drawing::Matrix GEMESABlurShaderFilter::BuildStretchMatrix(const Drawing::Rect& src,
    int imageWidth, int imageHeight) const
{
    Drawing::Matrix matrix;
    float scaleW = static_cast<float>((imageWidth - offsetX_ - offsetZ_)) / (imageWidth > 0 ? imageWidth : 1);
    float scaleH = static_cast<float>((imageHeight - offsetY_ - offsetW_)) / (imageHeight > 0 ? imageHeight : 1);
    matrix.Translate(-src.GetLeft(), -src.GetTop());
    matrix.PostScale(scaleW, scaleH);

    Drawing::Matrix translateMatrix;
    translateMatrix.Translate(offsetX_, offsetY_);
    matrix.PostConcat(translateMatrix);

    return matrix;
}

bool GEMESABlurShaderFilter::InitBlurEffect()
{
    if (g_blurEffect != nullptr) {
        return true;
    }

    static const std::string blurStringMESA(R"(
        uniform shader imageInput;
        uniform float2 in_blurOffset;

        half4 main(float2 xy) {
            half4 c = imageInput.eval(float2(in_blurOffset.x + xy.x, in_blurOffset.y + xy.y));
            c += imageInput.eval(float2(-in_blurOffset.y + xy.x, in_blurOffset.x + xy.y));
            c += imageInput.eval(float2(-in_blurOffset.x + xy.x, -in_blurOffset.y + xy.y));
            c += imageInput.eval(float2(in_blurOffset.y + xy.x, -in_blurOffset.x + xy.y));
            return half4(c.rgba * 0.25);
        }
    )");

    g_blurEffect = Drawing::RuntimeEffect::CreateForShader(blurStringMESA);
    if (g_blurEffect == nullptr) {
        LOGE("GEMESABlurShaderFilter::RuntimeShader blurEffect create failed");
        return false;
    }

    return true;
}

bool GEMESABlurShaderFilter::InitMixEffect()
{
    if (g_mixEffect != nullptr) {
        return true;
    }

    static const std::string mixStringMESA(R"(
        uniform shader blurredInput;
        uniform float inColorFactor;

        highp float random(float2 xy) {
            float t = dot(xy, float2(78.233, 12.9898));
            return fract(sin(t) * 43758.5453);
        }

        half4 main(float2 xy) {
            highp float noiseGranularity = inColorFactor / 255.0;
            half4 finalColor = blurredInput.eval(xy);
            float noise  = mix(-noiseGranularity, noiseGranularity, random(xy));
            finalColor.rgb += noise;
            return finalColor;
        }
    )");

    g_mixEffect = Drawing::RuntimeEffect::CreateForShader(mixStringMESA);
    if (g_mixEffect == nullptr) {
        LOGE("GEMESABlurShaderFilter::RuntimeShader mixEffect create failed");
        return false;
    }

    return true;
}

bool GEMESABlurShaderFilter::InitSimpleFilter()
{
    if (g_simpleFilter != nullptr) {
        return true;
    }

    static const std::string simpleShader(R"(
        uniform shader imageInput;
        half4 main(float2 xy) {
            return imageInput.eval(xy);
        }
    )");
    g_simpleFilter = Drawing::RuntimeEffect::CreateForShader(simpleShader);
    if (g_simpleFilter == nullptr) {
        LOGE("GEMESABlurShaderFilter::RuntimeShader simpleFilter create failed");
        return false;
    }

    return true;
}

bool GEMESABlurShaderFilter::InitGreyAdjustmentEffect()
{
    static const std::string greyXShader(R"(
        uniform shader imageShader;
        uniform float coefficient1;
        uniform float coefficient2;

        float calculateT_y(float rgb) {
            if (rgb > 127.5) { rgb = 255 - rgb; }
            float A = 106.5;    // 3 * b - 3 * c + d;
            float B = -93;      // 3 * (c - 2 * b);
            float p = 0.816240163988;                   // (3 * A * C - pow(B, 2)) / (3 * pow(A, 2));
            float s1 = rgb / 213.0 - 0.5 * 0.262253485943;    // -rgb/A - B*C/(3*pow(A,2)) + 2*pow(B,3)/(27*pow(A,3))
            float s2 = sqrt(pow(s1, 2) + pow(p / 3, 3));
            return pow((s1 + s2), 1.0 / 3) - pow((s2 - s1), 1.0 / 3) - (B / (3 * A));
        }

        float calculateGreyAdjustY(float rgb) {
            float t_r = calculateT_y(rgb);
            return (rgb < 127.5) ? (coefficient1 * pow((1 - t_r), 3)) : (-coefficient2 * pow((1 - t_r), 3));
        }

        vec4 main(vec2 drawing_coord) {
            vec3 color = imageShader.eval(drawing_coord).rgb;
            float Y = (0.299 * color.r + 0.587 * color.g + 0.114 * color.b) * 255;
            float dY = calculateGreyAdjustY(Y) / 255.0;
            return vec4(color+dY, 1.0);
        }
    )");
    if (g_greyAdjustEffect == nullptr) {
        g_greyAdjustEffect = Drawing::RuntimeEffect::CreateForShader(greyXShader);
        if (g_greyAdjustEffect == nullptr) {
            LOGE("GEMESABlurShaderFilter::RuntimeShader greyAdjustEffect create failed");
            return false;
        }
    }
    return true;
}

void GEMESABlurShaderFilter::CheckInputImage(Drawing::Canvas& canvas, const std::shared_ptr<Drawing::Image>& image,
    std::shared_ptr<Drawing::Image>& checkedImage, const Drawing::Rect& src) const
{
    auto srcRect = Drawing::RectI(src.GetLeft(), src.GetTop(), src.GetRight(), src.GetBottom());
    if (image->GetImageInfo().GetBound() != srcRect) {
        auto resizedImage = std::make_shared<Drawing::Image>();
        auto gpuCtx = canvas.GetGPUContext();
        if (gpuCtx == nullptr || !(image->IsValid(gpuCtx.get()))) {
            LOGE("GEMESABlurShaderFilter::CheckInputImage invalid image");
            return;
        }
        if (resizedImage->BuildSubset(image, srcRect, *gpuCtx)) {
            checkedImage = resizedImage;
            LOGD("GEMESABlurShaderFilter::resize image success");
        } else {
            LOGD("GEMESABlurShaderFilter::resize image failed, use original image");
        }
    }
}

std::shared_ptr<Drawing::Image> GEMESABlurShaderFilter::OutputImageWithoutBlur(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image>& image, const Drawing::Rect& src, const Drawing::Rect& dst) const
{
    auto width = image->GetWidth();
    auto height = image->GetHeight();
    if (width == 0 || height == 0) {
        return image;
    }

    auto width_output = std::max(static_cast<int>(std::ceil(dst.GetWidth())), width);
    auto height_output = std::max(static_cast<int>(std::ceil(dst.GetHeight())), height);
    Drawing::Matrix inputMatrix = BuildStretchMatrixFull(src, dst, width, height);

    Drawing::SamplingOptions linear(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NONE);
    auto imageInfo = Drawing::ImageInfo(width_output, height_output, image->GetImageInfo().GetColorType(),
        image->GetImageInfo().GetAlphaType(), image->GetImageInfo().GetColorSpace());

    std::shared_ptr<Drawing::Image> output;
    if (isGreyX_) {
        Drawing::RuntimeShaderBuilder builder(g_greyAdjustEffect);
        auto inputShader = Drawing::ShaderEffect::CreateImageShader(*image, tileMode_, tileMode_, linear, inputMatrix);
        builder.SetChild("imageShader", inputShader);
        builder.SetUniform("coefficient1", greyCoef1_);
        builder.SetUniform("coefficient2", greyCoef2_);
        output = builder.MakeImage(canvas.GetGPUContext().get(), nullptr, imageInfo, false);
    } else {
        Drawing::RuntimeShaderBuilder builder(g_simpleFilter);
        auto inputShader = Drawing::ShaderEffect::CreateImageShader(*image, tileMode_, tileMode_, linear, inputMatrix);
        builder.SetChild("imageInput", inputShader);
        output = builder.MakeImage(canvas.GetGPUContext().get(), nullptr, imageInfo, false);
    }
    if (!output) {
        LOGE("GEMESABlurShaderFilter::OutputImageWithoutBlur make image error");
        return image;
    } else {
        return output;
    }
}

std::shared_ptr<Drawing::Image> GEMESABlurShaderFilter::ScaleAndAddRandomColor(Drawing::Canvas& canvas,
    const std::shared_ptr<Drawing::Image>& image, const std::shared_ptr<Drawing::Image>& blurImage,
    const Drawing::Rect& src, const Drawing::Rect& dst, int& width, int& height) const
{
    if (fabs(blurScale_) < 1e-6 || blurImage->GetWidth() < 1e-6 || blurImage->GetHeight() < 1e-6 ||
        image->GetWidth() < 1e-6 || image->GetHeight() < 1e-6) {
        LOGE("GEMESABlurShaderFilter::ScaleAndAddRandomColor invalid blurScale is zero.");
        return blurImage;
    }

    Drawing::RuntimeShaderBuilder mixBuilder(g_mixEffect);
    Drawing::SamplingOptions linear(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NONE);
    auto scaledInfo = Drawing::ImageInfo(width, height, blurImage->GetImageInfo().GetColorType(),
        blurImage->GetImageInfo().GetAlphaType(), blurImage->GetImageInfo().GetColorSpace());
    if (blurRadius_ >= BLUR_RADIUS_1P5) {
        Drawing::Matrix scaleMatrix;
        // blurImage->GetWidth() and blurImage->GetHeight() are larger than zero, checked before
        float scaleW = static_cast<float>(dst.GetWidth()) / blurImage->GetWidth();
        float scaleH = static_cast<float>(dst.GetHeight()) / blurImage->GetHeight();
        scaleMatrix.SetScale(scaleW, scaleH);
        Drawing::Matrix translateMatrix;
        translateMatrix.Translate(dst.GetLeft(), dst.GetTop());
        scaleMatrix.PostConcat(translateMatrix);
        auto tmpShader = Drawing::ShaderEffect::CreateImageShader(*blurImage, Drawing::TileMode::CLAMP,
            Drawing::TileMode::CLAMP, linear, scaleMatrix);
        mixBuilder.SetChild("blurredInput", tmpShader);
    } else {
        Drawing::Rect srcRect(0.0f, 0.0f, static_cast<float>(blurImage->GetWidth()),
            static_cast<float>(blurImage->GetHeight()));
        const auto scaleMatrix = BuildStretchMatrixFull(srcRect, dst, blurImage->GetWidth(), blurImage->GetHeight());
        auto tmpShader = Drawing::ShaderEffect::CreateImageShader(*blurImage, tileMode_,
            tileMode_, linear, scaleMatrix);
        mixBuilder.SetChild("blurredInput", tmpShader);
    }
    static auto factor = 1.75; // 1.75 from experience

    mixBuilder.SetUniform("inColorFactor", factor);
    auto output = mixBuilder.MakeImage(canvas.GetGPUContext().get(), nullptr, scaledInfo, false);
    return output;
}

void GEMESABlurShaderFilter::ComputeRadiusAndScale(int radius)
{
    blurRadius_ = static_cast<float>(radius);
    AdjustRadiusAndScale();
    return;
}

void GEMESABlurShaderFilter::AdjustRadiusAndScale()
{
    auto radius = static_cast<int>(blurRadius_);
    if (radius < BLUR_RADIUS_1) {
        blurScale_ = BASE_BLUR_SCALE;
    } else if (radius < BLUR_RADIUS_1P5) {
        blurScale_ = BLUR_SCALE_1;
    } else if (radius < BLUR_RADIUS_2) {
        blurScale_ = BLUR_SCALE_2;
    } else if (radius < BLUR_RADIUS_3) {
        blurScale_ = BLUR_SCALE_3;
    } else {
        blurScale_ = BLUR_SCALE_4;
    }
}

std::string GEMESABlurShaderFilter::GetDescription() const
{
    return "blur radius is " + std::to_string(blurRadius_);
}

void GEMESABlurShaderFilter::CalculatePixelStretch(int width, int height)
{
    if (width_ > 0) {
        offsetX_ = width * (stretchOffsetX_ / width_);
        offsetZ_ = width * (stretchOffsetZ_ / width_);
    } else {
        offsetX_ = stretchOffsetX_;
        offsetZ_ = stretchOffsetZ_;
    }
    if (height_ > 0) {
        offsetY_ = height * (stretchOffsetY_ / height_);
        offsetW_ = height * (stretchOffsetW_ / height_);
    } else {
        offsetY_ = stretchOffsetY_;
        offsetW_ = stretchOffsetW_;
    }
}
} // namespace Rosen
} // namespace OHOS