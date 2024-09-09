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
#include "render/rs_fly_out_shader_filter.h"

#include "common/rs_common_def.h"
#include "common/rs_optional_trace.h"
#include "platform/common/rs_log.h"
#include "src/core/SkOpts.h"

namespace OHOS {
namespace Rosen {
// 0.22 means the ratio of deformation distance of the first four points a, a1, b1, b to width when fly out
static const float FLYOUT_DEFORM_PERCENTAGE_ONE = 0.22f;
// 0.19 means the ratio of deformation distance of the points a2, b2 to width when fly out
static const float FLYOUT_DEFORM_PERCENTAGE_TWO = 0.19f;
// 0.07 means the ratio of deformation distance of the points c3, c2, d3, d2 to width when fly in
static const float FLYIN_DEFORM_PERCENTAGE_ONE = 0.07f;
// 0.04 means the ratio of deformation distance of the points c3, c2, d3, d2 to height when fly in
static const float FLYIN_DEFORM_PERCENTAGE_HEIGHT = 0.04f;
// 0.21 means the ratio of deformation distance of the points e, e2, f, f2 to width when fly in
static const float FLYIN_DEFORM_PERCENTAGE_TWO = 0.21f;
static const size_t POINT_NUM = 12; // 12 anchor points of a patch
static const uint32_t FLY_OUT_MODE = 0;
static const uint32_t FLY_IN_MODE = 1;


RSFlyOutShaderFilter::RSFlyOutShaderFilter(float degree, uint32_t flyMode)
    : RSDrawingFilterOriginal(nullptr), degree_(degree), flyMode_(flyMode)
{
    type_ = FilterType::FLY_OUT;

    hash_ = SkOpts::hash(&type_, sizeof(type_), 0);
    hash_ = SkOpts::hash(&degree_, sizeof(degree_), hash_);
    hash_ = SkOpts::hash(&flyMode_, sizeof(flyMode_), hash_);
}


RSFlyOutShaderFilter::~RSFlyOutShaderFilter() = default;

std::string RSFlyOutShaderFilter::GetDescription()
{
    return "RSFlyOutShaderFilter " + std::to_string(degree_);
}

float RSFlyOutShaderFilter::GetDegree() const
{
    return degree_;
}

uint32_t RSFlyOutShaderFilter::GetFlyMode() const
{
    return flyMode_;
}

Drawing::Brush RSFlyOutShaderFilter::GetBrush(const std::shared_ptr<Drawing::Image>& image) const
{
    Drawing::Brush brush;
    if (image == nullptr) {
        return brush;
    }
    brush.SetBlendMode(Drawing::BlendMode::SRC_OVER);
    Drawing::SamplingOptions samplingOptions;
    Drawing::Matrix scaleMat;
    brush.SetShaderEffect(Drawing::ShaderEffect::CreateImageShader(
        *image, Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP, samplingOptions, scaleMat));
    return brush;
}

void RSFlyOutShaderFilter::CalculateDeformation(std::array<Drawing::Point, POINT_NUM>& flyUp,
    std::array<Drawing::Point, POINT_NUM>& flyDown, const float deformWidth, const float deformHeight) const
{
    float flyOutOffsetOne = FLYOUT_DEFORM_PERCENTAGE_ONE * deformWidth * degree_;
    float flyOutOffsetTwo = FLYOUT_DEFORM_PERCENTAGE_TWO * deformWidth * degree_;
    float flyInOffsetOne = FLYIN_DEFORM_PERCENTAGE_ONE * deformWidth * (1.0 - degree_);
    float flyInOffsetTwo = FLYIN_DEFORM_PERCENTAGE_TWO * deformWidth * (1.0 - degree_);
    float flyInOffsetHeight = FLYIN_DEFORM_PERCENTAGE_HEIGHT * deformHeight * (1.0 - degree_);

    if (flyMode_ == FLY_OUT_MODE) {
        // upper half part
        flyUp[0].Offset(flyOutOffsetOne, 0);  // Point 0  is a, which is the top left control point
        flyUp[1].Offset(flyOutOffsetOne, 0);  // Point 1  is a1 on the left one-third of the top edge
        flyUp[2].Offset(-flyOutOffsetOne, 0); // Point 2  is b1 on the right one-third of the top edge
        flyUp[3].Offset(-flyOutOffsetOne, 0); // Point 3  is b, which is thetop right control point
        flyUp[4].Offset(-flyOutOffsetTwo, 0); // Point 4  is b2 on the upper one-third of the right edge
        flyUp[11].Offset(flyOutOffsetTwo, 0); // Point 11 is a2 on the upper one-third of the left edge
    } else if (flyMode_ == FLY_IN_MODE) {
        // upper half part
        flyUp[5].Offset(flyInOffsetOne, flyInOffsetHeight); // Point 5 is d2 on the upper two-thirds of the right edge
        flyUp[10].Offset(-flyInOffsetOne, flyInOffsetHeight); // Point 10 is c2 on the upper two-thirds of left edge
        // lower half part
        flyDown[4].Offset(-flyInOffsetOne, -flyInOffsetHeight); // Point 4 is d3 on the lower two-thirds of right edge
        flyDown[5].Offset(-flyInOffsetTwo, 0); // Point 5  is f2 on the lower one-third of the right edge
        flyDown[6].Offset(-flyInOffsetTwo, 0); // Point 6  is f, which is the bottom right control point
        flyDown[7].Offset(flyInOffsetTwo, 0);  // Point 7  is f1 on the right one-third of the bottom edge
        flyDown[8].Offset(-flyInOffsetTwo, 0); // Point 8  is e1 on the left one-third of the bottom edge
        flyDown[9].Offset(flyInOffsetTwo, 0);  // Point 9  is e, which is the bottom left control point
        flyDown[10].Offset(flyInOffsetTwo, 0); // Point 10 is e2 on the lower one-third of the left edge
        flyDown[11].Offset(flyInOffsetOne, -flyInOffsetHeight); // Point 11 is c3 on the lower two-thirds of left edge
    }
}

void RSFlyOutShaderFilter::DrawImageRect(Drawing::Canvas& canvas, const std::shared_ptr<Drawing::Image>& image,
    const Drawing::Rect& src, const Drawing::Rect& dst) const
{
    if (image == nullptr || image->GetWidth() <= 0 || image->GetHeight() <= 0) {
        ROSEN_LOGE("RSFlyOutShaderFilter::shader error");
        return;
    }

    auto brush = GetBrush(image);
    canvas.AttachBrush(brush);

    int imageWidth = image->GetWidth();
    int imageHeight = image->GetHeight();
    float width = imageWidth; // the width of two deformation part
    float height = imageHeight / 2.0; // the height of two deformation part
    // 4 coordinates of image texture
    const std::array<Drawing::Point, 4> texCoordsUp = {
        Drawing::Point{ 0.0f, 0.0f }, Drawing::Point{ imageWidth, 0.0f },
        Drawing::Point{ imageWidth, height }, Drawing::Point{ 0.0f, height } };
    // 4 coordinates of image texture
    const std::array<Drawing::Point, 4> texCoordsDown = {
        Drawing::Point{ 0.0f, height }, Drawing::Point{ imageWidth, height },
        Drawing::Point{ imageWidth, imageHeight}, Drawing::Point{ 0.0f, imageHeight } };

    // coordinates init of deformation part
    float segmentWidthOne = width / 3.0; // Anchor point 1 is located at one-third of the width.
    float segmentWidthTwo = width / 3.0 * 2.0; // Anchor point 2 is located at two-thirds of the width.
    float segmentHeightOne = height / 3.0; // Anchor point 1 is located at one-third of the height.
    float segmentHeightTwo = height / 3.0 * 2.0; // Anchor point 2 is located at two-thirds of the height.
    std::array<Drawing::Point, POINT_NUM> flyUp = {
        // top edge control points of upper part
        Drawing::Point{0.0f, 0.0f}, Drawing::Point{segmentWidthOne, 0.0f},
        Drawing::Point{segmentWidthTwo, 0.0f}, Drawing::Point{width, 0.0f},
        // right edge control points of upper part
        Drawing::Point{width, segmentHeightOne}, Drawing::Point{width, segmentHeightTwo},
        // bottom edge control points of upper part
        Drawing::Point{width, height}, Drawing::Point{segmentWidthTwo, height},
        Drawing::Point{segmentWidthOne, height}, Drawing::Point{0.0f, height},
        // left edge control points of upper part
        Drawing::Point{0.0f, segmentHeightTwo}, Drawing::Point{0.0f, segmentHeightOne}
    };
    std::array<Drawing::Point, POINT_NUM> flyDown = {
        // top edge control points of lower part
        Drawing::Point{0.0f, height}, Drawing::Point{segmentWidthOne, height},
        Drawing::Point{segmentWidthTwo, height}, Drawing::Point{width, height},
        // right edge control points of lower part
        Drawing::Point{width, height + segmentHeightOne}, Drawing::Point{width, height + segmentHeightTwo},
        // bottom edge control points of lower part
        Drawing::Point{width, imageHeight}, Drawing::Point{segmentWidthTwo, imageHeight},
        Drawing::Point{segmentWidthOne, imageHeight}, Drawing::Point{0.0f, imageHeight},
        // left edge control points of lower part
        Drawing::Point{0.0f, height + segmentHeightTwo}, Drawing::Point{0.0f, height + segmentHeightOne}
    };

    // deformation coordinate
    CalculateDeformation(flyUp, flyDown, width, imageHeight);

    Drawing::Path path;
    // The 0th point is the starting point of drawing.
    path.MoveTo(flyUp[0].GetX(), flyUp[0].GetY());
    // The 1st, 2nd, and 3rd control points are connected to represent the upper edge.
    path.CubicTo(flyUp[1], flyUp[2], flyUp[3]);
    // The 4th, 5th and 6th control points are connected to represent the right edge of upper part.
    path.CubicTo(flyUp[4], flyUp[5], flyUp[6]);
    // The 4th, 5th and 6th control points are connected to represent the right edge of lower part.
    path.CubicTo(flyDown[4], flyDown[5], flyDown[6]);
    // The 7th, 8th, and 9th control points are connected to represent the bottom edge.
    path.CubicTo(flyDown[7], flyDown[8], flyDown[9]);
    // The 0th, 10th, and 11th control points are connected to represent the left edge of lower part.
    path.CubicTo(flyDown[10], flyDown[11], flyDown[0]);
    // The 0th, 10th, and 11th control points are connected to represent the left edge upper part.
    path.CubicTo(flyUp[10], flyUp[11], flyUp[0]);
    canvas.ClipPath(path, Drawing::ClipOp::INTERSECT, true);
    canvas.DrawPatch(flyUp.data(), nullptr, texCoordsUp.data(), Drawing::BlendMode::SRC_OVER);
    canvas.DrawPatch(flyDown.data(), nullptr, texCoordsDown.data(), Drawing::BlendMode::SRC_OVER);
    canvas.DetachBrush();
}
} // namespace Rosen
} // namespace OHOS