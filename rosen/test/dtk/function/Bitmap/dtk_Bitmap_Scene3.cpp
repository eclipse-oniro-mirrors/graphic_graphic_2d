/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in comliance with the License.
 * You may obtian a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "dtk_constants.h"
#include "dtk_test_ext.h"
#include "utils.h"

namespace OHOS {
namespace Rosen {

// Bitmap_Scene_0061
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：GetPixmap
// cilp：ClipRect
// transform：Scale(极小值)
// 抗锯齿：非AA
// 透明度：半透明
// 视效：CreateBlendImageFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 1)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::AlphaType::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x894567FA); // 半透明效果，粉蓝色
    auto image = Drawing::Image::MakeFromRaster(bitmap1.GetPixmap(), nullptr, nullptr);

    brush.SetColor(0x4CB21933);

    // 4.组合transform函数
    playbackCanvas_->Scale(10100.0f, 1.0f); // ratio

    for (auto blendMode : blendModes) {
        auto background = Drawing::ImageFilter::CreateBlurImageFilter(
            1.0f, 1.0f, Drawing::TileMode::REPEAT, nullptr, Drawing::ImageBlurType::GAUSS);
        auto foreground = Drawing::ImageFilter::CreateBlurImageFilter(
            1.0f, 1.0f, Drawing::TileMode::REPEAT, nullptr, Drawing::ImageBlurType::GAUSS);
        auto filter = Drawing::Filter();

        // 5.设置视效效果，将效果添加到笔刷
        filter.SetImageFilter(Drawing::ImageFilter::CreateBlendImageFilter(blendMode, background, foreground));
        brush.SetFilter(filter);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawImage(*image, 250, 300, SamplingOptions());
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 500, 500); // rect region (250, 300, 500, 500)
    playbackCanvas_->Save();
    playbackCanvas_->ClipRect(rect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0062
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：MakeImage
// cilp：ClipRoundRect(G2)
// transform：Shear
// 抗锯齿：AA
// 透明度：半透明
// 视效：CreateBlurMaskFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 2)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x894567FA); // 半透明效果，粉蓝色
    std::shared_ptr<Image> image = bitmap1.MakeImage();

    brush.SetColor(0x4CB21933);

    // 4.组合transform函数
    playbackCanvas_->Shear(10.0f, 10.0f); // slope

    for (auto blendMode : blendModes) {
        auto background = Drawing::ImageFilter::CreateBlurImageFilter(
            1.0f, 1.0f, Drawing::TileMode::REPEAT, nullptr, Drawing::ImageBlurType::GAUSS);
        auto foreground = Drawing::ImageFilter::CreateBlurImageFilter(
            1.0f, 1.0f, Drawing::TileMode::REPEAT, nullptr, Drawing::ImageBlurType::GAUSS);
        auto filter = Drawing::Filter();

        // 5.设置视效效果，将效果添加到笔刷
        filter.SetImageFilter(Drawing::ImageFilter::CreateBlendImageFilter(blendMode, background, foreground));
        brush.SetFilter(filter);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawImage(*image, 250, 300, SamplingOptions());
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 250, 400, 400); // rect region (250, 250, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0063
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：SetImmutable/IsImmutable
// cilp：ClipRoundRect(G2_capsule)
// transform：null
// 抗锯齿：非AA
// 透明度：不透明
// 视效：CreateLinearGradient
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 3)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0xFF4567FA); // 不透明效果，粉蓝色
    bitmap1.SetImmutable();
    if (bitmap1.IsImmutable()) {
        playbackCanvas_->DrawBackground(0xFF675800); // 深棕榈
    }

    std::vector<Drawing::ColorQuad> colors = { Drawing::Color::COLOR_RED, Drawing::Color::COLOR_GREEN,
        Drawing::Color::COLOR_BLUE };
    std::vector<Drawing::scalar> pos = { 0.00f, 0.50f, 1.00f };
    auto linearGradient = Drawing::ShaderEffect::CreateLinearGradient(
        { 0, 0 }, { 1000, 1000 }, colors, pos, Drawing::TileMode::CLAMP); // 0 start pos & 1000 end pos
    brush.SetShaderEffect(linearGradient);

    // 4.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    playbackCanvas_->DetachBrush();

    // 5.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 400, 500); // rect region (250, 300, 400, 500)
    auto rrect = Drawing::RoundRect(rect, 50.0f, 50.0f); // 50.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0064
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：ClearWithColor
// cilp：ClipRoundRect(非G2)
// transform：ConcatMatrix
// 抗锯齿：AA
// 透明度：透明
// 视效：CreateColorShader
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 4)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x004567FA); // 透明效果，粉蓝色

    // 4.组合transform函数
    Drawing::Matrix matrix;
    matrix.Rotate(15, 10, 10);             // 15 angle 10 position
    playbackCanvas_->ConcatMatrix(matrix); // ConcatMatrix

    // 5.设置视效效果，将效果添加到笔刷
    brush.SetColor(0xFFFF0000); // 红色
    auto colorShader = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_RED);
    brush.SetShaderEffect(colorShader);

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(300, 300, 400, 400); // rect region (300, 300, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0065
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：ExtractSubset
// cilp：null
// transform：Scale(正常值）
// 抗锯齿：非AA
// 透明度：半透明
// 视效：CreateLinearGradient
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 5)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::AlphaType::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);                       // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x894567FA);                    // 半透明效果，粉蓝色
    if (bitmap1.ExtractSubset(bitmap, Rect(0, 1, 2, 2))) { // rect(0, 1, 2, 2)
        playbackCanvas_->DrawBackground(0xFF675800); // 深棕榈
    }

    // 4.组合transform函数
    playbackCanvas_->Scale(2.0f, 2.0f); // ratio

    // 5.设置视效效果，将效果添加到笔刷
    std::vector<Drawing::ColorQuad> colors = { Drawing::Color::COLOR_RED, Drawing::Color::COLOR_GREEN,
        Drawing::Color::COLOR_BLUE };
    std::vector<Drawing::scalar> pos = { 0.00f, 0.50f, 1.00f };
    auto linearGradient = Drawing::ShaderEffect::CreateLinearGradient(
        { 0, 0 }, { 1000, 1000 }, colors, pos, Drawing::TileMode::CLAMP); // 0 start pos & 1000 end pos
    brush.SetShaderEffect(linearGradient);

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    playbackCanvas_->DetachBrush();
}

// Bitmap_Scene_0066
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：PeekPixels
// cilp：ClipPath
// transform：Scale(正常值）
// 抗锯齿：AA
// 透明度：不透明
// 视效：CreateColorShader
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 6)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::AlphaType::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    Drawing::Pixmap pixmap;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0xFF4567FA); // 不透明效果，粉蓝色
    if (bitmap1.PeekPixels(pixmap)) {
        auto image = Image::MakeFromRaster(pixmap, nullptr, nullptr);

        // 4.组合transform函数
        playbackCanvas_->Scale(2.0f, 2.0f); // ratio

        // 5.设置视效效果，将效果添加到笔刷
        brush.SetColor(0xFFFF0000); // 红色
        auto colorShader = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_RED);
        brush.SetShaderEffect(colorShader);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawImage(*image, 250, 300, SamplingOptions());
        playbackCanvas_->DetachBrush();

        // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
        Drawing::Path path;
        path.AddRect({ 200, 300, 700, 800 }); // rect region (200, 300, 700, 800)
        path.SetFillStyle(Drawing::PathFillType::INVERSE_WINDING);
        playbackCanvas_->Save();
        playbackCanvas_->ClipPath(path, Drawing::ClipOp::DIFFERENCE, true);
        playbackCanvas_->Clear(Drawing::Color::COLOR_GREEN);
        playbackCanvas_->Restore();
    }
}

// Bitmap_Scene_0067
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：ReadPixels
// cilp：ClipRect
// transform：Scale(极大值)
// 抗锯齿：非AA
// 透明度：透明
// 视效：null
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 7)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::AlphaType::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x004567FA); // 透明效果，粉蓝色
    auto imageInfo = Drawing::ImageInfo(500, 500, Drawing::ColorType::COLORTYPE_RGB_565, Drawing::ALPHATYPE_PREMUL);
    bitmap1.ReadPixels(imageInfo, bitmap.GetPixels(), bitmap.GetRowBytes(), 50, 50); // (50, 50) is position

    // 4.组合transform函数
    playbackCanvas_->Scale(1.0f, 10100.0f); // ratio

    // 5.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 500, 500); // rect region (250, 300, 500, 500)
    playbackCanvas_->Save();
    playbackCanvas_->ClipRect(rect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0068
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：CopyPixels
// cilp：ClipRoundRect(G2)
// transform：Scale(极小值)
// 抗锯齿：AA
// 透明度：半透明
// 视效：CreateBlendModeColorFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 8)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::AlphaType::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);      // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x894567FA); // 半透明效果，粉蓝色
    bitmap1.CopyPixels(bitmap, 500, 500); // 500 width & Height

    brush.SetColor(0xFFFF0000); // 红色

    // 4.组合transform函数
    playbackCanvas_->Scale(10100.0f, 1.0f); // ratio

    for (auto blendMode : blendModes) {
        std::shared_ptr<Drawing::ColorFilter> colorFilter =
            Drawing::ColorFilter::CreateBlendModeColorFilter(0xFFFF0000, blendMode);
        auto filter = Drawing::Filter();

        // 5.设置视效效果，将效果添加到笔刷
        filter.SetColorFilter(colorFilter);
        brush.SetFilter(filter);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
        playbackCanvas_->DetachBrush();
    }

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 250, 400, 400); // rect region (250, 250, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0069
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：InstallPixels
// cilp：ClipRoundRect(G2_capsule)
// transform：Translate
// 抗锯齿：非AA
// 透明度：不透明
// 视效：CreateComposeColorFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 9)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::AlphaType::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0xFF4567FA); // 不透明效果，粉蓝色
    auto imageInfo = Drawing::ImageInfo(500, 500, Drawing::ColorType::COLORTYPE_RGB_565, Drawing::ALPHATYPE_PREMUL);
    uint32_t pixels[][5] = { { 0xBFA12345, 0xCB9745D2, 0xD0ACB2F4, 0xD34A1234, 0xCDE7AB9F },
        { 0xD98289C1, 0xC56A2F1A, 0xF3A807CC, 0xBD31C9A2, 0xF05A5378 },
        { 0xCF19A7E4, 0xF29074BD, 0xC0C35F1A, 0xE73812A7, 0xD98E2B43 },
        { 0xB6F10D34, 0xD98289C1, 0xC9A4527A, 0xC03D15A2, 0xF4B2C380 },
        { 0xBF1D68A3, 0xE5A3D1C4, 0xCBF722ED, 0xD7A9BC64, 0xB4C5F219 } };
    if (bitmap1.InstallPixels(imageInfo, pixels, bitmap.GetRowBytes())) {
        Drawing::Image image;
        image.BuildFromBitmap(bitmap1);

        brush.SetColor(0xFFFF0000); // 红色
        // 4.组合transform函数
        playbackCanvas_->Translate(200, 200); // 200 distance

        for (auto blendMode1 : blendModes) {
            std::shared_ptr<Drawing::ColorFilter> colorFilter1 =
                Drawing::ColorFilter::CreateBlendModeColorFilter(0xFFFF0000, blendMode1);
            for (auto blendMode2 : blendModes) {
                std::shared_ptr<Drawing::ColorFilter> colorFilter2 =
                    Drawing::ColorFilter::CreateBlendModeColorFilter(0xFFFF00FF, blendMode2);
                std::shared_ptr<Drawing::ColorFilter> colorFilter3 =
                    Drawing::ColorFilter::CreateComposeColorFilter(*colorFilter1, *colorFilter2);
                auto filter = Drawing::Filter();

                // 5.设置视效效果，将效果添加到笔刷
                filter.SetColorFilter(colorFilter3);
                brush.SetFilter(filter);

                // 6.绘制结果
                playbackCanvas_->AttachBrush(brush);
                playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
                playbackCanvas_->DrawImage(image, 250, 300, SamplingOptions());
            }
        }
        playbackCanvas_->DetachBrush();
    }

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 400, 500); // rect region (250, 300, 400, 500)
    auto rrect = Drawing::RoundRect(rect, 50.0f, 50.0f); // 50.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0070
// Bitmap构造接口：Bitmap_Build_L1_21
// Bitmap操作接口：Serialize/Deserialize
// cilp：ClipRoundRect(非G2)
// transform：Shear
// 抗锯齿：AA
// 透明度：透明
// 视效：CreateSrgbGammaToLinear
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 10)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_RGB_565, Drawing::AlphaType::ALPHATYPE_PREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x004567FA); // 透明效果，粉蓝色
    auto data = bitmap1.Serialize();
    if (bitmap1.Deserialize(data)) {
        playbackCanvas_->DrawBackground(0xFF675800); // 深棕榈
    }

    brush.SetColor(0xFF4F7091);

    // 4.组合transform函数
    playbackCanvas_->Shear(10.0f, 10.0f); // slope

    // 5.设置视效效果，将效果添加到笔刷
    auto filter = Drawing::Filter();
    filter.SetColorFilter(Drawing::ColorFilter::CreateSrgbGammaToLinear());
    brush.SetFilter(filter);

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(300, 300, 400, 400); // rect region (300, 300, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0071
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：GetWidth
// cilp：null
// transform：null
// 抗锯齿：非AA
// 透明度：不透明
// 视效：CreateBlendShader
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 11)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(bitmap.GetWidth(), 500, format); // 500 height
    bitmap1.ClearWithColor(0xFF4567FA); // 不透明效果，粉蓝色

    // 4.设置视效效果，将效果添加到笔刷

    brush.SetColor(0xFFFF0000);
    auto dst = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_RED);
    auto src = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_GREEN);
    for (auto blendMode : blendModes) {
        auto blendShader = Drawing::ShaderEffect::CreateBlendShader(*dst, *src, blendMode);
        brush.SetShaderEffect(blendShader);

        // 5.绘制部分
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250, 300 is bitmap position
    }
    playbackCanvas_->DetachBrush();
}

// Bitmap_Scene_0072
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：GetHeight
// cilp：ClipPath
// transform：ConcatMatrix
// 抗锯齿：AA
// 透明度：透明
// 视效：CreateSrgbGammaToLinear
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 12)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, bitmap.GetHeight(), format); // 500 weidth
    bitmap1.ClearWithColor(0x004567FA);             // 透明效果

    // 4.设置视效效果，将效果添加到笔刷
    auto filter = Drawing::Filter();
    filter.SetColorFilter(Drawing::ColorFilter::CreateSrgbGammaToLinear());
    brush.SetFilter(filter);

    // 5.组合transform函数
    Drawing::Matrix matrix;
    matrix.Rotate(15, 10, 10); // 15 angle 10 position
    playbackCanvas_->ConcatMatrix(matrix);

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    Drawing::Path path;
    path.AddRect({ 200, 300, 700, 800 }); // rect region (200, 300, 700, 800)
    path.SetFillStyle(Drawing::PathFillType::INVERSE_WINDING);
    playbackCanvas_->Save();
    playbackCanvas_->ClipPath(path, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_GREEN);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0073
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：GetColorType
// cilp：ClipRect
// transform：Rotate
// 抗锯齿：非AA
// 透明度：半透明
// 视效：CreateLumaColorFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 13)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x894567FA); // 半透明效果，粉蓝色

    // 4.设置视效效果，将效果添加到笔刷
    brush.SetColor(0xFF0000FF);
    auto filter = Drawing::Filter();
    filter.SetColorFilter(Drawing::ColorFilter::CreateLumaColorFilter());
    brush.SetFilter(filter);

    // 5.组合transform函数
    playbackCanvas_->Rotate(30, 10, 10); // 30 angle 10 position

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 500, 500); // rect region (250, 300, 500, 500)
    playbackCanvas_->Save();
    playbackCanvas_->ClipRect(rect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0074
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：GetAlphaType
// cilp：ClipRoundRect(G2)
// transform：Scale(正常值）
// 抗锯齿：AA
// 透明度：透明
// 视效：CreateBlendImageFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 14)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x004567FA); // 透明效果

    // 4.组合transform函数
    playbackCanvas_->Scale(2.0f, 2.0f); // ratio

    // 5.设置视效效果，将效果添加到笔刷
    brush.SetColor(0x4CB21933);

    for (auto blendMode : blendModes) {
        auto background = Drawing::ImageFilter::CreateBlurImageFilter(
            1.0f, 1.0f, Drawing::TileMode::REPEAT, nullptr, Drawing::ImageBlurType::GAUSS);
        auto foreground = Drawing::ImageFilter::CreateBlurImageFilter(
            1.0f, 1.0f, Drawing::TileMode::REPEAT, nullptr, Drawing::ImageBlurType::GAUSS);
        auto filter = Drawing::Filter();
        filter.SetImageFilter(Drawing::ImageFilter::CreateBlendImageFilter(blendMode, background, foreground));
        brush.SetFilter(filter);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 250, 400, 400); // rect region (250, 250, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0075
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：GetRowBytes
// cilp：ClipRoundRect(G2_capsule)
// transform：Scale(极大值)
// 抗锯齿：非AA
// 透明度：半透明
// 视效：CreateBlendShader
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 15)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format); // 500 weidth & 500 height
    if (bitmap1.GetRowBytes() == sizeof(uint32_t) * bitmap1.GetWidth()) {
        playbackCanvas_->DrawBackground(0x89675800); // 半透明
    }

    // 4.组合transform函数
    playbackCanvas_->Scale(1.0f, 10100.0f); // ratio

    // 5.设置视效效果，将效果添加到笔刷
    brush.SetColor(0xFFFF0000);

    auto dst = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_RED);
    auto src = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_GREEN);
    for (auto blendMode : blendModes) {
        auto blendShader = Drawing::ShaderEffect::CreateBlendShader(*dst, *src, blendMode);
        brush.SetShaderEffect(blendShader);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 500, 500); // rect region (250, 300, 500, 500)
    auto rrect = Drawing::RoundRect(rect, 50.0f, 50.0f); // 50.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0076
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：GetImageInfo
// cilp：ClipRoundRect(非G2)
// transform：Scale(极小值)
// 抗锯齿：AA
// 透明度：不透明
// 视效：CreateBlurImageFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 16)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format); // 500 weidth & 500 height
    bitmap1.TryAllocPixels(bitmap.GetImageInfo());
    bitmap1.ClearWithColor(0xFF4567FA); // 不透明，粉蓝色

    // 4.组合transform函数
    playbackCanvas_->Scale(10100.0f, 1.0f); // ratio

    // 5.设置视效效果，将效果添加到笔刷
    brush.SetColor(0xFFFF0000);
    auto filter = Drawing::Filter();
    filter.SetImageFilter(Drawing::ImageFilter::CreateBlurImageFilter(
        10.0f, 10.0f, Drawing::TileMode::CLAMP, nullptr, Drawing::ImageBlurType::GAUSS));
    brush.SetFilter(filter);

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(300, 300, 400, 400); // rect region (300, 300, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0077
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：SetInfo
// cilp：null
// transform：Translate
// 抗锯齿：非AA
// 透明度：透明
// 视效：CreateColorShader
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 17)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format); // 500 weidth & 500 height
    bitmap1.SetInfo(bitmap.GetImageInfo());
    bitmap1.ClearWithColor(0x004567FA); // 透明

    // 4.组合transform函数
    playbackCanvas_->Translate(200, 200); // 200 distance

    // 5.设置视效效果，将效果添加到笔刷
    brush.SetColor(0xFFFF0000);
    auto colorShader = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_RED);
    brush.SetShaderEffect(colorShader);

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    playbackCanvas_->DetachBrush();
}

// Bitmap_Scene_0078
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：ComputeByteSize
// cilp：ClipPath
// transform：Shear
// 抗锯齿：AA
// 透明度：半透明
// 视效：CreateLinearGradient
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 18)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format); // 500 weidth & 500 height
    size_t size = bitmap.GetRowBytes() * bitmap.GetHeight();
    if (bitmap1.ComputeByteSize() == size) {
        playbackCanvas_->DrawBackground(0x89675800); // 半透明，灰绿色
    }

    // 4.组合transform函数
    playbackCanvas_->Shear(10.0f, 10.0f); // slope

    // 5.设置视效效果，将效果添加到笔刷
    std::vector<Drawing::ColorQuad> colors = { Drawing::Color::COLOR_RED, Drawing::Color::COLOR_GREEN,
        Drawing::Color::COLOR_BLUE };
    std::vector<Drawing::scalar> pos = { 0.00f, 0.50f, 1.00f };
    auto linearGradient = Drawing::ShaderEffect::CreateLinearGradient(
        { 0, 0 }, { 1000, 1000 }, colors, pos, Drawing::TileMode::CLAMP); // 0 start pos & 1000 end pos
    brush.SetShaderEffect(linearGradient);

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    Drawing::Path path;
    path.AddRect({ 200, 300, 700, 800 }); // rect region (200, 300, 700, 800)
    path.SetFillStyle(Drawing::PathFillType::INVERSE_WINDING);
    playbackCanvas_->Save();
    playbackCanvas_->ClipPath(path, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_GREEN);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0079
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：SetPixel/GetPixel
// cilp：ClipRect
// transform：null
// 抗锯齿：非AA
// 透明度：不透明
// 视效：CreateMatrixColorFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 19)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format); // 500 weidth & 500 height
    bitmap1.SetPixels(bitmap.GetPixels());

    // 4.设置视效效果，将效果添加到笔刷
    Drawing::ColorMatrix matrix;
    matrix.SetArray(ARR);
    auto cf = Drawing::ColorFilter::CreateMatrixColorFilter(matrix);
    auto filter = Drawing::Filter();
    filter.SetImageFilter(Drawing::ImageFilter::CreateColorFilterImageFilter(*cf, nullptr));
    brush.SetFilter(filter);

    // 5.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    playbackCanvas_->DetachBrush();

    // 6.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 500, 500); // rect region (250, 300, 500, 500)
    playbackCanvas_->Save();
    playbackCanvas_->ClipRect(rect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap_Scene_0080
// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：IsEmpty
// cilp：ClipRoundRect(G2)
// transform：ConcatMatrix
// 抗锯齿：AA
// 透明度：透明
// 视效：CreateLinearToSrgbGamma
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 20)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）
    // 2.创建Bitmap
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { Drawing::ColorType::COLORTYPE_ARGB_4444, Drawing::AlphaType::ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 固定为不透明，灰绿色

    // 3.组合Bitmap操作函数，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format); // 500 weidth & 500 height
    if (bitmap1.IsEmpty()) {
        playbackCanvas_->DrawBackground(0x00675800); // 透明
    }

    // 4.组合transform函数
    Drawing::Matrix matrix;
    matrix.Rotate(15, 10, 10); // 15 angle 10 position
    playbackCanvas_->ConcatMatrix(matrix);

    // 5.设置视效效果，将效果添加到笔刷
    brush.SetColor(0xFF4F7091);
    auto filter = Drawing::Filter();
    filter.SetColorFilter(Drawing::ColorFilter::CreateLinearToSrgbGamma());
    brush.SetFilter(filter);

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300); // 250，300 is bitmap position
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 250, 400, 400); // rect region (250, 250, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：IsValid
// cilp：ClipRoundRect(G2_capsule)
// transform：Rotate
// 抗锯齿：非AA
// 透明度：半透明
// 视效：CreateBlurMaskFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 21)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：非AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数IsValid，设置透明度, 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);
    bitmap1.ClearWithColor(0x89789645); // 半透明效果，灰绿色
    if (bitmap1.IsValid()) {
        playbackCanvas_->DrawBackground(0xFF675800); // 深棕榈
    }

    std::vector<Drawing::BlurType> blurTypes = { Drawing::BlurType::NORMAL, Drawing::BlurType::SOLID,
        Drawing::BlurType::OUTER, Drawing::BlurType::INNER };

    brush.SetColor(0xFFFF0000);

    // 4.组合transform函数Rotate
    playbackCanvas_->Rotate(30, 10, 10); // 30 angle 10 position

    for (auto& blurType : blurTypes) {
        auto filter = Drawing::Filter();
        filter.SetMaskFilter(Drawing::MaskFilter::CreateBlurMaskFilter(blurType, 10.0f, true));

        // 5.设置视效效果CreateBlurMaskFilter，将效果添加到笔刷
        brush.SetFilter(filter);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数ClipRoundRect(G2_capsule)，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 400, 500); // rect region (250, 300, 400, 500)
    auto rrect = Drawing::RoundRect(rect, 50.0f, 50.0f); // 50.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：GetColor
// cilp：ClipRoundRect(非G2)
// transform：Scale(正常值）
// 抗锯齿：AA
// 透明度：不透明
// 视效：null
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 22)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数GetColor，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);
    bitmap1.ClearWithColor(bitmap.GetColor(1, 1)); // 1 is color position

    // 4.无视效效果函数
    // 5.组合transform函数Scale(正常值）
    playbackCanvas_->Scale(2.0f, 2.0f); // ratio

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数ClipRoundRect(非G2)，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(300, 300, 400, 400); // rect region (300, 300, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：SetFormat/GetFormat
// cilp：null
// transform：Scale(极小值)
// 抗锯齿：非AA
// 透明度：透明
// 视效：CreateBlendModeColorFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 23)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：非AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数SetFormat/GetFormat，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1 = BuildRandomBitmap();
    bitmap1.SetFormat(bitmap.GetFormat());
    bitmap1.ClearWithColor(0x004567FA); // 透明效果，粉蓝色


    brush.SetColor(0xFFFF0000); // 红色

    // 4.组合transform函数Scale(极小值)
    playbackCanvas_->Scale(10100.0f, 1.0f); // ratio

    for (auto blendMode : blendModes) {
        std::shared_ptr<Drawing::ColorFilter> colorFilter =
            Drawing::ColorFilter::CreateBlendModeColorFilter(0xFFFF0000, blendMode);
        auto filter = Drawing::Filter();

        // 5.设置视效效果CreateBlendModeColorFilter，将效果添加到笔刷
        filter.SetColorFilter(colorFilter);
        brush.SetFilter(filter);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    }
    playbackCanvas_->DetachBrush();

    // 7.无Clip函数
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：GetPixmap
// cilp：ClipPath
// transform：Translate
// 抗锯齿：AA
// 透明度：半透明
// 视效：CreateComposeColorFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 24)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数GetPixmap，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x89789645); // 半透明效果，灰绿色
    auto image = Drawing::Image::MakeFromRaster(bitmap1.GetPixmap(), nullptr, nullptr);


    brush.SetColor(0xFFFF0000); // 红色

    // 4.组合transform函数Translate
    playbackCanvas_->Translate(200, 200); // 200 distance

    for (auto blendMode1 : blendModes) {
        std::shared_ptr<Drawing::ColorFilter> colorFilter1 =
            Drawing::ColorFilter::CreateBlendModeColorFilter(0xFFFF0000, blendMode1);
        for (auto blendMode2 : blendModes) {
            std::shared_ptr<Drawing::ColorFilter> colorFilter2 =
                Drawing::ColorFilter::CreateBlendModeColorFilter(0xFFFF00FF, blendMode2);
            std::shared_ptr<Drawing::ColorFilter> colorFilter3 =
                Drawing::ColorFilter::CreateComposeColorFilter(*colorFilter1, *colorFilter2);
            auto filter = Drawing::Filter();

            // 5.设置视效效果CreateComposeColorFilter，将效果添加到笔刷
            filter.SetColorFilter(colorFilter3);
            brush.SetFilter(filter);

            // 6.绘制结果
            playbackCanvas_->AttachBrush(brush);
            playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
            playbackCanvas_->DrawImage(*image, 250, 300, SamplingOptions());
        }
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数ClipPath，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    Drawing::Path path;
    path.AddRect({ 200, 300, 700, 800 }); // rect region (200, 300, 700, 800)
    path.SetFillStyle(Drawing::PathFillType::INVERSE_WINDING);
    playbackCanvas_->Save();
    playbackCanvas_->ClipPath(path, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_GREEN);
    playbackCanvas_->Restore();
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：MakeImage
// cilp：ClipRect
// transform：Translate
// 抗锯齿：非AA
// 透明度：不透明
// 视效：CreateSrgbGammaToLinear
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 25)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：非AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数MakeImage，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // bitmap Pixelwidth and Height
    bitmap1.ClearWithColor(0xFF789645); // 不透明效果，灰绿色
    std::shared_ptr<Image> image = bitmap1.MakeImage();

    // 4.设置视效效果CreateSrgbGammaToLinear，将效果添加到笔刷
    brush.SetColor(0xFF4F7091);
    auto filter = Drawing::Filter();
    filter.SetColorFilter(Drawing::ColorFilter::CreateSrgbGammaToLinear());
    brush.SetFilter(filter);

    // 5.组合transform函数Translate
    playbackCanvas_->Translate(200, 200); // 200 distance

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawImage(*image, 250, 300, SamplingOptions());
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数ClipRect，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 500, 500); // rect region (250, 300, 500, 500)
    playbackCanvas_->Save();
    playbackCanvas_->ClipRect(rect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：SetImmutable/IsImmutable
// cilp：ClipRoundRect(G2)
// transform：Shear
// 抗锯齿：AA
// 透明度：透明
// 视效：CreateBlendShader
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 26)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数SetImmutable/IsImmutable，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x00789645); // 透明效果，灰绿色
    bitmap1.SetImmutable();
    if (bitmap1.IsImmutable()) {
        playbackCanvas_->DrawBackground(0xFF675800); // 深棕榈
    }


    brush.SetColor(0xFFFF0000);

    // 4.组合transform函数Shear
    playbackCanvas_->Shear(10.0f, 10.0f); // slope

    auto dst = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_RED);
    auto src = Drawing::ShaderEffect::CreateColorShader(Drawing::Color::COLOR_GREEN);
    for (auto blendMode : blendModes) {
        auto blendShader = Drawing::ShaderEffect::CreateBlendShader(*dst, *src, blendMode);

        // 5.设置视效效果CreateBlendShader，将效果添加到笔刷
        brush.SetShaderEffect(blendShader);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数ClipRoundRect(G2)，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 250, 400, 400); // rect region (250, 250, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：ClearWithColor
// cilp：ClipRoundRect(G2_capsule)
// transform：null
// 抗锯齿：非AA
// 透明度：半透明
// 视效：CreateBlendModeColorFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 27)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：非AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数ClearWithColor，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x894567FA); // 半透明效果

    // 4.无transform函数


    brush.SetColor(0xFFFF0000); // 红色

    for (auto blendMode : blendModes) {
        std::shared_ptr<Drawing::ColorFilter> colorFilter =
            Drawing::ColorFilter::CreateBlendModeColorFilter(0xFFFF0000, blendMode);
        auto filter = Drawing::Filter();

        // 5.设置视效效果CreateBlendModeColorFilter，将效果添加到笔刷
        filter.SetColorFilter(colorFilter);
        brush.SetFilter(filter);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数ClipRoundRect(G2_capsule)，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(250, 300, 400, 500); // rect region (250, 300, 400, 500)
    auto rrect = Drawing::RoundRect(rect, 50.0f, 50.0f); // 50.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, false);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：ExtractSubset
// cilp：ClipRoundRect(非G2)
// transform：ConcatMatrix
// 抗锯齿：AA
// 透明度：不透明
// 视效：CreateBlurMaskFilter
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 28)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数ExtractSubset，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);                       // 500 weidth & 500 height
    bitmap1.ClearWithColor(0xFF789645);                    // 不透明效果，灰绿色
    if (bitmap1.ExtractSubset(bitmap, Rect(0, 1, 2, 2))) { // rect(0, 1, 2, 2)
        playbackCanvas_->DrawBackground(0xFF675800); // 深棕榈
    }

    std::vector<Drawing::BlurType> blurTypes = { Drawing::BlurType::NORMAL, Drawing::BlurType::SOLID,
        Drawing::BlurType::OUTER, Drawing::BlurType::INNER };

    brush.SetColor(0xFFFF0000);

    // 4.组合transform函数ConcatMatrix
    Drawing::Matrix matrix;
    matrix.Rotate(15, 10, 10); // 15 angle 10 position
    playbackCanvas_->ConcatMatrix(matrix);

    for (auto& blurType : blurTypes) {
        auto filter = Drawing::Filter();
        filter.SetMaskFilter(Drawing::MaskFilter::CreateBlurMaskFilter(blurType, 10.0f, true));

        // 5.设置视效效果CreateBlurMaskFilter，将效果添加到笔刷
        brush.SetFilter(filter);

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    }
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数ClipRoundRect(非G2)，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    auto rect = Drawing::Rect(300, 300, 400, 400); // rect region (300, 300, 400, 400)
    auto rrect = Drawing::RoundRect(rect, 30.0f, 30.0f); // 30.0f is angle
    playbackCanvas_->Save();
    playbackCanvas_->ClipRoundRect(rrect, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_RED);
    playbackCanvas_->Restore();
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：PeekPixels
// cilp：null
// transform：Rotate
// 抗锯齿：非AA
// 透明度：透明
// 视效：CreateLinearToSrgbGamma
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 29)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：非AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(false); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数PeekPixels，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format); // bitmap Pixelwidth and Height
    bitmap.ClearWithColor(0x00789645); // 透明效果，灰绿色
    Drawing::Pixmap pixmap;
    if (bitmap1.PeekPixels(pixmap)) {
        auto image = Image::MakeFromRaster(pixmap, nullptr, nullptr);

        // 4.设置视效效果CreateLinearToSrgbGamma，将效果添加到笔刷
        brush.SetColor(0xFF4F7091);
        auto filter = Drawing::Filter();
        filter.SetColorFilter(Drawing::ColorFilter::CreateLinearToSrgbGamma());
        brush.SetFilter(filter);

        // 5.组合transform函数Rotate
        playbackCanvas_->Rotate(30, 10, 10); // 30 angle 10 position

        // 6.绘制结果
        playbackCanvas_->AttachBrush(brush);
        playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
        playbackCanvas_->DrawImage(*image, 250, 300, SamplingOptions());
        playbackCanvas_->DetachBrush();

        // 7.无Clip函数
    }
}

// Bitmap构造接口：Bitmap_Build_L1_31
// Bitmap操作接口：ReadPixels
// cilp：ClipPath
// transform：Scale(正常值）
// 抗锯齿：AA
// 透明度：半透明
// 视效：CreateSrgbGammaToLinear
DEF_DTK(Bitmap_Scene3, TestLevel::L2, 30)
{
    /*
     *绘制流程说明：默认绘制两个Bitmap，即2、3两步，透明度效果只在第3步设置
     */
    // 1.创建笔刷，设置笔刷是否为抗锯齿效果，抗锯齿：AA
    using namespace Drawing;
    Drawing::Brush brush;
    brush.SetAntiAlias(true); // 设置笔刷抗锯齿，true为AA（抗锯齿），false为非AA（不抗锯齿）

    // 2.创建Bitmap，Bitmap_Build_L1_31
    Drawing::Bitmap bitmap;
    Drawing::BitmapFormat format { COLORTYPE_ARGB_4444, ALPHATYPE_UNPREMUL };
    bitmap.Build(500, 500, format);    // 500 weidth & 500 height
    bitmap.ClearWithColor(0xFF789645); // 灰绿色

    // 3.组合Bitmap操作函数ReadPixels，设置透明度,
    // 由最后一步填充的颜色值的前两位控制，00为透明效果，89为半透明，FF为不透明
    Drawing::Bitmap bitmap1;
    bitmap1.Build(500, 500, format);              // 500 weidth & 500 height
    bitmap1.ClearWithColor(0x89789645);           // 半透明效果，灰绿色
    auto imageInfo = Drawing::ImageInfo(500, 500, // 500 width & Height
        Drawing::ColorType::COLORTYPE_UNKNOWN, Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    bitmap1.ReadPixels(imageInfo, bitmap.GetPixels(), bitmap.GetRowBytes(), 50, 50); // (50, 50) is position

    // 4.设置视效效果CreateSrgbGammaToLinear，将效果添加到笔刷
    brush.SetColor(0xFF4F7091);
    auto filter = Drawing::Filter();
    filter.SetColorFilter(Drawing::ColorFilter::CreateSrgbGammaToLinear());
    brush.SetFilter(filter);

    // 5.组合transform函数Scale(正常值）
    playbackCanvas_->Scale(2.0f, 2.0f); // ratio

    // 6.绘制结果
    playbackCanvas_->AttachBrush(brush);
    playbackCanvas_->DrawBitmap(bitmap, 200, 200); // 200，200 is bitmap position
    playbackCanvas_->DrawBitmap(bitmap1, 250, 300);
    playbackCanvas_->DetachBrush();

    // 7.组合Clip函数ClipPath，cilp也有抗锯齿效果，默认和笔刷效果保持一致
    Drawing::Path path;
    path.AddRect({ 200, 300, 700, 800 }); // rect region (200, 300, 700, 800)
    path.SetFillStyle(Drawing::PathFillType::INVERSE_WINDING);
    playbackCanvas_->Save();
    playbackCanvas_->ClipPath(path, Drawing::ClipOp::DIFFERENCE, true);
    playbackCanvas_->Clear(Drawing::Color::COLOR_GREEN);
    playbackCanvas_->Restore();
}
} // namespace Rosen
} // namespace OHOS