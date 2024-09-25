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

#include "rs_graphic_test.h"
#include "rs_graphic_test_img.h"

#include "render/rs_filter.h"
#include "render/rs_gradient_blur_para.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class ForegroundTest : public RSGraphicTest {
private:
    int screenWidth = 1260;
    int screenHeight = 2720;

public:
    // called before each tests
    void BeforeEach() override
    {
        SetScreenSurfaceBounds({ 0, 0, screenWidth, screenHeight });
    }
};

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Blur_ForegroundEffectRadius_Test_1)
{
    float radiusList[] = { 0, 10.0, 100.0 };
    for (int i = 0; i < 3; i++) {
        int x = (i % 2) * 510;
        int y = (i / 2) * 510;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 500, 500 });
        testNode->SetForegroundEffectRadius(radiusList[i]);
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Blur_Saturation_Test_1)
{
    float radiusList[] = { 10.0, 0.0, 10.0, 10.0 };
    float degreeList[] = { 0.0, 0.5, 0.5, 5.0 };
    for (int i = 0; i < 4; i++) {
        int x = (i % 2) * 510;
        int y = (i / 2) * 510;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 500, 500 });
        testNode->SetForegroundBlurRadius(radiusList[i]);
        testNode->SetForegroundBlurSaturation(degreeList[i]);
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Blur_Brightness_Test_1)
{
    float radiusList[] = { 10.0, 0.0, 10.0, 10.0 };
    float degreeList[] = { 0.0, 0.5, 0.5, 1.5 };
    for (int i = 0; i < 4; i++) {
        int x = (i % 2) * 510;
        int y = (i / 2) * 510;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 500, 500 });
        testNode->SetForegroundBlurRadius(radiusList[i]);
        testNode->SetForegroundBlurBrightness(degreeList[i]);
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Blur_Color_Test_1)
{
    float radiusList[] = { 10.0, 0.0, 10.0 };
    uint32_t colorList[] = { 0x00ffffff, 0x0000ff00, 0x7d00ff00 };
    for (int i = 0; i < 3; i++) {
        int x = (i % 2) * 510;
        int y = (i / 2) * 510;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 500, 500 });
        testNode->SetForegroundBlurRadius(radiusList[i]);
        testNode->SetForegroundBlurMaskColor(RSColor::FromArgbInt(colorList[i]));
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Blur_ColorMode_Test_1)
{
    for (int i = 0; i < 3; i++) {
        int x = (i % 2) * 510;
        int y = (i / 2) * 510;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 500, 500 });
        testNode->SetForegroundBlurRadius(10.f);
        testNode->SetForegroundBlurMaskColor(RSColor::FromArgbInt(0x7dff0000));
        testNode->SetForegroundBlurColorMode(i);
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Blur_RadiusXY_Test_1)
{
    float radiusX[] = { 0.0, 1.1, 10.0, 10.0 };
    float radiusY[] = { 0.0, 10.0, 1.1, 10.0 };
    for (int i = 0; i < 4; i++) {
        int x = (i % 2) * 610;
        int y = (i / 2) * 610;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 600, 600 });
        testNode->SetForegroundBlurRadiusX(radiusX[i]);
        testNode->SetForegroundBlurRadiusY(radiusY[i]);
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Blur_LinearGradientBlur_Test_1)
{
    GradientDirection direction[] = {
        GradientDirection::RIGHT,
        GradientDirection::RIGHT,
        GradientDirection::BOTTOM,
        GradientDirection::RIGHT,
        GradientDirection::RIGHT,
    };
    std::vector<std::pair<float, float>> fractionStops[] = {
        { std::make_pair(0.0, 0.0), std::make_pair(0.0, 1.0) },
        { std::make_pair(1.0, 0.0), std::make_pair(1.0, 1.0) },
        { std::make_pair(0.0, 0.0), std::make_pair(1.0, 1.0) },
        { std::make_pair(0.0, 0.0), std::make_pair(1.0, 1.0) },
        { std::make_pair(0.0, 0.0), std::make_pair(1.0, 0.5), std::make_pair(0.0, 1.0) },
    };
    for (int i = 0; i < 5; i++) {
        int x = (i % 2) * 610;
        int y = (i / 2) * 610;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 600, 600 });
        testNode->SetFrame({ x, y, 600, 600 });
        std::shared_ptr<RSLinearGradientBlurPara> param(
            std::make_shared<Rosen::RSLinearGradientBlurPara>(100.f, fractionStops[i], direction[i]));
        testNode->SetLinearGradientBlurPara(param);
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

} // namespace OHOS::Rosen