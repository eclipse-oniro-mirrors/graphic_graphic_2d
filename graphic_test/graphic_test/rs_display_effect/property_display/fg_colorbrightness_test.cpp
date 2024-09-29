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

#include "property/rs_properties_def.h"

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

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, FgBrightnessParams_Fraction_Test_1)
{
    float rateList[] = { -0.05, 0.0, 1.0, 20.0 };
    float saturationList[] = { 0.0, 5.0, 10.0, 20.0 };
    std::array<float, 3> RGB[] = { { 2.3, 4.5, 2 }, { 0.5, 2, 0.5 } };
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 2; k++) {
                RSDynamicBrightnessPara params = RSDynamicBrightnessPara(rateList[i], rateList[(i + 3) % 4],
                    saturationList[j], saturationList[(j + 1) % 4], saturationList[j], RGB[k], RGB[(k + 1) % 2]);
                params.fraction_ = 0.5;
                int x = i * 310;
                int y = (k + j * 2) * 310;
                auto testFaNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 300, 300 });
                auto testNode = RSCanvasNode::Create();
                testNode->SetBounds({ 0, 0, 300, 300 });
                testNode->SetForegroundColor(0xff7d112c);
                testNode->SetFgBrightnessParams(params);
                testNode->SetFgBrightnessFract(params.fraction_);
                GetRootNode()->AddChild(testFaNode);
                testFaNode->AddChild(testNode);
                RegisterNode(testFaNode);
                RegisterNode(testNode);
            }
        }
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, FgBrightnessParams_Fraction_Test_2)
{
    float rateList[] = { -0.05, 0.0, 1.0, 20.0 };
    float saturationList[] = { 0.0, 5.0, 10.0, 20.0 };
    std::array<float, 3> RGB[] = { { 2.3, 4.5, 2 }, { 0.5, 2, 0.5 } };
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 2; k++) {
                RSDynamicBrightnessPara params = RSDynamicBrightnessPara(rateList[i], rateList[(i + 3) % 4],
                    saturationList[j], saturationList[(j + 1) % 4], saturationList[j], RGB[k], RGB[(k + 1) % 2]);
                params.fraction_ = 1.0;
                int x = i * 310;
                int y = (k + j * 2) * 310;
                auto testFaNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 300, 300 });
                auto testNode = RSCanvasNode::Create();
                testNode->SetBounds({ 0, 0, 300, 300 });
                testNode->SetForegroundColor(0xff7d112c);
                testNode->SetFgBrightnessParams(params);
                testNode->SetFgBrightnessFract(params.fraction_);
                GetRootNode()->AddChild(testFaNode);
                testFaNode->AddChild(testNode);
                RegisterNode(testFaNode);
                RegisterNode(testNode);
            }
        }
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, FgBrightnessParams_Fraction_Test_3)
{
    float rateList[] = { -0.05, 0.0, 1.0, 20.0 };
    float saturationList[] = { 0.0, 5.0, 10.0, 20.0 };
    std::array<float, 3> RGB[] = { { 2.3, 4.5, 2 }, { 0.5, 2, 0.5 } };
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 2; k++) {
                RSDynamicBrightnessPara params = RSDynamicBrightnessPara(rateList[i], rateList[(i + 3) % 4],
                    saturationList[j], saturationList[(j + 1) % 4], saturationList[j], RGB[k], RGB[(k + 1) % 2]);
                params.fraction_ = 0.0;
                int x = i * 310;
                int y = (k + j * 2) * 310;
                auto testFaNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 300, 300 });
                auto testNode = RSCanvasNode::Create();
                testNode->SetBounds({ 0, 0, 300, 300 });
                testNode->SetForegroundColor(0xff7d112c);
                testNode->SetFgBrightnessParams(params);
                testNode->SetFgBrightnessFract(params.fraction_);
                GetRootNode()->AddChild(testFaNode);
                testFaNode->AddChild(testNode);
                RegisterNode(testFaNode);
                RegisterNode(testNode);
            }
        }
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Foreground_SetBlender_Test_1)
{
    float rateList[] = { -0.05, 0.0, 1.0, 20.0 };
    float saturationList[] = { 0.0, 5.0, 10.0, 20.0 };
    float fractionVal = 0.5;
    Vector3f RGB[] = { { 2.3, 4.5, 2 }, { 0.5, 2, 0.5 } };
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 2; k++) {
                auto blenderPara = std::make_shared<BrightnessBlender>();
                blenderPara->SetFraction(fractionVal);
                blenderPara->SetLinearRate(rateList[i]);
                blenderPara->SetDegree(rateList[(i + 3) % 4]);
                blenderPara->SetCubicRate(saturationList[j]);
                blenderPara->SetQuadRate(saturationList[(j + 1) % 4]);
                blenderPara->SetSaturation(saturationList[j]);
                blenderPara->SetPositiveCoeff(RGB[k]);
                blenderPara->SetNegativeCoeff(RGB[(k + 1) % 2]);
                int x = i * 310;
                int y = (k + j * 2) * 310;
                auto testFaNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 300, 300 });
                auto testNode = RSCanvasNode::Create();
                testNode->SetBounds({ 0, 0, 300, 300 });
                testNode->SetForegroundColor(0xff7d112c);
                testNode->SetBlender(blenderPara.get());
                GetRootNode()->AddChild(testFaNode);
                testFaNode->AddChild(testNode);
                RegisterNode(testFaNode);
                RegisterNode(testNode);
            }
        }
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Foreground_SetBlender_Test_2)
{
    float rateList[] = { -0.05, 0.0, 1.0, 20.0 };
    float saturationList[] = { 0.0, 5.0, 10.0, 20.0 };
    float fractionVal = 1.0;
    Vector3f RGB[] = { { 2.3, 4.5, 2 }, { 0.5, 2, 0.5 } };
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 2; k++) {
                auto blenderPara = std::make_shared<BrightnessBlender>();
                blenderPara->SetFraction(fractionVal);
                blenderPara->SetLinearRate(rateList[i]);
                blenderPara->SetDegree(rateList[(i + 3) % 4]);
                blenderPara->SetCubicRate(saturationList[j]);
                blenderPara->SetQuadRate(saturationList[(j + 1) % 4]);
                blenderPara->SetSaturation(saturationList[j]);
                blenderPara->SetPositiveCoeff(RGB[k]);
                blenderPara->SetNegativeCoeff(RGB[(k + 1) % 2]);
                int x = i * 310;
                int y = (k + j * 2) * 310;
                auto testFaNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 300, 300 });
                auto testNode = RSCanvasNode::Create();
                testNode->SetBounds({ 0, 0, 300, 300 });
                testNode->SetForegroundColor(0xff7d112c);
                testNode->SetBlender(blenderPara.get());
                GetRootNode()->AddChild(testFaNode);
                testFaNode->AddChild(testNode);
                RegisterNode(testFaNode);
                RegisterNode(testNode);
            }
        }
    }
}

GRAPHIC_TEST(ForegroundTest, CONTENT_DISPLAY_TEST, Foreground_SetBlender_Test_3)
{
    float rateList[] = { -0.05, 0.0, 1.0, 20.0 };
    float saturationList[] = { 0.0, 5.0, 10.0, 20.0 };
    float fractionVal = 0.0;
    Vector3f RGB[] = { { 2.3, 4.5, 2 }, { 0.5, 2, 0.5 } };
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 2; k++) {
                auto blenderPara = std::make_shared<BrightnessBlender>();
                blenderPara->SetFraction(fractionVal);
                blenderPara->SetLinearRate(rateList[i]);
                blenderPara->SetDegree(rateList[(i + 3) % 4]);
                blenderPara->SetCubicRate(saturationList[j]);
                blenderPara->SetQuadRate(saturationList[(j + 1) % 4]);
                blenderPara->SetSaturation(saturationList[j]);
                blenderPara->SetPositiveCoeff(RGB[k]);
                blenderPara->SetNegativeCoeff(RGB[(k + 1) % 2]);
                int x = i * 310;
                int y = (k + j * 2) * 310;
                auto testFaNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", { x, y, 300, 300 });
                auto testNode = RSCanvasNode::Create();
                testNode->SetBounds({ 0, 0, 300, 300 });
                testNode->SetForegroundColor(0xff7d112c);
                testNode->SetBlender(blenderPara.get());
                GetRootNode()->AddChild(testFaNode);
                testFaNode->AddChild(testNode);
                RegisterNode(testFaNode);
                RegisterNode(testNode);
            }
        }
    }
}

} // namespace OHOS::Rosen