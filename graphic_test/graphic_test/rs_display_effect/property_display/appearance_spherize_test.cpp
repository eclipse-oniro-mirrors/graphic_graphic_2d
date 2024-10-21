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
#include "parameters_defination.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class AppearanceTest : public RSGraphicTest {
private:
    const int screenWidth = 1260;
    const int screenHeight = 2720;

public:
    // called before each tests
    void BeforeEach() override
    {
        SetScreenSurfaceBounds({ 0, 0, screenWidth, screenHeight });
    }
};

// Spherize degree
GRAPHIC_TEST(AppearanceTest, CONTENT_DISPLAY_TEST, Appearance_Spherize_Test_1)
{
    float spherizeList[] = { 0, 0.001, 0.5, 1 };

    for (int i = 0; i < FOUR_; i++) {
        int x = (i % TWO_) * FIVE_HUNDRED_TEN_;
        int y = (i / TWO_) * FIVE_HUNDRED_TEN_;
        auto testNodeSpherize = RSCanvasNode::Create();
        testNodeSpherize->SetBounds({ x, y, FIVE_HUNDRED_, FIVE_HUNDRED_ });
        auto imageModifier = std::make_shared<ImageCustomModifier>();
        imageModifier->SetWidth(FIVE_HUNDRED_);
        imageModifier->SetHeight(FIVE_HUNDRED_);
        imageModifier->SetPixelMapPath("/data/local/tmp/appearance_test.jpg");
        testNodeSpherize->AddModifier(imageModifier);
        testNodeSpherize->SetSpherizeDegree(spherizeList[i]);
        GetRootNode()->AddChild(testNodeSpherize);
        RegisterNode(testNodeSpherize);
    }
}

// first fg blur, then Spherize degree
GRAPHIC_TEST(AppearanceTest, CONTENT_DISPLAY_TEST, Appearance_Spherize_Test_2)
{
    auto testNodeSpherizeBlur = RSCanvasNode::Create();
    testNodeSpherizeBlur->SetBounds({ 0, 0, FIVE_HUNDRED_, FIVE_HUNDRED_ });
    auto imageModifier2 = std::make_shared<ImageCustomModifier>();
    imageModifier2->SetWidth(FIVE_HUNDRED_);
    imageModifier2->SetHeight(FIVE_HUNDRED_);
    imageModifier2->SetPixelMapPath("/data/local/tmp/appearance_test.jpg");
    testNodeSpherizeBlur->AddModifier(imageModifier2);
    testNodeSpherizeBlur->SetForegroundEffectRadius(TEN_);
    testNodeSpherizeBlur->SetSpherizeDegree(1);
    GetRootNode()->AddChild(testNodeSpherizeBlur);
    RegisterNode(testNodeSpherizeBlur);
}

} // namespace OHOS::Rosen