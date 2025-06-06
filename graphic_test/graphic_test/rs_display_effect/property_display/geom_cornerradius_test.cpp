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
#include "rs_graphic_test_text.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class GeometryTest : public RSGraphicTest {
private:
    const int screenWidth = 1200;
    const int screenHeight = 2000;

public:
    // called before each tests
    void BeforeEach() override
    {
        SetScreenSize(screenWidth, screenHeight);
    }
};

GRAPHIC_TEST(GeometryTest, CONTENT_DISPLAY_TEST, Geometry_CornerRadius_Test_001)
{
    float radiusList[] = { -1.0, 0.0, 250.0, 500.0 };
    for (int i = 0; i < 4; i++) {
        int x = (i % 2) * 510;
        int y = (i / 2) * 510;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/geom_test.jpg", { x, y, 500, 500 });
        testNode->SetCornerRadius(radiusList[i]);
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

GRAPHIC_TEST(GeometryTest, CONTENT_DISPLAY_TEST, Geometry_CornerRadius_Test_002)
{
    for (int i = 0; i < 3; i++) {
        int x = (i % 2) * 510;
        int y = (i / 2) * 510;
        auto testNode = SetUpNodeBgImage("/data/local/tmp/geom_test.jpg", { x, y, 500, 500 });
        if (!i)
            testNode->SetForegroundEffectRadius(100.0f);
        if (i == 1)
            testNode->SetForegroundBlurRadius(100.0f);
        if (i == 2)
            testNode->SetBackgroundBlurRadius(100.0f);
        testNode->SetCornerRadius(250);
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
    }
}

} // namespace OHOS::Rosen