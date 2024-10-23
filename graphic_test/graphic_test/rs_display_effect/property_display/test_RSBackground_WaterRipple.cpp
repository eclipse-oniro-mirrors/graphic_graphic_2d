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

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class BackgroundTest : public RSGraphicTest {
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

GRAPHIC_TEST(BackgroundTest, CONTENT_DISPLAY_TEST, Water_Ripple_Test)
{
    int columnCount = 3;
    int rowCount = 3;
    auto sizeX = screenWidth / columnCount;
    auto sizeY = screenHeight / rowCount;

    std::vector<float> progressList = { 0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0, 20, 100 };

    for (int i = 0; i < progressList.size(); i++) {
        int x = (i % columnCount) * sizeX;
        int y = (i / columnCount) * sizeY;
        auto testNodeBackGround =
            SetUpNodeBgImage("/data/local/tmp/Images/backGroundImage.jpg", { x, y, sizeX - 10, sizeY - 10 });
        RSWaterRipplePara para = { 3, 0.3, 0.5 };
        testNodeBackGround->SetWaterRippleParams(para, progressList[i]);
        GetRootNode()->AddChild(testNodeBackGround);
        RegisterNode(testNodeBackGround);
    }
}

GRAPHIC_TEST(BackgroundTest, CONTENT_DISPLAY_TEST, Fly_In_Test)
{
    int columnCount = 3;
    int rowCount = 3;
    auto sizeX = screenWidth / columnCount;
    auto sizeY = screenHeight / rowCount;

    std::vector<float> progressList = { 0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0, 20, 100 };

    for (int i = 0; i < progressList.size(); i++) {
        int x = (i % columnCount) * sizeX;
        int y = (i / columnCount) * sizeY;
        auto testNodeBackGround =
            SetUpNodeBgImage("/data/local/tmp/Images/backGroundImage.jpg", { x, y, sizeX - 10, sizeY - 10 });
        RSFlyOutPara para = { i % 2 };
        testNodeBackGround->SetFlyOutParams(para, progressList[i]);
        GetRootNode()->AddChild(testNodeBackGround);
        RegisterNode(testNodeBackGround);
    }
}

} // namespace OHOS::Rosen