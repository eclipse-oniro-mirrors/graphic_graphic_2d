/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <unistd.h>

#include "rs_graphic_test.h"
#include "rs_graphic_test_director.h"
#include "rs_graphic_test_img.h"
#include "ui_effect/property/include/rs_ui_shader_base.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {

constexpr size_t screenWidth = 1200;
constexpr size_t screenHeight = 2000;
constexpr uint32_t SLEEP_TIME_FOR_PROXY = 100000; // 100 ms

struct BorderLightParams {
    Vector3f position;
    Vector4f color;
    float intensity;
    float width;
    Vector3f rotationAngle;
    float cornerRadius;
};

const std::vector<BorderLightParams> borderLightParams = {
    {
        .position = {0.5f, 0.5f, 0.0f},
        .color = {1.0f, 0.2f, 0.2f, 1.0f},
        .intensity = 0.8f,
        .width = 0.10f,
        .rotationAngle = {0.0f, 0.0f, 0.0f},
        .cornerRadius = 0.10f
    },
    {
        .position = {0.3f, 0.7f, 0.0f},
        .color = {0.2f, 1.0f, 0.3f, 1.0f},
        .intensity = 0.7f,
        .width = 0.10f,
        .rotationAngle = {0.0f, 0.0f, 15.0f},
        .cornerRadius = 0.15f
    },
    {
        .position = {0.7f, 0.3f, 0.0f},
        .color = {0.2f, 0.4f, 1.0f, 1.0f},
        .intensity = 0.8f,
        .width = 0.12f,
        .rotationAngle = {0.0f, 0.0f, -15.0f},
        .cornerRadius = 0.20f
    },
    {
        .position = {0.5f, 0.2f, 0.0f},
        .color = {1.0f, 0.9f, 0.2f, 1.0f},
        .intensity = 0.9f,
        .width = 0.08f,
        .rotationAngle = {0.0f, 0.0f, 30.0f},
        .cornerRadius = 0.10f
    },
    {
        .position = {0.2f, 0.5f, 0.0f},
        .color = {1.0f, 0.5f, 0.1f, 1.0f},
        .intensity = 0.8f,
        .width = 0.12f,
        .rotationAngle = {0.0f, 0.0f, 45.0f},
        .cornerRadius = 0.00f
    },
    {
        .position = {0.8f, 0.5f, 0.0f},
        .color = {0.1f, 1.0f, 0.8f, 1.0f},
        .intensity = 0.8f,
        .width = 0.10f,
        .rotationAngle = {0.0f, 0.0f, -45.0f},
        .cornerRadius = 0.30f
    },
    {
        .position = {0.5f, 0.8f, 0.0f},
        .color = {1.0f, 0.2f, 0.7f, 1.0f},
        .intensity = 0.7f,
        .width = 0.09f,
        .rotationAngle = {20.0f, 0.0f, 0.0f},
        .cornerRadius = 0.20f
    },
    {
        .position = {0.5f, 0.5f, 0.0f},
        .color = {0.6f, 0.2f, 1.0f, 1.0f},
        .intensity = 0.6f,
        .width = 0.07f,
        .rotationAngle = {0.0f, 20.0f, 0.0f},
        .cornerRadius = 0.12f
    }
};

} // namespace

class BorderLightTest : public RSGraphicTest {
public:
    void BeforeEach() override
    {
        SetScreenSize(screenWidth, screenHeight);
    }

private:
    const int screenWidth_ = screenWidth;
    const int screenHeight_ = screenHeight;
};

void SetBorderLightParams(const std::shared_ptr<RSNGBorderLight>& shader, const BorderLightParams& params)
{
    if (!shader) {
        return;
    }
    Vector3f position = {
        std::clamp(params.position.x_, 0.0f, 1.0f),
        std::clamp(params.position.y_, 0.0f, 1.0f),
        std::clamp(params.position.z_, 0.0f, 1.0f)
    };
    Vector4f color = {
        std::clamp(params.color.x_, 0.0f, 1.0f),
        std::clamp(params.color.y_, 0.0f, 1.0f),
        std::clamp(params.color.z_, 0.0f, 1.0f),
        std::clamp(params.color.w_, 0.0f, 1.0f)
    };
    shader->Setter<BorderLightPositionTag>(position);
    shader->Setter<BorderLightColorTag>(color);
    shader->Setter<BorderLightIntensityTag>(std::clamp(params.intensity, 0.1f, 0.8f));
    shader->Setter<BorderLightWidthTag>(std::clamp(params.width, 0.02f, 0.12f));
    shader->Setter<BorderLightRotationAngleTag>(params.rotationAngle);
    shader->Setter<BorderLightCornerRadiusTag>(std::clamp(params.cornerRadius, 0.0f, 0.3f));
}

GRAPHIC_TEST(BorderLightTest, EFFECT_TEST, Set_Border_Light_Background_Test)
{
    const int columnCount = 2;
    const int rowCount = borderLightParams.size();
    auto sizeX = screenWidth_ / columnCount;
    auto sizeY = screenHeight_ * columnCount / rowCount;

    for (size_t i = 0; i < borderLightParams.size(); ++i) {
        auto shader = std::make_shared<RSNGBorderLight>();
        SetBorderLightParams(shader, borderLightParams[i]);

        int x = (i % columnCount) * sizeX;
        int y = (i / columnCount) * sizeY;

        auto node = RSCanvasNode::Create();
        node->SetBounds({x, y, sizeX, sizeY});
        node->SetFrame({x, y, sizeX, sizeY});
        node->SetBackgroundColor(0xff202020);
        node->SetBackgroundNGShader(shader);
        GetRootNode()->AddChild(node);
        RegisterNode(node);
    }

    RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
    usleep(SLEEP_TIME_FOR_PROXY);
}

GRAPHIC_TEST(BorderLightTest, EFFECT_TEST, Set_Border_Light_Foreground_Test)
{
    const int columnCount = 2;
    const int rowCount = borderLightParams.size();
    auto sizeX = screenWidth_ / columnCount;
    auto sizeY = screenHeight_ * columnCount / rowCount;

    for (size_t i = 0; i < borderLightParams.size(); ++i) {
        auto shader = std::make_shared<RSNGBorderLight>();
        SetBorderLightParams(shader, borderLightParams[i]);
        shader->Setter<BorderLightIntensityTag>(std::clamp(borderLightParams[i].intensity * 0.6f, 0.08f, 0.5f));
        shader->Setter<BorderLightWidthTag>(std::clamp(borderLightParams[i].width, 0.02f, 0.08f));

        int x = (i % columnCount) * sizeX;
        int y = (i / columnCount) * sizeY;

        auto containerNode = RSCanvasNode::Create();
        containerNode->SetBounds({x, y, sizeX, sizeY});
        containerNode->SetFrame({x, y, sizeX, sizeY});
        containerNode->SetBackgroundColor(0xff182028);

        auto backgroundNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {0, 0, sizeX, sizeY});
        backgroundNode->SetBounds({0, 0, sizeX, sizeY});
        backgroundNode->SetFrame({0, 0, sizeX, sizeY});
        backgroundNode->SetForegroundShader(shader);
        containerNode->AddChild(backgroundNode);
        GetRootNode()->AddChild(containerNode);
        RegisterNode(backgroundNode);
        RegisterNode(containerNode);
    }

    RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
    usleep(SLEEP_TIME_FOR_PROXY);
}

} // namespace OHOS::Rosen
