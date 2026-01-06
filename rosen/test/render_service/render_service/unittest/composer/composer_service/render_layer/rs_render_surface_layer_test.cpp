/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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


#include <gtest/gtest.h>
#include "rs_render_surface_layer.h"
#include "rs_render_layer_cmd.h"

using namespace OHOS::Rosen;
using namespace OHOS;
using namespace testing;
using namespace testing::ext;
class RSRenderSurfaceLayerTest : public Test {};
/**
 * Function: UpdateRSLayerCmd_Zorder_Applied
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. create layer and Zorder command
 *                  2. call UpdateRSLayerCmd
 *                  3. expect GetZorder equals set value
 */
HWTEST(RSRenderSurfaceLayerTest, UpdateRSLayerCmd_Zorder_Applied, TestSize.Level1)
{
    auto layer = std::make_shared<RSRenderSurfaceLayer>();
    auto prop = std::make_shared<RSRenderLayerCmdProperty<int32_t>>(9);
    auto cmd = std::make_shared<RSRenderLayerZorderCmd>(prop);
    layer->UpdateRSLayerCmd(cmd);
    EXPECT_EQ(layer->GetZorder(), 9u);
}

/**
 * Function: UpdateRSLayerCmd_PreMulti_Applied
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. create layer and PreMulti command
 *                  2. call UpdateRSLayerCmd
 *                  3. expect IsPreMulti equals set value
 */
HWTEST(RSRenderSurfaceLayerTest, UpdateRSLayerCmd_PreMulti_Applied, TestSize.Level1)
{
    auto layer = std::make_shared<RSRenderSurfaceLayer>();
    auto prop = std::make_shared<RSRenderLayerCmdProperty<bool>>(true);
    auto cmd = std::make_shared<RSRenderLayerPreMultiCmd>(prop);
    layer->UpdateRSLayerCmd(cmd);
    EXPECT_TRUE(layer->IsPreMulti());
}

/**
 * Function: UpdateRSLayerCmd_IsMaskLayer_Applied
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. create layer and IsMaskLayer command
 *                  2. call UpdateRSLayerCmd
 *                  3. expect GetIsMaskLayer equals set value
 */
HWTEST(RSRenderSurfaceLayerTest, UpdateRSLayerCmd_IsMaskLayer_Applied, TestSize.Level1)
{
    auto layer = std::make_shared<RSRenderSurfaceLayer>();
    auto prop = std::make_shared<RSRenderLayerCmdProperty<bool>>(true);
    auto cmd = std::make_shared<RSRenderLayerIsMaskLayerCmd>(prop);
    layer->UpdateRSLayerCmd(cmd);
    EXPECT_TRUE(layer->GetIsMaskLayer());
}

/**
 * Function: UpdateRSLayerCmd_Gravity_Applied
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. create layer and Gravity command
 *                  2. call UpdateRSLayerCmd
 *                  3. expect GetGravity equals set value
 */
HWTEST(RSRenderSurfaceLayerTest, UpdateRSLayerCmd_Gravity_Applied, TestSize.Level1)
{
    auto layer = std::make_shared<RSRenderSurfaceLayer>();
    auto prop = std::make_shared<RSRenderLayerCmdProperty<int32_t>>(3);
    auto cmd = std::make_shared<RSRenderLayerGravityCmd>(prop);
    layer->UpdateRSLayerCmd(cmd);
    EXPECT_EQ(layer->GetGravity(), 3);
}

/**
 * Function: UpdateRSLayerCmd_ColorDataSpace_Applied
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. create layer and ColorDataSpace command
 *                  2. call UpdateRSLayerCmd
 *                  3. expect GetColorDataSpace equals set value
 */
HWTEST(RSRenderSurfaceLayerTest, UpdateRSLayerCmd_ColorDataSpace_Applied, TestSize.Level1)
{
    auto layer = std::make_shared<RSRenderSurfaceLayer>();
    auto prop = std::make_shared<RSRenderLayerCmdProperty<GraphicColorDataSpace>>(GraphicColorDataSpace::GRAPHIC_COLOR_DATA_SPACE_SRGB);
    auto cmd = std::make_shared<RSRenderLayerColorDataSpaceCmd>(prop);
    layer->UpdateRSLayerCmd(cmd);
    EXPECT_EQ(layer->GetColorDataSpace(), GraphicColorDataSpace::GRAPHIC_COLOR_DATA_SPACE_SRGB);
}

/**
 * Function: UpdateRSLayerCmd_PixelMap_Unhandled_NoCrash
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. create layer and PixelMap command (not handled by RSRenderSurfaceLayer)
 *                  2. call UpdateRSLayerCmd
 *                  3. expect no crash
 */
HWTEST(RSRenderSurfaceLayerTest, UpdateRSLayerCmd_PixelMap_Unhandled_NoCrash, TestSize.Level1)
{
    auto layer = std::make_shared<RSRenderSurfaceLayer>();
    std::shared_ptr<Media::PixelMap> pm = nullptr;
    auto prop = std::make_shared<RSRenderLayerCmdProperty<std::shared_ptr<Media::PixelMap>>>(pm);
    auto cmd = std::make_shared<RSRenderLayerPixelMapCmd>(prop);
    layer->UpdateRSLayerCmd(cmd);
    SUCCEED();
}

/**
 * Function: Basic_Getter_Setter_Work
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. set Type/Transform/CropRect
 *                  2. verify getters return written values
 */
HWTEST(RSRenderSurfaceLayerTest, Basic_Getter_Setter_Work, TestSize.Level1)
{
    auto layer = std::make_shared<RSRenderSurfaceLayer>();
    layer->SetType(GraphicLayerType::GRAPHIC_LAYER_TYPE_GRAPHIC);
    EXPECT_EQ(layer->GetType(), GraphicLayerType::GRAPHIC_LAYER_TYPE_GRAPHIC);

    layer->SetTransform(GraphicTransformType::GRAPHIC_ROTATE_NONE);
    EXPECT_EQ(layer->GetTransform(), GraphicTransformType::GRAPHIC_ROTATE_NONE);

    GraphicIRect r {1, 2, 3, 4};
    layer->SetCropRect(r);
    EXPECT_EQ(layer->GetCropRect().x, 1);
    EXPECT_EQ(layer->GetCropRect().y, 2);
    EXPECT_EQ(layer->GetCropRect().w, 3);
    EXPECT_EQ(layer->GetCropRect().h, 4);
}
