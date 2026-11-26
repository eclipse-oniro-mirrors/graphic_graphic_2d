/*
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
#include "message_parcel.h"
#include "rs_render_layer_cmd.h"
#include "surface_buffer.h"
#include "sync_fence.h"
#include "graphic_common.h"
#include "composer/composer_service/external_depend/hpae_offline/rs_hpae_offline_layer_info.h"

using namespace OHOS::Rosen;
using namespace OHOS;
using namespace testing;
using namespace testing::ext;

class RSHpaeOfflineCmdAndParamsTest : public Test {};

HWTEST_F(RSHpaeOfflineCmdAndParamsTest, MarshallAndUnmarshallHpaeOriginalInfo, TestSize.Level1)
{
    // Unmarshalling fail path
    MessageParcel emptyParcel;
    EXPECT_EQ(RSRenderLayerCmd::Unmarshalling(emptyParcel), nullptr);

    MessageParcel unknownParcel;
    unknownParcel.WriteUint16(static_cast<uint16_t>(RSLayerCmdType::INVALID));
    EXPECT_EQ(RSRenderLayerCmd::Unmarshalling(unknownParcel), nullptr);
}

HWTEST_F(RSHpaeOfflineCmdAndParamsTest, HpaeOriginalInfoAllBranches, TestSize.Level1)
{
    // DEBUG_TDD: debug for tdd - start
    // Branch 1: originalBuffer != nullptr, originalPreBuffer != nullptr
    HpaeOriginalInfo info1;
    info1.originalBuffer = OHOS::SurfaceBuffer::Create();
    info1.originalPreBuffer = OHOS::SurfaceBuffer::Create();
    info1.originalAcquireFence = nullptr;
    info1.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    info1.originalCropRect = { 100, 200, 300, 400 };

    auto prop1 = std::make_shared<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(info1);
    auto cmd1 = std::make_shared<RSRenderLayerHpaeOriginalInfoCmd>(prop1);
    MessageParcel parcel1;
    printf("[DEBUG_TDD] Before Marshalling, parcel size: %zu\n", parcel1.GetDataSize());
    ASSERT_TRUE(cmd1->Marshalling(parcel1));
    printf("[DEBUG_TDD] After Marshalling, parcel size: %zu\n", parcel1.GetDataSize());
    auto out1 = RSRenderLayerCmd::Unmarshalling(parcel1);
    printf("[DEBUG_TDD] After Unmarshalling, out1: %p\n", static_cast<void*>(out1.get()));
    ASSERT_NE(out1, nullptr);
    // DEBUG_TDD: debug for tdd - end

    // Branch 2: originalBuffer == nullptr, originalPreBuffer == nullptr
    HpaeOriginalInfo info2;
    auto prop2 = std::make_shared<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(info2);
    auto cmd2 = std::make_shared<RSRenderLayerHpaeOriginalInfoCmd>(prop2);
    MessageParcel parcel2;
    ASSERT_TRUE(cmd2->Marshalling(parcel2));
    auto out2 = RSRenderLayerCmd::Unmarshalling(parcel2);
    ASSERT_NE(out2, nullptr);
    auto propOut2 = std::static_pointer_cast<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(
        out2->GetRSRenderLayerProperty());
    auto infoOut2 = propOut2->Get();
    EXPECT_EQ(infoOut2.originalBuffer, nullptr);
    EXPECT_EQ(infoOut2.originalPreBuffer, nullptr);

    // Branch 3: originalBuffer != nullptr, originalPreBuffer == nullptr
    HpaeOriginalInfo info3;
    info3.originalBuffer = OHOS::SurfaceBuffer::Create();
    auto prop3 = std::make_shared<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(info3);
    auto cmd3 = std::make_shared<RSRenderLayerHpaeOriginalInfoCmd>(prop3);
    MessageParcel parcel3;
    ASSERT_TRUE(cmd3->Marshalling(parcel3));
    auto out3 = RSRenderLayerCmd::Unmarshalling(parcel3);
    ASSERT_NE(out3, nullptr);

    // Branch 4: originalBuffer == nullptr, originalPreBuffer != nullptr
    HpaeOriginalInfo info4;
    info4.originalPreBuffer = OHOS::SurfaceBuffer::Create();
    auto prop4 = std::make_shared<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(info4);
    auto cmd4 = std::make_shared<RSRenderLayerHpaeOriginalInfoCmd>(prop4);
    MessageParcel parcel4;
    ASSERT_TRUE(cmd4->Marshalling(parcel4));
    auto out4 = RSRenderLayerCmd::Unmarshalling(parcel4);
    ASSERT_NE(out4, nullptr);

    // Branch 5: different transform types
    HpaeOriginalInfo info5;
    info5.originalBuffer = OHOS::SurfaceBuffer::Create();
    info5.originalTransformType = GraphicTransformType::GRAPHIC_ROTATE_180;
    auto prop5 = std::make_shared<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(info5);
    auto cmd5 = std::make_shared<RSRenderLayerHpaeOriginalInfoCmd>(prop5);
    MessageParcel parcel5;
    ASSERT_TRUE(cmd5->Marshalling(parcel5));
    auto out5 = RSRenderLayerCmd::Unmarshalling(parcel5);
    ASSERT_NE(out5, nullptr);
    auto propOut5 = std::static_pointer_cast<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(
        out5->GetRSRenderLayerProperty());
    EXPECT_EQ(propOut5->Get().originalTransformType, GraphicTransformType::GRAPHIC_ROTATE_180);

    // Branch 6: different crop rect
    HpaeOriginalInfo info6;
    info6.originalBuffer = OHOS::SurfaceBuffer::Create();
    info6.originalCropRect = { 0, 0, 1920, 1080 };
    auto prop6 = std::make_shared<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(info6);
    auto cmd6 = std::make_shared<RSRenderLayerHpaeOriginalInfoCmd>(prop6);
    MessageParcel parcel6;
    ASSERT_TRUE(cmd6->Marshalling(parcel6));
    auto out6 = RSRenderLayerCmd::Unmarshalling(parcel6);
    ASSERT_NE(out6, nullptr);
    auto propOut6 = std::static_pointer_cast<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(
        out6->GetRSRenderLayerProperty());
    auto infoOut6 = propOut6->Get();
    EXPECT_EQ(infoOut6.originalCropRect.x, 0);
    EXPECT_EQ(infoOut6.originalCropRect.y, 0);
    EXPECT_EQ(infoOut6.originalCropRect.w, 1920);
    EXPECT_EQ(infoOut6.originalCropRect.h, 1080);
}

HWTEST_F(RSHpaeOfflineCmdAndParamsTest, Marshall_HpaeOriginalInfo_Fail, TestSize.Level1)
{
    // Test fail path: renderProperty == nullptr
    HpaeOriginalInfo info;
    info.originalBuffer = OHOS::SurfaceBuffer::Create();
    auto prop = std::make_shared<RSRenderLayerCmdProperty<HpaeOriginalInfo>>(info);
    auto cmd = std::make_shared<RSRenderLayerHpaeOriginalInfoCmd>(prop);

    MessageParcel parcel;
    cmd->rsRenderLayerProperty_ = nullptr;  // Set to nullptr to trigger fail branch
    ASSERT_FALSE(cmd->Marshalling(parcel));
}