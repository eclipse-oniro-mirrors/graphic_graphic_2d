/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hdi_layer.h"

#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class HdiLayerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    static inline std::shared_ptr<HdiLayer> hdiLayer_;
};

void HdiLayerTest::SetUpTestCase()
{
    hdiLayer_ = HdiLayer::CreateHdiLayer(0);
    LayerInfoPtr layerInfo;
    hdiLayer_->Init(layerInfo);
    hdiLayer_->UpdateLayerInfo(layerInfo);
}

void HdiLayerTest::TearDownTestCase() {}

namespace {
/**
 * @tc.name: GetLayerStatus001
 * @tc.desc: Verify the GetLayerStatus of hdilayer
 * @tc.type:FUNC
 * @tc.require:AR000GGP0P
 * @tc.author:
 */
HWTEST_F(HdiLayerTest, GetLayerStatus001, Function | MediumTest| Level0)
{
    bool isUsing = true;
    HdiLayerTest::hdiLayer_->SetLayerStatus(isUsing);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->GetLayerStatus(), true);

    isUsing = false;
    HdiLayerTest::hdiLayer_->SetLayerStatus(isUsing);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->GetLayerStatus(), false);
}

/*
* Function: SetLayerColorDataSpace001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetLayerColorDataSpace
*                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerColorDataSpace001, Function | MediumTest | Level2)
{
    ColorDataSpace colorSpace = ColorDataSpace::BT709_SRGB_FULL;
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetLayerColorDataSpace(colorSpace), 0);
}

/*
* Function: GetLayerColorDataSpace001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call GetLayerColorDataSpace
*                  2. check ret
 */
HWTEST_F(HdiLayerTest, GetLayerColorDataSpace001, Function | MediumTest | Level2)
{
    ColorDataSpace colorSpace = ColorDataSpace::COLOR_DATA_SPACE_UNKNOWN;
    ASSERT_EQ(HdiLayerTest::hdiLayer_->GetLayerColorDataSpace(colorSpace), 0);
}

/*
* Function: SetLayerMetaData001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetLayerMetaData
*                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerMetaData001, Function | MediumTest | Level2)
{
    HDRMetaData metaData = {
        .key = HDRMetadataKey::MATAKEY_RED_PRIMARY_X,
        .value = 0,
    };
    const std::vector<HDRMetaData> metaDatas = { metaData };
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetLayerMetaData(metaDatas), 0);
}

/*
* Function: SetLayerMetaDataSet001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetLayerMetaDataSet
*                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet001, Function | MediumTest | Level2)
{
    HDRMetadataKey  key = HDRMetadataKey::MATAKEY_RED_PRIMARY_X;

    const std::vector<uint8_t> metaDatas = { 0 };
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetLayerMetaDataSet(key, metaDatas), 0);
}
} // namespace
} // namespace Rosen
} // namespace OHOS