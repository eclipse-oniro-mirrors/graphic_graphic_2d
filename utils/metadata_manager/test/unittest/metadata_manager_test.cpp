/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "metadata_manager.h"
#include "buffer_manager.h"

using namespace testing::ext;
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;

namespace OHOS {
namespace MetadataManager {
class MetadataManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    static inline BufferRequestConfig requestConfig = {
        .width = 0x100,
        .height = 0x100,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
    };
    static sptr<SurfaceBuffer> buffer;
};

void MetadataManagerTest::SetUpTestCase()
{
    buffer = new SurfaceBufferImpl(0);
    auto ret = BufferManager::GetInstance()->Alloc(requestConfig, buffer);
    ASSERT_EQ(sret, GSERROR_OK);
}

void MetadataManagerTest::TearDownTestCase()
{
    ret = BufferManager::GetInstance()->Free(buffer);
    ASSERT_EQ(ret, GSERROR_OK);
}

/*
* Function: MetadataManagerTest
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: test SetColorSpaceType and GetColorSpaceType
*/
HWTEST_F(MetadataManagerTest, ColorSpaceTypeTest, Function | SmallTest | Level2)
{
    auto retSet = MetadataManager::SetColorSpaceType(buffer, CM_SRGB_FULL);
    ASSERT_TRUE(retSet == GSERROR_OK || GSErrorStr(retSet) == "<500 api call failed>with low error <Not supported>");

    CM_ColorSpaceType colorSpaceType;
    auto retGet = MetadataManager::GetColorSpaceType(buffer, colorSpaceType);
    ASSERT_TRUE(retGet == GSERROR_OK || GSErrorStr(retGet) == "<500 api call failed>with low error <Not supported>");

    if (retSet == GSERROR_OK && retGet == GSERROR_OK) {
        ASSERT_EQ(colorSpaceType, CM_SRGB_FULL);
    }
}

/*
* Function: MetadataManagerTest
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: test SetHDRMetadataType and GetHDRMetadataType
*/
HWTEST_F(MetadataManagerTest, HDRMetadataTypeTest, Function | SmallTest | Level2)
{
    auto retSet = MetadataManager::SetHDRMetadataType(buffer, CM_VIDEO_HDR_VIVID);
    ASSERT_TRUE(retSet == GSERROR_OK || GSErrorStr(retSet) == "<500 api call failed>with low error <Not supported>");

    CM_HDR_Metadata_Type hdrMetadataType;
    auto retGet = MetadataManager::GetHDRMetadataType(buffer, hdrMetadataType);
    ASSERT_TRUE(retGet == GSERROR_OK || GSErrorStr(retGet) == "<500 api call failed>with low error <Not supported>");

    if (retSet == GSERROR_OK && retGet == GSERROR_OK) {
        ASSERT_EQ(hdrMetadataType, CM_VIDEO_HDR_VIVID);
    }
}

/*
* Function: MetadataManagerTest
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: test SetHDRStaticMetadata and GetHDRStaticMetadata
*/
HWTEST_F(MetadataManagerTest, HDRStaticMetadataTest, Function | SmallTest | Level2)
{
    HdrStaticMetadata metadataSet = {
        .smpte2086 = {
            .displayPrimaryRed = {0.1f, 0.1f},
            .displayPrimaryGreen = {0.2f, 0.2f},
            .displayPrimaryBlue = {0.3f, 0.3f},
            .whitePoint = {0.4f, 0.4f},
            .maxLuminance = 1000.0f,
            .minLuminance = 0.1f,
        },
        .cta861 = {
            .maxContentLightLevel = 500.0f,
            .maxFrameAverageLightLevel = 300.0f,
        },
    };

    auto retSet = MetadataManager::SetHDRStaticMetadata(buffer, metadataSet);
    ASSERT_TRUE(retSet == GSERROR_OK || GSErrorStr(retSet) == "<500 api call failed>with low error <Not supported>");

    HdrStaticMetadata metadataGet;
    auto retGet = MetadataManager::GetHDRStaticMetadata(buffer, metadataGet);
    ASSERT_TRUE(retGet == GSERROR_OK || GSErrorStr(retGet) == "<500 api call failed>with low error <Not supported>");

    if (retSet == GSERROR_OK && retGet == GSERROR_OK) {
        ASSERT_EQ(metadataSet.smpte.displayPrimaryRed.x, metadataGet.smpte.displayPrimaryRed.x);
        ASSERT_EQ(metadataSet.smpte.displayPrimaryRed.y, metadataGet.smpte.displayPrimaryRed.y);
        ASSERT_EQ(metadataSet.smpte.displayPrimaryGreen.x, metadataGet.smpte.displayPrimaryGreen.x);
        ASSERT_EQ(metadataSet.smpte.displayPrimaryGreen.y, metadataGet.smpte.displayPrimaryGreen.y);
        ASSERT_EQ(metadataSet.smpte.displayPrimaryBlue.x, metadataGet.smpte.displayPrimaryBlue.x);
        ASSERT_EQ(metadataSet.smpte.displayPrimaryBlue.y, metadataGet.smpte.displayPrimaryBlue.y);
        ASSERT_EQ(metadataSet.smpte.whitePoint.x, metadataGet.smpte.whitePoint.x);
        ASSERT_EQ(metadataSet.smpte.whitePoint.y, metadataGet.smpte.whitePoint.y);
        ASSERT_EQ(metadataSet.smpte.maxLuminance, metadataGet.smpte.maxLuminance);
        ASSERT_EQ(metadataSet.smpte.minLuminance, metadataGet.smpte.minLuminance);
        ASSERT_EQ(metadataSet.cta861.maxContentLightLevel, metadataGet.cta861.maxContentLightLevel);
        ASSERT_EQ(metadataSet.cta861.maxFrameAverageLightLevel, metadataGet.cta861.maxFrameAverageLightLevel);
    }
}

/*
* Function: MetadataManagerTest
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: test SetHDRVividMetadata and GetHDRVividMetadata
*/
HWTEST_F(MetadataManagerTest, HDRVividMetadataTest, Function | SmallTest | Level2)
{
    HdrVividMetadataV1 metadataSet = {
        .systemStartCode = 0,
        .minimumMaxRgbPq = 1,
        .averageMaxRgbPq = 2,
        .varianceMaxRgbPq = 3,
        .maximumMaxRgbPq = 4,
        .toneMappingMode = 5,
        .toneMappingParamNum = 6,
    };
    for (uint32_t i = 0; i < 16; i++) {
        metadataSet.colorSaturationGain[i] = i;
    }

    auto retSet = MetadataManager::SetHDRVividDynMetadataV1(buffer, metadataSet);
    ASSERT_TRUE(retSet == GSERROR_OK || GSErrorStr(retSet) == "<500 api call failed>with low error <Not supported>");

    HdrVividMetadataV1 metadataGet;
    auto retGet = MetadataManager::GetHDRVividDynMetadataV1(buffer, metadataGet);
    ASSERT_TRUE(retGet == GSERROR_OK || GSErrorStr(retGet) == "<500 api call failed>with low error <Not supported>");

    if (retSet == GSERROR_OK && retGet == GSERROR_OK) {
        ASSERT_EQ(metadataSet.systemStartCode, metadataGet.systemStartCode);
        ASSERT_EQ(metadataSet.minimumMaxRgbPq, metadataGet.minimumMaxRgbPq);
        ASSERT_EQ(metadataSet.averageMaxRgbPq, metadataGet.averageMaxRgbPq);
        ASSERT_EQ(metadataSet.varianceMaxRgbPq, metadataGet.varianceMaxRgbPq);
        ASSERT_EQ(metadataSet.maximumMaxRgbPq, metadataGet.maximumMaxRgbPq);
        ASSERT_EQ(metadataSet.toneMappingMode, metadataGet.toneMappingMode);
        ASSERT_EQ(metadataSet.toneMappingParamNum, metadataGet.toneMappingParamNum);
        for (uint32_t i = 0; i < 16; i++) {
            ASSERT_EQ(metadataSet.colorSaturationGain[i], metadataGet.colorSaturationGain[i]);
        }
    }
}
}
}