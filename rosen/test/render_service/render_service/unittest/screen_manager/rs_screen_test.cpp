/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "limit_number.h"
#include "screen_manager/rs_screen.h"
#include "mock_hdi_device.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSScreenTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static inline ScreenId mockScreenId_;
    static inline Mock::HdiDeviceMock* hdiDeviceMock_;
};

void RSScreenTest::SetUpTestCase()
{
    mockScreenId_ = 0xFFFF;
    hdiDeviceMock_ = Mock::HdiDeviceMock::GetInstance();
    EXPECT_CALL(*hdiDeviceMock_, SetScreenPowerStatus(mockScreenId_, _)).WillRepeatedly(
        DoAll(SaveArg<1>(&Mock::HdiDeviceMock::powerStatusMock_), testing::Return(0)));
    EXPECT_CALL(*hdiDeviceMock_, GetScreenPowerStatus(mockScreenId_, _)).WillRepeatedly(
        DoAll(SetArgReferee<1>(ByRef(Mock::HdiDeviceMock::powerStatusMock_)), testing::Return(0)));
}
void RSScreenTest::TearDownTestCase() {}
void RSScreenTest::SetUp() {}
void RSScreenTest::TearDown() {}

/*
 * @tc.name: DisplayDump_001
 * @tc.desc: Test PhysicalScreen DisplayDump
 * @tc.type: FUNC
 * @tc.require: issueI60RFZ
 */
HWTEST_F(RSScreenTest, DisplayDump_001, testing::ext::TestSize.Level2)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    std::string dumpString = "";
    int32_t screenIndex = 0;
    rsScreen->DisplayDump(screenIndex, dumpString);
}

/*
 * @tc.name: IsEnable_001
 * @tc.desc: IsEnable Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, IsEnable_001, testing::ext::TestSize.Level1)
{
    ScreenId id = INVALID_SCREEN_ID;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_EQ(rsScreen->IsEnable(), false);
}

/*
 * @tc.name: SetResolution_001
 * @tc.desc: SetResolution Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetResolution_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    uint32_t width = 100;
    uint32_t height = 100;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    virtualScreen->SetResolution(width, height);
}

/*
 * @tc.name: SetPowerStatus_001
 * @tc.desc: SetPowerStatus Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetPowerStatus_001, testing::ext::TestSize.Level2)
{
    ScreenId id = INVALID_SCREEN_ID;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    rsScreen->SetPowerStatus(static_cast<uint32_t>(1000));
}

/*
 * @tc.name: ScreenTypeDump_001
 * @tc.desc: ScreenTypeDump Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, ScreenTypeDump_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    config.id = static_cast<uint64_t>(1000);
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    std::string dumpString = "";
    virtualScreen->DisplayDump(config.id, dumpString);
}

/*
 * @tc.name: SetScreenBacklight_001
 * @tc.desc: SetScreenBacklight Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetScreenBacklight_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    virtualScreen->SetScreenBacklight(static_cast<uint32_t>(1000));
    ASSERT_EQ(virtualScreen->GetScreenBacklight(), INVALID_BACKLIGHT_VALUE);
}

/*
 * @tc.name: GetAndResetVirtualSurfaceUpdateFlag_001
 * @tc.desc: Test get virtualSurface update flag correctly
 * @tc.type: FUNC
 * @tc.require: issueIA9QG0
 */
HWTEST_F(RSScreenTest, GetAndResetVirtualSurfaceUpdateFlag_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    virtualScreen->isVirtualSurfaceUpdateFlag_ = true;
    ASSERT_EQ(virtualScreen->GetAndResetVirtualSurfaceUpdateFlag(), true);
    virtualScreen->isVirtualSurfaceUpdateFlag_ = false;
    ASSERT_EQ(virtualScreen->GetAndResetVirtualSurfaceUpdateFlag(), false);
}

/*
 * @tc.name: GetScreenSupportedColorGamuts_001
 * @tc.desc: GetScreenSupportedColorGamuts Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, GetScreenSupportedColorGamuts_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    std::vector<ScreenColorGamut> mode;
    virtualScreen->GetScreenSupportedColorGamuts(mode);
}

/*
 * @tc.name: SetScreenColorGamut_001
 * @tc.desc: SetScreenColorGamut Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetScreenColorGamut_001, testing::ext::TestSize.Level1)
{
    ScreenId id = static_cast<uint64_t>(1000);
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    rsScreen->SetScreenColorGamut(static_cast<int32_t>(1000));
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    ASSERT_EQ(virtualScreen->SetScreenColorGamut(static_cast<int32_t>(1000)), INVALID_ARGUMENTS);
}

/*
 * @tc.name: SetScreenVsyncEnabled_001
 * @tc.desc: SetScreenVsyncEnabled Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetScreenVsyncEnabled_001, testing::ext::TestSize.Level1)
{
    ScreenId id = static_cast<uint64_t>(1000);
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    rsScreen->SetScreenVsyncEnabled(true);
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    virtualScreen->SetScreenVsyncEnabled(true);
}

/*
 * @tc.name: SetActiveMode_001
 * @tc.desc: SetActiveMode Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetActiveMode_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    uint32_t modeId = static_cast<uint32_t>(1);
    virtualScreen->SetActiveMode(modeId);
}

/*
 * @tc.name: SetPowerStatus_002
 * @tc.desc: SetPowerStatus Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetPowerStatus_002, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    uint32_t status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_ON;
    virtualScreen->SetPowerStatus(status);
}

/*
 * @tc.name: SetPowerStatus_003
 * @tc.desc: SetPowerStatus Test, test POWER_STATUS_ON_ADVANCED with mock HDI device
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetPowerStatus_003, testing::ext::TestSize.Level1)
{
    ScreenId screenId = mockScreenId_;
    auto hdiOutput = HdiOutput::CreateHdiOutput(screenId);
    auto rsScreen = std::make_unique<impl::RSScreen>(screenId, false, hdiOutput, nullptr);
    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    uint32_t status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_ON_ADVANCED;
    rsScreen->SetPowerStatus(status);
    ASSERT_EQ(rsScreen->GetPowerStatus(), status);
}

/*
 * @tc.name: SetPowerStatus_004
 * @tc.desc: SetPowerStatus Test, test POWER_STATUS_OFF_ADVANCED with mock HDI device
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetPowerStatus_004, testing::ext::TestSize.Level1)
{
    ScreenId screenId = mockScreenId_;
    auto hdiOutput = HdiOutput::CreateHdiOutput(screenId);
    auto rsScreen = std::make_unique<impl::RSScreen>(screenId, false, hdiOutput, nullptr);
    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    uint32_t status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_OFF_ADVANCED;
    rsScreen->SetPowerStatus(status);
    ASSERT_EQ(rsScreen->GetPowerStatus(), status);
}

/*
 * @tc.name: GetActiveMode_001
 * @tc.desc: SetPowerStatus Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, GetActiveMode_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    ASSERT_EQ(virtualScreen->GetActiveMode().has_value(), false);
}

/*
 * @tc.name: GetScreenSupportedMetaDataKeys_001
 * @tc.desc: GetScreenSupportedMetaDataKeys Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, GetScreenSupportedMetaDataKeys_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    std::vector<ScreenHDRMetadataKey> keys;
    ASSERT_EQ(virtualScreen->GetScreenSupportedMetaDataKeys(keys), INVALID_BACKLIGHT_VALUE);
    ScreenId id = static_cast<uint64_t>(1);
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_EQ(rsScreen->GetScreenSupportedMetaDataKeys(keys), StatusCode::SUCCESS);
}

/*
 * @tc.name: SetScreenGamutMap_001
 * @tc.desc: SetScreenGamutMap Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetScreenGamutMap_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    ScreenGamutMap map1 = ScreenGamutMap::GAMUT_MAP_CONSTANT;
    auto result1 = virtualScreen->SetScreenGamutMap(map1);
    ASSERT_EQ(result1, StatusCode::SUCCESS);
    ScreenGamutMap map2 = ScreenGamutMap::GAMUT_MAP_CONSTANT;
    const auto result2 = virtualScreen->GetScreenGamutMap(map2);
    ASSERT_EQ(result2, StatusCode::SUCCESS);
}

/*
 * @tc.name: SetScreenGamutMap_002
 * @tc.desc: SetScreenGamutMap Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetScreenGamutMap_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_NE(nullptr, rsScreen);
    ScreenGamutMap map1 = ScreenGamutMap::GAMUT_MAP_CONSTANT;
    auto result1 = rsScreen->SetScreenGamutMap(map1);
    ASSERT_EQ(result1, StatusCode::HDI_ERROR);
    const auto result2 = rsScreen->GetScreenGamutMap(map1);
    ASSERT_EQ(result2, StatusCode::HDI_ERROR);
}

/*
 * @tc.name: GetActiveModePosByModeIdTest
 * @tc.desc: GetActiveModePosByModeId Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, GetActiveModePosByModeIdTest001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    int32_t modeId = 0;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    auto res = virtualScreen->GetActiveModePosByModeId(modeId);
    ASSERT_EQ(res, -1);
}

/*
 * @tc.name: GetScreenTypeTest
 * @tc.desc: GetScreenType Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, GetScreenTypeTest, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    config.id = static_cast<uint64_t>(1000);
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    auto res = virtualScreen->GetScreenType();
    auto type = RSScreenType::VIRTUAL_TYPE_SCREEN;
    ASSERT_EQ(res, type);
}

/*
 * @tc.name: SetScreenSkipFrameIntervalTest
 * @tc.desc: SetScreenSkipFrameInterval Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SetScreenSkipFrameIntervalTest, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    config.id = static_cast<uint64_t>(1000);
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    uint32_t skipFrameInterval = 0;
    virtualScreen->SetScreenSkipFrameInterval(skipFrameInterval);
    auto res = virtualScreen->GetScreenSkipFrameInterval();
    ASSERT_EQ(res, 0);
}

/*
 * @tc.name: GetScreenSupportedHDRFormats_001
 * @tc.desc: GetScreenSupportedHDRFormats Test
 * @tc.type: FUNC
 * @tc.require: issueI8ECTE
 */
HWTEST_F(RSScreenTest, GetScreenSupportedHDRFormats_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    std::vector<ScreenHDRFormat> hdrFormats;
    ASSERT_EQ(virtualScreen->GetScreenSupportedHDRFormats(hdrFormats), StatusCode::SUCCESS);
}

/*
 * @tc.name: SetScreenHDRFormat_001
 * @tc.desc: SetScreenHDRFormat Test
 * @tc.type: FUNC
 * @tc.require: issueI8ECTE
 */
HWTEST_F(RSScreenTest, SetScreenHDRFormat_001, testing::ext::TestSize.Level1)
{
    ScreenId id = static_cast<uint64_t>(1000);
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_EQ(rsScreen->SetScreenHDRFormat(static_cast<int32_t>(1000)), INVALID_ARGUMENTS);
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    ASSERT_EQ(virtualScreen->SetScreenHDRFormat(static_cast<int32_t>(1000)), INVALID_ARGUMENTS);
}

/*
 * @tc.name: SetPixelFormat_001
 * @tc.desc: SetPixelFormat Test
 * @tc.type: FUNC
 * @tc.require: issueI8ECTE
 */
HWTEST_F(RSScreenTest, SetPixelFormat_001, testing::ext::TestSize.Level1)
{
    ScreenId id = static_cast<uint64_t>(1000);
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_EQ(rsScreen->SetPixelFormat(static_cast<GraphicPixelFormat>(20)), StatusCode::SUCCESS); //BGRA8888
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    ASSERT_EQ(virtualScreen->SetPixelFormat(static_cast<GraphicPixelFormat>(20)), StatusCode::SUCCESS);
}

/*
 * @tc.name: GetScreenSupportedColorSpaces_001
 * @tc.desc: GetScreenSupportedColorSpaces Test
 * @tc.type: FUNC
 * @tc.require: issueI8ECTE
 */
HWTEST_F(RSScreenTest, GetScreenSupportedColorSpaces_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    std::vector<GraphicCM_ColorSpaceType> colorSpaces;
    ASSERT_EQ(virtualScreen->GetScreenSupportedColorSpaces(colorSpaces), StatusCode::SUCCESS);
}

/*
 * @tc.name: SetScreenColorSpace_001
 * @tc.desc: SetScreenColorSpace Test
 * @tc.type: FUNC
 * @tc.require: issueI8ECTE
 */
HWTEST_F(RSScreenTest, SetScreenColorSpace_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    auto virtualScreen = std::make_unique<impl::RSScreen>(config);
    ASSERT_EQ(virtualScreen->SetScreenColorSpace(
        static_cast<GraphicCM_ColorSpaceType>(1 | (2 << 8) | (3 << 16) | (1 << 21))), SUCCESS);
}

/*
 * @tc.name: SurfaceDumpTest
 * @tc.desc: SurfaceDump Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, SurfaceDumpTest, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_NE(nullptr, rsScreen);
    int32_t screenIndex = 0;
    std::string dumpString = "SurfaceDumpTest";
    rsScreen->SurfaceDump(screenIndex, dumpString);
}

/*
 * @tc.name: FpsDumpTest
 * @tc.desc: FpsDump Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, FpsDumpTest, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_NE(nullptr, rsScreen);
    int32_t screenIndex = 0;
    std::string dumpString = "FpsDumpTest";
    std::string arg = "FpsDumpTest";
    rsScreen->FpsDump(screenIndex, dumpString, arg);
}

/*
 * @tc.name: ClearFpsDumpTest
 * @tc.desc: ClearFpsDump Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, ClearFpsDumpTest_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_NE(nullptr, rsScreen);
    int32_t screenIndex = 0;
    std::string dumpString = "ClearFpsDumpTest";
    std::string arg = "ClearFpsDumpTest";
    rsScreen->ClearFpsDump(screenIndex, dumpString, arg);
}

/*
 * @tc.name: ClearFpsDumpTest
 * @tc.desc: ClearFpsDump Test
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, ClearFpsDumpTest_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);
    int32_t screenIndex = 0;
    std::string dumpString = "ClearFpsDumpTest";
    std::string arg = "ClearFpsDumpTest";
    rsScreen->ClearFpsDump(screenIndex, dumpString, arg);
}

/*
 * @tc.name: PowerStatusDump_001
 * @tc.desc: PowerStatusDump Test, virtual screen
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, PowerStatusDump_001, testing::ext::TestSize.Level1)
{
    VirtualScreenConfigs config;
    config.id = 1;
    auto rsScreen = std::make_unique<impl::RSScreen>(config);
    ASSERT_NE(rsScreen, nullptr);
    uint32_t status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_ON;
    rsScreen->SetPowerStatus(status);
    std::string dumpString = "";
    rsScreen->PowerStatusDump(dumpString);
    ASSERT_TRUE(dumpString=="powerstatus=INVALID_POWER_STATUS");
}

/*
 * @tc.name: PowerStatusDump_002
 * @tc.desc: PowerStatusDump Test, with mocked HDI device
 * @tc.type: FUNC
 * @tc.require: issueI78T3Z
 */
HWTEST_F(RSScreenTest, PowerStatusDump_002, testing::ext::TestSize.Level1)
{
    ScreenId screenId = mockScreenId_;
    auto hdiOutput = HdiOutput::CreateHdiOutput(screenId);
    auto rsScreen = std::make_unique<impl::RSScreen>(screenId, false, hdiOutput, nullptr);
    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    // Set status to GRAPHIC_POWER_STATUS_ON_ADVANCED
    rsScreen->SetPowerStatus(GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_ON_ADVANCED);
    std::string dumpString = "";
    rsScreen->PowerStatusDump(dumpString);
    ASSERT_TRUE(dumpString=="powerstatus=POWER_STATUS_ON_ADVANCED");
    // Set status to GRAPHIC_POWER_STATUS_OFF_ADVANCED
    rsScreen->SetPowerStatus(GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_OFF_ADVANCED);
    dumpString = "";
    rsScreen->PowerStatusDump(dumpString);
    ASSERT_TRUE(dumpString=="powerstatus=POWER_STATUS_OFF_ADVANCED");
}

/*
 * @tc.name: SetRogResolution_003
 * @tc.desc: SetRogResolution Test
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetRogResolution_003, testing::ext::TestSize.Level1)
{
    uint32_t width = 100;
    uint32_t height = 100;
    ScreenId id = INVALID_SCREEN_ID;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    rsScreen->SetRogResolution(width, height);
}

/*
 * @tc.name: ScreenCapabilityInit_001
 * @tc.desc: ScreenCapabilityInit
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, ScreenCapabilityInit_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->isVirtual_ = true;
    rsScreen->ScreenCapabilityInit();
}

/*
 * @tc.name: ScreenCapabilityInit_002
 * @tc.desc: ScreenCapabilityInit
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, ScreenCapabilityInit_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->isVirtual_ = false;

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, GetScreenCapability(id, _))
        .Times(1)
        .WillOnce(testing::Return(GRAPHIC_DISPLAY_SUCCESS));

    rsScreen->ScreenCapabilityInit();
}

/*
 * @tc.name: IsEnable_002
 * @tc.desc: IsEnable
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, IsEnable_002, testing::ext::TestSize.Level1)
{
    auto csurface = IConsumerSurface::Create();
    auto producer = csurface->GetProducer();
    auto psurface = Surface::CreateSurfaceAsProducer(producer);

    ScreenId id = 0;

    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);
    ASSERT_FALSE(rsScreen->IsEnable());

    rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), nullptr);
    ASSERT_TRUE(rsScreen->IsEnable());

    rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, psurface);
    ASSERT_TRUE(rsScreen->IsEnable());

    rsScreen = std::make_unique<impl::RSScreen>(id, false, HdiOutput::CreateHdiOutput(id), psurface);
    ASSERT_TRUE(rsScreen->IsEnable());
}

/*
 * @tc.name: SetActiveMode_006
 * @tc.desc: SetActiveMode, IsVirtual() is false, modeId >= supportedModes_.size()
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetActiveMode_006, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->isVirtual_ = false;

    rsScreen->supportedModes_.resize(1);
    uint32_t modeId = 5;

    rsScreen->SetActiveMode(modeId);
}

/*
 * @tc.name: SetActiveMode_002
 * @tc.desc: SetActiveMode, IsVirtual() is false, modeId < supportedModes_.size(),
 * hdiScreen_->SetScreenMode(static_cast<uint32_t>(selectModeId)) < 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetActiveMode_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->isVirtual_ = false;

    rsScreen->supportedModes_.resize(6);
    uint32_t modeId = 1;
    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenMode(_, _)).Times(1).WillOnce(testing::Return(-1));

    rsScreen->SetActiveMode(modeId);
}

/*
 * @tc.name: SetActiveMode_003
 * @tc.desc: SetActiveMode, IsVirtual() is false, modeId < supportedModes_.size(),
 * hdiScreen_->SetScreenMode(static_cast<uint32_t>(selectModeId)) > 0,
 * GetActiveMode() return {}
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetActiveMode_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    //  IsVirtual() is false
    rsScreen->isVirtual_ = false;

    // isure GetActiveMode return {}
    decltype(rsScreen->supportedModes_.size()) supportedModesSize = 2;
    rsScreen->supportedModes_.resize(supportedModesSize);

    rsScreen->supportedModes_[0] = { .width = 200, .height = 100, .freshRate = 60, .id = 1 }; // id not 0
    rsScreen->supportedModes_[1] = { .width = 200, .height = 100, .freshRate = 60, .id = 1 }; // id not 0

    // hdiScreen_->SetScreenMode(static_cast<uint32_t>(selectModeId)) > 0
    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenMode(_, _)).Times(1).WillOnce(testing::Return(1));

    // modeId < supportedModes_.size()
    uint32_t modeId = supportedModesSize - 1;
    rsScreen->SetActiveMode(modeId);
}

/*
 * @tc.name: SetActiveMode_004
 * @tc.desc: SetActiveMode, IsVirtual() is false, modeId < supportedModes_.size(),
 * hdiScreen_->SetScreenMode(static_cast<uint32_t>(selectModeId)) > 0,
 * GetActiveMode() return not {}
 * only if one !=, into branch
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetActiveMode_004, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    //  IsVirtual() is false
    rsScreen->isVirtual_ = false;

    // isure GetActiveMode return not {}
    decltype(rsScreen->supportedModes_.size()) supportedModesSize = 2;
    rsScreen->supportedModes_.resize(supportedModesSize);

    // default static init 0, into branch
    rsScreen->supportedModes_[0] = { .width = 200, .height = 100, .freshRate = 60, .id = 0 }; // id 0
    rsScreen->supportedModes_[1] = { .width = 200, .height = 100, .freshRate = 60, .id = 1 };

    // hdiScreen_->SetScreenMode(static_cast<uint32_t>(selectModeId)) > 0
    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenMode(_, _)).Times(1).WillOnce(testing::Return(1));

    // modeId < supportedModes_.size()
    uint32_t modeId = supportedModesSize - 1;
    rsScreen->SetActiveMode(modeId);
}

/*
 * @tc.name: SetActiveMode_005
 * @tc.desc: SetActiveMode, IsVirtual() is false, modeId < supportedModes_.size(),
 * hdiScreen_->SetScreenMode(static_cast<uint32_t>(selectModeId)) > 0,
 * GetActiveMode() return not {}
 * only if one !=, not into branch
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetActiveMode_005, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    //  IsVirtual() is false
    rsScreen->isVirtual_ = false;

    // isure GetActiveMode return not {}
    decltype(rsScreen->supportedModes_.size()) supportedModesSize = 2;
    rsScreen->supportedModes_.resize(supportedModesSize);

    // default static init 0, not into branch
    rsScreen->supportedModes_[0] = { .width = 0, .height = 0, .freshRate = 0, .id = 0 }; // id 0
    rsScreen->supportedModes_[1] = { .width = 200, .height = 100, .freshRate = 60, .id = 1 };

    // hdiScreen_->SetScreenMode(static_cast<uint32_t>(selectModeId)) > 0
    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenMode(_, _)).Times(1).WillOnce(testing::Return(1));

    // modeId < supportedModes_.size()
    uint32_t modeId = supportedModesSize - 1;
    rsScreen->SetActiveMode(modeId);
}

/*
 * @tc.name: SetRogResolution_002
 * @tc.desc: SetRogResolution， into branch 2 ,hdiScreen_->SetScreenOverlayResolution(width, height) < 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetRogResolution_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    uint32_t width = 100;
    uint32_t height = 100;

    rsScreen->width_ = width + 1;
    rsScreen->height_ = height + 1;

    rsScreen->phyWidth_ = width + 1;
    rsScreen->phyHeight_ = height + 1;

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenOverlayResolution(_, _, _)).Times(1).WillOnce(testing::Return(-1));

    rsScreen->SetRogResolution(width, height);
}

/*
 * @tc.name: SetResolution_002
 * @tc.desc: SetRogResolution， IsVirtual() is false
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetResolution_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->isVirtual_ = false;
    rsScreen->SetResolution(0, 0);
}

/*
 * @tc.name: GetActiveModePosByModeId_001
 * @tc.desc: GetActiveModePosByModeId
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetActiveModePosByModeId_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    decltype(rsScreen->supportedModes_.size()) supportedModesSize = 2;
    rsScreen->supportedModes_.resize(supportedModesSize);

    int32_t modeId = 0;
    rsScreen->supportedModes_[0] = { .width = 0, .height = 0, .freshRate = 0, .id = modeId };
    rsScreen->supportedModes_[1] = { .width = 200, .height = 100, .freshRate = 60, .id = 1 };

    ASSERT_EQ(rsScreen->GetActiveModePosByModeId(modeId), 0);
}

/*
 * @tc.name: SetPowerStatus_005
 * @tc.desc: SetPowerStatus, hdiScreen_->SetScreenVsyncEnabled(true) != GRAPHIC_DISPLAY_SUCCESS,
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetPowerStatus_005, testing::ext::TestSize.Level1)
{
    ScreenId id = mockScreenId_;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenVsyncEnabled(_, _))
        .Times(1)
        .WillOnce(testing::Return(GRAPHIC_DISPLAY_PARAM_ERR));

    rsScreen->isVirtual_ = false;
    uint32_t powerStatus = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_ON;
    rsScreen->SetPowerStatus(powerStatus);
}

/*
 * @tc.name: SetPowerStatus_006
 * @tc.desc: SetPowerStatus, hdiScreen_->SetScreenVsyncEnabled(true) == GRAPHIC_DISPLAY_SUCCESS,
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetPowerStatus_006, testing::ext::TestSize.Level1)
{
    ScreenId id = mockScreenId_;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenVsyncEnabled(_, _))
        .Times(1)
        .WillOnce(testing::Return(GRAPHIC_DISPLAY_SUCCESS));

    rsScreen->isVirtual_ = false;
    uint32_t powerStatus = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_ON;
    rsScreen->SetPowerStatus(powerStatus);
}

/*
 * @tc.name: GetActiveMode_002
 * @tc.desc: GetActiveMode
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetActiveMode_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->isVirtual_ = false;
    rsScreen->hdiScreen_ = nullptr;

    EXPECT_EQ(rsScreen->GetActiveMode(), std::nullopt);
}

/*
 * @tc.name: CapabilityTypeDump_001
 * @tc.desc: CapabilityTypeDump
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, CapabilityTypeDump_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    std::string dumpString = "";
    rsScreen->CapabilityTypeDump(GRAPHIC_DISP_INTF_LCD, dumpString);
    rsScreen->CapabilityTypeDump(GRAPHIC_DISP_INTF_BT1120, dumpString);
    rsScreen->CapabilityTypeDump(GRAPHIC_DISP_INTF_BT656, dumpString);
    rsScreen->CapabilityTypeDump(GRAPHIC_DISP_INTF_BUTT, dumpString);
}

/*
 * @tc.name: PropDump_001
 * @tc.desc: PropDump
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, PropDump_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->capability_.propertyCount = 2;
    rsScreen->capability_.props.resize(2);
    rsScreen->capability_.props[0] = { .name = "0", .propId = 0, .value = 0 };
    rsScreen->capability_.props[1] = { .name = "1", .propId = 1, .value = 1 };

    std::string dumpString = "";
    rsScreen->PropDump(dumpString);
}

/*
 * @tc.name: PowerStatusDump_003
 * @tc.desc: PowerStatusDump
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, PowerStatusDump_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    std::string dumpString = "dumpString";
    uint32_t status;

    status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_ON;
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);

    status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_STANDBY;
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);

    status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_SUSPEND;
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);

    status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_OFF;
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);

    status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_OFF_FAKE;
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);

    status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_BUTT;
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);

    status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_ON_ADVANCED;
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);

    status = GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_OFF_ADVANCED;
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);

    status = static_cast<GraphicDispPowerStatus>(GraphicDispPowerStatus::GRAPHIC_POWER_STATUS_OFF_ADVANCED + 1);
    rsScreen->SetPowerStatus(status);
    rsScreen->PowerStatusDump(dumpString);
}

/*
 * @tc.name: ScreenTypeDump_002
 * @tc.desc: ScreenTypeDump Test
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, ScreenTypeDump_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    std::string dumpString = "dumpString";

    rsScreen->screenType_ = RSScreenType::BUILT_IN_TYPE_SCREEN;
    rsScreen->ScreenTypeDump(dumpString);

    rsScreen->screenType_ = RSScreenType::EXTERNAL_TYPE_SCREEN;
    rsScreen->ScreenTypeDump(dumpString);

    rsScreen->screenType_ = RSScreenType::VIRTUAL_TYPE_SCREEN;
    rsScreen->ScreenTypeDump(dumpString);

    rsScreen->screenType_ = RSScreenType::UNKNOWN_TYPE_SCREEN;
    rsScreen->ScreenTypeDump(dumpString);
}

/*
 * @tc.name: ResizeVirtualScreen_001
 * @tc.desc: ResizeVirtualScreen
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, ResizeVirtualScreen_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->ResizeVirtualScreen(100, 100);
}

/*
 * @tc.name: SetScreenBacklight_002
 * @tc.desc: SetScreenBacklight
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenBacklight_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenBacklight(_, _)).Times(1).WillOnce(testing::Return(-1));

    rsScreen->SetScreenBacklight(1);
}

/*
 * @tc.name: GetScreenBacklight_001
 * @tc.desc: GetScreenBacklight, hdiScreen_->GetScreenBacklight(level) < 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenBacklight_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->screenBacklightLevel_ = INVALID_BACKLIGHT_VALUE;
    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, GetScreenBacklight(_, _)).Times(1).WillOnce(testing::Return(-1));

    ASSERT_EQ(rsScreen->GetScreenBacklight(), INVALID_BACKLIGHT_VALUE);
}

/*
 * @tc.name: GetScreenSupportedColorGamuts_002
 * @tc.desc: GetScreenSupportedColorGamuts
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenSupportedColorGamuts_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->isVirtual_ = false;
    std::vector<ScreenColorGamut> mode;

    rsScreen->supportedPhysicalColorGamuts_.resize(0);
    ASSERT_EQ(rsScreen->GetScreenSupportedColorGamuts(mode), StatusCode::HDI_ERROR);

    rsScreen->supportedPhysicalColorGamuts_.resize(1);
    ASSERT_EQ(rsScreen->GetScreenSupportedColorGamuts(mode), StatusCode::SUCCESS);
}

/*
 * @tc.name: GetScreenColorGamut_001
 * @tc.desc: GetScreenColorGamut, IsVirtual() return false and if (supportedPhysicalColorGamuts_.size() == 0)
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenColorGamut_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    ScreenColorGamut mode;

    rsScreen->supportedPhysicalColorGamuts_.resize(0);
    ASSERT_EQ(rsScreen->GetScreenColorGamut(mode), StatusCode::HDI_ERROR);
}

/*
 * @tc.name: SetScreenColorGamut_002
 * @tc.desc: SetScreenColorGamut
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorGamut_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    int32_t modeIdx = -1;
    ASSERT_EQ(rsScreen->SetScreenColorGamut(modeIdx), StatusCode::INVALID_ARGUMENTS);
}

/*
 * @tc.name: SetScreenColorGamut_003
 * @tc.desc: SetScreenColorGamut
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorGamut_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;

    // modeIdx >=0
    int32_t modeIdx = 2;
    // IsVirtual() return false
    rsScreen->isVirtual_ = false;
    // hdiScreen_->GetScreenSupportedColorGamuts(hdiMode) == GRAPHIC_DISPLAY_SUCCESS
    // modeIdx >= static_cast<int32_t>(hdiMode.size())
    EXPECT_CALL(*hdiDeviceMock_, GetScreenSupportedColorGamuts(_, _))
        .Times(1)
        .WillOnce([modeIdx](uint32_t, std::vector<GraphicColorGamut>& gamuts) {
            gamuts.resize(modeIdx - 1);
            return GRAPHIC_DISPLAY_SUCCESS;
        });

    ASSERT_EQ(rsScreen->SetScreenColorGamut(modeIdx), StatusCode::INVALID_ARGUMENTS);
}

/*
 * @tc.name: SetScreenColorGamut_004
 * @tc.desc: SetScreenColorGamut
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorGamut_004, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;

    // modeIdx >=0
    int32_t modeIdx = 2;
    // IsVirtual() return false
    rsScreen->isVirtual_ = false;
    // hdiScreen_->GetScreenSupportedColorGamuts(hdiMode) == GRAPHIC_DISPLAY_SUCCESS
    // modeIdx < static_cast<int32_t>(hdiMode.size())
    EXPECT_CALL(*hdiDeviceMock_, GetScreenSupportedColorGamuts(_, _))
        .Times(1)
        .WillOnce([modeIdx](uint32_t, std::vector<GraphicColorGamut>& gamuts) {
            gamuts.resize(modeIdx + 1);
            return GRAPHIC_DISPLAY_SUCCESS;
        });

    // result == GRAPHIC_DISPLAY_SUCCESS
    EXPECT_CALL(*hdiDeviceMock_, SetScreenColorGamut(_, _)).Times(1).WillOnce(testing::Return(GRAPHIC_DISPLAY_SUCCESS));
    ASSERT_EQ(rsScreen->SetScreenColorGamut(modeIdx), StatusCode::SUCCESS);
}

/*
 * @tc.name: SetScreenColorGamut_005
 * @tc.desc: SetScreenColorGamut
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorGamut_005, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;

    // modeIdx >=0
    int32_t modeIdx = 2;
    // IsVirtual() return false
    rsScreen->isVirtual_ = false;
    // hdiScreen_->GetScreenSupportedColorGamuts(hdiMode) == GRAPHIC_DISPLAY_SUCCESS
    // modeIdx < static_cast<int32_t>(hdiMode.size())
    EXPECT_CALL(*hdiDeviceMock_, GetScreenSupportedColorGamuts(_, _))
        .Times(1)
        .WillOnce([modeIdx](uint32_t, std::vector<GraphicColorGamut>& gamuts) {
            gamuts.resize(modeIdx + 1);
            return GRAPHIC_DISPLAY_SUCCESS;
        });

    // result != GRAPHIC_DISPLAY_SUCCESS
    EXPECT_CALL(*hdiDeviceMock_, SetScreenColorGamut(_, _))
        .Times(1)
        .WillOnce(testing::Return(GRAPHIC_DISPLAY_PARAM_ERR));
    ASSERT_EQ(rsScreen->SetScreenColorGamut(modeIdx), StatusCode::HDI_ERROR);
}

/*
 * @tc.name: SetScreenGamutMap_003
 * @tc.desc: SetScreenGamutMap
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenGamutMap_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenGamutMap(_, _)).Times(1).WillOnce(testing::Return(GRAPHIC_DISPLAY_SUCCESS));

    ScreenGamutMap mode = GAMUT_MAP_CONSTANT;
    ASSERT_EQ(rsScreen->SetScreenGamutMap(mode), StatusCode::SUCCESS);
}

/*
 * @tc.name: GetScreenGamutMap_001
 * @tc.desc: GetScreenGamutMap， hdiScreen_->GetScreenGamutMap(hdiMode) == GRAPHIC_DISPLAY_SUCCESS
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenGamutMap_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, GetScreenGamutMap(_, _)).Times(1).WillOnce([](uint32_t, GraphicGamutMap& gamutMap) {
        GraphicGamutMap hdiMode = GRAPHIC_GAMUT_MAP_CONSTANT;
        gamutMap = hdiMode;
        return GRAPHIC_DISPLAY_SUCCESS;
    });

    ScreenGamutMap mode = GAMUT_MAP_CONSTANT;
    ASSERT_EQ(rsScreen->GetScreenGamutMap(mode), StatusCode::SUCCESS);
}

/*
 * @tc.name: SetVirtualMirrorScreenCanvasRotation_001
 * @tc.desc: SetVirtualMirrorScreenCanvasRotation
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetVirtualMirrorScreenCanvasRotation_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    ASSERT_FALSE(rsScreen->SetVirtualMirrorScreenCanvasRotation(false));
}

/*
 * @tc.name: GetScaleMode_001
 * @tc.desc: GetScaleMode
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScaleMode_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    ScreenScaleMode scaleMode = ScreenScaleMode::UNISCALE_MODE;
    rsScreen->scaleMode_ = scaleMode;
    ASSERT_EQ(rsScreen->GetScaleMode(), scaleMode);
}

/*
 * @tc.name: GetScreenSupportedHDRFormats_002
 * @tc.desc: GetScreenSupportedHDRFormats, IsVirtual() return  false, hdrFormats.size() == 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenSupportedHDRFormats_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->supportedPhysicalHDRFormats_.resize(0);
    std::vector<ScreenHDRFormat> hdrFormats;
    ASSERT_EQ(rsScreen->GetScreenSupportedHDRFormats(hdrFormats), StatusCode::HDI_ERROR);
}
/*
 * @tc.name: GetScreenSupportedHDRFormats_003
 * @tc.desc: GetScreenSupportedHDRFormats, IsVirtual() return  false, hdrFormats.size() != 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenSupportedHDRFormats_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->supportedPhysicalHDRFormats_.resize(1);
    std::vector<ScreenHDRFormat> hdrFormats;
    ASSERT_EQ(rsScreen->GetScreenSupportedHDRFormats(hdrFormats), StatusCode::SUCCESS);
}

/*
 * @tc.name: GetScreenHDRFormat_001
 * @tc.desc: GetScreenHDRFormat, IsVirtual() return false, supportedPhysicalHDRFormats_.size() == 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenHDRFormat_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->supportedPhysicalHDRFormats_.resize(0);
    ScreenHDRFormat hdrFormat;
    ASSERT_EQ(rsScreen->GetScreenHDRFormat(hdrFormat), StatusCode::HDI_ERROR);
}

/*
 * @tc.name: SetScreenHDRFormat_002
 * @tc.desc: SetScreenHDRFormat, modeIdx < 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenHDRFormat_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    int32_t modeIdx = -1;
    ASSERT_EQ(rsScreen->SetScreenHDRFormat(modeIdx), StatusCode::INVALID_ARGUMENTS);
}

/*
 * @tc.name: SetScreenHDRFormat_003
 * @tc.desc: SetScreenHDRFormat, modeIdx > 0, IsVirtual() return false,modeIdx <
 * static_cast<int32_t>(hdrCapability_.formats.size())
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenHDRFormat_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    int32_t modeIdx = 1;
    decltype(rsScreen->hdrCapability_.formats.size()) formatsSize = modeIdx + 1;
    rsScreen->hdrCapability_.formats.resize(formatsSize);

    ASSERT_EQ(rsScreen->SetScreenHDRFormat(modeIdx), StatusCode::SUCCESS);
}

/*
 * @tc.name: GetScreenSupportedColorSpaces_002
 * @tc.desc: GetScreenSupportedColorSpaces, IsVirtual() return false, colorSpaces.size() == 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenSupportedColorSpaces_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    ASSERT_FALSE(rsScreen->IsVirtual());

    std::vector<GraphicCM_ColorSpaceType> colorSpaces;
    colorSpaces.resize(0);
    ASSERT_EQ(colorSpaces.size(), 0);

    rsScreen->supportedPhysicalColorGamuts_.resize(0);
    ASSERT_EQ(rsScreen->GetScreenSupportedColorSpaces(colorSpaces), StatusCode::HDI_ERROR);
}

/*
 * @tc.name: GetScreenSupportedColorSpaces_003
 * @tc.desc: GetScreenSupportedColorSpaces, IsVirtual() return false, colorSpaces.size() != 0
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetScreenSupportedColorSpaces_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    std::vector<GraphicCM_ColorSpaceType> colorSpaces;
    colorSpaces.resize(2);

    ASSERT_EQ(rsScreen->GetScreenSupportedColorSpaces(colorSpaces), StatusCode::SUCCESS);
}
/*
 * @tc.name: SetScreenColorSpace_002
 * @tc.desc: SetScreenColorSpace, iter == COMMON_COLOR_SPACE_TYPE_TO_RS_MAP.end()
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorSpace_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    GraphicCM_ColorSpaceType colorSpace = GRAPHIC_CM_COLORSPACE_NONE;
    ASSERT_EQ(rsScreen->SetScreenColorSpace(colorSpace), StatusCode::INVALID_ARGUMENTS);
}

/*
 * @tc.name: SetScreenColorSpace_003
 * @tc.desc: SetScreenColorSpace, iter != COMMON_COLOR_SPACE_TYPE_TO_RS_MAP.end(), IsVirtual true,it ==
 * supportedVirtualColorGamuts_.end()
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorSpace_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, true, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->supportedVirtualColorGamuts_.resize(0);

    GraphicCM_ColorSpaceType colorSpace = GRAPHIC_CM_BT601_EBU_FULL;
    ASSERT_EQ(rsScreen->SetScreenColorSpace(colorSpace), StatusCode::INVALID_ARGUMENTS);
}

/*
 * @tc.name: SetScreenColorSpace_004
 * @tc.desc: SetScreenColorSpace,iter != COMMON_COLOR_SPACE_TYPE_TO_RS_MAP.end(), IsVirtual false,
 * hdiScreen_->GetScreenSupportedColorGamuts(hdiMode) != GRAPHIC_DISPLAY_SUCCESS
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorSpace_004, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, GetScreenSupportedColorGamuts(_, _))
        .Times(1)
        .WillOnce(testing::Return(GRAPHIC_DISPLAY_PARAM_ERR));

    GraphicCM_ColorSpaceType colorSpace = GRAPHIC_CM_BT601_EBU_FULL;
    ASSERT_EQ(rsScreen->SetScreenColorSpace(colorSpace), StatusCode::HDI_ERROR);
}

/*
 * @tc.name: SetScreenColorSpace_005
 * @tc.desc: SetScreenColorSpace,iter != COMMON_COLOR_SPACE_TYPE_TO_RS_MAP.end(), IsVirtual false,
 * hdiScreen_->GetScreenSupportedColorGamuts(hdiMode) == GRAPHIC_DISPLAY_SUCCESS
 * it == hdiMode.end()
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorSpace_005, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, GetScreenSupportedColorGamuts(_, _))
        .Times(1)
        .WillOnce([](uint32_t, std::vector<GraphicColorGamut>& hdiMode) {
            hdiMode.resize(0);
            return GRAPHIC_DISPLAY_SUCCESS;
        });

    GraphicCM_ColorSpaceType colorSpace = GRAPHIC_CM_BT601_EBU_FULL;
    ASSERT_EQ(rsScreen->SetScreenColorSpace(colorSpace), StatusCode::INVALID_ARGUMENTS);
}

/*
 * @tc.name: SetScreenColorSpace_007
 * @tc.desc: SetScreenColorSpace,iter != COMMON_COLOR_SPACE_TYPE_TO_RS_MAP.end(), IsVirtual false,
 * hdiScreen_->GetScreenSupportedColorGamuts(hdiMode) == GRAPHIC_DISPLAY_SUCCESS
 * it != hdiMode.end()
 * result == GRAPHIC_DISPLAY_SUCCESS
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorSpace_007, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, GetScreenSupportedColorGamuts(_, _))
        .Times(1)
        .WillOnce([](uint32_t, std::vector<GraphicColorGamut>& hdiMode) {
            hdiMode.resize(1);
            hdiMode[0] = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_STANDARD_BT601; // it != hdiMode.end(),curIdx=0
            return GRAPHIC_DISPLAY_SUCCESS;
        });

    EXPECT_CALL(*hdiDeviceMock_, SetScreenColorGamut(_, _)).Times(1).WillOnce(testing::Return(GRAPHIC_DISPLAY_SUCCESS));

    GraphicCM_ColorSpaceType colorSpace = GRAPHIC_CM_BT601_EBU_FULL;
    ASSERT_EQ(rsScreen->SetScreenColorSpace(colorSpace), StatusCode::SUCCESS);
}

/*
 * @tc.name: SetScreenColorSpace_006
 * @tc.desc: SetScreenColorSpace,iter != COMMON_COLOR_SPACE_TYPE_TO_RS_MAP.end(), IsVirtual false,
 * hdiScreen_->GetScreenSupportedColorGamuts(hdiMode) == GRAPHIC_DISPLAY_SUCCESS
 * it != hdiMode.end()
 * result != GRAPHIC_DISPLAY_SUCCESS
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenColorSpace_006, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, GetScreenSupportedColorGamuts(_, _))
        .Times(1)
        .WillOnce([](uint32_t, std::vector<GraphicColorGamut>& hdiMode) {
            hdiMode.resize(1);
            hdiMode[0] = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_STANDARD_BT601; // it != hdiMode.end(),curIdx=0
            return GRAPHIC_DISPLAY_SUCCESS;
        });

    EXPECT_CALL(*hdiDeviceMock_, SetScreenColorGamut(_, _))
        .Times(1)
        .WillOnce(testing::Return(GRAPHIC_DISPLAY_PARAM_ERR));

    GraphicCM_ColorSpaceType colorSpace = GRAPHIC_CM_BT601_EBU_FULL;
    ASSERT_EQ(rsScreen->SetScreenColorSpace(colorSpace), StatusCode::HDI_ERROR);
}

/*
 * @tc.name: SetBlackList_001
 * @tc.desc: SetBlackList
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetBlackList_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    std::unordered_set<uint64_t> blackList {};
    rsScreen->SetBlackList(blackList);
}

/*
 * @tc.name: SetCastScreenEnableSkipWindow_001
 * @tc.desc: SetCastScreenEnableSkipWindow
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetCastScreenEnableSkipWindow_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->SetCastScreenEnableSkipWindow(false);
}

/*
 * @tc.name: GetCastScreenEnableSkipWindow_001
 * @tc.desc: GetCastScreenEnableSkipWindow
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetCastScreenEnableSkipWindow_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->skipWindow_ = true;
    ASSERT_TRUE(rsScreen->GetCastScreenEnableSkipWindow());
}

/*
 * @tc.name: GetBlackList_001
 * @tc.desc: GetBlackList
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetBlackList_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    std::unordered_set<uint64_t> blackList {};
    rsScreen->blackList_ = blackList;
    ASSERT_TRUE(rsScreen->GetBlackList() == blackList);
}

/*
 * @tc.name: SetScreenConstraint_001
 * @tc.desc: SetScreenConstraint, IsVirtual is true
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenConstraint_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, true, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    uint64_t frameId = 0;
    uint64_t timestamp = 0;
    ScreenConstraintType type = ScreenConstraintType::CONSTRAINT_NONE;

    ASSERT_EQ(rsScreen->SetScreenConstraint(frameId, timestamp, type), StatusCode::SUCCESS);
}

/*
 * @tc.name: SetScreenConstraint_002
 * @tc.desc: SetScreenConstraint, IsVirtual is  fasle, hdiScreen_ == nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenConstraint_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    uint64_t frameId = 0;
    uint64_t timestamp = 0;
    ScreenConstraintType type = ScreenConstraintType::CONSTRAINT_NONE;
    rsScreen->hdiScreen_ = nullptr;

    ASSERT_EQ(rsScreen->SetScreenConstraint(frameId, timestamp, type), StatusCode::HDI_ERROR);
}

/*
 * @tc.name: SetScreenConstraint_003
 * @tc.desc: SetScreenConstraint, IsVirtual is  fasle, hdiScreen_ != nullptr
 * result == GRAPHIC_DISPLAY_SUCCESS
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenConstraint_003, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    uint64_t frameId = 0;
    uint64_t timestamp = 0;
    ScreenConstraintType type = ScreenConstraintType::CONSTRAINT_NONE;
    rsScreen->hdiScreen_ = HdiScreen::CreateHdiScreen(ScreenPhysicalId(id));
    ASSERT_NE(rsScreen->hdiScreen_, nullptr);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenConstraint(_, _, _, _))
        .Times(1)
        .WillOnce(testing::Return(GRAPHIC_DISPLAY_SUCCESS));

    ASSERT_EQ(rsScreen->SetScreenConstraint(frameId, timestamp, type), StatusCode::SUCCESS);
}

/*
 * @tc.name: SetScreenConstraint_004
 * @tc.desc: SetScreenConstraint, IsVirtual is  fasle, hdiScreen_ != nullptr
 * result != GRAPHIC_DISPLAY_SUCCESS
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetScreenConstraint_004, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    uint64_t frameId = 0;
    uint64_t timestamp = 0;
    ScreenConstraintType type = ScreenConstraintType::CONSTRAINT_NONE;
    rsScreen->hdiScreen_ = HdiScreen::CreateHdiScreen(ScreenPhysicalId(id));
    ASSERT_NE(rsScreen->hdiScreen_, nullptr);

    rsScreen->hdiScreen_->device_ = hdiDeviceMock_;
    EXPECT_CALL(*hdiDeviceMock_, SetScreenConstraint(_, _, _, _))
        .Times(1)
        .WillOnce(testing::Return(GRAPHIC_DISPLAY_PARAM_ERR));

    ASSERT_EQ(rsScreen->SetScreenConstraint(frameId, timestamp, type), StatusCode::HDI_ERROR);
}

/*
 * @tc.name: SetVirtualScreenStatus_001
 * @tc.desc: SetVirtualScreenStatus, IsVirtual false
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetVirtualScreenStatus_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    ASSERT_FALSE(rsScreen->SetVirtualScreenStatus(VirtualScreenStatus::VIRTUAL_SCREEN_PLAY));
}

/*
 * @tc.name: SetVirtualScreenStatus_002
 * @tc.desc: SetVirtualScreenStatus, IsVirtual false
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, SetVirtualScreenStatus_002, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, true, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    ASSERT_TRUE(rsScreen->SetVirtualScreenStatus(VirtualScreenStatus::VIRTUAL_SCREEN_PLAY));
}

/*
 * @tc.name: GetVirtualScreenStatus_001
 * @tc.desc: GetVirtualScreenStatus
 * @tc.type: FUNC
 * @tc.require: issueIAIRAN
 */
HWTEST_F(RSScreenTest, GetVirtualScreenStatus_001, testing::ext::TestSize.Level1)
{
    ScreenId id = 0;
    auto rsScreen = std::make_unique<impl::RSScreen>(id, false, nullptr, nullptr);
    ASSERT_NE(nullptr, rsScreen);

    rsScreen->screenStatus_ = VirtualScreenStatus::VIRTUAL_SCREEN_PLAY;
    ASSERT_EQ(rsScreen->GetVirtualScreenStatus(), VirtualScreenStatus::VIRTUAL_SCREEN_PLAY);
}

} // namespace OHOS::Rosen
