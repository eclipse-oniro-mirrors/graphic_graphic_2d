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

#include <gtest/gtest.h>

#include <string>

#include "rs_graphic_test_capture.h"

namespace OHOS {
namespace Rosen {
namespace {

constexpr uint32_t READY_MAX_RETRIES = 3;
constexpr uint32_t FLUSH_SETTLE_MS = 100;

class CaptureConfigTest : public testing::Test {
protected:
    void SetUp() override
    {
        ResetEmulatorCaptureConfigForTest();
    }

    void TearDown() override
    {
        ResetEmulatorCaptureConfigForTest();
    }
};

EmulatorCaptureConfig MakeConfig()
{
    EmulatorCaptureConfig config;
    config.enabled = true;
    config.displayFallback = true;
    config.outputDirectory = "/data/local/tmp/graphic-test-output";
    config.readyMaxRetries = READY_MAX_RETRIES;
    return config;
}

TEST_F(CaptureConfigTest, DefaultPathIsNotEmulatorMode)
{
    EXPECT_FALSE(IsEmulatorCaptureModeEnabled());
    EXPECT_FALSE(IsDisplayCaptureFallbackEnabled());
    EXPECT_EQ(GetEmulatorFlushSettleMs(), 0U);
    EXPECT_TRUE(GetEmulatorCaptureConfig().outputDirectory.empty());
}

TEST_F(CaptureConfigTest, FlushSettleMsFollowsConfiguration)
{
    EXPECT_EQ(GetEmulatorFlushSettleMs(), 0U);
    auto config = MakeConfig();
    config.flushSettleMs = FLUSH_SETTLE_MS;
    std::string error;
    ASSERT_TRUE(ConfigureEmulatorCapture(config, error)) << error;
    EXPECT_EQ(GetEmulatorFlushSettleMs(), FLUSH_SETTLE_MS);
    EXPECT_EQ(GetEmulatorCaptureConfig().flushSettleMs, FLUSH_SETTLE_MS);
    ResetEmulatorCaptureConfigForTest();
    EXPECT_EQ(GetEmulatorFlushSettleMs(), 0U);
}

TEST_F(CaptureConfigTest, ExplicitConfigurationEnablesOnlyRequestedFeatures)
{
    auto config = MakeConfig();
    std::string error;
    ASSERT_TRUE(ConfigureEmulatorCapture(config, error)) << error;
    EXPECT_TRUE(IsEmulatorCaptureModeEnabled());
    EXPECT_TRUE(IsDisplayCaptureFallbackEnabled());
    EXPECT_EQ(GetEmulatorCaptureConfig().outputDirectory, config.outputDirectory);
}

TEST_F(CaptureConfigTest, EmulatorModeWithoutFallbackKeepsSurfaceCapture)
{
    auto config = MakeConfig();
    config.displayFallback = false;
    std::string error;
    ASSERT_TRUE(ConfigureEmulatorCapture(config, error)) << error;
    EXPECT_TRUE(IsEmulatorCaptureModeEnabled());
    EXPECT_FALSE(IsDisplayCaptureFallbackEnabled());
}

TEST_F(CaptureConfigTest, RejectsDisabledConfiguration)
{
    EmulatorCaptureConfig config;
    config.outputDirectory = "/data/local/tmp/output";
    std::string error;
    EXPECT_FALSE(ConfigureEmulatorCapture(config, error));
    EXPECT_FALSE(IsEmulatorCaptureModeEnabled());
}

TEST_F(CaptureConfigTest, RejectsUnsafeOutputDirectory)
{
    auto config = MakeConfig();
    config.outputDirectory = "/data/local/tmp/../escape";
    std::string error;
    EXPECT_FALSE(ConfigureEmulatorCapture(config, error));
}

TEST_F(CaptureConfigTest, RejectsRelativeOutputDirectory)
{
    auto config = MakeConfig();
    config.outputDirectory = "relative/output";
    std::string error;
    EXPECT_FALSE(ConfigureEmulatorCapture(config, error));
}

TEST_F(CaptureConfigTest, RejectsZeroReadyRetries)
{
    auto config = MakeConfig();
    config.readyMaxRetries = 0;
    std::string error;
    EXPECT_FALSE(ConfigureEmulatorCapture(config, error));
}

TEST_F(CaptureConfigTest, ResetRestoresDefaultBehavior)
{
    auto config = MakeConfig();
    std::string error;
    ASSERT_TRUE(ConfigureEmulatorCapture(config, error)) << error;
    ResetEmulatorCaptureConfigForTest();
    EXPECT_FALSE(IsEmulatorCaptureModeEnabled());
    EXPECT_FALSE(IsDisplayCaptureFallbackEnabled());
}

} // namespace
} // namespace Rosen
} // namespace OHOS
