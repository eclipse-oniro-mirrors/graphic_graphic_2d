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

#include "rs_graphic_test_environment.h"

namespace OHOS {
namespace Rosen {
namespace {

DisplayEnvironmentInfo MakeEnvironment()
{
    DisplayEnvironmentInfo info;
    info.product = EMULATOR_PRODUCT_NAME;
    info.width = EMULATOR_EXPECTED_WIDTH;
    info.height = EMULATOR_EXPECTED_HEIGHT;
    info.renderMode = "divided";
    return info;
}

TEST(DisplayEnvironmentTest, AcceptsExpectedEmulator)
{
    std::string error;
    EXPECT_TRUE(ValidateEmulatorEnvironment(
        MakeEnvironment(), EMULATOR_EXPECTED_WIDTH, EMULATOR_EXPECTED_HEIGHT, error));
    EXPECT_TRUE(error.empty());
}

TEST(DisplayEnvironmentTest, RejectsRealDeviceProduct)
{
    auto info = MakeEnvironment();
    info.product = "phone";
    std::string error;
    EXPECT_FALSE(ValidateEmulatorEnvironment(
        info, EMULATOR_EXPECTED_WIDTH, EMULATOR_EXPECTED_HEIGHT, error));
    EXPECT_NE(error.find("product"), std::string::npos);
}

TEST(DisplayEnvironmentTest, RejectsUnknownProduct)
{
    auto info = MakeEnvironment();
    info.product = "unknown";
    std::string error;
    EXPECT_FALSE(ValidateEmulatorEnvironment(
        info, EMULATOR_EXPECTED_WIDTH, EMULATOR_EXPECTED_HEIGHT, error));
}

TEST(DisplayEnvironmentTest, RejectsWrongDimensions)
{
    auto info = MakeEnvironment();
    info.width = 1024;
    info.height = 768;
    std::string error;
    EXPECT_FALSE(ValidateEmulatorEnvironment(
        info, EMULATOR_EXPECTED_WIDTH, EMULATOR_EXPECTED_HEIGHT, error));
    EXPECT_NE(error.find("1024x768"), std::string::npos);
}

TEST(DisplayEnvironmentTest, RejectsUniRender)
{
    auto info = MakeEnvironment();
    info.renderMode = "uni";
    std::string error;
    EXPECT_FALSE(ValidateEmulatorEnvironment(
        info, EMULATOR_EXPECTED_WIDTH, EMULATOR_EXPECTED_HEIGHT, error));
    EXPECT_NE(error.find("render mode"), std::string::npos);
}

TEST(DisplayEnvironmentTest, ProductCheckIsIndependentOfDimensions)
{
    auto info = MakeEnvironment();
    info.width = 1;
    info.height = 1;
    std::string error;
    EXPECT_TRUE(ValidateEmulatorProduct(info, error));
    info.renderMode = "uni";
    EXPECT_FALSE(ValidateEmulatorProduct(info, error));
}

TEST(DisplayEnvironmentTest, RejectsInvalidExpectedDimensions)
{
    std::string error;
    EXPECT_FALSE(ValidateEmulatorEnvironment(MakeEnvironment(), 0, EMULATOR_EXPECTED_HEIGHT, error));
}

} // namespace
} // namespace Rosen
} // namespace OHOS
