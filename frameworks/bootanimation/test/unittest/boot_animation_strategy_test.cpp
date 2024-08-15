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

#include <gtest/gtest.h>

#include <parameters.h>
#include "util.h"
#include "boot_animation_strategy.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class BootAnimationStrategyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void BootAnimationStrategyTest::SetUpTestCase() {}
void BootAnimationStrategyTest::TearDownTestCase() {}
void BootAnimationStrategyTest::SetUp() {}
void BootAnimationStrategyTest::TearDown() {}

/**
 * @tc.name: BootAnimationStrategyTest_001
 * @tc.desc: Verify the CheckExitAniamtion
 * @tc.type:FUNC
 */
HWTEST_F(BootAnimationStrategyTest, BootAnimationStrategyTest_001, TestSize.Level1)
{
    std::shared_ptr<BootAnimationStrategy> bas1 = std::make_shared<BootAnimationStrategy>();
    bas1->isAnimationEnd_ = false;
    bas1->CheckExitAnimation();
    
    std::shared_ptr<BootAnimationStrategy> bas2 = std::make_shared<BootAnimationStrategy>();
    bas2->isAnimationEnd_ = true;
    bas2->CheckExitAnimation();

    std::shared_ptr<BootAnimationStrategy> bas3 = std::make_shared<BootAnimationStrategy>();
    bas3->isAnimationEnd_ = true;
    system::SetParameter(BOOT_COMPLETED, "false");
    bas3->CheckExitAnimation();

    std::shared_ptr<BootAnimationStrategy> bas4 = std::make_shared<BootAnimationStrategy>();
    bas4->isAnimationEnd_ = true;
    system::SetParameter(BOOT_COMPLETED, "true");
    bas4->CheckExitAnimation();
}

/**
 * @tc.name: BootAnimationStrategyTest_002
 * @tc.desc: Verify the CheckNeedOtaCompile
 * @tc.type:FUNC
 */
HWTEST_F(BootAnimationStrategyTest, BootAnimationStrategyTest_002, TestSize.Level1)
{
    std::shared_ptr<BootAnimationStrategy> bas1 = std::make_shared<BootAnimationStrategy>();
    system::SetParameter("const.bms.optimizing_apps.switch", "off");
    bas1->CheckNeedOtaCompile();
    
    std::shared_ptr<BootAnimationStrategy> bas2 = std::make_shared<BootAnimationStrategy>();
    system::SetParameter("const.bms.optimizing_apps.switch", "on");
    bas2->CheckNeedOtaCompile();

    std::shared_ptr<BootAnimationStrategy> bas3 = std::make_shared<BootAnimationStrategy>();
    system::SetParameter("const.bms.optimizing_apps.switch", "on");
    system::SetParameter("persist.dupdate_engine.update_type", "");
    bas3->CheckNeedOtaCompile();

    std::shared_ptr<BootAnimationStrategy> bas4 = std::make_shared<BootAnimationStrategy>();
    system::SetParameter("const.bms.optimizing_apps.switch", "on");
    system::SetParameter("persist.dupdate_engine.update_type", "manual");
    bas4->CheckNeedOtaCompile();

    std::shared_ptr<BootAnimationStrategy> bas5 = std::make_shared<BootAnimationStrategy>();
    system::SetParameter("const.bms.optimizing_apps.switch", "on");
    system::SetParameter("persist.dupdate_engine.update_type", "manual");
    system::SetParameter(BMS_COMPILE_STATUS, "-1");
    bas5->CheckNeedOtaCompile();

    std::shared_ptr<BootAnimationStrategy> bas6 = std::make_shared<BootAnimationStrategy>();
    system::SetParameter("const.bms.optimizing_apps.switch", "on");
    system::SetParameter("persist.dupdate_engine.update_type", "manual");
    system::SetParameter(BMS_COMPILE_STATUS, BMS_COMPILE_STATUS_END);
    bas6->CheckNeedOtaCompile();
}
}
