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
#include <limits>
#include <test_header.h>

#include "hgm_frame_rate_manager.h"
#include "hgm_test_base.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {

class HgmFrameVoterTest : public HgmTestBase {
public:
    static void SetUpTestCase()
    {
        HgmTestBase::SetUpTestCase();
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: MergeRangeByPriority
 * @tc.desc: Verify the result of MergeRangeByPriority function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameVoterTest, TestMergeRangeByPriority, Function | SmallTest | Level1)
{
    VoteRange voteRange0 = { OLED_40_HZ, OLED_120_HZ };
    VoteRange voteRange1 = { OLED_30_HZ, OLED_40_HZ };
    VoteRange voteRange2 = { OLED_60_HZ, OLED_90_HZ };
    VoteRange voteRange3 = { OLED_120_HZ, OLED_144_HZ };
    VoteRange voteRange4 = { OLED_30_HZ, OLED_144_HZ };
    VoteRange voteRangeRes;

    voteRangeRes = voteRange0;
    HgmVoter::MergeRangeByPriority(voteRangeRes, voteRange1);
    ASSERT_EQ(voteRangeRes.first, OledRefreshRate::OLED_40_HZ);
    ASSERT_EQ(voteRangeRes.second, OledRefreshRate::OLED_40_HZ);

    voteRangeRes = voteRange0;
    HgmVoter::MergeRangeByPriority(voteRangeRes, voteRange2);
    ASSERT_EQ(voteRangeRes.first, OledRefreshRate::OLED_60_HZ);
    ASSERT_EQ(voteRangeRes.second, OledRefreshRate::OLED_90_HZ);

    voteRangeRes = voteRange0;
    HgmVoter::MergeRangeByPriority(voteRangeRes, voteRange3);
    ASSERT_EQ(voteRangeRes.first, OledRefreshRate::OLED_120_HZ);
    ASSERT_EQ(voteRangeRes.second, OledRefreshRate::OLED_120_HZ);

    voteRangeRes = voteRange0;
    HgmVoter::MergeRangeByPriority(voteRangeRes, voteRange4);
    ASSERT_EQ(voteRangeRes.first, OledRefreshRate::OLED_40_HZ);
    ASSERT_EQ(voteRangeRes.second, OledRefreshRate::OLED_120_HZ);
}

/**
 * @tc.name: ChangePriority
 * @tc.desc: Verify the result of ChangePriority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameVoterTest, TestChangePriority, Function | SmallTest | Level1)
{
    constexpr uint32_t DEFAULT_PRIORITY = 0;
    constexpr uint32_t VOTER_SCENE_PRIORITY_BEFORE_PACKAGES = 1;
    constexpr uint32_t VOTER_LTPO_PRIORITY_BEFORE_PACKAGES = 2;
    auto &hgmCore = HgmCore::Instance();
    auto mgr = hgmCore.GetFrameRateMgr();
    if (mgr == nullptr) {
        return;
    }
    
    mgr->hgmFrameVoter_.ChangePriority(DEFAULT_PRIORITY);
    auto packagesPos = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_PACKAGES");
    auto ltpoPos = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_LTPO");
    auto scenePos = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_SCENE");
    ASSERT_LT(packagesPos, ltpoPos);
    ASSERT_LT(ltpoPos, scenePos);
    mgr->hgmFrameVoter_.ChangePriority(VOTER_SCENE_PRIORITY_BEFORE_PACKAGES);
    auto packagesPos1 = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_PACKAGES");
    auto ltpoPos1 = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_LTPO");
    auto scenePos1 = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_SCENE");
    ASSERT_LT(scenePos1, packagesPos1);
    ASSERT_LT(packagesPos1, ltpoPos1);
    mgr->hgmFrameVoter_.ChangePriority(VOTER_LTPO_PRIORITY_BEFORE_PACKAGES);
    auto packagesPos2 = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_PACKAGES");
    auto ltpoPos2 = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_LTPO");
    auto scenePos2 = find(mgr->hgmFrameVoter_.voters_.begin(), mgr->hgmFrameVoter_.voters_.end(), "VOTER_SCENE");
    ASSERT_LT(scenePos2, ltpoPos2);
    ASSERT_LT(ltpoPos2, packagesPos2);
}

} // namespace Rosen
} // namespace OHOS