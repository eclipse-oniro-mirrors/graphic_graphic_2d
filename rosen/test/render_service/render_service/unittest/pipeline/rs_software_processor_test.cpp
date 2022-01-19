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

#include "gtest/gtest.h"
#include "limit_number.h"
#include "pipeline/rs_software_processor.h"
#include "pipeline/rs_processor_factory.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSSoftwareProcessorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSSoftwareProcessorTest::SetUpTestCase() {}
void RSSoftwareProcessorTest::TearDownTestCase() {}
void RSSoftwareProcessorTest::SetUp() {}
void RSSoftwareProcessorTest::TearDown() {}

/**
 * @tc.name: CreateAndDestory001
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, CreateAndDestory001, TestSize.Level1)
{
    // The best way to create RSSoftwareProcessor.
    auto p = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
}

/**
 * @tc.name: CreateAndDestory002
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, CreateAndDestory002, TestSize.Level1)
{
    RSSoftwareProcessor rsSoftwareProcessor;
}

/**
 * @tc.name: ProcessSurface001
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, ProcessSurface001, TestSize.Level1)
{
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[1];
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    RSSurfaceRenderNode rsSurfaceRenderNode(nodeId);
    rsSoftwareProcessor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: ProcessSurface002
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, ProcessSurface002, TestSize.Level1)
{
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[2];
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    RSSurfaceRenderNode rsSurfaceRenderNode(nodeId);
    rsSoftwareProcessor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: ProcessSurface003
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, ProcessSurface003, TestSize.Level1)
{
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[3];
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    RSSurfaceRenderNode rsSurfaceRenderNode(nodeId);
    rsSoftwareProcessor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: ProcessSurface004
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, ProcessSurface004, TestSize.Level1)
{
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[4];
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    RSSurfaceRenderNode rsSurfaceRenderNode(nodeId);
    rsSoftwareProcessor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: ProcessSurface005
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, ProcessSurface005, TestSize.Level1)
{
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[5];
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    RSSurfaceRenderNode rsSurfaceRenderNode(nodeId);
    rsSoftwareProcessor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: ProcessSurface006
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, ProcessSurface006, TestSize.Level1)
{
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[6];
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    RSSurfaceRenderNode rsSurfaceRenderNode(nodeId);
    rsSoftwareProcessor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: ProcessSurface007
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, ProcessSurface007, TestSize.Level1)
{
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[7];
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    RSSurfaceRenderNode rsSurfaceRenderNode(nodeId);
    rsSoftwareProcessor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: ProcessSurface008
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, ProcessSurface008, TestSize.Level1)
{
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[0];
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    RSSurfaceRenderNode rsSurfaceRenderNode(nodeId);
    rsSoftwareProcessor->ProcessSurface(rsSurfaceRenderNode);
}

/**
 * @tc.name: PostProcess001
 * @tc.desc:
 * @tc.type:
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RSSoftwareProcessorTest, PostProcess001, TestSize.Level1)
{
    auto rsSoftwareProcessor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::SOFTWARE_COMPOSITE);
    rsSoftwareProcessor->PostProcess();
}
} // namespace OHOS::Rosen
