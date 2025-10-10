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
#include "multiscreen_param_parse.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class MultiScreenParamParseTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MultiScreenParamParseTest::SetUpTestCase() {}
void MultiScreenParamParseTest::TearDownTestCase() {}
void MultiScreenParamParseTest::SetUp() {}
void MultiScreenParamParseTest::TearDown() {}

/**
 * @tc.name: ParseFeatureParamTest
 * @tc.desc: Test ParseFeatureParam
 * @tc.type: FUNC
 * @tc.require: issue#IBZZ8D
 */
HWTEST_F(MultiScreenParamParseTest, ParseFeatureParamTest, TestSize.Level1)
{
    MultiScreenParamParse paramParse;
    FeatureParamMapType paramMapType;
    xmlNode node;
    auto res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_GET_CHILD_FAIL);

    xmlNode childNode;
    childNode.type = xmlElementType::XML_ATTRIBUTE_NODE;
    node.xmlChildrenNode = &childNode;
    res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_EXEC_SUCCESS);

    xmlNode nextNode;
    nextNode.type = xmlElementType::XML_ELEMENT_NODE;
    string name = "FeatureSwitch";
    nextNode.name = reinterpret_cast<const xmlChar*>(name.c_str());
    node.xmlChildrenNode->next = &nextNode;
    res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_EXEC_SUCCESS);

    name = "FeatureSingleParam";
    nextNode.name = reinterpret_cast<const xmlChar*>(name.c_str());
    node.xmlChildrenNode->next = &nextNode;
    res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_EXEC_SUCCESS);

    xmlSetProp(&nextNode, (const xmlChar*)("name"), (const xmlChar*)("MipmapMode"));
    xmlSetProp(&nextNode, (const xmlChar*)("value"), (const xmlChar*)("0"));
    res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_EXEC_SUCCESS);

    xmlSetProp(&nextNode, (const xmlChar*)("name"), (const xmlChar*)("MipmapMode"));
    xmlSetProp(&nextNode, (const xmlChar*)("value"), (const xmlChar*)("1"));
    res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_EXEC_SUCCESS);

    xmlSetProp(&nextNode, (const xmlChar*)("name"), (const xmlChar*)("FilterMode"));
    xmlSetProp(&nextNode, (const xmlChar*)("value"), (const xmlChar*)("0"));
    res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_EXEC_SUCCESS);

    xmlSetProp(&nextNode, (const xmlChar*)("name"), (const xmlChar*)("MipmapMode"));
    xmlSetProp(&nextNode, (const xmlChar*)("value"), (const xmlChar*)("Test"));
    res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_EXEC_SUCCESS);

    name = "FeatureParam0";
    nextNode.name = reinterpret_cast<const xmlChar*>(name.c_str());
    node.xmlChildrenNode->next = &nextNode;
    res = paramParse.ParseFeatureParam(paramMapType, node);
    ASSERT_EQ(res, ParseErrCode::PARSE_EXEC_SUCCESS);
}

/**
 * @tc.name: ParseMultiScreenInternalTest
 * @tc.desc: Test ParseMultiScreenInternal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiScreenParamParseTest, ParseMultiScreenInternalTest, TestSize.Level1)
{
    MultiScreenParamParse paramParse;
    FeatureParamMapType paramMapType;
    xmlNode node;
    node.type = xmlElementType::XML_ELEMENT_NODE;
    string name = "FeatureSwitch";
    node.name = reinterpret_cast<const xmlChar*>(name.c_str());
    xmlSetProp(&node, (const xmlChar*)("name"), (const xmlChar*)("IsSkipFrameByActiveRefreshRate"));
    xmlSetProp(&node, (const xmlChar*)("value"), (const xmlChar*)("true"));
    auto res = paramParse.ParseMultiScreenInternal(node);
    EXPECT_EQ(res, PARSE_EXEC_SUCCESS);
 
    xmlSetProp(&node, (const xmlChar*)("name"), (const xmlChar*)("test01"));
    xmlSetProp(&node, (const xmlChar*)("value"), (const xmlChar*)("true"));
    res = paramParse.ParseMultiScreenInternal(node);
    EXPECT_EQ(res, PARSE_EXEC_SUCCESS);
}
}