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

#include "rs_graphic_test.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class LoadRenderNodeTreeFileTest : public RSGraphicTest {
private:
    const int screenWidth = 1216;
    const int screenHeight = 2688;

public:
    // called before each tests
    void BeforeEach() override
    {
        SetScreenSize(screenWidth, screenHeight);
        system("setenforce 0");
    }

    void LoadRenderNodeTreeFile(const std::string& filePath)
    {
        auto testNode = RSCanvasNode::Create();
        testNode->SetBounds({ 0, 0, screenWidth, screenHeight });
        GetRootNode()->AddChild(testNode);
        RegisterNode(testNode);
        AddFileRenderNodeTreeToNode(testNode, filePath);
    }
};

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest12)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_12");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest13)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_13");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhutiTest14)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhuti_14");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tianqiTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tianqi_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tianqiTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tianqi_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tianqiTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tianqi_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tianqiTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tianqi_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tianqiTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tianqi_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tianqiTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tianqi_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tianqiTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tianqi_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tianqiTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tianqi_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, shizhongTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/shizhong_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, lianxirenTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/lianxiren_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, dianhuaTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/dianhua_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xinxiTest12)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xinxi_12");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest12)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_12");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest13)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_13");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest14)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_14");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest15)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_15");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest16)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_16");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest17)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_17");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest18)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_18");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, liulanqiTest19)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/liulanqi_19");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, jisuanqiTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/jisuanqi_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, jisuanqiTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/jisuanqi_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, jisuanqiTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/jisuanqi_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, jisuanqiTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/jisuanqi_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, jisuanqiTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/jisuanqi_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, jisuanqiTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/jisuanqi_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest12)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_12");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest13)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_13");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest14)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_14");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest15)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_15");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest16)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_16");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest17)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_17");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest18)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_18");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest19)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_19");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, riliTest20)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/rili_20");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest12)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_12");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest13)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_13");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest14)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_14");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest15)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_15");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest16)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_16");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest17)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_17");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest18)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_18");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest19)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_19");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiangjiTest20)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiangji_20");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest12)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_12");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest13)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_13");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest14)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_14");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest15)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_15");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest16)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_16");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest17)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_17");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, wenjianguanliTest18)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/wenjianguanli_18");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest12)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_12");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest13)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_13");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest14)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_14");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest15)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_15");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest16)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_16");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, xiaoyishurufaTest17)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/xiaoyishurufa_17");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, beiwangluTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/beiwanglu_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_02");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest03)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_03");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest04)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_04");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest05)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_05");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest06)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_06");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest07)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_07");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest08)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_08");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest09)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_09");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest10)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_10");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest11)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_11");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest12)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_12");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest13)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_13");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest14)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_14");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest15)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_15");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest16)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_16");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest17)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_17");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, tukuTest18)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/tuku_18");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhinanzhenTest01)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhinanzhen_01");
}

GRAPHIC_TEST(LoadRenderNodeTreeFileTest, CONTENT_DISPLAY_TEST, zhinanzhenTest02)
{
    LoadRenderNodeTreeFile("/data/local/tmp/NodeTree/zhinanzhen_02");
}

} // namespace OHOS::Rosen