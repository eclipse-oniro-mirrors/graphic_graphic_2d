/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <filesystem>
#include "gtest/gtest.h"
#include "common/rs_singleton.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/round_corner_display/rs_message_bus.h"
#include "pipeline/round_corner_display/rs_round_corner_display.h"
#include "pipeline/round_corner_display/rs_round_corner_display_manager.h"
#include "pipeline/round_corner_display/rs_round_corner_config.h"
#include "pipeline/round_corner_display/rs_rcd_render_manager.h"
#include "pipeline/round_corner_display/rs_rcd_surface_render_node.h"
#include "pipeline/round_corner_display/rs_rcd_render_listener.h"
#include "pipeline/round_corner_display/rs_rcd_render_visitor.h"
#include "pipeline/rs_display_render_node.h"
#include "surface_buffer_impl.h"
#include "rs_test_util.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSRoundCornerDisplayTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void RSRoundCornerDisplayTest::SetUpTestCase() {}
void RSRoundCornerDisplayTest::TearDownTestCase() {}
void RSRoundCornerDisplayTest::SetUp() {}
void RSRoundCornerDisplayTest::TearDown() {}

struct XMLProperty {
    std::string name;
    std::string value;
};

xmlNodePtr CreateNodeWithProperty(const std::string& nodeName, const XMLProperty& property)
{
    auto xmlptr = xmlNewNode(NULL, BAD_CAST(nodeName.c_str()));
    xmlNewProp(xmlptr, BAD_CAST(property.name.c_str()), BAD_CAST(property.value.c_str()));
    return xmlptr;
}

xmlNodePtr CreateNodeWithProperties(const std::string& nodeName, const std::vector<XMLProperty>& properties)
{
    auto xmlptr = xmlNewNode(NULL, BAD_CAST(nodeName.c_str()));
    for (auto& property : properties) {
        xmlNewProp(xmlptr, BAD_CAST(property.name.c_str()), BAD_CAST(property.value.c_str()));
    }
    return xmlptr;
}

xmlNodePtr CreateRCDLayer(const std::string& nodeName, const rs_rcd::RoundCornerLayer& layer)
{
    std::vector<XMLProperty> properties = {
        {rs_rcd::ATTR_FILENAME, layer.fileName},
        {rs_rcd::ATTR_OFFSET_X, std::to_string(layer.offsetX)},
        {rs_rcd::ATTR_OFFSET_Y, std::to_string(layer.offsetY)},
        {rs_rcd::ATTR_BINFILENAME, layer.binFileName},
        {rs_rcd::ATTR_BUFFERSIZE, std::to_string(layer.bufferSize)},
        {rs_rcd::ATTR_CLDWIDTH, std::to_string(layer.cldWidth)},
        {rs_rcd::ATTR_CLDHEIGHT, std::to_string(layer.cldHeight)}
    };
    return CreateNodeWithProperties(nodeName, properties);
}

/*
 * @tc.name: RCDLoadConfigFileTest
 * @tc.desc: Test RSRoundCornerDisplayTest.RCDLoadConfigFileTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RCDLoadConfigFileTest, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    auto res = rcdInstance.LoadConfigFile();
    std::filesystem::path pathCheck(rs_rcd::PATH_CONFIG_FILE);
    if (std::filesystem::exists(pathCheck)) {
        EXPECT_TRUE(res == true);
    } else {
        EXPECT_TRUE(res == false);
    }
}

/*
 * @tc.name: RCDInitTest
 * @tc.desc: Test RSRoundCornerDisplayTest.RCDInitTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RCDInitTest, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    auto res = rcdInstance.Init();
    EXPECT_TRUE(res == true);
}

/*
 * @tc.name: UpdateParameterTest
 * @tc.desc: Test RSRoundCornerDisplayTest.UpdateParameterTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, UpdateParameterTest, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    auto res = rcdInstance.Init();
    EXPECT_TRUE(res == true);

    ScreenRotation curOrientation = ScreenRotation::ROTATION_0;
    rcdInstance.UpdateOrientationStatus(curOrientation);

    uint32_t width = 1344;
    uint32_t height = 2772;
    rcdInstance.UpdateDisplayParameter(width, height);

    std::map<std::string, bool> updateFlag = {
        {"display", true},
        {"notch", true},
        {"orientation", true}
    };
    rcdInstance.UpdateParameter(updateFlag);

    int notchStatus = WINDOW_NOTCH_DEFAULT;
    rcdInstance.UpdateNotchStatus(notchStatus);
    EXPECT_TRUE(rcdInstance.notchStatus_ == notchStatus);
}

/*
 * @tc.name: RSDrawRoundCornerTest
 * @tc.desc: Test RSRoundCornerDisplayTest.RSDrawRoundCornerTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSDrawRoundCornerTest, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    auto res = rcdInstance.Init();
    EXPECT_TRUE(res == true);

    ScreenRotation curOrientation = ScreenRotation::ROTATION_0;
    rcdInstance.UpdateOrientationStatus(curOrientation);

    int notchStatus = WINDOW_NOTCH_DEFAULT;
    rcdInstance.UpdateNotchStatus(notchStatus);
    EXPECT_TRUE(rcdInstance.notchStatus_ == notchStatus);

    uint32_t width = 1344;
    uint32_t height = 2772;
    rcdInstance.UpdateDisplayParameter(width, height);

    std::unique_ptr<Drawing::Canvas> drawingCanvas = std::make_unique<Drawing::Canvas>(width, height);
    std::shared_ptr<RSPaintFilterCanvas> canvas = std::make_shared<RSPaintFilterCanvas>(drawingCanvas.get());
    ASSERT_NE(canvas, nullptr);
    rcdInstance.DrawTopRoundCorner(canvas.get());
    rcdInstance.DrawBottomRoundCorner(canvas.get());
}

/*
 * @tc.name: RSLoadImgTest
 * @tc.desc: Test RSRoundCornerDisplayTest.RSLoadImgTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSLoadImgTest, TestSize.Level1)
{
    std::shared_ptr<Drawing::Image> imgBottomPortrait;
    Drawing::Bitmap bitmapBottomPortrait;
    const char* path = "port_down.png";

    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    auto res = rcdInstance.Init();

    rcdInstance.LoadImg(path, imgBottomPortrait);
    if (imgBottomPortrait == nullptr) {
        std::cout << "RSRoundCornerDisplayTest: current os less rcd source" << std::endl;
        EXPECT_TRUE(res == true);
        return;
    }
    rcdInstance.DecodeBitmap(imgBottomPortrait, bitmapBottomPortrait);

    std::shared_ptr<Drawing::Image> imgNoneImageLoaded = nullptr;
    res = rcdInstance.DecodeBitmap(imgNoneImageLoaded, bitmapBottomPortrait);
    EXPECT_TRUE(res == false);
}

/*
 * @tc.name: RSLoadImgTest001
 * @tc.desc: Test RSRoundCornerDisplayTest.RSLoadImgTest001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSLoadImgTest001, TestSize.Level1)
{
    std::shared_ptr<Drawing::Image> imgBottomPortrait;
    Drawing::Bitmap bitmapBottomPortrait;
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.Init();

    // test waring path
    const char* path1 = "test_waring_path.png";
    bool flag1 = rcdInstance.LoadImg(path1, imgBottomPortrait);
    EXPECT_TRUE(flag1 == false);

    // test image is nullpr
    bool flag2 = rcdInstance.DecodeBitmap(nullptr, bitmapBottomPortrait);
    EXPECT_TRUE(flag2 == false);

    // test correct path, but the file type is incorrect.
    const char* path2 = "config.xml";
    bool flag3 = rcdInstance.LoadImg(path2, imgBottomPortrait);
    EXPECT_TRUE(flag3 == false);
}

/*
 * @tc.name: RSGetSurfaceSourceTest
 * @tc.desc: Test RSRoundCornerDisplayTest.RSGetSurfaceSourceTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSGetSurfaceSourceTest, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.InitOnce();
    auto res = rcdInstance.Init();
    rcdInstance.InitOnce();
    EXPECT_TRUE(res == true);

    uint32_t width = 1344;
    uint32_t height = 2772;
    rcdInstance.UpdateDisplayParameter(width, height);

    rcdInstance.GetTopSurfaceSource();
    rcdInstance.GetBottomSurfaceSource();
}

/*
 * @tc.name: RSChooseResourceTest
 * @tc.desc: Test RSRoundCornerDisplayTest.RSChooseResourceTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSChooseResourceTest, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.Init();

    ScreenRotation curOrientation = ScreenRotation::ROTATION_90;
    rcdInstance.UpdateOrientationStatus(curOrientation);

    int notchStatus = WINDOW_NOTCH_HIDDEN;
    rcdInstance.UpdateNotchStatus(notchStatus);
    EXPECT_TRUE(rcdInstance.notchStatus_ == notchStatus);

    uint32_t width = 1344;
    uint32_t height = 2772;
    rcdInstance.UpdateDisplayParameter(width, height);

    rcdInstance.RcdChooseTopResourceType();

    rcdInstance.RcdChooseRSResource();
    rcdInstance.RcdChooseHardwareResource();
}

/*
 * @tc.name: IsNotchNeedUpdate
 * @tc.desc: Test RSRoundCornerDisplayTest.IsNotchNeedUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, IsNotchNeedUpdate, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.Init();
    rcdInstance.IsNotchNeedUpdate(true);
    bool ischange = rcdInstance.IsNotchNeedUpdate(false);
    EXPECT_EQ(true, ischange);
}

/*
 * @tc.name: RunHardwareTask
 * @tc.desc: Test RSRoundCornerDisplayTest.RunHardwareTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RunHardwareTask, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    bool res = rcdInstance.Init();
    rcdInstance.RunHardwareTask(
        []() {
            std::cout << "do RSRoundCornerDisplayTest.RunHardwareTask1" << std::endl;
        }
    );
    rcdInstance.RunHardwareTask(
        []() {
            std::cout << "do RSRoundCornerDisplayTest.RunHardwareTask2" << std::endl;
        }
    );
    EXPECT_EQ(true, res);
}

/*
 * @tc.name: DrawRoundCorner
 * @tc.desc: Test RSRoundCornerDisplayTest.DrawRoundCorner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, DrawRoundCorner, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    bool res = rcdInstance.Init();
    rcdInstance.DrawTopRoundCorner(nullptr);
    rcdInstance.DrawBottomRoundCorner(nullptr);

    rcdInstance.DrawTopRoundCorner(nullptr);
    rcdInstance.DrawBottomRoundCorner(nullptr);
    EXPECT_EQ(true, res);
}

rs_rcd::ROGSetting* GetRogFromLcdModel(rs_rcd::LCDModel* lcdModel, int& width, int& height)
{
    if (lcdModel == nullptr) {
        return nullptr;
    }
    int widthMate40 = 1344;
    int heightMate40 = 2772;
    int widthMate60 = 1260;
    int heightMate60 = 2720;
    width = widthMate40;
    height = heightMate40;
    rs_rcd::ROGSetting* rog = lcdModel->GetRog(width, height);
    if (rog == nullptr) {
        rog = lcdModel->GetRog(widthMate60, heightMate60);
        width = widthMate60;
        height = heightMate60;
    }
    return rog;
}

/*
 * @tc.name: ProcessRcdSurfaceRenderNode1
 * @tc.desc: Test ProcessRcdSurfaceRenderNode1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, ProcessRcdSurfaceRenderNode1, TestSize.Level1)
{
    // prepare test
    std::shared_ptr<Drawing::Image> imgBottomPortrait;
    Drawing::Bitmap bitmapBottomPortrait;
    const char* path = "port_down.png";

    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.Init();
    rcdInstance.LoadImg(path, imgBottomPortrait);
    if (imgBottomPortrait == nullptr) {
        std::cout << "RSRoundCornerDisplayTest: current os less rcd source" << std::endl;
        return;
    }
    rcdInstance.DecodeBitmap(imgBottomPortrait, bitmapBottomPortrait);

    auto& rcdCfg = RSSingleton<rs_rcd::RCDConfig>::GetInstance();
    rcdCfg.Load(std::string(rs_rcd::PATH_CONFIG_FILE));
    rs_rcd::LCDModel* lcdModel = rcdCfg.GetLcdModel(std::string(rs_rcd::ATTR_DEFAULT));
    if (lcdModel == nullptr) {
        std::cout << "RSRoundCornerDisplayTest: current os less lcdModel source" << std::endl;
        return;
    }
    int width = 0;
    int height = 0;
    rs_rcd::ROGSetting* rog = GetRogFromLcdModel(lcdModel, width, height);
    if (rog == nullptr) {
        std::cout << "RSRoundCornerDisplayTest: current os less rog source" << std::endl;
        return;
    }
    rcdInstance.rog_ = rog;
    rcdInstance.GetTopSurfaceSource();
    rcdInstance.GetBottomSurfaceSource();
    rcdInstance.rog_ = nullptr;

    rs_rcd::RoundCornerHardware hardInfo;
    auto portrait = rog->GetPortrait(std::string(rs_rcd::NODE_PORTRAIT));
    if (portrait == std::nullopt) {
        std::cout << "RSRoundCornerDisplayTest: current os less bottomLayer source" << std::endl;
        return;
    }
    hardInfo.bottomLayer = std::make_shared<rs_rcd::RoundCornerLayer>(portrait->layerDown);
    hardInfo.bottomLayer->layerWidth = width;
    hardInfo.bottomLayer->layerHeight = height;
    hardInfo.bottomLayer->curBitmap = &bitmapBottomPortrait;

    auto bottomSurfaceNode = RSRcdSurfaceRenderNode::Create(0, RCDSurfaceType::BOTTOM);
    HardwareLayerInfo info{};
    bottomSurfaceNode->FillHardwareResource(info, 0, 0);
    auto visitor = std::make_shared<RSRcdRenderVisitor>();
    // test
    visitor->ProcessRcdSurfaceRenderNode(*bottomSurfaceNode, hardInfo.bottomLayer, true);
}

/*
 * @tc.name: ConsumeAndUpdateBufferTest
 * @tc.desc: Test RSRoundCornerDisplayTest.ConsumeAndUpdateBufferTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, ConsumeAndUpdateBufferTest, TestSize.Level1)
{
    std::shared_ptr<RSRcdSurfaceRenderNode> topSurfaceNode =
        std::make_shared<RSRcdSurfaceRenderNode>(0, RCDSurfaceType::TOP);
    std::shared_ptr<RSRcdSurfaceRenderNode> inValidSurfaceNode =
        std::make_shared<RSRcdSurfaceRenderNode>(0, RCDSurfaceType::INVALID);
    rs_rcd::RoundCornerHardware hardInfo{};
    auto visitor = std::make_shared<RSRcdRenderVisitor>();

    // 1 null processor
    std::shared_ptr<RSProcessor> processorPtr = nullptr;
    visitor->SetUniProcessor(processorPtr);
    EXPECT_TRUE(visitor->uniProcessor_ == processorPtr);
    visitor->ProcessRcdSurfaceRenderNode(*topSurfaceNode, hardInfo.bottomLayer, true);
    visitor->ProcessRcdSurfaceRenderNodeMainThread(*topSurfaceNode, true);

    // 2 invalid node
    processorPtr =
        RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::HARDWARE_COMPOSITE);
    visitor->SetUniProcessor(processorPtr);
    visitor->ProcessRcdSurfaceRenderNode(*inValidSurfaceNode, hardInfo.bottomLayer, true);
    visitor->ProcessRcdSurfaceRenderNodeMainThread(*inValidSurfaceNode, true);

    // 3 resource not changed
    visitor->ProcessRcdSurfaceRenderNode(*topSurfaceNode, hardInfo.bottomLayer, true);
    visitor->ProcessRcdSurfaceRenderNodeMainThread(*topSurfaceNode, true);

    // processor node changedTag Ok
    visitor->ProcessRcdSurfaceRenderNode(*topSurfaceNode, hardInfo.bottomLayer, true);
    visitor->ProcessRcdSurfaceRenderNodeMainThread(*topSurfaceNode, true);

    ASSERT_EQ(true, visitor->ConsumeAndUpdateBuffer(*topSurfaceNode));
}

template<typename T1, typename T2, typename T3>
struct TestMsgBus {
    T1 mA;
    T2 mB;
    T3 mC;
    TestMsgBus(T1 a, T2 b, T3 c) : mA{a}, mB{b}, mC{c} {};

    void TestFunc1(T1 a)
    {
        std::cout << "TestMsg Bus Func1:" << sizeof(T1) << "," << &a << std::endl;
        EXPECT_TRUE(mA == a);
    }

    void TestFunc2(T1 a, T2 b)
    {
        std::cout << "TestMsg Bus Func2:" <<
            sizeof(T1) << "," << &a << std::endl <<
            sizeof(T2) << "," << &b << std::endl;
        EXPECT_TRUE(mA == a);
        EXPECT_TRUE(mB == b);
    }

    void TestFunc3(T1 a, T2 b, T3 c)
    {
        std::cout << "TestMsg Bus Func3:" <<
            sizeof(T1) << "," << &a << std::endl <<
            sizeof(T2) << "," << &b << std::endl <<
            sizeof(T3) << "," << &c << std::endl;
        EXPECT_TRUE(mA == a);
        EXPECT_TRUE(mB == b);
        EXPECT_TRUE(mC == c);
    }
};

template<typename T1, typename T2, typename T3>
void TestMsgBusFunc()
{
    std::string topic = "TEST_TOPIC";
    auto& msgBus = RSSingleton<RsMessageBus>::GetInstance();
    using TestMsgBusClass = TestMsgBus<T1, T2, T3>;
    TestMsgBusClass* objPtr = nullptr;
    int num1 = 1;
    int num2 = 2;
    int num3 = 3;
    TestMsgBusClass obj(static_cast<T1>(num1), static_cast<T2>(num2), static_cast<T3>(num3));
    msgBus.RegisterTopic<T1>(topic, objPtr, &TestMsgBusClass::TestFunc1);
    msgBus.RegisterTopic<T1>(topic, &obj, &TestMsgBusClass::TestFunc1);
    EXPECT_TRUE(msgBus.m_map.size() == 1);
    msgBus.SendMsg(topic, static_cast<T1>(num1));
    msgBus.RemoveTopic<T1>(topic);
    EXPECT_TRUE(msgBus.m_map.size() == 0);
    msgBus.RegisterTopic<T1, T2>(topic, &obj, &TestMsgBusClass::TestFunc2);
    EXPECT_TRUE(msgBus.m_map.size() == 1);
    msgBus.SendMsg(topic, static_cast<T1>(num1), static_cast<T2>(num2));
    msgBus.RemoveTopic<T1, T2>(topic);
    EXPECT_TRUE(msgBus.m_map.size() == 0);
    msgBus.RegisterTopic<T1, T2, T3>(topic, &obj, &TestMsgBusClass::TestFunc3);
    EXPECT_TRUE(msgBus.m_map.size() == 1);
    msgBus.SendMsg(topic, static_cast<T1>(num1), static_cast<T2>(num2), static_cast<T3>(num3));
    msgBus.RemoveTopic<T1, T2, T3>(topic);
    EXPECT_TRUE(msgBus.m_map.size() == 0);
}

template<typename T1, typename T2>
void TestMsgBusFunc3()
{
    TestMsgBusFunc<T1, T2, uint8_t>();
    TestMsgBusFunc<T1, T2, uint16_t>();
    TestMsgBusFunc<T1, T2, uint32_t>();
    TestMsgBusFunc<T1, T2, uint64_t>();
    TestMsgBusFunc<T1, T2, int>();
    TestMsgBusFunc<T1, T2, float>();
    TestMsgBusFunc<T1, T2, double>();
}

template<typename T1>
void TestMsgBusFunc2()
{
    TestMsgBusFunc3<T1, uint8_t>();
    TestMsgBusFunc3<T1, uint16_t>();
    TestMsgBusFunc3<T1, uint32_t>();
    TestMsgBusFunc3<T1, uint64_t>();
    TestMsgBusFunc3<T1, int>();
    TestMsgBusFunc3<T1, float>();
    TestMsgBusFunc3<T1, double>();
}

/*
 * @tc.name: MessageBus
 * @tc.desc: Test RSRoundCornerDisplayTest.MessageBus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, MessageBus, TestSize.Level1)
{
    auto& msgBus = RSSingleton<RsMessageBus>::GetInstance();
    msgBus.RemoveTopic("NG_TOPIC");
    TestMsgBusFunc2<uint8_t>();
    TestMsgBusFunc2<uint16_t>();
    TestMsgBusFunc2<uint32_t>();
    TestMsgBusFunc2<uint64_t>();
    TestMsgBusFunc2<int>();
    TestMsgBusFunc2<float>();
    TestMsgBusFunc2<double>();
    EXPECT_TRUE(msgBus.m_map.size() == 0);
}

/*
 * @tc.name: RCDConfig
 * @tc.desc: Test RSRoundCornerDisplayTest.RCDConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RCDConfig, TestSize.Level1)
{
    auto& rcdCfg = RSSingleton<rs_rcd::RCDConfig>::GetInstance();
    rcdCfg.Load(std::string("NG_PATH_CONFIG_FILE"));
    rcdCfg.Load(std::string(rs_rcd::PATH_CONFIG_FILE));
    auto invalidLcd = rcdCfg.GetLcdModel(std::string(""));
    EXPECT_EQ(invalidLcd, nullptr);
    rs_rcd::LCDModel* nullLcdModel = nullptr;
    rcdCfg.lcdModels.push_back(nullLcdModel);
    invalidLcd = rcdCfg.GetLcdModel(std::string("invalideName"));
    EXPECT_EQ(invalidLcd, nullptr);
    rs_rcd::RCDConfig::PrintParseRog(nullptr);
    rs_rcd::ROGSetting rog;
    rs_rcd::RogPortrait rp;
    rs_rcd::RogLandscape rl;
    rog.portraitMap["a"] = rp;
    rog.landscapeMap["b"] = rl;
    rs_rcd::RCDConfig::PrintParseRog(&rog);
}

/*
 * @tc.name: LCDModel
 * @tc.desc: Test RSRoundCornerDisplayTest.LCDModel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, LCDModel, TestSize.Level1)
{
    auto& rcdCfg = RSSingleton<rs_rcd::RCDConfig>::GetInstance();
    rcdCfg.Load(std::string(rs_rcd::PATH_CONFIG_FILE));
    auto defaultLcd = rcdCfg.GetLcdModel(std::string(rs_rcd::ATTR_DEFAULT));
    if (defaultLcd == nullptr) {
        std::cout << "OS less lcdModel resource" << std::endl;
        return;
    }
    rs_rcd::ROGSetting* nullRog = nullptr;
    defaultLcd->rogs.push_back(nullRog);
    defaultLcd->GetRog(0, 0);
    defaultLcd->GetHardwareComposerConfig();
    defaultLcd->GetSideRegionConfig();
    defaultLcd->GetSurfaceConfig();

    xmlNodePtr xmlptr = nullptr;
    auto res = defaultLcd->ReadXmlNode(xmlptr);
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: HardwareComposerConfig
 * @tc.desc: Test RSRoundCornerDisplayTest.HardwareComposerConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, HardwareComposerConfig, TestSize.Level1)
{
    rs_rcd::HardwareComposerConfig cfg;
    xmlNodePtr xmlptr = nullptr;
    bool res = cfg.ReadXmlNode(xmlptr);
    EXPECT_EQ(res, false);
    xmlptr = xmlNewNode(NULL, BAD_CAST(rs_rcd::NODE_HARDWARECOMPOSERCONFIG));
    auto child = xmlNewNode(NULL, BAD_CAST(rs_rcd::NODE_HARDWARECOMPOSER));
    xmlNewProp(child, BAD_CAST(rs_rcd::ATTR_SUPPORT), BAD_CAST("true"));
    xmlAddChild(xmlptr, child);
    res = cfg.ReadXmlNode(xmlptr);
    EXPECT_EQ(res, true);

    if (xmlptr != nullptr) {
        xmlFreeNode(xmlptr);
        xmlptr = nullptr;
    }
    auto ngPtr = CreateNodeWithProperty(std::string("node"), XMLProperty{std::string("a1"), std::string("")});
    rs_rcd::SupportConfig sc = {true, 1};
    EXPECT_EQ(sc.ReadXmlNode(ngPtr, std::string("aa"), std::string("mm")), false);
    if (ngPtr != nullptr) {
        xmlFreeNode(ngPtr);
        ngPtr = nullptr;
    }
}

/*
 * @tc.name: HardwareComposer
 * @tc.desc: Test RSRoundCornerDisplayTest.HardwareComposer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, HardwareComposer, TestSize.Level1)
{
    rs_rcd::HardwareComposer cfg;
    xmlNodePtr xmlptr = nullptr;
    bool res = cfg.ReadXmlNode(xmlptr, "ngAttr");
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: SideRegionConfig
 * @tc.desc: Test RSRoundCornerDisplayTest.SideRegionConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, SideRegionConfig, TestSize.Level1)
{
    rs_rcd::SideRegionConfig cfg;
    xmlNodePtr xmlptr = nullptr;
    bool res = cfg.ReadXmlNode(xmlptr);
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: SurfaceConfig
 * @tc.desc: Test RSRoundCornerDisplayTest.SurfaceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, SurfaceConfig, TestSize.Level1)
{
    rs_rcd::SurfaceConfig cfg;
    xmlNodePtr xmlptr = nullptr;
    bool res = cfg.ReadXmlNode(xmlptr);
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: ROGSetting
 * @tc.desc: Test RSRoundCornerDisplayTest.ROGSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, ROGSetting, TestSize.Level1)
{
    rs_rcd::ROGSetting cfg;
    xmlNodePtr xmlptr = nullptr;
    bool res = cfg.ReadXmlNode(xmlptr);
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: RogLandscape
 * @tc.desc: Test RSRoundCornerDisplayTest.RogLandscape
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RogLandscape, TestSize.Level1)
{
    rs_rcd::RogLandscape cfg;
    xmlNodePtr xmlptr = nullptr;
    bool res = cfg.ReadXmlNode(xmlptr);
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: RogPortrait
 * @tc.desc: Test RSRoundCornerDisplayTest.RogPortrait
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RogPortrait, TestSize.Level1)
{
    rs_rcd::RogPortrait cfg;
    xmlNodePtr xmlptr = nullptr;
    bool res = cfg.ReadXmlNode(xmlptr);
    EXPECT_EQ(res, false);
}

/*
 * @tc.name: RoundCornerLayer
 * @tc.desc: Test RSRoundCornerDisplayTest.RoundCornerLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RoundCornerLayer, TestSize.Level1)
{
    rs_rcd::RoundCornerLayer cfg;
    xmlNodePtr xmlptr = nullptr;
    cfg.ReadXmlNode(xmlptr, {"a", "b"});

    std::vector<std::string> properties = {
        rs_rcd::ATTR_FILENAME,
        rs_rcd::ATTR_OFFSET_X,
        rs_rcd::ATTR_OFFSET_Y,
        rs_rcd::ATTR_BINFILENAME,
        rs_rcd::ATTR_BUFFERSIZE,
        rs_rcd::ATTR_CLDWIDTH,
        rs_rcd::ATTR_CLDHEIGHT
    };

    rs_rcd::RoundCornerLayer cfgData = {
        "test", // fileName
        1, // offsetX
        1, // offsetY
        "test.bin", // binFileName
        10000, // bufferSize
        2, // cldWidth
        2, // cldHeight
        0,
        0,
        nullptr
    };
    auto nodePtr = CreateRCDLayer(std::string("layer"), cfgData);
    cfg.ReadXmlNode(nodePtr, properties);

    EXPECT_EQ(cfg.fileName.compare(cfgData.fileName), int{0});
    EXPECT_EQ(cfg.binFileName.compare(cfgData.binFileName), int{0});
    EXPECT_EQ(cfg.bufferSize, cfgData.bufferSize);
    EXPECT_EQ(cfg.offsetX, cfgData.offsetX);
    EXPECT_EQ(cfg.offsetY, cfgData.offsetY);
    EXPECT_EQ(cfg.cldWidth, cfgData.cldWidth);
    EXPECT_EQ(cfg.cldHeight, cfgData.cldHeight);
    xmlFreeNode(nodePtr);
    nodePtr = nullptr;
}

/*
 * @tc.name: XMLReader
 * @tc.desc: Test RSRoundCornerDisplayTest.XMLReader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, XMLReader, TestSize.Level1)
{
    xmlNodePtr nodePtr = nullptr;
    rs_rcd::XMLReader::ReadAttrStr(nodePtr, std::string("a"));
    rs_rcd::XMLReader::ReadAttrInt(nodePtr, std::string("a"));
    rs_rcd::XMLReader::ReadAttrFloat(nodePtr, std::string("a"));
    rs_rcd::XMLReader::ReadAttrBool(nodePtr, std::string("a"));

    auto attrName = std::string("num");
    auto numPtr = CreateNodeWithProperty(std::string("nodeName"), XMLProperty{attrName, std::string("")});
    EXPECT_TRUE(rs_rcd::XMLReader::ReadAttrInt(numPtr, attrName) == int{0});
    EXPECT_TRUE(rs_rcd::XMLReader::ReadAttrFloat(numPtr, attrName) < 1.0f);
    xmlFreeNode(numPtr);
    numPtr = CreateNodeWithProperty(std::string("nodeName"), XMLProperty{attrName, std::string("2.0")});
    EXPECT_TRUE(rs_rcd::XMLReader::ReadAttrInt(numPtr, attrName) == int{2});
    EXPECT_TRUE(rs_rcd::XMLReader::ReadAttrFloat(numPtr, attrName) > 1.0f);
    xmlFreeNode(numPtr);
    std::vector<std::string> okCase = { "0.0", "0", "123", "1230.0", "8192.0 ", "819200"};
    for (auto& tmpCase : okCase) {
        bool isOk = rs_rcd::XMLReader::RegexMatchNum(tmpCase);
        EXPECT_EQ(isOk, true);
    }

    std::vector<std::string> ngCase = {"a0.0", "0a", "a123", "1230.0c", "a8192.0 "};
    for (auto& tmpCase : ngCase) {
        bool isOk = rs_rcd::XMLReader::RegexMatchNum(tmpCase);
        EXPECT_EQ(isOk, false);
    }
}

/*
 * @tc.name: RcdExtInfo
 * @tc.desc: Test RSRoundCornerDisplayTest.RcdExtInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RcdExtInfo, TestSize.Level1)
{
    RcdExtInfo info;
    info.Clear();
    bool res = info.GetFrameOffsetX() > -1;
    EXPECT_EQ(res, true);
    res = info.GetFrameOffsetY() > -1;
    EXPECT_EQ(res, true);
}

/*
 * @tc.name: RSRcdSurfaceRenderNode
 * @tc.desc: Test RSRoundCornerDisplayTest.RSRcdSurfaceRenderNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSRcdSurfaceRenderNode, TestSize.Level1)
{
    for (int i = 0; i < 2; i++)
    {
        RSRcdSurfaceRenderNode rcdRenderNode(0, static_cast<RCDSurfaceType>(i));
        rcdRenderNode.ClearBufferCache();
        rcdRenderNode.ResetCurrFrameState();
        rcdRenderNode.Reset();

        rcdRenderNode.GetSrcRect();
        rcdRenderNode.GetDstRect();
        rcdRenderNode.IsSurfaceCreated();
        rcdRenderNode.IsBottomSurface();
        rcdRenderNode.IsTopSurface();
        rcdRenderNode.IsInvalidSurface();
        rcdRenderNode.GetFrameOffsetX();
        rcdRenderNode.GetFrameOffsetY();
        rcdRenderNode.GetRSSurface();
        rcdRenderNode.GetHardenBufferRequestConfig();
        auto comsumer = rcdRenderNode.GetConsumerListener();
        rcdRenderNode.CreateSurface(comsumer);
        rcdRenderNode.SetRcdBufferSize(0);
        rcdRenderNode.SetRcdBufferHeight(0);
        rcdRenderNode.SetRcdBufferWidth(0);
        rcdRenderNode.SetHardwareResourceToBuffer();
        rcdRenderNode.PrepareHardwareResourceBuffer(nullptr);
        rs_rcd::RoundCornerLayer layer;
        rcdRenderNode.PrepareHardwareResourceBuffer(std::make_shared<rs_rcd::RoundCornerLayer>(layer));
        uint32_t size = 10;
        rcdRenderNode.SetRcdBufferSize(size);
        auto bufferSize = rcdRenderNode.GetRcdBufferSize();
        EXPECT_EQ(bufferSize, size);

        uint32_t height = 20;
        rcdRenderNode.SetRcdBufferHeight(height);
        auto bufferHeight = rcdRenderNode.GetRcdBufferHeight();
        EXPECT_EQ(bufferHeight, height);

        uint32_t width = 100;
        rcdRenderNode.SetRcdBufferWidth(width);
        auto bufferWidth = rcdRenderNode.GetRcdBufferWidth();
        EXPECT_EQ(bufferWidth, width);
        rcdRenderNode.GetHardenBufferRequestConfig();
        rcdRenderNode.SetHardwareResourceToBuffer();
        rcdRenderNode.PrepareHardwareResourceBuffer(nullptr);
        rcdRenderNode.PrepareHardwareResourceBuffer(std::make_shared<rs_rcd::RoundCornerLayer>(layer));
        width = 0;
        rcdRenderNode.SetRcdBufferWidth(width);
        rcdRenderNode.GetHardenBufferRequestConfig();
        EXPECT_EQ(rcdRenderNode.GetRcdBufferWidth(), width);
        rcdRenderNode.ClearBufferCache();
    }
}

/*
 * @tc.name: RSRcdSurfaceRenderNodeResource
 * @tc.desc: Test RSRoundCornerDisplayTest.RSRcdSurfaceRenderNodeResource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSRcdSurfaceRenderNodeResource, TestSize.Level1)
{
    auto surfaceNodePtr = std::make_shared<RSRcdSurfaceRenderNode>(0, static_cast<RCDSurfaceType>(0));
    RSRcdSurfaceRenderNode rcdRenderNode(0, static_cast<RCDSurfaceType>(0)); // bottom
    auto cldInfo = surfaceNodePtr->GetCldInfo();
    EXPECT_TRUE(cldInfo.cldWidth >= 0);
    EXPECT_TRUE(surfaceNodePtr->GetSurfaceWidth() >= 0);
    EXPECT_TRUE(surfaceNodePtr->GetSurfaceHeight() >= 0);

    sptr<IBufferConsumerListener> listener = new RSRcdRenderListener(surfaceNodePtr);
    surfaceNodePtr->CreateSurface(listener);
    surfaceNodePtr->ClearBufferCache();
    EXPECT_TRUE(surfaceNodePtr->surface_ != nullptr);
}

/*
 * @tc.name: RSRoundCornerDisplayResource
 * @tc.desc: Test RSRoundCornerDisplayTest.RSRoundCornerDisplayResource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSRoundCornerDisplayResource, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.lcdModel_ = nullptr;
    EXPECT_TRUE(rcdInstance.LoadImgsbyResolution(0, 0) == false);

    rcdInstance.hardInfo_.topLayer = std::make_shared<rs_rcd::RoundCornerLayer>();
    rcdInstance.hardInfo_.bottomLayer = std::make_shared<rs_rcd::RoundCornerLayer>();
    rcdInstance.displayWidth_ = 640;
    rcdInstance.displayHeight_ = 480;
    EXPECT_TRUE(rcdInstance.SetHardwareLayerSize());
    rcdInstance.UpdateDisplayParameter(rcdInstance.displayWidth_, rcdInstance.displayHeight_);
    rcdInstance.updateFlag_["display"] = false;
    rcdInstance.UpdateDisplayParameter(0, 0);
    EXPECT_TRUE(rcdInstance.updateFlag_["display"] == false);

    rcdInstance.rog_ = new rs_rcd::ROGSetting();
    rcdInstance.lcdModel_ = new rs_rcd::LCDModel();
    rcdInstance.lcdModel_->rogs.push_back(rcdInstance.rog_);
    EXPECT_TRUE(rcdInstance.GetTopSurfaceSource() == false);
    EXPECT_TRUE(rcdInstance.GetBottomSurfaceSource() == false);
    const int supportTopTag = 3;
    const int supportBottomTag = 6;
    for (int i = 0; i < 8; i++) {
        rcdInstance.supportTopSurface_ = (i & 0x1) > 0;
        rcdInstance.supportHardware_ = (i & 0x02) > 0;
        rcdInstance.supportBottomSurface_ = (i & 0x04) > 0;
        EXPECT_TRUE(rcdInstance.LoadImgsbyResolution(0, 0) !=
            ((i & supportTopTag) == supportTopTag || (i & supportBottomTag) == supportBottomTag));
    }
    rs_rcd::RogPortrait rogPortrait{};
    rcdInstance.rog_->portraitMap[rs_rcd::NODE_PORTRAIT] = rogPortrait;
    EXPECT_TRUE(rcdInstance.GetTopSurfaceSource() == false);
    rs_rcd::RogLandscape rogLand{};
    rcdInstance.rog_->landscapeMap[rs_rcd::NODE_LANDSCAPE] = rogLand;
    rcdInstance.supportHardware_ = false;
    EXPECT_TRUE(rcdInstance.GetTopSurfaceSource() == true);

    rcdInstance.supportTopSurface_ = true;
    rcdInstance.supportHardware_ = true;
    rcdInstance.supportBottomSurface_ = false;
    EXPECT_TRUE(rcdInstance.LoadImgsbyResolution(0, 0) == true);

    rcdInstance.supportBottomSurface_ = true;
    EXPECT_TRUE(rcdInstance.LoadImgsbyResolution(0, 0) == true);
    rcdInstance.UpdateDisplayParameter(0, 0);
    EXPECT_TRUE(rcdInstance.updateFlag_["display"] == true);
    delete rcdInstance.rog_;
    rcdInstance.rog_ = nullptr;
    rcdInstance.lcdModel_->rogs.clear();
    delete rcdInstance.lcdModel_;
    rcdInstance.lcdModel_ = nullptr;
}

/*
 * @tc.name: RSRoundCornerDisplayUpdateHardWare
 * @tc.desc: Test RSRoundCornerDisplayTest.RSRoundCornerDisplayUpdateHardWare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSRoundCornerDisplayUpdateHardWare, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.hardInfo_.resourcePreparing = true;
    rcdInstance.UpdateHardwareResourcePrepared(true);
    EXPECT_TRUE(rcdInstance.hardInfo_.resourcePreparing == false);
    EXPECT_TRUE(rcdInstance.hardInfo_.resourceChanged == false);
    rcdInstance.UpdateHardwareResourcePrepared(true);
    EXPECT_TRUE(rcdInstance.hardInfo_.resourceChanged == false);
}

/*
 * @tc.name: RSRoundCornerDisplayChooseRS
 * @tc.desc: Test RSRoundCornerDisplayTest.RSRoundCornerDisplayChooseRS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSRoundCornerDisplayChooseRS, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    for (int i = 0; i < 4; i++) {
        ShowTopResourceType type = static_cast<ShowTopResourceType>(i);
        rcdInstance.showResourceType_ = type;
        rcdInstance.RcdChooseRSResource();
        EXPECT_TRUE(rcdInstance.curBottom_ == rcdInstance.imgBottomPortrait_);
    }
}

/*
 * @tc.name: RSRoundCornerDisplayDrawOne
 * @tc.desc: Test RSRoundCornerDisplayTest.RSRoundCornerDisplayDrawOne
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSRoundCornerDisplayDrawOne, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.curTop_ = std::make_shared<Drawing::Image>();
    rcdInstance.curBottom_ = std::make_shared<Drawing::Image>();
    auto baseCanvas = std::make_shared<Drawing::Canvas>();
    auto canvas = std::make_shared<RSPaintFilterCanvas>(baseCanvas.get(), 1.0f);
    rcdInstance.DrawTopRoundCorner(canvas.get());
    rcdInstance.DrawBottomRoundCorner(canvas.get());
    rcdInstance.DrawOneRoundCorner(canvas.get(), 3);
    EXPECT_TRUE(canvas.get() != nullptr);
}
/*
 * @tc.name: RcdChooseHardwareResourceTest
 * @tc.desc: Test RSRoundCornerDisplay.RcdChooseHardwareResource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RcdChooseHardwareResourceTest, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RSSymbolAnimationTest RcdChooseHardwareResourceTest start";
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rs_rcd::ROGSetting rog;
    rog.height = 2772;
    rog.width = 1344;
    rcdInstance.rog_ = &rog;

    rcdInstance.showResourceType_ = TOP_PORTRAIT;
    rcdInstance.RcdChooseHardwareResource();

    rcdInstance.showResourceType_ = TOP_HIDDEN;
    rcdInstance.RcdChooseHardwareResource();

    rcdInstance.showResourceType_ = TOP_LADS_ORIT;
    rcdInstance.RcdChooseHardwareResource();

    rcdInstance.showResourceType_ = 4;
    rcdInstance.RcdChooseHardwareResource();
    int type = 4;
    EXPECT_EQ(rcdInstance.showResourceType_, type);

    rs_rcd::RogPortrait rogPortrait{};
    rcdInstance.rog_->portraitMap[rs_rcd::NODE_PORTRAIT] = rogPortrait;
    rs_rcd::RogLandscape rogLand{};
    rcdInstance.rog_->landscapeMap[rs_rcd::NODE_LANDSCAPE] = rogLand;

    rcdInstance.showResourceType_ = TOP_PORTRAIT;
    rcdInstance.RcdChooseHardwareResource();

    rcdInstance.showResourceType_ = TOP_HIDDEN;
    rcdInstance.RcdChooseHardwareResource();

    rcdInstance.showResourceType_ = TOP_LADS_ORIT;
    rcdInstance.RcdChooseHardwareResource();

    rcdInstance.showResourceType_ = 4;
    rcdInstance.RcdChooseHardwareResource();

    EXPECT_EQ(rcdInstance.showResourceType_, type);
    GTEST_LOG_(INFO) << "RSSymbolAnimationTest RcdChooseHardwareResourceTest end";
}

/*
 * @tc.name: UpdateNotchStatusTest
 * @tc.desc: Test RSRoundCornerDisplay.UpdateNotchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, UpdateNotchStatusTest, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.Init();
    rcdInstance.UpdateNotchStatus(WINDOW_NOTCH_DEFAULT);
    // test status is < 0
    int notchStatus = -1;
    rcdInstance.UpdateNotchStatus(notchStatus);
    EXPECT_TRUE(rcdInstance.notchStatus_ == WINDOW_NOTCH_DEFAULT);

    // test status is > 1
    int notchStatusTwo = 2;
    rcdInstance.UpdateNotchStatus(notchStatusTwo);
    EXPECT_TRUE(rcdInstance.notchStatus_ == WINDOW_NOTCH_DEFAULT);
}

/*
 * @tc.name: RcdChooseTopResourceTypeTest
 * @tc.desc: Test RSRoundCornerDisplay.RcdChooseTopResourceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RcdChooseTopResourceTypeTest, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplay>::GetInstance();
    rcdInstance.Init();
    // test curOrientation is INVALID_SCREEN_ROTATION
    ScreenRotation curOrientation = ScreenRotation::INVALID_SCREEN_ROTATION;
    rcdInstance.UpdateOrientationStatus(curOrientation);
    rcdInstance.RcdChooseTopResourceType();
    EXPECT_TRUE(rcdInstance.curOrientation_ == ScreenRotation::INVALID_SCREEN_ROTATION);
    EXPECT_TRUE(rcdInstance.showResourceType_ == TOP_PORTRAIT);

    // test ScreenRotation::ROTATION_180, notchStatus is WINDOW_NOTCH_HIDDEN
    curOrientation = ScreenRotation::ROTATION_180;
    int notchStatus = WINDOW_NOTCH_HIDDEN;
    rcdInstance.UpdateNotchStatus(notchStatus);
    rcdInstance.UpdateOrientationStatus(curOrientation);
    rcdInstance.RcdChooseTopResourceType();
    EXPECT_TRUE(rcdInstance.showResourceType_ == TOP_HIDDEN);

    // test ScreenRotation::ROTATION_180, notchStatus is WINDOW_NOTCH_DEFAULT
    notchStatus = WINDOW_NOTCH_DEFAULT;
    rcdInstance.UpdateNotchStatus(notchStatus);
    rcdInstance.UpdateOrientationStatus(curOrientation);
    rcdInstance.RcdChooseTopResourceType();
    EXPECT_TRUE(rcdInstance.curOrientation_ == ScreenRotation::ROTATION_180);
    EXPECT_TRUE(rcdInstance.showResourceType_ == TOP_PORTRAIT);

    // test ScreenRotation::ROTATION_270, notchStatus is WINDOW_NOTCH_DEFAULT
    curOrientation = ScreenRotation::ROTATION_270;
    rcdInstance.UpdateOrientationStatus(curOrientation);
    rcdInstance.RcdChooseTopResourceType();
    EXPECT_TRUE(rcdInstance.curOrientation_ == ScreenRotation::ROTATION_270);
    EXPECT_TRUE(rcdInstance.showResourceType_ == TOP_PORTRAIT);
}

/*
 * @tc.name: ProcessFillHardwareResource
 * @tc.desc: Test RSRcdSurfaceRenderNode.FillHardwareResource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, ProcessFillHardwareResource, TestSize.Level1)
{
    // prepare test
    std::shared_ptr<RSRcdSurfaceRenderNode> bottomSurfaceNode =
        std::make_shared<RSRcdSurfaceRenderNode>(0, RCDSurfaceType::BOTTOM);
    if (bottomSurfaceNode == nullptr) {
        std::cout << "RSRoundCornerDisplayTest: current os less bottomSurfaceNode source" << std::endl;
        return;
    }

    HardwareLayerInfo info{};
    sptr<SurfaceBufferImpl> surfaceBufferImpl = new SurfaceBufferImpl();
    bottomSurfaceNode->buffer_.buffer = nullptr;
    bool flag1 = bottomSurfaceNode->FillHardwareResource(info, 2, 2);
    bottomSurfaceNode->buffer_.buffer = surfaceBufferImpl;
    EXPECT_TRUE(flag1 == false);

    BufferHandle* bufferHandle = AllocateBufferHandle(64, 128);
    EXPECT_TRUE(bufferHandle != nullptr);
    surfaceBufferImpl->SetBufferHandle(bufferHandle);
    surfaceBufferImpl->handle_->stride = 1;
    surfaceBufferImpl->handle_->size = 64 + 128 + sizeof(BufferHandle);

    bool flag2 = true;
    info.bufferSize = -1;
    flag2 = flag2 && !bottomSurfaceNode->FillHardwareResource(info, 2, 2);
    info.bufferSize = 10000;
    info.cldWidth = -1;
    flag2 = flag2 && !bottomSurfaceNode->FillHardwareResource(info, 2, 2);
    info.cldWidth = 2;
    info.cldHeight = -1;
    flag2 = flag2 && !bottomSurfaceNode->FillHardwareResource(info, 2, 2);
    info.cldHeight = 2;
    flag2 = flag2 && !bottomSurfaceNode->FillHardwareResource(info, -1, 2);
    flag2 = flag2 && !bottomSurfaceNode->FillHardwareResource(info, 2, -1);
    info.pathBin = "";
    EXPECT_TRUE(flag2);

    bool flag3 = true;
    flag3 = flag3 && !bottomSurfaceNode->FillHardwareResource(info, 2, 2);
    std::shared_ptr<uint8_t> buffer = std::make_shared<uint8_t>(10000);
    surfaceBufferImpl->handle_->virAddr = static_cast<void*>(buffer.get());
    surfaceBufferImpl->handle_->stride = -1;
    flag3 = flag3 && !bottomSurfaceNode->FillHardwareResource(info, 2, 2);
    surfaceBufferImpl->handle_->stride = 1;
    surfaceBufferImpl->handle_->size = 0;
    flag3 = flag3 && !bottomSurfaceNode->FillHardwareResource(info, 2, 2);
    EXPECT_TRUE(flag3);

    surfaceBufferImpl->handle_= nullptr;
    FreeBufferHandle(bufferHandle);
}

/*
 * @tc.name: RoundCornerDisplayManager
 * @tc.desc: Test RoundCornerDisplayManager.AddRoundCornerDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RoundCornerDisplayManager_AddRcd, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplayManager>::GetInstance();
    // 1.add and remove rcd module via nodeId
    auto res = rcdInstance.CheckExist(1);
    EXPECT_TRUE(res == false);
    rcdInstance.AddRoundCornerDisplay(1);
    rcdInstance.AddRoundCornerDisplay(1);
    res = rcdInstance.CheckExist(1);
    EXPECT_TRUE(res);
    rcdInstance.RemoveRoundCornerDisplay(0);
    res = rcdInstance.CheckExist(1);
    EXPECT_TRUE(res);
    rcdInstance.RemoveRoundCornerDisplay(1);
    res = rcdInstance.CheckExist(1);
    EXPECT_TRUE(res == false);
    rcdInstance.RemoveRCDResource(1);
    res = rcdInstance.CheckExist(1);
    EXPECT_TRUE(res == false);
}

/*
 * @tc.name: RoundCornerDisplayManager
 * @tc.desc: Test RoundCornerDisplayManager.AddLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RoundCornerDisplayManager_AddLayer, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplayManager>::GetInstance();
    // 1.add layerInfo via renderTarget nodeId
    NodeId id = 1;
    auto top = RoundCornerDisplayManager::RCDLayerType::TOP;

    auto topName = std::string("TopLayer");

    rcdInstance.AddLayer(topName, id, top);
    auto LayerInfo = rcdInstance.GetLayerPair(topName);
    EXPECT_TRUE(LayerInfo.first == id && LayerInfo.second == top);
    rcdInstance.RemoveRCDLayerInfo(id);
    rcdInstance.RemoveRCDResource(id);
    LayerInfo = rcdInstance.GetLayerPair(topName);
    EXPECT_TRUE(LayerInfo.second == RoundCornerDisplayManager::RCDLayerType::INVALID);
}

/*
 * @tc.name: RoundCornerDisplayManager
 * @tc.desc: Test RoundCornerDisplayManager null rcd Case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RoundCornerDisplayManagerNULLRcd, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplayManager>::GetInstance();
    // add layer and NodeId
    NodeId id = 1;
    int status = 1;
    uint32_t w = 1080, h = 1920;
    auto rot = ScreenRotation::ROTATION_90;
    rcdInstance.AddRoundCornerDisplay(id);
    auto res = rcdInstance.CheckExist(id);
    EXPECT_TRUE(res == true);
    rcdInstance.rcdMap_[id] = nullptr;
    rcdInstance.UpdateDisplayParameter(id, w, h);
    res = rcdInstance.CheckExist(id);
    EXPECT_TRUE(res == false);
    rcdInstance.rcdMap_[id] = nullptr;
    rcdInstance.UpdateNotchStatus(id, status);
    res = rcdInstance.CheckExist(id);
    EXPECT_TRUE(res == false);
    rcdInstance.rcdMap_[id] = nullptr;
    rcdInstance.UpdateOrientationStatus(id, rot);
    res = rcdInstance.CheckExist(id);
    EXPECT_TRUE(res == false);
}

/*
 * @tc.name: RoundCornerDisplayManager
 * @tc.desc: Test RoundCornerDisplayManagerUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RoundCornerDisplayManagerUpdate, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplayManager>::GetInstance();
        // add layer and NodeId
    NodeId id = 1;
    int status = 1;
    uint32_t w = 1080, h = 1920;
    auto rot = ScreenRotation::ROTATION_90;
    std::function<void()> task = []() {std::cout << "hardwareComposer RoundCornerDisplayManager Task" << std::endl;};
    // normal flow
    rcdInstance.AddRoundCornerDisplay(id);
    rcdInstance.UpdateDisplayParameter(id, w, h);
    rcdInstance.UpdateNotchStatus(id, status);
    rcdInstance.UpdateOrientationStatus(id, rot);
    auto hardInfo = rcdInstance.GetHardwareInfo(id);
    rcdInstance.RunHardwareTask(id, task);
    auto res = rcdInstance.CheckExist(id);
    EXPECT_TRUE(res == true);
    // no id flow
    rcdInstance.RemoveRoundCornerDisplay(id);
    rcdInstance.UpdateDisplayParameter(id, w, h);
    rcdInstance.UpdateNotchStatus(id, status);
    rcdInstance.UpdateOrientationStatus(id, rot);
    hardInfo = rcdInstance.GetHardwareInfo(id);
    rcdInstance.RunHardwareTask(id, task);
    res = rcdInstance.CheckExist(id);
    EXPECT_TRUE(res == false);
}

/*
 * @tc.name: RoundCornerDisplayManager
 * @tc.desc: Test RoundCornerDisplayManagerDraw
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RoundCornerDisplayManagerDraw, TestSize.Level1)
{
    auto& rcdInstance = RSSingleton<RoundCornerDisplayManager>::GetInstance();
    // add layer and NodeId
    NodeId id = 1;
    auto top = RoundCornerDisplayManager::RCDLayerType::TOP;
    auto bottom = RoundCornerDisplayManager::RCDLayerType::BOTTOM;
    auto topName = std::string("TopLayer");
    auto bottomName = std::string("BottomLayer");
    rcdInstance.AddRoundCornerDisplay(id);
    rcdInstance.AddLayer(topName, id, top);
    rcdInstance.AddLayer(bottomName, id, bottom);
    EXPECT_TRUE(rcdInstance.CheckLayerIsRCD(std::string("InvalidName")) == false);
    EXPECT_TRUE(rcdInstance.CheckLayerIsRCD(topName) == true);
    std::vector<std::string> renderLayersName = {topName, bottomName, std::string("InvalidName")};
    std::vector<std::pair<NodeId, RoundCornerDisplayManager::RCDLayerType>> renderTargetNodeInfoList;
    for (auto& layerName : renderLayersName) {
        auto nodeInfo = rcdInstance.GetLayerPair(layerName);
        renderTargetNodeInfoList.push_back(nodeInfo);
    }
    auto baseCanvas = std::make_shared<Drawing::Canvas>();
    auto canvas = std::make_shared<RSPaintFilterCanvas>(baseCanvas.get(), 1.0f);
    std::function<void()> task = []() {std::cout << "hardwareComposer RoundCornerDisplayManager Task" << std::endl;};
    rcdInstance.DrawRoundCorner(renderTargetNodeInfoList, canvas.get());
    EXPECT_TRUE(rcdInstance.GetRcdEnable() == true);
    for (auto& info : renderTargetNodeInfoList) {
        auto nodeId = info.first;
        auto type = info.second;
        if (type == top) {
            rcdInstance.rcdMap_[nodeId] = nullptr;
        }
        rcdInstance.DrawTopRoundCorner(nodeId, canvas.get());
        rcdInstance.DrawTopRoundCorner(nodeId, canvas.get());
        if (type == bottom) {
            rcdInstance.rcdMap_[nodeId] = nullptr;
        }
        rcdInstance.DrawBottomRoundCorner(nodeId, canvas.get());
        rcdInstance.DrawBottomRoundCorner(nodeId, canvas.get());
        EXPECT_TRUE(rcdInstance.CheckExist(nodeId) == false);
    }
}

/*
 * @tc.name: RSRcdRenderManager
 * @tc.desc: Test RSRcdRenderManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRoundCornerDisplayTest, RSRcdRenderManager, TestSize.Level1)
{
    auto& rcdManagerInstance = RSRcdRenderManager::GetInstance();
    rcdManagerInstance.InitInstance();
    NodeId id = 1;
    EXPECT_TRUE(rcdManagerInstance.GetRcdRenderEnabled() == true);
    auto topLayer = rcdManagerInstance.GetTopSurfaceNode(id);
    EXPECT_TRUE(topLayer == nullptr);
    auto bottomLayer = rcdManagerInstance.GetBottomSurfaceNode(id);
    EXPECT_TRUE(bottomLayer == nullptr);

    RcdProcessInfo info{};
    rcdManagerInstance.DoProcessRenderMainThreadTask(id, info);
    rcdManagerInstance.DoProcessRenderTask(id, info);
    auto topNode = rcdManagerInstance.GetTopRenderNode(id);
    auto bottomNode = rcdManagerInstance.GetTopRenderNode(id);
    RSRenderNodeMap nodeMap;
    EXPECT_TRUE(RSRcdRenderManager::CheckExist(id, nodeMap) == false);

    // to create layerInfo
    std::shared_ptr<Drawing::Bitmap> bitMap = std::make_shared<Drawing::Bitmap>();
    bitMap->Build(896, 1848,
        Drawing::BitmapFormat{Drawing::ColorType::COLORTYPE_RGBA_8888, Drawing::AlphaType::ALPHATYPE_OPAQUE});
    rs_rcd::RoundCornerLayer layerTmp{"top.png", 0, 0, "top.bin", 8112, 2028, 1, 896, 1848, bitMap.get()};
    std::shared_ptr<rs_rcd::RoundCornerLayer> topPtr = std::make_shared<rs_rcd::RoundCornerLayer>(layerTmp);
    auto rsHardwareProcessor =
        RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::HARDWARE_COMPOSITE);
    info = {rsHardwareProcessor, topPtr, topPtr, true};
    rcdManagerInstance.DoProcessRenderMainThreadTask(id, info);
    rcdManagerInstance.DoProcessRenderTask(id, info);
    RSContext context;
    context.nodeMap.renderNodeMap_ = {{id, std::make_shared<RSRenderNode>(id)}};
    rcdManagerInstance.CheckRenderTargetNode(context);
    context.nodeMap.renderNodeMap_ = {{id, std::make_shared<RSRenderNode>(id + 1)}};
    rcdManagerInstance.CheckRenderTargetNode(context);
    rcdManagerInstance.RemoveRcdResource(id);
    context.nodeMap.renderNodeMap_.clear();
    rcdManagerInstance.topSurfaceNodeMap_.clear();
    rcdManagerInstance.bottomSurfaceNodeMap_.clear();
}
} // OHOS::Rosen
