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

#include <filesystem>

#include "drawing_font_collection.h"
#include "drawing_register_font.h"
#include "drawing_text_font_descriptor.h"
#include "font_descriptor_mgr.h"
#include "gtest/gtest.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace {
namespace fs = std::filesystem;

const std::string STYLISH_FONT_CONFIG_FILE = "/system/fonts/visibility_list.json";
const std::string STYLISH_FONT_CONFIG_PROD_FILE = "/sys_prod/fonts/visibility_list.json";
const std::string INSTALLED_FONT_CONFIG_FILE =
    "/data/service/el1/public/for-all-app/fonts/install_fontconfig.json";
}

class OH_Drawing_FontDescriptorTest : public testing::Test {
};

/*
 * @tc.name: OH_Drawing_FontDescriptorTest001
 * @tc.desc: test for the fontDescriptor.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest001, TestSize.Level1)
{
    OH_Drawing_FontDescriptor* descArr = OH_Drawing_MatchFontDescriptors(nullptr, nullptr);
    EXPECT_EQ(descArr, nullptr);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest002
 * @tc.desc: test for the fontDescriptor.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest002, TestSize.Level1)
{
    OH_Drawing_FontDescriptor* desc = OH_Drawing_CreateFontDescriptor();
    size_t num = 0;
    OH_Drawing_FontDescriptor* descArr = OH_Drawing_MatchFontDescriptors(desc, &num);
    OH_Drawing_DestroyFontDescriptor(desc);
    EXPECT_NE(descArr, nullptr);
    EXPECT_NE(num, 0);
    OH_Drawing_DestroyFontDescriptors(descArr, num);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest003
 * @tc.desc: test for the fontDescriptor.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest003, TestSize.Level1)
{
    OH_Drawing_FontDescriptor* desc = OH_Drawing_CreateFontDescriptor();
    desc->weight = -1;
    size_t num = 0;
    OH_Drawing_FontDescriptor* descArr = OH_Drawing_MatchFontDescriptors(desc, &num);
    OH_Drawing_DestroyFontDescriptor(desc);
    EXPECT_EQ(descArr, nullptr);
    EXPECT_EQ(num, 0);
    OH_Drawing_DestroyFontDescriptors(descArr, num);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest004
 * @tc.desc: test for the fontDescriptor.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest004, TestSize.Level1)
{
    OH_Drawing_FontDescriptor* desc = OH_Drawing_CreateFontDescriptor();
    char* fontFamily = strdup("HarmonyOS Sans");
    desc->fontFamily = fontFamily;
    size_t num = 0;
    OH_Drawing_FontDescriptor* descArr = OH_Drawing_MatchFontDescriptors(desc, &num);
    ASSERT_NE(descArr, nullptr);
    EXPECT_LE(1, num);
    EXPECT_STREQ(descArr[0].fontFamily, fontFamily);
    OH_Drawing_DestroyFontDescriptors(descArr, num);
    free(fontFamily);

    fontFamily = strdup("HarmonyOS Sans Condensed");
    desc->fontFamily = fontFamily;
    descArr = OH_Drawing_MatchFontDescriptors(desc, &num);
    OH_Drawing_DestroyFontDescriptor(desc);
    ASSERT_NE(descArr, nullptr);
    EXPECT_EQ(num, 1);
    EXPECT_STREQ(descArr[0].fontFamily, fontFamily);
    OH_Drawing_DestroyFontDescriptors(descArr, num);
    free(fontFamily);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest005
 * @tc.desc: test for the fontDescriptor.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest005, TestSize.Level1)
{
    OH_Drawing_FontDescriptor* desc = OH_Drawing_CreateFontDescriptor();
    char* fontFamily = strdup("HarmonyOS Sans");
    desc->fontFamily = fontFamily;
    desc->weight = 400;

    size_t num = 0;
    OH_Drawing_FontDescriptor* descArr = OH_Drawing_MatchFontDescriptors(desc, &num);
    OH_Drawing_DestroyFontDescriptor(desc);
    ASSERT_NE(descArr, nullptr);
    EXPECT_LE(1, num);
    EXPECT_STREQ(descArr[0].fontFamily, fontFamily);
    EXPECT_EQ(descArr[0].weight, 400);
    OH_Drawing_DestroyFontDescriptors(descArr, num);
    free(fontFamily);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest006
 * @tc.desc: test for abnormal parameters when obtaining the font list and obtaining the FontDescriptor by fullName.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest006, TestSize.Level1)
{
    OH_Drawing_SystemFontType fontType = OH_Drawing_SystemFontType(0b10000);
    OH_Drawing_Array *fontList = OH_Drawing_GetSystemFontFullNamesByType(fontType);
    EXPECT_EQ(fontList, nullptr);

    OH_Drawing_FontDescriptor *descriptor = OH_Drawing_GetFontDescriptorByFullName(nullptr, fontType);
    EXPECT_EQ(descriptor, nullptr);

    // The array TTF_FULLNAME represents the UTF-16 encoded version of a non-existent font full name "你好openharmony".
    const uint8_t TTF_FULLNAME[] = {
        0x4F, 0x60,
        0x59, 0x7D,
        0x00, 0x6F,
        0x00, 0x70,
        0x00, 0x65,
        0x00, 0x6E,
        0x00, 0x68,
        0x00, 0x61,
        0x00, 0x72,
        0x00, 0x6D,
        0x00, 0x6F,
        0x00, 0x6E,
        0x00, 0x79
    };
    OH_Drawing_String drawingString;
    drawingString.strData = const_cast<uint8_t*>(TTF_FULLNAME);
    drawingString.strLen = sizeof(TTF_FULLNAME);
    OH_Drawing_FontDescriptor *descriptor1 =
        OH_Drawing_GetFontDescriptorByFullName(&drawingString, OH_Drawing_SystemFontType::ALL);
    EXPECT_EQ(descriptor1, nullptr);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest007
 * @tc.desc: test for obtaining the array of installed fonts.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest007, TestSize.Level1)
{
    if (!fs::exists(INSTALLED_FONT_CONFIG_FILE)) {
        return;
    }
    OH_Drawing_SystemFontType fontType = OH_Drawing_SystemFontType::INSTALLED;
    OH_Drawing_Array *fontList = OH_Drawing_GetSystemFontFullNamesByType(fontType);
    ASSERT_NE(fontList, nullptr);
    size_t size = OH_Drawing_GetDrawingArraySize(fontList);
    EXPECT_NE(size, 0);
    for (size_t i = 0; i < size; i++) {
        const OH_Drawing_String *fontFullName = OH_Drawing_GetSystemFontFullNameByIndex(fontList, i);
        EXPECT_NE(fontFullName, nullptr);
        OH_Drawing_FontDescriptor *descriptor = OH_Drawing_GetFontDescriptorByFullName(fontFullName, fontType);
        EXPECT_NE(descriptor, nullptr);
        OH_Drawing_DestroyFontDescriptor(descriptor);
    }
    OH_Drawing_DestroySystemFontFullNames(fontList);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest008
 * @tc.desc: test for obtaining the array of stylish fonts.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest008, TestSize.Level1)
{
    if (!fs::exists(STYLISH_FONT_CONFIG_FILE) && !fs::exists(STYLISH_FONT_CONFIG_PROD_FILE)) {
        return;
    }
    OH_Drawing_SystemFontType fontType = OH_Drawing_SystemFontType::STYLISH;
    OH_Drawing_Array *fontList = OH_Drawing_GetSystemFontFullNamesByType(fontType);
    ASSERT_NE(fontList, nullptr);
    size_t size = OH_Drawing_GetDrawingArraySize(fontList);
    EXPECT_NE(size, 0);
    for (size_t i = 0; i < size; i++) {
        const OH_Drawing_String *fontFullName = OH_Drawing_GetSystemFontFullNameByIndex(fontList, i);
        EXPECT_NE(fontFullName, nullptr);
        OH_Drawing_FontDescriptor *descriptor = OH_Drawing_GetFontDescriptorByFullName(fontFullName, fontType);
        EXPECT_NE(descriptor, nullptr);
        OH_Drawing_DestroyFontDescriptor(descriptor);
    }
    OH_Drawing_DestroySystemFontFullNames(fontList);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest009
 * @tc.desc: test for obtaining the array of system generic fonts.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest009, TestSize.Level1)
{
    OH_Drawing_SystemFontType fontType = OH_Drawing_SystemFontType::GENERIC;
    OH_Drawing_Array *fontList = OH_Drawing_GetSystemFontFullNamesByType(fontType);
    ASSERT_NE(fontList, nullptr);
    size_t size = OH_Drawing_GetDrawingArraySize(fontList);
    EXPECT_NE(size, 0);
    for (size_t i = 0; i < size; i++) {
        const OH_Drawing_String *fontFullName = OH_Drawing_GetSystemFontFullNameByIndex(fontList, i);
        EXPECT_NE(fontFullName, nullptr);
        OH_Drawing_FontDescriptor *descriptor = OH_Drawing_GetFontDescriptorByFullName(fontFullName, fontType);
        EXPECT_NE(descriptor, nullptr);
        OH_Drawing_DestroyFontDescriptor(descriptor);
    }
    OH_Drawing_DestroySystemFontFullNames(fontList);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest010
 * @tc.desc: test for obtaining the list of composite fonts.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest010, TestSize.Level1)
{
    if (!fs::exists(STYLISH_FONT_CONFIG_FILE) && !fs::exists(STYLISH_FONT_CONFIG_PROD_FILE) &&
        !fs::exists(INSTALLED_FONT_CONFIG_FILE)) {
        return;
    }
    OH_Drawing_SystemFontType fontType = OH_Drawing_SystemFontType(INSTALLED | STYLISH);
    OH_Drawing_Array *fontList = OH_Drawing_GetSystemFontFullNamesByType(fontType);
    ASSERT_NE(fontList, nullptr);
    size_t size = OH_Drawing_GetDrawingArraySize(fontList);
    EXPECT_NE(size, 0);
    for (size_t i = 0; i < size; i++) {
        const OH_Drawing_String *fontFullName = OH_Drawing_GetSystemFontFullNameByIndex(fontList, i);
        EXPECT_NE(fontFullName, nullptr);
        OH_Drawing_FontDescriptor *descriptor = OH_Drawing_GetFontDescriptorByFullName(fontFullName, fontType);
        EXPECT_NE(descriptor, nullptr);
        OH_Drawing_DestroyFontDescriptor(descriptor);
    }
    OH_Drawing_DestroySystemFontFullNames(fontList);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest011
 * @tc.desc: test for obtaining the list of composite fonts that include "ALL".
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest011, TestSize.Level1)
{
    OH_Drawing_SystemFontType fontType = OH_Drawing_SystemFontType(ALL | STYLISH);
    OH_Drawing_Array *fontList = OH_Drawing_GetSystemFontFullNamesByType(fontType);
    ASSERT_NE(fontList, nullptr);
    size_t size = OH_Drawing_GetDrawingArraySize(fontList);
    EXPECT_NE(size, 0);
    for (size_t i = 0; i < size; i++) {
        const OH_Drawing_String *fontFullName = OH_Drawing_GetSystemFontFullNameByIndex(fontList, i);
        EXPECT_NE(fontFullName, nullptr);
        OH_Drawing_FontDescriptor *descriptor = OH_Drawing_GetFontDescriptorByFullName(fontFullName, fontType);
        EXPECT_NE(descriptor, nullptr);
        OH_Drawing_DestroyFontDescriptor(descriptor);
    }
    OH_Drawing_DestroySystemFontFullNames(fontList);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest012
 * @tc.desc: test for abnormal parameters when obtaining the fullName by index and releasing array memory.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest012, TestSize.Level1)
{
    OH_Drawing_SystemFontType fontType = OH_Drawing_SystemFontType::GENERIC;
    OH_Drawing_Array *fontList = OH_Drawing_GetSystemFontFullNamesByType(fontType);
    ASSERT_NE(fontList, nullptr);
    const OH_Drawing_String* fullName = OH_Drawing_GetSystemFontFullNameByIndex(fontList, 500);
    EXPECT_EQ(fullName, nullptr);
    OH_Drawing_DestroySystemFontFullNames(fontList);

    const OH_Drawing_String* fullName1 = OH_Drawing_GetSystemFontFullNameByIndex(nullptr, 0);
    EXPECT_EQ(fullName1, nullptr);

    const OH_Drawing_String* fullName2 = OH_Drawing_GetSystemFontFullNameByIndex(nullptr, 500);
    EXPECT_EQ(fullName2, nullptr);

    OH_Drawing_DestroySystemFontFullNames(nullptr);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest013
 * @tc.desc: test for obtaining the list of composite fonts that include "ALL".
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest013, TestSize.Level1)
{
    OH_Drawing_FontCollection *fc = OH_Drawing_CreateSharedFontCollection();
    const char* fontFamily = "FTToken";
    const char* fontPath = "/system/fonts/FTToken.ttf";
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);

    OH_Drawing_Array *ttfs = OH_Drawing_GetSystemFontFullNamesByType(ALL);
    size_t num = OH_Drawing_GetDrawingArraySize(ttfs);
    EXPECT_EQ(num, 142);
    FontDescriptorMgrInstance.ClearFontFileCache();
    OH_Drawing_DestroyFontCollection(fc);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest014
 * @tc.desc: test for registering a font once and query it.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest014, TestSize.Level1)
{
    OH_Drawing_FontCollection *fc = OH_Drawing_CreateSharedFontCollection();
    const char* fontFamily = "FTToken";
    const char* fontPath = "/system/fonts/FTToken.ttf";
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);

    OH_Drawing_Array *ttfs = OH_Drawing_GetSystemFontFullNamesByType(CUSTOMIZED);
    size_t num = OH_Drawing_GetDrawingArraySize(ttfs);
    EXPECT_EQ(num, 1);
    for (size_t i = 0; i < num; i++) {
        const OH_Drawing_String *fullName = OH_Drawing_GetSystemFontFullNameByIndex(ttfs, i);
        OH_Drawing_FontDescriptor *fd = OH_Drawing_GetFontDescriptorByFullName(fullName, CUSTOMIZED);
        ASSERT_STREQ(fd->fullName, "FTToken");
    }
    FontDescriptorMgrInstance.ClearFontFileCache();
    OH_Drawing_DestroyFontCollection(fc);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest015
 * @tc.desc: test for registering a font five times and query it.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest015, TestSize.Level1)
{
    OH_Drawing_FontCollection *fc = OH_Drawing_CreateSharedFontCollection();
    const char* fontFamily = "FTToken";
    const char* fontPath = "/system/fonts/FTToken.ttf";
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);

    OH_Drawing_Array *ttfs = OH_Drawing_GetSystemFontFullNamesByType(CUSTOMIZED);
    size_t num = OH_Drawing_GetDrawingArraySize(ttfs);
    EXPECT_EQ(num, 1);
    for (size_t i = 0; i < num; i++) {
        const OH_Drawing_String *fullName = OH_Drawing_GetSystemFontFullNameByIndex(ttfs, i);
        OH_Drawing_FontDescriptor *fd = OH_Drawing_GetFontDescriptorByFullName(fullName, CUSTOMIZED);
        ASSERT_STREQ(fd->fullName, "FTToken");
    }
    FontDescriptorMgrInstance.ClearFontFileCache();
    OH_Drawing_DestroyFontCollection(fc);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest016
 * @tc.desc: test for registering a TTC font and query it.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest016, TestSize.Level1)
{
    OH_Drawing_FontCollection *fc = OH_Drawing_CreateSharedFontCollection();
    const char* fontFamily = "NotoSansCJKjp-Regular-Alphabetic";
    const char* fontPath = "/system/fonts/NotoSansCJK-Regular.ttc";
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);

    OH_Drawing_Array *ttfs = OH_Drawing_GetSystemFontFullNamesByType(CUSTOMIZED);
    size_t num = OH_Drawing_GetDrawingArraySize(ttfs);
    EXPECT_EQ(num, 1);
    for (size_t i = 0; i < num; i++) {
        const OH_Drawing_String *fullName = OH_Drawing_GetSystemFontFullNameByIndex(ttfs, i);
        OH_Drawing_FontDescriptor *fd = OH_Drawing_GetFontDescriptorByFullName(fullName, CUSTOMIZED);
        ASSERT_STREQ(fd->fullName, "Noto Sans CJK JP");
    }
    FontDescriptorMgrInstance.ClearFontFileCache();
    OH_Drawing_DestroyFontCollection(fc);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest017
 * @tc.desc: test for registering a OTF font and query it.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest017, TestSize.Level1)
{
    OH_Drawing_FontCollection *fc = OH_Drawing_CreateSharedFontCollection();
    const char* fontFamily = "Birch std";
    const char* fontPath = "/system/fonts/Birchstd.otf";
    if (!fs::exists(fontPath)) {
        return;
    }
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);

    OH_Drawing_Array *ttfs = OH_Drawing_GetSystemFontFullNamesByType(CUSTOMIZED);
    size_t num = OH_Drawing_GetDrawingArraySize(ttfs);
    EXPECT_EQ(num, 1);
    for (size_t i = 0; i < num; i++) {
        const OH_Drawing_String *fullName = OH_Drawing_GetSystemFontFullNameByIndex(ttfs, i);
        OH_Drawing_FontDescriptor *fd = OH_Drawing_GetFontDescriptorByFullName(fullName, CUSTOMIZED);
        ASSERT_STREQ(fd->fullName, "Birch std");
    }
    FontDescriptorMgrInstance.ClearFontFileCache();
    OH_Drawing_DestroyFontCollection(fc);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest018
 * @tc.desc: test for registering failed.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest018, TestSize.Level1)
{
    OH_Drawing_FontCollection *fc = OH_Drawing_CreateSharedFontCollection();
    const char* fontFamily = "xxxxxxx";
    const char* fontPath = "/system/fonts/xxxxxxx.ttf";
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);

    OH_Drawing_Array *ttfs = OH_Drawing_GetSystemFontFullNamesByType(CUSTOMIZED);
    size_t num = OH_Drawing_GetDrawingArraySize(ttfs);
    EXPECT_EQ(num, 0);
    FontDescriptorMgrInstance.ClearFontFileCache();
    OH_Drawing_DestroyFontCollection(fc);
}

/*
 * @tc.name: OH_Drawing_FontDescriptorTest019
 * @tc.desc: test for registering a font with a local fontCollection.
 * @tc.type: FUNC
 */
HWTEST_F(OH_Drawing_FontDescriptorTest, OH_Drawing_FontDescriptorTest019, TestSize.Level1)
{
    OH_Drawing_FontCollection *fc = OH_Drawing_CreateFontCollection();
    const char* fontFamily = "FTToken";
    const char* fontPath = "/system/fonts/FTToken.ttf";
    OH_Drawing_RegisterFont(fc, fontFamily, fontPath);

    OH_Drawing_Array *ttfs = OH_Drawing_GetSystemFontFullNamesByType(CUSTOMIZED);
    size_t num = OH_Drawing_GetDrawingArraySize(ttfs);
    EXPECT_EQ(num, 1);
    for (size_t i = 0; i < num; i++) {
        const OH_Drawing_String *fullName = OH_Drawing_GetSystemFontFullNameByIndex(ttfs, i);
        OH_Drawing_FontDescriptor *fd = OH_Drawing_GetFontDescriptorByFullName(fullName, CUSTOMIZED);
        ASSERT_STREQ(fd->fullName, "FTToken");
    }

    OH_Drawing_TypographyStyle *typoStyle = OH_Drawing_CreateTypographyStyle();
    OH_Drawing_CreateTypographyHandler(typoStyle, fc);
    OH_Drawing_Array *ttfs1 = OH_Drawing_GetSystemFontFullNamesByType(CUSTOMIZED);
    size_t num1 = OH_Drawing_GetDrawingArraySize(ttfs1);
    EXPECT_EQ(num1, 0);
    FontDescriptorMgrInstance.ClearFontFileCache();
    OH_Drawing_DestroyFontCollection(fc);
}
}