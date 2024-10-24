/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "font_config.h"
#include "font_parser.h"
#include "texgine/utils/exlog.h"
#include "cmap_table_parser.h"
#include "name_table_parser.h"
#include "post_table_parser.h"
#include "ranges.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace TextEngine {
static const std::string FILE_NAME = "/system/fonts/visibility_list.json";

class FontParserTest : public testing::Test {
};

class MockCmapTableParser : public CmapTableParser {
public:
    MockCmapTableParser() {}
    MOCK_METHOD0(Dump, void());
};

std::vector<std::string> GetFontSet(const char* fname)
{
    FontConfig fontConfig(fname);
    return fontConfig.GetFontSet();
}

void ShowVisibilityFonts(std::vector<FontParser::FontDescriptor>& visibilityFonts)
{
    for (auto &it : visibilityFonts) {
        LOGSO_FUNC_LINE(INFO) << "\n fontFamily: " << it.fontFamily
                              << "\n fontSubfamily: " << it.fontSubfamily
                              << "\n fullName: " << it.fullName
                              << "\n italic: " << it.italic
                              << "\n monoSpace: " << it.monoSpace
                              << "\n path: " << it.path
                              << "\n postScriptName: " << it.postScriptName
                              << "\n symbolic: " << it.symbolic
                              << "\n weight: " << it.weight
                              << "\n width: " << it.width;
    }
}

/**
 * @tc.name: FontParserTest1
 * @tc.desc: test get fontSet file parser
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, FontParserTest1, TestSize.Level1)
{
    auto fontSet1 = GetFontSet(nullptr);
    EXPECT_EQ(fontSet1.size(), 0);

    std::ifstream fileStream(FILE_NAME.c_str());
    if (fileStream.is_open()) {
        auto fontSet2 = GetFontSet(FILE_NAME.c_str());
        EXPECT_NE(fontSet2.size(), 0);
        fileStream.close();
    } else {
        auto fontSet2 = GetFontSet(FILE_NAME.c_str());
        EXPECT_EQ(fontSet2.size(), 0);
    }
}

/**
 * @tc.name: FontParserTest2
 * @tc.desc: test font file parser
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, FontParserTest2, TestSize.Level1)
{
    FontParser fontParser;
    auto visibilityFonts = fontParser.GetVisibilityFonts();
    fontParser.GetVisibilityFontByName("Noto Sans Regular");
    std::ifstream fileStream(FILE_NAME.c_str());
    if (fileStream.is_open()) {
        EXPECT_NE(visibilityFonts.size(), 0);
        ShowVisibilityFonts(visibilityFonts);
        fileStream.close();
    } else {
        EXPECT_EQ(visibilityFonts.size(), 0);
    }
}

/**
 * @tc.name: FontParserTest3
 * @tc.desc: test font file parser
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, FontParserTest3, TestSize.Level1)
{
    FontParser fontParser;
    std::unique_ptr<FontParser::FontDescriptor> font =
        fontParser.GetVisibilityFontByName("Noto Sans Regular");
}

/**
 * @tc.name: FontConfigTest1
 * @tc.desc: test font file parser
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, FontConfigTest1, TestSize.Level1)
{
    FontConfigJson fontConfigJson;
    EXPECT_EQ(fontConfigJson.ParseFile(), 0);
    fontConfigJson.Dump();
}

/**
 * @tc.name: FontConfigTest2
 * @tc.desc: test font file parser
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, FontConfigTest2, TestSize.Level1)
{
    FontConfigJson fontConfigJson;
    EXPECT_EQ(fontConfigJson.ParseFontFileMap(), 0);
    fontConfigJson.Dump();
}

/**
 * @tc.name: CmapTableParserTest1
 * @tc.desc: opentype parser test
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, CmapTableParserTest1, TestSize.Level1)
{
    MockCmapTableParser mockCmapTableParser;
    CmapTableParser cmapTableParser_default;
    CmapTableParser cmapTableParser("test data", 9);
    struct NameRecord nameRecord;
    struct NameTable nameTable;
    nameRecord.encodingId = nameTable.count;
    EXPECT_EQ(CmapTableParser::Parse(nullptr, 0), nullptr);
    EXPECT_CALL(mockCmapTableParser, Dump()).Times(1);
    mockCmapTableParser.Dump();
}

/**
 * @tc.name: NameTableParserTest1
 * @tc.desc: opentype parser test
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, NameTableParserTest1, TestSize.Level1)
{
    NameTableParser nameTableParser(nullptr, 0);
    struct NameRecord nameRecord;
    struct NameTable nameTable;
    nameRecord.encodingId = nameTable.count;
    EXPECT_EQ(NameTableParser::Parse(nullptr, 0), nullptr);
    nameTableParser.Dump();
}

/**
 * @tc.name: NameTableParserTest2
 * @tc.desc: opentype parser test
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, NameTableParserTest2, TestSize.Level1)
{
    auto typeface = Drawing::Typeface::MakeDefault();
    if (typeface == nullptr) {
        LOGSO_FUNC_LINE(ERROR) << "typeface is nullptr";
        return;
    }
    auto tag = HB_TAG('n', 'a', 'm', 'e');
    auto size = typeface->GetTableSize(tag);
    if (size <= 0) {
        LOGSO_FUNC_LINE(ERROR) << "haven't name";
        return ;
    }
    std::unique_ptr<char[]> tableData = nullptr;
    tableData = std::make_unique<char[]>(size);
    auto retTableData = typeface->GetTableData(tag, 0, size, tableData.get());
    if (size != retTableData) {
        LOGSO_FUNC_LINE(ERROR) << "get table data failed size:" << size << ",ret:" << retTableData;
        return ;
    }
    hb_blob_t* hblob = nullptr;
    hblob = hb_blob_create(
            reinterpret_cast<const char *>(tableData.get()), size, HB_MEMORY_MODE_WRITABLE, tableData.get(), nullptr);
    if (hblob == nullptr) {
        LOGSO_FUNC_LINE(ERROR) << "hblob is nullptr";
        return ;
    }
    const char* data_ = nullptr;
    unsigned int length_ = 0;
    data_ = hb_blob_get_data(hblob, nullptr);
    length_ = hb_blob_get_length(hblob);
    auto parseName = std::make_shared<NameTableParser>(data_, length_);
    auto nameTable = parseName->Parse(data_, length_);
    parseName->Dump();
    hb_blob_destroy(hblob);
    EXPECT_NE(nameTable, nullptr);
}

/**
 * @tc.name: PostTableParserTest1
 * @tc.desc: opentype parser test
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, PostTableParserTest1, TestSize.Level1)
{
    PostTableParser postTableParser("test data", 9);
    struct PostTable postTable;
    postTable.underlinePosition = postTable.underlineThickness;
    EXPECT_EQ(PostTableParser::Parse(nullptr, 0), nullptr);
    postTableParser.Dump();
}

/**
 * @tc.name: OpenTypeBasicTypeTest1
 * @tc.desc: opentype parser test
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, OpenTypeBasicTypeTest1, TestSize.Level1)
{
    char test[4] = {'a', 'b', 'c', 'd'};
    struct OpenTypeBasicType::Tag tag;
    tag.Get();
    struct OpenTypeBasicType::Int16 int16;
    int16.Get();
    struct OpenTypeBasicType::Uint16 uint16;
    struct OpenTypeBasicType::Int32 int32;
    int32.Get();
    struct OpenTypeBasicType::Uint32 uint32;
    struct OpenTypeBasicType::Fixed fixed;
    std::copy(std::begin(test), std::end(test), std::begin(tag.tags));
    int16.data = (int16_t)uint16.data;
    fixed.data.data = int32.data = (int32_t)uint32.data;
}

/**
 * @tc.name: RangesTest1
 * @tc.desc: opentype parser test
 * @tc.type:FUNC
 */
HWTEST_F(FontParserTest, RangesTest1, TestSize.Level1)
{
    Ranges ranges;
    struct Ranges::Range range = { 0, 2, 1 };
    ranges.AddRange(range);
    struct Ranges::Range range2 = { 4, 5, 2 };
    ranges.AddRange(range2);
    EXPECT_EQ(ranges.GetGlyphId(3), Ranges::INVALID_GLYPH_ID);
    EXPECT_EQ(ranges.GetGlyphId(0), 1);
    EXPECT_EQ(ranges.GetGlyphId(4), 6);
    ranges.Dump();
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
