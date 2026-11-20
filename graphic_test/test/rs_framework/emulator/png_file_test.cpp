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

#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

#include "rs_graphic_test_file.h"
#include "rs_graphic_test_png.h"

namespace OHOS {
namespace Rosen {
namespace {

class PngFileTest : public testing::Test {
protected:
    void SetUp() override
    {
        std::string error;
        ASSERT_TRUE(EnsureDirectory(root_, &error)) << error;
        directory_ = root_;
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(directory_, error);
    }

    std::string Path(const std::string& name) const
    {
        return directory_ + "/" + name;
    }

    static void WriteBigEndian(std::string& data, size_t offset, uint32_t value)
    {
        data[offset] = static_cast<char>(value >> 24);
        data[offset + 1] = static_cast<char>(value >> 16);
        data[offset + 2] = static_cast<char>(value >> 8);
        data[offset + 3] = static_cast<char>(value);
    }

    static std::string Header(uint32_t width = 2, uint32_t height = 3, uint8_t colorType = 6)
    {
        std::string data(33, '\0');
        const unsigned char signature[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
        for (size_t index = 0; index < sizeof(signature); index++) {
            data[index] = static_cast<char>(signature[index]);
        }
        data.replace(12, 4, "IHDR");
        WriteBigEndian(data, 16, width);
        WriteBigEndian(data, 20, height);
        data[24] = 8;
        data[25] = static_cast<char>(colorType);
        data[26] = 0;
        data[27] = 0;
        data[28] = 0;
        return data;
    }

    void Create(const std::string& name, const std::string& content)
    {
        std::string error;
        ASSERT_TRUE(WriteTextFileAtomic(Path(name), content, &error)) << error;
    }

private:
    std::string root_ = (std::filesystem::temp_directory_path() / "rs-png-file-test").string();
    std::string directory_;
};

TEST_F(PngFileTest, ReadsRgbaHeaderSizeAndHash)
{
    Create("valid.png", Header());
    PngFileInfo info;
    std::string error;
    ASSERT_TRUE(ReadPngFileHeader(Path("valid.png"), info, error)) << error;
    EXPECT_EQ(info.width, 2u);
    EXPECT_EQ(info.height, 3u);
    EXPECT_EQ(info.channels, 4u);
    EXPECT_EQ(info.size, 33u);
}

TEST_F(PngFileTest, ReadsRgbHeader)
{
    Create("rgb.png", Header(4, 5, 2));
    PngFileInfo info;
    std::string error;
    ASSERT_TRUE(ReadPngFileHeader(Path("rgb.png"), info, error)) << error;
    EXPECT_EQ(info.channels, 3u);
}

TEST_F(PngFileTest, RejectsTruncatedHeader)
{
    Create("short.png", "short");
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(ReadPngFileHeader(Path("short.png"), info, error));
    EXPECT_FALSE(error.empty());
}

TEST_F(PngFileTest, RejectsInvalidSignature)
{
    auto data = Header();
    data[1] = 'X';
    Create("invalid.png", data);
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(ReadPngFileHeader(Path("invalid.png"), info, error));
}

TEST_F(PngFileTest, RejectsUnsupportedBitDepth)
{
    auto data = Header();
    data[24] = 16;
    Create("depth.png", data);
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(ReadPngFileHeader(Path("depth.png"), info, error));
}

TEST_F(PngFileTest, RejectsInterlacedHeader)
{
    auto data = Header();
    data[28] = 1;
    Create("interlace.png", data);
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(ReadPngFileHeader(Path("interlace.png"), info, error));
}

TEST_F(PngFileTest, RejectsZeroDimensions)
{
    Create("zero.png", Header(0, 0));
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(ReadPngFileHeader(Path("zero.png"), info, error));
}

TEST_F(PngFileTest, FinalizePublishesValidatedFile)
{
    Create("image.tmp", Header());
    PngFileInfo info;
    std::string error;
    ASSERT_TRUE(FinalizePngFile(Path("image.tmp"), Path("image.png"), 2, 3, info, error)) << error;
    EXPECT_FALSE(std::filesystem::exists(Path("image.tmp")));
    EXPECT_TRUE(std::filesystem::exists(Path("image.png")));
}

TEST_F(PngFileTest, DimensionMismatchLeavesTemporaryFile)
{
    Create("image.tmp", Header());
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(FinalizePngFile(Path("image.tmp"), Path("image.png"), 10, 10, info, error));
    EXPECT_TRUE(std::filesystem::exists(Path("image.tmp")));
    EXPECT_FALSE(std::filesystem::exists(Path("image.png")));
}

TEST_F(PngFileTest, ExistingFinalFileIsNotOverwritten)
{
    Create("image.tmp", Header());
    Create("image.png", "old");
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(FinalizePngFile(Path("image.tmp"), Path("image.png"), 2, 3, info, error));
    EXPECT_EQ(std::filesystem::file_size(Path("image.png")), 3u);
}

} // namespace
} // namespace Rosen
} // namespace OHOS
