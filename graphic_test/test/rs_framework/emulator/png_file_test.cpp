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

// IHDR layout of a minimal PNG header: signature, chunk length/type, then width, height and format bytes.
constexpr size_t PNG_HEADER_SIZE = 33;
constexpr size_t CHUNK_TYPE_OFFSET = 12;
constexpr size_t CHUNK_TYPE_SIZE = 4;
constexpr size_t WIDTH_OFFSET = 16;
constexpr size_t HEIGHT_OFFSET = 20;
constexpr size_t BIT_DEPTH_OFFSET = 24;
constexpr size_t COLOR_TYPE_OFFSET = 25;
constexpr size_t COMPRESSION_OFFSET = 26;
constexpr size_t FILTER_OFFSET = 27;
constexpr size_t INTERLACE_OFFSET = 28;
constexpr size_t U32_BYTES = 4;
constexpr uint32_t BITS_PER_BYTE = 8;
constexpr uint32_t BYTE_MASK = 0xFF;
constexpr char BIT_DEPTH_8 = 8;
constexpr char BIT_DEPTH_16 = 16;
constexpr uint8_t COLOR_TYPE_RGB = 2;
constexpr uint8_t COLOR_TYPE_RGBA = 6;
constexpr uint32_t DEFAULT_WIDTH = 2;
constexpr uint32_t DEFAULT_HEIGHT = 3;
constexpr uint32_t RGB_WIDTH = 4;
constexpr uint32_t RGB_HEIGHT = 5;
constexpr uint32_t MISMATCHED_SIZE = 10;

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
        for (size_t index = 0; index < U32_BYTES; index++) {
            const uint32_t shift = static_cast<uint32_t>(U32_BYTES - 1 - index) * BITS_PER_BYTE;
            data[offset + index] = static_cast<char>((value >> shift) & BYTE_MASK);
        }
    }

    static std::string Header(uint32_t width = DEFAULT_WIDTH, uint32_t height = DEFAULT_HEIGHT,
        uint8_t colorType = COLOR_TYPE_RGBA)
    {
        std::string data(PNG_HEADER_SIZE, '\0');
        const unsigned char signature[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
        for (size_t index = 0; index < sizeof(signature); index++) {
            data[index] = static_cast<char>(signature[index]);
        }
        data.replace(CHUNK_TYPE_OFFSET, CHUNK_TYPE_SIZE, "IHDR");
        WriteBigEndian(data, WIDTH_OFFSET, width);
        WriteBigEndian(data, HEIGHT_OFFSET, height);
        data[BIT_DEPTH_OFFSET] = BIT_DEPTH_8;
        data[COLOR_TYPE_OFFSET] = static_cast<char>(colorType);
        data[COMPRESSION_OFFSET] = 0;
        data[FILTER_OFFSET] = 0;
        data[INTERLACE_OFFSET] = 0;
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
    Create("rgb.png", Header(RGB_WIDTH, RGB_HEIGHT, COLOR_TYPE_RGB));
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
    data[BIT_DEPTH_OFFSET] = BIT_DEPTH_16;
    Create("depth.png", data);
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(ReadPngFileHeader(Path("depth.png"), info, error));
}

TEST_F(PngFileTest, RejectsInterlacedHeader)
{
    auto data = Header();
    data[INTERLACE_OFFSET] = 1;
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
    ASSERT_TRUE(FinalizePngFile(Path("image.tmp"), Path("image.png"), DEFAULT_WIDTH, DEFAULT_HEIGHT, info, error))
        << error;
    EXPECT_FALSE(std::filesystem::exists(Path("image.tmp")));
    EXPECT_TRUE(std::filesystem::exists(Path("image.png")));
}

TEST_F(PngFileTest, DimensionMismatchLeavesTemporaryFile)
{
    Create("image.tmp", Header());
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(FinalizePngFile(Path("image.tmp"), Path("image.png"), MISMATCHED_SIZE, MISMATCHED_SIZE, info, error));
    EXPECT_TRUE(std::filesystem::exists(Path("image.tmp")));
    EXPECT_FALSE(std::filesystem::exists(Path("image.png")));
}

TEST_F(PngFileTest, ExistingFinalFileIsNotOverwritten)
{
    Create("image.tmp", Header());
    Create("image.png", "old");
    PngFileInfo info;
    std::string error;
    EXPECT_FALSE(FinalizePngFile(Path("image.tmp"), Path("image.png"), DEFAULT_WIDTH, DEFAULT_HEIGHT, info, error));
    EXPECT_EQ(std::filesystem::file_size(Path("image.png")), 3u);
}

} // namespace
} // namespace Rosen
} // namespace OHOS
