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

#include "rs_graphic_test_png.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>

#include "pixel_map.h"
#include "rs_graphic_test_file.h"

namespace OHOS {
namespace Rosen {
namespace {

constexpr size_t PNG_HEADER_SIZE = 33;
constexpr size_t PNG_WIDTH_OFFSET = 16;
constexpr size_t PNG_HEIGHT_OFFSET = 20;
constexpr size_t PNG_BIT_DEPTH_OFFSET = 24;
constexpr size_t PNG_COLOR_TYPE_OFFSET = 25;
constexpr size_t PNG_INTERLACE_OFFSET = 28;
constexpr unsigned char PNG_SIGNATURE[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
constexpr size_t PNG_CHUNK_TYPE_OFFSET = 12;
constexpr size_t PNG_CHUNK_TYPE_SIZE = 4;
constexpr unsigned char PNG_SUPPORTED_BIT_DEPTH = 8;
constexpr unsigned char PNG_COLOR_TYPE_RGB = 2;
constexpr unsigned char PNG_COLOR_TYPE_RGBA = 6;
constexpr uint32_t PNG_RGB_CHANNELS = 3;
constexpr uint32_t PNG_RGBA_CHANNELS = 4;
constexpr size_t BIG_ENDIAN_U32_BYTES = 4;
constexpr uint32_t BITS_PER_BYTE = 8;

uint32_t ReadBigEndian(const std::array<unsigned char, PNG_HEADER_SIZE>& data, size_t offset)
{
    uint32_t value = 0;
    for (size_t index = 0; index < BIG_ENDIAN_U32_BYTES; index++) {
        value = (value << BITS_PER_BYTE) | static_cast<uint32_t>(data[offset + index]);
    }
    return value;
}

bool ValidateHeader(const std::array<unsigned char, PNG_HEADER_SIZE>& data, PngFileInfo& info, std::string& error)
{
    if (!std::equal(std::begin(PNG_SIGNATURE), std::end(PNG_SIGNATURE), data.begin()) ||
        std::string(reinterpret_cast<const char*>(data.data() + PNG_CHUNK_TYPE_OFFSET), PNG_CHUNK_TYPE_SIZE) !=
        "IHDR") {
        error = "invalid PNG signature or IHDR";
        return false;
    }
    const unsigned char colorType = data[PNG_COLOR_TYPE_OFFSET];
    if (data[PNG_BIT_DEPTH_OFFSET] != PNG_SUPPORTED_BIT_DEPTH ||
        (colorType != PNG_COLOR_TYPE_RGB && colorType != PNG_COLOR_TYPE_RGBA) || data[PNG_INTERLACE_OFFSET] != 0) {
        error = "only non-interlaced 8-bit RGB/RGBA PNG headers are supported";
        return false;
    }
    info.width = ReadBigEndian(data, PNG_WIDTH_OFFSET);
    info.height = ReadBigEndian(data, PNG_HEIGHT_OFFSET);
    info.channels = colorType == PNG_COLOR_TYPE_RGBA ? PNG_RGBA_CHANNELS : PNG_RGB_CHANNELS;
    if (info.width == 0 || info.height == 0) {
        error = "PNG dimensions must be positive";
        return false;
    }
    return true;
}

} // namespace

bool ReadPngFileHeader(const std::string& path, PngFileInfo& info, std::string& error)
{
    info = PngFileInfo {};
    std::array<unsigned char, PNG_HEADER_SIZE> data = {};
    std::ifstream input(path, std::ios::binary);
    input.read(reinterpret_cast<char*>(data.data()), data.size());
    if (input.gcount() != static_cast<std::streamsize>(data.size()) || !ValidateHeader(data, info, error)) {
        if (error.empty()) {
            error = "truncated PNG header: " + path;
        }
        return false;
    }
    if (!FileSize(path, info.size, &error)) {
        return false;
    }
    return true;
}

bool FinalizePngFile(const std::string& temporaryPath, const std::string& finalPath,
    uint32_t expectedWidth, uint32_t expectedHeight, PngFileInfo& info, std::string& error)
{
    std::error_code filesystemError;
    if (std::filesystem::exists(finalPath, filesystemError)) {
        error = "final PNG already exists: " + finalPath;
        return false;
    }
    if (filesystemError) {
        error = "cannot inspect final PNG path: " + filesystemError.message();
        return false;
    }
    if (!ReadPngFileHeader(temporaryPath, info, error)) {
        return false;
    }
    if ((expectedWidth != 0 && info.width != expectedWidth) ||
        (expectedHeight != 0 && info.height != expectedHeight)) {
        error = "PNG dimensions do not match expected size";
        return false;
    }
    std::filesystem::rename(temporaryPath, finalPath, filesystemError);
    if (filesystemError) {
        error = "cannot atomically publish PNG: " + filesystemError.message();
        return false;
    }
    return true;
}

bool ArePixelMapsIdentical(Media::PixelMap& first, Media::PixelMap& second)
{
    const int32_t width = first.GetWidth();
    const int32_t height = first.GetHeight();
    const int32_t bytesPerPixel = first.GetPixelBytes();
    if (width <= 0 || height <= 0 || width != second.GetWidth() || height != second.GetHeight() ||
        bytesPerPixel <= 0 || bytesPerPixel != second.GetPixelBytes() || first.GetPixels() == nullptr ||
        second.GetPixels() == nullptr) {
        return false;
    }
    const uint32_t firstStride = first.GetRowStride();
    const uint32_t secondStride = second.GetRowStride();
    const size_t activeBytes = static_cast<size_t>(width) * static_cast<size_t>(bytesPerPixel);
    for (int32_t row = 0; row < height; row++) {
        const uint8_t* firstRow = first.GetPixels() + row * firstStride;
        const uint8_t* secondRow = second.GetPixels() + row * secondStride;
        if (std::memcmp(firstRow, secondRow, activeBytes) != 0) {
            return false;
        }
    }
    return true;
}

} // namespace Rosen
} // namespace OHOS
