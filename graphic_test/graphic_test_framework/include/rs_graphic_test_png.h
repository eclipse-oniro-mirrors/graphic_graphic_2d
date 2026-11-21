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

#ifndef RS_GRAPHIC_TEST_PNG_H
#define RS_GRAPHIC_TEST_PNG_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Media {
class PixelMap;
}

namespace Rosen {

struct PngFileInfo {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t channels = 0;
    uint64_t size = 0;
};

bool ReadPngFileHeader(const std::string& path, PngFileInfo& info, std::string& error);
bool FinalizePngFile(const std::string& temporaryPath, const std::string& finalPath,
    uint32_t expectedWidth, uint32_t expectedHeight, PngFileInfo& info, std::string& error);
bool ArePixelMapsIdentical(Media::PixelMap& first, Media::PixelMap& second);

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_PNG_H
