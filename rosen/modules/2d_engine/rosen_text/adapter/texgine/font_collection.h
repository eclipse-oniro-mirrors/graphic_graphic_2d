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

#ifndef ROSEN_TEXT_ADAPTER_TEXGINE_FONT_COLLECTION_H
#define ROSEN_TEXT_ADAPTER_TEXGINE_FONT_COLLECTION_H

#include <mutex>

#include "rosen_text/font_collection.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
class FontProviders;
class DynamicFontProvider;
class ThemeFontProvider;
class SystemFontProvider;
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS

namespace OHOS {
namespace Rosen {
namespace AdapterTextEngine {
class FontCollection : public ::OHOS::Rosen::FontCollection {
public:
    FontCollection();
    std::shared_ptr<TextEngine::FontProviders> Get();

    void DisableFallback() override;
    void DisableSystemFont() override;
    void LoadFont(const std::string& familyName, const uint8_t* data, size_t datalen) override;
    void LoadThemeFont(const std::string& familyName, const uint8_t* data, size_t datalen) override;

private:
    std::shared_ptr<TextEngine::FontProviders> fontProviders_ = nullptr;
    std::shared_ptr<TextEngine::DynamicFontProvider> dfprovider_ = nullptr;
    std::shared_ptr<TextEngine::ThemeFontProvider> tfprovider_ = nullptr;
    std::shared_ptr<TextEngine::SystemFontProvider> sysprovider_ = nullptr;
    bool disableSystemFont_ = false;
    std::mutex mutex_;
};
} // namespace AdapterTextEngine
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_TEXT_ADAPTER_TEXGINE_FONT_COLLECTION_H
