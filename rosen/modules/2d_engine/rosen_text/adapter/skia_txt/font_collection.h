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

#ifndef ROSEN_TEXT_ADAPTER_TXT_FONT_COLLECTION_H
#define ROSEN_TEXT_ADAPTER_TXT_FONT_COLLECTION_H

#include <mutex>
#include <unordered_map>

#include "rosen_text/font_collection.h"

#include "txt/font_collection.h"
#include "txt/asset_font_manager.h"

#include "text/font_mgr.h"

namespace OHOS {
namespace Rosen {
namespace AdapterTxt {
class FontCollection : public ::OHOS::Rosen::FontCollection {
public:
    explicit FontCollection(std::shared_ptr<txt::FontCollection> fontCollection = nullptr);
    ~FontCollection();
    std::shared_ptr<txt::FontCollection> Get();

    void DisableFallback() override;
    void DisableSystemFont() override;
    std::shared_ptr<Drawing::Typeface> LoadFont(
        const std::string &familyName, const uint8_t *data, size_t datalen) override;
    std::shared_ptr<Drawing::Typeface> LoadThemeFont(
        const std::string &familyName, const uint8_t *data, size_t datalen) override;
    std::shared_ptr<Drawing::FontMgr> GetFontMgr() override;
    bool RegisterTypeface(std::shared_ptr<Drawing::Typeface> typeface) override;

    void ClearCaches() override;
private:
    std::shared_ptr<txt::FontCollection> fontCollection_ = nullptr;
    std::shared_ptr<Drawing::FontMgr> dfmanager_ = nullptr;
    std::unordered_map<uint32_t, std::shared_ptr<Drawing::Typeface>> typefaces_;
    std::mutex mutex_;
};
} // namespace AdapterTxt
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_TEXT_ADAPTER_TXT_FONT_COLLECTION_H
