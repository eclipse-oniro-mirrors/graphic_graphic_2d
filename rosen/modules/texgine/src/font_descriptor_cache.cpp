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

#include "font_descriptor_cache.h"

#include <algorithm>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <unicode/brkiter.h>
#include <unistd.h>

#include "font_config.h"
#include "text/common_utils.h"
#include "utils/text_log.h"

#define INSTALL_FONT_CONFIG_FILE "/data/service/el1/public/for-all-app/fonts/install_fontconfig.json"

namespace OHOS::Rosen {
namespace {
constexpr uint32_t WEIGHT_400 = 400;
}

FontDescriptorCache::FontDescriptorCache() {}

FontDescriptorCache::~FontDescriptorCache() {}

void FontDescriptorCache::ClearFontFileCache()
{
    allFontDescriptor_.clear();
    fontFamilyMap_.clear();
    fullNameMap_.clear();
    postScriptNameMap_.clear();
    fontSubfamilyNameMap_.clear();
    boldCache_.clear();
    italicCache_.clear();
    monoSpaceCache_.clear();
    symbolicCache_.clear();
    stylishFullNameMap_.clear();
}

void FontDescriptorCache::ParserSystemFonts()
{
    for (auto& item : parser_.GetSystemFonts()) {
        FontDescriptorScatter(item);
    }
    Dump();
}

void FontDescriptorCache::ParserStylishFonts()
{
    icu::Locale locale = icu::Locale::getDefault();
    std::vector<TextEngine::FontParser::FontDescriptor> descriptors =
        parser_.GetVisibilityFonts(std::string(locale.getName()));
    for (const auto& descriptor : descriptors) {
        FontDescSharedPtr descriptorPtr = std::make_shared<TextEngine::FontParser::FontDescriptor>(descriptor);
        stylishFullNameMap_[descriptorPtr->fullName].emplace(descriptorPtr);
    }
}

void FontDescriptorCache::ParserInstallFonts()
{
    installPathMap_.clear();
    std::vector<std::string> fontPathList;
    std::string fontPath = INSTALL_FONT_CONFIG_FILE;

    if (!ParseInstalledConfigFile(fontPath, fontPathList)) {
        TEXT_LOGE("Failed to parse the installed fonts");
        return;
    }

    for (const auto& path : fontPathList) {
        if (!ProcessInstalledFontPath(path)) {
            TEXT_LOGE("Failed to process font path");
        }
    }
}

bool FontDescriptorCache::ParseInstalledConfigFile(const std::string& fontPath, std::vector<std::string>& fontPathList)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr = Drawing::FontMgr::CreateDynamicFontMgr();
    std::ifstream configFile(fontPath);
    if (!configFile.is_open()) {
        return false;
    }
    configFile.close();
    return (fontMgr->ParseInstallFontConfig(fontPath, fontPathList) == Drawing::FontCheckCode::SUCCESSED);
}

bool FontDescriptorCache::ProcessInstalledFontPath(const std::string& path)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr = Drawing::FontMgr::CreateDefaultFontMgr();
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        return false;
    }
    std::vector<Drawing::FontByteArray> fullNameVec;
    int ret = fontMgr->GetFontFullName(fd, fullNameVec);
    close(fd);
    if (ret != Drawing::FontCheckCode::SUCCESSED || fullNameVec.empty()) {
        return false;
    }
    std::vector<std::string> fullNameStringVec;
    for (const auto& fullName : fullNameVec) {
        std::string fullNameString;
        if (Drawing::ConvertToString(fullName.strData.get(), fullName.strLen, fullNameString)) {
            fullNameStringVec.push_back(fullNameString);
        } else {
            fullNameStringVec.clear();
            return false;
        }
    }
    installPathMap_[path] = fullNameStringVec;
    return true;
}

void FontDescriptorCache::FontDescriptorScatter(FontDescSharedPtr desc)
{
    auto ret = allFontDescriptor_.emplace(desc);
    if (!ret.second) {
        return;
    }

    auto handleMapScatter = [&](auto& map, const auto& key) {
        map[key].emplace(desc);
    };

    handleMapScatter(fontFamilyMap_, desc->fontFamily);
    handleMapScatter(fullNameMap_, desc->fullName);
    handleMapScatter(postScriptNameMap_, desc->postScriptName);
    handleMapScatter(fontSubfamilyNameMap_, desc->fontSubfamily);

    if (desc->weight > WEIGHT_400) {
        desc->typeStyle |= TextEngine::FontParser::FontTypeStyle::BOLD;
        boldCache_.emplace(desc);
    }

    if (desc->italic != 0) {
        desc->typeStyle |= TextEngine::FontParser::FontTypeStyle::ITALIC;
        italicCache_.emplace(desc);
    }

    if (desc->monoSpace) {
        monoSpaceCache_.emplace(desc);
    }

    if (desc->symbolic) {
        symbolicCache_.emplace(desc);
    }
}

std::set<std::string> FontDescriptorCache::GetInstallFontList()
{
    ParserInstallFonts();
    std::set<std::string> fullNameList;
    for (const auto& pathAndFonts : installPathMap_) {
        for (const auto& fullName : pathAndFonts.second) {
            fullNameList.emplace(fullName);
        }
    }
    return fullNameList;
}

std::set<std::string> FontDescriptorCache::GetStylishFontList()
{
    std::set<std::string> fullNameList;
    for (const auto& temp : stylishFullNameMap_) {
        fullNameList.emplace(temp.first);
    }
    return fullNameList;
}

std::set<std::string> FontDescriptorCache::GetGenericFontList()
{
    std::set<std::string> fullNameList;
    for (const auto& temp : allFontDescriptor_) {
        fullNameList.emplace(temp->fullName);
    }
    return fullNameList;
}

bool FontDescriptorCache::ProcessSystemFontType(const int32_t& systemFontType, int32_t& fontType)
{
    if ((systemFontType & (TextEngine::FontParser::SystemFontType::ALL |
        TextEngine::FontParser::SystemFontType::GENERIC |
        TextEngine::FontParser::SystemFontType::STYLISH |
        TextEngine::FontParser::SystemFontType::INSTALLED)) != systemFontType) {
        TEXT_LOGE("SystemFontType is invalid, systemFontType: %{public}d", systemFontType);
        return false;
    }
    fontType = systemFontType;
    if (systemFontType & TextEngine::FontParser::SystemFontType::ALL) {
        fontType = TextEngine::FontParser::SystemFontType::GENERIC |
            TextEngine::FontParser::SystemFontType::STYLISH |
            TextEngine::FontParser::SystemFontType::INSTALLED;
    }
    return true;
}

void FontDescriptorCache::GetSystemFontFullNamesByType(const int32_t& systemFontType, std::set<std::string>& fontList)
{
    int32_t fontType;
    if (!ProcessSystemFontType(systemFontType, fontType)) {
        fontList.clear();
        return;
    }

    if (fontType & TextEngine::FontParser::SystemFontType::GENERIC) {
        auto fullNameList = GetGenericFontList();
        fontList.insert(fullNameList.begin(), fullNameList.end());
    }

    if (fontType & TextEngine::FontParser::SystemFontType::STYLISH) {
        auto fullNameList = GetStylishFontList();
        fontList.insert(fullNameList.begin(), fullNameList.end());
    }

    if (fontType & TextEngine::FontParser::SystemFontType::INSTALLED) {
        auto fullNameList = GetInstallFontList();
        fontList.insert(fullNameList.begin(), fullNameList.end());
    }
}

bool FontDescriptorCache::ParseInstallFontDescSharedPtrByName(const std::string& fullName, FontDescSharedPtr& result)
{
    ParserInstallFonts();
    std::string path;
    for (const auto& pathAndFonts : installPathMap_) {
        for (const auto& font : pathAndFonts.second) {
            if (font == fullName) {
                path = pathAndFonts.first;
                break;
            }
        }
        if (!path.empty()) {
            break;
        }
    }
    // Setting the locale to English is to ensure consistency with the fullName format obtained from Skia.
    std::string locale = ENGLISH;
    std::vector<FontDescSharedPtr> descriptors;
    if (parser_.ParserFontDescriptorFromPath(path, descriptors, locale)) {
        for (auto& item : descriptors) {
            if (item->fullName == fullName) {
                result = item;
                return true;
            }
        }
    }
    TEXT_LOGE_LIMIT3_MIN("Failed to parser fontDescriptor from path, path: %{public}s", path.c_str());
    return false;
}

void FontDescriptorCache::GetFontDescSharedPtrByFullName(const std::string& fullName,
    const int32_t& systemFontType, FontDescSharedPtr& result)
{
    if (fullName.empty()) {
        TEXT_LOGE("Empty fullName is provided");
        result = nullptr;
        return;
    }
    int32_t fontType;
    if (!ProcessSystemFontType(systemFontType, fontType)) {
        result = nullptr;
        return;
    }
    auto tryFindFontDescriptor = [&fullName, &result](const std::unordered_map<std::string,
        std::set<FontDescSharedPtr>>& map) -> bool {
        auto it = map.find(fullName);
        if (it != map.end()) {
            result = *(it->second.begin());
            return true;
        }
        return false;
    };
    if ((fontType & TextEngine::FontParser::SystemFontType::GENERIC) && tryFindFontDescriptor(fullNameMap_)) {
        return;
    }
    if ((fontType & TextEngine::FontParser::SystemFontType::STYLISH) && tryFindFontDescriptor(stylishFullNameMap_)) {
        return;
    }
    if ((fontType & TextEngine::FontParser::SystemFontType::INSTALLED) &&
        ParseInstallFontDescSharedPtrByName(fullName, result)) {
        return;
    }
    TEXT_LOGD("Failed to get fontDescriptor by fullName: %{public}s", fullName.c_str());
    result = nullptr;
}

bool FontDescriptorCache::HandleMapIntersection(std::set<FontDescSharedPtr>& finishRet, const std::string& name,
    std::unordered_map<std::string, std::set<FontDescSharedPtr>>& map)
{
    if (name.empty()) {
        return true;
    }
    auto iter = map.find(name);
    if (iter == map.end()) {
        return false;
    }
    if (finishRet.empty()) {
        finishRet = iter->second;
    } else {
        std::set<FontDescSharedPtr> temp;
        std::set_intersection(iter->second.begin(), iter->second.end(), finishRet.begin(), finishRet.end(),
            std::insert_iterator<std::set<FontDescSharedPtr>>(temp, temp.begin()));
        if (temp.empty()) {
            return false;
        }
        finishRet = std::move(temp);
    }
    return true;
}

bool FontDescriptorCache::FilterBoldCache(int weight, std::set<FontDescSharedPtr>& finishRet)
{
    if (weight < 0) {
        return false;
    }

    if (weight == 0) {
        return true;
    }

    std::set<FontDescSharedPtr> temp;
    std::set<FontDescSharedPtr>::iterator begin;
    std::set<FontDescSharedPtr>::iterator end;
    if (!finishRet.empty()) {
        begin = finishRet.begin();
        end = finishRet.end();
    } else if (weight > WEIGHT_400) {
        begin = boldCache_.begin();
        end = boldCache_.end();
    } else {
        begin = allFontDescriptor_.begin();
        end = allFontDescriptor_.end();
    }
    std::for_each(begin, end, [&](FontDescSharedPtr item) {
        if (item->weight == weight) {
            temp.emplace(item);
        }
    });

    if (temp.empty()) {
        TEXT_LOGD("Failed to match weight");
        return false;
    }
    finishRet = std::move(temp);
    return true;
}

bool FontDescriptorCache::FilterWidthCache(int width, std::set<FontDescSharedPtr>& finishRet)
{
    if (width < 0) {
        return false;
    }

    if (width == 0) {
        return true;
    }

    std::set<FontDescSharedPtr> temp;
    std::set<FontDescSharedPtr>::iterator begin;
    std::set<FontDescSharedPtr>::iterator end;
    if (!finishRet.empty()) {
        begin = finishRet.begin();
        end = finishRet.end();
    } else {
        begin = allFontDescriptor_.begin();
        end = allFontDescriptor_.end();
    }
    std::for_each(begin, end, [&](FontDescSharedPtr item) {
        if (item->width == width) {
            temp.emplace(item);
        }
    });

    if (temp.empty()) {
        TEXT_LOGD("Failed to match width");
        return false;
    }
    finishRet = std::move(temp);
    return true;
}

bool FontDescriptorCache::FilterItalicCache(int italic, std::set<FontDescSharedPtr>& finishRet)
{
    if (italic == 0) {
        return true;
    }
    std::set<FontDescSharedPtr> temp;
    if (!finishRet.empty()) {
        std::for_each(finishRet.begin(), finishRet.end(), [&](FontDescSharedPtr item) {
            if (item->italic != 0) {
                temp.emplace(item);
            }
        });
    } else {
        temp = italicCache_;
    }
    if (temp.empty()) {
        TEXT_LOGD("Failed to match italic");
        return false;
    }
    finishRet = std::move(temp);
    return true;
}

bool FontDescriptorCache::FilterMonoSpaceCache(bool monoSpace, std::set<FontDescSharedPtr>& finishRet)
{
    if (!monoSpace) {
        return true;
    }

    std::set<FontDescSharedPtr> temp;
    if (!finishRet.empty()) {
        std::for_each(finishRet.begin(), finishRet.end(), [&](FontDescSharedPtr item) {
            if (item->monoSpace) {
                temp.emplace(item);
            }
        });
    } else {
        temp = monoSpaceCache_;
    }
    if (temp.empty()) {
        TEXT_LOGD("Failed to match monoSpace");
        return false;
    }
    finishRet = std::move(temp);
    return true;
}

bool FontDescriptorCache::FilterSymbolicCache(bool symbolic, std::set<FontDescSharedPtr>& finishRet)
{
    if (!symbolic) {
        return true;
    }
    std::set<FontDescSharedPtr> temp;
    if (!finishRet.empty()) {
        std::for_each(finishRet.begin(), finishRet.end(), [&](FontDescSharedPtr item) {
            if (item->symbolic) {
                temp.emplace(item);
            }
        });
    } else {
        temp = symbolicCache_;
    }
    if (temp.empty()) {
        TEXT_LOGD("Failed to match symbolic");
        return false;
    }
    finishRet = std::move(temp);
    return true;
}

bool FontDescriptorCache::FilterTypeStyle(int typeStyle, std::set<FontDescSharedPtr>& finishRet)
{
    if (typeStyle < 0) {
        return false;
    }
    if (typeStyle == 0) {
        return true;
    }

    bool italicFlag = typeStyle & TextEngine::FontParser::FontTypeStyle::ITALIC;
    bool boldFlag = typeStyle & TextEngine::FontParser::FontTypeStyle::BOLD;
    auto handleCache = [&](const std::set<FontDescSharedPtr>& cache, const char* cacheName) {
        if (cache.empty()) {
            TEXT_LOGD("%{public}s is empty", cacheName);
            return false;
        }
        if (finishRet.empty()) {
            finishRet = cache;
        } else {
            std::set<FontDescSharedPtr> temp;
            std::set_intersection(finishRet.begin(), finishRet.end(), cache.begin(), cache.end(),
                                  std::inserter(temp, temp.begin()));
            if (temp.empty()) {
                TEXT_LOGD("Failed to match typeStyle %{public}s", cacheName);
                return false;
            }
            finishRet = std::move(temp);
        }
        return true;
    };
    if (italicFlag && !handleCache(italicCache_, "italic")) {
        return false;
    }
    if (boldFlag && !handleCache(boldCache_, "bold")) {
        return false;
    }
    return true;
}

bool FontDescriptorCache::IsDefault(FontDescSharedPtr desc)
{
    if (desc->fontFamily.empty() && desc->fullName.empty() && desc->postScriptName.empty()
        && desc->fontSubfamily.empty() && desc->weight == 0 && desc->width == 0 && desc->italic == 0
        && !desc->monoSpace && !desc->symbolic && desc->typeStyle == 0) {
        return true;
    }
    return false;
}

void FontDescriptorCache::MatchFromFontDescriptor(FontDescSharedPtr desc, std::set<FontDescSharedPtr>& result)
{
    if (desc == nullptr) {
        TEXT_LOGE("desc is nullptr");
        return;
    }

    if (IsDefault(desc)) {
        result = std::set<FontDescSharedPtr>(allFontDescriptor_.begin(), allFontDescriptor_.end());
        return;
    }

    std::set<FontDescSharedPtr> finishRet;
    TEXT_INFO_CHECK(HandleMapIntersection(finishRet, desc->fontFamily, fontFamilyMap_), return,
        "Failed to match fontFamily");
    TEXT_INFO_CHECK(HandleMapIntersection(finishRet, desc->fullName, fullNameMap_), return, "Failed to match fullName");
    TEXT_INFO_CHECK(HandleMapIntersection(finishRet, desc->postScriptName, postScriptNameMap_), return,
        "Failed to match postScriptName");
    TEXT_INFO_CHECK(HandleMapIntersection(finishRet, desc->fontSubfamily, fontSubfamilyNameMap_), return,
        "Failed to match fontSubfamily");

    TEXT_CHECK(FilterBoldCache(desc->weight, finishRet), return);
    TEXT_CHECK(FilterWidthCache(desc->width, finishRet), return);
    TEXT_CHECK(FilterItalicCache(desc->italic, finishRet), return);
    TEXT_CHECK(FilterMonoSpaceCache(desc->monoSpace, finishRet), return);
    TEXT_CHECK(FilterSymbolicCache(desc->symbolic, finishRet), return);
    TEXT_CHECK(FilterTypeStyle(desc->typeStyle, finishRet), return);
    result = std::move(finishRet);
}

void FontDescriptorCache::Dump()
{
    TEXT_LOGD("allFontDescriptor size: %{public}zu, fontFamilyMap size: %{public}zu, fullNameMap size: %{public}zu \
        postScriptNameMap size: %{public}zu, fontSubfamilyNameMap size: %{public}zu, boldCache size: %{public}zu \
        italicCache size: %{public}zu, monoSpaceCache size: %{public}zu, symbolicCache size: %{public}zu",
        allFontDescriptor_.size(), fontFamilyMap_.size(), fullNameMap_.size(), postScriptNameMap_.size(),
        fontSubfamilyNameMap_.size(), boldCache_.size(), italicCache_.size(), monoSpaceCache_.size(),
        symbolicCache_.size());
}
}