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

#include "font_config.h"

#include "cJSON.h"
#include <dirent.h>
#include <fstream>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils/text_log.h"
#ifdef BUILD_NON_SDK_VER
#include "securec.h"
#endif
#include "utils/text_log.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
#define SUCCESSED 0
#define FAILED 1

const char* FONT_DEFAULT_CONFIG = "/system/etc/fontconfig.json";
constexpr const char* FALLBACK_VARIATIONS_KEY = "variations";
constexpr const char* FALLBACK_INDEX_KEY = "index";

FontConfig::FontConfig(const char* fname)
{
    int err = ParseConfig(fname);
    if (err != 0) {
        TEXT_LOGE("Parse config err");
    }
}

char* FontConfig::GetFileData(const char* fname, int& size)
{
#ifdef BUILD_NON_SDK_VER
    char realPath[PATH_MAX] = {0};
    if (fname == nullptr || realpath(fname, realPath) == NULL) {
        TEXT_LOGE("Path or realPath is NULL");
        return nullptr;
    }
#endif
    std::ifstream file(fname);
    if (file.good()) {
        FILE* fp = fopen(fname, "r");
        if (fp == nullptr) {
            return nullptr;
        }
        fseek(fp, 0L, SEEK_END);
        size = ftell(fp) + 1;
        rewind(fp);
        char* data = static_cast<char*>(malloc(size));
        if (data == nullptr) {
            fclose(fp);
            return nullptr;
        }
#ifdef BUILD_NON_SDK_VER
        if (memset_s(data, size, 0, size) != EOK) {
            TEXT_LOGE("Failed to memset");
            free(data);
            data = nullptr;
            fclose(fp);
            return nullptr;
        }
#else
            memset(data, 0, size);
#endif
        (void)fread(data, size, 1, fp);
        fclose(fp);
        return data;
    }

    return nullptr;
}
cJSON* FontConfig::CheckConfigFile(const char* fname) const
{
    int size = 0;
    char* data = GetFileData(fname, size);
    if (data == nullptr) {
        TEXT_LOGE("Data is NULL");
        return nullptr;
    }
    std::string pramsString;
    pramsString.assign(data, size);
    free(data);
    return cJSON_Parse(pramsString.c_str());
}

int FontConfig::ParseFont(const cJSON* root)
{
    const char* tag = "font";
    cJSON* filters = cJSON_GetObjectItem(root, tag);
    if (filters == nullptr) {
        TEXT_LOGE("Failed to parse font");
        return FAILED;
    }
    int size = cJSON_GetArraySize(filters);
    for (int i = 0; i < size;i++) {
        cJSON* item = cJSON_GetArrayItem(filters, i);
        if (item != nullptr && cJSON_IsString(item)) {
            fontSet_.emplace_back(rootPath_ + std::string(item->valuestring));
        }
    }
    return SUCCESSED;
}

int FontConfig::ParseConfig(const char* fname)
{
    if (fname == nullptr) {
        TEXT_LOGE("File name is null");
        return FAILED;
    }

    std::string rootPath(fname);
    size_t idx = rootPath.rfind('/');
    if (idx == 0 || idx == std::string::npos) {
        TEXT_LOGE("File name is illegal");
        return FAILED;
    }
    rootPath_.assign(rootPath.substr(0, idx) + "/");
    cJSON* root = CheckConfigFile(fname);
    if (root == nullptr) {
        TEXT_LOGE("Failed to check config file");
        return FAILED;
    }
    int result = ParseFont(root);
    cJSON_Delete(root);
    return result;
}

void FontConfig::Dump() const
{
    for (auto it : fontSet_) {
        TEXT_LOGI("File name: %{public}s", it.c_str());
    }
}

std::vector<std::string> FontConfig::GetFontSet() const
{
    return fontSet_;
}

int FontConfigJson::ParseFile(const char* fname)
{
    if (fname == nullptr) {
        TEXT_LOGD("ParseFile fname is nullptr");
        fname = FONT_DEFAULT_CONFIG;
    }

    TEXT_LOGI("ParseFile fname is: %{public}s", fname);
    fontPtr = std::make_shared<FontConfigJsonInfo>();
    int err = ParseConfigList(fname);
    if (err != 0) {
        TEXT_LOGE("Failed to ParseFile ParseConfigList");
        return err;
    }
    return SUCCESSED;
}
int FontConfigJson::ParseFontFileMap(const char* fname)
{
    if (fname == nullptr) {
        TEXT_LOGD("ParseFontFileMap fname is nullptr");
        fname = FONT_DEFAULT_CONFIG;
    }

    TEXT_LOGI("ParseFontFileMap fname is: %{public}s", fname);
    fontFileMap = std::make_shared<FontFileMap>();
    int err = ParseConfigListPath(fname);
    if (err != 0) {
        TEXT_LOGE("Failed to ParseFontFileMap ParseConfigList");
        return err;
    }
    return SUCCESSED;
}

void FontConfigJson::AnalyseFontDir(const cJSON* root)
{
    if (root == nullptr) {
        return;
    }
    int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(root, i);
        if (item != nullptr && cJSON_IsString(item)) {
            fontPtr->fontDirSet.emplace_back(std::string(item->valuestring));
        }
    }
    return;
}

int FontConfigJson::ParseDir(const cJSON* root)
{
    if (root == nullptr) {
        TEXT_LOGE("Failed to parse dir");
        return FAILED;
    }
    const char* key = "fontdir";
    cJSON* item = cJSON_GetObjectItem(root, key);
    if (item != nullptr) {
        AnalyseFontDir(item);
    }
    return SUCCESSED;
}

int FontConfigJson::ParseConfigList(const char* fname)
{
    if (fname == nullptr) {
        TEXT_LOGE("ParseConfigList fname is nullptr");
        return FAILED;
    }
    cJSON* root = CheckConfigFile(fname);
    if (root == nullptr) {
        TEXT_LOGE("Failed to ParseConfigList CheckConfigFile");
        return FAILED;
    }
    // "generic", "fallback" - font attribute
    const char* keys[] = {"generic", "fallback", "fontdir", nullptr};
    int index = 0;
    while (true) {
        if (keys[index] == nullptr) {
            break;
        }
        const char* key = keys[index++];
        if (!strcmp(key, "fontdir")) {
            ParseDir(root);
        } else if (!strcmp(key, "generic")) {
            ParseGeneric(root, key);
        } else if (!strcmp(key, "fallback")) {
            ParseFallback(root, key);
        }
    }
    cJSON_Delete(root);
    return SUCCESSED;
}

int FontConfigJson::ParseConfigListPath(const char* fname)
{
    if (fname == nullptr) {
        TEXT_LOGE("ParseConfigListPath fname is nullptr");
        return FAILED;
    }
    cJSON* root = CheckConfigFile(fname);
    if (root == nullptr) {
        TEXT_LOGE("Failed to ParseConfigListPath CheckConfigFile");
        return FAILED;
    }
    ParseFontMap(root, "font_file_map");
    cJSON_Delete(root);
    return SUCCESSED;
}

int FontConfigJson::ParseAdjustArr(const cJSON* arr, FontGenericInfo &genericInfo)
{
    if (arr == nullptr) {
        TEXT_LOGE("Failed to parse adjust arr");
        return FAILED;
    }
    int size = cJSON_GetArraySize(arr);
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(arr, i);
        if (item == nullptr) {
            continue;
        }
        ParseAdjust(item, genericInfo);
    }
    return SUCCESSED;
}

int FontConfigJson::ParseAliasArr(const cJSON* arr, FontGenericInfo &genericInfo)
{
    if (arr == nullptr) {
        TEXT_LOGE("Failed to parseAliasArr");
        return FAILED;
    }
    int size = cJSON_GetArraySize(arr);
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(arr, i);
        if (item == nullptr) {
            continue;
        }
        ParseAlias(item, genericInfo);
    }
    return SUCCESSED;
}

int FontConfigJson::ParseGeneric(const cJSON* root, const char* key)
{
    if (root == nullptr) {
        TEXT_LOGE("Root is nullptr");
        return FAILED;
    }
    cJSON* filters = cJSON_GetObjectItem(root, key);
    if (filters == nullptr || !cJSON_IsArray(filters)) {
        TEXT_LOGE("Failed to parseGeneric");
        return FAILED;
    }
    int size = cJSON_GetArraySize(filters);
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(filters, i);
        if (item == nullptr) {
            continue;
        }
        FontGenericInfo genericInfo;
        cJSON* family = cJSON_GetObjectItem(item, "family");
        if (family != nullptr && cJSON_IsString(family)) {
            genericInfo.familyName = std::string(family->valuestring);
        }

        cJSON* alias = cJSON_GetObjectItem(item, "alias");
        if (alias != nullptr && cJSON_IsArray(alias)) {
            ParseAliasArr(alias, genericInfo);
        }

        cJSON* adjust = cJSON_GetObjectItem(item, "adjust");
        if (adjust != nullptr && cJSON_IsArray(adjust)) {
            ParseAdjustArr(adjust, genericInfo);
        }

        fontPtr->genericSet.push_back(genericInfo);
    }

    return SUCCESSED;
}

int FontConfigJson::ParseAlias(const cJSON* root, FontGenericInfo &genericInfo)
{
    if (root == nullptr) {
        TEXT_LOGE("Root is nullptr");
        return FAILED;
    }

    int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(root, i);
        if (item == nullptr) {
            continue;
        }
        std::string aliasName = std::string(item->string);
        if (!cJSON_IsNumber(item)) {
            continue;
        }
        int weight = item->valueint;
        AliasInfo info = {aliasName, weight};
        genericInfo.aliasSet.emplace_back(std::move(info));
    }

    return SUCCESSED;
}

int FontConfigJson::ParseAdjust(const cJSON* root, FontGenericInfo &genericInfo)
{
    if (root == nullptr) {
        TEXT_LOGE("Root is nullptr");
        return FAILED;
    }
    int size = cJSON_GetArraySize(root);
    const int count = 2; // the adjust item is 2
    int value[count] = { 0 };
    for (int i = 0; i < size; i++) {
        if (i >= count) {
            break;
        }
        cJSON* item = cJSON_GetArrayItem(root, i);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            continue;
        }
        value[i] = item->valueint;
    }

    AdjustInfo info = {value[0], value[1]};
    genericInfo.adjustSet.emplace_back(std::move(info));
    return SUCCESSED;
}

int FontConfigJson::ParseFallback(const cJSON* root, const char* key)
{
    if (root == nullptr) {
        TEXT_LOGE("Root is nullptr");
        return FAILED;
    }
    cJSON* filters = cJSON_GetObjectItem(root, key);
    if (filters == nullptr || !cJSON_IsArray(filters)) {
        TEXT_LOGE("Failed to cJSON_GetObjectItem");
        return FAILED;
    }
    cJSON* forItem = cJSON_GetArrayItem(cJSON_GetArrayItem(filters, 0), 0);
    int size = cJSON_GetArraySize(forItem);
    FallbackGroup fallbackGroup;
    fallbackGroup.groupName = std::string("");
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(forItem, i);
        if (item == nullptr) {
            continue;
        }
        // refer to FontConfig_OHOS::parseFallbackItem
        int itemSize = cJSON_GetArraySize(item);
        for (int j = itemSize - 1; j >= 0; --j) {
            cJSON* item2 = cJSON_GetArrayItem(item, j);
            if (item2 == nullptr || item2->valuestring == nullptr || item2->string == nullptr ||
                strcmp(item2->string, FALLBACK_VARIATIONS_KEY) == 0 ||
                strcmp(item2->string, FALLBACK_INDEX_KEY) == 0) {
                continue;
            }
            FallbackInfo fallbackInfo;
            fallbackInfo.familyName = item2->valuestring;
            fallbackInfo.font = item2->string;
            fallbackGroup.fallbackInfoSet.emplace_back(std::move(fallbackInfo));
            break;
        }
    }
    fontPtr->fallbackGroupSet.emplace_back(std::move(fallbackGroup));
    return SUCCESSED;
}

int FontConfigJson::ParseFontMap(const cJSON* root, const char* key)
{
    if (root == nullptr) {
        TEXT_LOGE("Root is nullptr");
        return FAILED;
    }
    cJSON* filters = cJSON_GetObjectItem(root, key);
    if (filters == nullptr || !cJSON_IsArray(filters)) {
        TEXT_LOGE("Failed to cJSON_GetObjectItem");
        return FAILED;
    }
    int size = cJSON_GetArraySize(filters);
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(filters, i);
        if (item == nullptr) {
            continue;
        }
        cJSON* item2 = cJSON_GetArrayItem(item, 0);
        if (item2 == nullptr || item2->valuestring == nullptr || item2->string == nullptr) {
            continue;
        }
        (*fontFileMap)[item2->string] = item2->valuestring;
    }
    return SUCCESSED;
}

int FontConfigJson::ParseInstallFont(const cJSON* root, std::vector<std::string>& fontPathList)
{
    const char* tag = "fontlist";
    cJSON* rootObj = cJSON_GetObjectItem(root, tag);
    if (rootObj == nullptr) {
        TEXT_LOGE("Failed to get json object");
        return FAILED;
    }
    int size = cJSON_GetArraySize(rootObj);
    if (size <= 0) {
        TEXT_LOGE("Failed to get json array size");
        return FAILED;
    }
    fontPathList.reserve(size);
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(rootObj, i);
        if (item == nullptr) {
            TEXT_LOGE("Failed to get json item");
            return FAILED;
        }
        cJSON* fullPath = cJSON_GetObjectItem(item, "fontfullpath");
        if (fullPath == nullptr || !cJSON_IsString(fullPath) || fullPath->valuestring == nullptr) {
            TEXT_LOGE("Failed to get fullPath");
            return FAILED;
        }
        fontPathList.emplace_back(std::string(fullPath->valuestring));
    }
    return SUCCESSED;
}

int FontConfigJson::ParseInstallConfig(const char* fontPath, std::vector<std::string>& fontPathList)
{
    if (fontPath == nullptr) {
        TEXT_LOGE("Font path is null");
        return FAILED;
    }

    cJSON* root = CheckConfigFile(fontPath);
    if (root == nullptr) {
        TEXT_LOGE("Failed to check config file");
        return FAILED;
    }
    if (ParseInstallFont(root, fontPathList) != SUCCESSED) {
        cJSON_Delete(root);
        return FAILED;
    }
    cJSON_Delete(root);
    return SUCCESSED;
}

void FontConfigJson::DumpAlias(const AliasSet& aliasSet) const
{
    if (!aliasSet.empty()) {
        const char* space = "    ";
        TEXT_LOGI("  \"alias\": [");
        for (auto it : aliasSet) {
            TEXT_LOGI("  {");
            TEXT_LOGI("%{public}s  \"%{public}s\" : %{public}d", space, it.familyName.c_str(), it.weight);
            TEXT_LOGI("   },");
        }
        TEXT_LOGI("  ],");
    }
}

void FontConfigJson::DumpAjdust(const AdjustSet& adjustSet) const
{
    if (!adjustSet.empty()) {
        TEXT_LOGI("  \"adjust\": [");
        const char* space = "    ";
        for (auto it : adjustSet) {
            TEXT_LOGI("   {");
            TEXT_LOGI("%{public}s  \"weght\" :%{public}d , \"to\" :%{public}d", space, it.origValue, it.newValue);
            TEXT_LOGI("   },");
        }
        TEXT_LOGI("  ],");
    }
}

void FontConfigJson::DumpGeneric() const
{
    TEXT_LOGI("Generic : [");
    if (!fontPtr->genericSet.empty()) {
        for (auto it : fontPtr->genericSet) {
            TEXT_LOGI("  \"family\": [\"%{public}s\"],", it.familyName.c_str());
            DumpAlias(it.aliasSet);
            DumpAjdust(it.adjustSet);
        }
    }
    TEXT_LOGI("]");
}

void FontConfigJson::DumpForbak() const
{
    if (!fontPtr->fallbackGroupSet.empty()) {
        TEXT_LOGI("\"fallback\": [");
        TEXT_LOGI("{");
        for (auto group : fontPtr->fallbackGroupSet) {
            TEXT_LOGI(" \"%{public}s\" : [", group.groupName.c_str());
            if (group.fallbackInfoSet.empty())
                continue;
            const char* space = "    ";
            for (auto it : group.fallbackInfoSet) {
                TEXT_LOGI("  {");
                TEXT_LOGI("%{public}s%{public}s\" : \"%{public}s\"", space, it.font.c_str(), it.familyName.c_str());
                TEXT_LOGI("   },");
            }
            TEXT_LOGI(" ]");
        }
        TEXT_LOGI("}");
        TEXT_LOGI("]");
    }
}

void FontConfigJson::DumpFontDir() const
{
    TEXT_LOGI("Fontdir : [");
    if (!fontPtr->fontDirSet.empty()) {
        for (auto it : fontPtr->fontDirSet) {
            TEXT_LOGI("\"%{public}s\",", it.c_str());
        }
    }
    TEXT_LOGI("]");
}

void FontConfigJson::DumpFontFileMap() const
{
    for (auto it : (*fontFileMap)) {
        TEXT_LOGI("\"%{public}s\": \"%{public}s\"", it.first.c_str(), it.second.c_str());
    }
}

void FontConfigJson::Dump() const
{
    if (fontPtr != nullptr) {
        TEXT_LOGI("Font config dump fontPtr in");
        DumpFontDir();
        DumpGeneric();
        DumpForbak();
        TEXT_LOGI("Font config dump fontPtr out");
    }
    if (fontFileMap != nullptr) {
        TEXT_LOGI("Font config dump fontFileMap in");
        DumpFontFileMap();
        TEXT_LOGI("Font config dump fontFileMap out");
    }
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
