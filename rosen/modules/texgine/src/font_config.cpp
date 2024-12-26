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

const char* FONT_DEFAULT_CONFIG = "/system/etc/fontconfig_ohos.json";
const char* FONT_FILE_MAP_CONFIG = "/system/etc/font_file_map.json";

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
    cJSON_Minify(data);
    if (data == nullptr) {
        TEXT_LOGE("Data is NULL");
        return nullptr;
    }
    cJSON* res = cJSON_Parse(data);
    free(data);
    return res;
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
    indexMap = std::make_shared<std::unordered_map<std::string, size_t>>();
    fontPtr->fallbackGroupSet.emplace_back();
    fontPtr->fallbackGroupSet[0].groupName = "";
    int err = ParseConfigList(fname);
    // only for compatible with old version
    fontPtr->genericSet[0].adjustSet = { { 50, 100 }, { 80, 400 }, { 100, 700 }, { 200, 900 } };
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
        fname = FONT_FILE_MAP_CONFIG;
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

void FontConfigJson::emplaceFontJson(const FontJson& fontJson)
{
    if (!fontPtr) {
        return;
    }

    if (fontJson.type == 0) {
        auto exist = indexMap->find(fontJson.family);
        if (exist == indexMap->end()) {
            (*indexMap)[fontJson.family] = fontPtr->genericSet.size();
            fontPtr->genericSet.emplace_back(FontGenericInfo { fontJson.family });
            fontPtr->genericSet.back().aliasSet.emplace_back(AliasInfo { fontJson.alias, fontJson.weight });
            return;
        }
        auto& aliasSet = fontPtr->genericSet[exist->second].aliasSet;
        auto existAlias = std::find_if(aliasSet.begin(), aliasSet.end(),
            [&fontJson](const AliasInfo& aliasInfo) { return aliasInfo.familyName == fontJson.alias; });
        if (existAlias == aliasSet.end()) {
            fontPtr->genericSet[exist->second].aliasSet.emplace_back(AliasInfo { fontJson.alias, fontJson.weight });
        }
        return;
    }
    fontPtr->fallbackGroupSet[0].fallbackInfoSet.emplace_back(FallbackInfo { fontJson.family, fontJson.lang });
}

int FontConfigJson::ParseDir(const cJSON* root)
{
    if (!fontPtr) {
        return FAILED;
    }
    int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; i++) {
        cJSON* item = cJSON_GetArrayItem(root, i);
        if (cJSON_IsString(item)) {
            fontPtr->fontDirSet.emplace_back(std::string(item->valuestring));
        }
    }
    return SUCCESSED;
}

void FontConfigJson::AnalyseFont(const cJSON* root)
{
    cJSON* item = root->child;

    FontJson fontJson;
    while (item != nullptr) {
        if (strcmp(item->string, "type") == 0 && cJSON_IsNumber(item)) {
            fontJson.type = item->valueint;
        } else if (strcmp(item->string, "alias") == 0 && cJSON_IsString(item)) {
            fontJson.alias = item->valuestring;
        } else if (strcmp(item->string, "family") == 0 && cJSON_IsString(item)) {
            fontJson.family = item->valuestring;
        } else if (strcmp(item->string, "weight") == 0 && cJSON_IsNumber(item)) {
            fontJson.weight = item->valueint;
        } else if (strcmp(item->string, "lang") == 0  && cJSON_IsString(item)) {
            fontJson.lang = item->valuestring;
        }
        item = item->next;
    }
    emplaceFontJson(fontJson);
}

int FontConfigJson::ParseFonts(const cJSON* root)
{
    if (root == nullptr) {
        TEXT_LOGE("Failed to parse fonts");
        return FAILED;
    }
    if (root != nullptr && cJSON_IsArray(root)) {
        int fontsSize = cJSON_GetArraySize(root);
        for (int i = 0; i < fontsSize; i++) {
            cJSON* item = cJSON_GetArrayItem(root, i);
            if (item != nullptr && cJSON_IsObject(item)) {
                AnalyseFont(item);
            }
        }
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
    // "font_dir", "fonts" - font attribute
    cJSON* item = root->child;
    while (item != nullptr) {
        if (strcmp(item->string, "font_dir") == 0) {
            ParseDir(item);
        } else if (strcmp(item->string, "fonts") == 0) {
            ParseFonts(item);
        }
        item = item->next;
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

int FontConfigJson::ParseFontMap(const cJSON* root, const char* key)
{
    if (root == nullptr) {
        TEXT_LOGE("Root is nullptr");
        return FAILED;
    }
    cJSON* filters = cJSON_GetObjectItem(root, key);
    if (filters == nullptr || !cJSON_IsObject(filters)) {
        TEXT_LOGE("Failed to cJSON_GetObjectItem");
        return FAILED;
    }
    cJSON* item = filters->child;
    while (item != nullptr) {
        (*fontFileMap)[item->string] = item->valuestring;
        item = item->next;
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
