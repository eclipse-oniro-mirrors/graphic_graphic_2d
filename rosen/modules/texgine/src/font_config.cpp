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

#ifdef BUILD_NON_SDK_VER
#include "securec.h"
#endif
#include "texgine/utils/exlog.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
#define SUCCESSED 0
#define FAILED 1

const char* FONT_DEFAULT_CONFIG = "/system/etc/fontconfig.json";

FontConfig::FontConfig(const char* fname)
{
    int err = ParseConfig(fname);
    if (err != 0) {
        LOGSO_FUNC_LINE(ERROR) << "parse config err";
    }
}

char* FontConfig::GetFileData(const char* fname, int& size)
{
#ifdef BUILD_NON_SDK_VER
    char realPath[PATH_MAX] = {0};
    if (fname == nullptr || realpath(fname, realPath) == NULL) {
        LOGSO_FUNC_LINE(ERROR) << "path or realPath is NULL";
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
            LOGSO_FUNC_LINE(ERROR) << "memset failed";
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
        LOGSO_FUNC_LINE(ERROR) << "data is NULL";
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
        LOGSO_FUNC_LINE(ERROR) << "parse font failed";
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
        LOGSO_FUNC_LINE(ERROR) << "fname is null";
        return FAILED;
    }

    std::string rootPath(fname);
    size_t idx = rootPath.rfind('/');
    if (idx == 0 || idx == std::string::npos) {
        LOGSO_FUNC_LINE(ERROR) << "fname is illegal";
        return FAILED;
    }
    rootPath_.assign(rootPath.substr(0, idx) + "/");
    cJSON* root = CheckConfigFile(fname);
    if (root == nullptr) {
        LOGSO_FUNC_LINE(ERROR) << "check config file failed";
        return FAILED;
    }
    return ParseFont(root);
}

void FontConfig::Dump() const
{
    for (auto it : fontSet_) {
        LOGSO_FUNC_LINE(INFO) << "fname:" << it;
    }
}

std::vector<std::string> FontConfig::GetFontSet() const
{
    return fontSet_;
}

int FontConfigJson::ParseFile(const char* fname)
{
    if (fname == nullptr) {
        LOGSO_FUNC_LINE(DEBUG) << "ParseFile fname is nullptr";
        fname = FONT_DEFAULT_CONFIG;
    }

    LOGSO_FUNC_LINE(INFO) << "ParseFile fname is: " << fname;
    fontPtr = std::make_shared<FontConfigJsonInfo>();
    int err = ParseConfigList(fname);
    if (err != 0) {
        LOGSO_FUNC_LINE(ERROR) << "ParseFile ParseConfigList failed";
        return err;
    }
    return SUCCESSED;
}
int FontConfigJson::ParseFontFileMap(const char* fname)
{
    if (fname == nullptr) {
        LOGSO_FUNC_LINE(DEBUG) << "ParseFontFileMap fname is nullptr";
        fname = FONT_DEFAULT_CONFIG;
    }

    LOGSO_FUNC_LINE(INFO) << "ParseFontFileMap fname is: " << fname;
    fontFileMap = std::make_shared<FontFileMap>();
    int err = ParseConfigListPath(fname);
    if (err != 0) {
        LOGSO_FUNC_LINE(ERROR) << "ParseFontFileMap ParseConfigList failed";
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
        LOGSO_FUNC_LINE(ERROR) << "parse dir failed";
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
        LOGSO_FUNC_LINE(ERROR) << "ParseConfigList fname is nullptr";
        return FAILED;
    }
    cJSON* root = CheckConfigFile(fname);
    if (root == nullptr) {
        LOGSO_FUNC_LINE(ERROR) << "ParseConfigList CheckConfigFile failed";
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
        LOGSO_FUNC_LINE(ERROR) << "ParseConfigListPath fname is nullptr";
        return FAILED;
    }
    cJSON* root = CheckConfigFile(fname);
    if (root == nullptr) {
        LOGSO_FUNC_LINE(ERROR) << "ParseConfigListPath CheckConfigFile failed";
        return FAILED;
    }
    ParseFontMap(root, "font_file_map");
    cJSON_Delete(root);
    return SUCCESSED;
}

int FontConfigJson::ParseAdjustArr(const cJSON* arr, FontGenericInfo &genericInfo)
{
    if (arr == nullptr) {
        LOGSO_FUNC_LINE(ERROR) << "parse adjust arr failed";
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
        LOGSO_FUNC_LINE(ERROR) << "ParseAliasArr failed";
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
        LOGSO_FUNC_LINE(ERROR) << "root is nullptr";
        return FAILED;
    }
    cJSON* filters = cJSON_GetObjectItem(root, key);
    if (filters == nullptr || !cJSON_IsArray(filters)) {
        LOGSO_FUNC_LINE(ERROR) << "ParseGeneric failed";
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
        LOGSO_FUNC_LINE(ERROR) << "root is nullptr";
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
        LOGSO_FUNC_LINE(ERROR) << "root is nullptr";
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
        LOGSO_FUNC_LINE(ERROR) << "root is nullptr";
        return FAILED;
    }
    cJSON* filters = cJSON_GetObjectItem(root, key);
    if (filters == nullptr || !cJSON_IsArray(filters)) {
        LOGSO_FUNC_LINE(ERROR) << "cJSON_GetObjectItem failed";
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
        cJSON* item2 = cJSON_GetArrayItem(item, 0);
        if (item2 == nullptr || item2->valuestring == nullptr || item2->string == nullptr) {
            continue;
        }
        FallbackInfo fallbackInfo;
        fallbackInfo.familyName = item2->valuestring;
        fallbackInfo.font = item2->string;
        fallbackGroup.fallbackInfoSet.emplace_back(std::move(fallbackInfo));
    }
    fontPtr->fallbackGroupSet.emplace_back(std::move(fallbackGroup));
    return SUCCESSED;
}

int FontConfigJson::ParseFontMap(const cJSON* root, const char* key)
{
    if (root == nullptr) {
        LOGSO_FUNC_LINE(ERROR) << "root is nullptr";
        return FAILED;
    }
    cJSON* filters = cJSON_GetObjectItem(root, key);
    if (filters == nullptr || !cJSON_IsArray(filters)) {
        LOGSO_FUNC_LINE(ERROR) << "cJSON_GetObjectItem failed";
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

void FontConfigJson::DumpAlias(const AliasSet &aliasSet) const
{
    if (!aliasSet.empty()) {
        const std::string space = "    ";
        LOGSO_FUNC_LINE(INFO) << "  \"alias\": [";
        for (auto it : aliasSet) {
            LOGSO_FUNC_LINE(INFO) << "  {";
            LOGSO_FUNC_LINE(INFO) << space << "  \"" <<
                it.familyName << "\" : " << it.weight;
            LOGSO_FUNC_LINE(INFO) << "   },";
        }
        LOGSO_FUNC_LINE(INFO) << "  ],";
    }
}

void FontConfigJson::DumpAjdust(const AdjustSet &adjustSet) const
{
    if (!adjustSet.empty()) {
        LOGSO_FUNC_LINE(INFO) << "  \"adjust\": [";
        const std::string space = "    ";
        for (auto it : adjustSet) {
            LOGSO_FUNC_LINE(INFO) << "   {";
            LOGSO_FUNC_LINE(INFO) << space << "  \"weght\" :" <<
                it.origValue << " , " << "\"to\" :" << it.newValue;
            LOGSO_FUNC_LINE(INFO) << "   },";
        }
        LOGSO_FUNC_LINE(INFO) << "  ],";
    }
}

void FontConfigJson::DumpGeneric() const
{
    LOGSO_FUNC_LINE(INFO) << "generic : [";
    if (!fontPtr->genericSet.empty()) {
        for (auto it : fontPtr->genericSet) {
            LOGSO_FUNC_LINE(INFO) << "  \"family\": [\""<< it.familyName << "\"],";
            DumpAlias(it.aliasSet);
            DumpAjdust(it.adjustSet);
        }
    }
    LOGSO_FUNC_LINE(INFO) << "]";
}

void FontConfigJson::DumpForbak() const
{
    if (!fontPtr->fallbackGroupSet.empty()) {
        LOGSO_FUNC_LINE(INFO) << "\"fallback\": [";
        LOGSO_FUNC_LINE(INFO) << "{";
        for (auto group : fontPtr->fallbackGroupSet) {
            LOGSO_FUNC_LINE(INFO) << " \"" << group.groupName << "\" : [";
            if (group.fallbackInfoSet.empty()) continue;
            const std::string space = "    ";
            for (auto it : group.fallbackInfoSet) {
                LOGSO_FUNC_LINE(INFO) << "  {";
                LOGSO_FUNC_LINE(INFO) << space << it.font << "\" : \""
                    << it.familyName << "\"";
                LOGSO_FUNC_LINE(INFO) << "   },";
            }
            LOGSO_FUNC_LINE(INFO) << " ]";
        }
        LOGSO_FUNC_LINE(INFO) << "}";
        LOGSO_FUNC_LINE(INFO) << "]";
    }
}

void FontConfigJson::DumpFontDir() const
{
    LOGSO_FUNC_LINE(INFO) << "fontdir : [";
    if (!fontPtr->fontDirSet.empty()) {
        for (auto it : fontPtr->fontDirSet) {
            LOGSO_FUNC_LINE(INFO) << "\""<< it << "\",";
        }
    }
    LOGSO_FUNC_LINE(INFO) << "]";
}

void FontConfigJson::DumpFontFileMap() const
{
    for (auto it : (*fontFileMap)) {
        LOGSO_FUNC_LINE(INFO) << "\"" << it.first << "\": \""
            << it.second << "\"";
    }
}

void FontConfigJson::Dump() const
{
    if (fontPtr != nullptr) {
        LOGSO_FUNC_LINE(INFO) << "font config dump fontPtr in";
        DumpFontDir();
        DumpGeneric();
        DumpForbak();
        LOGSO_FUNC_LINE(INFO) << "font config dump fontPtr out";
    }
    if (fontFileMap != nullptr) {
        LOGSO_FUNC_LINE(INFO) << "font config dump fontFileMap in";
        DumpFontFileMap();
        LOGSO_FUNC_LINE(INFO) << "font config dump fontFileMap out";
    }
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
