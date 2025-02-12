/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.. All rights reserved.
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

#include "symbol_config_parser.h"

#include <functional>

namespace {
constexpr char SYMBOL_LAYERS_GROUPING[] = "symbol_layers_grouping";
constexpr char NATIVE_GLYPH_ID[] = "native_glyph_id";
constexpr char SYMBOL_GLYPH_ID[] = "symbol_glyph_id";
constexpr char LAYERS[] = "layers";
constexpr char COMPONENTS[] = "components";
constexpr char RENDER_MODES[] = "render_modes";
constexpr char MODE[] = "mode";
constexpr char RENDER_GROUPS[] = "render_groups";
constexpr char GROUP_INDEXES[] = "group_indexes";
constexpr char DEFAULT_COLOR[] = "default_color";
constexpr char FIX_ALPHA[] = "fix_alpha";
constexpr char LAYER_INDEXES[] = "layer_indexes";
constexpr char MASK_INDEXES[] = "mask_indexes";
constexpr char GROUP_SETTINGS[] = "group_settings";
constexpr char ANIMATION_INDEX[] = "animation_index";
constexpr char ANIMATION_SETTINGS[] = "animation_settings";
constexpr char ANIMATION_TYPES[] = "animation_types";

constexpr uint32_t defaultColorHexLen = 9;
constexpr uint32_t defaultColorStrLen = 7;
constexpr uint32_t hexFlag = 16;
constexpr uint32_t twoBytesBitsLen = 16;
constexpr uint32_t oneByteBitsLen = 8;

using SymbolKeyFunc = std::function<void(const char*, const Json::Value&, RSSymbolLayersGroups&)>;
using SymbolKeyFuncMap = std::unordered_map<std::string, SymbolKeyFunc>;

const std::unordered_map<std::string, RSAnimationType> ANIMATIONS_TYPES = {
    {"scale", RSAnimationType::SCALE_TYPE},
    {"appear", RSAnimationType::APPEAR_TYPE},
    {"disappear", RSAnimationType::DISAPPEAR_TYPE},
    {"bounce", RSAnimationType::BOUNCE_TYPE},
    {"variable_color", RSAnimationType::VARIABLE_COLOR_TYPE},
    {"pulse", RSAnimationType::PULSE_TYPE},
    {"replace_appear", RSAnimationType::REPLACE_APPEAR_TYPE},
    {"replace_disappear", RSAnimationType::REPLACE_DISAPPEAR_TYPE}
}

const std::unordered_map<std::string, RSDrawing::DrawingCurveType> CURVE_TYPES = {
    {"spring", RSDrawing::DrawingCurveType::SPRING},
    {"linear", RSDrawing::DrawingCurveType::LINEAR},
    {"friction", RSDrawing::DrawingCurveType::FRICTION},
    {"sharp", RSDrawing::DrawingCurveType::SHARP}
}

const std::unordered_map<std::string, SymbolRenderingStrategy> RENDER_STRATEGY = {
    {"monochrome", SymbolRenderingStrategy::SINGLE},
    {"multicolor", SymbolRenderingStrategy::MULTIPLE_COLOR},
    {"hierarchical", SymbolRenderingStrategy::MULTIPLE_OPACITY},
};
};



bool SymbolConfigParser::ParseSymbolLayersGrouping(const Json::Value& root,
    std::unordered_map<uint16_t, RSSymbolLayersGroups>& symbolConfig)
{
    if (!CheckSymbolLayersIsVaild(root)) {
        return false;
    }
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[SYMBOL_LAYERS_GROUPING][i].isObject()) {
            continue;
        }
        ParseOneSymbol(root[SYMBOL_LAYERS_GROUPING][i], symbolConfig);
    }
    
    return true;
}

bool SymbolConfigParser::CheckSymbolLayersIsVaild(const Json::Value& root)
{
    if (!root.isMember(SYMBOL_LAYERS_GROUPING) || !root[SYMBOL_LAYERS_GROUPING].isArray()) {
        return false;
    }
    return true;
}

void SymbolConfigParser::ParseOneSymbolNativeCase(const char* key, const Json::Value& root,
    RSSymbolLayersGroups& symbolLayersGroups, uint16_t& nativeGlyphId)
{
    if (!root[key].isInt()) {
        return;
    }
    nativeGlyphId = root[key].asInt();
}

void SymbolConfigParser::ParseComponets(const Json::Value& root, std::vector<size_t>& components)
{
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[i].isInt()) {
            continue;
        }
        components.push_back(root[i].asInt());
    }
}

void SymbolConfigParser::SymbolGlyphCase(const char* key, const Json::Value& root,
    RSSymbolLayersGroups& symbolLayersGroups)
{
    if (!root[key].isInt()) {
        return;
    }
    symbolLayersGroups.symbolGlyphId = root[key].asInt();
}

void SymbolConfigParser::ParseLayers(const Json::Value& root, std::vector<std::vector<size_t>>& layers)
{
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[i].isObject()) {
            continue;
        }

        if (!root[i].isMember(COMPONENTS)) {
            continue;
        }
        if (!root[i][COMPONENTS].isArray()) {
            continue;
        }
        std::vector<size_t> components;
        ParseComponets(root[i][COMPONENTS], components);
        layers.push_back(components);
    }
}

void SymbolConfigParser::ParseOneSymbolLayerCase(const char* key, const Json::Value& root,
    RSSymbolLayersGroups& symbolLayersGroups)
{
    if (!root[key].isArray()) {
        return;
    }
    ParseLayers(root[key], symbolLayersGroups.layers);
}

void SymbolConfigParser::ParseOneSymbolRenderCase(const char* key, const Json::Value& root,
    RSSymbolLayersGroups& symbolLayersGroups)
{
    if (!root[key].isArray()) {
        return;
    }
    ParseRenderModes(root[key], symbolLayersGroups.renderModeGroups);
}

void SymbolConfigParser::ParseRenderModes(const Json::Value& root,
    std::map<RSSymbolRenderingStrategy,std::vector<RSRenderGroup>>& renderModesGroups)
{
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[i].isObject()) {
            continue;
        }

        SymbolRenderingStrategy renderingStrategy;
        if (root[i].isMember(MODE)) {
            if (!root[i][MODE].isString()) {
                continue;
            }
            std::string modeValue = root[i][MODE].asCString();
            if (RENDER_STRATEGY.count(modeValue) == 0) {
                continue;
            }
            renderingStrategy = RENDER_STRATEGY[modeValue];
        }

        std::vector<RenderGroup> renderGroups;
        if (root[i].isMember(RENDER_GROUPS)) {
            if (!root[i][RENDER_GROUPS].isArray()) {
                continue;
            }
            ParseRenderGroups(root[i][RENDER_GROUPS], renderGroups);
        }
        renderModesGroups.insert({renderingStrategy, renderGroups});
    }
}

void SymbolConfigParser::ParseRenderGroups(const Json::Value& root, std::vector<RSRenderGroup>& renderGroups)
{
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[i].isObject()) {
            continue;
        }

        RenderGroup renderGroup;
        if (root[i].isMember(GROUP_INDEXES) && root[i][GROUP_INDEXES].isArray()) {
            ParseGroupIndexes(root[i][GROUP_INDEXES], renderGroup.groupInfos);
        }
        if (root[i].isMember(DEFAULT_COLOR) && root[i][DEFAULT_COLOR].isString()) {
            ParseDefaultColor(root[i][DEFAULT_COLOR].asCString(), renderGroup);
        }
        if (root[i].isMember(FIX_ALPHA) && root[i][FIX_ALPHA].isDouble()) {
            renderGroup.color.a = root[i][FIX_ALPHA].asFloat();
        }
        renderGroups.push_back(renderGroup);
    }
}

void SymbolConfigParser::ParseDefaultColor(const char* defaultColor, RSRenderGroup& renderGroup)
{
    char defaultColorHex[defaultColorHexLen];
    defaultColorHex[0] = '0';
    defaultColorHex[1] = 'X';
    if (defaultColor == nullptr || strlen(defaultColor) != defaultColorStrLen) {
        return;
    }

    for (size_t i = 1; i < defaultColorStrLen; i++) {
        defaultColorHex[i + 1] = defaultColor[i];
    }
    defaultColorHex[defaultColorHexLen - 1] = '\0';
    char* endPtr = nullptr;
    int defaultColorInt = strtol(defaultColorHex, &endPtr, hexFlag);
    renderGroup.color.r = (defaultColorInt >> twoBytesBitsLen) & 0xFF;
    renderGroup.color.g = (defaultColorInt >> oneByteBitsLen) & 0xFF;
    renderGroup.color.b = defaultColorInt & 0xFF;
}

void SymbolConfigParser::ParseGroupIndexes(const Json::Value& root, std::vector<RSGroupInfo>& groupInfos)
{
    for (size_t i = 0; i < root.size(); i++) {
        GroupInfo groupInfo;
        if (root[i].isMember(LAYER_INDEXES)) {
            if (!root[i][LAYER_INDEXES].isArray()) {
                continue;
            }
            ParseLayerOrMaskIndexes(root[i][LAYER_INDEXES], groupInfo.layerIndexes);
        }
        if (root[i].isMember(MASK_INDEXES)) {
            if (!root[i][MASK_INDEXES].isArray()) {
                continue;
            }
            ParseLayerOrMaskIndexes(root[i][MASK_INDEXES], groupInfo.maskIndexes);
        }
        groupInfos.push_back(groupInfo);
    }
}

void SymbolConfigParser::ParseLayerOrMaskIndexes(const Json::Value& root, std::vector<size_t>& indexes)
{
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[i].isInt()) {
            continue;
        }
        indexes.push_back(root[i].asInt());
    }
}

void SymbolConfigParser::ParseOneSymbolAnimateCase(const char* key, const Json::Value& root,
    RSSymbolLayersGroups& symbolLayersGroups)
{
    if (!root[key].isArray()) {
        return;
    }
    ParseAnimationSettings(root[key], symbolLayersGroups.animationSettings);
}

void SymbolConfigParser::ParseAnimationSettings(const Json::Value& root,
    std::vector<RSAnimationSetting>& animationSettings)
{
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[i].isObject()) {
            continue;
        }
        AnimationSetting animationSetting;
        ParseAnimationSetting(root[i], animationSetting);
        animationSettings.push_back(animationSetting);
    }
}

void SymbolConfigParser::ParseAnimationSetting(const Json::Value& root, RSAnimationSetting& animationSetting)
{
    if (root.isMember(ANIMATION_TYPES) && root[ANIMATION_TYPES].isArray()) {
        ParseAnimationTypes(root[ANIMATION_TYPES], animationSetting.animationTypes);
    }

    if (root.isMember(GROUP_SETTINGS) && root[GROUP_SETTINGS].isArray()) {
        ParseGroupSettings(root[GROUP_SETTINGS], animationSetting.groupSettings);
    }
}

void SymbolConfigParser::ParseAnimationTypes(const Json::Value& root, std::vector<RSAnimationType>& animationTypes)
{
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[i].isString()) {
            continue;
        }
        const std::string animationTypeStr = root[i].asCString();
        AnimationType animationType;
        ParseAnimationType(animationTypeStr, animationType);
        animationTypes.push_back(animationType);
    }
}

void SymbolConfigParser::ParseAnimationType(const std::string& animationTypeStr, RSAnimationType& animationType)
{
    auto iter = ANIMATIONS_TYPES.find(animationTypeStr);
    if (iter != ANIMATIONS_TYPES.end()) {
        animationType = iter->second;
    }
}

void SymbolConfigParser::ParseGroupSettings(const Json::Value& root, std::vector<RSGroupSetting>& groupSettings)
{
    for (size_t i = 0; i < root.size(); i++) {
        if (!root[i].isObject()) {
            continue;
        }
        GroupSetting groupSetting;
        ParseGroupSetting(root[i], groupSetting);
        groupSettings.push_back(groupSetting);
    }
}

void SymbolConfigParser::ParseGroupSetting(const Json::Value& root, RSGroupSetting& groupSetting)
{
    if (root.isMember(GROUP_INDEXES) && root[GROUP_INDEXES].isArray()) {
        ParseGroupIndexes(root[GROUP_INDEXES], groupSetting.groupInfos);
    }

    if (root.isMember(ANIMATION_INDEX) && root[ANIMATION_INDEX].isInt()) {
        groupSetting.animationIndex = root[ANIMATION_INDEX].asInt();
    }
}

void SymbolConfigParser::ParseOneSymbol(const Json::Value& root,
    std::unordered_map<uint16_t, RSSymbolLayersGroups>& symbolConfig)
{
    std::vector<std::string> tags = {NATIVE_GLYPH_ID, SYMBOL_GLYPH_ID, LAYERS, RENDER_MODES, ANIMATION_SETTINGS};
    uint16_t nativeGlyphId;
    SymbolLayersGroups symbolLayersGroups;

    static SymbolKeyFuncMap funcMap = {
        {NATIVE_GLYPH_ID, [this, &nativeGlyphId](const char* key, const Json::Value& root,
            SymbolLayersGroups& symbolLayersGroups)
            {
                this.ParseOneSymbolNativeCase(key, root, symbolLayersGroups, nativeGlyphId);
            }
        },
        {SYMBOL_GLYPH_ID, [this](const char* key, const Json::Value& root, SymbolLayersGroups& symbolLayersGroups)
            {
                this.SymbolGlyphCase(key, root, symbolLayersGroups);
            }
        },
        {LAYERS, [this](const char* key, const Json::Value& root, SymbolLayersGroups& symbolLayersGroups)
            {
                this.ParseOneSymbolLayerCase(key, root, symbolLayersGroups);
            }
        },
        {RENDER_MODES, [this](const char* key, const Json::Value& root, SymbolLayersGroups& symbolLayersGroups)
            {
                this.ParseOneSymbolRenderCase(key, root, symbolLayersGroups);
            }
        },
        {ANIMATION_SETTINGS, [this](const char* key, const Json::Value& root,
            SymbolLayersGroups& symbolLayersGroups)
            {
                this.ParseOneSymbolAnimateCase(key, root, symbolLayersGroups);
            }
        }
    };
    for (size_t i = 0; i < tags.size(); i++) {
        const char* key = tags[i].c_str();
        if (!root.isMember(key)) {
            continue;
        }
        if (funcMap.count(key) > 0) {
            funcMap[key](key, root, symbolLayersGroups);
        }
    }
    symbolConfig.emplace({nativeGlyphId, symbolLayersGroups});
}
