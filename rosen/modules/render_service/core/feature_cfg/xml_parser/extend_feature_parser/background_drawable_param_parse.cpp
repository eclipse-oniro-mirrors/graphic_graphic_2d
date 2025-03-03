/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "background_drawable_param_parse.h"

namespace OHOS::Rosen {
int32_t BackgroundDrawableParamParse::ParseFeatureParam(FeatureParamMapType &featureMap, xmlNode &node)
{
    RS_LOGI("BackgroundDrawableParamParse start");
    xmlNode *currNode = &node;
    if (currNode->xmlChildrenNode == nullptr) {
        RS_LOGD("BackgroundDrawableParamParse stop parsing, no children nodes");
        return PARSE_GET_CHILD_FAIL;
    }

    currNode = currNode->xmlChildrenNode;
    for (; currNode; currNode = currNode->next) {
        if (currNode->type!= XML_ELEMENT_NODE) {
            continue;
        }
        if (ParseBackgroundDrawableInternal(featureMap, *currNode)!= PARSE_EXEC_SUCCESS) {
            RS_LOGD("BackgroundDrawableParamParse stop parsing, parse internal fail");
            return PARSE_INTERNAL_FAIL;
        }
    }
    return PARSE_EXEC_SUCCESS;
}

int32_t BackgroundDrawableParamParse::ParseBackgroundDrawableInternal(FeatureParamMapType &featureMap, xmlNode &node)
{
    xmlNode *currNode = &node;
    auto iter = featureMap.find(FEATURE_CONFIGS[BACKGROUND_DRAWABLE_CCM]);
    if (iter!= featureMap.end()) {
        backgroundDrawableParam_ = std::static_pointer_cast<BackgroundDrawableParam>(iter->second);
    } else {
        RS_LOGD("BackgroundDrawableParamParse stop parsing, no initializing param map");
        return PARSE_NO_PARAM;
    }

    // Start Parse Feature Params
    int xmlParamType = GetXmlNodeAsInt(*currNode);
    auto name = ExtractPropertyValue("name", *currNode);
    auto val = ExtractPropertyValue("value", *currNode);
    if (xmlParamType == PARSE_XML_FEATURE_SWITCH) {
        bool isEnabled = ParseFeatureSwitch(val);
        if (name == "DrawRRect") {
            backgroundDrawableParam_->SetDrawRRectEnabled(isEnabled);
            RS_LOGI("BackgroundDrawableParamParse stop parsing, DrawRRect is %{public}s",
                isEnabled ? "enabled" : "disabled");
        }
    }

    return PARSE_EXEC_SUCCESS;
}
} // namespace OHOS::Rosen