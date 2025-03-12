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

#include "accessibility_param_parse.h"

namespace OHOS::Rosen {

int32_t AccessibilityParamParse::ParseFeatureParam(FeatureParamMapType &featureMap, xmlNode &node)
{
    RS_LOGI("AccessibilityParamParse start");
    xmlNode *currNode = &node;
    if (currNode->xmlChildrenNode == nullptr) {
        RS_LOGD("AccessibilityParamParse stop parsing, no children nodes");
        return PARSE_GET_CHILD_FAIL;
    }

    currNode = currNode->xmlChildrenNode;
    for (; currNode; currNode = currNode->next) {
        if (currNode->type != XML_ELEMENT_NODE) {
            continue;
        }

        if (ParseAccessibilityInternal(featureMap, *currNode) != PARSE_EXEC_SUCCESS) {
            RS_LOGD("AccessibilityParamParse stop parsing, parse internal fail");
            return PARSE_INTERNAL_FAIL;
        }
    }
    return PARSE_EXEC_SUCCESS;
}

int32_t AccessibilityParamParse::ParseAccessibilityInternal(FeatureParamMapType &featureMap, xmlNode &node)
{
    xmlNode *currNode = &node;

    auto iter = featureMap.find(FEATURE_CONFIGS[Accessibility]);
    if (iter == featureMap.end()) {
        RS_LOGD("AccessibilityParamParse stop parsing, no initializing param map");
        return PARSE_NO_PARAM;
    }

    accessibilityParam_ = std::static_pointer_cast<AccessibilityParam>(iter->second);

    if (accessibilityParam_ == nullptr) {
        RS_LOGD("accessibilityParam_ is nullptr");
        return PARSE_ERROR;
    }
    
    // Start Parse Feature Params
    int xmlParamType = GetXmlNodeAsInt(*currNode);
    auto name = ExtractPropertyValue("name", *currNode);
    auto val = ExtractPropertyValue("value", *currNode);
    if (xmlParamType == PARSE_XML_FEATURE_MULTIPARAM) {
        bool isEnabled = ParseFeatureSwitch(val);
        if (name == "HighContrastEnabled") {
            accessibilityParam_->SetHighContrastEnabled(isEnabled);
            RS_LOGI("AccessibilityParamParse parse HighContrastEnabled %{public}d",
                    accessibilityParam_->IsHighContrastEnabled());
        } else if (name == "CurtainScreenEnabled") {
            accessibilityParam_->SetCurtainScreenEnabled(isEnabled);
            RS_LOGI("AccessibilityParamParse parse CurtainScreenEnabled %{public}d",
                    accessibilityParam_->IsCurtainScreenEnabled());
        } else if (name == "ColorReverseEnabled") {
            accessibilityParam_->SetColorReverseEnabled(isEnabled);
            RS_LOGI("AccessibilityParamParse parse ColorReverseEnabled %{public}d",
                    accessibilityParam_->IsColorReverseEnabled());
        } else if (name == "ColorCorrectionEnabled") {
            accessibilityParam_->SetColorCorrectionEnabled(isEnabled);
            RS_LOGI("AccessibilityParamParse parse ColorCorrectionEnabled %{public}d",
                    accessibilityParam_->IsColorCorrectionEnabled());
        } else {
            RS_LOGI("AccessibilityParamParse parse %{public}s is not support!", name.c_str());
        }
    }

    return PARSE_EXEC_SUCCESS;
}

} // namespace OHOS::Rosen