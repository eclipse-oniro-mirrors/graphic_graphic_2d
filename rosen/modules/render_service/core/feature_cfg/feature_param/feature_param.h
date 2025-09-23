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

#ifndef FEATURE_PARAM_H
#define FEATURE_PARAM_H

#include <string>
#include <unordered_map>

#include <libxml/parser.h>
#include <libxml/tree.h>

namespace OHOS::Rosen {
const std::vector<std::string> FEATURE_CONFIGS = {
    "DirtyRegionConfig",
    "ColorGamutConfig",
    "DrmConfig",
    "SpecialLayerConfig",
    "HardCursorConfig",
    "HwcConfig",
    "MemConfig",
    "OcclusionCullingConfig",
    "MultiScreenConfig",
    "OPIncConfig",
    "UIFirstConfig",
    "DvsyncConfig",
    "CaptureConfig",
    "SurfaceCaptureConfig",
    "UICaptureConfig",
    "FilterConfig",
    "SocperfConfig",
    "VRateConfig",
    "AccessibilityConfig",
    "RotateOffScreenConfig",
    "HfbcConfig",
    "SubtreeConfig",
};

enum FeatureModule {
    DIRTYREGION = 0,
    COLOR_GAMUT,
    DRM,
    SPECIALLAYER,
    HARDCURSOR,
    HWC,
    MEM,
    OCCLUSION_CULLING,
    MULTISCREEN,
    OPInc,
    UIFirst,
    DVSYNC,
    CAPTURE_BASE,
    SURFACE_CAPTURE,
    UI_CAPTURE,
    FILTER,
    SOC_PERF,
    VRATE,
    ACCESSIBILITY,
    PREVALIDATE,
    ROTATEOFFSCREEN,
    HFBC,
    SUBTREEPARALLEL,
    // Do not change it.
    ENUM_LENGTH,
};

enum ParseErrCode {
    PARSE_ERROR = -1,

    PARSE_EXEC_SUCCESS = 0,

    PARSE_NO_PARAM = 100,

    PARSE_SYS_FILE_LOAD_FAIL = 200,
    PARSE_PROD_FILE_LOAD_FAIL,
    PARSE_GET_ROOT_FAIL,
    PARSE_GET_CHILD_FAIL,
    PARSE_INTERNAL_FAIL,
};

class FeatureParam {
public:
    FeatureParam() = default;
    ~FeatureParam() = default;

private:
    void Init();
};
} // namespace OHOS::Rosen
#endif // FEATURE_PARAM_H