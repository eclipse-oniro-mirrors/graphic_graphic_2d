/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_SYMBOL_NODE_CONFIG_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_SYMBOL_NODE_CONFIG_H

#include "symbol_animation_config.h"

namespace OHOS {
namespace Rosen {

struct AnimationNodeConfig {
    TextEngine::SymbolNode symbolNode;
    NodeId nodeId = 0;
    int animationIndex = -1;
};
}
}

#endif