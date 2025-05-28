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

#ifndef OHOS_ROSEN_TEXT_TEXT_EFFECT_H
#define OHOS_ROSEN_TEXT_TEXT_EFFECT_H

#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "typography.h"

namespace OHOS::Rosen {
enum class TextEffectAttribute {
    FLIP_DIRECTION = 0,
    BLUR_ENABLE,
};

enum class TextEffectState {
    START,
    STOP,
};

enum class TextEffectStrategy {
    FLIP,

    STRATEGY_BUTT
};

enum class TextEffectFlipDirection {
    UP,
    DOWN,
};

struct TypographyConfig {
    std::shared_ptr<Typography> typography{nullptr};
    std::pair<size_t, size_t> rawTextRange{0, 0};
};

class TextEffect {
public:
    virtual ~TextEffect() = default;
    virtual int UpdateEffectConfig(const std::unordered_map<TextEffectAttribute, std::string>& config) = 0;
    virtual int AppendTypography(const std::vector<TypographyConfig>& typographyConfigs) = 0;
    virtual void RemoveTypography(const std::vector<TypographyConfig>& typographyConfigs) = 0;
    virtual int UpdateTypography(std::shared_ptr<Typography> typography,
        const std::vector<TypographyConfig>& typographyConfigs) = 0;
    virtual void StartEffect(Drawing::Canvas* canvas, double x, double y) = 0;
    virtual void StopEffect(Drawing::Canvas* canvas, double x, double y) = 0;
};

class TextEffectFactory {
public:
    virtual ~TextEffectFactory() = default;
    virtual std::shared_ptr<TextEffect> CreateTextEffect() = 0;
};

class TextEffectFactoryCreator final {
public:
    static TextEffectFactoryCreator& GetInstance();
    ~TextEffectFactoryCreator() = default;
    bool RegisterFactory(TextEffectStrategy strategy, std::shared_ptr<TextEffectFactory> factory);
    std::shared_ptr<TextEffect> CreateTextEffect(TextEffectStrategy strategy) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        if (factoryTable_.find(strategy) == factoryTable_.end()) {
            return nullptr;
        }
        return factoryTable_[strategy]->CreateTextEffect();
    }

private:
    TextEffectFactoryCreator() = default;
    TextEffectFactoryCreator(const TextEffectFactoryCreator&) = delete;
    TextEffectFactoryCreator& operator=(const TextEffectFactoryCreator&) = delete;
    TextEffectFactoryCreator(TextEffectFactoryCreator&&) = delete;
    TextEffectFactoryCreator& operator=(TextEffectFactoryCreator&&) = delete;

    std::unordered_map<TextEffectStrategy, std::shared_ptr<TextEffectFactory>> factoryTable_;
    std::shared_mutex mutex_;
}

}

#endif // OHOS_ROSEN_TEXT_TEXT_EFFECT_H