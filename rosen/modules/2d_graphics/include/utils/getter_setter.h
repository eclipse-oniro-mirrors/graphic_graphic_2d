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

#ifndef GETTER_SETTER_H
#define GETTER_SETTER_H

#define SETTER(NAME, TYPE, MEMBER)  \
    void NAME(TYPE newval)          \
    {                               \
        MEMBER = newval;            \
    }

#define REF_SETTER(NAME, TYPE, MEMBER)  \
    void NAME(const TYPE& newval)       \
    {                                   \
        MEMBER = newval;                \
    }

#define GETTER(NAME, TYPE, MEMBER)  \
    TYPE NAME() const               \
    {                               \
        return MEMBER;              \
    }

#define REF_GETTER(NAME, TYPE, MEMBER)  \
    TYPE& NAME()                        \
    {                                   \
        return MEMBER;                  \
    }

#define CONST_REF_GETTER(NAME, TYPE, MEMBER)    \
    const TYPE& NAME() const                    \
    {                                           \
        return MEMBER;                          \
    }

#define MOVE_SETTER(NAME, TYPE, MEMBER) \
    void NAME(TYPE&& newval)            \
    {                                   \
        MEMBER = std::move(newval);     \
    }
#endif // GETTER_SETTER_H