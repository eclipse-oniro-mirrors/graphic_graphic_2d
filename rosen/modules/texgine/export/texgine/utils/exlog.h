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

#ifndef ROSEN_MODULES_TEXGINE_EXPORT_TEXGINE_UTILS_EXLOG_H
#define ROSEN_MODULES_TEXGINE_EXPORT_TEXGINE_UTILS_EXLOG_H

#include "logger.h"

namespace OHOS {
namespace TextEngine {
void ExTime(Logger &logger, enum Logger::LOG_PHASE phase);

// exlog
#define LOGNEX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    Logger::NoReturn, Logger::Continue, Logger::FileLog, "exlog", NULL)
#define LOGCEX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    Logger::Continue, Logger::FileLog, "exlog", NULL)
#define LOG0EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    Logger::FileLog, "exlog", NULL)
#define LOG1EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    ExTime, Logger::Func, Logger::FileLog, "exlog", NULL)
#define LOG2EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    ExTime, Logger::FuncLine, Logger::FileLog, "exlog", NULL)
#define LOG3EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    ExTime, Logger::FileLine, Logger::FileLog, "exlog", NULL)
#define LOG4EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    ExTime, Logger::FileFuncLine, Logger::FileLog, "exlog", NULL)
#define LOG5EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    Logger::PidTid, Logger::FileLog, "exlog", NULL)
#define LOG6EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    ExTime, Logger::PidTid, Logger::Func, Logger::FileLog, "exlog", NULL)
#define LOG7EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    ExTime, Logger::PidTid, Logger::FuncLine, Logger::FileLog, "exlog", NULL)
#define LOG8EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    ExTime, Logger::PidTid, Logger::FileLine, Logger::FileLog, "exlog", NULL)
#define LOG9EX(level, ...) Logger(LOGGER_ARG(level), ##__VA_ARGS__, \
    ExTime, Logger::PidTid, Logger::FileFuncLine, Logger::FileLog, "exlog", NULL)

#ifdef TEXGINE_ENABLE_DEBUGLOG
#define LOGNEX_DEBUG(...) LOGNEX(DEBUG, ##__VA_ARGS__)
#define LOGCEX_DEBUG(...) LOGCEX(DEBUG, ##__VA_ARGS__)
#define LOG0EX_DEBUG(...) LOG0EX(DEBUG, ##__VA_ARGS__)
#define LOG1EX_DEBUG(...) LOG1EX(DEBUG, ##__VA_ARGS__)
#define LOG2EX_DEBUG(...) LOG2EX(DEBUG, ##__VA_ARGS__)
#define LOG3EX_DEBUG(...) LOG3EX(DEBUG, ##__VA_ARGS__)
#define LOG4EX_DEBUG(...) LOG4EX(DEBUG, ##__VA_ARGS__)
#define LOG5EX_DEBUG(...) LOG5EX(DEBUG, ##__VA_ARGS__)
#define LOG6EX_DEBUG(...) LOG6EX(DEBUG, ##__VA_ARGS__)
#define LOG7EX_DEBUG(...) LOG7EX(DEBUG, ##__VA_ARGS__)
#define LOG8EX_DEBUG(...) LOG8EX(DEBUG, ##__VA_ARGS__)
#define LOG9EX_DEBUG(...) LOG9EX(DEBUG, ##__VA_ARGS__)
#else
#define LOGNEX_DEBUG(...) NoLogger()
#define LOGCEX_DEBUG(...) NoLogger()
#define LOG0EX_DEBUG(...) NoLogger()
#define LOG1EX_DEBUG(...) NoLogger()
#define LOG2EX_DEBUG(...) NoLogger()
#define LOG3EX_DEBUG(...) NoLogger()
#define LOG4EX_DEBUG(...) NoLogger()
#define LOG5EX_DEBUG(...) NoLogger()
#define LOG6EX_DEBUG(...) NoLogger()
#define LOG7EX_DEBUG(...) NoLogger()
#define LOG8EX_DEBUG(...) NoLogger()
#define LOG9EX_DEBUG(...) NoLogger()
#endif
} // namespace TextEngine
} // namespace OHOS

#endif // ROSEN_MODULES_TEXGINE_EXPORT_TEXGINE_UTILS_EXLOG_H
