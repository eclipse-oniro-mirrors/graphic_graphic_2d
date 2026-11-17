/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "src/core/SkLRUCache.h"

using namespace testing;
using namespace testing::ext;

namespace {
constexpr uint32_t DUPLICATE_KEY = 42;
constexpr int MAX_CACHE_COUNT = 4;
constexpr int CONCURRENT_THREAD_COUNT = 8;
constexpr int CONCURRENT_ITERATIONS = 1000;
constexpr uint32_t CONCURRENT_KEY_RANGE = 24;

using TestLRUCache = SkLRUCache<uint32_t, std::shared_ptr<std::string>>;

std::shared_ptr<std::string> MakeValue(uint32_t key)
{
    return std::make_shared<std::string>("value-" + std::to_string(key));
}

class SkLRUCacheTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: SkLRUCacheDuplicateInsert001
 * @tc.desc: Guard the UAF fixed in SkLRUCache::insert: simulates the
 *           FontCollection::CloneTypeface find/insert TOCTOU where two callers
 *           both miss on the same hash and both insert it. The duplicated
 *           insert must update the existing entry in place instead of
 *           orphaning it in the LRU list, otherwise a later insert of the
 *           same key makes the internal eviction delete the entry that
 *           insert() is about to return (heap-use-after-free on copy-out).
 * @tc.type: FUNC
 */
HWTEST_F(SkLRUCacheTest, SkLRUCacheDuplicateInsert001, TestSize.Level0)
{
    TestLRUCache cache(MAX_CACHE_COUNT);
    cache.insert(DUPLICATE_KEY, MakeValue(DUPLICATE_KEY));
    cache.insert(DUPLICATE_KEY, MakeValue(DUPLICATE_KEY));

    for (uint32_t k = 1; k <= static_cast<uint32_t>(MAX_CACHE_COUNT); k++) {
        cache.insert(100 + k, MakeValue(100 + k));
    }

    std::shared_ptr<std::string>* out = cache.insert(DUPLICATE_KEY, MakeValue(DUPLICATE_KEY));
    ASSERT_NE(out, nullptr);
    std::shared_ptr<std::string> copied = *out;
    EXPECT_NE(copied, nullptr);
    EXPECT_NE(cache.find(DUPLICATE_KEY), nullptr);
    EXPECT_LE(cache.count(), MAX_CACHE_COUNT);
}

/**
 * @tc.name: SkLRUCacheDuplicateInsert002
 * @tc.desc: A duplicate-key insert must not grow the cache: the existing
 *           entry is updated in place and stays the most recently used one.
 * @tc.type: FUNC
 */
HWTEST_F(SkLRUCacheTest, SkLRUCacheDuplicateInsert002, TestSize.Level0)
{
    TestLRUCache cache(MAX_CACHE_COUNT);
    cache.insert(9, MakeValue(9));
    cache.insert(9, MakeValue(9));
    EXPECT_EQ(cache.count(), 1);

    for (uint32_t k = 1; k <= 3; k++) {
        cache.insert(100 + k, MakeValue(100 + k));
    }
    EXPECT_EQ(cache.count(), MAX_CACHE_COUNT);
    EXPECT_NE(cache.find(9), nullptr);

    for (uint32_t k = 200; k < 220; k++) {
        cache.insert(k, MakeValue(k));
    }
    EXPECT_LE(cache.count(), MAX_CACHE_COUNT);
}

/**
 * @tc.name: SkLRUCacheEvictionOrder001
 * @tc.desc: Regular LRU behavior must be preserved: find promotes the entry
 *           and eviction removes the least recently used one.
 * @tc.type: FUNC
 */
HWTEST_F(SkLRUCacheTest, SkLRUCacheEvictionOrder001, TestSize.Level0)
{
    constexpr int kSize = 5;
    const int seq[] = {0, 1, 2, 3, 4, 1, 6, 2, 7, 5, 3, 2, 2, 3, 1, 7};
    const uint32_t expected[] = {7, 1, 3, 2, 5};
    SkLRUCache<int, std::shared_ptr<int>> cache(kSize);
    for (int key : seq) {
        if (!cache.find(key)) {
            cache.insert(key, std::make_shared<int>(key));
        }
    }
    ASSERT_EQ(cache.count(), kSize);
    for (uint32_t key : expected) {
        std::shared_ptr<int>* value = cache.find(key);
        ASSERT_NE(value, nullptr);
        EXPECT_EQ(**value, static_cast<int>(key));
    }
}

/**
 * @tc.name: SkLRUCacheConcurrentInsert001
 * @tc.desc: Stress the CloneTypeface race pattern: several "font collection
 *           instances" (independent find/clone/insert sequences) sharing one
 *           global cache. Duplicate inserts caused by the race must not
 *           corrupt the cache and the count must stay within the limit.
 * @tc.type: FUNC
 */
HWTEST_F(SkLRUCacheTest, SkLRUCacheConcurrentInsert001, TestSize.Level0)
{
    TestLRUCache cache(16);
    std::mutex cacheMutex;
    std::vector<std::thread> workers;
    for (int t = 0; t < CONCURRENT_THREAD_COUNT; t++) {
        workers.emplace_back([&cache, &cacheMutex, t]() {
            for (int i = 0; i < CONCURRENT_ITERATIONS; i++) {
                uint32_t key = static_cast<uint32_t>(i % CONCURRENT_KEY_RANGE);
                bool cached = false;
                {
                    std::lock_guard<std::mutex> lock(cacheMutex);
                    cached = cache.find(key) != nullptr;
                }
                if (!cached) {
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                    std::lock_guard<std::mutex> lock(cacheMutex);
                    cache.insert(key, std::make_shared<std::string>("t" + std::to_string(t)));
                }
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    EXPECT_LE(cache.count(), 16);
}
} // namespace
