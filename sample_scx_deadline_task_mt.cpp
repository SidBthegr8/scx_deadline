// fib_sched_ext.cpp
// Compile: g++ -std=c++17 fib_sched_ext.cpp -o fib_sched_ext -lpthread
// Run: sudo ./fib_sched_ext 200

#include <iostream>
#include <algorithm>
#include <string>
#include <vector>
#include <cstring>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <thread>
#include <mutex>

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>

#include "scx_deadline_helpers.h"

// -------------------------------
// Attempt to set scheduling class
// -------------------------------
int try_set_sched_ext(int pid) {
#ifndef SCHED_EXT
#define SCHED_EXT 7  // Fallback value (used by recent Linux kernels)
#endif

    struct sched_param sp;
    sp.sched_priority = 0;

    if (sched_setscheduler(pid, SCHED_EXT, &sp) == -1) {
        std::cerr << "Warning: Failed to set SCHED_EXT scheduling for pid: "
                  << strerror(errno) << "\n";
        std::cerr << "This usually means the kernel doesn’t support SCHED_EXT "
                     "or privileges are insufficient.\n";
        return -1;
    }

    std::cout << "Successfully set scheduling policy to SCHED_EXT.\n";
    return 0;
}

// ----------------------------------
// Big integer addition using strings
// ----------------------------------
std::string add_big(const std::string& a, const std::string& b) {
    std::string result;
    int carry = 0;

    int i = (int)a.size() - 1;
    int j = (int)b.size() - 1;

    while (i >= 0 || j >= 0 || carry) {
        int da = (i >= 0 ? a[i--] - '0' : 0);
        int db = (j >= 0 ? b[j--] - '0' : 0);
        int sum = da + db + carry;
        carry = sum / 10;
        result.push_back((sum % 10) + '0');
    }

    std::reverse(result.begin(), result.end());
    return result;
}
// Global mutex to prevent console output interleaving
std::mutex cout_mutex;
// --------------------------------
// Compute nth Fibonacci as a string
// --------------------------------
std::string fibonacci_str(unsigned int n, int thread_num) {
    if (n == 0) return "0";
    if (n == 1 || n == 2) return "1";
    int tid = gettid();

    std::string a = "1";
    std::string b = "1";

    for (unsigned int i = 3; i <= n; ++i) {
        //if (i % 1000)
            //std::cout << "@" << i << std::endl;
        std::string c = add_big(a, b);
        a = b;
        b = c;

/*
        if (i%10000000)
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "[Thread " << thread_num << "(" << tid << ")" << "] running" << std::endl;
        }   
*/

    }

    return b;
}

void fib_thread(unsigned int n, int thread_num) {
    std::string fib = fibonacci_str(n,thread_num);
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "[Thread " << thread_num << "] Done\n";
    std::cout << "[Thread " << thread_num << "] F_" << n << " = " << fib << "\n";
    std::cout << "[Thread " << thread_num << "] Number of digits: " << fib.size() << "\n";
}

// Checks if a string consists only of digits
int is_digits(const char *str) {
    for (; *str; ++str)
        if (!isdigit((unsigned char)*str)) return 0;
    return 1;
}

std::vector<int> get_tids(pid_t pid)
{
    std::vector<int> tids;
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR *dir = opendir(path);
    if (!dir) {
        perror("opendir");
        return tids;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (entry->d_name[0] == '.')
            continue;
        if (is_digits(entry->d_name)) {
            int tid = atoi(entry->d_name);
            tids.push_back(tid);
        }
    }

    closedir(dir);
    return tids;
}

// -------------
// Entry point
// -------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <n> <num_threads>\n";
        return 1;
    }

    unsigned int n = std::stoul(argv[1]);
    unsigned int num_threads = std::stoul(argv[2]);

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(fib_thread, n, i+1);
    }

    pid_t pid = getpid();
    std::vector<int> tids = get_tids(pid);
    std::cout << "TIDs for PID " << pid << ": ";
    for (const auto& tid : tids)
    {
        std::cout << tid << ", ";
        
    }
    std::cout << std::endl;

    uint64_t rel_dl = 1e7;
    uint64_t rel_dl_set;
    
    for (int i = 0; i < tids.size(); i++)
    {
        if (i==0) continue;
        int tid = tids.at(i);
        set_rel_deadline(tid, rel_dl);
        rel_dl_set= get_rel_deadline(tid);
        std::cout << "Set releative deadline for " << tid << " to " << rel_dl_set << std::endl;
        rel_dl *= 2;
    }

    for (int i = 1; i < tids.size(); i++)
    {
        int tid = tids.at(i);
        try_set_sched_ext(tid);
        std::cout << "Set " << tid << " to SCHED_EXT" << std::endl;
    }

    for (auto& t : threads) t.join();

    return 0;
}

