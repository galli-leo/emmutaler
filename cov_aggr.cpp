#include <iostream>
#include <sys/mman.h>
#include <map>
#include <unistd.h>
#include <vector>
#include <filesystem>
#include <stdio.h>
#include <fcntl.h>

#define PAGE_SIZE (0x1000)
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

static uint64_t start_addr;
static uint64_t end_addr;

std::map<std::string, std::string> SPECIAL_FUZZERS = {
    {"fuzzer0", "main"},
    {"fuzzer1", "comp_cov"},
    {"fuzzer2", "comp_cov_lib"},
    {"fuzzer3", "qasan"},
    {"fuzzer4", "cmp_log"}
};

template<typename I>
struct mmaped_file
{
public:
    std::string path;
    size_t size;
    bool create;
    int fd;
    void* addr;
    I* hitmap;
    size_t real_size;

    mmaped_file<I>();
    mmaped_file<I>(std::string path, size_t size, bool create) : path(path), size(size), create(create) {};
    bool open_file();
    void close_file();
};

template<typename I>
bool mmaped_file<I>::open_file()
{
    int flags = 0;
    if (create) {
        flags |= O_CREAT | O_TRUNC | O_RDWR;
    } else {
        flags |= O_RDONLY;
    }
    fd = open(path.c_str(), flags, 0666);
    if (fd == -1)
    {
        fprintf(stderr, "failed to open %s\n", path.c_str());
        return false;
    }

    size_t hitmap_size = sizeof(I)*size + sizeof(uint64_t);
    size_t hitmap_real_size = ROUND_UP(hitmap_size, PAGE_SIZE);
    // fprintf(stderr, "hitmap_size: 0x%lx, aligned size: 0x%lx", hitmap_size, hitmap_real_size);

    if (create)
    {
        int res = ftruncate(fd, hitmap_real_size);
        if (res == -1)
        {
            fprintf(stderr, "failed to truncate file\n");
            close(fd);
            return false;
        }
    }

    int prot = PROT_READ;
    if (create)
    {
        prot |= PROT_WRITE;
    }

    addr = mmap(0, hitmap_real_size, prot, MAP_SHARED, fd, 0);
    if (addr == (void*)-1)
    {
        fprintf(stderr, "failed to mmap file\n");
        return false;
    }

    uint64_t* hitmap_ptr = (uint64_t*)addr;
    if (create)
        *hitmap_ptr = (uint64_t)start_addr;
    hitmap = (I*)((unsigned char*)addr + sizeof(uint64_t));

    return true;
}

template<typename I>
void mmaped_file<I>::close_file()
{
    msync(addr, real_size, MS_SYNC);
    munmap(addr, real_size);
    close(fd);
}

void aggregate_coverage(std::string outpath, std::vector<std::string>& input_files)
{
    mmaped_file<uint32_t> outfile(outpath, end_addr - start_addr, true);
    if (!outfile.open_file())
    {
        fprintf(stderr, "failed to open output file at %s\n", outpath.c_str());
        return;
    }

    for (auto & elem : input_files)
    {
        mmaped_file<uint16_t> currfile(elem, end_addr - start_addr, false);
        if (!currfile.open_file())
        {
            fprintf(stderr, "failed to open input file at %s\n", elem.c_str());
            continue;
        }
        std::cout << "Aggregating for " << elem << std::endl;
        for (size_t i = 0; i < currfile.size; i++)
        {
            outfile.hitmap[i] += currfile.hitmap[i];
            // std::cout << "aggregated at " << i << std::endl;
        }
        currfile.close_file();
    }
    std::cout << "Finished writing coverage to " << outpath << std::endl;
    outfile.close_file();
}


int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " coverage_dir output_dir" << std::endl;
        return 1;
    }
    start_addr = 0x0000000100000000;
    end_addr = start_addr + 0x25390;
    char* input_dir = argv[1];
    char* output_dir = argv[2];
    std::filesystem::path outpath(output_dir);
    std::vector<std::string> all_files;
    for (auto& fuzzer : std::filesystem::directory_iterator(input_dir))
    {
        if (!fuzzer.is_directory()) continue;
        std::string fuzzer_name = fuzzer.path().filename();
        auto find = SPECIAL_FUZZERS.find(fuzzer_name);
        std::vector<std::string> fuzzer_files;
        bool special_fuzzer = false;
        std::string special_name;
        if (find != SPECIAL_FUZZERS.end())
        {
            std::cout << "Special Fuzzer: " << find->second << std::endl;
            special_name = find->second;
            special_fuzzer = true;
        }

        for (auto& cov_file : std::filesystem::directory_iterator(fuzzer.path()))
        {
            all_files.push_back(cov_file.path().string());
            if (special_fuzzer)
            {
                fuzzer_files.push_back(cov_file.path().string());
            }
        }
        if (special_fuzzer)
        {
            special_name.append(".cov");
            auto special_outpath = outpath / special_name;
            std::cout << "Writing special fuzzer to " << special_outpath.string() << std::endl;
            aggregate_coverage(special_outpath, fuzzer_files);
        }
    }

    aggregate_coverage((outpath / "all.cov").string(), all_files);
    return 0;
}