#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <fstream>
#include <thread>
#include <chrono>
#include <iomanip>

constexpr auto META_RESERVED = 6;
constexpr auto RED = "\x1B[31m";
constexpr auto GRN = "\x1B[32m";
constexpr auto YEL = "\x1B[33m";
constexpr auto WHT = "\x1B[37m";

struct fclose_auto {
    void operator()(FILE* f) const noexcept {
        std::fclose(f);
    }
};

struct node {
    node(unsigned char _ch, int _weight) : ch(_ch), weight(_weight) {
        son_l = nullptr;
        son_r = nullptr;
        parent = nullptr;
        symb = true;
        used = false;
    }
    unsigned char ch;
    int weight;
    bool symb;
    bool used;
    node* son_l;
    node* son_r;
    node* parent;
};

struct d_node {
    d_node() {
        ch = '\0';
        son_l = nullptr;
        son_r = nullptr;
        parent = nullptr;
    }
    unsigned char ch;
    d_node* son_l;
    d_node* son_r;
    d_node* parent;
};

bool comp(node* n1, node* n2) {
    return n1->weight < n2->weight;
}

///////////////////////////////////////////////////////////////////////////////ARCHIVING/////////////////////////////////////////////////////////////

node* table_to_list(std::vector<unsigned char>& counts_table) {
    std::list<node*> list;
    for (int i = 0; i < 256; ++i) {
        if (counts_table[i])
            list.push_back(new node(i, counts_table[i]));
    }

    while (list.size() != 1) {
        list.sort(comp);
        node* s1 = *list.begin();
        list.pop_front();
        node* s2 = *list.begin();
        list.pop_front();

        node* parent = new node(' ', s1->weight + s2->weight);
        parent->son_l = s1;
        parent->son_r = s2;
        s1->parent = parent;
        s2->parent = parent;
        parent->symb = false;
        list.push_back(parent);
    }

    return list.front();
}

std::vector<std::string> list_to_tree(node* root, std::vector<unsigned char>& hash, int& size) {
    unsigned char count = 0;
    unsigned char buf = '\0';
    std::string code;
    std::vector<std::string> table(256);

    node* cur_root = root;
    while (true) {
        if (cur_root->son_l != nullptr && cur_root->son_l->used != true) {
            code.push_back('0');

            //std::cout << 0;

            buf = buf | (0 << (7 - count++));
            if (count == 8) {
                hash[size++] = buf;
                count = 0;
                buf = '\0';
            }
            cur_root = cur_root->son_l;
            cur_root->used = true;
        }
        else if (cur_root->son_r != nullptr && cur_root->son_r->used != true) {
            code.push_back('1');
            cur_root->used = true;
            cur_root = cur_root->son_r;
        }
        else {
            if (cur_root->symb == true) {
                table[cur_root->ch] = code;
                buf = buf | (1 << (7 - count++));

                //std::cout << 1;

                if (count == 8) {
                    hash[size++] = buf;
                    count = 0;
                    buf = '\0';
                }
                unsigned char letter = cur_root->ch;
                for (int i = 0; i < 8; ++i) {
                    int bit = 1 & letter >> (7 - i);

                    //std::cout << bit;

                    buf = buf | (bit << (7 - count++));
                    if (count == 8) {
                        hash[size++] = buf;
                        count = 0;
                        buf = '\0';
                    }
                }
            }
            cur_root->used = true;
            cur_root = cur_root->parent;
            if (cur_root == nullptr)
                break;
            code.pop_back();
        }
    }
    hash[size++] = buf;
    return table;
}

void encode(const char* input, int BLOCK_SIZE, std::shared_ptr<std::vector<unsigned char>> encoded_string, long long& total_read_bytes) {

    std::unique_ptr<FILE, fclose_auto> in_f(std::fopen(input, "rb"));
    encoded_string->reserve(BLOCK_SIZE);

    unsigned char* in_buffer = new unsigned char[BLOCK_SIZE * 4];

    while (true) {
        int read_bytes = std::fread(in_buffer, 1, BLOCK_SIZE, in_f.get());
        total_read_bytes += read_bytes;
        if (read_bytes == 0)
            break;

        std::vector<unsigned char> counts_table(256);
        for (int i = 0; i < read_bytes; ++i)
            if (counts_table[in_buffer[i]] != 255)
                ++counts_table[in_buffer[i]];

        node* root = table_to_list(counts_table);

        int size = 0;
        std::vector<unsigned char> hash(320);
        std::vector<std::string> table = list_to_tree(root, hash, size);

        std::vector<unsigned char> encoded_string_tmp(META_RESERVED, '\0');
        encoded_string_tmp.reserve(BLOCK_SIZE);

        for (int i = 0; i < size; ++i)
            encoded_string_tmp.push_back(hash[i]);

        unsigned char buf = '\0';
        int count = 0;
        for (int i = 0; i < read_bytes; ++i) {
            unsigned char c = in_buffer[i];
            std::string tmp = table[c];
            for (int j = 0; j < tmp.size(); ++j) {
                int tmpi = static_cast<int>(tmp[j] - 48);
                buf = buf | (tmpi << (7 - count++));
                if (count == 8) {
                    encoded_string_tmp.push_back(buf);
                    count = 0;
                    buf = '\0';
                }
            }
        }
        encoded_string_tmp.push_back(buf);

        // META FILLING ///////////////////////////////////

        encoded_string_tmp[0] = size / 256;
        encoded_string_tmp[1] = size % 256;
        encoded_string_tmp[2] = (encoded_string_tmp.size() - META_RESERVED - size) / 65536;
        encoded_string_tmp[3] = (encoded_string_tmp.size() - META_RESERVED - size) / 256;
        encoded_string_tmp[4] = (encoded_string_tmp.size() - META_RESERVED - size) % 256;
        encoded_string_tmp[5] = count;

        ///////////////////////////////////////////////////

        for (int i = 0; i < encoded_string_tmp.size(); ++i)
            encoded_string->push_back(encoded_string_tmp[i]);
    }    
    delete[] in_buffer;
}

void archive(const char* input, const char* output, int User_block_size = 0) {
    auto start = std::chrono::high_resolution_clock::now();

    std::cout << "====================Encoding started====================\n";

    long long total_read_bytes = 0;
    long long total_written_bytes = 0;     

    std::unique_ptr<FILE, fclose_auto> out_f(std::fopen(output, "wb"));
    std::chrono::duration<double> diff_interrupt(0);
    std::string CMPSN = GRN;

    std::vector<std::shared_ptr<std::vector<unsigned char>>> strings(7);
    strings[0] = std::make_shared<std::vector<unsigned char>>(*(new std::vector<unsigned char>(1, 0))); // user size
    strings[1] = std::make_shared<std::vector<unsigned char>>(*(new std::vector<unsigned char>(1, 4)));
    strings[2] = std::make_shared<std::vector<unsigned char>>(*(new std::vector<unsigned char>(1, 8)));
    strings[3] = std::make_shared<std::vector<unsigned char>>(*(new std::vector<unsigned char>(1, 16)));
    strings[4] = std::make_shared<std::vector<unsigned char>>(*(new std::vector<unsigned char>(1, 32)));
    strings[5] = std::make_shared<std::vector<unsigned char>>(*(new std::vector<unsigned char>(1, 48)));
    strings[6] = std::make_shared<std::vector<unsigned char>>(*(new std::vector<unsigned char>(1, 64)));

    long long cur_min = 1e18;
    int proper_index = 0;

    if (User_block_size != 0) {
        if (User_block_size > 256 || User_block_size < 0) {
            std::cout << "Incorrect block size. Chosen 256KB.\n";
            User_block_size = 256;
        }
        strings[0]->operator[](0) = User_block_size % 256;
        encode(input, 1024 * User_block_size, strings[0], std::ref(total_read_bytes));
        cur_min = strings[0]->size();
        std::cout << GRN << "Bytes read: " << total_read_bytes << '\n' << WHT;
        std::cout << "Block size / Zip size\n";
        std::cout << User_block_size << "KB: " << strings[0]->size() << '\n';
    }
    else {
        std::thread mod4 (encode, input, 1024 * 4,  strings[1], std::ref(total_read_bytes));
        std::thread mod8 (encode, input, 1024 * 8,  strings[2], std::ref(total_read_bytes));
        std::thread mod16(encode, input, 1024 * 16, strings[3], std::ref(total_read_bytes));
        std::thread mod32(encode, input, 1024 * 32, strings[4], std::ref(total_read_bytes));
        std::thread mod48(encode, input, 1024 * 48, strings[5], std::ref(total_read_bytes));
        std::thread mod64(encode, input, 1024 * 64, strings[6], std::ref(total_read_bytes));

        mod4.join();
        mod8.join();
        mod16.join();
        mod32.join();
        mod48.join();
        mod64.join();

        total_read_bytes /= static_cast<long long>(strings.size()) - 1;
        std::cout << GRN << "Bytes read: " << total_read_bytes << '\n' << WHT;
        std::cout << "Block sizes / Zip sizes\n";
        std::cout << "4Kb:  " << strings[1]->size() << "b\n";
        std::cout << "8Kb:  " << strings[2]->size() << "b\n";
        std::cout << "16Kb: " << strings[3]->size() << "b\n";
        std::cout << "32Kb: " << strings[4]->size() << "b\n";
        std::cout << "48Kb: " << strings[5]->size() << "b\n";
        std::cout << "64Kb: " << strings[6]->size() << "b\n";

        for (int i = 1; i < strings.size(); ++i) {
            if (strings[i]->size() < cur_min) {
                cur_min = strings[i]->size();
                proper_index = i;
            }
        }
    }

    if (cur_min < total_read_bytes) {
        std::cout << "Block size chosen: " << static_cast<int>(strings[proper_index]->operator[](0)) << "Kb\n";
        for (int i = 0; i < strings[proper_index]->size(); ++i)
            total_written_bytes += std::fwrite(&strings[proper_index]->operator[](i), sizeof(char), 1, out_f.get());
    }
    else {
        CMPSN = YEL;
        std::cout << RED << "Impossible to zip this file. Do you want to zip it anyway ? (enter \"yes\"/\"no\")\n" << YEL;
        std::string ans;
        auto start_interrupt = std::chrono::high_resolution_clock::now();
        std::cin >> ans;
        auto end_interrupt = std::chrono::high_resolution_clock::now();
        diff_interrupt = end_interrupt - start_interrupt;
        if (ans == "yes") {
            for (int i = 0; i < strings[proper_index]->size(); ++i)
                total_written_bytes += std::fwrite(&strings[proper_index]->operator[](i), sizeof(char), 1, out_f.get());
        }
        else {
            std::cout << YEL << "File wasn't changed\n" << WHT;
            std::cout << "====================Encoding ended====================\n\n";
            return;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start - diff_interrupt;
    std::cout.precision(4);
    std::cout << GRN << "\nSuccessful archiving!\n";
    std::cout << std::fixed << WHT << "Bytes read: " << GRN << total_read_bytes << WHT << "\nBytes written: " << GRN << total_written_bytes <<
        WHT << "\nFile compression: " << CMPSN << static_cast<double>(total_read_bytes - total_written_bytes) * 100.0 / total_read_bytes << "%\n";

    std::cout << WHT << "Archiving: " << GRN << diff.count() << " sec\n" << WHT;
    std::cout << "====================Encoding ended====================\n\n";
}

///////////////////////////////////////////////////////////////////////////////UNZIP/////////////////////////////////////////////////////////////////

std::vector<d_node> restore_tree(unsigned char* inzip_buffer, int hash_size) {
    int count = 0;
    int size = 0;
    
    std::vector<d_node> root(512);
    d_node* cur_root = &root[size++];
    for (int i = 0; i < hash_size;) {
        bool exit = false;
        if (cur_root == nullptr) {
            std::cerr << RED << "Decoding failed! Maybe this file was archived incorrectly...\n" << WHT;
            return {};
        }
        while (cur_root->son_l != nullptr && cur_root->son_r != nullptr) {
            cur_root = cur_root->parent;
            if (cur_root == nullptr) {
                exit = true;
                break;
            }
        }
        if (exit)
            break;

        unsigned char byte = inzip_buffer[i];
        bool b = 1 & (byte >> (7 - count++));
        if (count == 8) {
            ++i;
            count = 0;
        }

        //std::cout << static_cast<int>(b);

        if (b == 0) {
            if (cur_root->son_l != nullptr) {
                cur_root->son_r = &root[size++];
                cur_root->son_r->parent = cur_root;
                cur_root = cur_root->son_r;
            }
            cur_root->son_l = &root[size++];
            cur_root->son_l->parent = cur_root;
            cur_root = cur_root->son_l;
        }
        else {
            if (cur_root->son_l != nullptr) {
                cur_root->son_r = &root[size++];
                cur_root->son_r->parent = cur_root;
                cur_root = cur_root->son_r;
            }
            cur_root->ch = '\0';
            for (int k = 0; k < 8; ++k) {
                unsigned char tmp = inzip_buffer[i];
                int bit = 1 & tmp >> (7 - count++);
                cur_root->ch = (cur_root->ch | (bit << (7 - k)));

                //std::cout << static_cast<int>(bit);

                if (count == 8) {
                    ++i;
                    count = 0;
                }
            }
            cur_root = cur_root->parent;
        }
    }
    return root;
}

void unzip(const char* input, const char* output) {

    //////////////////////////////////////////////////////////
    //                                                      //
    //  [first byte of zip file] - block size (entire file) //
    //  BLOCK STRUCTURE:                                    //
    //  [0][1] - hash size (MAX SIZE: 320 bytes)            //
    //  [2][3][4] - main size                               //
    //  [5]    - main tail                                  //
    //  [6]~[hash size] - hash_tree                         //
    //  [hash size + 6]~[main size + 6] - encoded data      //
    //                                                      //
    //////////////////////////////////////////////////////////

    auto start = std::chrono::high_resolution_clock::now();

    std::cout << "====================Decoding started==================\n";

    std::unique_ptr<FILE, fclose_auto> inzip_f(std::fopen(input, "rb"));
    std::unique_ptr<FILE, fclose_auto> outzip_f(std::fopen(output, "wb"));

    long long total_read_bytes = 0;
    long long total_written_bytes = 0;

    int base = 1024;
    unsigned char mod = 0;
    int BLOCK_SIZE = 0;
    total_read_bytes += std::fread(&mod, 1, 1, inzip_f.get());
    if (mod == 0) {
        BLOCK_SIZE = base * 256;
    }
    else {
        BLOCK_SIZE = base * mod;
    }
     
    unsigned char* inzip_meta = new unsigned char[META_RESERVED];
    unsigned char* inzip_buffer = new unsigned char[BLOCK_SIZE * 4];

    while (true) {        

        std::size_t readzip_meta = std::fread(inzip_meta, 1, META_RESERVED, inzip_f.get());
        if (readzip_meta == 0)
            break;

        int hash_size = inzip_meta[0] * 256 + inzip_meta[1];
        int main_size = inzip_meta[2] * 65536 + inzip_meta[3] * 256 + inzip_meta[4];
        unsigned char main_tail = inzip_meta[5];

        std::size_t readzip_bytes = std::fread(inzip_buffer, 1, main_size + hash_size, inzip_f.get());
        total_read_bytes += static_cast<long long>(readzip_meta + readzip_bytes);

        std::vector<d_node> root = restore_tree(inzip_buffer, hash_size);
        if (root.size() == 0)
            return;

        d_node* cur_root = &root[0];
        unsigned char buf;
        int byte_size = 8;
        for (int i = hash_size; i < readzip_bytes; ++i) {
            buf = inzip_buffer[i];

            if (i == readzip_bytes - 1)
                byte_size = main_tail;

            for (int count = 0; count < byte_size; ++count) {
                bool b = buf & (1 << (7 - count));
                if (b == true) {
                    cur_root = cur_root->son_r;
                }
                else {
                    cur_root = cur_root->son_l;
                }
                if (cur_root->son_l == nullptr && cur_root->son_r == nullptr) {
                    total_written_bytes += std::fwrite(&cur_root->ch, sizeof(char), 1, outzip_f.get());
                    cur_root = &root[0];
                }
            }
        }
    }      

    delete[] inzip_meta;
    delete[] inzip_buffer;

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    std::cout.precision(4);
    std::cout << GRN << "Successful unzip!\n";
    std::cout << std::fixed << WHT << "Bytes read: " << GRN << total_read_bytes << WHT << "\nBytes written: " << GRN << total_written_bytes;
    std::cout << WHT << "\nUnzip: " << GRN << diff.count() << " sec\n" << WHT;
    std::cout << "====================Decoding ended====================\n\n";
}

///////////////////////////////////////////////////////////////////////////////MAIN//////////////////////////////////////////////////////////////////

int main() {

    for (int i = 0; i < 1; ++i) {
        archive("tests/originals/photo1.jpg", "test_zip.bin");
        unzip("test_zip.bin", "tests/decoded/photo1_d.jpg");
    }

    return 0;
}
