#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <fstream>

#define META_RESERVED 5
#define BLOCK_SIZE 1024 * 32

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

std::vector<std::string> list_to_tree(node* root, std::vector<unsigned char>& hash, int& size, bool DEBUG = false) {
    unsigned char count = 0;
    unsigned char buf = '\0';
    std::string code;
    std::vector<std::string> table(256);

    node* cur_root = root;
    while (true) {
        if (cur_root->son_l != nullptr && cur_root->son_l->used != true) {
            code.push_back('0');

            if (DEBUG) std::cout << 0;

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

                if (DEBUG) std::cout << 1;

                if (count == 8) {
                    hash[size++] = buf;
                    count = 0;
                    buf = '\0';
                }
                unsigned char letter = cur_root->ch;
                for (int i = 0; i < 8; ++i) {
                    int bit = 1 & letter >> (7 - i);

                    if (DEBUG) std::cout << bit;

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

struct fclose_auto {
    void operator()(FILE* f) const noexcept {
        std::fclose(f);
    }
};

void encode_huffman(const char* input, const char* output) {
    
    std::cout << "\nEncoding started\n";

    int total_read_bytes = 0;
    int total_written_bytes = 0;
    std::unique_ptr<FILE, fclose_auto> in_f(std::fopen(input, "rb"));
    std::unique_ptr<FILE, fclose_auto> out_f(std::fopen(output, "wb"));
    unsigned char* in_buffer = new unsigned char[BLOCK_SIZE];

    while (true) {
        std::size_t written_bytes = 0;
        std::size_t read_bytes = std::fread(in_buffer, 1, BLOCK_SIZE, in_f.get());
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

        std::vector<unsigned char> encoded_string(META_RESERVED, '\0');
        encoded_string.reserve(BLOCK_SIZE);

        for (int i = 0; i < size; ++i)
            encoded_string.push_back(hash[i]);

        unsigned char buf = '\0';
        int count = 0;
        for (int i = 0; i < read_bytes; ++i) {
            unsigned char c = in_buffer[i];
            std::string tmp = table[c];
            for (int j = 0; j < tmp.size(); ++j) {
                int tmpi = static_cast<int>(tmp[j] - 48);
                buf = buf | (tmpi << (7 - count++));
                if (count == 8) {
                    encoded_string.push_back(buf);
                    count = 0;
                    buf = '\0';
                }
            }
        }
        encoded_string.push_back(buf);

        // META FILLING ///////////////////////////////////

        encoded_string[0] = size / 256;
        encoded_string[1] = size % 256;
        encoded_string[2] = (encoded_string.size() - META_RESERVED - size) / 256;
        encoded_string[3] = (encoded_string.size() - META_RESERVED - size) % 256;
        encoded_string[4] = count;

        ///////////////////////////////////////////////////

        for (int i = 0; i < encoded_string.size(); ++i)
            written_bytes += std::fwrite(&encoded_string[i], sizeof(char), 1, out_f.get());
        total_read_bytes += read_bytes;
        total_written_bytes += written_bytes;
    }   

    std::cout.precision(4);
    std::cout << std::fixed << "\nBytes read: " << total_read_bytes << "\nBytes written: " << total_written_bytes <<
        "\nFile compression: " << static_cast<double>(total_read_bytes - total_written_bytes) * 100.0 / total_read_bytes << "%\n";
}

d_node* restore_tree(unsigned char* inzip_buffer, int hash_size, bool DEBUG) {
    int count = 0;
    d_node* root = new d_node;
    d_node* cur_root = root;
    for (int i = 0; i < hash_size;) {
        bool exit = false;
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

        if (DEBUG) std::cout << static_cast<int>(b);

        if (b == 0) {
            if (cur_root->son_l != nullptr) {
                cur_root->son_r = new d_node;
                cur_root->son_r->parent = cur_root;
                cur_root = cur_root->son_r;
            }
            cur_root->son_l = new d_node;
            cur_root->son_l->parent = cur_root;
            cur_root = cur_root->son_l;
        }
        else {
            if (cur_root->son_l != nullptr) {
                cur_root->son_r = new d_node;
                cur_root->son_r->parent = cur_root;
                cur_root = cur_root->son_r;
            }
            cur_root->ch = '\0';
            for (int k = 0; k < 8; ++k) {
                unsigned char tmp = inzip_buffer[i];
                int bit = 1 & tmp >> (7 - count++);
                cur_root->ch = cur_root->ch | (bit << (7 - k));

                if (DEBUG) std::cout << static_cast<int>(bit);

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

void decode_huffman(const char* input, const char* output, bool DEBUG = false) noexcept {

    //////////////////////////////////////////////////////////
    //                                                      //
    //  BLOCK STRUCTURE:                                    //
    //  [0][1] - hash size (MAX SIZE: 320 bytes)            //
    //  [2][3] - main size                                  //
    //  [4]    - main tail                                  //
    //  [5]~[hash size] - hash_tree                         //
    //  [hash size + 5]~[main size + 5] - encoded data      //
    //                                                      //
    //////////////////////////////////////////////////////////

    std::cout << "\nDecoding started\n";

    int total_read_bytes = 0;
    int total_written_bytes = 0;

    std::unique_ptr<FILE, fclose_auto> inzip_f(std::fopen(input, "rb"));
    std::unique_ptr<FILE, fclose_auto> outzip_f(std::fopen(output, "wb"));
    unsigned char* inzip_meta = new unsigned char[META_RESERVED];
    unsigned char* inzip_buffer = new unsigned char[BLOCK_SIZE];

    while (true) {

        std::size_t readzip_meta = std::fread(inzip_meta, 1, META_RESERVED, inzip_f.get());
        if (readzip_meta == 0)
            break;

        int hash_size = inzip_meta[0] * 256 + inzip_meta[1];
        int main_size = inzip_meta[2] * 256 + inzip_meta[3];
        unsigned char main_tail = inzip_meta[4];

        std::size_t readzip_bytes = std::fread(inzip_buffer, 1, main_size + hash_size, inzip_f.get());
        total_read_bytes += readzip_meta + readzip_bytes;

        d_node* root = restore_tree(inzip_buffer, hash_size, DEBUG);

        d_node* cur_root = root;
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
                    cur_root = root;
                }
            }
        }
        delete[] root;
    }      

    std::cout << std::fixed << "\nBytes read: " << total_read_bytes << "\nBytes written: " << total_written_bytes << "\n";
}

int main() {

    encode_huffman("testword.docx", "test_zip.bin");
    decode_huffman("test_zip.bin", "decword.docx");

    return 0;
}