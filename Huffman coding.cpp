#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <fstream>

#define META_RESERVED 5
#define BLOCK_SIZE 65536

typedef struct Node {
    Node(unsigned char _ch, int _weight) : ch(_ch), weight(_weight) {
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
    Node* son_l;
    Node* son_r;
    Node* parent;
} node ;

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

std::vector<std::string> list_to_tree(node* root, unsigned char* hash, int& size) {
    unsigned char count = 0;
    unsigned char buf = '\0';
    std::string code;
    std::vector<std::string> table(256);

    node* cur_root = root;
    while (true) {
        if (cur_root->son_l != nullptr && cur_root->son_l->used != true) {
            code.push_back('0');
            std::cout << 0;
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
                std::cout << 1;
                if (count == 8) {
                    hash[size++] = buf;
                    count = 0;
                    buf = '\0';
                }
                unsigned char letter = cur_root->ch;
                for (int i = 0; i < 8; ++i) {
                    int bit = 1 & letter >> (7 - i);
                    std::cout << bit;
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

void pack_huffman(const char* input, const char* output) {
    struct fclose_auto {
        void operator()(FILE* f) const noexcept {
            std::fclose(f);
        }
    };
    std::size_t written_bytes = 0;
    std::unique_ptr<FILE, fclose_auto> in_f(std::fopen(input, "rb"));
    std::unique_ptr<FILE, fclose_auto> out_f(std::fopen(output, "wb"));
    std::unique_ptr<unsigned char[]> in_buffer(new unsigned char[BLOCK_SIZE]);

    std::size_t read_bytes = std::fread(in_buffer.get(), 1, BLOCK_SIZE, in_f.get());

    std::vector<unsigned char> counts_table(256);

    for (auto ptr = in_buffer.get(); ptr != in_buffer.get() + read_bytes; ++ptr)
        if (counts_table[*ptr] != 255)
            ++counts_table[*ptr];

    node* root = table_to_list(counts_table);

    int size = 0;
    unsigned char* hash = new unsigned char[1024]{ '\0' };
    std::vector<std::string> table = list_to_tree(root, hash, size);
    
    std::vector<unsigned char> encoded_string(META_RESERVED, '\0');
    encoded_string.reserve(BLOCK_SIZE);

    for (int i = 0; i < size; ++i)
        encoded_string.push_back(hash[i]);

    unsigned char buf = '\0';
    int count = 0;
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        unsigned char c = in_buffer.get()[i];
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

    std::cout << "\nBytes read: " << read_bytes << "\nBytes written: " << written_bytes << "\n";
    return;
}

void decode_huffman(const char* input, const char* output) {
    struct fclose_auto {
        void operator()(FILE* f) const noexcept {
            std::fclose(f);
        }
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

    std::unique_ptr<FILE, fclose_auto> inzip_f(std::fopen(input, "rb"));
    std::unique_ptr<FILE, fclose_auto> outzip_f(std::fopen(output, "wb"));
    std::unique_ptr<unsigned char[]> inzip_meta(new unsigned char[META_RESERVED]);
    std::unique_ptr<unsigned char[]> inzip_buffer(new unsigned char[BLOCK_SIZE]);

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

    std::fread(inzip_meta.get(), 1, META_RESERVED, inzip_f.get());

    int hash_size = inzip_meta.get()[0] * 256 + inzip_meta.get()[1];
    int main_size = inzip_meta.get()[2] * 256 + inzip_meta.get()[3];
    unsigned char main_tail = inzip_meta.get()[4];

    std::size_t readzip_bytes = std::fread(inzip_buffer.get(), 1, main_size + hash_size + META_RESERVED, inzip_f.get());

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

        unsigned char byte = inzip_buffer.get()[i];
        bool b = 1 & (byte >> (7 - count++));
        if (count == 8) {
            ++i;
            count = 0;
        }
        std::cout << static_cast<int>(b);
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
                unsigned char tmp = inzip_buffer.get()[i];
                int bit = 1 & tmp >> (7 - count++);
                cur_root->ch = cur_root->ch | (bit << (7 - k));
                std::cout << static_cast<int>(bit);
                if (count == 8) {
                    ++i;
                    count = 0;
                }
            }
            cur_root = cur_root->parent;
        }
    }

    cur_root = root;
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
                std::fwrite(&cur_root->ch, sizeof(char), 1, outzip_f.get());
                cur_root = root;
            }
        }
    }
}

int main() {

    pack_huffman("test.txt", "test_zip.bin");
    decode_huffman("test_zip.bin", "test_normal.txt");

    return 0;
}