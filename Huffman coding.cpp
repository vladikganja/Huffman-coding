#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <fstream>

#define SIZE 65536

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

std::vector<std::string> list_to_tree(node* root) {
    std::string code;
    std::vector<std::string> table(256);

    node* cur_root = root;
    while (true) {
        if (cur_root->son_l != nullptr && cur_root->son_l->used != true) {
            code.push_back('0');
            cur_root->used = true;
            cur_root = cur_root->son_l;
        }
        else if (cur_root->son_r != nullptr && cur_root->son_r->used != true) {
            code.push_back('1');
            cur_root->used = true;
            cur_root = cur_root->son_r;
        }
        else {
            if (cur_root->symb == true)
                table[cur_root->ch] = code;
            cur_root->used = true;
            cur_root = cur_root->parent;
            if (cur_root == nullptr)
                break;
            code.pop_back();
        }
    }
    return table;
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

// unite with list_to_tree
unsigned char* hash_tree(node* root) {
    unsigned char* hash = new unsigned char[1024]{'\0'};
    int size = 0;
    node* cur_root = root;
    unsigned char buf = '\0';
    int count = 0;
    while (true) {
        if (cur_root->son_l != nullptr && cur_root->son_l->used != true) {
            buf = buf | (0 << (7 - count++));
            cur_root->used = true;
            cur_root = cur_root->son_l;
        }
        else if (cur_root->son_r != nullptr && cur_root->son_r->used != true) {
            cur_root->used = true;
            cur_root = cur_root->son_r;
        }
        else {
            if (cur_root->symb == true) {
                buf = buf | (1 << (7 - count++));
                unsigned char letter = cur_root->ch;
                for (int i = 0; i < 8; ++i) {
                    int bit = 1 & letter >> (7 - i);
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
        }
        if (count == 8) {
            hash[size++] = buf;
            count = 0;
            buf = '\0';
        }
    }
    hash[size++] = buf;
    return hash;
}

node* pack_huffman(const char* input, const char* output) {
    struct fclose_auto {
        void operator()(FILE* f) const noexcept {
            std::fclose(f);
        }
    };
    std::size_t written_bytes = 0;
    std::unique_ptr<FILE, fclose_auto> in_f(std::fopen(input, "rb"));
    std::unique_ptr<FILE, fclose_auto> out_f(std::fopen(output, "wb"));
    std::unique_ptr<unsigned char[]> in_buffer(new unsigned char[SIZE]);    

    std::size_t read_bytes = std::fread(in_buffer.get(), 1, SIZE, in_f.get());

    std::vector<unsigned char> counts_table(256);

    for (auto ptr = in_buffer.get(); ptr != in_buffer.get() + read_bytes; ++ptr)
        if (counts_table[*ptr] != 255)
            ++counts_table[*ptr];

    node* root = table_to_list(counts_table);

    // Дерево портится этим методом, надо объедиить с list_to_tree
    /*unsigned char* hash = hash_tree(root);
    for (int i = 0; hash[i] != '\0'; ++i)
        written_bytes += std::fwrite(&hash[i], sizeof(char), 1, out_f.get());*/

    std::vector<std::string> table = list_to_tree(root);

    unsigned char buf = '\0';
    int count = 0;
    for (int i = 0; i < SIZE; ++i) {
        unsigned char c = in_buffer.get()[i];
        std::string tmp = table[c];
        for (int j = 0; j < tmp.size(); ++j) {
            int tmpi = static_cast<int>(tmp[j] - 48);
            buf = buf | (tmpi << (7 - count));
            count++;
            if (count == 8) {
                written_bytes += std::fwrite(&buf, sizeof(char), 1, out_f.get());
                count = 0;
                buf = '\0';
            }
        }
    }
    written_bytes += std::fwrite(&buf, sizeof(char), 1, out_f.get());
    std::cout << "Bytes read: " << read_bytes << "\nBytes written: " << written_bytes << "\n";
    return root;
}

void decode_huffman(const char* input, const char* output, node* root) {
    struct fclose_auto {
        void operator()(FILE* f) const noexcept {
            std::fclose(f);
        }
    };

    std::unique_ptr<FILE, fclose_auto> inzip_f(std::fopen(input, "rb"));
    std::unique_ptr<FILE, fclose_auto> outzip_f(std::fopen(output, "wb"));
    std::unique_ptr<unsigned char[]> inzip_buffer(new unsigned char[SIZE]);
    std::size_t readzip_bytes = std::fread(inzip_buffer.get(), 1, SIZE, inzip_f.get());

    unsigned char buf;
    node* cur_root = root;
    for (int i = 0; i < readzip_bytes; ++i) {
        buf = inzip_buffer[i];
        for (int count = 0; count < 8; ++count) {
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

    node* key = pack_huffman("test2.txt", "test_zip.bin");
    decode_huffman("test_zip.bin", "test_normal.txt", key);

    return 0;
}