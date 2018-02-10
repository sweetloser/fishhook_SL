// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#import "fishhook.h"

#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/types.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {

  /*
  为全局变量_rebindings_head分配空间(_rebindings_head为结构体链表，用于保存hook函数的信息)
  */
  struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
  if (!new_entry) {
    return -1;
  }

  /*
  为成员属性`rebindings`分配内存空间
  */
  new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }

  /*
  赋值，并设置链表header(每次都将新增的node插入表头)
  */
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {

  /*
  获取间接符号表索引数组
  */
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;

   /*
  获取保存符号指针的数组
  */
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  /*
  遍历整个section，查找有没有hook的符号
  因为整个section是一个指针数组，所以获取数组长度很简单，就是用整个section的大小除以每个指针的大小即可。
 */
  for (uint i = 0; i < section->size / sizeof(void *); i++) {
    //获取符号索引
    uint32_t symtab_index = indirect_symbol_indices[i];

    //排除INDIRECT_SYMBOL_LOCAL和INDIRECT_SYMBOL_ABS
    /*
    INDIRECT_SYMBOL_LOCAL:it is for a non-lazy symbol pointer section for a defined symbol which strip(1) as  removed.
    */
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }

    //通过下标，获取符号表信息
    /*
    struct nlist_64 {
    union {
        uint32_t  n_strx; //在字符串符号表的偏移
    } n_un;
    uint8_t n_type;       
    uint8_t n_sect;       
    uint16_t n_desc;      
    uint64_t n_value;     
  };
    */
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    if (strnlen(symbol_name, 2) < 2) {
      continue;
    }

     //这里是遍历整个结构体链表，寻找与之匹配的符号
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint j = 0; j < cur->rebindings_nel; j++) {

        //C语言默认在符号前面加`_`，所以需要从`symbol_name[1]`比较
        if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
          if (cur->rebindings[j].replaced != NULL &&
              indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {

            //保存原地址
            *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
          }

          //替换指针
          indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
          goto symbol_loop;
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  /*
  这里介绍一下dladdr这个函数：
  dladdr是通过动态连接器(dyld)查询给定地址的模块信息(模块文件路径(dli_fname)、基址(dli_fbase)、符号名(dli_sname)、符号地址(dli_saddr))。
  查找到的模块信息保存在函数的第二个参数中，是一个Dl_info结构体，具体用法和细节可以自行google or baidu。
  这里调用这个函数，查找header地址处的模块信息，旨在确定这个模块是否存在。
  */
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }

  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;


  /*
  遍历所有的load_command,查找LC_SEGMENT_64/LC_SEGMENT段（实际上是找 SEG_LINKEDIT 段）、LC_SYMTAB段、LC_DYSYMTAB段。
  SEG_LINKEDIT：这个段里面，包含了link edit信息的表，例如符号表(symtab)、字符串表(strtab).
  LC_SYMTAB：这个段里包含了link edit中的符号表信息。
  LC_DYSYMTAB：这个段里包含了间接符号表的相关信息。
  */

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms) {
    return;
  }

  /*
通过`linkedit_segment`获取linkedit的基址，计算公式为：模块基址(slide)+虚拟地址(vmaddr)-SEG_LINKEDIT文件偏移(fileoff)。
之前学习fishhook的时候，以为模块基址slide即为link_edit的基地址，事实上当文件偏移和虚拟内存地址相等时，确实是这样的。
*/
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;

  /*
 通过linkedit_base获取符号表地址----实际上是一个nlist/nlist_64数组。
  */
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);

  /*
  字符串表（strtab）：是一段连续的空间，每个字符串以`\0`结尾，用于字符串之间的区分(注意，这并不是一个字符串数组）。
  */
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

/*
  间接符号表：是一个无符号int(uint32_t)型数组，表示的是间接符号的索引。
*/
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

/*
再次遍历所有的cmd，寻找__DATA和__DATA_CONST（好像是iOS9新加的）段中包含懒加载和非懒加载符号的section。(__got、__la_symbol_ptr)
*/
  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
        continue;
      }
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
          (section_t *)(cur + sizeof(segment_command_t)) + j;
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
      }
    }
  }
}


static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
    struct rebindings_entry *rebindings_head = NULL;
    int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
    rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
    free(rebindings_head);
    return retval;
}

/*
接收两个参数
arg1:结构体数组，看.h文件可以看出，struct rebinding结构体为存放要hook函数的相关信息：name（函数名），replacement（替换的函数），replaced（用来保留原函数的指针）。由于提供的接口可以一次hook多个函数，所有这里选择用数组传递参数。
arg2:hook的函数个数，和arg1数组的长度一致
*/
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {

  /*
 调用`prepend_rebindings`函数，并将函数的两个参数传过去，为rebind做准备工作
  */
  int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (retval < 0) {
    return retval;
  }

  /*
这里是注册模块加载回调。
这个if...else...，主要是区分第一次调用，避免多次注册回调。因为每次都是往链表头插入节点，并且全局变量`_rebindings_head`指针一直指向链表头，所以判断是否为第一次，只需判断其next是否为NULL即可。
*/
  if (!_rebindings_head->next) {

/*
  extern void _dyld_register_func_for_add_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide))    __OSX_AVAILABLE_STARTING(__MAC_10_1, __IPHONE_2_0);

 * The function allow you to install callbacks which will be called   
 * by dyld whenever an image is loaded.  During a call to _dyld_register_func_for_add_image()
 * the callback func is called for every existing image.  Later, it is called as each new image
 * is loaded and bound (but initializers not yet run).
 */

/*
大致意思就是：同过这个函数，可以为程序加载的每一个模块(image)注册回调(callback)。当`_dyld_register_func_for_add_image`函数被调用后，回调函数会对已经加载过的每个image调用一次，并且之后加载的模块，也会被调用。
*/

/*
fishhook注册这个回调函数旨在遍历所有加载的模块，搜索被hook的符号。
*/
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  } else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return retval;
}
