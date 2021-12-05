#include <cstdint>
#include <elf.h>
#include <error.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

uint32_t strTableOffset;
uint32_t fileSize;

uint32_t find_string(uint8_t *mem, const char *string)
{
  uint32_t i;
  for (i = 0; i < fileSize; i++)
  {
    if (memcmp(mem + i, string, strlen(string)) == 0)
    {
      break;
    }
  };
  return i;
}
uint32_t find_string_offset(uint8_t *mem, const char *string)
{
  uint32_t i;
  for (i = strTableOffset; i < fileSize; i++)
  {
    if (memcmp(mem + i, string, strlen(string)) == 0)
    {
      break;
    }
  };
  return i - strTableOffset;
}

int main()
{
  auto soul = "/home/junknet/Desktop/armeabi-v7a/libsoulpower.so";
  auto ke = "/home/junknet/Desktop/armeabi-v7a/libsgmainso-5.4.193.so";
  auto fd = open(ke, O_RDONLY);
  auto fd_out = fopen("/home/junknet/Desktop/fix.so", "w");
  struct stat st;
  fstat(fd, &st);
  fileSize = st.st_size;
  auto mem = (uint8_t *)malloc(st.st_size);
  read(fd, mem, st.st_size);
  strTableOffset = find_string(mem, ".shstrtab") - 1;
  auto ehdr = (Elf32_Ehdr *)mem;
  auto phdr = (Elf32_Phdr *)&mem[ehdr->e_phoff];
  auto shdr = (Elf32_Shdr *)&mem[ehdr->e_shoff];
  auto phnum = ehdr->e_phnum;
  auto shnum = ehdr->e_shnum;
  uint32_t dynamic_section_offset;
  uint32_t dynamic_num;
  uint32_t data_section_end_addr;
  uint32_t load2_start;
  //   find dynamic_section_offset
  for (int i = 0; i < phnum; i++)
  {
    if (i == 2)
    {
      load2_start = phdr[i].p_offset;
      data_section_end_addr = phdr[i].p_vaddr + phdr[i].p_filesz;
    }

    switch (phdr[i].p_type)
    {
    case PT_DYNAMIC:
      dynamic_section_offset = phdr[i].p_offset;
      shdr[19].sh_type = SHT_DYNAMIC;
      shdr[19].sh_offset = dynamic_section_offset;
      shdr[19].sh_addr = phdr[i].p_paddr;
      shdr[19].sh_name = find_string_offset(mem, ".dynamic");
      shdr[19].sh_size = phdr[i].p_filesz;
      dynamic_num = phdr[i].p_filesz / sizeof(Elf32_Dyn);
      break;
    }
  }

  auto dynamic_ptr = (Elf32_Dyn *)&mem[dynamic_section_offset];
  uint32_t hash_section_vaddr;
  uint32_t hash_section_size;
  uint32_t dynsym_section_vaddr;
  for (int i = 0; i < dynamic_num; i++)
  {
    switch (dynamic_ptr[i].d_tag)
    {
    case DT_HASH:
      hash_section_vaddr = dynamic_ptr[i].d_un.d_ptr;
      break;
    case DT_SYMTAB:
      dynsym_section_vaddr = dynamic_ptr[i].d_un.d_ptr;
      break;
    case DT_REL:
      shdr[8].sh_type = SHT_REL;
      shdr[8].sh_offset = dynamic_ptr[i].d_un.d_ptr;
      shdr[8].sh_name = find_string_offset(mem, ".rel.dyn");
      break;
    case DT_RELSZ:
      shdr[8].sh_size = dynamic_ptr[i].d_un.d_val;
      break;
    case DT_JMPREL:
      shdr[9].sh_type = SHT_REL;
      shdr[9].sh_offset = dynamic_ptr[i].d_un.d_ptr;
      shdr[9].sh_name = find_string_offset(mem, ".rel.plt");
      break;
    case DT_PLTRELSZ:
      shdr[9].sh_size = dynamic_ptr[i].d_un.d_val;
      break;
    case DT_INIT_ARRAY:
      shdr[18].sh_type = SHT_INIT_ARRAY;
      shdr[18].sh_addr = dynamic_ptr[i].d_un.d_ptr;
      shdr[18].sh_offset = shdr[18].sh_addr - 0x1000;
      shdr[18].sh_name = find_string_offset(mem, ".init_array");
      break;
    case DT_INIT_ARRAYSZ:
      shdr[18].sh_size = dynamic_ptr[i].d_un.d_val;
      break;
    case DT_FINI_ARRAY:
      shdr[16].sh_type = SHT_FINI_ARRAY;
      shdr[16].sh_addr = dynamic_ptr[i].d_un.d_ptr;
      shdr[16].sh_offset = shdr[16].sh_offset - 0x1000;
      shdr[16].sh_name = find_string_offset(mem, ".fini_array");
      break;
    case DT_FINI_ARRAYSZ:
      shdr[16].sh_size = dynamic_ptr[i].d_un.d_val;
      break;
    case DT_STRTAB:
      shdr[3].sh_type = SHT_STRTAB;
      shdr[3].sh_addr = dynamic_ptr[i].d_un.d_ptr;
      shdr[3].sh_offset = shdr[3].sh_addr;
      shdr[3].sh_offset = shdr[3].sh_addr - 0x1000;
      printf("%x\n", find_string_offset(mem, ".dynstr"));
      break;
    case DT_STRSZ:
      shdr[3].sh_size = dynamic_ptr[i].d_un.d_val;
      break;
    }
  }

  for (int i = 0; i < dynamic_num; i++)
  {
    switch (dynamic_ptr[i].d_tag)
    {
    case DT_PLTGOT:
      shdr[20].sh_type = SHT_PROGBITS;
      auto got_offset = dynamic_ptr[i].d_un.d_ptr;
      auto data_section_vaddr = got_offset + 12 + shdr[9].sh_size / 2;
      shdr[20].sh_name = find_string_offset(mem, ".got");
      shdr[20].sh_addr = shdr[19].sh_addr + shdr[19].sh_size;
      shdr[20].sh_size = data_section_vaddr - shdr[20].sh_addr;
      shdr[20].sh_offset = shdr[20].sh_addr - 0x1000;
    }
  }
  shdr[21].sh_type = SHT_PROGBITS;
  shdr[21].sh_offset = shdr[20].sh_offset + shdr[20].sh_size;
  shdr[21].sh_name = find_string_offset(mem, ".data");
  shdr[21].sh_addr = shdr[21].sh_offset + 0x1000;
  shdr[21].sh_size = data_section_end_addr - shdr[21].sh_addr;

  shdr[22].sh_type = SHT_NOBITS;
  shdr[22].sh_addr = data_section_end_addr;
  shdr[22].sh_offset = shdr[22].sh_addr - 0x1000;
  shdr[22].sh_name = find_string_offset(mem, ".bss");

  shdr[10].sh_type = SHT_PROGBITS;
  shdr[10].sh_offset = shdr[9].sh_offset + shdr[9].sh_size;
  shdr[10].sh_name = find_string_offset(mem, ".plt");
  shdr[10].sh_size = 20 + 12 * (shdr[9].sh_size / sizeof(Elf32_Rel));

  auto nbucket = *(uint32_t *)(mem + hash_section_vaddr);
  auto nchain = *(uint32_t *)(mem + hash_section_vaddr + 4);
  hash_section_size = (2 + nchain + nbucket) * 4;
  auto dynsym_num = nchain;
  auto dynsym_section_size = nchain * 0x10;

  //  fix section header
  shdr[2].sh_type = SHT_SYMTAB;
  shdr[2].sh_offset = dynsym_section_vaddr;
  shdr[2].sh_name = find_string_offset(mem, ".dynsym");
  shdr[2].sh_size = dynsym_section_size;

  shdr[4].sh_type = SHT_HASH;
  shdr[4].sh_offset = hash_section_vaddr;
  shdr[4].sh_name = find_string_offset(mem, ".hash");
  shdr[4].sh_size = hash_section_size;

  shdr[26].sh_type = SHT_STRTAB;
  shdr[26].sh_offset = strTableOffset;
  shdr[26].sh_name = find_string_offset(mem, ".shstrtab");
  shdr[26].sh_addr = 0;

  shdr[11].sh_type = SHT_PROGBITS;
  shdr[11].sh_offset = shdr[10].sh_offset + shdr[10].sh_size;
  shdr[11].sh_addr = shdr[11].sh_offset;
  shdr[11].sh_name = find_string_offset(mem, ".text");
  shdr[11].sh_size = load2_start - shdr[11].sh_offset;

  fwrite(mem, st.st_size, 1, fd_out);
  fclose(fd_out);
  return 0;
}