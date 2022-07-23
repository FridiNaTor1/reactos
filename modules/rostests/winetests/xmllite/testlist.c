/* Automatically generated file; DO NOT EDIT!! */

#define STANDALONE
#include <wine/test.h>

extern void func_reader(void);
extern void func_writer(void);

const struct test winetest_testlist[] =
{
//    { "reader", func_reader }, // UM stack corruption
    { "writer", func_writer },
    { 0, 0 }
};
