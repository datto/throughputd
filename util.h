/*
    Copyright (C) 2015 Datto Inc.

    This file is part of throughputd.

    This program is free software; you can redistribute it and/or modify it 
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation.
*/

#ifndef UTIL_H_
#define UTIL_H_

#define offset_of(type, member) ((size_t) &((type *)0)->member)
#define container_of(ptr, type, member) ({const typeof( ((type *)0)->member ) *__mptr = (ptr); (type *)( (char *)__mptr - offset_of(type,member) );})

#endif
