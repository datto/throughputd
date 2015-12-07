/*
    Copyright (C) 2015 Datto Inc.

    This file is part of throughputd.

    This program is free software; you can redistribute it and/or modify it 
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation.
*/

#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdio.h>

#ifdef DEBUG_ENABLED
	#define PRINT_DEBUG(fmt, args...) printf("DEBUG %s %d: " fmt "\n", __FILE__, __LINE__, ## args)
	#define PRINT_ERROR(error, fmt, args...) printf("ERROR %s %d: " fmt ": %d\n", __FILE__, __LINE__, ## args, error)
#else
	#define PRINT_DEBUG(fmt, args...)
	#define PRINT_ERROR(error, fmt, args...) printf("ERROR: " fmt ": %d\n", ## args, error)
#endif

#endif
