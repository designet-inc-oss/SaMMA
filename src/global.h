/*
 * samma
 *
 * Copyright (C) 2006,2007,2008 DesigNET, INC.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

/* SaMMA version */
#define SAMMA_VERSION "5.0.3"

/* Return Code */
#define SUCCESS		0
#define ERROR		-1

/* String Code */
#define STR_JIS        "ISO-2022-JP"
#define STR_EUC        "EUC-JP"
#define STR_SJIS       "SJIS"
#define STR_UTF8       "UTF-8"
#define STR_UTF8_LEN   sizeof(STR_UTF8)
#define STR_JIS_LEN    sizeof(STR_JIS)
#define STR_EUC_LEN    sizeof(STR_EUC)
#define STR_SJIS_LEN   sizeof(STR_SJIS)

#define MALLOC_ERROR -2

#ifdef DEBUG

#define	DEBUGLOG(a...)	log(a)

#else

#define	DEBUGLOG(a...)

#endif

/* Define the run mode flag of SaMMA. */
extern int ismode_enc;
extern int ismode_delete;  // 0 : Encryption mode
                           // 1 : Delete mode
extern int ismode_harmless;

#endif /* _GLOBAL_H_ */
