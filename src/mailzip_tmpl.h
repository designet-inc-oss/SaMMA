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

#include "zipconv.h"

#define STARTTAG	"<@@"
#define ENDTAG		"@@>"

#define SUBJECT  0
#define DATE     1
#define PASSWORD 2
#define RCPTLIST 3
#define FILENAME 4
#define TOADDR   5
#define ENVFROM  6

#define ERR_FUNC    -1
#define ERR_VALUE    1
#define REPLACED_TAG 0
#define CONVERT_ERROR -2
#define MAIL_SEP "\n\n"
#define NOT_ENC_SUBJECT "Invalid character code exists in the subject."
#define NOT_ENC_ADDR    "Invalid character code exists in the mail address."
#define NOT_ENC_ATTACHFILE "Invalid character code exists in the attach file."
#define NOT_ENC_HEADER "%s:Cannot encode header data."
#define NOT_ENC_TMPL "%s:Cannot encode template file."
#define BAD_MAIL_TMPL "%s:Cannot separate header part and body part."
#define NO_HEADER "%s:Cannot find mail header data."

# define NOTICEPASS_FROM 1
# define NOTICEPASS_TO 2

int tmpl_tag_replace(char *, struct mailzip, struct rcptinfo *, char *, char **, int, char *);
int tmpl_tag_replace_noconv(struct mailzip, struct rcptinfo *, char *, char **, char *, int);
int tmpl_read(char **, char *);
