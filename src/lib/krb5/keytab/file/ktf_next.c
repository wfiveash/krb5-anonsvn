/*
 * lib/krb5/keytab/file/ktf_next.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_ktfile_get_next()
 */

#include "k5-int.h"
#include "ktfile.h"

krb5_error_code KRB5_CALLCONV 
krb5_ktfile_get_next(context, id, entry, cursor)
    krb5_context context;
krb5_keytab id;
krb5_keytab_entry *entry;
krb5_kt_cursor *cursor;
{
    long *fileoff = (long *)*cursor;
    krb5_keytab_entry cur_entry;
    krb5_error_code kerror;

    if (fseek(KTFILEP(id), *fileoff, 0) == -1)
	return KRB5_KT_END;
    if ((kerror = krb5_ktfileint_read_entry(context, id, &cur_entry)))
	return kerror;
    *fileoff = ftell(KTFILEP(id));
    *entry = cur_entry;
    return 0;
}
