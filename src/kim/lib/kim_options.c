/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "kim_private.h"

/* ------------------------------------------------------------------------ */

struct kim_options_opaque {
    kim_time start_time;
    kim_lifetime lifetime;
    kim_boolean renewable;
    kim_lifetime renewal_lifetime;
    kim_boolean forwardable;
    kim_boolean proxiable;
    kim_boolean addressless;
    kim_string service_name;
};

struct kim_options_opaque kim_options_initializer = { 
0, 
kim_default_lifetime, 
kim_default_renewable, 
kim_default_renewal_lifetime,
kim_default_forwardable,
kim_default_proxiable,
kim_default_addressless,
NULL };

/* ------------------------------------------------------------------------ */

static inline kim_error kim_options_allocate (kim_options *out_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = NULL;
    
    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        options = malloc (sizeof (*options));
        if (!options) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        *options = kim_options_initializer;
        *out_options = options;
        options = NULL;
    }
    
    kim_options_free (&options);
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_create_empty (kim_options *out_options)
{
    return check_error (kim_options_allocate (out_options));
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_create (kim_options *out_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_preferences preferences = NULL;
    
    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_preferences_create (&preferences);
    }
    
    if (!err) {
        err = kim_preferences_get_options (preferences, out_options);
    }
    
    kim_preferences_free (&preferences);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_copy (kim_options *out_options,
                            kim_options  in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_options options = KIM_OPTIONS_DEFAULT;
    
    if (!err && !out_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_options ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err && in_options != KIM_OPTIONS_DEFAULT) {
        err = kim_options_allocate (&options);
        
        if (!err) {
            options->start_time = in_options->start_time;
            options->lifetime = in_options->lifetime;
            options->renewable = in_options->renewable;
            options->renewal_lifetime = in_options->renewal_lifetime;
            options->forwardable = in_options->forwardable;
            options->proxiable = in_options->proxiable;
            options->addressless = in_options->addressless;
            
            if (in_options->service_name) {
                err = kim_string_copy (&options->service_name, 
                                       in_options->service_name);
            }
        }
    }
        
    if (!err) {
        *out_options = options;
        options = NULL;
    }
    
    kim_options_free (&options);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_start_time (kim_options io_options,
                                      kim_time    in_start_time)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_options->start_time = in_start_time;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_start_time (kim_options  in_options,
                                      kim_time    *out_start_time)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_options    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_start_time) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_start_time = in_options->start_time;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_lifetime (kim_options  io_options,
                                    kim_lifetime in_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_options->lifetime = in_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_lifetime (kim_options   in_options,
                                    kim_lifetime *out_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_options  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_lifetime = in_options->lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_renewable (kim_options io_options,
                                     kim_boolean in_renewable)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_options->renewable = in_renewable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_renewable (kim_options  in_options,
                                     kim_boolean *out_renewable)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_options   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_renewable) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_renewable = in_options->renewable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_renewal_lifetime (kim_options  io_options,
                                            kim_lifetime in_renewal_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_options->renewal_lifetime = in_renewal_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_renewal_lifetime (kim_options   in_options,
                                            kim_lifetime *out_renewal_lifetime)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_options          ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_renewal_lifetime) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_renewal_lifetime = in_options->renewal_lifetime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_forwardable (kim_options io_options,
                                       kim_boolean in_forwardable)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_options->forwardable = in_forwardable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_forwardable (kim_options  in_options,
                                       kim_boolean *out_forwardable)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_options     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_forwardable) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_forwardable = in_options->forwardable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_proxiable (kim_options io_options,
                                     kim_boolean in_proxiable)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_options->proxiable = in_proxiable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_proxiable (kim_options  in_options,
                                     kim_boolean *out_proxiable)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_options   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_proxiable) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_proxiable = in_options->proxiable;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_addressless (kim_options io_options,
                                       kim_boolean in_addressless)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !io_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        io_options->addressless = in_addressless;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_addressless (kim_options  in_options,
                                       kim_boolean *out_addressless)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_options     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_addressless) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_addressless = in_options->addressless;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_set_service_name (kim_options  io_options,
                                        kim_string   in_service_name)
{
    kim_error err = KIM_NO_ERROR;
    kim_string service_name = NULL;
    
    if (!err && !io_options     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_service_name) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err && in_service_name) {
        err = kim_string_copy (&service_name, in_service_name);
    }
    
    if (!err) {
	kim_string_free (&io_options->service_name);
	io_options->service_name = service_name;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_service_name (kim_options  in_options,
                                        kim_string  *out_service_name)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_options      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_service_name) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        if (in_options->service_name) {
            err = kim_string_copy (out_service_name, in_options->service_name);
        } else {
            *out_service_name = NULL;
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_get_init_cred_options (kim_options               in_options, 
                                             krb5_context              in_context,
                                             krb5_get_init_creds_opt **out_init_cred_options)
{
    kim_error err = KIM_NO_ERROR;
    krb5_get_init_creds_opt *init_cred_options;
    krb5_address **addresses = NULL;
    
    if (!err && !in_options           ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_context           ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_init_cred_options) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        krb5_get_init_creds_opt_alloc (in_context, &init_cred_options);
    }
    
    if (!err && in_options) {
        if (!in_options->addressless) {
            err = krb5_error (in_context, 
                              krb5_os_localaddr (in_context, &addresses));
        }
        
        if (!err) {
            krb5_get_init_creds_opt_set_tkt_life (init_cred_options, in_options->lifetime);
            krb5_get_init_creds_opt_set_renew_life (init_cred_options, in_options->renewable ? in_options->renewal_lifetime : 0);
            krb5_get_init_creds_opt_set_forwardable (init_cred_options, in_options->forwardable);
            krb5_get_init_creds_opt_set_proxiable (init_cred_options, in_options->proxiable);
            krb5_get_init_creds_opt_set_address_list (init_cred_options, addresses);
            addresses = NULL;
        }
    }
     
    if (!err) {
        *out_init_cred_options = init_cred_options;
        init_cred_options = NULL;
    }
    
    if (init_cred_options) { krb5_get_init_creds_opt_free (in_context, init_cred_options); }
    if (addresses        ) { krb5_free_addresses (in_context, addresses); }
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

kim_error kim_options_free_init_cred_options (krb5_context              in_context,
                                              krb5_get_init_creds_opt **io_init_cred_options)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err && io_init_cred_options && *io_init_cred_options) {
	if ((*io_init_cred_options)->address_list) {
	    krb5_free_addresses (in_context, (*io_init_cred_options)->address_list);
            (*io_init_cred_options)->address_list = NULL;
	}
	krb5_get_init_creds_opt_free (in_context, *io_init_cred_options);
	*io_init_cred_options = NULL;
    }
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

void kim_options_free (kim_options *io_options)
{
    if (io_options && *io_options) { 
        kim_string_free (&(*io_options)->service_name); 
        free (*io_options);
        *io_options = NULL;
    }
}
