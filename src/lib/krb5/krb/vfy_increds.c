/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "k5-int.h"
#include "int-proto.h"

/* Return true if configuration demands that a keytab be present.  (By default
 * verification will be skipped if no keytab exists.) */
static krb5_boolean
nofail(krb5_context context, krb5_verify_init_creds_opt *options,
       krb5_creds *creds)
{
    int val;

    if (options &&
        (options->flags & KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL))
        return (options->ap_req_nofail != 0);
    if (krb5int_libdefault_boolean(context, &creds->client->realm,
                                   KRB5_CONF_VERIFY_AP_REQ_NOFAIL,
                                   &val) == 0)
        return (val != 0);
    return FALSE;
}

static krb5_error_code
copy_creds_except(krb5_context context, krb5_ccache incc,
                  krb5_ccache outcc, krb5_principal princ)
{
    krb5_error_code code;
    krb5_flags flags;
    krb5_cc_cursor cur;
    krb5_creds creds;

    flags = 0;                           /* turns off OPENCLOSE mode */
    if ((code = krb5_cc_set_flags(context, incc, flags)))
        return(code);
    if ((code = krb5_cc_set_flags(context, outcc, flags)))
        return(code);

    if ((code = krb5_cc_start_seq_get(context, incc, &cur)))
        goto cleanup;

    while (!(code = krb5_cc_next_cred(context, incc, &cur, &creds))) {
        if (krb5_principal_compare(context, princ, creds.server))
            continue;

        code = krb5_cc_store_cred(context, outcc, &creds);
        krb5_free_cred_contents(context, &creds);
        if (code)
            goto cleanup;
    }

    if (code != KRB5_CC_END)
        goto cleanup;

    code = 0;

cleanup:
    flags = KRB5_TC_OPENCLOSE;

    if (code)
        krb5_cc_set_flags(context, incc, flags);
    else
        code = krb5_cc_set_flags(context, incc, flags);

    if (code)
        krb5_cc_set_flags(context, outcc, flags);
    else
        code = krb5_cc_set_flags(context, outcc, flags);

    return(code);
}

static krb5_error_code
get_vfy_cred(krb5_context context,
             krb5_creds *creds,
             krb5_principal server,
             krb5_keytab keytab,
             krb5_ccache *ccache_arg,
             krb5_verify_init_creds_opt *options)
{
    krb5_error_code ret;
    krb5_ccache ccache;
    krb5_creds in_creds, *out_creds;
    krb5_auth_context authcon;
    krb5_data ap_req;

    ccache = NULL;
    out_creds = NULL;
    authcon = NULL;
    ap_req.data = NULL;
    /*
     * If the creds are for the server principal, we're set, just do a mk_req.
     * Otherwise, do a get_credentials first.
     */
    if (krb5_principal_compare(context, server, creds->server)) {
        /* make an ap_req */
        ret = krb5_mk_req_extended(context, &authcon, 0, NULL, creds, &ap_req);
        if (ret)
            goto cleanup;
    } else {
        /*
         * This is unclean, but it's the easiest way without ripping the
         * library into very small pieces.  store the client's initial cred in
         * a memory ccache, then call the library.  Later, we'll copy
         * everything except the initial cred into the ccache we return to the
         * user.  A clean implementation would involve library internals with a
         * coherent idea of "in" and "out".
         */

        /* insert the initial cred into the ccache */
        ret = krb5_cc_new_unique(context, "MEMORY", NULL, &ccache);
        if (ret) {
            ccache = NULL;
            goto cleanup;
        }

        ret = krb5_cc_initialize(context, ccache, creds->client);
        if (ret)
            goto cleanup;

        ret = krb5_cc_store_cred(context, ccache, creds);
        if (ret)
            goto cleanup;

        /* set up for get_creds */
        memset(&in_creds, 0, sizeof(in_creds));
        in_creds.client = creds->client;
        in_creds.server = server;
        ret = krb5_timeofday(context, &in_creds.times.endtime);
        if (ret)
            goto cleanup;
        in_creds.times.endtime += 5*60;

        /* attempt to get the service ticket/cred */
        ret = krb5_get_credentials(context, 0, ccache, &in_creds, &out_creds);
        if (ret)
            goto cleanup;

        /* make an ap_req */
        ret = krb5_mk_req_extended(context, &authcon, 0, NULL, out_creds,
                                   &ap_req);
        if (ret)
            goto cleanup;
    }

    /* wipe the auth context for mk_req */
    if (authcon) {
        krb5_auth_con_free(context, authcon);
        authcon = NULL;
    }

    /* verify the ap_req */
    ret = krb5_rd_req(context, &authcon, &ap_req, server, keytab, NULL, NULL);
    if (ret)
        goto cleanup;

    /*
     * If we get this far, then the verification succeeded.  We can still fail
     * if the library stuff here fails, but that's it.
     */
    if (ccache_arg && ccache) {
        if (*ccache_arg == NULL) {
            krb5_ccache retcc = NULL;

            if ((ret = krb5_cc_resolve(context, "MEMORY:rd_req2", &retcc)) ||
                (ret = krb5_cc_initialize(context, retcc, creds->client)) ||
                (ret = copy_creds_except(context, ccache, retcc,
                                         creds->server))) {
                if (retcc)
                    krb5_cc_destroy(context, retcc);
            } else {
                *ccache_arg = retcc;
            }
        } else {
            ret = copy_creds_except(context, ccache, *ccache_arg, server);
        }
    }
    /*
     * If any of the above paths returned an errors, then ret is set
     * accordingly.  Either that, or it's zero, which is fine, too.
     */
cleanup:
    if (ccache)
        krb5_cc_destroy(context, ccache);
    if (out_creds)
        krb5_free_creds(context, out_creds);
    if (authcon)
        krb5_auth_con_free(context, authcon);
    if (ap_req.data)
        free(ap_req.data);

    return ret;
}

static void
free_princ_list(krb5_context context, krb5_principal *plist)
{
    size_t i;

    if (plist == NULL)
        return;

    for (i = 0; plist[i] != NULL; i++)
        krb5_free_principal(context, plist[i]);

    free(plist);
}

/*
 * Adds a princ to plist if it isn't already in plist.  Will create plist if
 * it doesn't exist already.
 */
static krb5_error_code
add_princ_list(krb5_context context, krb5_const_principal princ,
               krb5_principal **plist)
{
    krb5_error_code ret;
    size_t i;
    void *newdata;
    krb5_principal *tmp_plist = *plist;

    if (tmp_plist == NULL) {
        tmp_plist = calloc(2, sizeof (krb5_principal));
        if (tmp_plist == NULL)
            return ENOMEM;
    }

    for (i = 0; tmp_plist[i] != NULL; i++) {
        if (krb5_principal_compare(context, princ, tmp_plist[i])) {
            /* this princ is already in the list so stop searching */
            return 0;
        }
    }

    /* if we get here then i == number of princs in plist */
    newdata = realloc(tmp_plist, (i + 2) * sizeof (krb5_principal));
    if (newdata == NULL) {
        return ENOMEM;
    } else {
        tmp_plist = newdata;
        tmp_plist[i] = NULL; 
        tmp_plist[i+1] = NULL; /* terminate the list */
        ret = krb5_copy_principal(context, princ, &tmp_plist[i]);
        if (ret)
            return ret;
        *plist = tmp_plist;
    }
    return 0;
}

/*
 * Returns a list of all unique host service princs in keytab.
 */
static krb5_error_code
get_host_princs_from_keytab(krb5_context context, krb5_keytab keytab,
                            krb5_principal **princ_list_out)
{
    krb5_error_code ret, code;
    krb5_kt_cursor cursor;
    krb5_keytab_entry kte;
    krb5_principal *tmp_list = NULL;
    krb5_principal srv_princ_match = NULL;

    /*
     * If the keytab doesn't support this then return KRB5_KT_NOTFOUND because
     * we don't have another way of reading this keytab.
     */
    if (keytab->ops->start_seq_get == NULL)
        return KRB5_KT_NOTFOUND;

    /*
     * Build a host srv princ with only the service name specified.  Note
     * krb5_sname_match will only match specified princ components.
     */
    ret = krb5_build_principal(context, &srv_princ_match, 0, "", "host",
                               "", (char *) 0);
    if (ret)
        goto cleanup;

    krb5_princ_type(context, srv_princ_match) = KRB5_NT_SRV_HST;

    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret)
        goto cleanup;

    while ((code = krb5_kt_next_entry(context, keytab, &kte, &cursor)) == 0) {
        if (krb5_sname_match(context, srv_princ_match, kte.principal))
            ret = add_princ_list(context, kte.principal, &tmp_list);

        krb5_kt_free_entry(context, &kte);

        if (ret)
            goto cleanup;
    }

    if (code && code != KRB5_KT_END) {
        ret = code;
        goto cleanup;
    } else {
        (void) krb5_kt_end_seq_get(context, keytab, &cursor);
    }

    *princ_list_out = tmp_list;

cleanup:
    if (ret != 0)
        free_princ_list(context, tmp_list);
    krb5_free_principal(context, srv_princ_match);

    return ret;
}

/*
 * If nofail() returns false, succeed if and only if:
 *  - No keying material is available
 *  - A key is available and verification using that key succeeds
 *
 * If nofail() returns true, succeed if and only if:
 *  - A key is available and verification using that key succeeds
 *
 * So, only the specific failure of "no keying material is available"
 * should consult the return of nofail().
 */
krb5_error_code KRB5_CALLCONV
krb5_verify_init_creds(krb5_context context,
                       krb5_creds *creds,
                       krb5_principal server_arg,
                       krb5_keytab keytab_arg,
                       krb5_ccache *ccache_arg,
                       krb5_verify_init_creds_opt *options)
{
    krb5_error_code ret;
    krb5_principal server = NULL, *host_princs = NULL;
    krb5_keytab keytab = NULL;
    krb5_keytab_entry kte;
    char kt_name[MAXPATHLEN], *cp;
    struct stat statbuf;
    size_t i;

    if (keytab_arg) {
        keytab = keytab_arg;
    } else {
        if (ret = krb5_kt_default(context, &keytab))
            goto cleanup;
    }

    /* verify that the keytab file exists */
    /*
     * XXX this is a hack until a keytab method is provided that will tell us
     * if the keytab exists or not.
     */
    ret = krb5_kt_get_name(context, keytab, kt_name, sizeof (kt_name));
    if (ret)
        goto cleanup;
    if (!strncmp(kt_name, "FILE:", 5) || !strncmp(kt_name, "WRFILE:", 7)){
        cp = strchr(kt_name, ':');
        /* ++cp to skip the ':' */
        ret = stat(++cp, &statbuf);
        if (ret) {
            /*
             * If the error indicates the keytab doesn't exist, stop processing
             * and return either success if nofail() returns false or errror if
             * nofail() returns true.
             */
            if (errno == ENOENT && !nofail(context, options, creds))
                ret = 0;
            else
                ret = errno;
            goto cleanup;
        }
    }

    if (server_arg) {
        krb5_keytab_entry kte;
        /*
         * Must copy server_arg princ because we may have to modify the realm
         * of the server princ.
         */
        ret = krb5_copy_principal(context, server_arg, &server);
        if (ret)
            goto cleanup;
        /*
         * First, check if the server is in the keytab.  If not, there's no
         * reason to continue.  rd_req does all this, but there's no way to
         * know that a given error is caused by a missing keytab or key, and
         * not by some other problem.
         */
        if (krb5_is_referral_realm(&server->realm)) {
            krb5_free_data_contents(context, &server->realm);
            ret = krb5_get_default_realm(context, &server->realm.data);
            if (ret)
                goto cleanup;
            server->realm.length = strlen(server->realm.data);
        }

        ret = krb5_kt_get_entry(context, keytab, server, 0, 0, &kte);
        if (ret) {
            /*
             * This means there is no keying material.  This is ok, as long as
             * it is not prohibited by the configuration
             */
            if (!nofail(context, options, creds))
                ret = 0;
            goto cleanup;
        }
        krb5_kt_free_entry(context, &kte);

        ret = get_vfy_cred(context, creds, server, keytab, ccache_arg,
                           options);
    } else {
        /* Try using the host service princs from the keytab. */

        ret = get_host_princs_from_keytab(context, keytab, &host_princs);
        /*
         * If there are no host princs in the keytab and nofail() returns true,
         * return error.
         */
        if (ret == 0 && host_princs == NULL) {
            if (nofail(context, options, creds))
                ret = KRB5_KT_NOTFOUND;
            goto cleanup;
        } else if (ret) {
            /* Ignore KRB5_KT_NOTFOUND depending on nofail() return */
            if (ret == KRB5_KT_NOTFOUND && !nofail(context, options, creds))
                ret = 0;
            goto cleanup;
        }

        /*
         * Try all host princs until either one succeeds in getting a valid
         * service cred or they all fail.
         */
        for (i = 0; host_princs[i] != NULL; i++) {
            ret = get_vfy_cred(context, creds, host_princs[i], keytab,
                               ccache_arg, options);
            if (ret == 0)
                break;
        }
    }

cleanup:
    krb5_free_principal(context, server);
    if (!keytab_arg && keytab)
        krb5_kt_close(context, keytab);
    free_princ_list(context, host_princs);

    return ret;
}
