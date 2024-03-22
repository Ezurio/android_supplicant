/*
 * EAP peer method: EAP-GTC (RFC 3748)
 * Copyright (c) 2004-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eap_i.h"

#define ERROR_RESTRICTED_LOGON_HOURS 646
#define ERROR_ACCT_DISABLED 647
#define ERROR_PASSWD_EXPIRED 648
#define ERROR_NO_DIALIN_PERMISSION 649
#define ERROR_AUTHENTICATION_FAILURE 691
#define ERROR_CHANGING_PASSWORD 709
#define ERROR_PAC_I_ID_NO_MATCH	755

struct eap_gtc_data {
	int prefix;
#ifdef _SDC_
	int password_tried;
#endif
};


static void * eap_gtc_init(struct eap_sm *sm)
{
	struct eap_gtc_data *data;
	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;

	if (sm->m && sm->m->vendor == EAP_VENDOR_IETF &&
	    sm->m->method == EAP_TYPE_FAST) {
		wpa_printf(MSG_DEBUG, "EAP-GTC: EAP-FAST tunnel - use prefix "
			   "with challenge/response");
		data->prefix = 1;
	}
	return data;
}


static void eap_gtc_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_gtc_data *data = priv;
	os_free(data);
}

#ifdef _SDC_
static void * eap_gtc_init_for_reauth(struct eap_sm *sm, void *priv)
{
	struct eap_gtc_data *data = priv;
	if (data) {
		data->password_tried = 0;
	}
	return data;
}

static int eap_gtc_parse_errornum ( const u8 *buf, int buflen )
{
    int ret = 0;
    while (buflen--) {
        if (!isdigit(*buf)) break;
        ret = (ret * 10) + (*buf - '0');
        buf++;
    }
    return ret;
}
#endif

static struct wpabuf * eap_gtc_process(struct eap_sm *sm, void *priv,
				       struct eap_method_ret *ret,
				       const struct wpabuf *reqData)
{
	struct eap_gtc_data *data = priv;
	struct wpabuf *resp;
	const u8 *pos, *password, *identity;
	size_t password_len, identity_len, len, plen;
	int otp;
	u8 id;
#ifdef _SDC_
    int do_new_password = 0;
#endif

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_GTC, reqData, &len);
	if (pos == NULL) {
		ret->ignore = TRUE;
		return NULL;
	}
	id = eap_get_id(reqData);

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-GTC: Request message", pos, len);
#ifdef _SDC_
	// handling for error messages
	if (data->prefix &&
		(len >= 2) && os_memcmp(pos, "E=", 2) == 0) {
		// an error report -- change password?
		int errnum;

		// should not use atoi() in case bad packet, no len limit
		errnum = eap_gtc_parse_errornum(pos+2,len-2);
		wpa_printf(MSG_DEBUG, "EAP-GTC: Error E=%d", errnum);

		switch (errnum) {
		case ERROR_PASSWD_EXPIRED:
		case ERROR_CHANGING_PASSWORD:
			// try new password, or request new password
			do_new_password = 1;
			break;  // break out of while loop
		case ERROR_AUTHENTICATION_FAILURE:
		default:
			// credentials failed -- request password
			wpa_printf(MSG_INFO, "EAP-GTC: Authentication failed");
			eap_sm_request_otp(sm, (const char *) pos, len);
			ret->ignore = TRUE;
			return NULL;
		}
	} else
#endif
	if (data->prefix &&
	    (len < 10 || os_memcmp(pos, "CHALLENGE=", 10) != 0)) {
		wpa_printf(MSG_DEBUG, "EAP-GTC: Challenge did not start with "
			   "expected prefix");

		/* Send an empty response in order to allow tunneled
		 * acknowledgement of the failure. This will also cover the
		 * error case which seems to use EAP-MSCHAPv2 like error
		 * reporting with EAP-GTC inside EAP-FAST tunnel. */
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_GTC,
				     0, EAP_CODE_RESPONSE, id);
		return resp;
	}
#ifdef _SDC_
	else {
        // eap-gtc in PEAP tunnel
        // if we have already used the password, then try the new password
        do_new_password = data->password_tried;
    }
#endif

	password = eap_get_config_otp(sm, &password_len);
	if (password)
		otp = 1;
	else {
		password = eap_get_config_password(sm, &password_len);
		otp = 0;
	}

#ifdef _SDC_
	if (do_new_password) {
        // change password
        password = eap_get_config_new_password(sm, &password_len);
        if (password == NULL || data->password_tried >= 2) {
            // will be restarting, so first time need password again
            data->password_tried = 0;
			eap_sm_request_new_password(sm);
            ret->ignore = TRUE;
            return NULL;
        }
		wpa_printf(MSG_DEBUG, "GTC: setting flag to copy new password on success");
		sm->onSuccessCopyNewPassword = TRUE;
	}
#endif

	if (password == NULL) {
		wpa_printf(MSG_INFO, "EAP-GTC: Password not configured");
		eap_sm_request_otp(sm, (const char *) pos, len);
		ret->ignore = TRUE;
		return NULL;
	}

	ret->ignore = FALSE;

	ret->methodState = data->prefix ? METHOD_MAY_CONT : METHOD_DONE;
	ret->decision = DECISION_COND_SUCC;
	ret->allowNotifications = FALSE;

	plen = password_len;
	identity = eap_get_config_identity(sm, &identity_len);
	if (identity == NULL)
		return NULL;
	if (data->prefix)
		plen += 9 + identity_len + 1;
	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_GTC, plen,
			     EAP_CODE_RESPONSE, id);
	if (resp == NULL)
		return NULL;
	if (data->prefix) {
		wpabuf_put_data(resp, "RESPONSE=", 9);
		wpabuf_put_data(resp, identity, identity_len);
		wpabuf_put_u8(resp, '\0');
	}
	wpabuf_put_data(resp, password, password_len);
	wpa_hexdump_ascii_key(MSG_MSGDUMP, "EAP-GTC: Response",
			      wpabuf_head_u8(resp) + sizeof(struct eap_hdr) +
			      1, plen);

	if (otp) {
		wpa_printf(MSG_DEBUG, "EAP-GTC: Forgetting used password");
		eap_clear_config_otp(sm);
	}

#ifdef _SDC_
    data->password_tried++;
#endif

	return resp;
}


int eap_peer_gtc_register(void)
{
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_GTC, "GTC");
	if (eap == NULL)
		return -1;

	eap->init = eap_gtc_init;
	eap->deinit = eap_gtc_deinit;
	eap->process = eap_gtc_process;
#ifdef _SDC_
	eap->init_for_reauth = eap_gtc_init_for_reauth;
#endif

	return eap_peer_method_register(eap);
}
