/*
 * rs-serve - (c) 2013 Niklas E. Cathor
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <alloca.h>

#include <sys/signalfd.h>
#include <gssapi.h>

#include "rs-serve.h"

#define IS_READ(r) (r->method == htp_method_GET || r->method == htp_method_HEAD)

// SPNEGO mechanism is 1.3.6.1.5.5.2 -- tag 0x06, lenght 6, 1.3 packed funny:
// uint8_t OID_SPNEGO_bytes [] = { 1*40+3, 6, 1, 5, 5, 2 };
// const gss_OID_desc OID_SPNEGO = {
// 	.length = 6,
// 	.elements =  OID_SPNEGO_bytes
// };

#if 0
static int match_scope(struct rs_scope *scope, evhtp_request_t *req) {
  const char *file_path = REQUEST_GET_PATH(req);
  log_debug("checking scope, name: %s, write: %d", scope->name, scope->write);
  int scope_len = strlen(scope->name);
  // check path
  if( (strcmp(scope->name, "") == 0) || // root scope
      ((strncmp(file_path + 1, scope->name, scope_len) == 0) && // other scope
       file_path[1 + scope_len] == '/') ) {
    log_debug("path authorized");
    // check mode
    if(scope->write || IS_READ(req)) {
      log_debug("mode authorized");
      return 0;
    }
  }
  return -1;
}
#endif


static uint8_t b64_decode_table [256] = {
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 62, 99, 99, 99, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 99, 99, 99, 99, 99, 99,
	99,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 99, 99, 99, 99, 99,
	99, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
};

int b64_decode (gss_buffer_t out, const char *in) {
	uint32_t digit = 0;
	uint32_t block = 0;
	int shift = 3*6;
	out->length = 0;
	while ((shift >= 0) && (digit <= 63)) {
		uint32_t digit = (uint32_t) b64_decode_table [(uint8_t) *in];
		if (digit <= 63) {
			block |= digit << shift;
			shift -= 6;
			in++;
		}
		if (shift < 0) {
			((uint8_t *) out->value) [out->length++] = digit >> 16;
			((uint8_t *) out->value) [out->length++] = digit >>  8;
			((uint8_t *) out->value) [out->length++] = digit      ;
			if (digit <= 63) {
				shift = 3*6;
			}
		}
	}
	if ((*in) && (*in != '=')) {
		return -1;
	}
	while ((out->length > 0) && (*in++ == '=')) {
		out->length--;
	}
	return 0;
}


int authorize_request(evhtp_request_t *req) {
#if 0
  char *username = REQUEST_GET_USER(req);
#endif
  const char *auth_header = evhtp_header_find(req->headers_in, "Authorization");
  evhtp_header_t *wwwauth;
  gss_ctx_id_t ctxh = GSS_C_NO_CONTEXT;
  int b64len;
  gss_buffer_desc gssbuf;
  gss_buffer_desc gssout;
  OM_uint32 major, minor;
  log_debug("Got auth header: %s", auth_header);
  const char *token;
  int retval = 0;
  if(auth_header) {
    if(strncmp(auth_header, "Negotiate ", 10) == 0) {
      token = auth_header + 10;
      b64len = strlen (token);
      if (b64len > 2048) {
	log_error("Rejecting long SPNEGO token: %d characters.", b64len);
	return -2;
      }
      gssbuf.length = (b64len * 3 + 3) >> 2; /* Perhaps slightly too much */
      gssbuf.value = alloca (gssbuf.length);	/* No NULL return */
      log_debug("Got SPNEGO token: %s", token);
      if (b64_decode (&gssbuf, token) < 0) {
	log_error("Rejecting faulty base64 coding in SPNEGO token.");
	return -2;
      }
      //TODO// Sessions are _only_ needed for additional client authentication
      //TODO// So skip: Was a usable GSSAPI context already created?
      major = gss_accept_sec_context (&minor, &ctxh, GSS_C_NO_CREDENTIAL, &gssbuf, GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL /**NONEED:OUTPUT** OID_SPNEGO */, &gssout, NULL /**TODO** &GSS_C_REPLAY_FLAG */, NULL, NULL /**TODO** or lure credential into this varptr with &GSS_C_DELEG_FLAG? */);
      //TODO// Supply token to session's GSSAPI accept environment
      if (major != GSS_S_COMPLETE) {
        if (major == GSS_S_CONTINUE_NEEDED) {
	  log_error("GSSAPI requires continued negotiation, which is not supported.");
	  retval = -2;
        } else {
	  log_error("GSSAPI returns error code %d and minor %d.", major, minor);
	  retval = -1;
        }
      }
      if (gssout.length > 0) {
	if (retval == 0) {
          //TODO// The construct WWW-Authenticate header for the 200 reply
	  log_debug("GSSAPI wants to send data back, which is not supported yet.");
	}
	gss_release_buffer (NULL, &gssout);
	/* Keep retval == 0 --> the client may fail, but we are satisfied */
      }
      if (ctxh != GSS_C_NO_CONTEXT) {
	gss_delete_sec_context (NULL, &ctxh, GSS_C_NO_BUFFER);
      }
      //TODO// Accepted and no sessions?  Then report success right now
      if (major == GSS_S_COMPLETE) {
	return 0;
      }
      return retval;
    }
#if 0
    if(strncmp(auth_header, "Bearer ", 7) == 0) {
      token = auth_header + 7;
      log_debug("Got Bearer token: %s", token);
      struct rs_authorization *auth = lookup_authorization(username, token);
      if(auth == NULL) {
        log_debug("Authorization not found");
      } else {
        log_debug("Got authorization (%p, scopes: %d)", auth, auth->scopes.count);
        struct rs_scope *scope;
        int i;
        for(i=0;i<auth->scopes.count;i++) {
          scope = auth->scopes.ptr[i];
          log_debug("Compare scope %s", scope->name);
          if(match_scope(scope, req) == 0) {
            return 0;
          }
        }
      }
    }
#endif
  }
  // special case: public reads on files (not directories) are allowed.
  // nothing else though.
  if(strncmp(REQUEST_GET_PATH(req), "/public/", 8) == 0 && IS_READ(req) &&
     req->uri->path->file != NULL) {
    return 0;
  }
  wwwauth = evhtp_header_new ("WWW-Authenticate", "Negotiate", 0, 0);
  if (wwwauth) {
    evhtp_headers_add_header (req->headers_out, wwwauth);
  } else {
    log_error("Failed to allocate memory for WWW-Authenticate header.");
  }
  return -1;
}
