#include <freeDiameter/extension.h>

static int my_auth_cb(struct msg **msg, struct avp *avp, struct session *sess, void *cbdata, enum disp_action *act);

/* ثبت افزونه */
static int my_auth_entry(char *conffile)
{
    TRACE_ENTRY("");

    struct dict_object *cmd_aar = NULL;
    struct dict_object *app = NULL;
    struct disp_when data;
    
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "AA-Request", &cmd_aar, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_NAME, "NASREQ Application", &app, ENOENT));
    
    memset(&data, 0, sizeof(data));
    data.app = app;
    data.command = cmd_aar;
    
    CHECK_FCT(fd_disp_register(my_auth_cb, DISP_HOW_CC, &data, NULL, NULL));
    CHECK_FCT(fd_disp_app_support(app, NULL, 0, 1));

    TRACE_DEBUG(INFO, "my_auth extension registered.");
    return 0;
}

/* بررسی پیام AAR */
static int my_auth_cb(struct msg **msg, struct avp *avp, struct session *sess, void *cbdata, enum disp_action *act)
{
    TRACE_ENTRY("");

    struct avp *search = NULL;
    struct dict_object *avp_model = NULL;
    union avp_value *val = NULL;
    struct msg *answer = NULL;

    // دریافت AVP User-Name
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "User-Name", &avp_model, ENOENT));
    CHECK_FCT(fd_msg_search_avp(*msg, avp_model, &search));

    if (!search) {
        TRACE_DEBUG(INFO, "No User-Name AVP found!");
        CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0));
        CHECK_FCT(fd_msg_rescode_set(*msg, "DIAMETER_MISSING_AVP", NULL, NULL, 1));
        *act = DISP_ACT_SEND;
        return 0;
    }

    CHECK_FCT(fd_msg_avp_value_get(search, &val));

    if (val && val->os.data) {
        TRACE_DEBUG(INFO, "Received User-Name: %.*s", val->os.len, val->os.data);
        
        // تولید پاسخ AAA
        CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0));
        
        if (strncmp((char *)val->os.data, "taha", val->os.len) == 0) {
            TRACE_DEBUG(INFO, "Authentication OK for user taha.");
            CHECK_FCT(fd_msg_rescode_set(*msg, "DIAMETER_SUCCESS", NULL, NULL, 1));
        } else {
            TRACE_DEBUG(INFO, "Authentication FAILED for user.");
            CHECK_FCT(fd_msg_rescode_set(*msg, "DIAMETER_AUTHENTICATION_REJECTED", NULL, NULL, 1));
        }
    }

    *act = DISP_ACT_SEND;
    return 0;
}

/* ثبت تابع entrypoint */
EXTENSION_ENTRY("my_auth", my_auth_entry);
