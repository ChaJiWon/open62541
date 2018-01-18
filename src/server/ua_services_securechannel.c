/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2014 (C) Leon Urbas
 *    Copyright 2014 (C) opcua
 *    Copyright 2014-2017 (C) Julius Pfrommer
 *    Copyright 2014, 2017 (C) Florian Palm
 *    Copyright 2015 (C) Oleksiy Vasylyev
 *    Copyright 2017 (C) Mark Giraud
 *    Copyright 2017 (C) Stefan Profanter
 */

#include "ua_server_internal.h"
#include "ua_services.h"
#include "ua_securechannel_manager.h"

void
Service_OpenSecureChannel(UA_Server *server, UA_SecureChannel *channel,
                          const UA_OpenSecureChannelRequest *request,
                          UA_OpenSecureChannelResponse *response) {
    if(request->requestType == UA_SECURITYTOKENREQUESTTYPE_RENEW) {
        /* Renew the channel */
        response->responseHeader.serviceResult =
            UA_SecureChannelManager_renew(&server->secureChannelManager,
                                          channel, request, response);

        /* Logging */
        if(response->responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
            UA_LOG_DEBUG_CHANNEL(server->config.logger, channel,
                                 "SecureChannel renewed");
        } else {
            UA_LOG_DEBUG_CHANNEL(server->config.logger, channel,
                                 "Renewing SecureChannel failed");
        }
        return;
    }

    /* Must be ISSUE or RENEW */
    if(request->requestType != UA_SECURITYTOKENREQUESTTYPE_ISSUE) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADINTERNALERROR;
        return;
    }

    /* Open the channel */
    response->responseHeader.serviceResult =
        UA_SecureChannelManager_open(&server->secureChannelManager, channel,
                                     request, response);

    /* Logging */
    if(response->responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO_CHANNEL(server->config.logger, channel,
                            "Opened SecureChannel");
    } else {
        UA_LOG_INFO_CHANNEL(server->config.logger, channel,
                            "Opening a SecureChannel failed");
    }
}

/* The server does not send a CloseSecureChannel response */
void
Service_CloseSecureChannel(UA_Server *server, UA_SecureChannel *channel) {
    UA_LOG_INFO_CHANNEL(server->config.logger, channel, "CloseSecureChannel");
    UA_SecureChannelManager_close(&server->secureChannelManager,
                                  channel->securityToken.channelId);
}
