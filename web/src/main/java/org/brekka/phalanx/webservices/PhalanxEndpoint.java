package org.brekka.phalanx.webservices;

import java.util.UUID;

import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.services.PhalanxService;
import org.brekka.xml.phalanx.v1.model.PrincipalIdType;
import org.brekka.xml.phalanx.v1.model.UUIDType;
import org.brekka.xml.phalanx.v1.wsops.AuthenticateRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.AuthenticateRequestDocument.AuthenticateRequest;
import org.brekka.xml.phalanx.v1.wsops.AuthenticateResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.AuthenticateResponseDocument.AuthenticateResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

@Endpoint
public class PhalanxEndpoint {
    private static final String NS = "http://brekka.org/xml/phalanx/v1/wsops";
    
    
    @Autowired
    private PhalanxService phalanxService;
    
    @PayloadRoot(localPart = "Authenticate", namespace = NS)
    @ResponsePayload
    public AuthenticateResponseDocument authenticate(AuthenticateRequestDocument requestDocument) {
        AuthenticateResponseDocument responseDocument = AuthenticateResponseDocument.Factory.newInstance();
        AuthenticateResponse response = responseDocument.addNewAuthenticateResponse();
        
        AuthenticateRequest request = requestDocument.getAuthenticateRequest();
        AuthenticatedPrincipal authenticatedPrincipal = phalanxService.authenticate(toUUID(request.getPrincipal().xgetId()), request.getPassword());
        
        
        
        return responseDocument;
    }

    private UUID toUUID(UUIDType uuidType) {
        return UUID.fromString(uuidType.getStringValue());
    }
    
}
