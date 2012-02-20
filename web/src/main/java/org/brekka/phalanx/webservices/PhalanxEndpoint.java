package org.brekka.phalanx.webservices;

import org.brekka.phalanx.services.PhalanxService;
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
    public void authenticate() {
        
    }
    
}
