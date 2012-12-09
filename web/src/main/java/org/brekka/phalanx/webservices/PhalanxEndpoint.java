package org.brekka.phalanx.webservices;

import java.util.UUID;

import org.apache.xmlbeans.XmlObject;
import org.brekka.phalanx.api.beans.IdentityCryptedData;
import org.brekka.phalanx.api.beans.IdentityKeyPair;
import org.brekka.phalanx.api.beans.IdentityPrincipal;
import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.CryptedData;
import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.api.services.PhalanxService;
import org.brekka.phalanx.core.services.PhalanxSessionService;
import org.brekka.xml.phalanx.v2.model.AuthenticatedPrincipalType;
import org.brekka.xml.phalanx.v2.model.CryptedDataIdType;
import org.brekka.xml.phalanx.v2.model.KeyPairIdType;
import org.brekka.xml.phalanx.v2.model.PrincipalIdType;
import org.brekka.xml.phalanx.v2.model.PrincipalType;
import org.brekka.xml.phalanx.v2.model.UUIDType;
import org.brekka.xml.phalanx.v2.wsops.AssignKeyPairRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.AssignKeyPairRequestDocument.AssignKeyPairRequest;
import org.brekka.xml.phalanx.v2.wsops.AssignKeyPairResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.AssignKeyPairResponseDocument.AssignKeyPairResponse;
import org.brekka.xml.phalanx.v2.wsops.AsymmetricDecryptionRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.AsymmetricDecryptionRequestDocument.AsymmetricDecryptionRequest;
import org.brekka.xml.phalanx.v2.wsops.AsymmetricDecryptionResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.AsymmetricDecryptionResponseDocument.AsymmetricDecryptionResponse;
import org.brekka.xml.phalanx.v2.wsops.AsymmetricEncryptionRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.AsymmetricEncryptionRequestDocument.AsymmetricEncryptionRequest;
import org.brekka.xml.phalanx.v2.wsops.AsymmetricEncryptionResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.AsymmetricEncryptionResponseDocument.AsymmetricEncryptionResponse;
import org.brekka.xml.phalanx.v2.wsops.AuthenticateRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.AuthenticateRequestDocument.AuthenticateRequest;
import org.brekka.xml.phalanx.v2.wsops.AuthenticateResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.AuthenticateResponseDocument.AuthenticateResponse;
import org.brekka.xml.phalanx.v2.wsops.ChangePasswordRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.ChangePasswordRequestDocument.ChangePasswordRequest;
import org.brekka.xml.phalanx.v2.wsops.ChangePasswordResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.CloneKeyPairPublicRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.CloneKeyPairPublicRequestDocument.CloneKeyPairPublicRequest;
import org.brekka.xml.phalanx.v2.wsops.CloneKeyPairPublicResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.CloneKeyPairPublicResponseDocument.CloneKeyPairPublicResponse;
import org.brekka.xml.phalanx.v2.wsops.CreatePrincipalRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.CreatePrincipalRequestDocument.CreatePrincipalRequest;
import org.brekka.xml.phalanx.v2.wsops.CreatePrincipalResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.CreatePrincipalResponseDocument.CreatePrincipalResponse;
import org.brekka.xml.phalanx.v2.wsops.DecryptKeyPairRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.DecryptKeyPairRequestDocument.DecryptKeyPairRequest;
import org.brekka.xml.phalanx.v2.wsops.DecryptKeyPairResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.DecryptKeyPairResponseDocument.DecryptKeyPairResponse;
import org.brekka.xml.phalanx.v2.wsops.DeleteCryptedDataRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.DeleteCryptedDataRequestDocument.DeleteCryptedDataRequest;
import org.brekka.xml.phalanx.v2.wsops.DeleteCryptedDataResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.DeleteKeyPairRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.DeleteKeyPairRequestDocument.DeleteKeyPairRequest;
import org.brekka.xml.phalanx.v2.wsops.DeleteKeyPairResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.DeletePrincipalRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.DeletePrincipalRequestDocument.DeletePrincipalRequest;
import org.brekka.xml.phalanx.v2.wsops.DeletePrincipalResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.GenerateKeyPairRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.GenerateKeyPairRequestDocument.GenerateKeyPairRequest;
import org.brekka.xml.phalanx.v2.wsops.GenerateKeyPairResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.GenerateKeyPairResponseDocument.GenerateKeyPairResponse;
import org.brekka.xml.phalanx.v2.wsops.LogoutRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.LogoutRequestDocument.LogoutRequest;
import org.brekka.xml.phalanx.v2.wsops.LogoutResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedDecryptionRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedDecryptionRequestDocument.PasswordBasedDecryptionRequest;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedDecryptionResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedDecryptionResponseDocument.PasswordBasedDecryptionResponse;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedEncryptionRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedEncryptionRequestDocument.PasswordBasedEncryptionRequest;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedEncryptionResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedEncryptionResponseDocument.PasswordBasedEncryptionResponse;
import org.brekka.xml.phalanx.v2.wsops.PrincipalAssertedRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

@Endpoint
public class PhalanxEndpoint {
    private static final String NS = "http://brekka.org/xml/phalanx/v2/wsops";
    
    @Autowired
    private PhalanxService phalanxService;
    
    @Autowired
    private PhalanxSessionService sessionService;
    
    @PayloadRoot(localPart = "AuthenticateRequest", namespace = NS)
    @ResponsePayload
    public AuthenticateResponseDocument authenticate(@RequestPayload AuthenticateRequestDocument requestDocument) {
        AuthenticateResponseDocument responseDocument = AuthenticateResponseDocument.Factory.newInstance();
        AuthenticateResponse response = responseDocument.addNewAuthenticateResponse();
        
        AuthenticateRequest request = requestDocument.getAuthenticateRequest();
        AuthenticatedPrincipal authenticatedPrincipal = phalanxService.authenticate(id(request.getPrincipal().xgetId()), request.getPassword());
        try {
            byte[] sessionId = sessionService.allocateAndBind(authenticatedPrincipal);
            byte[] privateKeyTokenId = sessionService.registerPrivateKey(authenticatedPrincipal.getDefaultPrivateKey());
            
            AuthenticatedPrincipalType authenticatedPrincipalXml = response.addNewAuthenticatedPrincipal();
            authenticatedPrincipalXml.setId(id(authenticatedPrincipal.getPrincipal().getId()));
            authenticatedPrincipalXml.setDefaultPrivateKey(privateKeyTokenId);
            authenticatedPrincipalXml.setSessionID(sessionId);
            authenticatedPrincipalXml.addNewDefaultKeyPair()
                .setId(id(authenticatedPrincipal.getPrincipal().getDefaultKeyPair().getId()));
        } finally {
            sessionService.unbind();
        }
        return responseDocument;
    }
    
    
    @PayloadRoot(localPart = "LogoutRequest", namespace = NS)
    @ResponsePayload
    public LogoutResponseDocument asymmetricEncryption(@RequestPayload LogoutRequestDocument requestDocument) {
        LogoutRequest request = requestDocument.getLogoutRequest();
        sessionService.logout(request.getSessionID());
        LogoutResponseDocument responseDocument = LogoutResponseDocument.Factory.newInstance();
        responseDocument.addNewLogoutResponse();
        return responseDocument;
    }
    
    @PayloadRoot(localPart = "AsymmetricEncryptionRequest", namespace = NS)
    @ResponsePayload
    public AsymmetricEncryptionResponseDocument asymmetricEncryption(@RequestPayload AsymmetricEncryptionRequestDocument requestDocument) {
        AsymmetricEncryptionRequest request = requestDocument.getAsymmetricEncryptionRequest();
        CryptedData cryptedData;
        if (request.isSetKeyPair()) {
            cryptedData = phalanxService.asymEncrypt(request.getData(), id(request.getKeyPair().xgetId()));
        } else {
            cryptedData = phalanxService.asymEncrypt(request.getData(), id(request.getRecipient().xgetId()));
        }
        
        AsymmetricEncryptionResponseDocument responseDocument = AsymmetricEncryptionResponseDocument.Factory.newInstance();
        AsymmetricEncryptionResponse response = responseDocument.addNewAsymmetricEncryptionResponse();
        response.addNewCryptedData().setId(id(cryptedData.getId()));
        return responseDocument;
    }
    
    @PayloadRoot(localPart = "AsymmetricDecryptionRequest", namespace = NS)
    @ResponsePayload
    public AsymmetricDecryptionResponseDocument asymmetricDecryption(@RequestPayload AsymmetricDecryptionRequestDocument requestDocument) {
        AsymmetricDecryptionRequest request = requestDocument.getAsymmetricDecryptionRequest();
        return doInSession(request, new SessionCallback<AsymmetricDecryptionRequest, AsymmetricDecryptionResponseDocument>() {
            @Override
            public AsymmetricDecryptionResponseDocument inSession(AsymmetricDecryptionRequest request) {
                AsymmetricDecryptionResponseDocument responseDocument = AsymmetricDecryptionResponseDocument.Factory.newInstance();
                AsymmetricDecryptionResponse response = responseDocument.addNewAsymmetricDecryptionResponse();
                PrivateKeyToken privateKeyToken = sessionService.retrievePrivateKey(request.getPrivateKey());
                byte[] data = phalanxService.asymDecrypt(id(request.getCryptedData().xgetId()), privateKeyToken);
                response.setData(data);
                return responseDocument;
            }
        });
    }

    @PayloadRoot(localPart = "PasswordBasedEncryptionRequest", namespace = NS)
    @ResponsePayload
    public PasswordBasedEncryptionResponseDocument passwordBasedEncryption(@RequestPayload PasswordBasedEncryptionRequestDocument requestDocument) {
        PasswordBasedEncryptionRequest request = requestDocument.getPasswordBasedEncryptionRequest();
        CryptedData cryptoData = phalanxService.pbeEncrypt(request.getData(), request.getPassword());
        
        PasswordBasedEncryptionResponseDocument responseDocument = PasswordBasedEncryptionResponseDocument.Factory.newInstance();
        PasswordBasedEncryptionResponse response = responseDocument.addNewPasswordBasedEncryptionResponse();
        response.addNewCryptedData().setId(id(cryptoData.getId()));
        return responseDocument;
    }

    @PayloadRoot(localPart = "PasswordBasedDecryptionRequest", namespace = NS)
    @ResponsePayload
    public PasswordBasedDecryptionResponseDocument passwordBasedDecryption(@RequestPayload PasswordBasedDecryptionRequestDocument requestDocument) {
        PasswordBasedDecryptionRequest request = requestDocument.getPasswordBasedDecryptionRequest();
        byte[] data = phalanxService.pbeDecrypt(id(request.getCryptedData().xgetId()), request.getPassword());
        
        PasswordBasedDecryptionResponseDocument responseDocument = PasswordBasedDecryptionResponseDocument.Factory.newInstance();
        PasswordBasedDecryptionResponse response = responseDocument.addNewPasswordBasedDecryptionResponse();
        response.setData(data);
        return responseDocument;
    }

    @PayloadRoot(localPart = "DecryptKeyPairRequest", namespace = NS)
    @ResponsePayload
    public DecryptKeyPairResponseDocument decryptKeyPair(@RequestPayload DecryptKeyPairRequestDocument requestDocument) {
        DecryptKeyPairRequest request = requestDocument.getDecryptKeyPairRequest();
        return doInSession(request, new SessionCallback<DecryptKeyPairRequest, DecryptKeyPairResponseDocument>() {
            @Override
            public DecryptKeyPairResponseDocument inSession(DecryptKeyPairRequest request) {
                DecryptKeyPairResponseDocument responseDocument = DecryptKeyPairResponseDocument.Factory.newInstance();
                DecryptKeyPairResponse response = responseDocument.addNewDecryptKeyPairResponse();
                PrivateKeyToken privateKeyToken = sessionService.retrievePrivateKey(request.getPrivateKey());
                PrivateKeyToken decryptedPrivateKeyToken = phalanxService.decryptKeyPair(id(request.getKeyPair().xgetId()), privateKeyToken);
                byte[] registeredPrivateKey = sessionService.registerPrivateKey(decryptedPrivateKeyToken);
                response.setPrivateKey(registeredPrivateKey);
                return responseDocument;
            }
        });
    }

    @PayloadRoot(localPart = "GenerateKeyPairRequest", namespace = NS)
    @ResponsePayload
    public GenerateKeyPairResponseDocument generateKeyPair(@RequestPayload GenerateKeyPairRequestDocument requestDocument) {
        GenerateKeyPairRequest request = requestDocument.getGenerateKeyPairRequest();
        KeyPair keyPair;
        if (request.isSetOwner()) {
            keyPair = phalanxService.generateKeyPair(id(request.getKeyPair().xgetId()), id(request.getOwner().xgetId()));
        } else {
            keyPair = phalanxService.generateKeyPair(id(request.getKeyPair().xgetId()));
        }
        GenerateKeyPairResponseDocument responseDocument = GenerateKeyPairResponseDocument.Factory.newInstance();
        GenerateKeyPairResponse response = responseDocument.addNewGenerateKeyPairResponse();
        response.addNewKeyPair().setId(id(keyPair.getId()));
        return responseDocument;
    }

    @PayloadRoot(localPart = "AssignKeyPairRequest", namespace = NS)
    @ResponsePayload
    public AssignKeyPairResponseDocument assignKeyPair(@RequestPayload AssignKeyPairRequestDocument requestDocument) {
        AssignKeyPairRequest request = requestDocument.getAssignKeyPairRequest();
        return doInSession(request, new SessionCallback<AssignKeyPairRequest, AssignKeyPairResponseDocument>() {
            @Override
            public AssignKeyPairResponseDocument inSession(AssignKeyPairRequest request) {
                AssignKeyPairResponseDocument responseDocument = AssignKeyPairResponseDocument.Factory.newInstance();
                AssignKeyPairResponse response = responseDocument.addNewAssignKeyPairResponse();
                PrivateKeyToken privateKeyToken = sessionService.retrievePrivateKey(request.getPrivateKey());
                KeyPair keyPair = phalanxService.assignKeyPair(privateKeyToken, id(request.getAssignTo().xgetId()));
                response.addNewKeyPair().setId(id(keyPair.getId()));
                return responseDocument;
            }
        });
    }
    
    @PayloadRoot(localPart = "CloneKeyPairPublicRequest", namespace = NS)
    @ResponsePayload
    public CloneKeyPairPublicResponseDocument cloneKeyPairPublic(@RequestPayload CloneKeyPairPublicRequestDocument requestDocument) {
        CloneKeyPairPublicRequest request = requestDocument.getCloneKeyPairPublicRequest();
        CloneKeyPairPublicResponseDocument responseDocument = CloneKeyPairPublicResponseDocument.Factory.newInstance();
        CloneKeyPairPublicResponse response = responseDocument.addNewCloneKeyPairPublicResponse();
        KeyPair keyPair = phalanxService.cloneKeyPairPublic(id(request.getKeyPair().xgetId()));
        response.addNewKeyPair().setId(id(keyPair.getId()));
        return responseDocument;
    }

    @PayloadRoot(localPart = "DeleteCryptedDataRequest", namespace = NS)
    @ResponsePayload
    public DeleteCryptedDataResponseDocument deleteCryptedData(@RequestPayload DeleteCryptedDataRequestDocument requestDocument) {
        DeleteCryptedDataRequest request = requestDocument.getDeleteCryptedDataRequest();
        DeleteCryptedDataResponseDocument responseDocument = DeleteCryptedDataResponseDocument.Factory.newInstance();
        responseDocument.addNewDeleteCryptedDataResponse();
        phalanxService.deleteCryptedData(id(request.getCryptedData().xgetId()));
        return responseDocument;
    }

    @PayloadRoot(localPart = "DeleteKeyPairRequest", namespace = NS)
    @ResponsePayload
    public DeleteKeyPairResponseDocument deleteKeyPair(@RequestPayload DeleteKeyPairRequestDocument requestDocument) {
        DeleteKeyPairRequest request = requestDocument.getDeleteKeyPairRequest();
        DeleteKeyPairResponseDocument responseDocument = DeleteKeyPairResponseDocument.Factory.newInstance();
        responseDocument.addNewDeleteKeyPairResponse();
        phalanxService.deleteKeyPair(id(request.getKeyPair().xgetId()));
        return responseDocument;
    }

    @PayloadRoot(localPart = "CreatePrincipalRequest", namespace = NS)
    @ResponsePayload
    public CreatePrincipalResponseDocument createPrincipal(@RequestPayload CreatePrincipalRequestDocument requestDocument) {
        CreatePrincipalRequest request = requestDocument.getCreatePrincipalRequest();
        CreatePrincipalResponseDocument responseDocument = CreatePrincipalResponseDocument.Factory.newInstance();
        CreatePrincipalResponse response = responseDocument.addNewCreatePrincipalResponse();
        
        Principal principal = phalanxService.createPrincipal(request.getPassword());
        PrincipalType principalXml = response.addNewPrincipal();
        principalXml.setId(id(principal.getId()));
        principalXml.addNewDefaultKeyPair().setId(id(principal.getDefaultKeyPair().getId()));
        
        return responseDocument;
    }

    @PayloadRoot(localPart = "DeletePrincipalRequest", namespace = NS)
    @ResponsePayload
    public DeletePrincipalResponseDocument deletePrincipal(@RequestPayload DeletePrincipalRequestDocument requestDocument) {
        DeletePrincipalRequest request = requestDocument.getDeletePrincipalRequest();
        DeletePrincipalResponseDocument responseDocument = DeletePrincipalResponseDocument.Factory.newInstance();
        responseDocument.addNewDeletePrincipalResponse();
        
        phalanxService.deletePrincipal(id(request.getPrincipal().xgetId()));
        
        return responseDocument;
    }

    @PayloadRoot(localPart = "ChangePasswordRequest", namespace = NS)
    @ResponsePayload
    public ChangePasswordResponseDocument changePassword(@RequestPayload ChangePasswordRequestDocument requestDocument) {
        ChangePasswordRequest request = requestDocument.getChangePasswordRequest();
        AuthenticatedPrincipal principal = sessionService.getCurrentPrincipal();
        phalanxService.changePassword(principal.getPrincipal(), request.getCurrentPassword(), request.getNewPassword());
        
        ChangePasswordResponseDocument responseDocument = ChangePasswordResponseDocument.Factory.newInstance();
        responseDocument.addNewChangePasswordResponse();
        return responseDocument;
    }


    protected <Req extends PrincipalAssertedRequest, ResDoc extends XmlObject> ResDoc doInSession(Req request, SessionCallback<Req, ResDoc> operation) {
        try {
            sessionService.bind(request.getSessionID());
            return operation.inSession(request);
        } finally {
            sessionService.unbind();
        }
    }
    
    
    protected static UUID uuid(UUIDType uuidType) {
        return UUID.fromString(uuidType.getStringValue());
    }
    
    protected static IdentityKeyPair id(KeyPairIdType keyPairId) {
        return new IdentityKeyPair(uuid(keyPairId));
    }
    protected static IdentityPrincipal id(PrincipalIdType principalId) {
        return new IdentityPrincipal(uuid(principalId));
    }
    
    protected static IdentityCryptedData id(CryptedDataIdType cryptedDataId) {
        return new IdentityCryptedData(uuid(cryptedDataId));
    }
    
    protected static String id(UUID id) {
        return id.toString();
    }
    
    interface SessionCallback<Request, ResponseDocument> {
        ResponseDocument inSession(Request request);
    }
}
