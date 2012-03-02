package org.brekka.phalanx.webservices;

import java.util.UUID;

import org.apache.xmlbeans.XmlObject;
import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.PrivateKeyToken;
import org.brekka.phalanx.services.PhalanxService;
import org.brekka.phalanx.services.PhalanxSessionService;
import org.brekka.xml.phalanx.v1.model.AuthenticatedPrincipalType;
import org.brekka.xml.phalanx.v1.model.UUIDType;
import org.brekka.xml.phalanx.v1.wsops.AssignKeyPairRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.AssignKeyPairRequestDocument.AssignKeyPairRequest;
import org.brekka.xml.phalanx.v1.wsops.AssignKeyPairResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.AssignKeyPairResponseDocument.AssignKeyPairResponse;
import org.brekka.xml.phalanx.v1.wsops.AsymmetricDecryptionRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.AsymmetricDecryptionRequestDocument.AsymmetricDecryptionRequest;
import org.brekka.xml.phalanx.v1.wsops.AsymmetricDecryptionResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.AsymmetricDecryptionResponseDocument.AsymmetricDecryptionResponse;
import org.brekka.xml.phalanx.v1.wsops.AsymmetricEncryptionRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.AsymmetricEncryptionRequestDocument.AsymmetricEncryptionRequest;
import org.brekka.xml.phalanx.v1.wsops.AsymmetricEncryptionResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.AsymmetricEncryptionResponseDocument.AsymmetricEncryptionResponse;
import org.brekka.xml.phalanx.v1.wsops.AuthenticateRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.AuthenticateRequestDocument.AuthenticateRequest;
import org.brekka.xml.phalanx.v1.wsops.AuthenticateResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.AuthenticateResponseDocument.AuthenticateResponse;
import org.brekka.xml.phalanx.v1.wsops.ChangePasswordRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.ChangePasswordRequestDocument.ChangePasswordRequest;
import org.brekka.xml.phalanx.v1.wsops.ChangePasswordResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.CreatePrincipalRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.CreatePrincipalRequestDocument.CreatePrincipalRequest;
import org.brekka.xml.phalanx.v1.wsops.CreatePrincipalResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.CreatePrincipalResponseDocument.CreatePrincipalResponse;
import org.brekka.xml.phalanx.v1.wsops.DecryptKeyPairRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.DecryptKeyPairRequestDocument.DecryptKeyPairRequest;
import org.brekka.xml.phalanx.v1.wsops.DecryptKeyPairResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.DecryptKeyPairResponseDocument.DecryptKeyPairResponse;
import org.brekka.xml.phalanx.v1.wsops.DeleteCryptedDataRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.DeleteCryptedDataRequestDocument.DeleteCryptedDataRequest;
import org.brekka.xml.phalanx.v1.wsops.DeleteCryptedDataResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.DeleteKeyPairRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.DeleteKeyPairRequestDocument.DeleteKeyPairRequest;
import org.brekka.xml.phalanx.v1.wsops.DeleteKeyPairResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.DeletePrincipalRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.DeletePrincipalRequestDocument.DeletePrincipalRequest;
import org.brekka.xml.phalanx.v1.wsops.DeletePrincipalResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.GenerateKeyPairRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.GenerateKeyPairRequestDocument.GenerateKeyPairRequest;
import org.brekka.xml.phalanx.v1.wsops.GenerateKeyPairResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.GenerateKeyPairResponseDocument.GenerateKeyPairResponse;
import org.brekka.xml.phalanx.v1.wsops.PasswordBasedDecryptionRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.PasswordBasedDecryptionRequestDocument.PasswordBasedDecryptionRequest;
import org.brekka.xml.phalanx.v1.wsops.PasswordBasedDecryptionResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.PasswordBasedDecryptionResponseDocument.PasswordBasedDecryptionResponse;
import org.brekka.xml.phalanx.v1.wsops.PasswordBasedEncryptionRequestDocument;
import org.brekka.xml.phalanx.v1.wsops.PasswordBasedEncryptionRequestDocument.PasswordBasedEncryptionRequest;
import org.brekka.xml.phalanx.v1.wsops.PasswordBasedEncryptionResponseDocument;
import org.brekka.xml.phalanx.v1.wsops.PasswordBasedEncryptionResponseDocument.PasswordBasedEncryptionResponse;
import org.brekka.xml.phalanx.v1.wsops.PrincipalAssertedRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

@Endpoint
public class PhalanxEndpoint {
    private static final String NS = "http://brekka.org/xml/phalanx/v1/wsops";
    
    @Autowired
    private PhalanxService phalanxService;
    
    @Autowired
    private PhalanxSessionService sessionService;
    
    
    @PayloadRoot(localPart = "Authenticate", namespace = NS)
    @ResponsePayload
    public AuthenticateResponseDocument authenticate(AuthenticateRequestDocument requestDocument) {
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
        } finally {
            sessionService.unbind();
        }
        return responseDocument;
    }
    
    @PayloadRoot(localPart = "AsymmetricEncryption", namespace = NS)
    @ResponsePayload
    public AsymmetricEncryptionResponseDocument asymmetricEncryption(AsymmetricEncryptionRequestDocument requestDocument) {
        AsymmetricEncryptionRequest request = requestDocument.getAsymmetricEncryptionRequest();
        return doInSession(request, new SessionCallback<AsymmetricEncryptionRequest, AsymmetricEncryptionResponseDocument>() {
            @Override
            public AsymmetricEncryptionResponseDocument inSession(AsymmetricEncryptionRequest request) {
                AsymmetricEncryptionResponseDocument responseDocument = AsymmetricEncryptionResponseDocument.Factory.newInstance();
                AsymmetricEncryptionResponse response = responseDocument.addNewAsymmetricEncryptionResponse();
                UUID cryptoDataId = phalanxService.asymEncrypt(request.getData(), id(request.getKeyPair().xgetId()));
                response.addNewCryptedData().setId(id(cryptoDataId));
                return responseDocument;
            }
        });
    }
    
    @PayloadRoot(localPart = "AsymmetricDecryption", namespace = NS)
    @ResponsePayload
    public AsymmetricDecryptionResponseDocument asymmetricDecryption(AsymmetricDecryptionRequestDocument requestDocument) {
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

    @PayloadRoot(localPart = "PasswordBasedEncryption", namespace = NS)
    @ResponsePayload
    public PasswordBasedEncryptionResponseDocument passwordBasedEncryption(PasswordBasedEncryptionRequestDocument requestDocument) {
        PasswordBasedEncryptionRequest request = requestDocument.getPasswordBasedEncryptionRequest();
        return doInSession(request, new SessionCallback<PasswordBasedEncryptionRequest, PasswordBasedEncryptionResponseDocument>() {
            @Override
            public PasswordBasedEncryptionResponseDocument inSession(PasswordBasedEncryptionRequest request) {
                PasswordBasedEncryptionResponseDocument responseDocument = PasswordBasedEncryptionResponseDocument.Factory.newInstance();
                PasswordBasedEncryptionResponse response = responseDocument.addNewPasswordBasedEncryptionResponse();
                UUID cryptoDataId = phalanxService.pbeEncrypt(request.getData(), request.getPassword());
                response.addNewCryptedData().setId(id(cryptoDataId));
                return responseDocument;
            }
        });
    }

    @PayloadRoot(localPart = "PasswordBasedDecryption", namespace = NS)
    @ResponsePayload
    public PasswordBasedDecryptionResponseDocument passwordBasedDecryption(PasswordBasedDecryptionRequestDocument requestDocument) {
        PasswordBasedDecryptionRequest request = requestDocument.getPasswordBasedDecryptionRequest();
        return doInSession(request, new SessionCallback<PasswordBasedDecryptionRequest, PasswordBasedDecryptionResponseDocument>() {
            @Override
            public PasswordBasedDecryptionResponseDocument inSession(PasswordBasedDecryptionRequest request) {
                PasswordBasedDecryptionResponseDocument responseDocument = PasswordBasedDecryptionResponseDocument.Factory.newInstance();
                PasswordBasedDecryptionResponse response = responseDocument.addNewPasswordBasedDecryptionResponse();
                byte[] data = phalanxService.pbeDecrypt(id(request.getCryptedData().xgetId()), request.getPassword());
                response.setData(data);
                return responseDocument;
            }
        });
    }

    @PayloadRoot(localPart = "DecryptKeyPair", namespace = NS)
    @ResponsePayload
    public DecryptKeyPairResponseDocument decryptKeyPair(DecryptKeyPairRequestDocument requestDocument) {
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

    @PayloadRoot(localPart = "GenerateKeyPair", namespace = NS)
    @ResponsePayload
    public GenerateKeyPairResponseDocument generateKeyPair(GenerateKeyPairRequestDocument requestDocument) {
        GenerateKeyPairRequest request = requestDocument.getGenerateKeyPairRequest();
        return doInSession(request, new SessionCallback<GenerateKeyPairRequest, GenerateKeyPairResponseDocument>() {
            @Override
            public GenerateKeyPairResponseDocument inSession(GenerateKeyPairRequest request) {
                GenerateKeyPairResponseDocument responseDocument = GenerateKeyPairResponseDocument.Factory.newInstance();
                GenerateKeyPairResponse response = responseDocument.addNewGenerateKeyPairResponse();
                UUID keyPairId = phalanxService.generateKeyPair(id(request.getKeyPair().xgetId()), id(request.getOwner().xgetId()));
                response.addNewKeyPair().setId(id(keyPairId));
                return responseDocument;
            }
        });
    }

    @PayloadRoot(localPart = "AssignKeyPair", namespace = NS)
    @ResponsePayload
    public AssignKeyPairResponseDocument assignKeyPair(AssignKeyPairRequestDocument requestDocument) {
        AssignKeyPairRequest request = requestDocument.getAssignKeyPairRequest();
        return doInSession(request, new SessionCallback<AssignKeyPairRequest, AssignKeyPairResponseDocument>() {
            @Override
            public AssignKeyPairResponseDocument inSession(AssignKeyPairRequest request) {
                AssignKeyPairResponseDocument responseDocument = AssignKeyPairResponseDocument.Factory.newInstance();
                AssignKeyPairResponse response = responseDocument.addNewAssignKeyPairResponse();
                PrivateKeyToken privateKeyToken = sessionService.retrievePrivateKey(request.getPrivateKey());
                UUID keyPairId = phalanxService.assignKeyPair(privateKeyToken, id(request.getAssignTo().xgetId()));
                response.addNewKeyPair().setId(id(keyPairId));
                return responseDocument;
            }
        });
    }

    @PayloadRoot(localPart = "DeleteCryptedData", namespace = NS)
    @ResponsePayload
    public DeleteCryptedDataResponseDocument deleteCryptedData(DeleteCryptedDataRequestDocument requestDocument) {
        DeleteCryptedDataRequest request = requestDocument.getDeleteCryptedDataRequest();
        return doInSession(request, new SessionCallback<DeleteCryptedDataRequest, DeleteCryptedDataResponseDocument>() {
            @Override
            public DeleteCryptedDataResponseDocument inSession(DeleteCryptedDataRequest request) {
                DeleteCryptedDataResponseDocument responseDocument = DeleteCryptedDataResponseDocument.Factory.newInstance();
                responseDocument.addNewDeleteCryptedDataResponse();
                phalanxService.deleteCryptoDataItem(id(request.getCryptedData().xgetId()));
                return responseDocument;
            }
        });
    }

    @PayloadRoot(localPart = "DeleteKeyPair", namespace = NS)
    @ResponsePayload
    public DeleteKeyPairResponseDocument deleteKeyPair(DeleteKeyPairRequestDocument requestDocument) {
        DeleteKeyPairRequest request = requestDocument.getDeleteKeyPairRequest();
        return doInSession(request, new SessionCallback<DeleteKeyPairRequest, DeleteKeyPairResponseDocument>() {
            @Override
            public DeleteKeyPairResponseDocument inSession(DeleteKeyPairRequest request) {
                DeleteKeyPairResponseDocument responseDocument = DeleteKeyPairResponseDocument.Factory.newInstance();
                responseDocument.addNewDeleteKeyPairResponse();
                phalanxService.deleteKeyPair(id(request.getKeyPair().xgetId()));
                return responseDocument;
            }
        });
    }

    @PayloadRoot(localPart = "CreatePrincipal", namespace = NS)
    @ResponsePayload
    public CreatePrincipalResponseDocument createPrincipal(CreatePrincipalRequestDocument requestDocument) {
        CreatePrincipalRequest request = requestDocument.getCreatePrincipalRequest();
        CreatePrincipalResponseDocument responseDocument = CreatePrincipalResponseDocument.Factory.newInstance();
        CreatePrincipalResponse response = responseDocument.addNewCreatePrincipalResponse();
        
        UUID principalId = phalanxService.createPrincipal(request.getPassword());
        response.addNewPrincipal().setId(id(principalId));
        
        return responseDocument;
    }

    @PayloadRoot(localPart = "DeletePrincipal", namespace = NS)
    @ResponsePayload
    public DeletePrincipalResponseDocument deletePrincipal(DeletePrincipalRequestDocument requestDocument) {
        DeletePrincipalRequest request = requestDocument.getDeletePrincipalRequest();
        DeletePrincipalResponseDocument responseDocument = DeletePrincipalResponseDocument.Factory.newInstance();
        responseDocument.addNewDeletePrincipalResponse();
        
        phalanxService.deletePrincipal(id(request.getPrincipal().xgetId()));
        
        return responseDocument;
    }

    @PayloadRoot(localPart = "ChangePassword", namespace = NS)
    @ResponsePayload
    public ChangePasswordResponseDocument changePassword(ChangePasswordRequestDocument requestDocument) {
        ChangePasswordRequest request = requestDocument.getChangePasswordRequest();
        return doInSession(request, new SessionCallback<ChangePasswordRequest, ChangePasswordResponseDocument>() {
            @Override
            public ChangePasswordResponseDocument inSession(ChangePasswordRequest request) {
                ChangePasswordResponseDocument responseDocument = ChangePasswordResponseDocument.Factory.newInstance();
                responseDocument.addNewChangePasswordResponse();
                AuthenticatedPrincipal principal = sessionService.getCurrentPrincipal();
                phalanxService.changePassword(principal.getPrincipal().getId(), request.getCurrentPassword(), request.getNewPassword());
                return responseDocument;
            }
        });
    }


    protected <Req extends PrincipalAssertedRequest, ResDoc extends XmlObject> ResDoc doInSession(Req request, SessionCallback<Req, ResDoc> operation) {
        try {
            sessionService.bind(request.getSessionID());
            return operation.inSession(request);
        } finally {
            sessionService.unbind();
        }
    }
    
    
    protected static UUID id(UUIDType uuidType) {
        return UUID.fromString(uuidType.getStringValue());
    }
    
    protected static String id(UUID id) {
        return id.toString();
    }
    
    interface SessionCallback<Request, ResponseDocument> {
        ResponseDocument inSession(Request request);
    }
}
