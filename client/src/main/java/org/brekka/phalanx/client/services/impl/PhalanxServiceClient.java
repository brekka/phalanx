package org.brekka.phalanx.client.services.impl;

import java.util.UUID;

import javax.xml.transform.Result;
import javax.xml.transform.dom.DOMResult;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.api.beans.IdentityCryptedData;
import org.brekka.phalanx.api.beans.IdentityKeyPair;
import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.CryptedData;
import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.api.services.PhalanxService;
import org.brekka.xml.phalanx.v2.model.AuthenticatedPrincipalType;
import org.brekka.xml.phalanx.v2.model.CryptedDataType;
import org.brekka.xml.phalanx.v2.model.KeyPairType;
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
import org.brekka.xml.phalanx.v2.wsops.OperationFault;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedDecryptionRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedDecryptionRequestDocument.PasswordBasedDecryptionRequest;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedDecryptionResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedDecryptionResponseDocument.PasswordBasedDecryptionResponse;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedEncryptionRequestDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedEncryptionRequestDocument.PasswordBasedEncryptionRequest;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedEncryptionResponseDocument;
import org.brekka.xml.phalanx.v2.wsops.PasswordBasedEncryptionResponseDocument.PasswordBasedEncryptionResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.ws.client.core.WebServiceOperations;
import org.springframework.ws.soap.client.SoapFaultClientException;
import org.w3c.dom.Node;

@Service
public class PhalanxServiceClient implements PhalanxService {

    @Autowired
    private WebServiceOperations phalanxWebServiceOperations;
    
    
    public PhalanxServiceClient() {
        super();
    }
    
    public PhalanxServiceClient(WebServiceOperations phalanxWebServiceOperations) {
        this();
        this.phalanxWebServiceOperations = phalanxWebServiceOperations;
    }
    
    @Override
    public CryptedData asymEncrypt(byte[] data, KeyPair keyPair) {
        AsymmetricEncryptionRequestDocument requestDocument = AsymmetricEncryptionRequestDocument.Factory.newInstance();
        AsymmetricEncryptionRequest request = requestDocument.addNewAsymmetricEncryptionRequest();
        request.setData(data);
        request.setKeyPair(xml(keyPair));
        
        AsymmetricEncryptionResponseDocument responseDocument = marshal(requestDocument, AsymmetricEncryptionResponseDocument.class);
        AsymmetricEncryptionResponse response = responseDocument.getAsymmetricEncryptionResponse();
        return identity(response.getCryptedData());
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phalanx.api.services.PhalanxService#asymEncrypt(byte[], org.brekka.phalanx.api.model.Principal)
     */
    @Override
    public CryptedData asymEncrypt(byte[] data, Principal recipientPrincipal) {
        AsymmetricEncryptionRequestDocument requestDocument = AsymmetricEncryptionRequestDocument.Factory.newInstance();
        AsymmetricEncryptionRequest request = requestDocument.addNewAsymmetricEncryptionRequest();
        request.setData(data);
        request.setRecipient(xml(recipientPrincipal));
        
        AsymmetricEncryptionResponseDocument responseDocument = marshal(requestDocument, AsymmetricEncryptionResponseDocument.class);
        AsymmetricEncryptionResponse response = responseDocument.getAsymmetricEncryptionResponse();
        return identity(response.getCryptedData());
    }
    
    @Override
    public byte[] asymDecrypt(CryptedData asymedCryptoData, PrivateKeyToken privateKeyToken) {
        AsymmetricDecryptionRequestDocument requestDocument = AsymmetricDecryptionRequestDocument.Factory.newInstance();
        AsymmetricDecryptionRequest request = requestDocument.addNewAsymmetricDecryptionRequest();
        
        PrivateKeyTokenImpl privateKey = narrow(privateKeyToken);
        request.setSessionID(privateKey.getAuthenticatedPrincipal().getSessionId());
        request.setPrivateKey(privateKey.getId());
        request.setCryptedData(xml(asymedCryptoData));
        
        AsymmetricDecryptionResponseDocument responseDocument = marshal(requestDocument, AsymmetricDecryptionResponseDocument.class);
        AsymmetricDecryptionResponse response = responseDocument.getAsymmetricDecryptionResponse();
        return response.getData();
    }

    @Override
    public CryptedData pbeEncrypt(byte[] data, String password) {
        PasswordBasedEncryptionRequestDocument requestDocument = PasswordBasedEncryptionRequestDocument.Factory.newInstance();
        PasswordBasedEncryptionRequest request = requestDocument.addNewPasswordBasedEncryptionRequest();
        request.setData(data);
        request.setPassword(password);
        
        PasswordBasedEncryptionResponseDocument responseDocument = marshal(requestDocument, PasswordBasedEncryptionResponseDocument.class);
        PasswordBasedEncryptionResponse response = responseDocument.getPasswordBasedEncryptionResponse();
        return identity(response.getCryptedData());
    }

    @Override
    public byte[] pbeDecrypt(CryptedData passwordedCryptoData, String password) {
        PasswordBasedDecryptionRequestDocument requestDocument = PasswordBasedDecryptionRequestDocument.Factory.newInstance();
        PasswordBasedDecryptionRequest request = requestDocument.addNewPasswordBasedDecryptionRequest();
        request.setCryptedData(xml(passwordedCryptoData));
        request.setPassword(password);
        
        PasswordBasedDecryptionResponseDocument responseDocument = marshal(requestDocument, PasswordBasedDecryptionResponseDocument.class);
        PasswordBasedDecryptionResponse response = responseDocument.getPasswordBasedDecryptionResponse();
        return response.getData();
    }

    @Override
    public PrivateKeyToken decryptKeyPair(KeyPair keyPair, PrivateKeyToken privateKeyToken) {
        DecryptKeyPairRequestDocument requestDocument = DecryptKeyPairRequestDocument.Factory.newInstance();
        DecryptKeyPairRequest request = requestDocument.addNewDecryptKeyPairRequest();
        PrivateKeyTokenImpl privateKey = narrow(privateKeyToken);
        request.setKeyPair(xml(keyPair));
        request.setSessionID(privateKey.getAuthenticatedPrincipal().getSessionId());
        request.setPrivateKey(privateKey.getId());
        
        DecryptKeyPairResponseDocument responseDocument = marshal(requestDocument, DecryptKeyPairResponseDocument.class);
        DecryptKeyPairResponse response = responseDocument.getDecryptKeyPairResponse();
        return new PrivateKeyTokenImpl(response.getPrivateKey(), keyPair, privateKey.getAuthenticatedPrincipal());
    }

    @Override
    public KeyPair generateKeyPair(KeyPair protectedByKeyPair, Principal ownerPrincipal) {
        GenerateKeyPairRequestDocument requestDocument = GenerateKeyPairRequestDocument.Factory.newInstance();
        GenerateKeyPairRequest request = requestDocument.addNewGenerateKeyPairRequest();
        request.setKeyPair(xml(protectedByKeyPair));
        if (ownerPrincipal != null) {
            request.setOwner(xml(ownerPrincipal));
        }
        
        GenerateKeyPairResponseDocument responseDocument = marshal(requestDocument, GenerateKeyPairResponseDocument.class);
        GenerateKeyPairResponse response = responseDocument.getGenerateKeyPairResponse();
        return identity(response.getKeyPair());
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phalanx.api.services.PhalanxService#generateKeyPair(org.brekka.phalanx.api.model.KeyPair)
     */
    @Override
    public KeyPair generateKeyPair(KeyPair protectedByKeyPair) {
        CloneKeyPairPublicRequestDocument requestDocument = CloneKeyPairPublicRequestDocument.Factory.newInstance();
        CloneKeyPairPublicRequest request = requestDocument.addNewCloneKeyPairPublicRequest();
        request.setKeyPair(xml(protectedByKeyPair));
        CloneKeyPairPublicResponseDocument responseDocument = marshal(requestDocument, CloneKeyPairPublicResponseDocument.class);
        CloneKeyPairPublicResponse response = responseDocument.getCloneKeyPairPublicResponse();
        return identity(response.getKeyPair());
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phalanx.api.services.PhalanxService#cloneKeyPairPublic(org.brekka.phalanx.api.model.KeyPair)
     */
    @Override
    public KeyPair cloneKeyPairPublic(KeyPair keyPair) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public KeyPair assignKeyPair(PrivateKeyToken privateKeyToken, Principal assignToPrincipal) {
        AssignKeyPairRequestDocument requestDocument = AssignKeyPairRequestDocument.Factory.newInstance();
        AssignKeyPairRequest request = requestDocument.addNewAssignKeyPairRequest();
        PrivateKeyTokenImpl privateKey = narrow(privateKeyToken);
        request.setSessionID(privateKey.getAuthenticatedPrincipal().getSessionId());
        request.setPrivateKey(privateKey.getId());
        request.setAssignTo(xml(assignToPrincipal));
        
        AssignKeyPairResponseDocument responseDocument = marshal(requestDocument, AssignKeyPairResponseDocument.class);
        AssignKeyPairResponse response = responseDocument.getAssignKeyPairResponse();
        return identity(response.getKeyPair());
    }

    @Override
    public void deleteCryptedData(CryptedData cryptedDataItem) {
        DeleteCryptedDataRequestDocument requestDocument = DeleteCryptedDataRequestDocument.Factory.newInstance();
        DeleteCryptedDataRequest request = requestDocument.addNewDeleteCryptedDataRequest();
        request.setCryptedData(xml(cryptedDataItem));
        
        marshal(requestDocument, DeleteCryptedDataResponseDocument.class);
    }

    @Override
    public void deleteKeyPair(KeyPair keyPair) {
        DeleteKeyPairRequestDocument requestDocument = DeleteKeyPairRequestDocument.Factory.newInstance();
        DeleteKeyPairRequest request = requestDocument.addNewDeleteKeyPairRequest();
        request.setKeyPair(xml(keyPair));
        
        marshal(requestDocument, DeleteKeyPairResponseDocument.class);
    }

    @Override
    public Principal createPrincipal(String password) {
        CreatePrincipalRequestDocument requestDocument = CreatePrincipalRequestDocument.Factory.newInstance();
        CreatePrincipalRequest request = requestDocument.addNewCreatePrincipalRequest();
        request.setPassword(password);
        
        CreatePrincipalResponseDocument responseDocument = marshal(requestDocument, CreatePrincipalResponseDocument.class);
        CreatePrincipalResponse response = responseDocument.getCreatePrincipalResponse();
        PrincipalType principal = response.getPrincipal();
        IdentityKeyPair keyPair = identity(principal.getDefaultKeyPair());
        return new PrincipalImpl(uuid(principal.xgetId()), keyPair);
    }

    @Override
    public void deletePrincipal(Principal principal) {
        DeletePrincipalRequestDocument requestDocument = DeletePrincipalRequestDocument.Factory.newInstance();
        DeletePrincipalRequest request = requestDocument.addNewDeletePrincipalRequest();
        request.setPrincipal(xml(principal));
        
        marshal(requestDocument, DeletePrincipalResponseDocument.class);
    }

    @Override
    public AuthenticatedPrincipal authenticate(Principal principal, String password) {
        AuthenticateRequestDocument requestDocument = AuthenticateRequestDocument.Factory.newInstance();
        AuthenticateRequest request = requestDocument.addNewAuthenticateRequest();
        request.addNewPrincipal().setId(principal.getId().toString());
        request.setPassword(password);
        
        AuthenticateResponseDocument responseDocument = marshal(requestDocument, AuthenticateResponseDocument.class);
        AuthenticateResponse response = responseDocument.getAuthenticateResponse();
        AuthenticatedPrincipalType authenticatedPrincipal = response.getAuthenticatedPrincipal();
        IdentityKeyPair keyPair = identity(authenticatedPrincipal.getDefaultKeyPair());
        PrincipalImpl principalImpl = new PrincipalImpl(uuid(authenticatedPrincipal.xgetId()), keyPair);
        AuthenticatedPrincipalImpl authenticatedPrincipalImpl = new AuthenticatedPrincipalImpl(
                principalImpl, authenticatedPrincipal.getSessionID(), authenticatedPrincipal.getDefaultPrivateKey());
        return authenticatedPrincipalImpl;
    }
    
    @Override
    public void logout(AuthenticatedPrincipal authenticatedPrincipal) {
        LogoutRequestDocument requestDocument = LogoutRequestDocument.Factory.newInstance();
        LogoutRequest request = requestDocument.addNewLogoutRequest();
        AuthenticatedPrincipalImpl principal = narrow(authenticatedPrincipal);
        request.setSessionID(principal.getSessionId());
        marshal(requestDocument, LogoutResponseDocument.class);
    }



    @Override
    public void changePassword(Principal principal, String currentPassword, String newPassword) {
        ChangePasswordRequestDocument requestDocument = ChangePasswordRequestDocument.Factory.newInstance();
        ChangePasswordRequest request = requestDocument.addNewChangePasswordRequest();
        request.setPrincipal(xml(principal));
        request.setCurrentPassword(currentPassword);
        request.setNewPassword(newPassword);
        marshal(requestDocument, ChangePasswordResponseDocument.class);
    }



    @SuppressWarnings("unchecked")
    protected <ReqDoc extends XmlObject, RespDoc extends XmlObject> RespDoc marshal(ReqDoc requestDocument, Class<RespDoc> expected) {
        Object marshalSendAndReceive;
        try {
            marshalSendAndReceive = phalanxWebServiceOperations.marshalSendAndReceive(requestDocument);
        } catch (SoapFaultClientException e) {
            identifyFault(e);
            throw new PhalanxException(PhalanxErrorCode.CP500, e, 
                    "Request '%s' failed", requestDocument.schemaType().toString());
        }
        if (!expected.isAssignableFrom(marshalSendAndReceive.getClass())) {
            throw new PhalanxException(PhalanxErrorCode.CP500, 
                    "Expected '%s', actual '%s'", expected.getClass().getName(), 
                    marshalSendAndReceive.getClass().getName());
        }
        return (RespDoc) marshalSendAndReceive;
    }
    
    /**
     * @param e
     */
    private void identifyFault(SoapFaultClientException e) {
        Result result = e.getSoapFault().getFaultDetail().getResult();
        OperationFault fault = null;
        if (result instanceof DOMResult) {
            DOMResult domResult = (DOMResult) result;
            Node node = domResult.getNode().getFirstChild();
            XmlCursor cursor = null;
            try {
                XmlObject object = XmlObject.Factory.parse(node);
                cursor = object.newCursor();
                while(cursor.hasNextToken()) {
                    XmlObject xml = cursor.getObject();
                    if (xml instanceof OperationFault) {
                        fault = (OperationFault) xml;
                        break;
                    }
                    cursor.toNextToken();
                }
            } catch (XmlException xmlex) {
                // Never mind
            } finally {
                if (cursor != null) {
                    cursor.dispose();
                }
            }
        }
        if (fault != null) {
            PhalanxErrorCode errorCode = PhalanxErrorCode.valueOf(fault.getCode());
            throw new PhalanxException(errorCode, fault.getMessage());
        }
    }

    protected PrivateKeyTokenImpl narrow(PrivateKeyToken privateKeyToken) {
        if (privateKeyToken instanceof PrivateKeyTokenImpl == false) {
            
            // TODO
            throw new IllegalStateException();
        }
        return (PrivateKeyTokenImpl) privateKeyToken;
    }
    protected AuthenticatedPrincipalImpl narrow(AuthenticatedPrincipal authenticatedPrincipal) {
        if (authenticatedPrincipal instanceof AuthenticatedPrincipalImpl == false) {
            // TODO
            throw new IllegalStateException();
        }
        return (AuthenticatedPrincipalImpl) authenticatedPrincipal;
    }
    
    private static IdentityCryptedData identity(CryptedDataType cryptedData) {
        return new IdentityCryptedData(UUID.fromString(cryptedData.getId()));
    }
    
    private static IdentityKeyPair identity(KeyPairType keyPair) {
        return new IdentityKeyPair(UUID.fromString(keyPair.getId()));
    }
    
    private static KeyPairType xml(KeyPair keyPair) {
        KeyPairType keyPairType = KeyPairType.Factory.newInstance();
        keyPairType.setId(keyPair.getId().toString());
        return keyPairType;
    }
    
    private static PrincipalType xml(Principal principal) {
        PrincipalType principalType = PrincipalType.Factory.newInstance();
        principalType.setId(principal.getId().toString());
        return principalType;
    }

    private static CryptedDataType xml(CryptedData asymedCryptoData) {
        CryptedDataType cryptedDataType = CryptedDataType.Factory.newInstance();
        cryptedDataType.setId(asymedCryptoData.getId().toString());
        return cryptedDataType;
    }
    
    private static UUID uuid(UUIDType uuid) {
        return UUID.fromString(uuid.getStringValue());
    }
}
