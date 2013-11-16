/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.brekka.phalanx.webservices;

import static java.lang.String.format;

import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.Locale;

import javax.xml.namespace.QName;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xmlbeans.SchemaType;
import org.apache.xmlbeans.XmlBeans;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;
import org.brekka.commons.lang.BaseCheckedException;
import org.brekka.commons.lang.BaseException;
import org.brekka.commons.lang.ErrorCode;
import org.brekka.commons.lang.ErrorCoded;
import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.xml.phalanx.v2.wsops.OperationFault;
import org.springframework.oxm.ValidationFailureException;
import org.springframework.util.Assert;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.endpoint.AbstractEndpointExceptionResolver;
import org.springframework.ws.soap.SoapBody;
import org.springframework.ws.soap.SoapFault;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.SoapMessage;
import org.w3c.dom.Node;

/**
 * @author Andrew Taylor
 */
public class SoapExceptionResolver extends AbstractEndpointExceptionResolver {

    private static final Log log = LogFactory.getLog(SoapExceptionResolver.class);

    private static final XmlOptions SAVE_OPTIONS = new XmlOptions().setSaveAggressiveNamespaces();

    private final TransformerFactory transformerFactory = TransformerFactory.newInstance();

    @Override
    protected final boolean resolveExceptionInternal(final MessageContext messageContext, final Object endpoint, final Exception ex) {
        Assert.isInstanceOf(SoapMessage.class, messageContext.getResponse(),
                "SimpleSoapExceptionResolver requires a SoapMessage");

        SoapMessage response = (SoapMessage) messageContext.getResponse();
        SoapBody soapBody = response.getSoapBody();

        String message = determineMessage(ex);
        SoapFault soapFault;
        if (isServerFault(ex)) {
            soapFault = soapBody.addServerOrReceiverFault(message, Locale.ENGLISH);
        } else {
            soapFault = soapBody.addClientOrSenderFault(message, Locale.ENGLISH);
        }

        resolveDetail(messageContext, ex, soapFault);
        log.error(String.format("Error while invoking SOAP operation"), ex);
        return true;
    }

    private void resolveDetail(final MessageContext messageContext, final Throwable ex, final SoapFault soapFault) {
        SoapMessage request = (SoapMessage) messageContext.getRequest();
        DOMSource payloadSource = (DOMSource) request.getPayloadSource();
        Node node = payloadSource.getNode();
        String localName = node.getLocalName();
        String namespace = node.getNamespaceURI();
        String faultName = StringUtils.removeEnd(localName, "Request") + "Fault";
        QName faultQName = new QName(namespace, faultName);

        SchemaType schemaType = XmlBeans.getContextTypeLoader().findDocumentType(faultQName);
        if (schemaType != null) {
            try {
                XmlObject faultDocument = prepareFaultDetail(messageContext, faultName, schemaType, ex);
                if (faultDocument != null) {
                    // Add detailed
                    StringWriter writer = new StringWriter();
                    faultDocument.save(writer, SAVE_OPTIONS);
                    Transformer transformer = transformerFactory.newTransformer();

                    SoapFaultDetail faultDetail = soapFault.addFaultDetail();
                    Result result = faultDetail.getResult();
                    transformer.transform(new StreamSource(new StringReader(writer.toString())), result);
                }
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    log.warn(format(
                            "Failed to create custom fault message of type '%s'",
                            schemaType), e);
                }
            }
        }
    }

    protected String determineMessage(final Exception ex) {
        String localizedMessage = ex.getLocalizedMessage();
        String faultString = StringUtils.isNotBlank(localizedMessage) ? localizedMessage : ex.toString();
        return faultString;
    }

    protected boolean isServerFault(final Throwable ex) {
        // For now assume all errors are server faults
        return true;
    }

    protected XmlObject prepareFaultDetail(final MessageContext messageContext, final String faultName, final SchemaType schemaType, final Throwable ex)
            throws Exception {

        XmlObject faultDocument = XmlBeans.getContextTypeLoader().newInstance(schemaType, XmlOptions.maskNull(null));
        OperationFault faultType = prepareFaultType(faultName, faultDocument);

        ErrorCode code = PhalanxErrorCode.CP500;
        String message = "An unexpected error (" + ex.getClass().getSimpleName() + ")";
        if (ex instanceof ErrorCoded) {
            code = ((ErrorCoded) ex).getErrorCode();
            if (ex instanceof BaseException) {
                BaseException be = (BaseException) ex;
                message = format(be.getMessage(), (Object[]) be.getMessageArgs());
            } else if (ex instanceof BaseCheckedException) {
                BaseCheckedException bce = (BaseCheckedException) ex;
                message = format(bce.getMessage(), (Object[]) bce.getMessageArgs());
            } else {
                message = ex.getMessage();
            }
        } else if (ex instanceof ValidationFailureException) {
            code = PhalanxErrorCode.CP501;
            if (ex.getCause() != null) {
                message = ex.getCause().getMessage();
            }
        }
        faultType.setCode(code.toString());
        faultType.setMessage(message);

        return faultDocument;
    }


    private static OperationFault prepareFaultType(final String faultName, final XmlObject faultDocument) throws Exception {
        Method method = faultDocument.getClass().getMethod("addNew" + faultName);
        OperationFault faultType = (OperationFault) method.invoke(faultDocument);
        return faultType;
    }

}