package org.brekka.phalanx.core;

import org.brekka.commons.lang.BaseException;


/**
 * @author Andrew Taylor
 */
public class PhalanxException extends BaseException {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -4138976811848253266L;

    /**
     * @param errorCode
     * @param message
     * @param messageArgs
     */
    public PhalanxException(PhalanxErrorCode errorCode, String message, Object... messageArgs) {
        super(errorCode, message, messageArgs);
    }

    /**
     * @param errorCode
     * @param cause
     * @param message
     * @param messageArgs
     */
    public PhalanxException(PhalanxErrorCode errorCode, Throwable cause, String message, Object... messageArgs) {
        super(errorCode, cause, message, messageArgs);
    }

}
