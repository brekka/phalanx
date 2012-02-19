package org.brekka.phalanx;

import org.brekka.commons.lang.ErrorCode;

/**
 * Error types relating to the crypto subsystem.
 * 
 * @author Andrew Taylor
 */
public enum PhalanxErrorCode implements ErrorCode {

    CP100,
    CP101,
    CP102,
    CP103,
    CP104,
    CP105,
    CP106,
    
    
    CP200,
    CP201,
    CP202,
    CP203,
    CP204,
    CP205,
    CP206,
    CP207,
    CP208,
    CP209,
    CP210,
    CP211,
    CP212,
    CP213,
    
    CP300,
    CP301,
    
    CP400,
    
    CP600,
    
    CP700,
    ;
    
    private static final Area AREA = ErrorCode.Utils.createArea("CP");
    private int number = 0;

    @Override
    public int getNumber() {
        return (this.number == 0 ? this.number = ErrorCode.Utils.extractErrorNumber(name(), getArea()) : this.number);
    }
    @Override
    public Area getArea() { return AREA; }
}
