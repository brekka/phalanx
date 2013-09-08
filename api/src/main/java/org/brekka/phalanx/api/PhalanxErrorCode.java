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

package org.brekka.phalanx.api;

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
    /**
     * Incorrect password
     */
    CP302,
    
    CP400,
    
    CP500,
    CP501,
    
    CP600,
    CP601,
    
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
