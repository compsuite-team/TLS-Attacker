/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.exceptions;

public class StarttlsCommandTypeNotImplementedException extends RuntimeException {
    public StarttlsCommandTypeNotImplementedException() {

    }

    public StarttlsCommandTypeNotImplementedException(String message) {
        super(message);
    }

    public StarttlsCommandTypeNotImplementedException(String message, Throwable cause) {
        super(message, cause);
    }

    public StarttlsCommandTypeNotImplementedException(Throwable cause) {
        super(cause);
    }

    public StarttlsCommandTypeNotImplementedException(String message, Throwable cause, boolean enableSuppression,
        boolean writeableStackTrace) {
        super(message, cause, enableSuppression, writeableStackTrace);
    }

}
