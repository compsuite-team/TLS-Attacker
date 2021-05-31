/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
