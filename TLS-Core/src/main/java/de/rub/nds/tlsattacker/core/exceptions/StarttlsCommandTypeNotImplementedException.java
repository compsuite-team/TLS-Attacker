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

