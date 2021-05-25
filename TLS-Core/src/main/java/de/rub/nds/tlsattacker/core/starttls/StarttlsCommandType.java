/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.starttls;

public enum StarttlsCommandType {
    S_CONNECTED,
    C_CAPA,
    S_CAPA,
    C_STARTTLS,
    S_STARTTLS,
    C_NOOP,
    S_OK,
    C_QUIT,
    S_BYE,
    S_ERR
}
