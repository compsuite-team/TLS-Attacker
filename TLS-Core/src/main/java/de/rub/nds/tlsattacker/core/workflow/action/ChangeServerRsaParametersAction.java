/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeServerRsaParametersAction extends ConnectionBoundAction {
    private static final Logger LOGGER = LogManager.getLogger();
    private final BigInteger modulus, publicExponent, privateExponent;
    private BigInteger oldModulus, oldPublicExponent, oldPrivateExponent;

    public ChangeServerRsaParametersAction(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        oldModulus = state.getTlsContext().getServerRSAModulus();
        oldPublicExponent = state.getTlsContext().getServerRSAPublicKey();
        oldPrivateExponent = state.getTlsContext().getServerRSAPrivateKey();
        state.getTlsContext().setServerRSAModulus(modulus);
        state.getTlsContext().setServerRSAPublicKey(publicExponent);
        state.getTlsContext().setServerRSAPrivateKey(privateExponent);
        setExecuted(true);
        LOGGER.info("Changed N,e,d");
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    public BigInteger getOldModulus() {
        return oldModulus;
    }

}
