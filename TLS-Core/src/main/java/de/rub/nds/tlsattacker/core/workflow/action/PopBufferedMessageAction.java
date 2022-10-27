/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class PopBufferedMessageAction extends ConnectionBoundAction {

    public PopBufferedMessageAction() {
        super();
    }

    public PopBufferedMessageAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext ctx = state.getContext(getConnectionAlias()).getTlsContext();
        ctx.getMessageBuffer().pop();
        setExecuted(Boolean.TRUE);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

}
