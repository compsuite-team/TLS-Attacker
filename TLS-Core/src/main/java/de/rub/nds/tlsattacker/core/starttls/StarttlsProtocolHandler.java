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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

import java.util.Dictionary;
import java.util.List;
import java.util.Map;

public interface StarttlsProtocolHandler {

    public void handleServerGreeting(TlsContext tlsContext, String str);

    public void handleCapabilities(TlsContext tlsContext, String str);

    public String createCommand(TlsContext tlsContext, StarttlsCommandType commandType);

    public Map<StarttlsCommandType, String> expectedCommandsDict();

    public Map<StarttlsCommandType, StarttlsCommandType> CommandsResponses();

    public WorkflowTrace extendWorkflowTrace(AliasedConnection connection, Config config, WorkflowTrace workflowTrace);

}
