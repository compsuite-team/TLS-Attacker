/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.starttls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.starttls.StarttlsActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.core.jmx.Server;

import java.util.Dictionary;
import java.util.List;
import java.util.Map;

public abstract class StarttlsProtocolHandler {

    protected final String capabilityPrefix;

    public StarttlsProtocolHandler() {
        this("");
    }

    public StarttlsProtocolHandler(String prefix) {
        this.capabilityPrefix = prefix;
    }

    public abstract void handleServerGreeting(TlsContext tlsContext, String str);

    public abstract void handleCapabilities(TlsContext tlsContext, String str);

    public abstract String createCommand(TlsContext tlsContext, StarttlsCommandType commandType);

    public abstract Map<StarttlsCommandType, String> expectedCommandsDict();

    public abstract Map<StarttlsCommandType, StarttlsCommandType> CommandsResponses();

    public WorkflowTrace extendWorkflowTrace(AliasedConnection connection, Config config, WorkflowTrace workflowTrace) {
        workflowTrace.addTlsAction(
            StarttlsActionFactory.createServerGreetingAction(config, connection, ConnectionEndType.SERVER, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createStarttlsCommunicationAction(config, connection,
            ConnectionEndType.CLIENT, StarttlsCommandType.C_STARTTLS, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createIssueStarttlsCommandAction(config, connection,
            ConnectionEndType.SERVER, StarttlsCommandType.S_STARTTLS, "US-ASCII"));
        return workflowTrace;
    }

    public abstract String getNegotiationString();

    public abstract List<ServerCapability> getImplementedCapabilities();

    public boolean offersPlainLogin(String serverCapability) {
        ServerCapability capability = getCapabilityFromString(serverCapability);
        if (capability != null)
            return capability.isPlain();
        return false;
    }

    public String getCapabilityPrefix() {
        return this.capabilityPrefix;
    }

    public ServerCapability getCapabilityFromString(String str) {
        String comparison = str;
        for (ServerCapability capability : getImplementedCapabilities()) {
            comparison = comparison.substring(getCapabilityPrefix().length());
            if (capability.getName().equalsIgnoreCase(comparison))
                return capability;
        }
        return null;
    }
}
