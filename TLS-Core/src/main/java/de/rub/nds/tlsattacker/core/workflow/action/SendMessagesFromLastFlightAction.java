/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.TlsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendMessagesFromLastFlightAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private int depth;

    public SendMessagesFromLastFlightAction() {
        super();
    }

    public SendMessagesFromLastFlightAction(String connectionAlias) {
        super(connectionAlias);
    }

    public SendMessagesFromLastFlightAction(int depth) {
        super();
        this.depth = depth;
    }

    public SendMessagesFromLastFlightAction(String connectionAlias, int depth) {
        super(connectionAlias);
        this.depth = depth;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getContext(connectionAlias).getTlsContext();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        List<SendingAction> sendActions = state.getWorkflowTrace().getSendingActions();
        int ownIndex = sendActions.indexOf(this);
        for (int i = depth; i > 0; i--) {
            messages = new ArrayList<>(sendActions.get(ownIndex - i).getSendMessages());
        }
        for (TlsMessage message : messages) {
            message.setAdjustContext(false);
            if (message instanceof HandshakeMessage) {
                ((HandshakeMessage) message).setIncludeInDigest(false);
            }
        }
        String sending = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Executing retransmissions: " + sending);
        } else {
            LOGGER.info("Executing retransmissions (" + connectionAlias + "): " + sending);
        }

        try {
            send(tlsContext, messages, records);
            setExecuted(true);
        } catch (IOException e) {
            tlsContext.setReceivedTransportHandlerException(true);
            LOGGER.debug(e);
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
        }
    }

    @Override
    public void reset() {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        if (messages != null) {
            for (TlsMessage message : messages) {
                holders.addAll(message.getAllModifiableVariableHolders());
            }
        }
        if (getRecords() != null) {
            for (Record record : getRecords()) {
                holders.addAll(record.getAllModifiableVariableHolders());
            }
        }
        if (getFragments() != null) {
            for (DtlsHandshakeMessageFragment fragment : getFragments()) {
                holders.addAll(fragment.getAllModifiableVariableHolders());
            }
        }
        for (ModifiableVariableHolder holder : holders) {
            holder.reset();
        }
        setExecuted(null);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SendAction other = (SendAction) obj;
        if (!Objects.equals(this.messages, other.messages)) {
            return false;
        }
        if (!Objects.equals(this.records, other.records)) {
            return false;
        }
        if (!Objects.equals(this.fragments, other.fragments)) {
            return false;
        }
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 67 * hash + Objects.hashCode(this.messages);
        hash = 67 * hash + Objects.hashCode(this.records);
        hash = 67 * hash + Objects.hashCode(this.fragments);
        return hash;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public List<TlsMessage> getSendMessages() {
        return messages;
    }

    @Override
    public List<Record> getSendRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        return fragments;
    }

    @Override
    public MessageAction.MessageActionDirection getMessageDirection() {
        return MessageAction.MessageActionDirection.SENDING;
    }

}
