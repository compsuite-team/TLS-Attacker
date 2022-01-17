/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.TlsMessageType;
import de.rub.nds.tlsattacker.core.protocol.TlsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WorkflowTraceUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    public static TlsMessage getFirstReceivedMessage(TlsMessageType type, WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstReceivedMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static HandshakeMessage getLastReceivedMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static TlsMessage getLastReceivedMessage(TlsMessageType type, WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static TlsMessage getLastReceivedMessage(WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllReceivedMessages(trace);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static Record getLastReceivedRecord(WorkflowTrace trace) {
        List<Record> recordList = getAllReceivedRecords(trace);
        if (recordList.isEmpty()) {
            return null;
        } else {
            return recordList.get(recordList.size() - 1);
        }
    }

    public static TlsMessage getFirstSendMessage(TlsMessageType type, WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllSendMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllSendMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static ExtensionMessage getFirstSendExtension(ExtensionType type, WorkflowTrace trace) {
        List<ExtensionMessage> extensionList = getAllSendExtensions(trace);
        extensionList = filterExtensionList(extensionList, type);
        if (extensionList.isEmpty()) {
            return null;
        } else {
            return extensionList.get(0);
        }
    }

    public static TlsAction getFirstFailedAction(WorkflowTrace trace) {
        for (TlsAction action : trace.getTlsActions()) {
            if (!action.executedAsPlanned()) {
                return action;
            }
        }
        return null;
    }

    public static List<HandshakeMessage> getAllSendHandshakeMessages(WorkflowTrace trace) {
        return filterHandshakeMessagesFromList(getAllSendMessages(trace));
    }

    public static List<HandshakeMessage> getAllReceivedHandshakeMessages(WorkflowTrace trace) {
        return filterHandshakeMessagesFromList(getAllReceivedMessages(trace));
    }

    public static List<ExtensionMessage> getAllSendExtensions(WorkflowTrace trace) {
        List<HandshakeMessage> handshakeMessageList = getAllSendHandshakeMessages(trace);
        List<ExtensionMessage> extensionList = new LinkedList<>();
        for (HandshakeMessage message : handshakeMessageList) {
            extensionList.addAll(message.getExtensions());
        }
        return extensionList;
    }

    public static List<ExtensionMessage> getAllReceivedExtensions(WorkflowTrace trace) {
        List<HandshakeMessage> handshakeMessageList = getAllReceivedHandshakeMessages(trace);
        List<ExtensionMessage> extensionList = new LinkedList<>();
        for (HandshakeMessage message : handshakeMessageList) {
            extensionList.addAll(message.getExtensions());
        }
        return extensionList;
    }

    public static HandshakeMessage getLastSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllSendMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static TlsMessage getLastSendMessage(TlsMessageType type, WorkflowTrace trace) {
        List<TlsMessage> messageList = getAllSendMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static boolean didReceiveMessage(TlsMessageType type, WorkflowTrace trace) {
        return getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didReceiveMessage(HandshakeMessageType type, WorkflowTrace trace) {
        return getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didSendMessage(TlsMessageType type, WorkflowTrace trace) {
        return getFirstSendMessage(type, trace) != null;
    }

    public static boolean didSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        return getFirstSendMessage(type, trace) != null;
    }

    private static List<TlsMessage> filterMessageList(List<TlsMessage> messages, TlsMessageType type) {
        List<TlsMessage> returnedMessages = new LinkedList<>();
        for (TlsMessage tlsMessage : messages) {
            if (tlsMessage.getProtocolMessageType() == type) {
                returnedMessages.add(tlsMessage);
            }
        }
        return returnedMessages;
    }

    private static List<HandshakeMessage> filterMessageList(List<HandshakeMessage> messages,
        HandshakeMessageType type) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (HandshakeMessage handshakeMessage : messages) {
            if (handshakeMessage.getHandshakeMessageType() == type) {
                returnedMessages.add(handshakeMessage);
            }
        }
        return returnedMessages;
    }

    private static List<ExtensionMessage> filterExtensionList(List<ExtensionMessage> extensions, ExtensionType type) {
        List<ExtensionMessage> resultList = new LinkedList<>();
        for (ExtensionMessage extension : extensions) {
            if (extension.getExtensionTypeConstant() == type) {
                resultList.add(extension);
            }
        }
        return resultList;
    }

    public static List<HandshakeMessage> filterHandshakeMessagesFromList(List<TlsMessage> messages) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (TlsMessage tlsMessage : messages) {
            if (tlsMessage instanceof HandshakeMessage) {
                returnedMessages.add((HandshakeMessage) tlsMessage);
            }
        }
        return returnedMessages;
    }

    public static List<TlsMessage> getAllReceivedMessages(WorkflowTrace trace) {
        List<TlsMessage> receivedMessage = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedMessages() != null) {
                receivedMessage.addAll(action.getReceivedMessages());
            }
        }
        return receivedMessage;
    }

    public static List<TlsMessage> getAllReceivedMessages(WorkflowTrace trace, TlsMessageType type) {
        List<TlsMessage> receivedMessage = new LinkedList<>();
        for (TlsMessage message : getAllReceivedMessages(trace)) {
            if (message.getProtocolMessageType() == type) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    public static List<TlsMessage> getAllSendMessages(WorkflowTrace trace) {
        List<TlsMessage> sendMessages = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            sendMessages.addAll(action.getSendMessages());
        }
        return sendMessages;
    }

    public static Boolean didReceiveTypeBeforeType(TlsMessageType protocolMessageType, HandshakeMessageType type,
        WorkflowTrace trace) {
        List<TlsMessage> receivedMessages = getAllReceivedMessages(trace);
        for (TlsMessage message : receivedMessages) {
            if (message.getProtocolMessageType() == protocolMessageType) {
                return true;
            }
            if (message instanceof HandshakeMessage) {
                if (((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    return false;
                }
            }
        }
        return false;
    }

    public static List<Record> getAllReceivedRecords(WorkflowTrace trace) {
        List<Record> receivedRecords = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedRecords() != null) {
                receivedRecords.addAll(action.getReceivedRecords());
            }
        }
        return receivedRecords;
    }

    public static List<Record> getAllSendRecords(WorkflowTrace trace) {
        List<Record> sendRecords = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            if (action.getSendRecords() != null) {
                sendRecords.addAll(action.getSendRecords());
            }
        }
        return sendRecords;
    }

    public static SendingAction getLastSendingAction(WorkflowTrace trace) {
        List<SendingAction> sendingActions = trace.getSendingActions();
        return sendingActions.get(sendingActions.size() - 1);
    }

    public static List<SendingAction> getSendingActionsForMessage(@Nonnull TlsMessageType type,
        @Nonnull WorkflowTrace trace) {
        List<SendingAction> sendingActions = trace.getSendingActions();
        sendingActions.removeIf((SendingAction i) -> {
            List<TlsMessageType> types = i.getGoingToSendProtocolMessageTypes();
            return !types.contains(type);
        });
        return sendingActions;
    }

    public static List<SendingAction> getSendingActionsForMessage(@Nonnull HandshakeMessageType type,
        @Nonnull WorkflowTrace trace) {
        List<SendingAction> sendingActions = trace.getSendingActions();

        sendingActions.removeIf((SendingAction i) -> {
            List<HandshakeMessageType> handshakeTypes = i.getGoingToSendHandshakeMessageTypes();
            return !handshakeTypes.contains(type);
        });
        return sendingActions;
    }

    public static List<ReceivingAction> getReceivingActionsForMessage(@Nonnull TlsMessageType type,
        @Nonnull WorkflowTrace trace) {
        List<ReceivingAction> receivingActions = trace.getReceivingActions();

        receivingActions.removeIf((ReceivingAction i) -> {
            List<TlsMessageType> types = i.getGoingToReceiveProtocolMessageTypes();
            return !types.contains(type);
        });

        return receivingActions;
    }

    public static List<ReceivingAction> getReceivingActionsForMessage(@Nonnull HandshakeMessageType type,
        @Nonnull WorkflowTrace trace) {
        List<ReceivingAction> receivingActions = trace.getReceivingActions();

        receivingActions.removeIf((ReceivingAction i) -> {
            List<HandshakeMessageType> types = i.getGoingToReceiveHandshakeMessageTypes();
            return !types.contains(type);
        });

        return receivingActions;
    }

    public static TlsAction getFirstActionForMessage(@Nonnull HandshakeMessageType type, @Nonnull WorkflowTrace trace) {
        TlsAction receiving = getFirstReceivingActionForMessage(type, trace);
        TlsAction sending = getFirstSendingActionForMessage(type, trace);
        if (receiving == null && sending == null)
            return null;
        else if (receiving == null)
            return sending;
        else if (sending == null)
            return receiving;

        return trace.getTlsActions().indexOf(receiving) < trace.getTlsActions().indexOf(sending) ? receiving : sending;
    }

    public static TlsAction getFirstActionForMessage(@Nonnull TlsMessageType type, @Nonnull WorkflowTrace trace) {
        TlsAction receiving = getFirstReceivingActionForMessage(type, trace);
        TlsAction sending = getFirstSendingActionForMessage(type, trace);
        if (receiving == null && sending == null)
            return null;
        else if (receiving == null)
            return sending;
        else if (sending == null)
            return receiving;

        return trace.getTlsActions().indexOf(receiving) < trace.getTlsActions().indexOf(sending) ? receiving : sending;
    }

    public static TlsAction getFirstSendingActionForMessage(@Nonnull TlsMessageType type,
        @Nonnull WorkflowTrace trace) {
        if (!getSendingActionsForMessage(type, trace).isEmpty()) {
            return (TlsAction) getSendingActionsForMessage(type, trace).get(0);
        }
        return null;
    }

    public static TlsAction getFirstSendingActionForMessage(@Nonnull HandshakeMessageType type,
        @Nonnull WorkflowTrace trace) {
        if (!getSendingActionsForMessage(type, trace).isEmpty()) {
            return (TlsAction) getSendingActionsForMessage(type, trace).get(0);
        }
        return null;
    }

    public static TlsAction getFirstReceivingActionForMessage(@Nonnull TlsMessageType type,
        @Nonnull WorkflowTrace trace) {
        if (!getReceivingActionsForMessage(type, trace).isEmpty()) {
            return (TlsAction) getReceivingActionsForMessage(type, trace).get(0);
        }
        return null;
    }

    public static TlsAction getFirstReceivingActionForMessage(@Nonnull HandshakeMessageType type,
        @Nonnull WorkflowTrace trace) {
        if (!getReceivingActionsForMessage(type, trace).isEmpty()) {
            return (TlsAction) getReceivingActionsForMessage(type, trace).get(0);
        }
        return null;
    }

    public static TlsAction getLastActionForMessage(@Nonnull HandshakeMessageType type, @Nonnull WorkflowTrace trace) {
        TlsAction receiving = getLastReceivingActionForMessage(type, trace);
        TlsAction sending = getLastSendingActionForMessage(type, trace);
        if (receiving == null && sending == null)
            return null;
        else if (receiving == null)
            return sending;
        else if (sending == null)
            return receiving;

        return trace.getTlsActions().indexOf(receiving) > trace.getTlsActions().indexOf(sending) ? receiving : sending;
    }

    public static TlsAction getLastActionForMessage(@Nonnull TlsMessageType type, @Nonnull WorkflowTrace trace) {
        TlsAction receiving = getLastReceivingActionForMessage(type, trace);
        TlsAction sending = getLastSendingActionForMessage(type, trace);
        if (receiving == null && sending == null)
            return null;
        else if (receiving == null)
            return sending;
        else if (sending == null)
            return receiving;

        return trace.getTlsActions().indexOf(receiving) > trace.getTlsActions().indexOf(sending) ? receiving : sending;
    }

    public static TlsAction getLastSendingActionForMessage(@Nonnull TlsMessageType type, @Nonnull WorkflowTrace trace) {
        if (!getSendingActionsForMessage(type, trace).isEmpty()) {
            List<SendingAction> sndActions = getSendingActionsForMessage(type, trace);
            return (TlsAction) sndActions.get(sndActions.size() - 1);
        }
        return null;
    }

    public static TlsAction getLastSendingActionForMessage(@Nonnull HandshakeMessageType type,
        @Nonnull WorkflowTrace trace) {
        if (!getSendingActionsForMessage(type, trace).isEmpty()) {
            List<SendingAction> sndActions = getSendingActionsForMessage(type, trace);
            return (TlsAction) sndActions.get(sndActions.size() - 1);
        }
        return null;
    }

    public static TlsAction getLastReceivingActionForMessage(@Nonnull TlsMessageType type,
        @Nonnull WorkflowTrace trace) {
        if (!getReceivingActionsForMessage(type, trace).isEmpty()) {
            List<ReceivingAction> rcvActions = getReceivingActionsForMessage(type, trace);
            return (TlsAction) rcvActions.get(rcvActions.size() - 1);
        }
        return null;
    }

    public static TlsAction getLastReceivingActionForMessage(@Nonnull HandshakeMessageType type,
        @Nonnull WorkflowTrace trace) {
        if (!getReceivingActionsForMessage(type, trace).isEmpty()) {
            List<ReceivingAction> rcvActions = getReceivingActionsForMessage(type, trace);
            return (TlsAction) rcvActions.get(rcvActions.size() - 1);
        }
        return null;
    }

    private WorkflowTraceUtil() {
    }
}
