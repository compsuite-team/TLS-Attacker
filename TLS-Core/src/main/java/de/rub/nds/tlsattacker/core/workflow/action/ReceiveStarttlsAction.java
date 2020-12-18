/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.List;

public class ReceiveStarttlsAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String expectedMessage;

    private final StarttlsType starttlsType;

    private StarttlsMessageFactory factory;

    protected ReceiveMessageHelper receiveMessageHelper;

    protected SendMessageHelper sendMessageHelper;

    protected List<AbstractRecord> receivedRecords;

    protected List<ProtocolMessage> receivedMessages;

    public ReceiveStarttlsAction(Config config, String expectedMessage, StarttlsType type, String encoding) {
        super(encoding);
        this.expectedMessage = expectedMessage;
        this.starttlsType = config.getStarttlsType();
        this.sendMessageHelper = new SendMessageHelper();
        this.receiveMessageHelper = new ReceiveMessageHelper();
        this.factory = new StarttlsMessageFactory(config);
    }

    /**
     * Communicate with Client until expected command was issued. Handled
     * Protocol messages: SMTP: EHLO, NOOP, QUIT, (STARTTLS) IMAP: CAPABILITY,
     * NOOP, LOGOUT, (STARTTLS) POP3: CAPA, QUIT, (STARTTLS)
     * 
     * @param state
     * @throws WorkflowExecutionException
     */
    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        try {
            LOGGER.debug("Receiving STARTTLS Messages...");
            boolean receivedExpectedMessage = false;
            while (!receivedExpectedMessage) {
                byte[] fetchData = tlsContext.getTransportHandler().fetchData();
                String receivedMessage = new String(fetchData, getEncoding());
                if (receivedMessage == null || receivedMessage.isEmpty())
                    break;
                if (receivedMessage.contains(expectedMessage))
                    receivedExpectedMessage = true;

                else {
                    String answer = "";
                    // Answer to specific protocol commands.
                    switch (starttlsType) {
                        case FTP:
                            break;
                        case IMAP: {
                            String IMAPTag = receivedMessage.split(" ")[0];
                            tlsContext.setRecentIMAPTag(IMAPTag);
                            if (receivedMessage.contains("NOOP"))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_OK, IMAPTag);
                            else if (receivedMessage.contains("CAPABILITY"))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_CAPA, IMAPTag);
                            else if (receivedMessage.contains("LOGOUT")) {
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_BYE, IMAPTag);
                                // TODO: Terminate connection.
                            }
                            break;
                        }
                        case POP3: {
                            if (receivedMessage.contains("CAPA"))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_CAPA);
                            if (receivedMessage.contains("QUIT"))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_BYE);
                            // TODO: Terminate connection.
                            break;
                        }
                        case SMTP: {
                            if (receivedMessage.contains("NOOP"))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_OK);
                            if (receivedMessage.contains("EHLO") && !"EHLO".equals(expectedMessage))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_CAPA);
                            if (receivedMessage.contains("QUIT"))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_BYE);
                            // TODO: Terminate connection.
                            break;
                        }
                    }
                    tlsContext.getTransportHandler().sendData(answer.getBytes(getEncoding()));
                }
            }

        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(false);
        }
    }

    @Override
    public void reset() {

    }

    @Override
    public boolean executedAsPlanned() {
        return false;
    }
}
