/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.TlsMessageType;
import de.rub.nds.tlsattacker.core.exceptions.BouncyCastleNotLoadedException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.TransportHandlerConnectException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerStackFactory;
import de.rub.nds.tlsattacker.core.layer.constant.LayerStackType;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.protocol.TlsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();
    static {
        if (!BouncyCastleProviderChecker.isLoaded()) {
            throw new BouncyCastleNotLoadedException("BouncyCastleProvider not loaded");
        }
    }

    private Function<State, Integer> beforeTransportPreInitCallback = (State state) -> {
        LOGGER.trace("BeforePreInitCallback");
        return 0;
    };

    private Function<State, Integer> beforeTransportInitCallback = (State state) -> {
        LOGGER.trace("BeforeInitCallback");
        return 0;
    };

    private Function<State, Integer> afterTransportInitCallback = (State state) -> {
        LOGGER.trace("AfterTransportInitCallback");
        return 0;
    };

    private Function<State, Integer> afterExecutionCallback = (State state) -> {
        LOGGER.trace("AfterExecutionCallback");
        return 0;
    };

    protected final WorkflowExecutorType type;

    protected final State state;
    protected final Config config;

    /**
     * Prepare a workflow trace for execution according to the given state and executor type. Try various ways to
     * initialize a workflow trace and add it to the state. For workflow creation, use the first method which does not
     * return null, in the following order: state.getWorkflowTrace(), state.config.getWorkflowInput(),
     * config.getWorkflowTraceType().
     *
     * @param type
     *              of the workflow executor (currently only DEFAULT)
     * @param state
     *              to work on
     */
    public WorkflowExecutor(WorkflowExecutorType type, State state) {
        this.type = type;
        this.state = state;
        this.config = state.getConfig();
    }

    public abstract void executeWorkflow() throws WorkflowExecutionException;

    /**
     * Initialize the context's transport handler.Start listening or connect to a server, depending on our connection
     * end type.
     *
     * @param context
     */
    public void initTransportHandler(TcpContext context) {

        if (context.getTransportHandler() == null) {
            if (context.getContext().getConnection() == null) {
                throw new ConfigurationException("Connection end not set");
            }
            context.setTransportHandler(
                TransportHandlerFactory.createTransportHandler(context.getContext().getConnection()));
            if (context.getTransportHandler() instanceof ClientTcpTransportHandler) {
                ((ClientTcpTransportHandler) context.getTransportHandler())
                    .setRetryFailedSocketInitialization(config.isRetryFailedClientTcpSocketInitialization());
            }
        }

        try {
            getBeforeTransportPreInitCallback().apply(state);
            context.getTransportHandler().preInitialize();
            getBeforeTransportInitCallback().apply(state);
            context.getTransportHandler().initialize();
            getAfterTransportInitCallback().apply(state);
        } catch (Exception ex) {
            throw new TransportHandlerConnectException(
                "Unable to initialize the transport handler with: " + context.getContext().getConnection().toString(),
                ex);
        }
    }

    public Function<State, Integer> getBeforeTransportPreInitCallback() {
        return beforeTransportPreInitCallback;
    }

    public void setBeforeTransportPreInitCallback(Function<State, Integer> beforeTransportPreInitCallback) {
        this.beforeTransportPreInitCallback = beforeTransportPreInitCallback;
    }

    public Function<State, Integer> getBeforeTransportInitCallback() {
        return beforeTransportInitCallback;
    }

    public void setBeforeTransportInitCallback(Function<State, Integer> beforeTransportInitCallback) {
        this.beforeTransportInitCallback = beforeTransportInitCallback;
    }

    public Function<State, Integer> getAfterTransportInitCallback() {
        return afterTransportInitCallback;
    }

    public void setAfterTransportInitCallback(Function<State, Integer> afterTransportInitCallback) {
        this.afterTransportInitCallback = afterTransportInitCallback;
    }

    public Function<State, Integer> getAfterExecutionCallback() {
        return afterExecutionCallback;
    }

    public void setAfterExecutionCallback(Function<State, Integer> afterExecutionCallback) {
        this.afterExecutionCallback = afterExecutionCallback;
    }

    public void closeConnection() {
        for (Context context : state.getAllTlsContexts()) {
            try {
                context.getTcpContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.warn("Could not close connection for context " + context);
                LOGGER.debug(ex);
            }
        }
    }

    public void initAllLayer() throws IOException {
        for (Context ctx : state.getAllTlsContexts()) {
            initTransportHandler(ctx.getTcpContext());
            initProtocolStack(ctx);
        }
    }

    public void sendCloseNotify() {
        AlertMessage alertMessage = new AlertMessage();
        alertMessage.setConfig(AlertLevel.FATAL, AlertDescription.CLOSE_NOTIFY);
        SendAction sendAction =
            new SendAction(state.getWorkflowTrace().getConnections().get(0).getAlias(), alertMessage);
        sendAction.getActionOptions().add(ActionOption.MAY_FAIL);
        sendAction.execute(state);
    }

    public void setFinalSocketState() {
        for (Context ctx : state.getAllTlsContexts()) {
            TransportHandler handler = ctx.getTcpContext().getTransportHandler();
            if (handler instanceof TcpTransportHandler) {
                SocketState socketSt =
                    ((TcpTransportHandler) handler).getSocketState(config.isReceiveFinalTcpSocketStateWithTimeout());
                ctx.getTlsContext().setFinalSocketState(socketSt);
            } else {
                ctx.getTlsContext().setFinalSocketState(SocketState.UNAVAILABLE);
            }
        }
    }

    /**
     * Check if a at least one TLS context received a fatal alert.
     */
    public boolean isReceivedFatalAlert() {
        for (Context ctx : state.getAllTlsContexts()) {
            if (ctx.getTlsContext().isReceivedFatalAlert()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a at least one TLS context received a warning alert.
     */
    public boolean isReceivedWarningAlert() {
        List<TlsMessage> allReceivedMessages =
            WorkflowTraceUtil.getAllReceivedMessages(state.getWorkflowTrace(), TlsMessageType.ALERT);
        for (TlsMessage message : allReceivedMessages) {
            AlertMessage alert = (AlertMessage) message;
            if (alert.getLevel().getValue() == AlertLevel.WARNING.getValue()) {
                return true;
            }
        }
        return false;
    }

    public boolean isIoException() {
        for (Context context : state.getAllTlsContexts()) {
            if (context.getTlsContext().isReceivedTransportHandlerException()) {
                return true;
            }
        }
        return false;
    }

    private void initProtocolStack(Context context) throws IOException {
        context.setLayerStack(LayerStackFactory.createLayerStack(LayerStackType.TLS, context));

    }
}
