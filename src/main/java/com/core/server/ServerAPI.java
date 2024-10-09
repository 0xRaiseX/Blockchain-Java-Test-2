package com.core.server;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.CharsetUtil;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import com.core.Blockchain;
import com.core.classes.ContainerECDSA;
import com.core.classes.ContainerKeys;
import com.core.classes.ECDSAKeyGenerator;
import com.core.mainStructs.Transaction;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class ServerAPI extends SimpleChannelInboundHandler<FullHttpRequest> {
    private Blockchain blockchain;
    private final Map<String, RequestHandler> routeHandlers = new HashMap<>();
    private BlockingQueue<Transaction> transactionsQueue;
    private BlockingQueue<Transaction> transactionsQueueOK;
    // private ContainerKeys containerKeys = new ContainerKeys();
    private ContainerECDSA ecdsa = new ContainerECDSA();

    public ServerAPI(Blockchain blockchain, BlockingQueue<Transaction> transactionsQueue, BlockingQueue<Transaction> transactionsQueueOK) {
        this.blockchain = blockchain;
        this.transactionsQueue = transactionsQueue;
        this.transactionsQueueOK = transactionsQueueOK;

        routeHandlers.put("/api/transactions/get", this::getTransactionsByLastBlock);
        routeHandlers.put("/api/transactions/add", this::addTransaction);

        routeHandlers.put("/api/block/get", this::handleEndpoint3);

        routeHandlers.put("/api/data/print/base", this::handleEndpoint4);
        routeHandlers.put("/api/data/print/keys", this::handleEndpoint5);

        routeHandlers.put("/api/node/connect", this::connectNode);

        routeHandlers.put("/api/account/getkeys", this::keysGen);

        routeHandlers.put("/api/wallet/balance/get", this::print);

        routeHandlers.put("/api", this::keysGen);
        TransactionProcessor();
    }

    private String buildMessage(int statusCode, String text) {
        JsonObject jsonObject = new JsonObject();

        jsonObject.addProperty("code", statusCode);
        jsonObject.addProperty("message", text);
        jsonObject.addProperty("timestamp", blockchain.getTimestamp());
        String message = jsonObject.toString();
        return message;
    }

    private void TransactionProcessor() {
        Thread transactionProcessor = new Thread(() -> {
            while (true) {
                try {
                    Transaction transaction = transactionsQueueOK.take();
                    sendHttpResponse(transaction.getCtx(), transaction.getRequest(), transaction.getMessageState());
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                    e.printStackTrace();
                }
            }
        });

        transactionProcessor.start();
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        RequestHandler handler = routeHandlers.get(uri);

        if (handler != null) {
            handler.handle(request, ctx);
        } else {
            sendNotFoundResponse(ctx);
        }
    }

    private void getTransactionsByLastBlock(FullHttpRequest request, ChannelHandlerContext ctx) {
        String messageTransactions = blockchain.getTransactions();
        JsonArray arrayTransactions = JsonParser.parseString(messageTransactions).getAsJsonArray();
        JsonObject jsonObject = new JsonObject();

        jsonObject.addProperty("code", "0");
        jsonObject.add("message", arrayTransactions);
        jsonObject.addProperty("timestamp", blockchain.getTimestamp());
        String message = jsonObject.toString();

        sendHttpResponse(ctx, request, message);
    }

    private void print(FullHttpRequest request, ChannelHandlerContext ctx) {
        String message = "Test OK";

        sendHttpResponse(ctx, request, message);
    }


    private void addTransaction(FullHttpRequest request, ChannelHandlerContext ctx) {
        ByteBuf context = request.content();
        String text = context.toString(CharsetUtil.UTF_8);
        HttpHeaders headers = request.headers();

        // JsonObject json = JsonParser.parseString(text).getAsJsonObject();
        String signature = headers.get("SIGNATURE");
        // String timestamp = headers.get("TIMESTAMP");

        if (signature == null) {
            sendHttpResponse(ctx, request, buildMessage(1, "Signature must be empty"));
        }

        try {
            Gson gson = new Gson();
            Transaction object = gson.fromJson(text, Transaction.class);
            object.setCtx(ctx);
            object.setRequest(request);
            object.setSignature(signature);
            object.typeTransaction = 1;

            transactionsQueue.add(object);

        } catch (NullPointerException e) {
            System.out.println(e);
            sendHttpResponse(ctx, request, buildMessage(1, "Data error"));
        }
    }

    private void handleEndpoint3(FullHttpRequest request, ChannelHandlerContext ctx) {
        ByteBuf context = request.content();
        String text = context.toString(CharsetUtil.UTF_8);

        System.out.println(text);

        JsonObject json = JsonParser.parseString(text).getAsJsonObject();

        int index = json.get("index").getAsInt();
        blockchain.getBlock(index);

        sendHttpResponse(ctx, request, buildMessage(0, "OK"));
    }

    private void handleEndpoint4(FullHttpRequest request, ChannelHandlerContext ctx) {
        blockchain.printLastBlock();
        sendHttpResponse(ctx, request, buildMessage(0, "OK"));
    }

    private void handleEndpoint5(FullHttpRequest request, ChannelHandlerContext ctx) {
        blockchain.loadKeys();
        sendHttpResponse(ctx, request, buildMessage(0, "OK"));
    }

    private void sendHttpResponse(ChannelHandlerContext ctx, FullHttpRequest request, String content) {
        ByteBuf buffer = ctx.alloc().buffer();
        buffer.writeBytes(content.getBytes(CharsetUtil.UTF_8));

        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.OK, buffer);
        ctx.writeAndFlush(response);
        ctx.close();
    }

    private void connectNode(FullHttpRequest request, ChannelHandlerContext ctx) {
        ServerConnect.searchNodes();
        ServerConnect.connectNodes();

        sendHttpResponse(ctx, request, buildMessage(0, "OK"));
    }

    private void keysGen(FullHttpRequest request, ChannelHandlerContext ctx) {
        JsonObject jsonObject = new JsonObject();
        
        jsonObject.addProperty("code", "0");
        jsonObject.add("data", ecdsa.generateKeys());
        jsonObject.addProperty("timestamp", blockchain.getTimestamp());
        String message = jsonObject.toString();

        sendHttpResponse(ctx, request, message);
    }


    private void sendNotFoundResponse(ChannelHandlerContext ctx) {
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND);
        ctx.writeAndFlush(response);
        ctx.close();
    }


    @FunctionalInterface
    private interface RequestHandler {
        void handle(FullHttpRequest request, ChannelHandlerContext ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}
