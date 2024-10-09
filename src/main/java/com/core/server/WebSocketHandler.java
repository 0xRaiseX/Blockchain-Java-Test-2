package com.core.server;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import com.core.mainStructs.Transaction;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;

public class WebSocketHandler extends SimpleChannelInboundHandler<WebSocketFrame> {
    private static Map<Channel, Set<String>> subscribedChannels = new HashMap<>();
    private BlockingQueue<Transaction> transactionsQueue;
    
    public WebSocketHandler(BlockingQueue<Transaction> transactionsQueue) {
        this.transactionsQueue = transactionsQueue;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        super.channelActive(ctx);
        subscribedChannels.put(ctx.channel(), new HashSet<>());
        
        ctx.channel().writeAndFlush(new TextWebSocketFrame("{\"connect\":\"OK\"}"));
    }

    private void subscribeToChannel(Channel channel, String channelName) {
        System.out.println("Подписываю на канал" + channel + channelName);

        Set<String> userChannels = subscribedChannels.get(channel);
        if (userChannels != null) {
            userChannels.add(channelName);
        }
    }

    // private void sendMessageTransaction(String message) {
    //     for (Map.Entry<Channel, Set<String>> entry : subscribedChannels.entrySet()) {
    //         Channel subscriber = entry.getKey();
    //         Set<String> userChannels = entry.getValue();

    //         if (userChannels.contains("transactions")) {
    //             subscriber.writeAndFlush(new TextWebSocketFrame(message));
    //         }
    //     }
    // }

    private void sendMessageToChannel(String channelName, String message) {
        for (Map.Entry<Channel, Set<String>> entry : subscribedChannels.entrySet()) {
            Channel subscriber = entry.getKey();
            Set<String> userChannels = entry.getValue();

            if (userChannels.contains(channelName)) {
                subscriber.writeAndFlush(new TextWebSocketFrame("[" + channelName + "] " + message));
            }
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, WebSocketFrame msg) throws Exception {
        if (msg instanceof TextWebSocketFrame) {
            TextWebSocketFrame textFrame = (TextWebSocketFrame) msg;
            String request = textFrame.text();

            JsonObject json = JsonParser.parseString(request).getAsJsonObject();
            System.out.println(json);

            if (json.has("sender")) {
                Gson gson = new Gson();
                Transaction object = gson.fromJson(json.get("transaction"), Transaction.class);
        
                transactionsQueue.add(object);
            }
            // if (request.startsWith("/subscribe ")) {
            //     String channelName = request.substring("/subscribe ".length()).trim();
            //     subscribeToChannel(ctx.channel(), channelName);
            //     ctx.writeAndFlush(new TextWebSocketFrame("{\"status\":\"OK\"}"));

            // } else if (request.startsWith("/send ")) {
            //     String[] parts = request.split(" ", 3);
            //     if (parts.length == 3) {
            //         String channelName = parts[1];
            //         String message = parts[2];
            //         sendMessageToChannel(channelName, message);
            //         ctx.writeAndFlush(new TextWebSocketFrame("{\"status\":\"OK\"}"));
            //     }
            // } else {
            //     ctx.writeAndFlush(new TextWebSocketFrame("Error. Обработчик не найден"));
            // }
        } else {
            
        }
    }
}
