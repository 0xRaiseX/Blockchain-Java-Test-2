package com.core.server;

import java.util.concurrent.BlockingQueue;
import com.core.Blockchain;
import com.core.Main;
import com.core.NetworkManager;
import com.core.mainStructs.Transaction;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.WebSocketFrameAggregator;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;


public class Server extends Thread {
    Blockchain blockchain;
    private BlockingQueue<Transaction> transactionsQueue;
    private BlockingQueue<Transaction> transactionsQueueOK;

    public Server (Blockchain blockchain, BlockingQueue<Transaction> transactionsQueue, BlockingQueue<Transaction> transactionsQueueOK) {
        this.blockchain = blockchain;
        this.transactionsQueue = transactionsQueue;
        this.transactionsQueueOK = transactionsQueueOK;
    }   

    public void run() { 
        while (true) {
            if (startServer(Main.PORT_TO_START)) {
                break;
            } else {
                Main.PORT_TO_START++;
            }
        }
    }
    
    public boolean startServer(int PORT_TO_START) {
        NioEventLoopGroup bossGroup = new NioEventLoopGroup();
        NioEventLoopGroup workerGroup = new NioEventLoopGroup();

        try {

            ServerBootstrap serverBootstrap = new ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ChannelPipeline pipeline = ch.pipeline();

                        pipeline.addLast(new HttpServerCodec());
                        pipeline.addLast(new HttpObjectAggregator(65536));
                        pipeline.addLast(new WebSocketFrameAggregator(65536));
                        pipeline.addLast(new WebSocketServerProtocolHandler("/ws"));

                        pipeline.addLast(new ServerAPI(blockchain, transactionsQueue, transactionsQueueOK));
                        pipeline.addLast(new WebSocketHandler(transactionsQueue));
                    }
                });

            ChannelFuture future = serverBootstrap.bind(PORT_TO_START).sync();
            NetworkManager.searchNodes();
            System.out.println("Server started on port: " + PORT_TO_START);
            future.channel().closeFuture().sync();
            return true;
        
        } catch (Exception e) {
            if (e.getMessage().contains("Address already in use: bind")) {
                // System.err.println("Port " + PORT_TO_START + " is already in use. Restarting...");
                return false;
            } else {
                e.printStackTrace();
                Thread.currentThread().interrupt();
            }
        
        } finally {

            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
        return false;
    }
}