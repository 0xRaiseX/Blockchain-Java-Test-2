package com.core.classes;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.interfaces.ECPrivateKey;

import com.core.classes.ContainerECDSA;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class HttpGetRequestExample {

    public static void main(String[] args) {
        try {
            // Замените URL на тот, который вам нужен
            String apiUrl = "http://127.0.0.1:8080/gen";

            // Создание объекта HttpClient
            HttpClient httpClient = HttpClients.createDefault();

            // Создание объекта HttpGet с указанием URL
            HttpGet httpGet = new HttpGet(apiUrl);

            // Выполнение GET-запроса
            HttpResponse response = httpClient.execute(httpGet);

            // Получение кода ответа
            int statusCode = response.getStatusLine().getStatusCode();
            System.out.println("Status Code: " + statusCode);

            // Чтение данных из InputStream
            BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String line;
            StringBuilder content = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();
            String jsonGET = content.toString();
            // Вывод ответа
            JsonObject json2 = JsonParser.parseString(jsonGET).getAsJsonObject();
            JsonObject json = json2.get("data").getAsJsonObject();
            System.out.println(json);
            System.out.println("Response: " + content.toString());

            post(json.get("public_key").getAsString(), json.get("secret_key").getAsString());


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

     public static void post(String publicKey, String secretKey) {
        try {
            JsonObject json = new JsonObject();
            json.addProperty("sender", publicKey);
            json.addProperty("recipient", secretKey);
            json.addProperty("amount", 234);
            String message = json.toString();

            ContainerECDSA secp = new ContainerECDSA();

            ECPrivateKey privateKeyEC = secp.privateKeyFromHex(secretKey);
            byte[] signMessage = secp.signMessage(privateKeyEC, message);
            String hexString = Hex.toHexString(signMessage);

            // Замените URL на тот, который вам нужен
            String apiUrl = "http://127.0.0.1:8080/transaction";

            // Создание объекта HttpClient
            HttpClient httpClient = HttpClients.createDefault();

            // Создание объекта HttpPost с указанием URL
            HttpPost httpPost = new HttpPost(apiUrl);

            // Установка заголовка Content-Type
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("SIGNATURE", hexString);

            // Установка данных запроса
            StringEntity entity = new StringEntity(message);
            httpPost.setEntity(entity);

            // Выполнение POST-запроса
            HttpResponse response = httpClient.execute(httpPost);

            // Получение кода ответа
            int statusCode = response.getStatusLine().getStatusCode();
            System.out.println("Status Code: " + statusCode);

            // Чтение данных из InputStream
            BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String line;
            StringBuilder content = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();

            // Вывод ответа
            System.out.println("Response: " + content.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
