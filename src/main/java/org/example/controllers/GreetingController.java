package org.example.controllers;

import org.example.models.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

import java.sql.Timestamp;

@Controller
public class GreetingController {

    @MessageMapping("/hello")
    @SendTo("/topic/greetings")
    public Message greeting(Message message) throws InterruptedException {
        Thread.sleep(1000);
        
        return new Message("dasda", "dsasd", new Timestamp(System.currentTimeMillis()));
    }



}
