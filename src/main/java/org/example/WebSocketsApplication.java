package org.example;

import com.vaadin.flow.component.dependency.NpmPackage;
import com.vaadin.flow.component.page.AppShellConfigurator;
import com.vaadin.flow.component.page.Push;
import com.vaadin.flow.theme.Theme;
import org.example.models.Message;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import reactor.core.publisher.Flux;
import reactor.core.publisher.UnicastProcessor;

@Push
@SpringBootApplication
public class WebSocketsApplication implements AppShellConfigurator {
    public static void main(String[] args) {
        SpringApplication.run(WebSocketsApplication.class, args);
    }

    @Bean
    Flux<Message> messages(UnicastProcessor<Message> messagePublisher) {
        return messagePublisher.replay(30).autoConnect();
    }

    @Bean
    UnicastProcessor<Message> messagePublisher() {
        return UnicastProcessor.create();
    }
}
