package org.example;

import com.vaadin.flow.component.page.AppShellConfigurator;
import com.vaadin.flow.component.page.Push;
import org.example.models.Message;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import reactor.core.publisher.Flux;
import reactor.core.publisher.UnicastProcessor;

@Push
@SpringBootApplication
public class Application implements AppShellConfigurator {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
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
