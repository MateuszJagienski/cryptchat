package org.example.view;

import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import org.springframework.stereotype.Component;
@Route("")
public class MainView extends VerticalLayout {

    public MainView() {
        var users = new VerticalLayout();
        // get users who are on this view

        var chatRoom = new Button("Chat Room");
        chatRoom.addClickListener(event -> {
            chatRoom.getUI().ifPresent(ui -> {
                ui.navigate(ChatRoomView.class, "123");
            });
        });


        add(chatRoom);
    }
}
