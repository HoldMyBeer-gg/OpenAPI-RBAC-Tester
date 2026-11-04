package burp.openapirbactester;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Adds a "Send to OpenAPI-RBAC-Tester" entry to any Burp HTTP message context menu.
 * Extracts auth headers from the chosen request and, if the response looks like an
 * OpenAPI spec (or the URL looks spec-shaped), pre-populates the extension tab.
 */
public class RbacTesterContextMenuProvider implements ContextMenuItemsProvider {

    private final OpenAPIRbacTesterTab tab;

    public RbacTesterContextMenuProvider(OpenAPIRbacTesterTab tab) {
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        HttpRequestResponse target = resolveTarget(event);
        if (target == null || target.request() == null) {
            return Collections.emptyList();
        }
        JMenuItem item = new JMenuItem("Send to OpenAPI-RBAC-Tester");
        item.addActionListener(e -> tab.importFromRequest(target));
        return List.of(item);
    }

    private HttpRequestResponse resolveTarget(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) {
            return selected.get(0);
        }
        Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
        if (editor.isPresent()) {
            return editor.get().requestResponse();
        }
        return null;
    }
}
