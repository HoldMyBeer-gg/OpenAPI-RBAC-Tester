package burp.openapibifrost;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * OpenAPI-Bifrost extension entry point. Registers the main tab with Burp Suite and wires up
 * the unloading handler.
 * <p>
 * Load OpenAPI specs via URL, drag-and-drop, or file browse (including network drives).
 * Actively scan and send to Intruder with auto-highlighted payload positions.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class OpenAPIBifrostExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("OpenAPI-Bifrost: API Spec Endpoint Importer and Tester");

        OpenAPIBifrostTab tab = new OpenAPIBifrostTab(api);
        api.userInterface().applyThemeToComponent(tab);
        api.userInterface().registerSuiteTab("OpenAPI-Bifrost", tab);
        api.userInterface().registerContextMenuItemsProvider(new BifrostContextMenuProvider(tab));

        api.extension().registerUnloadingHandler(tab::unload);

        api.logging().logToOutput("OpenAPI-Bifrost loaded.");
    }
}
