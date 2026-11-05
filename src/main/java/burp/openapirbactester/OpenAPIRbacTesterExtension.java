package burp.openapirbactester;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * OpenAPI RBAC Tester extension entry point. Registers the main tab with Burp Suite and wires up
 * the unloading handler.
 * <p>
 * Load OpenAPI specs via URL, drag-and-drop, or file browse (including network drives).
 * Actively scan and send to Intruder with auto-highlighted payload positions.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class OpenAPIRbacTesterExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(ExtensionInfo.DISPLAY_NAME);

        OpenAPIRbacTesterTab tab = new OpenAPIRbacTesterTab(api);
        api.userInterface().applyThemeToComponent(tab);
        api.userInterface().registerSuiteTab(ExtensionInfo.DISPLAY_NAME, tab);
        api.userInterface().registerContextMenuItemsProvider(new RbacTesterContextMenuProvider(tab));

        api.extension().registerUnloadingHandler(tab::unload);

        api.logging().logToOutput(ExtensionInfo.DISPLAY_NAME + " loaded.");
    }
}
