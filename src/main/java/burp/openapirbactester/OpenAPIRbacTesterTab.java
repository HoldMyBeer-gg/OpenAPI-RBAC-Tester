package burp.openapirbactester;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.RawEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Main OpenAPI-RBAC-Tester tab panel. Provides the UI for loading OpenAPI specs, viewing parsed
 * endpoints, and sending requests to Scanner, Repeater, or Intruder.
 * <p>
 * Supports loading specs via drag-and-drop, URL, file path (including network drives),
 * or raw paste. Includes base URL override, regex filtering, and request preview.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class OpenAPIRbacTesterTab extends JPanel {

    private final MontoyaApi api;
    private final Logging logging;
    private final OpenAPIParser parser = new OpenAPIParser();
    private final RequestGenerator requestGenerator = new RequestGenerator();
    private final EndpointTableModel tableModel = new EndpointTableModel();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final IdentityStore identityStore;

    private static final int FILTER_DEBOUNCE_MS = 150;

    /** Background runs (RBAC comparisons) that must be stopped if the extension unloads mid-run. */
    private final Set<AbortableRun> activeRuns = ConcurrentHashMap.newKeySet();

    private JTextField urlOrPathField;
    private JCheckBox verifyTlsCheckBox;
    private RawEditor rawSpecEditor;
    private Timer filterDebounce;
    private JTextField baseUrlOverrideField;
    private JTextField bearerField;
    private JTextField apiKeyValueField;
    private JTextField apiKeyNameField;
    private JComboBox<AuthConfig.ApiKeyLocation> apiKeyLocationCombo;
    private JTextField basicUserField;
    private JPasswordField basicPassField;
    private JTextArea extraHeadersArea;
    private JComboBox<String> identityDropdown;
    private JTextField filterField;
    private JLabel filterHitsLabel;
    private JTable endpointTable;
    private HttpRequestEditor requestEditor;
    private JLabel statusLabel;
    private JLabel specAuthSummaryLabel;
    private String defaultServer = "";
    private boolean hasScanner = false;
    /** Suppresses capture-on-change when we're programmatically loading fields. */
    private boolean suppressCapture = false;

    public OpenAPIRbacTesterTab(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.hasScanner = detectScannerSupport(api);
        this.identityStore = new IdentityStore(new MontoyaPrefsBackend(api.persistence().preferences()));
        buildUi();
        loadActiveIdentityIntoFields();
    }

    /** Test-only constructor that takes an explicit IdentityStore (skips Montoya wiring). */
    OpenAPIRbacTesterTab(MontoyaApi api, IdentityStore identityStore) {
        this.api = api;
        this.logging = api.logging();
        this.hasScanner = detectScannerSupport(api);
        this.identityStore = identityStore;
        buildUi();
        loadActiveIdentityIntoFields();
    }

    private static boolean detectScannerSupport(MontoyaApi api) {
        try {
            BurpSuiteEdition edition = api.burpSuite().version().edition();
            return edition == BurpSuiteEdition.PROFESSIONAL || edition == BurpSuiteEdition.ENTERPRISE_EDITION;
        } catch (Exception e) {
            return false;
        }
    }

    private void buildUi() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new GridBagLayout());

        // Drop zone spans the full width.
        JPanel dropZone = new JPanel(new GridBagLayout());
        dropZone.setPreferredSize(new Dimension(0, 70));
        dropZone.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(UIManager.getColor("Component.borderColor"), 2),
                new EmptyBorder(8, 10, 8, 10)
        ));
        dropZone.setBackground(UIManager.getColor("Panel.background"));
        JLabel dropLabel = new JLabel("Drop OpenAPI spec here, paste URL/path below, or paste raw JSON/YAML");
        dropZone.add(dropLabel);
        setupDropTarget(dropZone);

        GridBagConstraints full = rowConstraints(0);
        full.gridwidth = GridBagConstraints.REMAINDER;
        full.fill = GridBagConstraints.HORIZONTAL;
        full.weightx = 1.0;
        full.insets = new Insets(0, 0, 8, 0);
        topPanel.add(dropZone, full);

        // Parse-from row: label + field + Browse + Load.
        urlOrPathField = new JTextField();
        JButton browseBtn = new JButton("Browse");
        browseBtn.addActionListener(e -> doBrowse());
        JButton loadBtn = new JButton("Load");
        loadBtn.addActionListener(e -> doLoad());
        verifyTlsCheckBox = new JCheckBox("Verify TLS", true);
        verifyTlsCheckBox.setToolTipText("Verify the spec host's certificate when fetching over https. "
                + "Untick for staging hosts with self-signed or internal-CA certificates.");
        addFormRow(topPanel, 1, "Parse from local file or URL:", urlOrPathField, browseBtn, loadBtn, verifyTlsCheckBox);

        // Base URL override row.
        baseUrlOverrideField = new JTextField();
        baseUrlOverrideField.setToolTipText("Override server URL from spec (e.g. https://api.target.com). Stored per identity.");
        baseUrlOverrideField.addFocusListener(new FocusAdapter() {
            @Override public void focusLost(FocusEvent e) {
                captureActiveIdentity();
                updateRequestPreview();
            }
        });
        addFormRow(topPanel, 2, "Base URL override (optional):", baseUrlOverrideField);

        // Auth panel — full width, already grid-aligned internally.
        GridBagConstraints authC = rowConstraints(3);
        authC.gridwidth = GridBagConstraints.REMAINDER;
        authC.fill = GridBagConstraints.HORIZONTAL;
        authC.weightx = 1.0;
        authC.insets = new Insets(6, 0, 6, 0);
        topPanel.add(buildAuthPanel(), authC);

        // Raw spec paste area: Burp's own raw editor, so it gets line numbers, Burp styling and
        // theme support. It scrolls itself, so it is not wrapped in another JScrollPane.
        rawSpecEditor = api.userInterface().createRawEditor();
        Component rawSpecComponent = rawSpecEditor.uiComponent();
        JPanel rawSpecPanel = new JPanel(new BorderLayout());
        rawSpecPanel.setBorder(new LineBorder(UIManager.getColor("Component.borderColor"), 1));
        rawSpecPanel.setPreferredSize(new Dimension(0, 140));
        rawSpecPanel.add(rawSpecComponent, BorderLayout.CENTER);
        JButton parseRawBtn = new JButton("Parse");
        parseRawBtn.addActionListener(e -> {
            String content = rawSpecText();
            if (content != null && !content.isBlank()) {
                setStatus("Parsing...");
                parseInBackground(content.trim(), "pasted");
            } else {
                setStatus("Paste OpenAPI spec content (JSON or YAML) above, then click Parse.");
            }
        });

        // "Or paste raw OpenAPI spec (JSON/YAML):" label row.
        GridBagConstraints pasteLabelC = rowConstraints(4);
        pasteLabelC.gridwidth = GridBagConstraints.REMAINDER;
        pasteLabelC.anchor = GridBagConstraints.WEST;
        pasteLabelC.fill = GridBagConstraints.HORIZONTAL;
        pasteLabelC.insets = new Insets(4, 0, 2, 0);
        topPanel.add(new JLabel("Or paste raw OpenAPI spec (JSON/YAML):"), pasteLabelC);

        // Textarea row — full width, fills vertically to take remaining space.
        GridBagConstraints textareaC = rowConstraints(5);
        textareaC.gridwidth = GridBagConstraints.REMAINDER;
        textareaC.fill = GridBagConstraints.BOTH;
        textareaC.weightx = 1.0;
        textareaC.weighty = 1.0;
        textareaC.insets = new Insets(0, 0, 4, 0);
        topPanel.add(rawSpecPanel, textareaC);

        // Parse button aligned under the textarea.
        GridBagConstraints btnC = rowConstraints(6);
        btnC.gridwidth = GridBagConstraints.REMAINDER;
        btnC.anchor = GridBagConstraints.WEST;
        btnC.fill = GridBagConstraints.NONE;
        btnC.insets = new Insets(0, 0, 0, 0);
        topPanel.add(parseRawBtn, btnC);

        JScrollPane topScroll = new JScrollPane(topPanel);
        topScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        topScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        topScroll.setBorder(BorderFactory.createEmptyBorder());
        topScroll.getViewport().setPreferredSize(new Dimension(0, 460));
        add(topScroll, BorderLayout.NORTH);

        // Filter row and table/editor
        JPanel centerPanel = new JPanel(new BorderLayout(0, 5));
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        filterRow.add(new JLabel("Filter (regex, case-sensitive):"));
        filterField = new JTextField(25);
        // Debounce: a large spec is re-filtered once per pause in typing, not once per keystroke.
        filterDebounce = new Timer(FILTER_DEBOUNCE_MS, e -> {
            tableModel.setFilter(filterField.getText());
            updateFilterHits();
        });
        filterDebounce.setRepeats(false);
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { filterDebounce.restart(); }
            @Override public void removeUpdate(DocumentEvent e) { filterDebounce.restart(); }
            @Override public void changedUpdate(DocumentEvent e) { filterDebounce.restart(); }
        });
        filterRow.add(filterField);
        filterHitsLabel = new JLabel("0 hits");
        filterRow.add(filterHitsLabel);

        // Actions on the current selection, visible without opening the context menu.
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        JButton repeaterBtn = new JButton("Send to Repeater");
        repeaterBtn.addActionListener(e -> doSendToRepeater());
        JButton intruderBtn = new JButton("Send to Intruder");
        intruderBtn.setToolTipText("Cmd/Ctrl+I");
        intruderBtn.addActionListener(e -> doSendToIntruder());
        JButton compareBtn = new JButton("Compare across identities…");
        compareBtn.setToolTipText("Run the selected endpoints under every identity and compare the responses.");
        compareBtn.addActionListener(e -> doCompareIdentities());
        actionRow.add(repeaterBtn);
        actionRow.add(intruderBtn);
        actionRow.add(compareBtn);

        JPanel toolbar = new JPanel(new BorderLayout());
        toolbar.add(filterRow, BorderLayout.WEST);
        toolbar.add(actionRow, BorderLayout.EAST);
        centerPanel.add(toolbar, BorderLayout.NORTH);

        // Table and request preview
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        endpointTable = new JTable(tableModel);
        endpointTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        endpointTable.setAutoCreateRowSorter(true);
        endpointTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateRequestPreview();
        });
        setupContextMenu();
        setupKeyBinding();
        JScrollPane tableScroll = new JScrollPane(endpointTable);
        split.setTopComponent(tableScroll);

        requestEditor = api.userInterface().createHttpRequestEditor();
        split.setBottomComponent(requestEditor.uiComponent());
        split.setResizeWeight(0.6);
        centerPanel.add(split, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);

        statusLabel = new JLabel(" ");
        add(statusLabel, BorderLayout.SOUTH);
    }

    private void setupDropTarget(JComponent dropZone) {
        if (GraphicsEnvironment.isHeadless()) return; // DropTarget needs a display; tests run headless.
        dropZone.setDropTarget(new DropTarget() {
            @Override
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    @SuppressWarnings("unchecked")
                    java.util.List<java.io.File> files = (java.util.List<java.io.File>)
                            evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (files != null && !files.isEmpty()) {
                        java.io.File f = files.get(0);
                        if (f.isFile()) {
                            urlOrPathField.setText(f.getAbsolutePath());
                            doLoad();
                        }
                    }
                    evt.dropComplete(true);
                } catch (Exception ex) {
                    logging.logToError("Drop failed: " + ex.getMessage());
                    evt.dropComplete(false);
                }
            }
        });
    }

    private void doBrowse() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setDialogTitle("Select OpenAPI spec (JSON, YAML, TXT)");
        java.awt.Frame parent = api.userInterface().swingUtils().suiteFrame();
        if (chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
            urlOrPathField.setText(chooser.getSelectedFile().getAbsolutePath());
            doLoad();
        }
    }

    private void doLoad() {
        String input = urlOrPathField.getText();
        String rawContent = rawSpecText();
        if ((input == null || input.isBlank()) && (rawContent == null || rawContent.isBlank())) {
            setStatus("Enter a URL or file path, paste raw spec below, or drag & drop a file.");
            return;
        }
        if (input == null || input.isBlank()) {
            setStatus("Parsing...");
            parseInBackground(rawContent.trim(), "pasted");
            return;
        }
        final String source = input.trim();
        setStatus("Loading...");

        if (looksLikeUrl(source)) {
            executor.submit(() -> {
                try {
                    loadFromUrl(source);
                } catch (Throwable t) {
                    logging.logToError("Load from URL failed: " + t.getMessage());
                    java.io.StringWriter sw = new java.io.StringWriter();
                    t.printStackTrace(new java.io.PrintWriter(sw));
                    logging.logToError(sw.toString());
                    SwingUtilities.invokeLater(() -> setStatus("Load failed: " + t.getMessage()));
                }
            });
        } else {
            executor.submit(() -> {
                try {
                    loadFromFile(source);
                } catch (Throwable t) {
                    logging.logToError("Load from file failed: " + t.getMessage());
                    java.io.StringWriter sw = new java.io.StringWriter();
                    t.printStackTrace(new java.io.PrintWriter(sw));
                    logging.logToError(sw.toString());
                    SwingUtilities.invokeLater(() -> setStatus("Load failed: " + t.getMessage()));
                }
            });
        }
    }

    private boolean looksLikeUrl(String s) {
        return s.startsWith("http://") || s.startsWith("https://");
    }

    void loadFromUrl(String url) {
        try {
            HttpRequest req = applyAuthToFetch(HttpRequest.httpRequestFromUrl(url), getAuthConfig());
            // The spec URL is user-supplied and often external: verify its certificate by
            // default. Only for https, though: with the TLS option set, Burp never sends a
            // plain-http request. The checkbox exists for self-signed staging hosts.
            boolean verifying = url.startsWith("https://") && verifyTlsCheckBox.isSelected();
            var response = verifying
                    ? api.http().sendRequest(req, RequestOptions.requestOptions().withUpstreamTLSVerification())
                    : api.http().sendRequest(req);
            var httpResponse = response.response();
            if (httpResponse == null) {
                StringBuilder msg = new StringBuilder("No response from ").append(url);
                String hint = networkHint();
                if (hint != null) msg.append(". ").append(hint);
                if (verifying) {
                    msg.append(". If the host uses a self-signed or internal-CA certificate, untick \"Verify TLS\" and retry");
                }
                throw new IOException(msg.toString());
            }
            short status = httpResponse.statusCode();
            if (status < 200 || status >= 300) {
                String msg = "Spec fetch returned HTTP " + status
                        + (status == 401 || status == 403 ? " — check your auth / Extra Headers" : "");
                logging.logToError(msg);
                SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError(msg));
                return;
            }
            byte[] body = httpResponse.body().getBytes();
            String content = new String(body, StandardCharsets.UTF_8);
            parseInBackground(content, url);
        } catch (Exception e) {
            logging.logToError("Failed to load URL: " + e.getMessage());
            SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError("Unable to load from URL: " + e.getMessage()));
        }
    }

    /**
     * Applies the active AuthConfig to an HttpRequest used for fetching the spec itself.
     * Mirrors RequestGenerator's header-injection logic but targets a Montoya HttpRequest
     * rather than raw bytes.
     */
    private HttpRequest applyAuthToFetch(HttpRequest req, AuthConfig auth) {
        if (auth == null || auth.isEmpty()) return req;
        if (auth.hasBearer()) {
            req = req.withAddedHeader("Authorization", "Bearer " + auth.bearerToken());
        }
        if (auth.hasBasic()) {
            req = req.withAddedHeader("Authorization", auth.basicAuthorizationHeaderValue());
        }
        if (auth.hasApiKey()) {
            switch (auth.apiKeyLocation()) {
                case HEADER:
                    req = req.withAddedHeader(auth.apiKeyName(), auth.apiKeyValue());
                    break;
                case COOKIE:
                    req = req.withAddedHeader("Cookie", auth.apiKeyName() + "=" + auth.apiKeyValue());
                    break;
                case QUERY:
                    // Query-string API keys are endpoint-specific; not applied to the spec fetch.
                    break;
            }
        }
        for (AuthConfig.HeaderPair h : auth.extraHeaders()) {
            req = req.withAddedHeader(h.name(), h.value());
        }
        return req;
    }

    /**
     * Explains a silent null response in terms of Burp's own proxy settings, since a stale
     * SOCKS or upstream proxy swallows every extension request without an exception.
     */
    private String networkHint() {
        try {
            String project = api.burpSuite().exportProjectOptionsAsJson("project_options.connections");
            String user = api.burpSuite().exportUserOptionsAsJson("user_options.connections");
            return NetworkHints.describe(project, user);
        } catch (Exception e) {
            return null;
        }
    }

    /** Current status bar text; for tests. */
    String statusText() {
        return statusLabel.getText();
    }

    /** Current text of the raw spec editor, decoded as UTF-8; empty if the editor isn't built yet. */
    private String rawSpecText() {
        if (rawSpecEditor == null) return "";
        ByteArray contents = rawSpecEditor.getContents();
        return contents == null ? "" : new String(contents.getBytes(), StandardCharsets.UTF_8);
    }

    private void fallbackToRawPasteOrSetError(String errorMsg) {
        String raw = rawSpecText();
        if (raw != null && !raw.isBlank()) {
            setStatus("File/URL failed. Parsing pasted content instead...");
            parseInBackground(raw.trim(), "pasted");
        } else {
            setStatus(errorMsg);
        }
    }

    private void loadFromFile(String pathStr) {
        try {
            Path path = Paths.get(pathStr);
            if (!Files.exists(path) || !Files.isRegularFile(path)) {
                SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError("File not found: " + pathStr));
                return;
            }
            byte[] bytes = Files.readAllBytes(path);
            String content = new String(bytes, StandardCharsets.UTF_8);
            parseInBackground(content, pathStr);
        } catch (Exception e) {
            logging.logToError("Failed to load file: " + e.getMessage());
            SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError("Unable to read file: " + e.getMessage()));
        }
    }

    /**
     * Parses spec content in a background thread to keep the UI responsive (BApp Store
     * criterion: use threads for slow operations). Updates the UI on the EDT when done.
     */
    /** Parses a raw body, decoding it on the worker thread rather than the EDT. */
    private void parseInBackground(ByteArray rawBody, String source) {
        executor.submit(() -> {
            try {
                String content = new String(rawBody.getBytes(), StandardCharsets.UTF_8).trim();
                OpenAPIParser.ParseResult result = parser.parse(source, content);
                SwingUtilities.invokeLater(() -> applyParseResult(result, source));
            } catch (Throwable t) {
                logging.logToError("Parse failed: " + t.getMessage());
                SwingUtilities.invokeLater(() -> setStatus("Parse failed: " + t.getMessage()));
            }
        });
    }

    private void parseInBackground(String content, String source) {
        executor.submit(() -> {
            try {
                OpenAPIParser.ParseResult result = parser.parse(source, content);
                SwingUtilities.invokeLater(() -> applyParseResult(result, source));
            } catch (Throwable t) {
                logging.logToError("Parse failed: " + t.getMessage());
                java.io.StringWriter sw = new java.io.StringWriter();
                t.printStackTrace(new java.io.PrintWriter(sw));
                logging.logToError(sw.toString());
                SwingUtilities.invokeLater(() -> setStatus("Parse failed: " + t.getMessage()));
            }
        });
    }

    private void applyParseResult(OpenAPIParser.ParseResult result, String source) {
        tableModel.setEndpoints(result.getEndpoints());
        defaultServer = result.getDefaultServer();
        String existingOverride = baseUrlOverrideField.getText();
        if (!defaultServer.isEmpty() && (existingOverride == null || existingOverride.isBlank())) {
            baseUrlOverrideField.setText(defaultServer);
        }
        applySpecSecuritySchemes(result.getSecuritySchemes());
        tableModel.setFilter(filterField.getText());
        updateFilterHits();
        updateRequestPreview();
        captureActiveIdentity();

        if (!result.getMessages().isEmpty()) {
            for (String m : result.getMessages()) {
                logging.logToOutput("OpenAPI parse: " + m);
            }
        }
        if (result.getEndpoints().isEmpty()) {
            String errMsg = result.getMessages().isEmpty()
                    ? "No endpoints parsed. Check spec format."
                    : "Parse failed: " + result.getMessages().get(0);
            if (result.getMessages().size() > 1) {
                errMsg += " (see extension log for more)";
            }
            setStatus(errMsg);
        } else {
            setStatus("Loaded " + result.getEndpoints().size() + " endpoints from " + source);
        }
    }

    private void updateFilterHits() {
        filterHitsLabel.setText(tableModel.getFilterHitCount() + " hits");
    }

    private void updateRequestPreview() {
        int viewRow = endpointTable.getSelectedRow();
        if (viewRow >= 0) {
            int modelRow = endpointTable.convertRowIndexToModel(viewRow);
            ApiEndpoint ep = tableModel.getEndpointAt(modelRow);
            if (ep != null) {
                HttpRequest req = requestGenerator.buildRequest(ep, getBaseUrlOverride(), getAuthConfig());
                requestEditor.setRequest(req);
            }
        } else {
            requestEditor.setRequest(null);
        }
    }

    /** Returns selected rows translated from view indices (possibly sorted) to model indices. */
    private int[] selectedModelRows() {
        int[] viewRows = endpointTable.getSelectedRows();
        int[] modelRows = new int[viewRows.length];
        for (int i = 0; i < viewRows.length; i++) {
            modelRows[i] = endpointTable.convertRowIndexToModel(viewRows[i]);
        }
        return modelRows;
    }

    private String getBaseUrlOverride() {
        String s = baseUrlOverrideField.getText();
        return (s != null && !s.isBlank()) ? s.trim() : null;
    }

    private JPanel buildAuthPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Authentication (applied to active identity)"));

        // Row 0: Identity dropdown + action buttons.
        identityDropdown = new JComboBox<>();
        identityDropdown.setToolTipText("Switch between named auth configurations. Each stores its own bearer/API key/basic/cookies.");
        refreshIdentityDropdown();
        identityDropdown.addActionListener(e -> {
            if (suppressCapture) return;
            int selected = identityDropdown.getSelectedIndex();
            if (selected < 0 || selected == identityStore.activeIndex()) return;
            captureActiveIdentity();
            identityStore.setActive(selected);
            loadActiveIdentityIntoFields();
        });

        JButton newBtn = new JButton("New…");
        newBtn.addActionListener(e -> doNewIdentity());
        JButton renameBtn = new JButton("Rename…");
        renameBtn.addActionListener(e -> doRenameIdentity());
        JButton deleteBtn = new JButton("Delete");
        deleteBtn.addActionListener(e -> doDeleteIdentity());
        addFormRow(panel, 0, "Identity:", identityDropdown, newBtn, renameBtn, deleteBtn);

        // Row 1: spec-auth summary (dimmed). Aligns under the field column so it reads as metadata
        // for the identity, not as a separate section.
        specAuthSummaryLabel = new JLabel(" ");
        specAuthSummaryLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        GridBagConstraints summaryC = rowConstraints(1);
        summaryC.gridx = 1;
        summaryC.gridwidth = GridBagConstraints.REMAINDER;
        summaryC.fill = GridBagConstraints.HORIZONTAL;
        summaryC.weightx = 1.0;
        summaryC.insets = new Insets(0, 6, 4, 0);
        panel.add(specAuthSummaryLabel, summaryC);

        // Row 2: Bearer token.
        bearerField = new JTextField();
        bearerField.setToolTipText("Whitespace/newlines stripped automatically. Sent as 'Authorization: Bearer <token>'.");
        addFormRow(panel, 2, "Bearer token:", bearerField);

        // Row 3: API key — value + name + location on one row using a sub-grid so they align.
        JPanel apiKeySubrow = new JPanel(new GridBagLayout());
        GridBagConstraints s = new GridBagConstraints();
        s.gridy = 0;
        s.insets = new Insets(0, 0, 0, 6);
        s.fill = GridBagConstraints.HORIZONTAL;

        apiKeyValueField = new JTextField();
        s.gridx = 0; s.weightx = 0.55; apiKeySubrow.add(apiKeyValueField, s);

        s.weightx = 0;
        s.gridx = 1; apiKeySubrow.add(new JLabel("name:"), s);
        apiKeyNameField = new JTextField("X-API-Key", 14);
        s.gridx = 2; s.weightx = 0.35; apiKeySubrow.add(apiKeyNameField, s);

        s.weightx = 0;
        s.gridx = 3; apiKeySubrow.add(new JLabel("in:"), s);
        apiKeyLocationCombo = new JComboBox<>(AuthConfig.ApiKeyLocation.values());
        s.gridx = 4; s.insets = new Insets(0, 0, 0, 0); apiKeySubrow.add(apiKeyLocationCombo, s);

        addFormRow(panel, 3, "API key:", apiKeySubrow);

        // Row 4: Basic auth — user + pass on one row with a sub-grid.
        JPanel basicSubrow = new JPanel(new GridBagLayout());
        GridBagConstraints b = new GridBagConstraints();
        b.gridy = 0;
        b.insets = new Insets(0, 0, 0, 6);
        b.fill = GridBagConstraints.HORIZONTAL;

        basicUserField = new JTextField();
        b.gridx = 0; b.weightx = 0.5; basicSubrow.add(basicUserField, b);

        b.weightx = 0;
        b.gridx = 1; basicSubrow.add(new JLabel("pass:"), b);
        basicPassField = new JPasswordField();
        b.gridx = 2; b.weightx = 0.5; b.insets = new Insets(0, 0, 0, 0); basicSubrow.add(basicPassField, b);

        addFormRow(panel, 4, "Basic auth — user:", basicSubrow);

        // Row 5: Extra headers — label across 2 rows: short inline description, then textarea full width.
        extraHeadersArea = new JTextArea(3, 60);
        extraHeadersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        extraHeadersArea.setToolTipText("Example: X-Tenant: acme  (or paste 'Cookie: session=...' for session-based APIs)");
        JScrollPane headersScroll = new JScrollPane(extraHeadersArea);
        headersScroll.setBorder(new LineBorder(UIManager.getColor("Component.borderColor"), 1));

        GridBagConstraints headersLabelC = rowConstraints(5);
        headersLabelC.gridx = 0;
        headersLabelC.anchor = GridBagConstraints.NORTHEAST;
        headersLabelC.insets = new Insets(6, 0, 0, 6);
        panel.add(new JLabel("Extra headers:"), headersLabelC);

        GridBagConstraints headersFieldC = rowConstraints(5);
        headersFieldC.gridx = 1;
        headersFieldC.gridwidth = GridBagConstraints.REMAINDER;
        headersFieldC.fill = GridBagConstraints.HORIZONTAL;
        headersFieldC.weightx = 1.0;
        headersFieldC.insets = new Insets(4, 0, 2, 0);
        panel.add(headersScroll, headersFieldC);

        GridBagConstraints headersHintC = rowConstraints(6);
        headersHintC.gridx = 1;
        headersHintC.gridwidth = GridBagConstraints.REMAINDER;
        headersHintC.fill = GridBagConstraints.HORIZONTAL;
        headersHintC.weightx = 1.0;
        headersHintC.insets = new Insets(0, 0, 2, 0);
        JLabel hint = new JLabel("One per line, 'Name: Value'. Overrides auth fields on collision.");
        hint.setForeground(UIManager.getColor("Label.disabledForeground"));
        panel.add(hint, headersHintC);

        // Wire field listeners for capture + preview refresh.
        ActionListener captureAndRefresh = e -> {
            captureActiveIdentity();
            updateRequestPreview();
        };
        bearerField.addActionListener(captureAndRefresh);
        apiKeyValueField.addActionListener(captureAndRefresh);
        apiKeyNameField.addActionListener(captureAndRefresh);
        apiKeyLocationCombo.addActionListener(captureAndRefresh);
        basicUserField.addActionListener(captureAndRefresh);
        basicPassField.addActionListener(captureAndRefresh);

        FocusAdapter captureOnBlur = new FocusAdapter() {
            @Override public void focusLost(FocusEvent e) {
                captureActiveIdentity();
                updateRequestPreview();
            }
        };
        bearerField.addFocusListener(captureOnBlur);
        apiKeyValueField.addFocusListener(captureOnBlur);
        apiKeyNameField.addFocusListener(captureOnBlur);
        basicUserField.addFocusListener(captureOnBlur);
        basicPassField.addFocusListener(captureOnBlur);
        extraHeadersArea.addFocusListener(captureOnBlur);

        return panel;
    }

    /** GridBagConstraints preset for a standard form row. */
    private static GridBagConstraints rowConstraints(int gridy) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = gridy;
        c.insets = new Insets(3, 0, 3, 6);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    /**
     * Adds a label-in-column-0 + components-in-column-1+ row to a GridBagLayout container.
     * The first trailing component gets weightx=1.0 so it absorbs horizontal resize; later
     * trailing components (e.g. buttons) hug the right side at their preferred width.
     */
    private static void addFormRow(JPanel container, int gridy, String labelText, java.awt.Component... fields) {
        GridBagConstraints labelC = rowConstraints(gridy);
        labelC.gridx = 0;
        labelC.anchor = GridBagConstraints.EAST;
        JLabel lbl = new JLabel(labelText);
        container.add(lbl, labelC);

        for (int i = 0; i < fields.length; i++) {
            GridBagConstraints fc = rowConstraints(gridy);
            fc.gridx = i + 1;
            if (i == 0) {
                fc.fill = GridBagConstraints.HORIZONTAL;
                fc.weightx = 1.0;
            } else {
                fc.fill = GridBagConstraints.NONE;
                fc.weightx = 0;
            }
            if (i == fields.length - 1) {
                fc.gridwidth = GridBagConstraints.REMAINDER;
                fc.insets = new Insets(3, 0, 3, 0);
            }
            container.add(fields[i], fc);
        }
    }

    private void refreshIdentityDropdown() {
        boolean prevSuppress = suppressCapture;
        suppressCapture = true;
        try {
            identityDropdown.removeAllItems();
            for (Identity id : identityStore.identities()) {
                identityDropdown.addItem(id.name());
            }
            identityDropdown.setSelectedIndex(identityStore.activeIndex());
        } finally {
            suppressCapture = prevSuppress;
        }
    }

    /** Writes the active identity's stored values into the auth form fields. */
    void loadActiveIdentityIntoFields() {
        boolean prevSuppress = suppressCapture;
        suppressCapture = true;
        try {
            Identity active = identityStore.active();
            AuthConfig cfg = active.authConfig();
            bearerField.setText(cfg.bearerToken());
            apiKeyValueField.setText(cfg.apiKeyValue());
            apiKeyNameField.setText(cfg.apiKeyName().isEmpty() ? "X-API-Key" : cfg.apiKeyName());
            apiKeyLocationCombo.setSelectedItem(cfg.apiKeyLocation());
            basicUserField.setText(cfg.basicUser());
            basicPassField.setText(cfg.basicPass());
            StringBuilder sb = new StringBuilder();
            for (AuthConfig.HeaderPair h : cfg.extraHeaders()) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(h.name()).append(": ").append(h.value());
            }
            extraHeadersArea.setText(sb.toString());
            if (!active.baseUrlOverride().isEmpty()) {
                baseUrlOverrideField.setText(active.baseUrlOverride());
            }
        } finally {
            suppressCapture = prevSuppress;
        }
        updateRequestPreview();
    }

    /** Snapshots the current auth fields into the active identity and persists. */
    void captureActiveIdentity() {
        if (suppressCapture) return;
        Identity current = identityStore.active();
        Identity snapshot = new Identity(current.name(), getAuthConfig(), getBaseUrlOverride() != null ? getBaseUrlOverride() : "");
        identityStore.replaceActive(snapshot);
    }

    private void doNewIdentity() {
        String name = (String) JOptionPane.showInputDialog(
                this, "Name for new identity:", "New identity",
                JOptionPane.PLAIN_MESSAGE, null, null, "identity-" + (identityStore.size() + 1));
        if (name == null || name.isBlank()) return;
        try {
            captureActiveIdentity();
            identityStore.add(Identity.empty(name.trim()));
            refreshIdentityDropdown();
            loadActiveIdentityIntoFields();
            setStatus("Added identity '" + name.trim() + "'. Fill in its auth fields.");
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Cannot add identity", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void doRenameIdentity() {
        Identity current = identityStore.active();
        String name = (String) JOptionPane.showInputDialog(
                this, "New name for '" + current.name() + "':", "Rename identity",
                JOptionPane.PLAIN_MESSAGE, null, null, current.name());
        if (name == null || name.isBlank() || name.equals(current.name())) return;
        try {
            identityStore.rename(identityStore.activeIndex(), name.trim());
            refreshIdentityDropdown();
            setStatus("Renamed to '" + name.trim() + "'.");
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Cannot rename", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void doDeleteIdentity() {
        if (identityStore.size() <= 1) {
            JOptionPane.showMessageDialog(this, "At least one identity must exist.",
                    "Cannot delete", JOptionPane.WARNING_MESSAGE);
            return;
        }
        Identity current = identityStore.active();
        int choice = JOptionPane.showConfirmDialog(this,
                "Delete identity '" + current.name() + "'? This cannot be undone.",
                "Delete identity", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) return;
        identityStore.remove(identityStore.activeIndex());
        refreshIdentityDropdown();
        loadActiveIdentityIntoFields();
        setStatus("Deleted identity '" + current.name() + "'.");
    }

    /**
     * Updates the spec-auth summary label and pre-fills the API key fields when the spec
     * declares exactly one API-key scheme. Only fills fields that are currently empty —
     * never clobbers user-entered values.
     */
    void applySpecSecuritySchemes(List<SecuritySchemeInfo> schemes) {
        if (schemes == null || schemes.isEmpty()) {
            specAuthSummaryLabel.setText("Spec declares no auth schemes.");
            return;
        }
        StringBuilder summary = new StringBuilder("Spec declares: ");
        for (int i = 0; i < schemes.size(); i++) {
            if (i > 0) summary.append(", ");
            summary.append(schemes.get(i).displayName());
        }
        specAuthSummaryLabel.setText(summary.toString());

        // If exactly one apiKey scheme, pre-fill the apiKey name + location when the value is empty.
        SecuritySchemeInfo singleApiKey = null;
        for (SecuritySchemeInfo s : schemes) {
            if (s.type() == SecuritySchemeInfo.SchemeType.API_KEY) {
                if (singleApiKey != null) { singleApiKey = null; break; }
                singleApiKey = s;
            }
        }
        if (singleApiKey != null && apiKeyValueField.getText().isBlank()) {
            if (singleApiKey.apiKeyName() != null && !singleApiKey.apiKeyName().isBlank()) {
                apiKeyNameField.setText(singleApiKey.apiKeyName());
            }
            String loc = singleApiKey.apiKeyLocation();
            if ("query".equalsIgnoreCase(loc)) {
                apiKeyLocationCombo.setSelectedItem(AuthConfig.ApiKeyLocation.QUERY);
            } else if ("cookie".equalsIgnoreCase(loc)) {
                apiKeyLocationCombo.setSelectedItem(AuthConfig.ApiKeyLocation.COOKIE);
            } else {
                apiKeyLocationCombo.setSelectedItem(AuthConfig.ApiKeyLocation.HEADER);
            }
        }
    }

    private AuthConfig getAuthConfig() {
        return new AuthConfig(
                bearerField.getText(),
                apiKeyValueField.getText(),
                apiKeyNameField.getText(),
                (AuthConfig.ApiKeyLocation) apiKeyLocationCombo.getSelectedItem(),
                basicUserField.getText(),
                new String(basicPassField.getPassword()),
                AuthConfig.parseExtraHeaders(extraHeadersArea.getText())
        );
    }

    /**
     * Populates the auth panel from a Burp HTTP request, and — when possible — auto-detects
     * the OpenAPI spec source from the request's response body or URL path. Invoked from
     * the "Send to OpenAPI-RBAC-Tester" context menu. Runs on the EDT.
     */
    public void importFromRequest(HttpRequestResponse rr) {
        SwingUtilities.invokeLater(() -> applyImport(rr));
    }

    private void applyImport(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null) {
            setStatus("No request to import.");
            return;
        }

        // If more than one identity exists, ask which one should receive this auth.
        // Silent overwrite of the wrong identity is a nasty false-negative source:
        // "SuperAdmin got 401 too?" → turns out you overwrote SuperAdmin's cookie with
        // regularuser's during import. Only prompt when ambiguous — single-identity
        // users (the common first-run case) aren't bothered.
        if (identityStore.size() > 1) {
            Integer targetIndex = promptForImportTarget();
            if (targetIndex == null) {
                setStatus("Import cancelled.");
                return;
            }
            if (targetIndex == identityStore.size()) {
                // User picked "new identity".
                String name = (String) JOptionPane.showInputDialog(
                        this, "Name for new identity:", "New identity",
                        JOptionPane.PLAIN_MESSAGE, null, null, "identity-" + (identityStore.size() + 1));
                if (name == null || name.isBlank()) {
                    setStatus("Import cancelled.");
                    return;
                }
                try {
                    captureActiveIdentity();
                    identityStore.add(Identity.empty(name.trim()));
                    refreshIdentityDropdown();
                    loadActiveIdentityIntoFields();
                } catch (IllegalArgumentException ex) {
                    JOptionPane.showMessageDialog(this, ex.getMessage(),
                            "Cannot add identity", JOptionPane.WARNING_MESSAGE);
                    return;
                }
            } else if (targetIndex != identityStore.activeIndex()) {
                captureActiveIdentity();
                identityStore.setActive(targetIndex);
                refreshIdentityDropdown();
                loadActiveIdentityIntoFields();
            }
        }

        HttpRequest req = rr.request();
        List<String> rawLines = new ArrayList<>();
        for (HttpHeader h : req.headers()) {
            rawLines.add(h.name() + ": " + h.value());
        }
        HeaderClassifier.Extracted ex = HeaderClassifier.fromRawHeaderLines(rawLines);

        bearerField.setText(ex.bearerToken() != null ? ex.bearerToken() : "");
        basicUserField.setText(ex.basicUser() != null ? ex.basicUser() : "");
        basicPassField.setText(ex.basicPass() != null ? ex.basicPass() : "");
        if (ex.apiKeyValue() != null) {
            apiKeyNameField.setText(ex.apiKeyName());
            apiKeyValueField.setText(ex.apiKeyValue());
            apiKeyLocationCombo.setSelectedItem(AuthConfig.ApiKeyLocation.HEADER);
        } else {
            apiKeyValueField.setText("");
        }
        StringBuilder extras = new StringBuilder();
        for (AuthConfig.HeaderPair h : ex.extraHeaders()) {
            if (extras.length() > 0) extras.append("\n");
            extras.append(h.name()).append(": ").append(h.value());
        }
        extraHeadersArea.setText(extras.toString());

        String baseUrl = deriveBaseUrl(req);
        if (baseUrl != null) {
            baseUrlOverrideField.setText(baseUrl);
            logging.logToOutput("Imported base URL: " + baseUrl);
        } else {
            logging.logToOutput("Could not derive base URL — req.httpService() was null. URL: " + safeUrl(req));
        }

        String fullUrl = safeUrl(req);
        boolean looksLikeSpecPath = HeaderClassifier.isSpecUrlPath(req.path()) && fullUrl != null;
        HttpResponse response = rr.response();
        ByteArray rawBody = response != null ? response.body() : null;

        // Sniffing only needs the first few KB, but even that decode stays off the EDT; the
        // full decode happens in the parse worker, so the whole body is never held twice.
        setStatus("Imported auth — inspecting response body...");
        try {
            executor.submit(() -> {
                boolean haveSpecBody = HeaderClassifier.looksLikeSpecBody(decodePrefix(rawBody, SNIFF_BYTES));
                SwingUtilities.invokeLater(() ->
                        finishImport(rawBody, haveSpecBody, looksLikeSpecPath, fullUrl, baseUrl));
            });
        } catch (RejectedExecutionException e) {
            // Extension is unloading; nothing left to do.
            logging.logToOutput("Import skipped: extension is unloading.");
        }
    }

    private static final int SNIFF_BYTES = 4096;

    private static String decodePrefix(ByteArray body, int maxBytes) {
        if (body == null) return null;
        byte[] bytes = body.getBytes();
        int n = Math.min(bytes.length, maxBytes);
        return new String(bytes, 0, n, StandardCharsets.UTF_8);
    }

    /** Second half of {@link #applyImport}, back on the EDT with the body already sniffed. */
    private void finishImport(ByteArray rawBody, boolean haveSpecBody,
                              boolean looksLikeSpecPath, String fullUrl, String baseUrl) {
        if (haveSpecBody || looksLikeSpecPath) {
            if (fullUrl != null) urlOrPathField.setText(fullUrl);
            if (haveSpecBody) {
                rawSpecEditor.setContents(rawBody);
                setStatus("Imported auth + spec body — parsing now...");
                updateRequestPreview();
                captureActiveIdentity();
                parseInBackground(rawBody, fullUrl != null ? fullUrl : "pasted");
                return;
            }
            setStatus("Imported auth + spec URL — click Load.");
            updateRequestPreview();
            captureActiveIdentity();
            return;
        }

        // No spec detected in the request. Guess the most common spec path on the same host
        // so the user can just click Load instead of typing the URL themselves.
        if (baseUrl != null && urlOrPathField.getText().isBlank()) {
            String guess = baseUrl + "/openapi.json";
            urlOrPathField.setText(guess);
            setStatus("Imported auth. Guessed spec URL " + guess + " — click Load (or edit if your spec lives elsewhere).");
        } else {
            setStatus("Imported auth from request. Load a spec URL or paste a spec to continue.");
        }
        updateRequestPreview();
        captureActiveIdentity();
    }

    /**
     * Modal picker shown during "Send to OpenAPI-RBAC-Tester" when more than one identity
     * exists. Returns the chosen existing identity index, {@code identityStore.size()}
     * to signal "create new identity", or {@code null} if the user cancelled.
     */
    private Integer promptForImportTarget() {
        List<Identity> all = identityStore.identities();
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("Which identity should receive this auth?"));
        panel.add(Box.createVerticalStrut(6));

        ButtonGroup group = new ButtonGroup();
        List<JRadioButton> buttons = new ArrayList<>();
        int activeIdx = identityStore.activeIndex();
        for (int i = 0; i < all.size(); i++) {
            JRadioButton rb = new JRadioButton(all.get(i).name(), i == activeIdx);
            buttons.add(rb);
            group.add(rb);
            panel.add(rb);
        }
        JRadioButton newRb = new JRadioButton("Create new identity…");
        group.add(newRb);
        panel.add(Box.createVerticalStrut(4));
        panel.add(newRb);

        int choice = JOptionPane.showConfirmDialog(this, panel,
                "Send to OpenAPI-RBAC-Tester — choose identity",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) return null;
        if (newRb.isSelected()) return all.size();
        for (int i = 0; i < buttons.size(); i++) {
            if (buttons.get(i).isSelected()) return i;
        }
        return null; // Nothing selected — treat as cancel.
    }

    private static String safeUrl(HttpRequest req) {
        try {
            return req.url();
        } catch (Exception e) {
            return null;
        }
    }

    /** Builds scheme://host[:port] from a request's HttpService, omitting default ports. */
    private static String deriveBaseUrl(HttpRequest req) {
        try {
            HttpService svc = req.httpService();
            if (svc == null) return null;
            String scheme = svc.secure() ? "https" : "http";
            int port = svc.port();
            boolean defaultPort = (svc.secure() && port == 443) || (!svc.secure() && port == 80);
            return scheme + "://" + svc.host() + (defaultPort ? "" : ":" + port);
        } catch (Exception e) {
            return null;
        }
    }

    private void setupContextMenu() {
        JPopupMenu popup = new JPopupMenu();
        JMenu openapiMenu = new JMenu("OpenAPI-RBAC-Tester");
        JMenuItem scanItem = new JMenuItem("Actively Scan");
        scanItem.setEnabled(hasScanner);
        if (!hasScanner) {
            scanItem.setToolTipText("Requires Burp Suite Professional");
        }
        scanItem.addActionListener(e -> doActivelyScan());
        JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
        repeaterItem.addActionListener(e -> doSendToRepeater());
        JMenuItem intruderItem = new JMenuItem("Send to Intruder");
        intruderItem.addActionListener(e -> doSendToIntruder());
        JMenuItem compareItem = new JMenuItem("Compare across identities...");
        compareItem.addActionListener(e -> doCompareIdentities());
        openapiMenu.add(scanItem);
        openapiMenu.add(repeaterItem);
        openapiMenu.add(intruderItem);
        openapiMenu.addSeparator();
        openapiMenu.add(compareItem);
        popup.add(openapiMenu);

        endpointTable.setComponentPopupMenu(popup);
        endpointTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = endpointTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !endpointTable.isRowSelected(row)) {
                        endpointTable.setRowSelectionInterval(row, row);
                    }
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = endpointTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !endpointTable.isRowSelected(row)) {
                        endpointTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });
    }

    private void setupKeyBinding() {
        int modifier = GraphicsEnvironment.isHeadless()
                ? InputEvent.CTRL_DOWN_MASK
                : Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_I, modifier);
        endpointTable.getInputMap(JComponent.WHEN_FOCUSED).put(ks, "SendToIntruder");
        endpointTable.getActionMap().put("SendToIntruder", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                doSendToIntruder();
            }
        });
    }

    private void doActivelyScan() {
        if (!hasScanner) {
            setStatus("Active Scan requires Burp Suite Professional.");
            return;
        }
        int[] rows = selectedModelRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to scan.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        AuthConfig auth = getAuthConfig();
        try {
            int outOfScope = 0;
            String firstOutOfScopeUrl = null;
            for (ApiEndpoint ep : endpoints) {
                HttpRequest probe = requestGenerator.buildRequest(ep, override, auth);
                if (!api.scope().isInScope(probe.url())) {
                    outOfScope++;
                    if (firstOutOfScopeUrl == null) firstOutOfScopeUrl = probe.url();
                }
            }
            if (outOfScope == endpoints.size()) {
                String msg = "All " + outOfScope + " endpoints are out of scope. Scanner silently drops "
                        + "out-of-scope requests. Add target to scope (e.g. " + firstOutOfScopeUrl + ").";
                logging.logToError(msg);
                setStatus(msg);
                return;
            }
            if (outOfScope > 0) {
                logging.logToOutput(outOfScope + "/" + endpoints.size()
                        + " endpoints out of scope — Scanner will skip those.");
            }

            Audit audit = api.scanner().startAudit(
                    AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            logging.logToOutput("startAudit -> " + (audit != null ? audit.getClass().getSimpleName() : "null"));
            int added = 0;
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override, auth);
                audit.addRequest(req);
                added++;
            }
            logging.logToOutput("Added " + added + " requests. Audit status: " + audit.statusMessage());
            setStatus("Audit started: " + added + " requests (" + outOfScope + " skipped as out of scope) — see Dashboard.");
        } catch (Exception ex) {
            logging.logToError("Actively scan failed: " + ex.getMessage());
            java.io.StringWriter sw = new java.io.StringWriter();
            ex.printStackTrace(new java.io.PrintWriter(sw));
            logging.logToError(sw.toString());
            setStatus("Scan failed: " + ex.getMessage());
        }
    }

    private void doSendToRepeater() {
        int[] rows = selectedModelRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to send to Repeater.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        AuthConfig auth = getAuthConfig();
        try {
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override, auth);
                String tabName = ep.getMethod() + " " + ep.getPath();
                if (tabName.length() > 50) tabName = tabName.substring(0, 47) + "...";
                api.repeater().sendToRepeater(req, tabName);
            }
            setStatus("Sent " + endpoints.size() + " endpoints to Repeater. Right-click in Repeater → Scan to scan.");
        } catch (Exception ex) {
            logging.logToError("Send to Repeater failed: " + ex.getMessage());
            setStatus("Repeater failed: " + ex.getMessage());
        }
    }

    private void doSendToIntruder() {
        int[] rows = selectedModelRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to send to Intruder.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        AuthConfig auth = getAuthConfig();
        try {
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override, auth);
                HttpRequestTemplate template = requestGenerator.buildIntruderTemplate(ep, override, auth);
                String tabName = ep.getMethod() + " " + ep.getPath();
                if (tabName.length() > 70) tabName = tabName.substring(0, 67) + "...";
                api.intruder().sendToIntruder(req.httpService(), template, tabName);
            }
            setStatus("Sent " + endpoints.size() + " endpoints to Intruder.");
        } catch (Exception ex) {
            logging.logToError("Send to Intruder failed: " + ex.getMessage());
            setStatus("Intruder failed: " + ex.getMessage());
        }
    }

    private void doCompareIdentities() {
        int[] rows = selectedModelRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to compare.");
            return;
        }
        List<ApiEndpoint> selected = tableModel.getSelectedEndpoints(rows);
        if (identityStore.size() < 2) {
            JOptionPane.showMessageDialog(this,
                    "Create at least two identities (Auth panel → 'New...') to compare access between them.",
                    "Nothing to compare", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Capture the active identity's latest fields before running — otherwise just-typed
        // tokens wouldn't reach the runner.
        captureActiveIdentity();

        List<Identity> picked = pickIdentitiesForCompare();
        if (picked == null || picked.size() < 2) return;

        // Persist the latest state once more in case the picker dialog stole focus.
        captureActiveIdentity();

        List<ApiEndpoint> filtered = confirmOrExcludeDestructive(selected);
        if (filtered == null) return; // user cancelled
        if (filtered.isEmpty()) {
            setStatus("All selected endpoints were excluded — nothing to compare.");
            return;
        }

        RbacHttpSender sender = new MontoyaRbacHttpSender(api.http(), requestGenerator);
        Frame parent = api.userInterface().swingUtils().suiteFrame();
        RbacComparisonDialog dialog = new RbacComparisonDialog(
                parent, api, filtered, picked, sender, 6);
        trackRun(dialog);
        dialog.addWindowListener(new WindowAdapter() {
            @Override public void windowClosed(WindowEvent e) { untrackRun(dialog); }
        });
        dialog.setVisible(true);
        dialog.startRun();
        setStatus("RBAC comparison started: " + filtered.size() + " endpoints × " + picked.size() + " identities.");
    }

    /**
     * Detects logout/delete/revoke endpoints in the selection. If any are present, prompts
     * the user to exclude them from the comparison — firing /logout mid-run invalidates
     * the very sessions we're testing with, producing garbage divergence data.
     *
     * @return filtered list to run (may exclude destructive entries), or {@code null} if
     *         the user cancelled.
     */
    private List<ApiEndpoint> confirmOrExcludeDestructive(List<ApiEndpoint> selected) {
        List<ApiEndpoint> risky = new ArrayList<>();
        for (ApiEndpoint ep : selected) {
            if (DestructiveEndpointDetector.isLikelyDestructive(ep)) risky.add(ep);
        }
        if (risky.isEmpty()) return selected;

        StringBuilder text = new StringBuilder();
        text.append(risky.size()).append(" of ").append(selected.size())
                .append(" selected endpoints look destructive. Running them\n")
                .append("across identities may invalidate the sessions you're comparing\n")
                .append("or mutate server state:\n\n");
        int shown = 0;
        int maxMethodWidth = 0;
        for (ApiEndpoint ep : risky) {
            if (shown++ >= 12) break;
            maxMethodWidth = Math.max(maxMethodWidth, ep.getMethod().length());
        }
        shown = 0;
        for (ApiEndpoint ep : risky) {
            if (shown++ >= 12) break;
            text.append("  • ").append(padRight(ep.getMethod(), maxMethodWidth)).append("  ")
                    .append(ep.getPath());
            String reason = DestructiveEndpointDetector.reasonFor(ep);
            if (!reason.isEmpty()) text.append("   — ").append(reason);
            text.append("\n");
        }
        if (risky.size() > 12) {
            text.append("  … and ").append(risky.size() - 12).append(" more\n");
        }
        text.append("\nExclude these from the comparison?");

        JTextArea area = new JTextArea(text.toString());
        area.setEditable(false);
        area.setOpaque(false);
        area.setBorder(null);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        int choice = JOptionPane.showConfirmDialog(this, area,
                "Destructive endpoints detected",
                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice == JOptionPane.CANCEL_OPTION || choice == JOptionPane.CLOSED_OPTION) return null;
        if (choice == JOptionPane.YES_OPTION) {
            List<ApiEndpoint> filtered = new ArrayList<>();
            for (ApiEndpoint ep : selected) {
                if (!DestructiveEndpointDetector.isLikelyDestructive(ep)) filtered.add(ep);
            }
            return filtered;
        }
        return selected; // NO — user explicitly wants to include them
    }

    private static String padRight(String s, int width) {
        if (s == null) s = "";
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < width) sb.append(' ');
        return sb.toString();
    }

    /**
     * Shows a reorderable checkbox list of identities and returns the user's picks in
     * the order they appear top-to-bottom. The classifier treats list index 0 as the
     * least-privileged identity and the last index as the most-privileged — so the
     * dialog is explicit: "Least privileged at top, most privileged at bottom."
     */
    private List<Identity> pickIdentitiesForCompare() {
        List<Identity> all = identityStore.identities();

        DefaultListModel<IdentityChoice> listModel = new DefaultListModel<>();
        for (Identity id : all) listModel.addElement(new IdentityChoice(id, true));
        JList<IdentityChoice> list = new JList<>(listModel);
        list.setCellRenderer(new IdentityChoiceRenderer());
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setSelectedIndex(0);
        list.setVisibleRowCount(Math.min(listModel.getSize() + 1, 8));

        // Double-click (or Space) toggles the included flag. Single click just selects
        // the row — so Move up/down buttons can reorder without disabling as a side effect.
        list.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() < 2) return;
                int idx = list.locationToIndex(e.getPoint());
                toggleAt(listModel, idx);
            }
        });
        list.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, 0), "rbac-toggle");
        list.getActionMap().put("rbac-toggle", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                toggleAt(listModel, list.getSelectedIndex());
            }
        });

        JButton upBtn = new JButton("↑ Move up");
        upBtn.addActionListener(e -> moveSelected(list, listModel, -1));
        JButton downBtn = new JButton("↓ Move down");
        downBtn.addActionListener(e -> moveSelected(list, listModel, +1));

        JPanel buttonCol = new JPanel();
        buttonCol.setLayout(new BoxLayout(buttonCol, BoxLayout.Y_AXIS));
        buttonCol.add(upBtn);
        buttonCol.add(Box.createVerticalStrut(4));
        buttonCol.add(downBtn);
        buttonCol.add(Box.createVerticalGlue());

        JPanel listAndButtons = new JPanel(new BorderLayout(8, 0));
        listAndButtons.add(new JScrollPane(list), BorderLayout.CENTER);
        listAndButtons.add(buttonCol, BorderLayout.EAST);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        JLabel header = new JLabel("Run each selected endpoint with each ticked identity.");
        JLabel orderHint = new JLabel("Order top → bottom is priority ascending:  put LEAST-privileged at top, MOST-privileged at bottom.");
        orderHint.setForeground(UIManager.getColor("Label.disabledForeground"));
        JLabel clickHint = new JLabel("Double-click (or Space) to toggle ☑/☐. Use Move up/down to reorder.");
        clickHint.setForeground(UIManager.getColor("Label.disabledForeground"));
        panel.add(header);
        panel.add(Box.createVerticalStrut(2));
        panel.add(orderHint);
        panel.add(clickHint);
        panel.add(Box.createVerticalStrut(6));
        panel.add(listAndButtons);

        int choice = JOptionPane.showConfirmDialog(this, panel,
                "Compare identities", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) return null;

        List<Identity> picked = new ArrayList<>();
        for (int i = 0; i < listModel.getSize(); i++) {
            IdentityChoice c = listModel.get(i);
            if (c.included) picked.add(c.identity);
        }
        if (picked.size() < 2) {
            JOptionPane.showMessageDialog(this, "Tick at least two identities to compare.",
                    "Too few identities", JOptionPane.WARNING_MESSAGE);
            return null;
        }
        return picked;
    }

    private static void toggleAt(DefaultListModel<IdentityChoice> model, int idx) {
        if (idx < 0 || idx >= model.getSize()) return;
        IdentityChoice choice = model.get(idx);
        choice.included = !choice.included;
        model.set(idx, choice);
    }

    private static void moveSelected(JList<IdentityChoice> list, DefaultListModel<IdentityChoice> model, int direction) {
        int idx = list.getSelectedIndex();
        if (idx < 0) return;
        int newIdx = idx + direction;
        if (newIdx < 0 || newIdx >= model.getSize()) return;
        IdentityChoice moving = model.remove(idx);
        model.add(newIdx, moving);
        list.setSelectedIndex(newIdx);
    }

    /** Mutable row type for the identity picker list — bundles the identity with a user-toggled include flag. */
    private static final class IdentityChoice {
        final Identity identity;
        boolean included;
        IdentityChoice(Identity identity, boolean included) {
            this.identity = identity;
            this.included = included;
        }
    }

    private static final class IdentityChoiceRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof IdentityChoice choice) {
                String marker = choice.included ? "☑" : "☐";
                setText(marker + "   " + choice.identity.name());
            }
            return c;
        }
    }

    private void setStatus(String msg) {
        statusLabel.setText(msg);
    }

    /** A background run (e.g. an RBAC comparison) that must stop when the extension unloads. */
    interface AbortableRun {
        void abort();
    }

    void trackRun(AbortableRun run) {
        activeRuns.add(run);
    }

    void untrackRun(AbortableRun run) {
        activeRuns.remove(run);
    }

    public void unload() {
        if (filterDebounce != null) filterDebounce.stop();
        for (AbortableRun run : activeRuns) {
            try {
                run.abort();
            } catch (RuntimeException e) {
                logging.logToError("Failed to abort run on unload: " + e.getMessage());
            }
        }
        activeRuns.clear();
        executor.shutdown();
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
