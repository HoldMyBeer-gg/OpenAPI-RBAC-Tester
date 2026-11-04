package burp.openapirbactester;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Modeless dialog that runs and displays the endpoint × identity comparison grid.
 * Cells show HTTP status codes coloured by category; rows carry a divergence label
 * (TIERED / DIVERGENT / CONSISTENT_ALLOW / CONSISTENT_DENY). Results stream in
 * as the runner completes each cell; the dialog remains interactive during the run.
 * Right-click a completed cell to send its request/response to Repeater.
 */
public class RbacComparisonDialog extends JDialog implements OpenAPIRbacTesterTab.AbortableRun {

    private final MontoyaApi api;
    private final List<ApiEndpoint> endpoints;
    private final List<Identity> identities;
    private final RbacRunner runner;
    private final RbacResultTableModel model;
    private JTable table;
    private JLabel progressLabel;
    private JLabel histogramLabel;
    private JButton cancelButton;
    private AccessRuleSet rules = AccessRuleSet.empty();
    private String rulesText = "";
    private final long startedAt = System.currentTimeMillis();

    public RbacComparisonDialog(Frame owner, MontoyaApi api,
                                List<ApiEndpoint> endpoints,
                                List<Identity> identities,
                                RbacHttpSender sender,
                                int concurrency) {
        super(owner, "Compare identities — OpenAPI-RBAC-Tester", false);
        this.api = api;
        this.endpoints = endpoints;
        this.identities = identities;
        this.model = new RbacResultTableModel(endpoints,
                identities.stream().map(Identity::name).toList(),
                identities.stream().map(i -> i.authConfig().hasCredentials()).toList());
        this.runner = new RbacRunner(sender, Math.max(1, concurrency));
        buildUi();
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) { runner.cancel(); runner.shutdown(); }
            @Override public void windowClosed(WindowEvent e) { runner.shutdown(); }
        });
    }

    private void buildUi() {
        setLayout(new BorderLayout(5, 5));

        JPanel top = new JPanel(new BorderLayout(5, 5));
        top.setBorder(new EmptyBorder(8, 10, 4, 10));

        JPanel leftStatus = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        progressLabel = new JLabel(endpoints.size() + " endpoints × " + identities.size()
                + " identities (0/" + totalCells() + ")");
        leftStatus.add(progressLabel);
        histogramLabel = new JLabel(" ");
        leftStatus.add(histogramLabel);
        top.add(leftStatus, BorderLayout.WEST);

        JPanel rightButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        JButton rulesButton = new JButton("Rules...");
        rulesButton.setToolTipText("Declare tag → allowed-identity expectations to flag access violations.");
        rulesButton.addActionListener(e -> openRulesDialog());
        rightButtons.add(rulesButton);

        JButton exportButton = new JButton("Export CSV...");
        exportButton.addActionListener(e -> exportCsv());
        rightButtons.add(exportButton);

        cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> runner.cancel());
        rightButtons.add(cancelButton);
        top.add(rightButtons, BorderLayout.EAST);
        add(top, BorderLayout.NORTH);

        table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        table.setDefaultRenderer(RbacCellResult.class, new CellRenderer());
        table.setDefaultRenderer(DivergenceLevel.class, new DivergenceRenderer());
        table.setRowHeight(Math.max(table.getRowHeight(), 22));
        table.setFillsViewportHeight(true);
        setColumnWidths();
        addContextMenu();
        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        JButton close = new JButton("Close");
        close.addActionListener(e -> dispose());
        bottom.add(close);
        add(bottom, BorderLayout.SOUTH);

        setPreferredSize(new Dimension(1000, 600));
        pack();
        setLocationRelativeTo(getOwner());
    }

    private void setColumnWidths() {
        table.getColumnModel().getColumn(RbacResultTableModel.COL_INDEX).setPreferredWidth(40);
        table.getColumnModel().getColumn(RbacResultTableModel.COL_METHOD).setPreferredWidth(70);
        table.getColumnModel().getColumn(RbacResultTableModel.COL_PATH).setPreferredWidth(280);
        int divCol = RbacResultTableModel.FIRST_IDENTITY_COL + identities.size();
        for (int c = RbacResultTableModel.FIRST_IDENTITY_COL; c < divCol; c++) {
            table.getColumnModel().getColumn(c).setPreferredWidth(80);
        }
        table.getColumnModel().getColumn(divCol).setPreferredWidth(130);
    }

    private int totalCells() {
        return endpoints.size() * identities.size();
    }

    /**
     * Stops the run and closes the window. Called from the extension's unload handler, which
     * may run off the EDT: the runner is stopped immediately (its HTTP traffic must not
     * outlive the extension) and the window disposal is queued onto the EDT.
     */
    @Override
    public void abort() {
        runner.abort();
        if (SwingUtilities.isEventDispatchThread()) {
            dispose();
        } else {
            SwingUtilities.invokeLater(this::dispose);
        }
    }

    public void startRun() {
        runner.run(endpoints, identities, new RbacRunner.Listener() {
            @Override
            public void onCellComplete(int row, int col, RbacCellResult result, Object raw) {
                SwingUtilities.invokeLater(() -> {
                    model.setCell(row, col, result, raw);
                    refreshHeader();
                });
            }

            @Override
            public void onFinished(boolean wasCancelled, int completedCount, int totalCount) {
                SwingUtilities.invokeLater(() -> {
                    long elapsed = System.currentTimeMillis() - startedAt;
                    cancelButton.setEnabled(false);
                    progressLabel.setText(
                            (wasCancelled ? "Cancelled" : "Finished") + " — "
                                    + completedCount + "/" + totalCount + " in " + (elapsed / 1000) + "s");
                });
            }
        });
    }

    private void refreshHeader() {
        int done = 0;
        for (int r = 0; r < endpoints.size(); r++) {
            for (int c = 0; c < identities.size(); c++) {
                if (model.getCell(r, c) != null) done++;
            }
        }
        progressLabel.setText(endpoints.size() + " endpoints × " + identities.size()
                + " identities (" + done + "/" + totalCells() + ")");
        int[] histogram = model.divergenceHistogram();
        StringBuilder sb = new StringBuilder("  ·  ");
        boolean first = true;
        for (DivergenceLevel level : DivergenceLevel.values()) {
            int count = histogram[level.ordinal()];
            if (count == 0) continue;
            if (!first) sb.append(", ");
            sb.append(count).append(' ').append(level.summaryLabel());
            first = false;
        }
        histogramLabel.setText(sb.toString());
    }

    private void addContextMenu() {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem toRepeater = new JMenuItem("Send to Repeater");
        toRepeater.addActionListener(e -> sendSelectedCellToRepeater());
        popup.add(toRepeater);

        table.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybePopup(e); }
            private void maybePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int viewRow = table.rowAtPoint(e.getPoint());
                int viewCol = table.columnAtPoint(e.getPoint());
                if (viewRow < 0 || viewCol < 0) return;
                table.setRowSelectionInterval(viewRow, viewRow);
                table.setColumnSelectionInterval(viewCol, viewCol);
                popup.show(e.getComponent(), e.getX(), e.getY());
            }
        });
    }

    private void sendSelectedCellToRepeater() {
        int viewRow = table.getSelectedRow();
        int viewCol = table.getSelectedColumn();
        if (viewRow < 0 || viewCol < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        int identityCol = viewCol - RbacResultTableModel.FIRST_IDENTITY_COL;
        if (identityCol < 0 || identityCol >= identities.size()) return;
        Object raw = model.getRawResponse(modelRow, identityCol);
        if (!(raw instanceof HttpRequestResponse rr) || rr.request() == null) {
            api.logging().logToOutput("No raw response cached for selected cell.");
            return;
        }
        ApiEndpoint ep = model.endpointAt(modelRow);
        String tabName = identities.get(identityCol).name() + ": " + ep.getMethod() + " " + ep.getPath();
        if (tabName.length() > 60) tabName = tabName.substring(0, 57) + "...";
        api.repeater().sendToRepeater(rr.request(), tabName);
    }

    /** Custom renderer for identity cells — colour-codes by status category. */
    private static class CellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, "", isSelected, hasFocus, row, column);
            if (!(value instanceof RbacCellResult cell)) {
                setText("…");
                if (!isSelected) c.setBackground(table.getBackground());
                return c;
            }
            setText(cell.shortLabel());
            setToolTipText(cell.isError() ? cell.errorMessage()
                    : cell.statusCode() + " · " + cell.bodySize() + "B · " + cell.elapsedMs() + "ms");
            if (!isSelected) c.setBackground(colorFor(cell));
            return c;
        }

        private static Color colorFor(RbacCellResult cell) {
            if (cell.isError()) return new Color(0xFFB3B3);
            if (cell.is2xx()) return new Color(0xC7F0C7);
            if (cell.isAuthDenied()) return new Color(0xFFE4A8);
            if (cell.isNotFound()) return new Color(0xE0E0E0);
            if (cell.is5xx()) return new Color(0xE5C7F0);
            if (cell.is3xx()) return new Color(0xC7DAF0);
            return Color.WHITE;
        }
    }

    /** Custom renderer for the Divergence column — colour-codes the classification. */
    private static class DivergenceRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!(value instanceof DivergenceLevel level)) {
                setText("");
                setToolTipText(null);
                return c;
            }
            setText(level.humanLabel());
            setToolTipText(level.explanation());
            if (!isSelected) {
                switch (level) {
                    case DIVERGENT -> c.setBackground(new Color(0xFFD6D6));
                    case HORIZONTAL -> c.setBackground(new Color(0xFFD9B3));
                    case TIERED -> c.setBackground(new Color(0xDCF0DC));
                    case CONSISTENT_ALLOW -> c.setBackground(new Color(0xE8F5E8));
                    case CONSISTENT_DENY -> c.setBackground(new Color(0xF0F0F0));
                    case ALL_ERRORED -> c.setBackground(new Color(0xFFC5C5));
                    default -> c.setBackground(table.getBackground());
                }
            }
            return c;
        }
    }

    /** Makes the CellRenderer inner class visible to subclasses for future skinning. */
    protected TableCellRenderer createCellRenderer() {
        return new CellRenderer();
    }

    private void openRulesDialog() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("One rule per line:  tag-pattern -> allowed-identity-pattern[,pattern...]"));
        panel.add(new JLabel("Globs: * matches anything, ? one char. Lines starting with # are comments."));
        panel.add(new JLabel("Example:  Admin -> admin*     Public -> *"));
        JTextArea area = new JTextArea(rulesText, 10, 60);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        panel.add(new JScrollPane(area));

        int choice = JOptionPane.showConfirmDialog(this, panel,
                "Access expectation rules", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) return;
        rulesText = area.getText();
        rules = AccessRuleSet.parse(rulesText);
        refreshHeader();
        table.repaint();
    }

    private void exportCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("openapi-rbac-tester.csv"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path target = chooser.getSelectedFile().toPath();
        try {
            String csv = CsvWriter.fromMatrix(model, rules);
            Files.writeString(target, csv, StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this,
                    "Exported " + model.getRowCount() + " rows to " + target.toString(),
                    "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to write CSV: " + ex.getMessage(),
                    "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Exposes the current rule set to tests (package-private). */
    AccessRuleSet currentRules() {
        return rules;
    }
}
