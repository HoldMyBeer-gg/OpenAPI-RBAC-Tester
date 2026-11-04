package burp.openapirbactester;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for the RBAC comparison grid. Columns: {@code [#, Method, Path, ...identities, Divergence]}.
 * Cells for identity columns hold {@link RbacCellResult} or {@code null} when the cell hasn't run yet —
 * the renderer interprets null as "pending".
 * <p>
 * Thread-safety: all mutation must happen on the EDT (Swing requirement). The runner pushes
 * results via {@link #setCell}; the dialog wraps that call in {@code SwingUtilities.invokeLater}.
 */
public class RbacResultTableModel extends AbstractTableModel {

    static final int COL_INDEX = 0;
    static final int COL_METHOD = 1;
    static final int COL_PATH = 2;
    static final int FIRST_IDENTITY_COL = 3;

    private final List<ApiEndpoint> endpoints;
    private final List<String> identityNames;
    private final List<Boolean> credentialed;
    private final RbacCellResult[][] cells;
    private final Object[][] rawResponses;

    /** Every identity is treated as credentialed; see the three-argument form. */
    public RbacResultTableModel(List<ApiEndpoint> endpoints, List<String> identityNames) {
        this(endpoints, identityNames, null);
    }

    /**
     * @param credentialed per identity (same order as {@code identityNames}), whether it carries
     *                     any credentials. Drives the horizontal (IDOR) check; null means all do.
     */
    public RbacResultTableModel(List<ApiEndpoint> endpoints, List<String> identityNames, List<Boolean> credentialed) {
        this.endpoints = new ArrayList<>(endpoints);
        this.identityNames = new ArrayList<>(identityNames);
        this.credentialed = credentialed == null ? null : new ArrayList<>(credentialed);
        this.cells = new RbacCellResult[endpoints.size()][identityNames.size()];
        this.rawResponses = new Object[endpoints.size()][identityNames.size()];
    }

    @Override
    public int getRowCount() {
        return endpoints.size();
    }

    @Override
    public int getColumnCount() {
        return FIRST_IDENTITY_COL + identityNames.size() + 1; // +1 for divergence column
    }

    @Override
    public String getColumnName(int column) {
        if (column == COL_INDEX) return "#";
        if (column == COL_METHOD) return "Method";
        if (column == COL_PATH) return "Path";
        int divCol = FIRST_IDENTITY_COL + identityNames.size();
        if (column == divCol) return "Divergence";
        return identityNames.get(column - FIRST_IDENTITY_COL);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == COL_INDEX) return Integer.class;
        int divCol = FIRST_IDENTITY_COL + identityNames.size();
        if (columnIndex == divCol) return DivergenceLevel.class;
        if (columnIndex >= FIRST_IDENTITY_COL && columnIndex < divCol) return RbacCellResult.class;
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ApiEndpoint ep = endpoints.get(rowIndex);
        switch (columnIndex) {
            case COL_INDEX: return ep.getIndex();
            case COL_METHOD: return ep.getMethod();
            case COL_PATH: return ep.getPath();
            default:
                int divCol = FIRST_IDENTITY_COL + identityNames.size();
                if (columnIndex == divCol) {
                    return divergenceFor(rowIndex);
                }
                return cells[rowIndex][columnIndex - FIRST_IDENTITY_COL];
        }
    }

    public void setCell(int row, int col, RbacCellResult result, Object raw) {
        cells[row][col] = result;
        rawResponses[row][col] = raw;
        int divCol = FIRST_IDENTITY_COL + identityNames.size();
        fireTableCellUpdated(row, FIRST_IDENTITY_COL + col);
        fireTableCellUpdated(row, divCol);
    }

    public RbacCellResult getCell(int row, int col) {
        return cells[row][col];
    }

    public Object getRawResponse(int row, int col) {
        return rawResponses[row][col];
    }

    public List<String> identityNames() {
        return new ArrayList<>(identityNames);
    }

    public ApiEndpoint endpointAt(int row) {
        return endpoints.get(row);
    }

    public DivergenceLevel divergenceFor(int row) {
        List<RbacCellResult> rowCells = new ArrayList<>(identityNames.size());
        for (int c = 0; c < identityNames.size(); c++) {
            rowCells.add(cells[row][c]);
        }
        return DivergenceLevel.classify(rowCells, endpoints.get(row).hasPathParameter(), credentialed);
    }

    /** Summary of how many rows fall into each divergence bucket — used for the header stat. */
    public int[] divergenceHistogram() {
        int[] histogram = new int[DivergenceLevel.values().length];
        for (int r = 0; r < endpoints.size(); r++) {
            histogram[divergenceFor(r).ordinal()]++;
        }
        return histogram;
    }
}
