package burp.openapibifrost;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Swing table model for the OpenAPI-Bifrost endpoint list. Supports regex filtering with a
 * maximum pattern length to mitigate ReDoS. Displays index, scheme, method, server,
 * path, parameters, and description.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class EndpointTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {"#", "Scheme", "Method", "Server", "Path", "Parameters (COOKIE, URL)", "Description"};
    /** Max filter regex length to mitigate ReDoS. Filter content is not sanitized for display. */
    private static final int MAX_FILTER_REGEX_LENGTH = 500;
    private static final int COL_INDEX = 0;
    private static final int COL_SCHEME = 1;
    private static final int COL_METHOD = 2;
    private static final int COL_SERVER = 3;
    private static final int COL_PATH = 4;
    private static final int COL_PARAMS = 5;
    private static final int COL_DESC = 6;

    private List<ApiEndpoint> allEndpoints = new ArrayList<>();
    private List<ApiEndpoint> filteredEndpoints = new ArrayList<>();
    private String filterRegex = "";
    private Pattern filterPattern = null;

    public void setEndpoints(List<ApiEndpoint> endpoints) {
        this.allEndpoints = endpoints != null ? endpoints : new ArrayList<>();
        applyFilter();
    }

    public void setFilter(String regex) {
        String next = regex != null ? regex : "";
        if (next.equals(this.filterRegex)) return; // same text: keep the compiled pattern and the rows
        this.filterRegex = next;
        this.filterPattern = null;
        if (!this.filterRegex.isBlank() && this.filterRegex.length() <= MAX_FILTER_REGEX_LENGTH) {
            try {
                this.filterPattern = Pattern.compile(this.filterRegex);
            } catch (PatternSyntaxException ignored) {
                filterPattern = null;
            }
        }
        applyFilter();
    }

    private void applyFilter() {
        filteredEndpoints.clear();
        if (filterPattern == null) {
            filteredEndpoints.addAll(allEndpoints);
        } else {
            for (ApiEndpoint e : allEndpoints) {
                String row = e.getMethod() + " " + e.getPath() + " " + e.getServer();
                if (filterPattern.matcher(row).find()) {
                    filteredEndpoints.add(e);
                }
            }
        }
        fireTableDataChanged();
    }

    public int getFilterHitCount() {
        return filteredEndpoints.size();
    }

    public ApiEndpoint getEndpointAt(int modelIndex) {
        if (modelIndex >= 0 && modelIndex < filteredEndpoints.size()) {
            return filteredEndpoints.get(modelIndex);
        }
        return null;
    }

    public List<ApiEndpoint> getSelectedEndpoints(int[] modelRows) {
        List<ApiEndpoint> result = new ArrayList<>();
        for (int r : modelRows) {
            ApiEndpoint e = getEndpointAt(r);
            if (e != null) result.add(e);
        }
        return result;
    }

    @Override
    public int getRowCount() {
        return filteredEndpoints.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnIndex == COL_INDEX ? Integer.class : String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ApiEndpoint e = getEndpointAt(rowIndex);
        if (e == null) return "";
        switch (columnIndex) {
            case COL_INDEX: return e.getIndex();
            case COL_SCHEME: return e.getScheme();
            case COL_METHOD: return e.getMethod();
            case COL_SERVER: return e.getServer();
            case COL_PATH: return e.getPath();
            case COL_PARAMS: return formatParams(e.getParameters());
            case COL_DESC: return e.getDescription();
            default: return "";
        }
    }

    private String formatParams(List<ApiEndpoint.ParameterInfo> params) {
        if (params == null || params.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (ApiEndpoint.ParameterInfo p : params) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(p.getLocation().toUpperCase()).append(":").append(p.getName());
        }
        return sb.toString();
    }
}
