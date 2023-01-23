package com.nccgroup.loggerplusplus.util.userinterface.dialog;

import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Created by corey on 19/07/17.
 */
public class TagTableModel extends AbstractTableModel {

    private final Map<Short, UUID> rowUUIDs = new HashMap<Short, UUID>();
    private final Map<UUID, Tag> tags;
    private final String[] columnNames = {"Tag", "LogFilter", "Enabled", ""};
    private final JButton removeButton = new JButton("Remove");
    private final FilterLibraryController filterLibraryController;

    TagTableModel(FilterLibraryController filterLibraryController) {
        this.filterLibraryController = filterLibraryController;
        //Sort existing filters by their priority before adding to table.
        tags = filterLibraryController.getTags();
        List<Tag> sorted = new ArrayList<Tag>(tags.values());
        Collections.sort(sorted);
        for (Tag filter : sorted) {
            rowUUIDs.put((short) rowUUIDs.size(), filter.getUUID());
        }
    }

    @Override
    public int getRowCount() {
        return tags.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int i) {
        return columnNames[i];
    }

    @Override
    public Object getValueAt(int row, int col) {
        UUID rowUid = rowUUIDs.get((short) row);
        switch (col) {
            case 0:
                return (tags.get(rowUid).getName() == null ? "" : tags.get(rowUid).getName());
            case 1:
                return (tags.get(rowUid).getFilterString() == null ? "" : tags.get(rowUid).getFilterString());
            case 2:
                return tags.get(rowUid).isEnabled();
            case 3:
                return removeButton;
            default:
                return false;
        }
    }

    public boolean validFilterAtRow(int row) {
        return getTagAtRow(row).getFilter() != null;
    }

//    public LogFilter getFilterAtRow(int row){
//        return filters.get(rowUUIDs.get((short) row)).getFilter();
//    }

    public Tag getTagAtRow(int row) {
        return tags.get(rowUUIDs.get((short) row));
    }

    public void setValueAt(Object value, int row, int col) {
        UUID rowUid = rowUUIDs.get((short) row);
        Tag tag = tags.get(rowUid);
        switch (col) {
            case 0:
                tag.setName((String) value);
                break;
            case 1: {
                tag.setFilterString((String) value);
                try {
                    tag.setFilter(new LogFilter(filterLibraryController, (String) value));
                } catch (ParseException e) {
                    tag.setFilter(null);
                }
                break;
            }
            case 2:
                tag.setEnabled((Boolean) value);
                break;
            default:
                return;
        }

        this.filterLibraryController.updateTag(tag);
    }


    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 2:
                return Boolean.class;
            case 3:
                return JButton.class;
            default:
                return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col != 3;
    }

    public void addTag(Tag tag) {
        int i = tags.size();
        filterLibraryController.addTag(tag);
        rowUUIDs.put((short) i, tag.getUUID());
        tag.setPriority((short) i);
        this.fireTableRowsInserted(i, i);
    }

    public void onClick(int row, int column) {
        if (row != -1 && row < tags.size() && column == 3) {
            synchronized (rowUUIDs) {
                Tag removedFilter = tags.get(rowUUIDs.get((short) row));
                filterLibraryController.removeTag(removedFilter);
                this.fireTableRowsDeleted(row, row);
                rowUUIDs.remove((short) row);

                for (int i = row + 1; i <= rowUUIDs.size(); i++) {
                    rowUUIDs.put((short) (i - 1), rowUUIDs.get((short) i));
                    tags.get(rowUUIDs.get((short) i)).setPriority((short) (i - 1));
                    rowUUIDs.remove((short) i);
                }
            }
        }
    }

    public void switchRows(int from, int to) {
        UUID toUid = this.rowUUIDs.get((short) to);
        rowUUIDs.put((short) to, rowUUIDs.get((short) from));
        rowUUIDs.put((short) from, toUid);
        Tag toFilter = tags.get(rowUUIDs.get((short) to));
        toFilter.setPriority((short) to);
        Tag fromFilter = tags.get(rowUUIDs.get((short) from));
        fromFilter.setPriority((short) from);
        filterLibraryController.updateTag(toFilter);
        filterLibraryController.updateTag(fromFilter);
        this.fireTableRowsUpdated(from, from);
        this.fireTableRowsUpdated(to, to);
    }

    public void removeAll() {
        for (Tag tag : new ArrayList<>(filterLibraryController.getTags().values())) {
            filterLibraryController.removeTag(tag);
        }

        this.rowUUIDs.clear();
        this.fireTableDataChanged();
    }
}
