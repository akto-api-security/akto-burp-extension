package com.nccgroup.loggerplusplus.util.userinterface.dialog;

import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.ButtonRenderer;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.ColorRenderer;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.FilterRenderer;
import com.nccgroup.loggerplusplus.util.userinterface.ColorEditor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Created by corey on 19/07/17.
 */
public class ColorFilterTable extends JTable {
    private final FilterLibraryController filterLibraryController;

    ColorFilterTable(FilterLibraryController filterLibraryController){
        this.filterLibraryController = filterLibraryController;
        this.setModel(new ColorFilterTableModel(filterLibraryController));
        this.setFillsViewportHeight(true);
        this.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        this.setAutoCreateRowSorter(false);
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.setRowHeight(25);
        ((JComponent) this.getDefaultRenderer(Boolean.class)).setOpaque(true); // to remove the white background of the checkboxes!
        ((JComponent) this.getDefaultRenderer(JButton.class)).setOpaque(true);

        this.getColumnModel().getColumn(1).setCellRenderer(new FilterRenderer());
        this.getColumnModel().getColumn(2).setCellRenderer(new ColorRenderer(true));
        this.getColumnModel().getColumn(2).setCellEditor(new ColorEditor());
        this.getColumnModel().getColumn(3).setCellRenderer(new ColorRenderer(true));
        this.getColumnModel().getColumn(3).setCellEditor(new ColorEditor());
        this.getColumnModel().getColumn(5).setCellRenderer(new ButtonRenderer());


        this.setDragEnabled(true);
        this.setDropMode(DropMode.INSERT);

        int[] minWidths = {100, 250, 50, 50, 100, 100};
        for(int i=0; i<minWidths.length; i++) {
            this.getColumnModel().getColumn(i).setMinWidth(minWidths[i]);
        }
        int[] maxWidths = {9999, 9999, 200, 200, 100, 100};
        for(int i=0; i<maxWidths.length; i++) {
            this.getColumnModel().getColumn(i).setMaxWidth(maxWidths[i]);
        }
        this.setMinimumSize(new Dimension(850, 200));

        final JTable _this = this;
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                if(SwingUtilities.isLeftMouseButton(mouseEvent)) {
                    int col = _this.columnAtPoint(mouseEvent.getPoint());
                    int row = _this.rowAtPoint(mouseEvent.getPoint());
                    ((ColorFilterTableModel) getModel()).onClick(row, col);
                }
            }
        });
    }

    public void moveSelectedUp() {
        if(this.getSelectedRow() > 0){
            ((ColorFilterTableModel) this.getModel()).switchRows(this.getSelectedRow(), this.getSelectedRow()-1);
            this.getSelectionModel().setSelectionInterval(this.getSelectedRow()-1, this.getSelectedRow()-1);
            ColorFilter filter = ((ColorFilterTableModel) this.getModel()).getFilterAtRow(this.getSelectedRow());
            filterLibraryController.updateColorFilter(filter);
        }
    }
    public void moveSelectedDown() {
        if(this.getSelectedRow() >= 0 && this.getSelectedRow() < this.getRowCount()){
            ((ColorFilterTableModel) this.getModel()).switchRows(this.getSelectedRow(), this.getSelectedRow()+1);
            this.getSelectionModel().setSelectionInterval(this.getSelectedRow()+1, this.getSelectedRow()+1);
            ColorFilter filter = ((ColorFilterTableModel) this.getModel()).getFilterAtRow(this.getSelectedRow());
            filterLibraryController.updateColorFilter(filter);
        }
    }
}
