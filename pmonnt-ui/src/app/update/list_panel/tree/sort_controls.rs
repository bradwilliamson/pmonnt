use eframe::egui;

use crate::app::PMonNTApp;
use crate::view::GroupSort;

pub(super) fn render_tree_sort_controls(app: &mut PMonNTApp, ui: &mut egui::Ui) {
    // Simple sort toggle controls for tree view
    ui.horizontal(|ui| {
        ui.label("Sort:");
        if ui
            .selectable_label(app.group_sort == GroupSort::Name, "Name")
            .clicked()
        {
            if app.group_sort == GroupSort::Name {
                app.sort_desc = !app.sort_desc;
            } else {
                app.group_sort = GroupSort::Name;
                app.sort_desc = false;
            }
        }
        if ui
            .selectable_label(
                app.group_sort == GroupSort::VerifiedSigner,
                "Verified Signer",
            )
            .clicked()
        {
            if app.group_sort == GroupSort::VerifiedSigner {
                app.sort_desc = !app.sort_desc;
            } else {
                app.group_sort = GroupSort::VerifiedSigner;
                app.sort_desc = false;
            }
        }
        if ui
            .selectable_label(app.group_sort == GroupSort::Disk, "Disk")
            .clicked()
        {
            if app.group_sort == GroupSort::Disk {
                app.sort_desc = !app.sort_desc;
            } else {
                app.group_sort = GroupSort::Disk;
                app.sort_desc = true;
            }
        }
        if ui
            .selectable_label(app.group_sort == GroupSort::Handles, "Handles")
            .clicked()
        {
            if app.group_sort == GroupSort::Handles {
                app.sort_desc = !app.sort_desc;
            } else {
                app.group_sort = GroupSort::Handles;
                app.sort_desc = true;
            }
        }
    });
}
