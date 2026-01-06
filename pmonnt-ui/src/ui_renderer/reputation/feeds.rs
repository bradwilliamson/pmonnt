use crate::ui_state::MbUiState;
use eframe::egui;
use pmonnt_core::reputation::LookupState;
use pmonnt_core::reputation_service::ReputationService;
use std::collections::HashMap;
use std::sync::Arc;

pub fn render_threat_intel_feeds(
    ui: &mut egui::Ui,
    mb_state: &mut MbUiState,
    reputation_service: &Arc<ReputationService>,
    _pid_to_image_path: &HashMap<u32, String>,
    bg_worker: &crate::background_worker::BackgroundWorker,
) {
    // NOTE: This helper renders the MalwareBazaar feed/discovery panels that
    // were moved out of the per-process view so they can be collapsed by
    // default. Panels: Recent additions, CSCB, Recent Detections, Tag Search.

    // Get current process hash for MB lookup
    let current_hash = if let Some(result) = reputation_service.get_result("") {
        result.sha256.clone()
    } else {
        None
    };

    // Recent additions (get_recent)
    ui.heading("Recent additions");
    ui.horizontal(|ui| {
        ui.label("Selector:");
        ui.radio_value(
            &mut mb_state.recent_additions_selector,
            "time".to_string(),
            "Last 60 minutes",
        );
        ui.radio_value(
            &mut mb_state.recent_additions_selector,
            "100".to_string(),
            "Latest 100",
        );
        if ui.button("🔄 Fetch").clicked() && !mb_state.recent_additions_fetch_in_progress {
            mb_state.recent_additions_fetch_in_progress = true;
            mb_state.recent_additions_error = None;
            let selector = mb_state.recent_additions_selector.clone();
            let rep = reputation_service.clone();
            let pending = mb_state.recent_additions_pending.clone();
            let ctx = ui.ctx().clone();
            bg_worker.spawn(move || match rep.mb_get_recent(&selector) {
                Ok(results) => {
                    if let Ok(mut guard) = pending.lock() {
                        *guard = Some(results);
                    }
                    ctx.request_repaint();
                }
                Err(e) => {
                    log::error!("Failed to fetch recent additions: {}", e);
                }
            });
        }
        if mb_state.recent_additions_fetch_in_progress {
            ui.spinner();
        }
    });

    // Drain pending recent additions into visible state
    if let Ok(mut guard) = mb_state.recent_additions_pending.lock() {
        if let Some(results) = guard.take() {
            mb_state.recent_additions = results;
            mb_state.recent_additions_fetch_in_progress = false;
        }
    }

    if !mb_state.recent_additions.is_empty() {
        // Sort by first_seen (desc) and page
        let mut view = mb_state.recent_additions.clone();
        view.sort_by(|a, b| b.first_seen.cmp(&a.first_seen));
        let total = view.len();
        ui.label(format!("Found {} recent additions", total));
        let per_page = mb_state.recent_additions_per_page.max(1);
        let page = if total == 0 {
            0
        } else {
            mb_state.recent_additions_page.min((total - 1) / per_page)
        };
        let start = page * per_page;
        let end = (start + per_page).min(total);
        let pages = if total == 0 {
            0
        } else {
            (total - 1) / per_page + 1
        };
        ui.horizontal(|ui| {
            if ui.button("◀ Prev").clicked() && page > 0 {
                mb_state.recent_additions_page = page - 1;
            }
            ui.label(format!("Page {}/{}", page + 1, pages));
            if ui.button("Next ▶").clicked() && end < total {
                mb_state.recent_additions_page = page + 1;
            }
        });
        for s in view.iter().skip(start).take(per_page) {
            ui.horizontal(|ui| {
                ui.label(s.first_seen.clone().unwrap_or_default());
                ui.label(&s.sha256[..8]);
                ui.label(s.signature.clone().unwrap_or_default());
                ui.label(s.file_name.clone().unwrap_or_default());
            });
        }
    }

    // CSCB panel
    ui.heading("Code Signing Blocklist (CSCB)");
    ui.horizontal(|ui| {
        if ui.button("🔄 Fetch CSCB").clicked() && !mb_state.cscb_fetch_in_progress {
            mb_state.cscb_fetch_in_progress = true;
            mb_state.cscb_error = None;
            let rep = reputation_service.clone();
            let pending = mb_state.cscb_pending.clone();
            let ctx = ui.ctx().clone();
            bg_worker.spawn(move || match rep.mb_get_cscb() {
                Ok(entries) => {
                    if let Ok(mut guard) = pending.lock() {
                        *guard = Some(entries);
                    }
                    ctx.request_repaint();
                }
                Err(e) => log::error!("Failed to fetch CSCB: {}", e),
            });
        }
        if mb_state.cscb_fetch_in_progress {
            ui.spinner();
        }
    });
    // Drain pending CSCB results into visible state
    if let Ok(mut guard) = mb_state.cscb_pending.lock() {
        if let Some(entries) = guard.take() {
            mb_state.cscb_entries = entries;
            mb_state.cscb_fetch_in_progress = false;
        }
    }

    if !mb_state.cscb_entries.is_empty() {
        // Sort by valid_to desc and page
        let mut view = mb_state.cscb_entries.clone();
        view.sort_by(|a, b| b.valid_to.cmp(&a.valid_to));
        let total = view.len();
        ui.label(format!("Found {} CSCB entries", total));
        let per_page = mb_state.cscb_per_page.max(1);
        let page = if total == 0 {
            0
        } else {
            mb_state.cscb_page.min((total - 1) / per_page)
        };
        let start = page * per_page;
        let end = (start + per_page).min(total);
        let pages = if total == 0 {
            0
        } else {
            (total - 1) / per_page + 1
        };
        ui.horizontal(|ui| {
            if ui.button("◀ Prev").clicked() && page > 0 {
                mb_state.cscb_page = page - 1;
            }
            ui.label(format!("Page {}/{}", page + 1, pages));
            if ui.button("Next ▶").clicked() && end < total {
                mb_state.cscb_page = page + 1;
            }
        });
        for e in view.iter().skip(start).take(per_page) {
            ui.horizontal(|ui| {
                ui.label(&e.subject_cn);
                ui.label(&e.issuer_cn);
                ui.label(&e.serial_number);
                ui.label(&e.cscb_reason);
                ui.label(&e.valid_to);
            });
        }
    }

    if let Some(_hash) = &current_hash {
        // Display MB-specific data if available
        if let Some(result) = reputation_service.get_result("") {
            if let LookupState::Aggregated(_agg) = &result.state {
                // Prefer the cached sample from the provider for rich UI panels
                if let Some(sample) = reputation_service.mb_get_last_sample() {
                    ui.horizontal(|ui| {
                        ui.label("Signature:");
                        ui.label(sample.signature.clone().unwrap_or_else(|| "—".to_string()));
                    });

                    // Download button
                    ui.horizontal(|ui| {
                        if ui.button("📥 Download sample (zip)").clicked()
                            && !mb_state.download_in_progress
                        {
                            mb_state.download_in_progress = true;
                            mb_state.download_error = None;

                            let hash_clone = sample.sha256.clone();
                            let reputation_service_clone = reputation_service.clone();
                            bg_worker.spawn(move || {
                                let temp_dir = std::env::temp_dir();
                                match reputation_service_clone
                                    .mb_download_sample(&hash_clone, &temp_dir)
                                {
                                    Ok(result) => {
                                        log::info!("Download complete: {:?}", result);
                                    }
                                    Err(e) => {
                                        log::error!("Download failed: {}", e);
                                    }
                                }
                            });
                        }

                        if mb_state.download_in_progress {
                            ui.spinner();
                            ui.label("Downloading...");
                        } else if let Some(error) = &mb_state.download_error {
                            ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
                        } else if let Some(path) = &mb_state.last_download_path {
                            ui.colored_label(egui::Color32::GREEN, format!("Downloaded: {}", path));
                        }
                    });

                    // Vendor Intelligence
                    ui.collapsing("Vendor Intelligence", |ui| {
                        if let Some(v) = &sample.vendor_intel {
                            match serde_json::to_string_pretty(v) {
                                Ok(s) => {
                                    ui.monospace(s);
                                }
                                Err(_) => {
                                    ui.label("(unrenderable vendor intel)");
                                }
                            }
                        } else {
                            ui.label("No vendor intelligence available.");
                        }
                    });

                    // YARA Rules
                    ui.collapsing("YARA Rules", |ui| {
                        if let Some(y) = &sample.yara_rules {
                            match serde_json::to_string_pretty(y) {
                                Ok(s) => {
                                    ui.monospace(s);
                                }
                                Err(_) => {
                                    ui.label("(unrenderable YARA data)");
                                }
                            }
                        } else {
                            ui.label("No YARA rules available.");
                        }
                    });

                    // Comments
                    ui.collapsing("Comments", |ui| {
                        if let Some(comments) = &sample.comments {
                            if comments.is_empty() {
                                ui.label("No comments.");
                            } else {
                                for c in comments.iter() {
                                    ui.horizontal(|ui| {
                                        let meta = format!(
                                            "{} - {}",
                                            c.date.clone().unwrap_or_default(),
                                            c.author.clone().unwrap_or_default()
                                        );
                                        ui.label(meta);
                                    });
                                    ui.label(c.comment.clone().unwrap_or_default());
                                    ui.separator();
                                }
                            }
                        } else {
                            ui.label("No comments available.");
                        }
                    });
                }
            }
        }
    }

    ui.separator();
    ui.add_space(4.0);

    // Recent detections section
    ui.heading("Recent Detections");
    ui.horizontal(|ui| {
        ui.label("Hours:");
        ui.add(egui::Slider::new(&mut mb_state.recent_hours, 1..=168));

        if ui.button("🔄 Fetch").clicked() && !mb_state.recent_fetch_in_progress {
            mb_state.recent_fetch_in_progress = true;
            mb_state.recent_error = None;

            let hours = mb_state.recent_hours;
            let reputation_service_clone = reputation_service.clone();
            bg_worker.spawn(move || {
                // Call the real recent_detections method
                match reputation_service_clone.mb_recent_detections(Some(hours)) {
                    Ok(detections) => {
                        // Update UI state with results
                        // Note: This would need proper UI update mechanism
                        log::info!("Fetched {} recent detections", detections.len());
                    }
                    Err(e) => {
                        log::error!("Recent detections failed: {}", e);
                    }
                }
            });
        }

        if mb_state.recent_fetch_in_progress {
            ui.spinner();
        }
    });

    if let Some(error) = &mb_state.recent_error {
        ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
    } else if !mb_state.recent_detections.is_empty() {
        ui.label(format!(
            "Found {} recent detections",
            mb_state.recent_detections.len()
        ));
        // Show first few
        for detection in mb_state.recent_detections.iter().take(5) {
            ui.horizontal(|ui| {
                ui.label(&detection.sha256_hash[..8]);
                if let Some(sig) = &detection.signature {
                    ui.label(sig);
                }
            });
        }
    }

    ui.separator();
    ui.add_space(4.0);

    // Tag search section
    ui.heading("Tag Search");
    ui.horizontal(|ui| {
        ui.label("Tag:");
        ui.text_edit_singleline(&mut mb_state.tag_search_text);

        ui.label("Limit:");
        ui.add(egui::Slider::new(&mut mb_state.tag_search_limit, 1..=1000));

        if ui.button("🔍 Search").clicked() && !mb_state.tag_search_in_progress {
            mb_state.tag_search_in_progress = true;
            mb_state.tag_search_error = None;

            let tag = mb_state.tag_search_text.clone();
            let limit = mb_state.tag_search_limit;
            let reputation_service_clone = reputation_service.clone();
            bg_worker.spawn(move || {
                // Call the real tag search method
                match reputation_service_clone.mb_tag_search(&tag, Some(limit)) {
                    Ok(samples) => {
                        log::info!("Found {} samples with tag '{}'", samples.len(), tag);
                    }
                    Err(e) => {
                        log::error!("Tag search failed: {}", e);
                    }
                }
            });
        }

        if mb_state.tag_search_in_progress {
            ui.spinner();
        }
    });

    if let Some(error) = &mb_state.tag_search_error {
        ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
    } else if !mb_state.tag_search_results.is_empty() {
        ui.label(format!(
            "Found {} samples with tag '{}'",
            mb_state.tag_search_results.len(),
            mb_state.tag_search_text
        ));
        // Show first few
        for sample in mb_state.tag_search_results.iter().take(5) {
            ui.horizontal(|ui| {
                ui.label(&sample.sha256_hash[..8]);
                if let Some(sig) = &sample.signature {
                    ui.label(sig);
                }
            });
        }
    }
}
