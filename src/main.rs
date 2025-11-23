use eframe::egui;
use keepass::{Database, DatabaseKey};
use keepass::db::{Entry, Group};
use std::collections::HashMap;
use std::fs::File;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("RustPass - KeePass Database Sync"),
        ..Default::default()
    };

    eframe::run_native(
        "RustPass",
        options,
        Box::new(|_cc| Ok(Box::new(RustPassApp::default()))),
    )
}

struct RustPassApp {
    database1_path: String,
    database1_pass: String,
    database2_path: String,
    database2_pass: String,
    status_message: String,
    differences: Vec<DifferenceInfo>,
}

#[derive(Clone)]
struct DifferenceInfo {
    title: String,
    username: String,
    diff_type: DifferenceType,
}

#[derive(Clone)]
enum DifferenceType {
    OnlyInOne,
    OnlyInTwo,
    UsernameDiffers { username1: String, username2: String },
    PasswordDiffers,
}

impl Default for RustPassApp {
    fn default() -> Self {
        Self {
            database1_path: String::new(),
            database1_pass: String::new(),
            database2_path: String::new(),
            database2_pass: String::new(),
            status_message: String::from("Welcome to RustPass! 🔐"),
            differences: Vec::new(),
        }
    }
}

impl RustPassApp {
    fn browse_file(&mut self, target: DatabaseTarget) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("KeePass Database", &["kdbx"])
            .pick_file()
        {
            let path_str = path.display().to_string();
            match target {
                DatabaseTarget::First => self.database1_path = path_str,
                DatabaseTarget::Second => self.database2_path = path_str,
            }
            self.status_message = format!("Selected: {}", path.display());
        }
    }

    fn sync_databases(&mut self) {
        self.status_message = "Decrypting databases...".to_string();

        // Open and decrypt first database
        let db1 = match self.open_database(&self.database1_path, &self.database1_pass) {
            Ok(db) => db,
            Err(e) => {
                self.status_message = format!("Error opening first database: {}", e);
                return;
            }
        };

        // Open and decrypt second database
        let db2 = match self.open_database(&self.database2_path, &self.database2_pass) {
            Ok(db) => db,
            Err(e) => {
                self.status_message = format!("Error opening second database: {}", e);
                return;
            }
        };

        // Compare databases
        self.differences = self.compare_databases(&db1, &db2);

        self.status_message = format!(
            "Successfully compared databases!\nDatabase 1: {} entries\nDatabase 2: {} entries\nDifferences found: {}",
            self.count_entries(&db1),
            self.count_entries(&db2),
            self.differences.len()
        );
    }

    fn open_database(&self, path: &str, password: &str) -> Result<Database, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        let key = DatabaseKey::new().with_password(password);
        Database::open(&mut std::io::BufReader::new(file), key)
            .map_err(|e| format!("Failed to decrypt database: {}", e))
    }

    fn count_entries(&self, db: &Database) -> usize {
        db.root.entries().len()
            + db.root
                .groups()
                .iter()
                .map(|g| self.count_group_entries(g))
                .sum::<usize>()
    }

    fn count_group_entries(&self, group: &Group) -> usize {
        group.entries().len()
            + group
                .groups()
                .iter()
                .map(|g| self.count_group_entries(g))
                .sum::<usize>()
    }

    fn compare_databases(&self, db1: &Database, db2: &Database) -> Vec<DifferenceInfo> {
        let mut differences = Vec::new();

        // Build maps of entries with title as key
        let entries1 = self.collect_all_entries(&db1.root);
        let entries2 = self.collect_all_entries(&db2.root);

        // Check entries in db1
        for (key, entry1) in &entries1 {
            if let Some(entry2) = entries2.get(key) {
                // Entry exists in both - check for differences
                let username1 = entry1.get_username().map(|v| v.to_string()).unwrap_or_default();
                let username2 = entry2.get_username().map(|v| v.to_string()).unwrap_or_default();

                let pass1 = entry1.get_password().map(|v| v.to_string()).unwrap_or_default();
                let pass2 = entry2.get_password().map(|v| v.to_string()).unwrap_or_default();

                if username1 != username2 {
                    differences.push(DifferenceInfo {
                        title: entry1.get_title().unwrap_or("(no title)").to_string(),
                        username: username1.clone(),
                        diff_type: DifferenceType::UsernameDiffers {
                            username1: username1,
                            username2: username2,
                        },
                    });
                } else if pass1 != pass2 {
                    differences.push(DifferenceInfo {
                        title: entry1.get_title().unwrap_or("(no title)").to_string(),
                        username: username1,
                        diff_type: DifferenceType::PasswordDiffers,
                    });
                }
            } else {
                // Entry only in db1
                let title = entry1.get_title().unwrap_or("(no title)").to_string();
                let username = entry1.get_username().map(|v| v.to_string()).unwrap_or_default();

                differences.push(DifferenceInfo {
                    title: title,
                    username: username,
                    diff_type: DifferenceType::OnlyInOne,
                });
            }
        }

        // Check for entries only in db2
        for (key, entry2) in &entries2 {
            if !entries1.contains_key(key) {
                let title = entry2.get_title().unwrap_or("(no title)").to_string();
                let username = entry2.get_username().map(|v| v.to_string()).unwrap_or_default();

                differences.push(DifferenceInfo {
                    title: title,
                    username: username,
                    diff_type: DifferenceType::OnlyInTwo,
                });
            }
        }

        differences
    }

    fn collect_all_entries<'a>(&self, group: &'a Group) -> HashMap<String, &'a Entry> {
        let mut entries = HashMap::new();

        for entry in group.entries() {
            let title = entry.get_title().unwrap_or("(no title)");
            entries.insert(String::from(title), entry);
        }

        for child_group in group.groups() {
            entries.extend(self.collect_all_entries(child_group));
        }

        entries
    }
}

enum DatabaseTarget {
    First,
    Second,
}

impl eframe::App for RustPassApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("RustPass - KeePass Database Sync");
            ui.separator();

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.label("First Database Path:");
                ui.text_edit_singleline(&mut self.database1_path);
                if ui.button("Browse...").clicked() {
                    self.browse_file(DatabaseTarget::First);
                }
            });
            ui.horizontal(|ui| {
                ui.label("First Database Password:");
                let password_field = egui::TextEdit::singleline(&mut self.database1_pass).password(true);
                password_field.show(ui);
            });
            ui.horizontal(|ui| {
                ui.label("Second Database Path:");
                ui.text_edit_singleline(&mut self.database2_path);
                if ui.button("Browse...").clicked() {
                    self.browse_file(DatabaseTarget::Second);
                }
            });
            ui.horizontal(|ui| {
                ui.label("Second Database Password:");
                let password_field = egui::TextEdit::singleline(&mut self.database2_pass).password(true);
                password_field.show(ui);
            });

            ui.add_space(20.0);

            ui.horizontal(|ui| {
                let button = egui::Button::new("🔄 Sync");
                let button_enabled = !(self.database1_path.is_empty() || self.database1_pass.is_empty() || self.database2_path.is_empty() || self.database2_pass.is_empty());
                if ui.add_enabled(button_enabled, button).clicked() {
                    self.sync_databases();
                }
            });

            ui.add_space(20.0);
            ui.separator();

            ui.label(&self.status_message);

            // Display differences
            if !self.differences.is_empty() {
                ui.add_space(20.0);
                ui.separator();
                ui.heading("Differences Found:");

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for diff in &self.differences {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.strong(&diff.title);
                            });

                            match &diff.diff_type {
                                DifferenceType::OnlyInOne => {
                                    ui.colored_label(egui::Color32::YELLOW, "⚠ Only in Database 1");
                                }
                                DifferenceType::OnlyInTwo => {
                                    ui.colored_label(egui::Color32::YELLOW, "⚠ Only in Database 2");
                                }
                                DifferenceType::UsernameDiffers { username1, username2 } => {
                                    ui.colored_label(egui::Color32::LIGHT_BLUE, "📧 Username differs:");
                                    ui.label(format!("  DB1: {}", username1));
                                    ui.label(format!("  DB2: {}", username2));
                                }
                                DifferenceType::PasswordDiffers => {
                                    ui.colored_label(egui::Color32::RED, "🔑 Password differs");
                                }
                            }
                        });
                        ui.add_space(5.0);
                    }
                });
            }
        });
    }
}
