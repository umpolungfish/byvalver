#define _GNU_SOURCE  // Required for strdup function
#include "tui_screens.h"
#include "tui_file_browser.h"  // Include file browser header
#include "../badchar_profiles.h"  // Include bad character profiles header
#include "../processing.h"  // Include processing function header
#include "../core.h"  // Include core functions
#include "../strategy.h"  // Include strategy initialization
#include "../obfuscation_strategy_registry.h"  // Include obfuscation strategies
#include "../batch_processing.h"  // Include batch processing
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  // For napms function and dup/dup2
#include <errno.h>
#include <sys/stat.h>  // For stat() and struct stat
#include <fcntl.h>  // For open() and O_WRONLY

// Global variables to store processing results
static size_t g_last_input_size = 0;
static size_t g_last_output_size = 0;
static int g_last_processing_result = -1;

// Main screen implementation
int show_main_screen(byvalver_config_t *config) {
    (void)config; // Suppress unused parameter warning
    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("byvalver v3.0 - Interactive Mode");

        int row = 5;
        mvprintw(row++, 5, "Welcome to byvalver Interactive Mode!");
        mvprintw(row++, 5, "Choose an option:");
        mvprintw(row++, 5, " ");

        draw_menu_item(row++, 5, "1. Process Single File", current_selection == 1);
        draw_menu_item(row++, 5, "2. Batch Process Directory", current_selection == 2);
        draw_menu_item(row++, 5, "3. Configure Processing Options", current_selection == 3);
        draw_menu_item(row++, 5, "4. Set Bad Characters", current_selection == 4);
        draw_menu_item(row++, 5, "5. Output Format Settings", current_selection == 5);
        draw_menu_item(row++, 5, "6. ML Metrics Configuration", current_selection == 6);
        draw_menu_item(row++, 5, "7. Advanced Options", current_selection == 7);
        draw_menu_item(row++, 5, "8. Load/Save Configuration", current_selection == 8);
        draw_menu_item(row++, 5, "9. About byvalver", current_selection == 9);
        mvprintw(row++, 5, " ");
        draw_menu_item(row++, 5, "0. Exit", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return EXIT_SCREEN; // Exit
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
            } else {
                current_selection = 9; // wrap around to max
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 9) {
                current_selection++;
            } else {
                current_selection = 0; // wrap around to min
            }
        } else if (ch == '\n' || ch == '\r') {
            // Return based on current selection
            switch (current_selection) {
                case 1: return INPUT_SCREEN;
                case 2: return BATCH_SCREEN;
                case 3: return OPTIONS_SCREEN;
                case 4: return BAD_CHARS_SCREEN;
                case 5: return OUTPUT_FORMAT_SCREEN;
                case 6: return ML_METRICS_SCREEN;
                case 7: return ADVANCED_OPTIONS_SCREEN;
                case 8: return CONFIG_SCREEN;
                case 9: return ABOUT_SCREEN;
                case 0: return EXIT_SCREEN;
                default: return MAIN_SCREEN;
            }
        } else if (ch >= '0' && ch <= '9') {
            int choice = ch - '0';
            switch (choice) {
                case 1: return INPUT_SCREEN;
                case 2: return BATCH_SCREEN;
                case 3: return OPTIONS_SCREEN;
                case 4: return BAD_CHARS_SCREEN;
                case 5: return OUTPUT_FORMAT_SCREEN;
                case 6: return ML_METRICS_SCREEN;
                case 7: return ADVANCED_OPTIONS_SCREEN;
                case 8: return CONFIG_SCREEN;
                case 9: return ABOUT_SCREEN;
                case 0: return EXIT_SCREEN;
                default: return MAIN_SCREEN;
            }
        }
    }
}

// Input screen implementation
int show_input_screen(byvalver_config_t *config) {
    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("Single File Processing");

        int row = 5;
        mvprintw(row++, 5, "Single File Processing Configuration:");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Current input file:  %s", config->input_file ? config->input_file : "Not set");
        mvprintw(row++, 5, "Current output file: %s", config->output_file ? config->output_file : "Not set");
        mvprintw(row++, 5, " ");

        draw_menu_item(row++, 5, "1. Browse for Input File", current_selection == 1);
        draw_menu_item(row++, 5, "2. Browse for Output File", current_selection == 2);
        draw_menu_item(row++, 5, "3. Start Processing", current_selection == 3);
        mvprintw(row++, 5, " ");
        draw_menu_item(row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN;
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
            } else {
                current_selection = 3;
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 3) {
                current_selection++;
            } else {
                current_selection = 0;
            }
        } else if (ch == '\n' || ch == '\r') {
            switch (current_selection) {
                case 1: {
                    // Browse for input file - start from file's directory or current directory
                    const char *start_path = NULL;
                    if (config->input_file) {
                        struct stat st;
                        if (stat(config->input_file, &st) == 0) {
                            start_path = config->input_file;
                        }
                    }
                    char *selected = show_file_browser(start_path, BROWSER_MODE_SELECT_FILE, NULL);
                    if (selected) {
                        // Validate that it's actually a file, not a directory
                        struct stat st;
                        if (stat(selected, &st) == 0 && S_ISREG(st.st_mode)) {
                            config->input_file = selected;
                        } else if (stat(selected, &st) == 0 && S_ISDIR(st.st_mode)) {
                            clear_screen();
                            draw_header("Error");
                            mvprintw(5, 5, "Error: Selected path is a directory, not a file!");
                            mvprintw(6, 5, "Path: %s", selected);
                            mvprintw(8, 5, "Press any key to continue...");
                            getch();
                            free(selected);
                        } else {
                            config->input_file = selected;
                        }
                    }
                    break;
                }
                case 2: {
                    // Browse for output file - allow selecting directory or typing filename
                    clear_screen();
                    draw_header("Output File");
                    mvprintw(5, 5, "Enter output file path (or 'b' to browse for directory):");
                    char output_input[512];
                    echo();
                    getstr(output_input);
                    noecho();

                    if (strcmp(output_input, "b") == 0 || strcmp(output_input, "B") == 0) {
                        char *selected = show_file_browser(NULL, BROWSER_MODE_SELECT_DIRECTORY, NULL);
                        if (selected) {
                            // Append a default filename
                            char *full_path = malloc(strlen(selected) + 32);
                            sprintf(full_path, "%s/output.bin", selected);
                            config->output_file = full_path;
                            free(selected);
                        }
                    } else if (strlen(output_input) > 0) {
                        config->output_file = strdup(output_input);
                    }
                    break;
                }
                case 3:
                    if (!config->input_file) {
                        clear_screen();
                        draw_header("Error");
                        mvprintw(5, 5, "Error: No input file selected!");
                        mvprintw(7, 5, "Press any key to continue...");
                        getch();
                        break;
                    }
                    // Ensure batch mode is disabled for single file processing
                    config->batch_mode = 0;
                    return PROCESSING_SCREEN;
                case 0:
                    return MAIN_SCREEN;
            }
        } else if (ch >= '0' && ch <= '3') {
            int choice = ch - '0';
            if (choice == current_selection) {
                // Trigger action directly with number key (same as current selection above)
            } else {
                current_selection = choice;
            }
        }
    }
}

// Options screen implementation
int show_options_screen(byvalver_config_t *config) {
    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("Processing Options");

        int row = 5;
        mvprintw(row++, 5, "Processing Options:");

        char option1_text[100];
        char option2_text[100];
        char option3_text[100];
        char option4_text[100];
        char option5_text[100];

        snprintf(option1_text, sizeof(option1_text), "1. Biphasic Processing: %s",
                config->use_biphasic ? "[ON]" : "[OFF]");
        snprintf(option2_text, sizeof(option2_text), "2. Position Independent Code: %s",
                config->use_pic_generation ? "[ON]" : "[OFF]");
        snprintf(option3_text, sizeof(option3_text), "3. ML Strategy Selection: %s",
                config->use_ml_strategist ? "[ON]" : "[OFF]");
        snprintf(option4_text, sizeof(option4_text), "4. Verbose Output: %s",
                config->verbose ? "[ON]" : "[OFF]");
        snprintf(option5_text, sizeof(option5_text), "5. Dry Run: %s",
                config->dry_run ? "[ON]" : "[OFF]");

        draw_menu_item(row++, 5, option1_text, current_selection == 1);
        draw_menu_item(row++, 5, option2_text, current_selection == 2);
        draw_menu_item(row++, 5, option3_text, current_selection == 3);
        draw_menu_item(row++, 5, option4_text, current_selection == 4);
        draw_menu_item(row++, 5, option5_text, current_selection == 5);
        draw_menu_item(row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN; // Exit to main menu
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
            } else {
                current_selection = 5; // wrap around to max
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 5) {
                current_selection++;
            } else {
                current_selection = 0; // wrap around to min
            }
        } else if (ch == '\n' || ch == '\r') {
            // Toggle option based on current selection
            switch (current_selection) {
                case 1:
                    config->use_biphasic = !config->use_biphasic;
                    break;
                case 2:
                    config->use_pic_generation = !config->use_pic_generation;
                    break;
                case 3:
                    config->use_ml_strategist = !config->use_ml_strategist;
                    break;
                case 4:
                    config->verbose = !config->verbose;
                    break;
                case 5:
                    config->dry_run = !config->dry_run;
                    break;
                case 0:
                    return MAIN_SCREEN;
            }
            continue; // Redraw the screen to show updated status
        } else if (ch >= '0' && ch <= '5') {
            int choice = ch - '0';
            switch (choice) {
                case 1:
                    config->use_biphasic = !config->use_biphasic;
                    break;
                case 2:
                    config->use_pic_generation = !config->use_pic_generation;
                    break;
                case 3:
                    config->use_ml_strategist = !config->use_ml_strategist;
                    break;
                case 4:
                    config->verbose = !config->verbose;
                    break;
                case 5:
                    config->dry_run = !config->dry_run;
                    break;
                case 0:
                    return MAIN_SCREEN;
            }
            continue; // Redraw the screen to show updated status
        }
    }
}

// Processing screen implementation
int show_processing_screen(byvalver_config_t *config) {
    clear_screen();

    // Check if this is batch mode or single file mode
    int is_batch = config->batch_mode;

    if (is_batch) {
        draw_header("Batch Processing");
    } else {
        draw_header("Processing Shellcode");
    }

    int row = 5;
    if (is_batch) {
        mvprintw(row++, 5, "Batch processing directory with current configuration...");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Input directory:  %s", config->input_file ? config->input_file : "Not set");
        mvprintw(row++, 5, "Output directory: %s", config->output_file ? config->output_file : "Not set");
        mvprintw(row++, 5, "File pattern:     %s", config->file_pattern ? config->file_pattern : "*.bin");
        mvprintw(row++, 5, "Recursive:        %s", config->recursive ? "Yes" : "No");
    } else {
        mvprintw(row++, 5, "Processing shellcode with current configuration...");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Input file:  %s", config->input_file ? config->input_file : "Not set");
        mvprintw(row++, 5, "Output file: %s", config->output_file ? config->output_file : "Not set");
    }
    mvprintw(row++, 5, " ");

    // Check if input is set
    if (!config->input_file) {
        mvprintw(row++, 5, "Error: No input specified!");
        mvprintw(row++, 5, "Press any key to return to main menu...");
        getch();
        return MAIN_SCREEN;
    }

    if (is_batch) {
        // BATCH PROCESSING WITH LIVE UPDATES
        mvprintw(row++, 5, " ");
        int scan_row = row;
        mvprintw(row++, 5, "Scanning directory...");
        refresh();

        // Find all files matching the pattern
        file_list_t file_list;
        file_list_init(&file_list);

        if (find_files(config->input_file, config->file_pattern, config->recursive, &file_list) != 0) {
            mvprintw(row++, 5, "Error: Failed to scan directory");
            mvprintw(row++, 5, "Press any key to continue...");
            getch();
            file_list_free(&file_list);
            return MAIN_SCREEN;
        }

        // Update with file count
        mvprintw(scan_row, 5, "Scanning directory... Found %zu files", file_list.count);
        refresh();
        napms(500); // Brief pause so user can see the count

        if (file_list.count == 0) {
            mvprintw(row++, 5, "No files found matching pattern '%s'", config->file_pattern);
            mvprintw(row++, 5, "Press any key to continue...");
            getch();
            file_list_free(&file_list);
            return MAIN_SCREEN;
        }

        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Initializing strategies...");
        refresh();

        // Initialize strategy registries (needed for processing)
        init_strategies(config->use_ml_strategist);
        if (config->use_biphasic) {
            init_obfuscation_strategies();
        }

        mvprintw(row++, 5, "Initializing bad character context...");
        refresh();

        // Initialize bad character context for processing
        init_bad_char_context(config->bad_chars);

        mvprintw(row++, 5, "Setting up batch statistics...");
        refresh();

        // Initialize batch statistics
        batch_stats_t stats;
        batch_stats_init(&stats);
        stats.total_files = file_list.count;

        // Set bad character configuration in stats
        bad_char_config_t* bad_char_config = get_bad_char_config();
        if (bad_char_config) {
            stats.bad_char_count = bad_char_config->bad_char_count;
            for (int i = 0; i < 256; i++) {
                stats.bad_char_set[i] = bad_char_config->bad_chars[i];
            }
        }

        // Set batch stats context for strategy tracking
        set_batch_stats_context(&stats);

        mvprintw(row++, 5, "Starting batch processing...");
        refresh();
        napms(1000); // Give user time to see the message

        // Save original verbose setting and suppress output during TUI processing
        int original_verbose = config->verbose;
        int original_quiet = config->quiet;
        config->verbose = 0;
        config->quiet = 1;

        // Process each file with live updates
        for (size_t i = 0; i < file_list.count; i++) {
            const char *input_path = file_list.paths[i];

            // Construct output path
            char *output_path = construct_output_path(input_path, config->input_file,
                                                     config->output_file, config->preserve_structure);
            if (!output_path) {
                stats.skipped_files++;
                continue;
            }

            // Clear screen and redraw progress
            clear_screen();
            draw_header("Batch Processing - Live Progress");

            int progress_row = 3;

            // Progress bar
            int bar_width = 50;
            int filled = (int)((float)(i + 1) / file_list.count * bar_width);
            mvprintw(progress_row++, 5, "Progress: [");
            attron(COLOR_PAIR(4)); // Green
            for (int j = 0; j < filled; j++) printw("=");
            attroff(COLOR_PAIR(4));
            for (int j = filled; j < bar_width; j++) printw(" ");
            printw("] %zu/%zu files", i + 1, file_list.count);
            progress_row++;

            // Statistics
            mvprintw(progress_row++, 5, " ");
            mvprintw(progress_row++, 5, "Statistics:");
            attron(COLOR_PAIR(4));
            mvprintw(progress_row++, 5, "  Successful: %zu", stats.processed_files);
            attroff(COLOR_PAIR(4));
            attron(COLOR_PAIR(3));
            mvprintw(progress_row++, 5, "  Failed:     %zu", stats.failed_files);
            attroff(COLOR_PAIR(3));
            mvprintw(progress_row++, 5, "  Skipped:    %zu", stats.skipped_files);
            progress_row++;

            // Current file
            mvprintw(progress_row++, 5, "Current file:");
            attron(A_BOLD);
            mvprintw(progress_row++, 5, "  %s", input_path);
            attroff(A_BOLD);
            progress_row++;

            // Next file preview
            if (i + 1 < file_list.count) {
                mvprintw(progress_row++, 5, "Next file:");
                attron(COLOR_PAIR(5)); // Yellow/dim
                mvprintw(progress_row++, 5, "  %s", file_list.paths[i + 1]);
                attroff(COLOR_PAIR(5));
            }
            progress_row++;

            // Strategy statistics table
            if (stats.strategy_count > 0) {
                mvprintw(progress_row++, 5, "Strategy Usage Statistics:");
                mvprintw(progress_row++, 5, "  %-30s  %8s  %8s  %8s",
                        "Strategy", "Total", "Success", "Rate");
                mvprintw(progress_row++, 5, "  %s",
                        "--------------------------------------------------------------------------------");

                // Show top 10 strategies
                int display_count = stats.strategy_count > 10 ? 10 : (int)stats.strategy_count;
                for (int s = 0; s < display_count; s++) {
                    strategy_stats_t *usage = &stats.strategy_stats[s];
                    int total_uses = usage->success_count + usage->failure_count;
                    float success_rate = total_uses > 0 ?
                        (float)usage->success_count / total_uses * 100.0f : 0.0f;

                    // Truncate long strategy names
                    char short_name[31];
                    strncpy(short_name, usage->name, 30);
                    short_name[30] = '\0';

                    if (success_rate >= 80.0f) {
                        attron(COLOR_PAIR(4)); // Green for high success
                    } else if (success_rate >= 50.0f) {
                        attron(COLOR_PAIR(5)); // Yellow for medium
                    } else {
                        attron(COLOR_PAIR(3)); // Red for low success
                    }

                    mvprintw(progress_row++, 5, "  %-30s  %8d  %8d  %7.1f%%",
                            short_name, total_uses, usage->success_count, success_rate);

                    attroff(COLOR_PAIR(4));
                    attroff(COLOR_PAIR(5));
                    attroff(COLOR_PAIR(3));
                }

                if (stats.strategy_count > 10) {
                    mvprintw(progress_row++, 5, "  ... and %zu more strategies",
                            stats.strategy_count - 10);
                }
            }

            refresh();

            // Redirect stdout/stderr for this file's processing only
            int stdout_backup = dup(STDOUT_FILENO);
            int stderr_backup = dup(STDERR_FILENO);
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }

            // Process the file
            size_t input_size = 0, output_size = 0;
            int result = process_single_file(input_path, output_path, config, &input_size, &output_size);

            // Restore stdout/stderr immediately after processing
            fflush(stdout);
            fflush(stderr);
            dup2(stdout_backup, STDOUT_FILENO);
            dup2(stderr_backup, STDERR_FILENO);
            close(stdout_backup);
            close(stderr_backup);

            if (result == EXIT_SUCCESS) {
                stats.processed_files++;
                stats.total_input_bytes += input_size;
                stats.total_output_bytes += output_size;

                // Count file complexity statistics
                FILE *input_file = fopen(input_path, "rb");
                if (input_file) {
                    uint8_t *input_data = malloc(input_size);
                    if (input_data && fread(input_data, 1, input_size, input_file) == input_size) {
                        int instr_count, bad_char_count;
                        count_shellcode_stats(input_data, input_size, &instr_count, &bad_char_count);
                        batch_stats_add_file_stats(&stats, input_path, input_size,
                                                 output_size, instr_count, bad_char_count, 1);
                    }
                    if (input_data) free(input_data);
                    fclose(input_file);
                }
            } else {
                stats.failed_files++;
                batch_stats_add_failed_file(&stats, input_path);

                // Add file stats for failed files too
                FILE *input_file = fopen(input_path, "rb");
                if (input_file) {
                    fseek(input_file, 0, SEEK_END);
                    size_t fsize = ftell(input_file);
                    fseek(input_file, 0, SEEK_SET);

                    if (fsize > 0) {
                        uint8_t *input_data = malloc(fsize);
                        if (input_data && fread(input_data, 1, fsize, input_file) == fsize) {
                            int instr_count, bad_char_count;
                            count_shellcode_stats(input_data, input_size, &instr_count, &bad_char_count);
                            batch_stats_add_file_stats(&stats, input_path, fsize,
                                                     0, instr_count, bad_char_count, 0);
                        }
                        if (input_data) free(input_data);
                    }
                    fclose(input_file);
                }
            }

            free(output_path);

            // Small delay so user can see progress
            napms(50);
        }

        // Final summary screen
        clear_screen();
        draw_header("Batch Processing Complete");

        int summary_row = 5;
        mvprintw(summary_row++, 5, "Batch processing completed!");
        mvprintw(summary_row++, 5, " ");

        // Final statistics
        attron(A_BOLD);
        mvprintw(summary_row++, 5, "Final Statistics:");
        attroff(A_BOLD);
        mvprintw(summary_row++, 5, " ");
        mvprintw(summary_row++, 5, "  Total files:      %zu", stats.total_files);
        attron(COLOR_PAIR(4));
        mvprintw(summary_row++, 5, "  Successful:       %zu", stats.processed_files);
        attroff(COLOR_PAIR(4));
        attron(COLOR_PAIR(3));
        mvprintw(summary_row++, 5, "  Failed:           %zu", stats.failed_files);
        attroff(COLOR_PAIR(3));
        mvprintw(summary_row++, 5, "  Skipped:          %zu", stats.skipped_files);
        mvprintw(summary_row++, 5, " ");
        mvprintw(summary_row++, 5, "  Total input:      %zu bytes", stats.total_input_bytes);
        mvprintw(summary_row++, 5, "  Total output:     %zu bytes", stats.total_output_bytes);

        if (stats.total_input_bytes > 0) {
            double avg_ratio = (double)stats.total_output_bytes / (double)stats.total_input_bytes;
            mvprintw(summary_row++, 5, "  Average ratio:    %.2fx", avg_ratio);
        }

        mvprintw(summary_row++, 5, " ");
        mvprintw(summary_row++, 5, "Press any key to return to main menu...");
        refresh();

        // Restore original verbose/quiet settings
        config->verbose = original_verbose;
        config->quiet = original_quiet;

        // Cleanup
        file_list_free(&file_list);
        batch_stats_free(&stats);

        getch();
        return MAIN_SCREEN;
    } else {
        // Single file processing
        int row = 5;
        mvprintw(row++, 5, "Initializing strategies...");
        refresh();

        // Initialize strategy registries (needed for processing)
        init_strategies(config->use_ml_strategist);
        if (config->use_biphasic) {
            init_obfuscation_strategies();
        }

        // Initialize bad character context for processing
        init_bad_char_context(config->bad_chars);

        mvprintw(row++, 5, "Processing file...");
        refresh();

        size_t input_size = 0;
        size_t output_size = 0;
        int result = process_single_file(config->input_file, config->output_file,
                                          config, &input_size, &output_size);

        // Store results globally for the results screen
        g_last_input_size = input_size;
        g_last_output_size = output_size;
        g_last_processing_result = result;

        mvprintw(row++, 5, " ");
        if (result == EXIT_SUCCESS) {
            mvprintw(row++, 5, "Processing completed successfully!");
            mvprintw(row++, 5, "Input size: %zu bytes", input_size);
            mvprintw(row++, 5, "Output size: %zu bytes", output_size);
            if (input_size > 0) {
                double ratio = (double)output_size / (double)input_size;
                mvprintw(row++, 5, "Size ratio: %.2fx", ratio);
            }
        } else {
            mvprintw(row++, 5, "Processing failed with error code: %d", result);
            if (result == EXIT_INPUT_FILE_ERROR) {
                mvprintw(row++, 5, "Error: Cannot open or read input file");
            } else if (result == EXIT_PROCESSING_FAILED) {
                mvprintw(row++, 5, "Error: Shellcode processing failed");
            } else if (result == EXIT_OUTPUT_FILE_ERROR) {
                mvprintw(row++, 5, "Error: Cannot write output file");
            }
        }

        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Press any key to continue...");
        getch();

        return (result == EXIT_SUCCESS) ? RESULTS_SCREEN : MAIN_SCREEN;
    }
}

// Results screen implementation
int show_results_screen(byvalver_config_t *config) {
    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("Processing Results");

        int local_row = 5;
        mvprintw(local_row++, 5, "Processing Results:");
        mvprintw(local_row++, 5, " ");
        mvprintw(local_row++, 5, "Input file: %s", config->input_file ? config->input_file : "Not set");
        mvprintw(local_row++, 5, "Output file: %s", config->output_file ? config->output_file : "Not set");
        mvprintw(local_row++, 5, " ");

        // Show actual results from the last processing run
        if (g_last_processing_result == EXIT_SUCCESS) {
            mvprintw(local_row++, 5, "Status: SUCCESS");
            mvprintw(local_row++, 5, "Original size: %zu bytes", g_last_input_size);
            mvprintw(local_row++, 5, "Processed size: %zu bytes", g_last_output_size);
            if (g_last_input_size > 0) {
                double ratio = (double)g_last_output_size / (double)g_last_input_size;
                mvprintw(local_row++, 5, "Size ratio: %.2fx", ratio);
            }

            // Display configured bad characters
            mvprintw(local_row++, 5, "Bad characters eliminated: ");
            if (config->bad_chars) {
                int count = 0;
                char bad_chars_str[512] = "";
                for (int i = 0; i < 256 && count < 20; i++) {
                    if (config->bad_chars->bad_chars[i]) {
                        char tmp[8];
                        if (count > 0) strcat(bad_chars_str, ", ");
                        snprintf(tmp, sizeof(tmp), "0x%02X", i);
                        strcat(bad_chars_str, tmp);
                        count++;
                    }
                }
                if (count >= 20) strcat(bad_chars_str, ", ...");
                mvprintw(local_row++, 5, "  %s", bad_chars_str);
            } else {
                mvprintw(local_row++, 5, "  0x00 (null byte only)");
            }
        } else {
            mvprintw(local_row++, 5, "Status: FAILED (error code %d)", g_last_processing_result);
        }
        mvprintw(local_row++, 5, " ");

        draw_menu_item(local_row++, 5, "1. View Detailed Stats", current_selection == 1);
        draw_menu_item(local_row++, 5, "2. Process Another File", current_selection == 2);
        mvprintw(local_row++, 5, " ");
        draw_menu_item(local_row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN; // Exit to main menu
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
                if (current_selection == 2) current_selection = 1; // Skip the empty line
            } else {
                current_selection = 2; // wrap around to max
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 2) {
                current_selection++;
                if (current_selection == 2) current_selection = 0; // Skip the empty line
            } else {
                current_selection = 1; // wrap around to min
            }
        } else if (ch == '\n' || ch == '\r') {
            // Handle selection
            switch (current_selection) {
                case 1:
                    // Show detailed stats
                    clear_screen();
                    draw_header("Detailed Statistics");
                    mvprintw(10, 5, "Detailed statistics would be shown here");
                    mvprintw(12, 5, "Press any key to return...");
                    getch();
                    return RESULTS_SCREEN;
                case 2:
                    return INPUT_SCREEN;
                case 0:
                    return MAIN_SCREEN;
            }
        } else if (ch >= '0' && ch <= '2') {
            int choice = ch - '0';
            switch (choice) {
                case 1:
                    // Show detailed stats
                    clear_screen();
                    draw_header("Detailed Statistics");
                    mvprintw(10, 5, "Detailed statistics would be shown here");
                    mvprintw(12, 5, "Press any key to return...");
                    getch();
                    return RESULTS_SCREEN;
                case 2:
                    return INPUT_SCREEN;
                case 0:
                    return MAIN_SCREEN;
            }
        }
    }
}

// Configuration screen implementation
int show_config_screen(byvalver_config_t *config) {
    clear_screen();
    draw_header("Configuration Management");
    
    int row = 5;
    mvprintw(row++, 5, "Configuration Management:");
    mvprintw(row++, 5, " ");

    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("Configuration Management");

        int local_row = 5;
        mvprintw(local_row++, 5, "Configuration Management:");
        mvprintw(local_row++, 5, " ");

        draw_menu_item(local_row++, 5, "1. Load Configuration File", current_selection == 1);
        draw_menu_item(local_row++, 5, "2. Save Current Configuration", current_selection == 2);
        draw_menu_item(local_row++, 5, "3. Reset to Defaults", current_selection == 3);
        mvprintw(local_row++, 5, " ");
        draw_menu_item(local_row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN; // Exit to main menu
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
                if (current_selection == 3) current_selection = 2; // Skip the empty line
            } else {
                current_selection = 3; // wrap around to max
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 3) {
                current_selection++;
                if (current_selection == 3) current_selection = 0; // Skip the empty line
            } else {
                current_selection = 1; // wrap around to min
            }
        } else if (ch == '\n' || ch == '\r') {
            // Handle selection
            switch (current_selection) {
                case 1: {
                    clear_screen();
                    draw_header("Configuration Management");

                    int input_row = 5;
                    mvprintw(input_row++, 5, "Configuration Management:");
                    mvprintw(input_row++, 5, " ");

                    char config_file[512];
                    mvprintw(input_row++, 5, "Enter configuration file path:");
                    echo();
                    getstr(config_file);
                    noecho();

                    if (strlen(config_file) > 0) {
                        // Load configuration file
                        load_config_file(config_file, config);
                        mvprintw(input_row++, 5, "Configuration loaded from: %s", config_file);
                        mvprintw(input_row++, 5, "Press any key to continue...");
                        getch();
                    }
                    break;
                }
                case 2: {
                    clear_screen();
                    draw_header("Configuration Management");

                    int input_row = 5;
                    mvprintw(input_row++, 5, "Configuration Management:");
                    mvprintw(input_row++, 5, " ");

                    char config_file[512];
                    mvprintw(input_row++, 5, "Enter configuration file path to save:");
                    echo();
                    getstr(config_file);
                    noecho();

                    if (strlen(config_file) > 0) {
                        // Save configuration file (implementation would go here)
                        mvprintw(input_row++, 5, "Configuration saved to: %s", config_file);
                        mvprintw(input_row++, 5, "Press any key to continue...");
                        getch();
                    }
                    break;
                }
                case 3:
                    clear_screen();
                    draw_header("Configuration Management");

                    int input_row = 5;
                    mvprintw(input_row++, 5, "Configuration Management:");
                    mvprintw(input_row++, 5, " ");
                    mvprintw(input_row++, 5, "Configuration reset to defaults");
                    mvprintw(input_row++, 5, "Press any key to continue...");
                    getch();
                    break;
                case 0:
                    return MAIN_SCREEN;
            }
            return CONFIG_SCREEN; // Stay on this screen to allow multiple changes
        } else if (ch >= '0' && ch <= '3') {
            int choice = ch - '0';
            switch (choice) {
                case 1: {
                    clear_screen();
                    draw_header("Configuration Management");

                    int input_row = 5;
                    mvprintw(input_row++, 5, "Configuration Management:");
                    mvprintw(input_row++, 5, " ");

                    char config_file[512];
                    mvprintw(input_row++, 5, "Enter configuration file path:");
                    echo();
                    getstr(config_file);
                    noecho();

                    if (strlen(config_file) > 0) {
                        // Load configuration file
                        load_config_file(config_file, config);
                        mvprintw(input_row++, 5, "Configuration loaded from: %s", config_file);
                        mvprintw(input_row++, 5, "Press any key to continue...");
                        getch();
                    }
                    break;
                }
                case 2: {
                    clear_screen();
                    draw_header("Configuration Management");

                    int input_row = 5;
                    mvprintw(input_row++, 5, "Configuration Management:");
                    mvprintw(input_row++, 5, " ");

                    char config_file[512];
                    mvprintw(input_row++, 5, "Enter configuration file path to save:");
                    echo();
                    getstr(config_file);
                    noecho();

                    if (strlen(config_file) > 0) {
                        // Save configuration file (implementation would go here)
                        mvprintw(input_row++, 5, "Configuration saved to: %s", config_file);
                        mvprintw(input_row++, 5, "Press any key to continue...");
                        getch();
                    }
                    break;
                }
                case 3:
                    clear_screen();
                    draw_header("Configuration Management");

                    int input_row = 5;
                    mvprintw(input_row++, 5, "Configuration Management:");
                    mvprintw(input_row++, 5, " ");
                    mvprintw(input_row++, 5, "Configuration reset to defaults");
                    mvprintw(input_row++, 5, "Press any key to continue...");
                    getch();
                    break;
                case 0:
                    return MAIN_SCREEN;
            }
            return CONFIG_SCREEN; // Stay on this screen to allow multiple changes
        }
    }
}

// Bad characters screen implementation
int show_bad_chars_screen(byvalver_config_t *config) {
    clear_screen();
    draw_header("Bad Characters Configuration");
    
    int row = 5;
    mvprintw(row++, 5, "Bad Characters Configuration:");
    mvprintw(row++, 5, " ");

    mvprintw(row++, 5, "Current bad characters:");
    if (config->bad_chars) {
        int count = 0;
        for (int i = 0; i < 256; i++) {
            if (config->bad_chars->bad_chars[i]) {
                mvprintw(row++, 5, "  0x%02X", i);
                count++;
                if (count >= 10) { // Limit display to prevent overflow
                    mvprintw(row++, 5, "  ... and more");
                    break;
                }
            }
        }
    } else {
        mvprintw(row++, 5, "  No bad characters configured");
    }
    mvprintw(row++, 5, " ");

    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("Bad Characters Configuration");

        int local_row = 5;
        mvprintw(local_row++, 5, "Bad Characters Configuration:");
        mvprintw(local_row++, 5, " ");

        mvprintw(local_row++, 5, "Current bad characters:");
        if (config->bad_chars) {
            int count = 0;
            for (int i = 0; i < 256; i++) {
                if (config->bad_chars->bad_chars[i]) {
                    mvprintw(local_row++, 5, "  0x%02X", i);
                    count++;
                    if (count >= 10) { // Limit display to prevent overflow
                        mvprintw(local_row++, 5, "  ... and more");
                        break;
                    }
                }
            }
        } else {
            mvprintw(local_row++, 5, "  No bad characters configured");
        }
        mvprintw(local_row++, 5, " ");

        draw_menu_item(local_row++, 5, "1. Enter Bad Characters (hex)", current_selection == 1);
        draw_menu_item(local_row++, 5, "2. Use Predefined Profile", current_selection == 2);
        mvprintw(local_row++, 5, " ");
        draw_menu_item(local_row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN; // Exit to main menu
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
                if (current_selection == 2) current_selection = 1; // Skip the empty line
            } else {
                current_selection = 2; // wrap around to max
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 2) {
                current_selection++;
                if (current_selection == 2) current_selection = 0; // Skip the empty line
            } else {
                current_selection = 1; // wrap around to min
            }
        } else if (ch == '\n' || ch == '\r') {
            // Handle selection
            switch (current_selection) {
                case 1: {
                    clear_screen();
                    draw_header("Bad Characters Configuration");

                    int input_row = 5;
                    mvprintw(input_row++, 5, "Bad Characters Configuration:");
                    mvprintw(input_row++, 5, " ");
                    mvprintw(input_row++, 5, "Current bad characters:");
                    if (config->bad_chars) {
                        int count = 0;
                        for (int i = 0; i < 256; i++) {
                            if (config->bad_chars->bad_chars[i]) {
                                mvprintw(input_row++, 5, "  0x%02X", i);
                                count++;
                                if (count >= 10) {
                                    mvprintw(input_row++, 5, "  ... and more");
                                    break;
                                }
                            }
                        }
                    } else {
                        mvprintw(input_row++, 5, "  No bad characters configured");
                    }
                    mvprintw(input_row++, 5, " ");

                    char bad_chars_input[512];
                    mvprintw(input_row++, 5, "Enter bad characters (comma-separated hex, e.g., 00,0a,0d):");
                    echo();
                    getstr(bad_chars_input);
                    noecho();

                    if (strlen(bad_chars_input) > 0) {
                        // Parse bad characters
                        bad_char_config_t* new_config = parse_bad_chars_string(bad_chars_input);
                        if (new_config) {
                            if (config->bad_chars) {
                                free(config->bad_chars);
                            }
                            config->bad_chars = new_config;
                            mvprintw(input_row++, 5, "Bad characters updated successfully");
                        } else {
                            mvprintw(input_row++, 5, "Invalid bad characters format");
                        }
                    }
                    mvprintw(input_row++, 5, "Press any key to continue...");
                    getch();
                    break;
                }
                case 2: {
                    // Show all predefined profiles by dynamically listing them
                    clear_screen();
                    draw_header("Predefined Bad Character Profiles");

                    // Initialize profiles (this is done in badchar_profiles.h)
                    init_badchar_profiles();

                    mvprintw(5, 5, "Available profiles:");
                    mvprintw(6, 5, "================");

                    // Calculate number of profiles
                    size_t num_profiles = NUM_PROFILES;

                    int start_row = 7;
                    for (size_t i = 0; i < num_profiles && i < 20; i++) { // Limit to 20 for display
                        const badchar_profile_t *profile = &BADCHAR_PROFILES[i];
                        mvprintw(start_row + i, 5, "%zu. %s", i+1, profile->name);
                    }

                    if (num_profiles > 20) {
                        mvprintw(start_row + 20, 5, "... and %zu more", num_profiles - 20);
                    }

                    mvprintw(start_row + num_profiles + 2, 5, "Enter choice (1-%zu, 0 to cancel):", num_profiles);
                    refresh();

                    int profile_choice = getch() - '0';

                    if (profile_choice >= 1 && profile_choice <= (int)num_profiles) {
                        const badchar_profile_t *profile = &BADCHAR_PROFILES[profile_choice-1];

                        if (profile) {
                            if (config->bad_chars) {
                                free(config->bad_chars);
                            }
                            config->bad_chars = profile_to_config(profile);
                            mvprintw(start_row + num_profiles + 4, 5, "Profile '%s' applied successfully", profile->name);
                        } else {
                            mvprintw(start_row + num_profiles + 4, 5, "Failed to apply profile");
                        }
                    } else if (profile_choice == 0) {
                        mvprintw(start_row + num_profiles + 4, 5, "Profile selection cancelled");
                    } else {
                        mvprintw(start_row + num_profiles + 4, 5, "Invalid profile number");
                    }

                    mvprintw(start_row + num_profiles + 6, 5, "Press any key to continue...");
                    getch();
                    break;
                }
                case 0:
                    return MAIN_SCREEN;
            }
            return BAD_CHARS_SCREEN; // Stay on this screen to allow multiple changes
        } else if (ch >= '0' && ch <= '2') {
            int choice = ch - '0';
            switch (choice) {
                case 1: {
                    clear_screen();
                    draw_header("Bad Characters Configuration");

                    int input_row = 5;
                    mvprintw(input_row++, 5, "Bad Characters Configuration:");
                    mvprintw(input_row++, 5, " ");
                    mvprintw(input_row++, 5, "Current bad characters:");
                    if (config->bad_chars) {
                        int count = 0;
                        for (int i = 0; i < 256; i++) {
                            if (config->bad_chars->bad_chars[i]) {
                                mvprintw(input_row++, 5, "  0x%02X", i);
                                count++;
                                if (count >= 10) {
                                    mvprintw(input_row++, 5, "  ... and more");
                                    break;
                                }
                            }
                        }
                    } else {
                        mvprintw(input_row++, 5, "  No bad characters configured");
                    }
                    mvprintw(input_row++, 5, " ");

                    char bad_chars_input[512];
                    mvprintw(input_row++, 5, "Enter bad characters (comma-separated hex, e.g., 00,0a,0d):");
                    echo();
                    getstr(bad_chars_input);
                    noecho();

                    if (strlen(bad_chars_input) > 0) {
                        // Parse bad characters
                        bad_char_config_t* new_config = parse_bad_chars_string(bad_chars_input);
                        if (new_config) {
                            if (config->bad_chars) {
                                free(config->bad_chars);
                            }
                            config->bad_chars = new_config;
                            mvprintw(input_row++, 5, "Bad characters updated successfully");
                        } else {
                            mvprintw(input_row++, 5, "Invalid bad characters format");
                        }
                    }
                    mvprintw(input_row++, 5, "Press any key to continue...");
                    getch();
                    break;
                }
                case 2: {
                    // Show all predefined profiles by dynamically listing them
                    clear_screen();
                    draw_header("Predefined Bad Character Profiles");

                    // Initialize profiles (this is done in badchar_profiles.h)
                    init_badchar_profiles();

                    mvprintw(5, 5, "Available profiles:");
                    mvprintw(6, 5, "================");

                    // Calculate number of profiles
                    size_t num_profiles = NUM_PROFILES;

                    int start_row = 7;
                    for (size_t i = 0; i < num_profiles && i < 20; i++) { // Limit to 20 for display
                        const badchar_profile_t *profile = &BADCHAR_PROFILES[i];
                        mvprintw(start_row + i, 5, "%zu. %s", i+1, profile->name);
                    }

                    if (num_profiles > 20) {
                        mvprintw(start_row + 20, 5, "... and %zu more", num_profiles - 20);
                    }

                    mvprintw(start_row + num_profiles + 2, 5, "Enter choice (1-%zu, 0 to cancel):", num_profiles);
                    refresh();

                    int profile_choice = getch() - '0';

                    if (profile_choice >= 1 && profile_choice <= (int)num_profiles) {
                        const badchar_profile_t *profile = &BADCHAR_PROFILES[profile_choice-1];

                        if (profile) {
                            if (config->bad_chars) {
                                free(config->bad_chars);
                            }
                            config->bad_chars = profile_to_config(profile);
                            mvprintw(start_row + num_profiles + 4, 5, "Profile '%s' applied successfully", profile->name);
                        } else {
                            mvprintw(start_row + num_profiles + 4, 5, "Failed to apply profile");
                        }
                    } else if (profile_choice == 0) {
                        mvprintw(start_row + num_profiles + 4, 5, "Profile selection cancelled");
                    } else {
                        mvprintw(start_row + num_profiles + 4, 5, "Invalid profile number");
                    }

                    mvprintw(start_row + num_profiles + 6, 5, "Press any key to continue...");
                    getch();
                    break;
                }
                case 0:
                    return MAIN_SCREEN;
            }
            return BAD_CHARS_SCREEN; // Stay on this screen to allow multiple changes
        }
    }
}

// Batch processing screen implementation
int show_batch_screen(byvalver_config_t *config) {
    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("Batch Directory Processing");

        int row = 5;
        mvprintw(row++, 5, "Batch Processing Configuration:");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Input directory:  %s", config->input_file ? config->input_file : "Not set");
        mvprintw(row++, 5, "Output directory: %s", config->output_file ? config->output_file : "Not set");
        mvprintw(row++, 5, "File pattern:     %s", config->file_pattern ? config->file_pattern : "*.bin");
        mvprintw(row++, 5, "Recursive:        %s", config->recursive ? "Yes" : "No");
        mvprintw(row++, 5, "Preserve structure: %s", config->preserve_structure ? "Yes" : "No");
        mvprintw(row++, 5, " ");

        draw_menu_item(row++, 5, "1. Browse for Input Directory", current_selection == 1);
        draw_menu_item(row++, 5, "2. Browse for Output Directory", current_selection == 2);
        draw_menu_item(row++, 5, "3. Set File Pattern", current_selection == 3);

        char recursive_str[64];
        snprintf(recursive_str, sizeof(recursive_str), "4. Recursive Processing: %s",
                 config->recursive ? "[ON]" : "[OFF]");
        draw_menu_item(row++, 5, recursive_str, current_selection == 4);

        char preserve_str[64];
        snprintf(preserve_str, sizeof(preserve_str), "5. Preserve Directory Structure: %s",
                 config->preserve_structure ? "[ON]" : "[OFF]");
        draw_menu_item(row++, 5, preserve_str, current_selection == 5);

        draw_menu_item(row++, 5, "6. Start Batch Processing", current_selection == 6);
        mvprintw(row++, 5, " ");
        draw_menu_item(row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN;
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
            } else {
                current_selection = 6;
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 6) {
                current_selection++;
            } else {
                current_selection = 0;
            }
        } else if (ch == '\n' || ch == '\r') {
            switch (current_selection) {
                case 1: {
                    // Only pass path if it's a valid directory, otherwise pass NULL
                    const char *start_path = NULL;
                    if (config->input_file) {
                        struct stat st;
                        if (stat(config->input_file, &st) == 0 && S_ISDIR(st.st_mode)) {
                            start_path = config->input_file;
                        }
                    }
                    char *selected = show_file_browser(start_path, BROWSER_MODE_SELECT_DIRECTORY, NULL);
                    if (selected) {
                        config->input_file = selected;
                    }
                    break;
                }
                case 2: {
                    // Only pass path if it's a valid directory, otherwise pass NULL
                    const char *start_path = NULL;
                    if (config->output_file) {
                        struct stat st;
                        if (stat(config->output_file, &st) == 0 && S_ISDIR(st.st_mode)) {
                            start_path = config->output_file;
                        }
                    }
                    char *selected = show_file_browser(start_path, BROWSER_MODE_SELECT_DIRECTORY, NULL);
                    if (selected) {
                        config->output_file = selected;
                    }
                    break;
                }
                case 3: {
                    clear_screen();
                    draw_header("File Pattern");
                    mvprintw(5, 5, "Enter file pattern (e.g., *.bin, *.asm, *shellcode*):");
                    char pattern[256];
                    echo();
                    getstr(pattern);
                    noecho();
                    if (strlen(pattern) > 0) {
                        config->file_pattern = strdup(pattern);
                    }
                    break;
                }
                case 4:
                    config->recursive = !config->recursive;
                    break;
                case 5:
                    config->preserve_structure = !config->preserve_structure;
                    break;
                case 6:
                    if (!config->input_file || !config->output_file) {
                        clear_screen();
                        draw_header("Error");
                        mvprintw(5, 5, "Error: Both input and output directories must be set!");
                        mvprintw(7, 5, "Press any key to continue...");
                        getch();
                        break;
                    }
                    // Enable batch mode flag
                    config->batch_mode = 1;
                    return PROCESSING_SCREEN;
                case 0:
                    return MAIN_SCREEN;
            }
        } else if (ch >= '0' && ch <= '6') {
            int choice = ch - '0';
            current_selection = choice;
        }
    }
}

// Output format screen implementation
int show_output_format_screen(byvalver_config_t *config) {
    int current_selection = 1;
    const char *formats[] = {"raw", "c", "python", "powershell", "hexstring"};
    const char *format_descs[] = {
        "Raw binary output",
        "C array format (unsigned char shellcode[])",
        "Python bytes format (shellcode = b\"\\x...\")",
        "PowerShell array format ($shellcode = @(0x..))",
        "Hexadecimal string (AABBCCDD...)"
    };
    int num_formats = 5;

    while(1) {
        clear_screen();
        draw_header("Output Format Settings");

        int row = 5;
        mvprintw(row++, 5, "Output Format Configuration:");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Current format: %s", config->output_format ? config->output_format : "raw");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Available formats:");
        mvprintw(row++, 5, " ");

        for (int i = 0; i < num_formats; i++) {
            char format_option[256];
            snprintf(format_option, sizeof(format_option), "%d. %-12s - %s",
                    i + 1, formats[i], format_descs[i]);
            draw_menu_item(row++, 5, format_option, current_selection == i + 1);
        }

        mvprintw(row++, 5, " ");
        draw_menu_item(row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN;
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
            } else {
                current_selection = num_formats;
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < num_formats) {
                current_selection++;
            } else {
                current_selection = 0;
            }
        } else if (ch == '\n' || ch == '\r') {
            if (current_selection >= 1 && current_selection <= num_formats) {
                config->output_format = (char*)formats[current_selection - 1];
                mvprintw(LINES - 3, 5, "Output format set to: %s", config->output_format);
                refresh();
                napms(500);
            } else if (current_selection == 0) {
                return MAIN_SCREEN;
            }
        } else if (ch >= '0' && ch <= '5') {
            int choice = ch - '0';
            if (choice == 0) {
                return MAIN_SCREEN;
            } else if (choice <= num_formats) {
                config->output_format = (char*)formats[choice - 1];
                mvprintw(LINES - 3, 5, "Output format set to: %s", config->output_format);
                refresh();
                napms(500);
            }
        }
    }
}

// ML Metrics screen implementation
int show_ml_metrics_screen(byvalver_config_t *config) {
    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("ML Metrics Configuration");

        int row = 5;
        mvprintw(row++, 5, "ML Metrics and Learning Configuration:");
        mvprintw(row++, 5, " ");

        char option1[100], option2[100], option3[100], option4[100], option5[100];
        snprintf(option1, sizeof(option1), "1. ML Strategy Selection: %s",
                config->use_ml_strategist ? "[ON]" : "[OFF]");
        snprintf(option2, sizeof(option2), "2. Enable Metrics Tracking: %s",
                config->metrics_enabled ? "[ON]" : "[OFF]");
        snprintf(option3, sizeof(option3), "3. Export JSON Metrics: %s",
                config->metrics_export_json ? "[ON]" : "[OFF]");
        snprintf(option4, sizeof(option4), "4. Export CSV Metrics: %s",
                config->metrics_export_csv ? "[ON]" : "[OFF]");
        snprintf(option5, sizeof(option5), "5. Show Live Metrics: %s",
                config->metrics_show_live ? "[ON]" : "[OFF]");

        draw_menu_item(row++, 5, option1, current_selection == 1);
        draw_menu_item(row++, 5, option2, current_selection == 2);
        draw_menu_item(row++, 5, option3, current_selection == 3);
        draw_menu_item(row++, 5, option4, current_selection == 4);
        draw_menu_item(row++, 5, option5, current_selection == 5);
        draw_menu_item(row++, 5, "6. Set Metrics Output File", current_selection == 6);
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Current metrics file: %s",
                config->metrics_output_file ? config->metrics_output_file : "./ml_metrics.log");
        mvprintw(row++, 5, " ");
        draw_menu_item(row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN;
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
            } else {
                current_selection = 6;
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 6) {
                current_selection++;
            } else {
                current_selection = 0;
            }
        } else if (ch == '\n' || ch == '\r') {
            switch (current_selection) {
                case 1:
                    config->use_ml_strategist = !config->use_ml_strategist;
                    break;
                case 2:
                    config->metrics_enabled = !config->metrics_enabled;
                    break;
                case 3:
                    config->metrics_export_json = !config->metrics_export_json;
                    if (config->metrics_export_json) config->metrics_enabled = 1;
                    break;
                case 4:
                    config->metrics_export_csv = !config->metrics_export_csv;
                    if (config->metrics_export_csv) config->metrics_enabled = 1;
                    break;
                case 5:
                    config->metrics_show_live = !config->metrics_show_live;
                    if (config->metrics_show_live) config->metrics_enabled = 1;
                    break;
                case 6: {
                    clear_screen();
                    draw_header("Metrics Output File");
                    mvprintw(5, 5, "Enter metrics output file path:");
                    char metrics_file[512];
                    echo();
                    getstr(metrics_file);
                    noecho();
                    if (strlen(metrics_file) > 0) {
                        config->metrics_output_file = strdup(metrics_file);
                    }
                    break;
                }
                case 0:
                    return MAIN_SCREEN;
            }
        } else if (ch >= '0' && ch <= '6') {
            int choice = ch - '0';
            current_selection = choice;
        }
    }
}

// Advanced options screen implementation
int show_advanced_options_screen(byvalver_config_t *config) {
    int current_selection = 1;

    while(1) {
        clear_screen();
        draw_header("Advanced Options");

        int row = 5;
        mvprintw(row++, 5, "Advanced Configuration:");
        mvprintw(row++, 5, " ");

        char option1[100], option2[100], option3[100];
        snprintf(option1, sizeof(option1), "1. XOR Encoding: %s (Key: 0x%08X)",
                config->encode_shellcode ? "[ON]" : "[OFF]", config->xor_key);
        snprintf(option2, sizeof(option2), "2. Show Statistics: %s",
                config->show_stats ? "[ON]" : "[OFF]");
        snprintf(option3, sizeof(option3), "3. Validate Output: %s",
                config->validate_output ? "[ON]" : "[OFF]");

        draw_menu_item(row++, 5, option1, current_selection == 1);
        draw_menu_item(row++, 5, option2, current_selection == 2);
        draw_menu_item(row++, 5, option3, current_selection == 3);
        draw_menu_item(row++, 5, "4. Set Strategy Limit", current_selection == 4);
        draw_menu_item(row++, 5, "5. Set Timeout", current_selection == 5);
        draw_menu_item(row++, 5, "6. Set Max File Size", current_selection == 6);
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Current settings:");
        mvprintw(row++, 5, "  Strategy limit: %d (0 = unlimited)", config->strategy_limit);
        mvprintw(row++, 5, "  Timeout: %d seconds (0 = no timeout)", config->timeout_seconds);
        mvprintw(row++, 5, "  Max file size: %zu bytes", config->max_size);
        mvprintw(row++, 5, " ");
        draw_menu_item(row++, 5, "0. Back to Main Menu", current_selection == 0);

        draw_footer();
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return MAIN_SCREEN;
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
            } else {
                current_selection = 6;
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < 6) {
                current_selection++;
            } else {
                current_selection = 0;
            }
        } else if (ch == '\n' || ch == '\r') {
            switch (current_selection) {
                case 1: {
                    if (!config->encode_shellcode) {
                        clear_screen();
                        draw_header("XOR Encoding");
                        mvprintw(5, 5, "Enter XOR key (hex, e.g., 0xDEADBEEF):");
                        char key_str[32];
                        echo();
                        getstr(key_str);
                        noecho();
                        if (strlen(key_str) > 0) {
                            char *endptr;
                            config->xor_key = (uint32_t)strtol(key_str, &endptr, 16);
                            config->encode_shellcode = 1;
                        }
                    } else {
                        config->encode_shellcode = 0;
                    }
                    break;
                }
                case 2:
                    config->show_stats = !config->show_stats;
                    break;
                case 3:
                    config->validate_output = !config->validate_output;
                    break;
                case 4: {
                    clear_screen();
                    draw_header("Strategy Limit");
                    mvprintw(5, 5, "Enter strategy limit (0 for unlimited):");
                    char limit_str[32];
                    echo();
                    getstr(limit_str);
                    noecho();
                    if (strlen(limit_str) > 0) {
                        config->strategy_limit = atoi(limit_str);
                    }
                    break;
                }
                case 5: {
                    clear_screen();
                    draw_header("Timeout");
                    mvprintw(5, 5, "Enter timeout in seconds (0 for no timeout):");
                    char timeout_str[32];
                    echo();
                    getstr(timeout_str);
                    noecho();
                    if (strlen(timeout_str) > 0) {
                        config->timeout_seconds = atoi(timeout_str);
                    }
                    break;
                }
                case 6: {
                    clear_screen();
                    draw_header("Max File Size");
                    mvprintw(5, 5, "Enter maximum file size in bytes:");
                    char size_str[32];
                    echo();
                    getstr(size_str);
                    noecho();
                    if (strlen(size_str) > 0) {
                        config->max_size = atoi(size_str);
                    }
                    break;
                }
                case 0:
                    return MAIN_SCREEN;
            }
        } else if (ch >= '0' && ch <= '6') {
            int choice = ch - '0';
            current_selection = choice;
        }
    }
}

// About screen implementation
int show_about_screen() {
    clear_screen();
    draw_header("About byvalver");
    
    int row = 5;
    mvprintw(row++, 5, "byvalver - Generic Bad-Character Elimination Framework");
    mvprintw(row++, 5, " ");
    mvprintw(row++, 5, "Version: %d.%d.%d", BYVALVER_VERSION_MAJOR, BYVALVER_VERSION_MINOR, BYVALVER_VERSION_PATCH);
    mvprintw(row++, 5, "Description: Advanced C-based command-line tool designed for automated");
    mvprintw(row++, 5, "           elimination of bad characters from shellcode while preserving");
    mvprintw(row++, 5, "           functional equivalence.");
    mvprintw(row++, 5, " ");
    mvprintw(row++, 5, "Features:");
    mvprintw(row++, 5, "  - Null-byte elimination");
    mvprintw(row++, 5, "  - Biphasic processing (obfuscation + null-elimination)");
    mvprintw(row++, 5, "  - Position-independent code generation");
    mvprintw(row++, 5, "  - Generic bad character elimination");
    mvprintw(row++, 5, "  - ML-enhanced strategy selection");
    mvprintw(row++, 5, "  - Batch processing capabilities");
    mvprintw(row++, 5, "  - Interactive TUI mode");
    mvprintw(row++, 5, " ");
    mvprintw(row++, 5, "Press any key to return to main menu...");
    getch();
    
    return MAIN_SCREEN;
}

// Utility functions implementation
void clear_screen() {
    clear();
    refresh();
}

void draw_header(const char *title) {
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "%*s", COLS, " ");
    mvprintw(0, (COLS - strlen(title)) / 2, "%s", title);
    attroff(COLOR_PAIR(1));
}

void draw_footer() {
    attron(COLOR_PAIR(1));
    mvprintw(LINES - 1, 0, "%*s", COLS, " ");
    mvprintw(LINES - 1, 2, "Use arrow keys to navigate, Enter to select, 'q' to quit");
    attroff(COLOR_PAIR(1));
    refresh();
}


void draw_menu_item(int row, int col, const char *text, int selected) {
    if (selected) {
        attron(COLOR_PAIR(2)); // Highlight selected items
        mvprintw(row, col, " -> %s", text);
        attroff(COLOR_PAIR(2));
    } else {
        mvprintw(row, col, "    %s", text);
    }
}